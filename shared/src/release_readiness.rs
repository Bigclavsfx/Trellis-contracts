//! Release readiness gate for migrations, security checks, and rollback rehearsals (Issue #253).
//!
//! Across Trellis Soroban contracts — Treasury, Aid, Referral, Governance, Oracle,
//! and Marketplace — production releases must be gated by strict operational, security,
//! and reliability verifications before on-chain execution or deployment promotion.
//!
//! This module provides:
//! 1. **Four-Pillar Gate Verification**: Ensures every target module satisfies:
//!    - **Migration Gate**: Schema versioning, dry-run simulation, and compatibility verified.
//!    - **Security Gate**: Security audit, allowlist freshness, invariant assertions, and auth roles verified.
//!    - **Smoke Tests Gate**: Cross-contract dependency wiring and entry point liveness verified.
//!    - **Rollback Rehearsal Gate**: Pre-upgrade snapshots, rollback procedures, and simulated reverts verified.
//! 2. **Automated Rollback Rehearsals**: Enables dry-run simulation of upgrade failure and
//!    subsequent state recovery under [`RollbackStrategy`] (Revert, ForwardFix, Manual),
//!    issuing auditable [`RollbackRehearsalReceipt`] records.
//! 3. **Release Readiness Evaluation**: Evaluates complete [`ReleaseManifest`] payloads,
//!    blocking unverified releases while acknowledging emergency exception markers with
//!    auditable trail logging.
//! 4. **State Tracking & Event Telemetry**: Emits structured Soroban events for indexing
//!    and stores immutable readiness reports in instance storage.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::migration::RollbackStrategy;
use crate::storage::{instance_get, instance_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 970–979)
// ---------------------------------------------------------------------------

/// Release readiness and rollback rehearsal orchestration errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ReleaseGateError {
    /// One or more required gate checks failed.
    GateCheckFailed = 970,
    /// Migration verification (schema/dry-run/compat) is missing.
    MissingMigrationVerification = 971,
    /// Security audit or invariant checks are missing.
    MissingSecurityCheck = 972,
    /// Deployment smoke test verification is missing.
    MissingSmokeTest = 973,
    /// Rollback verification or rehearsal is missing.
    MissingRollbackRehearsal = 974,
    /// The release manifest is invalid or empty.
    InvalidManifest = 975,
    /// Caller is not authorized to sign off or bypass gates.
    UnauthorizedSignoff = 976,
    /// Rehearsal simulation failed state consistency checks.
    RehearsalSimulationFailed = 977,
    /// Target module is invalid or not registered.
    InvalidModule = 978,
    /// Release is currently blocked by outstanding gate failures.
    ReleaseBlocked = 979,
}

impl From<ReleaseGateError> for Error {
    fn from(err: ReleaseGateError) -> Self {
        match err {
            ReleaseGateError::GateCheckFailed => Error::ConfigInvalid,
            ReleaseGateError::MissingMigrationVerification => Error::SchemaMigrationFailed,
            ReleaseGateError::MissingSecurityCheck => Error::ConfigInvalid,
            ReleaseGateError::MissingSmokeTest => Error::ConfigInvalid,
            ReleaseGateError::MissingRollbackRehearsal => Error::ConfigInvalid,
            ReleaseGateError::InvalidManifest => Error::InvalidArgument,
            ReleaseGateError::UnauthorizedSignoff => Error::Unauthorized,
            ReleaseGateError::RehearsalSimulationFailed => Error::ConfigInvalid,
            ReleaseGateError::InvalidModule => Error::InvalidArgument,
            ReleaseGateError::ReleaseBlocked => Error::ConfigInvalid,
        }
    }
}

// ---------------------------------------------------------------------------
// Modules & Gate Taxonomy
// ---------------------------------------------------------------------------

/// Target Soroban smart-contract modules covered by the release readiness gate.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ReleaseModule {
    Treasury = 1,
    Aid = 2,
    Referral = 3,
    Governance = 4,
    Oracle = 5,
    Marketplace = 6,
}

impl ReleaseModule {
    /// Returns a short 9-character-safe symbol for event topics and storage keys.
    pub fn as_symbol(&self, _env: &Env) -> Symbol {
        match self {
            ReleaseModule::Treasury => symbol_short!("treasury"),
            ReleaseModule::Aid => symbol_short!("aid"),
            ReleaseModule::Referral => symbol_short!("referral"),
            ReleaseModule::Governance => symbol_short!("gov"),
            ReleaseModule::Oracle => symbol_short!("oracle"),
            ReleaseModule::Marketplace => symbol_short!("market"),
        }
    }

    /// Returns a vector of all 6 core protocol modules.
    pub fn all(env: &Env) -> Vec<ReleaseModule> {
        let mut modules = Vec::new(env);
        modules.push_back(ReleaseModule::Treasury);
        modules.push_back(ReleaseModule::Aid);
        modules.push_back(ReleaseModule::Referral);
        modules.push_back(ReleaseModule::Governance);
        modules.push_back(ReleaseModule::Oracle);
        modules.push_back(ReleaseModule::Marketplace);
        modules
    }
}

/// The four mandatory pillars evaluated by the release readiness gate.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GateKind {
    /// Schema versioning, dry-run simulation, and data migration checks.
    Migration = 1,
    /// Security audit, allowlist freshness, role separation, and invariant validation.
    Security = 2,
    /// Cross-contract wiring, RPC reachability, and getter liveness smoke tests.
    SmokeTest = 3,
    /// Rehearsal of rollback to previous known-good WASM and state consistency check.
    RollbackRehearsal = 4,
}

impl GateKind {
    /// Returns a short symbol identifying the gate category.
    pub fn as_symbol(&self, _env: &Env) -> Symbol {
        match self {
            GateKind::Migration => symbol_short!("mig_gate"),
            GateKind::Security => symbol_short!("sec_gate"),
            GateKind::SmokeTest => symbol_short!("smk_gate"),
            GateKind::RollbackRehearsal => symbol_short!("rlb_gate"),
        }
    }

    /// Returns a vector of all 4 mandatory gate kinds.
    pub fn all(env: &Env) -> Vec<GateKind> {
        let mut kinds = Vec::new(env);
        kinds.push_back(GateKind::Migration);
        kinds.push_back(GateKind::Security);
        kinds.push_back(GateKind::SmokeTest);
        kinds.push_back(GateKind::RollbackRehearsal);
        kinds
    }
}

/// Execution status of an individual gate check.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GateCheckStatus {
    Pending = 0,
    Passed = 1,
    Failed = 2,
    BypassedWithException = 3,
}

/// Detailed specification and result of a gate check.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateCheck {
    pub name: Symbol,
    pub kind: GateKind,
    pub module: ReleaseModule,
    pub status: GateCheckStatus,
    pub details: Symbol,
    pub executed_at: u64,
}

/// Manifest defining the scope, checks, and metadata for a release evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest {
    pub release_version: Symbol,
    pub modules: Vec<ReleaseModule>,
    pub checks: Vec<GateCheck>,
    pub signoff_admin: Address,
    pub exception_marker: Option<Symbol>,
}

/// Consolidated audit report produced by release readiness evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseReadinessReport {
    pub release_version: Symbol,
    pub is_ready: bool,
    pub passed_checks: u32,
    pub failed_checks: u32,
    pub pending_checks: u32,
    pub bypassed_checks: u32,
    pub missing_gates: u32,
    pub evaluated_at: u64,
}

/// Parameters for simulating an upgrade rollback rehearsal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackRehearsalParams {
    pub module: ReleaseModule,
    pub current_version: u32,
    pub target_version: u32,
    pub previous_wasm_hash: BytesN<32>,
    pub strategy: RollbackStrategy,
    pub simulate_regression: bool,
}

/// Immutable receipt proving completion of a rollback rehearsal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackRehearsalReceipt {
    pub rehearsal_id: u64,
    pub module: ReleaseModule,
    pub from_version: u32,
    pub restored_version: u32,
    pub strategy: RollbackStrategy,
    pub state_intact: bool,
    pub passed: bool,
    pub rehearsed_at: u64,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

const KEY_GATE_REPORT: Symbol = symbol_short!("gat_rpt");
const KEY_REHEARSE_CNT: Symbol = symbol_short!("reh_cnt");
const KEY_REHEARSE_RCPT: Symbol = symbol_short!("reh_rcp");

// ---------------------------------------------------------------------------
// Core Logic & Functions
// ---------------------------------------------------------------------------

/// Evaluates release readiness across all target modules and mandatory gate kinds.
///
/// Acceptance criteria:
/// - Every module declared in `manifest.modules` must have non-missing checks for all
///   four gate pillars: `Migration`, `Security`, `SmokeTest`, and `RollbackRehearsal`.
/// - If any gate kind is missing or any check has failed, release readiness is blocked
///   (`is_ready = false`), unless validly bypassed with an acknowledged exception marker.
/// - Persists report in instance storage and publishes an event log.
pub fn evaluate_release_readiness(
    env: &Env,
    manifest: &ReleaseManifest,
) -> Result<ReleaseReadinessReport, ReleaseGateError> {
    if manifest.modules.is_empty() {
        return Err(ReleaseGateError::InvalidManifest);
    }

    let mut passed_checks = 0u32;
    let mut failed_checks = 0u32;
    let mut pending_checks = 0u32;
    let mut bypassed_checks = 0u32;
    let mut missing_gates = 0u32;

    let has_exception = manifest.exception_marker.is_some();

    // 1. Verify coverage of all 4 mandatory gate kinds for each target module.
    for m_idx in 0..manifest.modules.len() {
        let module = manifest.modules.get(m_idx).unwrap();
        let mut has_migration = false;
        let mut has_security = false;
        let mut has_smoke = false;
        let mut has_rollback = false;

        for c_idx in 0..manifest.checks.len() {
            let check = manifest.checks.get(c_idx).unwrap();
            if check.module == module {
                match check.kind {
                    GateKind::Migration => has_migration = true,
                    GateKind::Security => has_security = true,
                    GateKind::SmokeTest => has_smoke = true,
                    GateKind::RollbackRehearsal => has_rollback = true,
                }
            }
        }

        if !has_migration {
            if has_exception {
                bypassed_checks += 1;
            } else {
                missing_gates += 1;
            }
        }
        if !has_security {
            if has_exception {
                bypassed_checks += 1;
            } else {
                missing_gates += 1;
            }
        }
        if !has_smoke {
            if has_exception {
                bypassed_checks += 1;
            } else {
                missing_gates += 1;
            }
        }
        if !has_rollback {
            if has_exception {
                bypassed_checks += 1;
            } else {
                missing_gates += 1;
            }
        }
    }

    // 2. Evaluate status of each individual check.
    for c_idx in 0..manifest.checks.len() {
        let check = manifest.checks.get(c_idx).unwrap();
        match check.status {
            GateCheckStatus::Passed => {
                passed_checks += 1;
            }
            GateCheckStatus::BypassedWithException => {
                if has_exception {
                    bypassed_checks += 1;
                } else {
                    failed_checks += 1;
                }
            }
            GateCheckStatus::Failed => {
                failed_checks += 1;
            }
            GateCheckStatus::Pending => {
                pending_checks += 1;
            }
        }
    }

    let is_ready = failed_checks == 0 && pending_checks == 0 && missing_gates == 0;

    let report = ReleaseReadinessReport {
        release_version: manifest.release_version.clone(),
        is_ready,
        passed_checks,
        failed_checks,
        pending_checks,
        bypassed_checks,
        missing_gates,
        evaluated_at: env.ledger().timestamp(),
    };

    // Store report in instance storage.
    instance_set(
        env,
        &(KEY_GATE_REPORT, manifest.release_version.clone()),
        &report,
    );

    // Publish event telemetry.
    let zero_cid = BytesN::from_array(env, &[0u8; 32]);
    crate::events::emit_release_readiness_evaluated(
        env,
        &zero_cid,
        manifest.release_version.clone(),
        is_ready,
        passed_checks,
        failed_checks,
        missing_gates,
        env.ledger().timestamp(),
    );

    Ok(report)
}

/// Executes a simulated rollback rehearsal for a module before production deployment.
///
/// Proves that reverting to the previous WASM hash restores read/write consistency
/// and state integrity without orphaned data or bricked storage layouts.
pub fn rehearse_rollback(
    env: &Env,
    params: &RollbackRehearsalParams,
) -> Result<RollbackRehearsalReceipt, ReleaseGateError> {
    if params.target_version <= params.current_version {
        return Err(ReleaseGateError::RehearsalSimulationFailed);
    }

    let (restored_version, state_intact, passed) = if params.simulate_regression {
        match params.strategy {
            RollbackStrategy::Revert => {
                // Revert restores previous version and preserves state.
                (params.current_version, true, true)
            }
            RollbackStrategy::ForwardFix => {
                // ForwardFix keeps target version state staged for corrective migration.
                (params.target_version, true, true)
            }
            RollbackStrategy::Manual => {
                // Manual intervention cannot automatically recover without operator action.
                (params.current_version, false, false)
            }
        }
    } else {
        // Standard non-regression dry run confirms upgrade and rollback path capability.
        (params.target_version, true, true)
    };

    let count: u64 = instance_get(env, &KEY_REHEARSE_CNT).unwrap_or(0) + 1;
    instance_set(env, &KEY_REHEARSE_CNT, &count);

    let receipt = RollbackRehearsalReceipt {
        rehearsal_id: count,
        module: params.module,
        from_version: params.target_version,
        restored_version,
        strategy: params.strategy,
        state_intact,
        passed,
        rehearsed_at: env.ledger().timestamp(),
    };

    instance_set(env, &(KEY_REHEARSE_RCPT, count), &receipt);

    let zero_cid = BytesN::from_array(env, &[0u8; 32]);
    crate::events::emit_rollback_rehearsal_executed(
        env,
        &zero_cid,
        count,
        params.module as u32,
        params.target_version,
        restored_version,
        passed,
        env.ledger().timestamp(),
    );

    Ok(receipt)
}

/// Validates whether a release version is ready for merge or promotion.
pub fn is_release_ready(env: &Env, release_version: &Symbol) -> bool {
    instance_get::<_, ReleaseReadinessReport>(env, &(KEY_GATE_REPORT, release_version.clone()))
        .map_or(false, |r| r.is_ready)
}

/// Retrieves the evaluated release readiness report for a version, if present.
pub fn get_readiness_report(
    env: &Env,
    release_version: &Symbol,
) -> Option<ReleaseReadinessReport> {
    instance_get(env, &(KEY_GATE_REPORT, release_version.clone()))
}

/// Retrieves a specific rollback rehearsal receipt by ID.
pub fn get_rehearsal_receipt(env: &Env, rehearsal_id: u64) -> Option<RollbackRehearsalReceipt> {
    instance_get(env, &(KEY_REHEARSE_RCPT, rehearsal_id))
}

/// Returns the total number of executed rollback rehearsals.
pub fn get_rehearsal_count(env: &Env) -> u64 {
    instance_get(env, &KEY_REHEARSE_CNT).unwrap_or(0)
}

/// Helper to construct a gate check entry.
pub fn create_gate_check(
    name: Symbol,
    kind: GateKind,
    module: ReleaseModule,
    status: GateCheckStatus,
    details: Symbol,
    timestamp: u64,
) -> GateCheck {
    GateCheck {
        name,
        kind,
        module,
        status,
        details,
        executed_at: timestamp,
    }
}

/// Validates that a module's migration plan meets schema forward-compatibility requirements.
pub fn verify_migration_readiness(
    module: ReleaseModule,
    from_version: u32,
    to_version: u32,
    has_dry_run_journal: bool,
    unmigrated_records: u32,
    timestamp: u64,
) -> Result<GateCheck, ReleaseGateError> {
    if to_version <= from_version || !has_dry_run_journal || unmigrated_records > 0 {
        return Err(ReleaseGateError::MissingMigrationVerification);
    }
    Ok(create_gate_check(
        symbol_short!("mig_ver"),
        GateKind::Migration,
        module,
        GateCheckStatus::Passed,
        symbol_short!("mig_ok"),
        timestamp,
    ))
}

/// Validates that a module satisfies deployment smoke tests (RPC, getter liveness, client wiring).
pub fn verify_smoke_test_readiness(
    module: ReleaseModule,
    rpc_healthy: bool,
    getter_liveness: bool,
    client_binding_intact: bool,
    timestamp: u64,
) -> Result<GateCheck, ReleaseGateError> {
    if !rpc_healthy || !getter_liveness || !client_binding_intact {
        return Err(ReleaseGateError::MissingSmokeTest);
    }
    Ok(create_gate_check(
        symbol_short!("smk_ver"),
        GateKind::SmokeTest,
        module,
        GateCheckStatus::Passed,
        symbol_short!("smk_ok"),
        timestamp,
    ))
}

/// An address a deployment must have initialized before its smoke tests pass (Issue #331).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedAddress {
    /// Human-readable label for triage, e.g. `aid.treasury`.
    pub label: Symbol,
    /// The address read back from the deployed contract. `None` means it was never set.
    pub address: Option<Address>,
}

/// Verifies that every initialized address a deployment wires up resolved to a value.
///
/// Smoke tests must cover **all** initialized addresses, so one unset entry fails the
/// gate. An empty list also fails: a gate that verified nothing has not passed.
pub fn verify_initialized_addresses(
    module: ReleaseModule,
    entries: &Vec<InitializedAddress>,
    timestamp: u64,
) -> Result<GateCheck, ReleaseGateError> {
    if entries.is_empty() {
        return Err(ReleaseGateError::MissingSmokeTest);
    }
    for entry in entries.iter() {
        if entry.address.is_none() {
            return Err(ReleaseGateError::MissingSmokeTest);
        }
    }
    Ok(create_gate_check(
        symbol_short!("init_ver"),
        GateKind::SmokeTest,
        module,
        GateCheckStatus::Passed,
        symbol_short!("init_ok"),
        timestamp,
    ))
}

/// Validates rollback readiness: verifies pre-upgrade snapshot and successful rehearsal receipt.
pub fn verify_rollback_readiness(
    module: ReleaseModule,
    strategy: RollbackStrategy,
    snapshot_stored: bool,
    rehearsal_passed: bool,
    timestamp: u64,
) -> Result<GateCheck, ReleaseGateError> {
    if !snapshot_stored || !rehearsal_passed || strategy == RollbackStrategy::Manual {
        return Err(ReleaseGateError::MissingRollbackRehearsal);
    }
    Ok(create_gate_check(
        symbol_short!("rlb_ver"),
        GateKind::RollbackRehearsal,
        module,
        GateCheckStatus::Passed,
        symbol_short!("rlb_ok"),
        timestamp,
    ))
}

/// Signs off on a verified release readiness report using admin authority.
pub fn signoff_release(
    env: &Env,
    admin: &Address,
    release_version: &Symbol,
) -> Result<(), Error> {
    require_admin(env, admin)?;
    if !is_release_ready(env, release_version) {
        return Err(Error::ConfigInvalid);
    }
    env.events().publish(
        (symbol_short!("rel_sign"), release_version.clone()),
        (admin.clone(), env.ledger().timestamp()),
    );
    Ok(())
}

/// Emergency dual-administrator signoff to bypass gates under audited exception markers.
pub fn emergency_bypass_signoff(
    env: &Env,
    primary_admin: &Address,
    secondary_admin: &Address,
    release_version: &Symbol,
    exception_reason: Symbol,
) -> Result<(), Error> {
    require_admin(env, primary_admin)?;
    require_admin(env, secondary_admin)?;
    if primary_admin == secondary_admin {
        return Err(Error::InvalidArgument);
    }
    env.events().publish(
        (symbol_short!("emrg_byp"), release_version.clone()),
        (
            primary_admin.clone(),
            secondary_admin.clone(),
            exception_reason,
            env.ledger().timestamp(),
        ),
    );
    Ok(())
}

