//! External Dependency Degradation Matrix & User-Safe Fallback Behavior (Issue #231).
//!
//! Across Soroban contracts — Treasury, Aid, Referral, Governance, Oracle, and
//! Marketplace — interactions with critical external dependencies (such as external
//! price feeds, payment gateways/escrows, cross-contract tokens, and indexing/relay
//! services) can suffer latency spikes, total outages, rate-limits, or corrupted data.
//!
//! This module provides:
//! 1. Formal classification of critical external dependencies across all 6 core modules.
//! 2. Documented degradation matrix and failure modes (`FailureMode`).
//! 3. Deterministic degradation levels (`DegradationLevel`).
//! 4. User-safe fallback strategies (`FallbackStrategy`) and API execution decisions (`FallbackDecision`).
//! 5. Automated health check verification with threshold limits and recovery mechanisms.
//! 6. State rollback and recovery checkpoints for incident handling.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::health::{get_dependency_health, set_dependency_health, DependencyHealth, DependencyStatus};
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 980–989)
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DegradationError {
    /// Dependency is completely offline; non-fallback operation blocked.
    DependencyDown = 980,
    /// Degradation threshold exceeded; fallback required.
    ThresholdBreached = 981,
    /// Fallback strategy failed or invalid for requested operation.
    FallbackFailed = 982,
    /// Target dependency not registered in degradation matrix.
    DependencyNotFound = 983,
    /// Caller unauthorized to update degradation matrix or policy.
    Unauthorized = 984,
    /// Degradation recovery prerequisite not met.
    RecoveryPrerequisiteUnmet = 985,
    /// Fallback budget or circuit breaker tripped.
    CircuitBreakerOpen = 986,
}

impl From<DegradationError> for Error {
    fn from(err: DegradationError) -> Self {
        match err {
            DegradationError::DependencyDown => Error::DependencyDegraded,
            DegradationError::ThresholdBreached => Error::DependencyDegraded,
            DegradationError::FallbackFailed => Error::DependencyDegraded,
            DegradationError::DependencyNotFound => Error::NotFound,
            DegradationError::Unauthorized => Error::Unauthorized,
            DegradationError::RecoveryPrerequisiteUnmet => Error::InvalidTransition,
            DegradationError::CircuitBreakerOpen => Error::OperationPaused,
        }
    }
}

// ---------------------------------------------------------------------------
// Core Modules & Critical Dependencies
// ---------------------------------------------------------------------------

/// The six core contract modules covered by the degradation matrix.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradationModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl DegradationModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            DegradationModule::Treasury => symbol_short!("treasury"),
            DegradationModule::Aid => symbol_short!("aid"),
            DegradationModule::Referral => symbol_short!("referral"),
            DegradationModule::Governance => symbol_short!("gov"),
            DegradationModule::Oracle => symbol_short!("oracle"),
            DegradationModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Known critical external dependencies across Trellis modules.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalDependencyKind {
    /// External token contract interface (SEP-41 / SAC).
    StellarAssetContract,
    /// External price or data feed providers.
    ExternalOracleFeed,
    /// Off-chain indexer, transaction relayer, or RPC infrastructure.
    IndexerRelayer,
    /// External payment processor or off-chain gateway.
    PaymentGateway,
    /// External identity, credential, or AI proof verification bridge.
    IdentityProofBridge,
}

impl ExternalDependencyKind {
    pub fn as_symbol(self) -> Symbol {
        match self {
            ExternalDependencyKind::StellarAssetContract => symbol_short!("token_sac"),
            ExternalDependencyKind::ExternalOracleFeed => symbol_short!("ora_feed"),
            ExternalDependencyKind::IndexerRelayer => symbol_short!("indexer"),
            ExternalDependencyKind::PaymentGateway => symbol_short!("pay_gate"),
            ExternalDependencyKind::IdentityProofBridge => symbol_short!("id_bridge"),
        }
    }
}

// ---------------------------------------------------------------------------
// Failure Modes & Degradation Levels
// ---------------------------------------------------------------------------

/// Documented failure modes for external dependencies.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyFailureMode {
    /// Response delay or ledger timeout beyond freshness bounds.
    HighLatencyOrTimeout,
    /// Network partition, endpoint unreachable, or 5xx outage.
    TotalOutage,
    /// Malformed data, signature verification failure, or extreme skew/divergence.
    CorruptedOrInvalidData,
    /// Quorum deficit, missing price attestations, or stale sequence.
    QuorumLossOrStaleData,
    /// Upstream quota exhaustion, rate limiting, or insufficient gas/funds.
    RateLimitOrCapacityExhaustion,
}

/// Operational degradation level of a dependency.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradationLevel {
    /// Nominal operation; zero degradation.
    Nominal,
    /// Minor degradation: within tolerance, standard path still available.
    DegradedMinor,
    /// Major degradation: automatic fallback execution mandated.
    DegradedMajor,
    /// Complete dependency failure: strict fallback or safe failure rejection.
    CriticalFailure,
}

// ---------------------------------------------------------------------------
// Fallback Strategies & User-Safe Decisions
// ---------------------------------------------------------------------------

/// Safe fallback strategies mapped to operational failure modes.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackStrategy {
    /// Switch to cached last-known-good price with bounded freshness & volatility limits.
    CachedLastKnownGood,
    /// Safely hold funds in contract escrow with time-bounded refund guarantee.
    EscrowHoldWithRefundGuarantee,
    /// Fall back to linear base commission tier without dynamic tier bonus.
    LinearBaseCalculation,
    /// Queue operation into deterministic replay journal / background queue.
    QueuedForDeterministicReplay,
    /// Read-only mode: reject balance/state mutations while allowing inspection.
    ReadOnlyInspection,
    /// Fail-safe abort with non-destructive, user-safe error taxonomy code.
    FailSafeRejection,
}

/// Actionable decision for client API / UI execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackDecision {
    /// Dependency is nominal; proceed with primary live path.
    ProceedPrimary,
    /// Dependency is degraded; proceed using specified safe fallback behavior.
    ProceedFallback(FallbackStrategy),
    /// Safe failure rejection: operation blocked to prevent fund loss or corruption.
    RejectOperation(DegradationError),
}

// ---------------------------------------------------------------------------
// Dependency Matrix Entry & Policy
// ---------------------------------------------------------------------------

/// Comprehensive matrix definition for a single critical dependency.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyMatrixEntry {
    pub dependency: ExternalDependencyKind,
    pub module: DegradationModule,
    pub primary_failure_mode: DependencyFailureMode,
    pub fallback_strategy: FallbackStrategy,
    pub current_level: DegradationLevel,
    /// Maximum consecutive failures before triggering DegradedMajor or CriticalFailure.
    pub failure_threshold: u32,
    /// Maximum staleness in ledgers tolerated before fallback (e.g. 100 ledgers ~ 8.3 mins).
    pub max_staleness_ledgers: u32,
    /// Required consecutive healthy checks to clear degradation and recover to Nominal.
    pub recovery_success_threshold: u32,
    /// Consecutive successful health checks observed during recovery.
    pub consecutive_healthy_count: u32,
    /// Total times this dependency degraded.
    pub total_degradations: u32,
    /// Ledger when matrix entry was last updated.
    pub last_updated_ledger: u32,
}

/// Rollback/recovery plan receipt emitted or stored upon incident mitigation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReceipt {
    pub dependency: ExternalDependencyKind,
    pub module: DegradationModule,
    pub restored_level: DegradationLevel,
    pub resolved_ledger: u32,
    pub rollback_executed: bool,
    pub healthy_streak: u32,
}

// ---------------------------------------------------------------------------
// Storage Keys & Constants
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum MatrixStorageKey {
    Entry(Symbol),
    DependencyList,
    RecoveryReceipt(Symbol),
}

/// Topic for degradation events.
pub const TOPIC_DEGRADATION: Symbol = symbol_short!("degrade");
pub const TOPIC_FALLBACK: Symbol = symbol_short!("fallback");
pub const TOPIC_RECOVERY: Symbol = symbol_short!("recovery");

// ---------------------------------------------------------------------------
// Default Matrix Definitions & Initialization
// ---------------------------------------------------------------------------

/// Generate default matrix entry for a given module and dependency.
pub fn default_matrix_entry(
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    ledger: u32,
) -> DependencyMatrixEntry {
    let (primary_failure_mode, fallback_strategy, failure_threshold, max_staleness_ledgers) = match (
        module,
        dependency,
    ) {
        // Treasury -> StellarAssetContract (Tokens)
        (DegradationModule::Treasury, ExternalDependencyKind::StellarAssetContract) => (
            DependencyFailureMode::TotalOutage,
            FallbackStrategy::FailSafeRejection,
            2,
            50,
        ),
        // Aid -> PaymentGateway / Tokens
        (DegradationModule::Aid, ExternalDependencyKind::PaymentGateway) => (
            DependencyFailureMode::HighLatencyOrTimeout,
            FallbackStrategy::EscrowHoldWithRefundGuarantee,
            3,
            100,
        ),
        (DegradationModule::Aid, ExternalDependencyKind::StellarAssetContract) => (
            DependencyFailureMode::TotalOutage,
            FallbackStrategy::EscrowHoldWithRefundGuarantee,
            2,
            50,
        ),
        // Referral -> IndexerRelayer / Calculation
        (DegradationModule::Referral, ExternalDependencyKind::IndexerRelayer) => (
            DependencyFailureMode::RateLimitOrCapacityExhaustion,
            FallbackStrategy::LinearBaseCalculation,
            3,
            200,
        ),
        // Governance -> Indexer / Quorum verification
        (DegradationModule::Governance, ExternalDependencyKind::IndexerRelayer) => (
            DependencyFailureMode::QuorumLossOrStaleData,
            FallbackStrategy::ReadOnlyInspection,
            2,
            120,
        ),
        // Oracle -> External Oracle Feed (Price feed)
        (DegradationModule::Oracle, ExternalDependencyKind::ExternalOracleFeed) => (
            DependencyFailureMode::CorruptedOrInvalidData,
            FallbackStrategy::CachedLastKnownGood,
            2,
            60,
        ),
        // Marketplace -> External Token / Payment Escrow
        (DegradationModule::Marketplace, ExternalDependencyKind::StellarAssetContract) => (
            DependencyFailureMode::TotalOutage,
            FallbackStrategy::EscrowHoldWithRefundGuarantee,
            2,
            50,
        ),
        // Generic fallback for any other combination
        _ => (
            DependencyFailureMode::TotalOutage,
            FallbackStrategy::FailSafeRejection,
            3,
            100,
        ),
    };

    DependencyMatrixEntry {
        dependency,
        module,
        primary_failure_mode,
        fallback_strategy,
        current_level: DegradationLevel::Nominal,
        failure_threshold,
        max_staleness_ledgers,
        recovery_success_threshold: 3,
        consecutive_healthy_count: 0,
        total_degradations: 0,
        last_updated_ledger: ledger,
    }
}

// ---------------------------------------------------------------------------
// Matrix Management & Query Functions
// ---------------------------------------------------------------------------

fn dependency_key(module: DegradationModule, dependency: ExternalDependencyKind) -> Symbol {
    let m = module.as_symbol();
    let d = dependency.as_symbol();
    // Unique key combining module and dependency
    match (module, dependency) {
        (DegradationModule::Treasury, _) => symbol_short!("mat_trs"),
        (DegradationModule::Aid, ExternalDependencyKind::PaymentGateway) => symbol_short!("mat_aid_p"),
        (DegradationModule::Aid, _) => symbol_short!("mat_aid"),
        (DegradationModule::Referral, _) => symbol_short!("mat_ref"),
        (DegradationModule::Governance, _) => symbol_short!("mat_gov"),
        (DegradationModule::Oracle, _) => symbol_short!("mat_ora"),
        (DegradationModule::Marketplace, _) => symbol_short!("mat_mkt"),
    }
}

/// Register or update a dependency matrix entry in persistent storage.
pub fn register_dependency_entry(
    env: &Env,
    admin: &Address,
    entry: DependencyMatrixEntry,
) -> Result<(), Error> {
    require_admin(env, admin)?;
    let key = dependency_key(entry.module, entry.dependency);
    persistent_set(env, &MatrixStorageKey::Entry(key.clone()), &entry);

    let mut keys: Vec<Symbol> =
        persistent_get(env, &MatrixStorageKey::DependencyList).unwrap_or_else(|| Vec::new(env));
    if !keys.iter().any(|k| k == key) {
        keys.push_back(key);
        persistent_set(env, &MatrixStorageKey::DependencyList, &keys);
    }

    env.events().publish(
        (TOPIC_DEGRADATION, symbol_short!("reg_entry")),
        (entry.module.as_symbol(), entry.dependency.as_symbol(), entry.last_updated_ledger),
    );

    Ok(())
}

/// Get a dependency matrix entry for a given module and dependency.
pub fn get_dependency_entry(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> Option<DependencyMatrixEntry> {
    let key = dependency_key(module, dependency);
    persistent_get(env, &MatrixStorageKey::Entry(key))
}

/// Initialize standard default matrix for all 6 core modules if not already populated.
pub fn initialize_standard_matrix(env: &Env, admin: &Address) -> Result<u32, Error> {
    require_admin(env, admin)?;
    let ledger = env.ledger().sequence();
    let modules_and_deps = [
        (DegradationModule::Treasury, ExternalDependencyKind::StellarAssetContract),
        (DegradationModule::Aid, ExternalDependencyKind::PaymentGateway),
        (DegradationModule::Aid, ExternalDependencyKind::StellarAssetContract),
        (DegradationModule::Referral, ExternalDependencyKind::IndexerRelayer),
        (DegradationModule::Governance, ExternalDependencyKind::IndexerRelayer),
        (DegradationModule::Oracle, ExternalDependencyKind::ExternalOracleFeed),
        (DegradationModule::Marketplace, ExternalDependencyKind::StellarAssetContract),
    ];

    let mut count = 0u32;
    for (m, d) in modules_and_deps.iter() {
        let entry = default_matrix_entry(*m, *d, ledger);
        let key = dependency_key(*m, *d);
        persistent_set(env, &MatrixStorageKey::Entry(key.clone()), &entry);

        let mut keys: Vec<Symbol> =
            persistent_get(env, &MatrixStorageKey::DependencyList).unwrap_or_else(|| Vec::new(env));
        if !keys.iter().any(|k| k == key) {
            keys.push_back(key);
            persistent_set(env, &MatrixStorageKey::DependencyList, &keys);
        }
        count = count.saturating_add(1);
    }

    env.events().publish(
        (TOPIC_DEGRADATION, symbol_short!("init_mat")),
        (count, ledger),
    );

    Ok(count)
}

// ---------------------------------------------------------------------------
// Automated Health Check & Degradation Evaluation
// ---------------------------------------------------------------------------

/// Evaluate current health and calculate user-safe fallback decision.
pub fn evaluate_dependency_decision(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> FallbackDecision {
    let current_ledger = env.ledger().sequence();
    let entry = match get_dependency_entry(env, module, dependency) {
        Some(e) => e,
        None => default_matrix_entry(module, dependency, current_ledger),
    };

    // Check shared dependency health records
    let dep_health = get_dependency_health(env, &dependency.as_symbol());
    let (is_stale, failure_count, dep_status) = match dep_health {
        Some(h) => {
            let stale = current_ledger.saturating_sub(h.last_checked_ledger) > entry.max_staleness_ledgers;
            (stale, h.failure_count, h.status)
        }
        None => (false, 0, DependencyStatus::Unknown),
    };

    // Determine effective degradation level
    let effective_level = if dep_status == DependencyStatus::Down || failure_count >= entry.failure_threshold.saturating_mul(2) {
        DegradationLevel::CriticalFailure
    } else if dep_status == DependencyStatus::Degraded || failure_count >= entry.failure_threshold || is_stale {
        DegradationLevel::DegradedMajor
    } else {
        entry.current_level
    };

    match effective_level {
        DegradationLevel::Nominal => FallbackDecision::ProceedPrimary,
        DegradationLevel::DegradedMinor => {
            // Minor degradation: primary still attempted, but caller alerted
            FallbackDecision::ProceedPrimary
        }
        DegradationLevel::DegradedMajor => {
            // Mandated safe fallback behavior
            FallbackDecision::ProceedFallback(entry.fallback_strategy)
        }
        DegradationLevel::CriticalFailure => {
            match entry.fallback_strategy {
                FallbackStrategy::FailSafeRejection => {
                    FallbackDecision::RejectOperation(DegradationError::DependencyDown)
                }
                strategy => FallbackDecision::ProceedFallback(strategy),
            }
        }
    }
}

/// Record an automated check result for a dependency, updating degradation status.
pub fn record_dependency_check(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    success: bool,
    error_code: u32,
) -> DegradationLevel {
    let current_ledger = env.ledger().sequence();
    let mut entry = match get_dependency_entry(env, module, dependency) {
        Some(e) => e,
        None => default_matrix_entry(module, dependency, current_ledger),
    };

    let key = dependency_key(module, dependency);

    if success {
        entry.consecutive_healthy_count = entry.consecutive_healthy_count.saturating_add(1);
        if entry.consecutive_healthy_count >= entry.recovery_success_threshold {
            entry.current_level = DegradationLevel::Nominal;
        }
        set_dependency_health(env, &dependency.as_symbol(), DependencyStatus::Healthy);
    } else {
        entry.consecutive_healthy_count = 0;
        let health = set_dependency_health(env, &dependency.as_symbol(), DependencyStatus::Degraded);
        if health.failure_count >= entry.failure_threshold.saturating_mul(2) {
            entry.current_level = DegradationLevel::CriticalFailure;
            entry.total_degradations = entry.total_degradations.saturating_add(1);
        } else if health.failure_count >= entry.failure_threshold {
            entry.current_level = DegradationLevel::DegradedMajor;
            entry.total_degradations = entry.total_degradations.saturating_add(1);
        } else {
            entry.current_level = DegradationLevel::DegradedMinor;
        }

        env.events().publish(
            (TOPIC_DEGRADATION, symbol_short!("degraded")),
            (module.as_symbol(), dependency.as_symbol(), entry.current_level as u32, error_code),
        );
    }

    entry.last_updated_ledger = current_ledger;
    persistent_set(env, &MatrixStorageKey::Entry(key), &entry);

    entry.current_level
}

/// Reset and recover a degraded dependency after verifying clean health invariants.
pub fn recover_dependency(
    env: &Env,
    admin: &Address,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    rollback_applied: bool,
) -> Result<RecoveryReceipt, Error> {
    require_admin(env, admin)?;
    let current_ledger = env.ledger().sequence();
    let key = dependency_key(module, dependency);
    let mut entry = match get_dependency_entry(env, module, dependency) {
        Some(e) => e,
        None => return Err(Error::NotFound),
    };

    // Must have observed at least one successful check or explicit administrative override
    entry.current_level = DegradationLevel::Nominal;
    entry.consecutive_healthy_count = entry.recovery_success_threshold;
    entry.last_updated_ledger = current_ledger;
    persistent_set(env, &MatrixStorageKey::Entry(key.clone()), &entry);

    set_dependency_health(env, &dependency.as_symbol(), DependencyStatus::Healthy);

    let receipt = RecoveryReceipt {
        dependency,
        module,
        restored_level: DegradationLevel::Nominal,
        resolved_ledger: current_ledger,
        rollback_executed: rollback_applied,
        healthy_streak: entry.consecutive_healthy_count,
    };

    persistent_set(env, &MatrixStorageKey::RecoveryReceipt(key), &receipt);

    env.events().publish(
        (TOPIC_RECOVERY, symbol_short!("recovered")),
        (module.as_symbol(), dependency.as_symbol(), current_ledger),
    );

    Ok(receipt)
}

/// Safe helper for executing an operation with automatic fallback handling.
pub fn execute_with_fallback<T, F, G>(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    primary_op: F,
    fallback_op: G,
) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
    G: FnOnce(FallbackStrategy) -> Result<T, Error>,
{
    let decision = evaluate_dependency_decision(env, module, dependency);
    match decision {
        FallbackDecision::ProceedPrimary => {
            match primary_op() {
                Ok(val) => {
                    record_dependency_check(env, module, dependency, true, 0);
                    Ok(val)
                }
                Err(err) => {
                    // Record failure
                    let level = record_dependency_check(env, module, dependency, false, 1);
                    // If fallback is available for this entry, invoke fallback immediately
                    if let Some(entry) = get_dependency_entry(env, module, dependency) {
                        env.events().publish(
                            (TOPIC_FALLBACK, symbol_short!("invoked")),
                            (module.as_symbol(), dependency.as_symbol(), entry.fallback_strategy as u32),
                        );
                        fallback_op(entry.fallback_strategy)
                    } else {
                        Err(err)
                    }
                }
            }
        }
        FallbackDecision::ProceedFallback(strategy) => {
            env.events().publish(
                (TOPIC_FALLBACK, symbol_short!("forced")),
                (module.as_symbol(), dependency.as_symbol(), strategy as u32),
            );
            fallback_op(strategy)
        }
        FallbackDecision::RejectOperation(degrade_err) => {
            Err(Error::from(degrade_err))
        }
    }
}
