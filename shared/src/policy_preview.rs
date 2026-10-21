//! Policy Simulation Preview Framework for Irreversible or High-Impact Changes (Issue #250).
//!
//! Across Trellis Soroban contracts — Treasury, Aid, Referral, Governance, Oracle,
//! and Marketplace — maintainers frequently need to update operational rules,
//! risk parameters, limits, fees, and feature configurations.
//!
//! Because some policy changes are irreversible or carry high systemic blast radius
//! (such as lowering treasury withdrawal limits, tightening aid recipient eligibility,
//! altering referral reward tiers, updating governance voting quorums, modifying oracle
//! price variance bands, or adjusting marketplace fees), maintainers need to preview:
//! 1. **Affected Records and Users**: Counts and categorical breakdowns of actors/records impacted.
//! 2. **Expected Side Effects**: Operational consequences (e.g. pending claims invalidated,
//!    in-flight proposals failed, fee increases, or volume throttling).
//! 3. **Rollback Constraints**: Whether the proposed policy change can be cleanly rolled back,
//!    what state invariants must be preserved, and whether dual-maintainer signoff is mandated.
//! 4. **Safe Commit Guard**: Ensures irreversible or high-impact policies cannot be applied
//!    unless an authorized simulation preview has been generated and validated.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 990–999)
// ---------------------------------------------------------------------------

/// Policy simulation preview errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PolicySimulationError {
    /// Target policy configuration is structurally invalid or out of bounds.
    InvalidPolicyConfig = 990,
    /// Simulation preview expired or sequence is stale.
    SimulationPreviewExpired = 991,
    /// Simulation preview hash or signature does not match proposed policy.
    SimulationMismatch = 992,
    /// Policy change is high impact and requires dual-maintainer signoff.
    DualSignoffRequired = 993,
    /// Policy change violates immutable protocol safety invariants.
    InvariantViolation = 994,
    /// Policy cannot be safely rolled back under observed state constraints.
    IrreversibleChangeBlocked = 995,
    /// Caller is not authorized to simulate or commit policy changes.
    Unauthorized = 996,
}

impl From<PolicySimulationError> for Error {
    fn from(err: PolicySimulationError) -> Self {
        match err {
            PolicySimulationError::InvalidPolicyConfig => Error::ConfigInvalid,
            PolicySimulationError::SimulationPreviewExpired => Error::ActionExpired,
            PolicySimulationError::SimulationMismatch => Error::InvalidArgument,
            PolicySimulationError::DualSignoffRequired => Error::Unauthorized,
            PolicySimulationError::InvariantViolation => Error::ConfigInvalid,
            PolicySimulationError::IrreversibleChangeBlocked => Error::ConfigInvalid,
            PolicySimulationError::Unauthorized => Error::Unauthorized,
        }
    }
}

// ---------------------------------------------------------------------------
// Core Modules & Policy Scope
// ---------------------------------------------------------------------------

/// The six core contract modules covered by policy simulation preview.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl PolicyModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            PolicyModule::Treasury => symbol_short!("treasury"),
            PolicyModule::Aid => symbol_short!("aid"),
            PolicyModule::Referral => symbol_short!("referral"),
            PolicyModule::Governance => symbol_short!("gov"),
            PolicyModule::Oracle => symbol_short!("oracle"),
            PolicyModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Specific type of policy being altered.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyType {
    /// Treasury withdrawal and reserve limits.
    TreasuryLimits,
    /// Aid disbursement, claim caps, and eligibility criteria.
    AidDisbursement,
    /// Referral tier thresholds and commission basis points.
    ReferralCommission,
    /// Governance voting quorum and execution delay periods.
    GovernanceQuorum,
    /// Oracle price variance threshold and freshness window.
    OracleVarianceBounds,
    /// Marketplace fee bps, auto-extension window, and royalty bounds.
    MarketplaceFeeSchedule,
}

/// Impact severity level of the proposed policy modification.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyImpactSeverity {
    /// Low impact: minor tuning, fully reversible with zero stranded records.
    Low,
    /// Medium impact: affects future operations, existing records remain valid.
    Medium,
    /// High impact: tightens limits, affects active users or in-flight operations.
    High,
    /// Critical / Irreversible: modifies invariants, drops active entitlements, or locks funds.
    Critical,
}

// ---------------------------------------------------------------------------
// Concrete Module Policy Payloads
// ---------------------------------------------------------------------------

/// Universal container for typed policy parameters across modules.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyParameters {
    /// Primary numeric threshold (e.g. max_amount, commission_bps, quorum_bps, fee_bps).
    pub primary_limit: i128,
    /// Secondary numeric threshold (e.g. min_amount, variance_bps, delay_ledgers).
    pub secondary_limit: i128,
    /// Rate limit or time window in ledgers.
    pub window_or_rate: u32,
    /// Maximum allowed tier or level.
    pub max_tier: u32,
    /// Geographic or regional constraint toggle.
    pub region_restriction: bool,
    /// Explicit flag indicating if this change modifies an irreversible state invariant.
    pub irreversible_flag: bool,
}

/// Proposed policy change submission.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedPolicyChange {
    pub module: PolicyModule,
    pub policy_type: PolicyType,
    pub new_params: PolicyParameters,
    /// Reason or description provided by maintainer.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Preview Details: Affected Records, Side Effects, & Rollback Constraints
// ---------------------------------------------------------------------------

/// Categories of side effects expected from policy application.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedSideEffectKind {
    /// Active claims or pending payouts will be retroactively invalidated or capped.
    ClaimsInvalidated,
    /// In-flight governance proposals may fail quorum or miss execution deadlines.
    ProposalsDisrupted,
    /// Commission rates will be reduced for active affiliates.
    CommissionsReduced,
    /// Oracle price feeds will be rejected more aggressively, increasing fallback rate.
    OracleFallbackElevated,
    /// Marketplace listings may fail settlement due to higher fee requirements.
    MarketplaceSettlementAdjusted,
    /// Withdrawal volume will be restricted for high-tier accounts.
    WithdrawalsThrottled,
    /// No adverse operational side effects detected.
    None,
}

/// One specific expected side effect report.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SideEffectSummary {
    pub kind: ExpectedSideEffectKind,
    pub severity: PolicyImpactSeverity,
    pub description: String,
}

/// Rollback constraints and feasibility assessment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackConstraintReport {
    /// True if the policy change can be safely reverted without state corruption.
    pub is_reversible: bool,
    /// Maximum ledger sequence until which clean rollback remains guaranteed.
    pub rollback_window_ledgers: u32,
    /// Requires dual maintainer signoff before commit.
    pub requires_dual_signoff: bool,
    /// State invariant preservation requirements description.
    pub invariant_constraints: String,
    /// Suggested recovery / rollback procedure summary.
    pub recovery_steps: String,
}

/// Detailed preview of the simulated policy change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySimulationPreview {
    pub preview_id: u64,
    pub module: PolicyModule,
    pub policy_type: PolicyType,
    pub severity: PolicyImpactSeverity,
    pub current_params: PolicyParameters,
    pub proposed_params: PolicyParameters,
    /// Count of active records (e.g. pending aids, escrows, listings, proposals) impacted.
    pub affected_records_count: u32,
    /// Count of active actors/users affected by limit tightening or rule alteration.
    pub affected_users_count: u32,
    /// List of expected side effects.
    pub expected_side_effects: Vec<SideEffectSummary>,
    /// Rollback feasibility, constraints, and recovery steps.
    pub rollback_constraints: RollbackConstraintReport,
    /// Ledger sequence when this simulation was generated.
    pub simulated_at_ledger: u32,
    /// Expiry ledger sequence after which preview cannot be committed.
    pub valid_until_ledger: u32,
    /// Maintainer who initiated the simulation.
    pub simulated_by: Address,
}

// ---------------------------------------------------------------------------
// Storage Keys & Active State
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum PolicyStorageKey {
    ActivePolicy(Symbol),
    SimulationPreview(u64),
    LastPreviewId,
    CommittedHistory(Symbol),
}

/// Topic for simulation and policy change events.
pub const TOPIC_POLICY_SIMULATION: Symbol = symbol_short!("pol_sim");
pub const TOPIC_POLICY_COMMIT: Symbol = symbol_short!("pol_com");
pub const TOPIC_POLICY_ROLLBACK: Symbol = symbol_short!("pol_rb");

/// Default simulation validity window (e.g. 500 ledgers ~ 41 minutes).
pub const DEFAULT_PREVIEW_VALIDITY_LEDGERS: u32 = 500;

// ---------------------------------------------------------------------------
// Core Simulation Engine
// ---------------------------------------------------------------------------

/// Returns the default baseline parameters for a given module policy type.
pub fn default_policy_parameters(policy_type: PolicyType) -> PolicyParameters {
    match policy_type {
        PolicyType::TreasuryLimits => PolicyParameters {
            primary_limit: 1_000_000_000, // max withdrawal
            secondary_limit: 1,           // min withdrawal
            window_or_rate: 50,           // max daily ops
            max_tier: 3,
            region_restriction: false,
            irreversible_flag: false,
        },
        PolicyType::AidDisbursement => PolicyParameters {
            primary_limit: 500_000_000,
            secondary_limit: 10,
            window_or_rate: 100,
            max_tier: 2,
            region_restriction: true,
            irreversible_flag: false,
        },
        PolicyType::ReferralCommission => PolicyParameters {
            primary_limit: 500, // 5% base commission bps
            secondary_limit: 1000, // 10% top tier commission bps
            window_or_rate: 10,
            max_tier: 3,
            region_restriction: false,
            irreversible_flag: false,
        },
        PolicyType::GovernanceQuorum => PolicyParameters {
            primary_limit: 6000, // 60% approval threshold bps
            secondary_limit: 17_280, // execution delay window ledgers
            window_or_rate: 86_400,  // voting period ledgers
            max_tier: 1,
            region_restriction: false,
            irreversible_flag: false,
        },
        PolicyType::OracleVarianceBounds => PolicyParameters {
            primary_limit: 500, // 5% max variance bps
            secondary_limit: 100, // 100 ledgers max staleness
            window_or_rate: 3,   // min quorum sources
            max_tier: 1,
            region_restriction: false,
            irreversible_flag: false,
        },
        PolicyType::MarketplaceFeeSchedule => PolicyParameters {
            primary_limit: 250, // 2.5% platform fee bps
            secondary_limit: 1000, // 10% max royalty bps
            window_or_rate: 300,  // auto extension window ledgers
            max_tier: 1,
            region_restriction: false,
            irreversible_flag: false,
        },
    }
}

/// Retrieves the active policy parameters for a module.
pub fn get_active_policy(env: &Env, module: PolicyModule) -> PolicyParameters {
    persistent_get(env, &PolicyStorageKey::ActivePolicy(module.as_symbol()))
        .unwrap_or_else(|| default_policy_parameters(PolicyType::TreasuryLimits))
}

/// Sets active policy parameters (administrative / post-commit).
pub fn set_active_policy(env: &Env, module: PolicyModule, params: &PolicyParameters) {
    persistent_set(
        env,
        &PolicyStorageKey::ActivePolicy(module.as_symbol()),
        params,
    );
}

/// Pure validation of policy parameters structure.
pub fn validate_parameters(params: &PolicyParameters) -> Result<(), PolicySimulationError> {
    if params.primary_limit < 0 || params.secondary_limit < 0 {
        return Err(PolicySimulationError::InvalidPolicyConfig);
    }
    if params.window_or_rate == 0 {
        return Err(PolicySimulationError::InvalidPolicyConfig);
    }
    Ok(())
}

/// Simulates a policy change preview before committing.
///
/// Evaluates:
/// - Differential between current and proposed parameters.
/// - Affected records and affected users estimate based on parameter delta.
/// - Operational side effects (invalidations, throttling, fee increases).
/// - Rollback feasibility and constraints.
pub fn simulate_policy_preview(
    env: &Env,
    maintainer: &Address,
    change: &ProposedPolicyChange,
    simulated_active_records: u32,
    simulated_active_users: u32,
) -> Result<PolicySimulationPreview, PolicySimulationError> {
    validate_parameters(&change.new_params)?;

    let current = persistent_get(
        env,
        &PolicyStorageKey::ActivePolicy(change.module.as_symbol()),
    )
    .unwrap_or_else(|| default_policy_parameters(change.policy_type));

    // Determine severity and impact
    let mut severity = PolicyImpactSeverity::Low;
    let mut affected_records = 0u32;
    let mut affected_users = 0u32;
    let mut side_effects = Vec::new(env);

    let is_irreversible = change.new_params.irreversible_flag;

    // Check tightening of limits
    if change.new_params.primary_limit < current.primary_limit {
        let reduction_pct = if current.primary_limit > 0 {
            ((current.primary_limit - change.new_params.primary_limit) * 100)
                / current.primary_limit
        } else {
            0
        };

        if reduction_pct >= 50 || is_irreversible {
            severity = PolicyImpactSeverity::Critical;
        } else if reduction_pct >= 20 {
            severity = PolicyImpactSeverity::High;
        } else {
            severity = PolicyImpactSeverity::Medium;
        }

        // Affected records proportion
        affected_records = (simulated_active_records * (reduction_pct.min(100) as u32)) / 100;
        affected_users = (simulated_active_users * (reduction_pct.min(100) as u32)) / 100;

        match change.module {
            PolicyModule::Treasury => {
                side_effects.push_back(SideEffectSummary {
                    kind: ExpectedSideEffectKind::WithdrawalsThrottled,
                    severity,
                    description: String::from_str(
                        env,
                        "Pending or subsequent withdrawals exceeding new limit will be rejected.",
                    ),
                });
            }
            PolicyModule::Aid => {
                side_effects.push_back(SideEffectSummary {
                    kind: ExpectedSideEffectKind::ClaimsInvalidated,
                    severity,
                    description: String::from_str(
                        env,
                        "Pending aid disbursements above new limit cannot settle.",
                    ),
                });
            }
            PolicyModule::Referral => {
                side_effects.push_back(SideEffectSummary {
                    kind: ExpectedSideEffectKind::CommissionsReduced,
                    severity,
                    description: String::from_str(
                        env,
                        "Affiliate commissions lowered; historical payouts remain settled.",
                    ),
                });
            }
            PolicyModule::Governance => {
                side_effects.push_back(SideEffectSummary {
                    kind: ExpectedSideEffectKind::ProposalsDisrupted,
                    severity,
                    description: String::from_str(
                        env,
                        "Active proposals may fail new quorum threshold.",
                    ),
                });
            }
            PolicyModule::Oracle => {
                side_effects.push_back(SideEffectSummary {
                    kind: ExpectedSideEffectKind::OracleFallbackElevated,
                    severity,
                    description: String::from_str(
                        env,
                        "Tighter variance bounds will elevate fallback to cached prices.",
                    ),
                });
            }
            PolicyModule::Marketplace => {
                side_effects.push_back(SideEffectSummary {
                    kind: ExpectedSideEffectKind::MarketplaceSettlementAdjusted,
                    severity,
                    description: String::from_str(
                        env,
                        "Marketplace fee adjustment will apply to future escrow purchases.",
                    ),
                });
            }
        }
    } else {
        // Limit expansion or relaxed constraints
        if change.new_params.primary_limit > current.primary_limit {
            severity = PolicyImpactSeverity::Medium;
        }
        side_effects.push_back(SideEffectSummary {
            kind: ExpectedSideEffectKind::None,
            severity: PolicyImpactSeverity::Low,
            description: String::from_str(
                env,
                "Policy update relaxes limits or maintains operational continuity.",
            ),
        });
    }

    // Rollback feasibility evaluation
    let is_reversible = !is_irreversible;
    let requires_dual_signoff = matches!(
        severity,
        PolicyImpactSeverity::High | PolicyImpactSeverity::Critical
    ) || is_irreversible;

    let rollback_window = if is_reversible {
        100_000 // ~8 days window for rollback
    } else {
        0 // Cannot rollback
    };

    let invariant_constraints = if is_reversible {
        String::from_str(
            env,
            "State invariants: solvency conservation, monotonic sequence, no orphaned records.",
        )
    } else {
        String::from_str(
            env,
            "Irreversible constraint: historical state transitions cannot be automatically undone.",
        )
    };

    let recovery_steps = if is_reversible {
        String::from_str(
            env,
            "Invoke rollback_policy with preview_id; restore prior parameters from audit history.",
        )
    } else {
        String::from_str(
            env,
            "Forward migration required: manual compensatory actions needed for stranded records.",
        )
    };

    let rollback_constraints = RollbackConstraintReport {
        is_reversible,
        rollback_window_ledgers: rollback_window,
        requires_dual_signoff,
        invariant_constraints,
        recovery_steps,
    };

    let next_id: u64 = persistent_get(env, &PolicyStorageKey::LastPreviewId).unwrap_or(0) + 1;
    persistent_set(env, &PolicyStorageKey::LastPreviewId, &next_id);

    let current_ledger = env.ledger().sequence();
    let preview = PolicySimulationPreview {
        preview_id: next_id,
        module: change.module,
        policy_type: change.policy_type,
        severity,
        current_params: current,
        proposed_params: change.new_params.clone(),
        affected_records_count: affected_records,
        affected_users_count: affected_users,
        expected_side_effects: side_effects,
        rollback_constraints,
        simulated_at_ledger: current_ledger,
        valid_until_ledger: current_ledger + DEFAULT_PREVIEW_VALIDITY_LEDGERS,
        simulated_by: maintainer.clone(),
    };

    persistent_set(
        env,
        &PolicyStorageKey::SimulationPreview(next_id),
        &preview,
    );

    Ok(preview)
}

/// Retrieves an existing simulation preview by ID.
pub fn get_simulation_preview(
    env: &Env,
    preview_id: u64,
) -> Result<PolicySimulationPreview, PolicySimulationError> {
    persistent_get(env, &PolicyStorageKey::SimulationPreview(preview_id))
        .ok_or(PolicySimulationError::SimulationPreviewExpired)
}

/// Validates that a simulation preview is valid, non-expired, and eligible for commit.
pub fn validate_preview_for_commit(
    env: &Env,
    preview: &PolicySimulationPreview,
    co_signer: Option<&Address>,
) -> Result<(), PolicySimulationError> {
    let current_ledger = env.ledger().sequence();
    if current_ledger > preview.valid_until_ledger {
        return Err(PolicySimulationError::SimulationPreviewExpired);
    }

    if preview.rollback_constraints.requires_dual_signoff {
        match co_signer {
            Some(signer) => {
                if *signer == preview.simulated_by {
                    return Err(PolicySimulationError::DualSignoffRequired);
                }
            }
            None => return Err(PolicySimulationError::DualSignoffRequired),
        }
    }

    Ok(())
}

/// Commits a previewed policy change after preview verification.
pub fn commit_policy_change(
    env: &Env,
    maintainer: &Address,
    preview_id: u64,
    co_signer: Option<&Address>,
) -> Result<PolicyParameters, PolicySimulationError> {
    require_admin(env, maintainer).map_err(|_| PolicySimulationError::Unauthorized)?;

    let preview = get_simulation_preview(env, preview_id)?;
    validate_preview_for_commit(env, &preview, co_signer)?;

    // Archive current active policy to history for rollback support
    persistent_set(
        env,
        &PolicyStorageKey::CommittedHistory(preview.module.as_symbol()),
        &preview.current_params,
    );

    // Apply new policy
    set_active_policy(env, preview.module, &preview.proposed_params);

    // Publish commit event
    env.events().publish(
        (TOPIC_POLICY_COMMIT, preview.module.as_symbol()),
        preview.preview_id,
    );

    Ok(preview.proposed_params)
}

/// Rolls back a committed policy change to its prior parameters.
pub fn rollback_policy_change(
    env: &Env,
    maintainer: &Address,
    module: PolicyModule,
) -> Result<PolicyParameters, PolicySimulationError> {
    require_admin(env, maintainer).map_err(|_| PolicySimulationError::Unauthorized)?;

    let prior_params: PolicyParameters = persistent_get(
        env,
        &PolicyStorageKey::CommittedHistory(module.as_symbol()),
    )
    .ok_or(PolicySimulationError::IrreversibleChangeBlocked)?;

    // Restore prior parameters
    set_active_policy(env, module, &prior_params);

    // Publish rollback event
    env.events().publish(
        (TOPIC_POLICY_ROLLBACK, module.as_symbol()),
        env.ledger().sequence(),
    );

    Ok(prior_params)
}
