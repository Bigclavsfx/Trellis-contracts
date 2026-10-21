//! Explainable Risk Scoring for Suspicious High-Impact Actions (Issue #298).
//!
//! Across Trellis Soroban contracts — Treasury, Escrow, Upgradeability, Governance,
//! Rebalancer, and Batch execution — privileged and high-value mutations carry
//! potential systemic risk if hijacked, abused, or executed under compromised keys.
//!
//! Rather than simple binary allow/deny rules or opaque numeric scores, this module
//! provides transparent, explainable risk scoring:
//! 1. Every risk assessment computes an overall score (0–1000 basis) mapped to a [`RiskTier`].
//! 2. The assessment returns an explainability vector of [`RiskFactor`] records detailing:
//!    - The specific risk factor type (e.g. VelocitySpike, ExcessiveAmountRatio, Dormancy).
//!    - Contributed score weight.
//!    - Configured baseline threshold vs. observed runtime value.
//!    - Human/indexer-readable explanation code.
//! 3. Maps assessments to actionable protocol verdicts ([`RiskVerdict`]):
//!    - `Allow`: Low risk, transaction executes immediately.
//!    - `RequireDualAuth`: Medium-high risk, requires co-signer or multi-sig approval.
//!    - `Throttle`: Velocity anomaly, caller must delay execution.
//!    - `Block`: Critical risk, transaction is rejected with an auditable error.
//! 4. Full administrative governance: Authorized admins can update policy, configure
//!    thresholds, inspect explainable assessments, and remediate false positives.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Env, Symbol, Vec,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 980–989)
// ---------------------------------------------------------------------------

/// Risk scoring errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RiskError {
    /// Operation blocked due to excessive risk score.
    RiskScoreTooHigh = 980,
    /// Operation requires dual-party authorization before proceeding.
    DualAuthorizationRequired = 981,
    /// Operation throttled due to rapid velocity burst.
    ActionThrottled = 982,
    /// Risk policy configuration is invalid (e.g. zero window).
    InvalidPolicyConfig = 983,
    /// Caller is not authorized to modify risk policies or exemptions.
    Unauthorized = 984,
    /// Actor is explicitly blocked by risk governance.
    ActorExplicitlyBlocked = 985,
}

impl From<RiskError> for Error {
    fn from(err: RiskError) -> Self {
        match err {
            RiskError::RiskScoreTooHigh => Error::QuotaExceeded,
            RiskError::DualAuthorizationRequired => Error::Unauthorized,
            RiskError::ActionThrottled => Error::QuotaExceeded,
            RiskError::InvalidPolicyConfig => Error::ConfigInvalid,
            RiskError::Unauthorized => Error::Unauthorized,
            RiskError::ActorExplicitlyBlocked => Error::Unauthorized,
        }
    }
}

// ---------------------------------------------------------------------------
// Risk Models & Explanations
// ---------------------------------------------------------------------------

/// Action categories subjected to explainable risk scoring.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum HighImpactAction {
    TreasuryWithdrawal = 1,
    EscrowRelease = 2,
    EscrowRefund = 3,
    ContractUpgrade = 4,
    StorageMigration = 5,
    EmergencyPause = 6,
    RoleElevation = 7,
    RebalanceExecution = 8,
    BatchExecution = 9,
}

impl HighImpactAction {
    pub fn as_symbol(&self) -> Symbol {
        match self {
            HighImpactAction::TreasuryWithdrawal => symbol_short!("withdraw"),
            HighImpactAction::EscrowRelease => symbol_short!("release"),
            HighImpactAction::EscrowRefund => symbol_short!("refund"),
            HighImpactAction::ContractUpgrade => symbol_short!("upgrade"),
            HighImpactAction::StorageMigration => symbol_short!("migration"),
            HighImpactAction::EmergencyPause => symbol_short!("pause"),
            HighImpactAction::RoleElevation => symbol_short!("role_elev"),
            HighImpactAction::RebalanceExecution => symbol_short!("rebalance"),
            HighImpactAction::BatchExecution => symbol_short!("batch"),
        }
    }
}

/// Normalized risk tiers.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RiskTier {
    Minimal = 1,   // 0–199
    Low = 2,       // 200–399
    Medium = 3,    // 400–599
    High = 4,      // 600–799
    Critical = 5,  // 800–1000
}

/// Actionable protocol verdicts derived from explainable risk scoring.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RiskVerdict {
    Allow = 1,
    RequireDualAuth = 2,
    Throttle = 3,
    Block = 4,
}

/// Specific dimension contributing to overall risk score.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RiskFactorType {
    ExcessiveAmountRatio = 1,
    VelocitySpike = 2,
    UnrecognizedRecipient = 3,
    UnusualDormancy = 4,
    PriorStrikes = 5,
    LargeBatchSize = 6,
}

/// Explainable evidence record for a single risk dimension.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub score_weight: u32,
    pub threshold: u32,
    pub observed: u32,
    pub explanation: Symbol,
}

/// Full risk assessment returned by the evaluation engine.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskAssessment {
    pub total_score: u32,
    pub tier: RiskTier,
    pub verdict: RiskVerdict,
    pub factors: Vec<RiskFactor>,
    pub evaluated_at: u64,
}

/// Configuration policy per action category.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskPolicy {
    pub block_threshold: u32,
    pub dual_auth_threshold: u32,
    pub throttle_threshold: u32,
    pub velocity_window_ledgers: u32,
    pub velocity_burst_limit: u32,
    pub dormancy_window_ledgers: u32,
    pub decay_per_window: u32,
}

/// Historical tracking record per actor.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorRiskProfile {
    pub total_actions_in_window: u32,
    pub last_action_ledger: u32,
    pub accumulated_risk_score: u32,
    pub strike_count: u32,
}

/// Context parameter payload supplied when requesting risk evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionContext {
    pub action: HighImpactAction,
    pub actor: Address,
    pub amount: i128,
    pub max_reference_amount: i128,
    pub recipient_is_known: bool,
    pub is_batch: bool,
    pub batch_size: u32,
    pub prior_strikes: u32,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    RiskPolicy(HighImpactAction),
    ActorProfile(Address),
    Exemption(Address),
}

// ---------------------------------------------------------------------------
// Core Engine Functions
// ---------------------------------------------------------------------------

/// Returns the active risk policy for a given action, defaulting to standard parameters.
pub fn get_risk_policy(env: &Env, action: HighImpactAction) -> RiskPolicy {
    persistent_get(env, &DataKey::RiskPolicy(action)).unwrap_or(RiskPolicy {
        block_threshold: 800,
        dual_auth_threshold: 500,
        throttle_threshold: 650,
        velocity_window_ledgers: 120, // ~10 minutes on Soroban
        velocity_burst_limit: 5,
        dormancy_window_ledgers: 17_280, // ~1 day
        decay_per_window: 20,
    })
}

/// Configures risk policy for an action type under admin authorization.
pub fn set_risk_policy(
    env: &Env,
    admin: &Address,
    action: HighImpactAction,
    policy: &RiskPolicy,
) -> Result<(), Error> {
    require_admin(env, admin)?;

    if policy.velocity_window_ledgers == 0
        || policy.block_threshold <= policy.dual_auth_threshold
        || policy.block_threshold > 1000
    {
        return Err(RiskError::InvalidPolicyConfig.into());
    }

    persistent_set(env, &DataKey::RiskPolicy(action), policy);

    env.events().publish(
        (symbol_short!("r_policy"), action.as_symbol()),
        (policy.block_threshold, policy.dual_auth_threshold, policy.throttle_threshold),
    );

    Ok(())
}

/// Sets or removes an actor exemption under admin authorization.
pub fn set_actor_exemption(
    env: &Env,
    admin: &Address,
    actor: &Address,
    exempted: bool,
) -> Result<(), Error> {
    require_admin(env, admin)?;

    if exempted {
        persistent_set(env, &DataKey::Exemption(actor.clone()), &true);
    } else {
        persistent_set(env, &DataKey::Exemption(actor.clone()), &false);
    }

    env.events().publish(
        (symbol_short!("r_exempt"), actor.clone()),
        exempted,
    );

    Ok(())
}

/// Evaluates explainable risk for an action without mutating state.
pub fn evaluate_risk(env: &Env, ctx: &ActionContext) -> RiskAssessment {
    let now = env.ledger().timestamp();
    let current_ledger = env.ledger().sequence();

    // Check admin exemption
    let is_exempt: bool = persistent_get(env, &DataKey::Exemption(ctx.actor.clone()))
        .unwrap_or(false);

    if is_exempt {
        return RiskAssessment {
            total_score: 0,
            tier: RiskTier::Minimal,
            verdict: RiskVerdict::Allow,
            factors: Vec::new(env),
            evaluated_at: now,
        };
    }

    let policy = get_risk_policy(env, ctx.action);
    let mut factors: Vec<RiskFactor> = Vec::new(env);
    let mut total_score: u32 = 0;

    // 1. Amount ratio factor: (amount / max_reference_amount)
    if ctx.max_reference_amount > 0 && ctx.amount > 0 {
        let ratio_bps = ((ctx.amount * 10_000) / ctx.max_reference_amount) as u32;
        if ratio_bps >= 5000 {
            // >= 50% of reference pool
            let score = ((ratio_bps * 350) / 10_000).min(350);
            factors.push_back(RiskFactor {
                factor_type: RiskFactorType::ExcessiveAmountRatio,
                score_weight: score,
                threshold: 5000,
                observed: ratio_bps,
                explanation: symbol_short!("hi_amount"),
            });
            total_score += score;
        }
    }

    // 2. Unrecognized recipient factor
    if !ctx.recipient_is_known {
        let score = 150;
        factors.push_back(RiskFactor {
            factor_type: RiskFactorType::UnrecognizedRecipient,
            score_weight: score,
            threshold: 1,
            observed: 0,
            explanation: symbol_short!("unrec_rcp"),
        });
        total_score += score;
    }

    // 3. Prior strikes factor
    if ctx.prior_strikes > 0 {
        let score = (ctx.prior_strikes * 100).min(300);
        factors.push_back(RiskFactor {
            factor_type: RiskFactorType::PriorStrikes,
            score_weight: score,
            threshold: 0,
            observed: ctx.prior_strikes,
            explanation: symbol_short!("strikes"),
        });
        total_score += score;
    }

    // 4. Batch size factor
    if ctx.is_batch && ctx.batch_size > 10 {
        let score = ((ctx.batch_size - 10) * 10).min(200);
        factors.push_back(RiskFactor {
            factor_type: RiskFactorType::LargeBatchSize,
            score_weight: score,
            threshold: 10,
            observed: ctx.batch_size,
            explanation: symbol_short!("lg_batch"),
        });
        total_score += score;
    }

    // 5. Velocity and historical profile
    let profile: ActorRiskProfile = persistent_get(env, &DataKey::ActorProfile(ctx.actor.clone()))
        .unwrap_or(ActorRiskProfile {
            total_actions_in_window: 0,
            last_action_ledger: 0,
            accumulated_risk_score: 0,
            strike_count: 0,
        });

    let ledgers_elapsed = current_ledger.saturating_sub(profile.last_action_ledger);
    if profile.last_action_ledger > 0 && ledgers_elapsed <= policy.velocity_window_ledgers {
        if profile.total_actions_in_window >= policy.velocity_burst_limit {
            let score = 250;
            factors.push_back(RiskFactor {
                factor_type: RiskFactorType::VelocitySpike,
                score_weight: score,
                threshold: policy.velocity_burst_limit,
                observed: profile.total_actions_in_window,
                explanation: symbol_short!("vel_spike"),
            });
            total_score += score;
        }
    } else if profile.last_action_ledger > 0 && ledgers_elapsed >= policy.dormancy_window_ledgers {
        // 6. Dormancy factor: prolonged inactivity prior to high-impact privileged action
        let score = 150;
        factors.push_back(RiskFactor {
            factor_type: RiskFactorType::UnusualDormancy,
            score_weight: score,
            threshold: policy.dormancy_window_ledgers,
            observed: ledgers_elapsed,
            explanation: symbol_short!("dormant"),
        });
        total_score += score;
    }

    // Clamp score to max 1000
    total_score = total_score.min(1000);

    // Derive Risk Tier
    let tier = if total_score < 200 {
        RiskTier::Minimal
    } else if total_score < 400 {
        RiskTier::Low
    } else if total_score < 600 {
        RiskTier::Medium
    } else if total_score < 800 {
        RiskTier::High
    } else {
        RiskTier::Critical
    };

    // Derive Verdict
    let has_velocity_spike = factors.iter().any(|f| f.factor_type == RiskFactorType::VelocitySpike);

    let verdict = if total_score >= policy.block_threshold {
        RiskVerdict::Block
    } else if has_velocity_spike && total_score >= policy.throttle_threshold {
        RiskVerdict::Throttle
    } else if total_score >= policy.dual_auth_threshold {
        RiskVerdict::RequireDualAuth
    } else {
        RiskVerdict::Allow
    };

    RiskAssessment {
        total_score,
        tier,
        verdict,
        factors,
        evaluated_at: now,
    }
}

/// Evaluates risk, enforces verdicts, and updates actor historical velocity records.
pub fn assess_and_record(env: &Env, ctx: &ActionContext) -> Result<RiskAssessment, Error> {
    let assessment = evaluate_risk(env, ctx);
    let policy = get_risk_policy(env, ctx.action);
    let current_ledger = env.ledger().sequence();

    // Enforce protocol verdicts
    match assessment.verdict {
        RiskVerdict::Block => {
            env.events().publish(
                (symbol_short!("r_block"), ctx.actor.clone()),
                (assessment.total_score, ctx.action.as_symbol()),
            );
            return Err(RiskError::RiskScoreTooHigh.into());
        }
        RiskVerdict::RequireDualAuth => {
            env.events().publish(
                (symbol_short!("r_dual"), ctx.actor.clone()),
                (assessment.total_score, ctx.action.as_symbol()),
            );
            return Err(RiskError::DualAuthorizationRequired.into());
        }
        RiskVerdict::Throttle => {
            env.events().publish(
                (symbol_short!("r_throtl"), ctx.actor.clone()),
                (assessment.total_score, ctx.action.as_symbol()),
            );
            return Err(RiskError::ActionThrottled.into());
        }
        RiskVerdict::Allow => {
            // Update actor profile
            let mut profile: ActorRiskProfile = persistent_get(env, &DataKey::ActorProfile(ctx.actor.clone()))
                .unwrap_or(ActorRiskProfile {
                    total_actions_in_window: 0,
                    last_action_ledger: 0,
                    accumulated_risk_score: 0,
                    strike_count: 0,
                });

            let ledgers_elapsed = current_ledger.saturating_sub(profile.last_action_ledger);
            if profile.last_action_ledger > 0 && ledgers_elapsed <= policy.velocity_window_ledgers {
                profile.total_actions_in_window += 1;
            } else {
                profile.total_actions_in_window = 1;
            }

            profile.last_action_ledger = current_ledger;
            profile.accumulated_risk_score = assessment.total_score;
            persistent_set(env, &DataKey::ActorProfile(ctx.actor.clone()), &profile);

            env.events().publish(
                (symbol_short!("r_allow"), ctx.actor.clone()),
                (assessment.total_score, ctx.action.as_symbol()),
            );
        }
    }

    Ok(assessment)
}

/// Retrieves actor risk profile.
pub fn get_actor_profile(env: &Env, actor: &Address) -> Option<ActorRiskProfile> {
    persistent_get(env, &DataKey::ActorProfile(actor.clone()))
}

/// Resets actor risk profile under admin authorization (e.g. false positive remediation).
pub fn reset_actor_risk(env: &Env, admin: &Address, actor: &Address) -> Result<(), Error> {
    require_admin(env, admin)?;
    persistent_set(
        env,
        &DataKey::ActorProfile(actor.clone()),
        &ActorRiskProfile {
            total_actions_in_window: 0,
            last_action_ledger: 0,
            accumulated_risk_score: 0,
            strike_count: 0,
        },
    );
    Ok(())
}
