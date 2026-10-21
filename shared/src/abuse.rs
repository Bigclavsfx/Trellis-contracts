//! Abuse controls layered on top of quota checks.
///
/// Quotas limit repeated use of a resource. Abuse scoring records why an
/// operation was rejected so frontends and maintainers can distinguish normal
/// throttling from suspicious patterns.

use soroban_sdk::{contracttype, Address, Env, Symbol};

use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbusePolicy {
    pub max_score: u32,
    pub decay_per_window: u32,
    pub window_ledgers: u32,
}

impl Default for AbusePolicy {
    fn default() -> Self {
        Self {
            max_score: 100,
            decay_per_window: 10,
            window_ledgers: 17_280,
        }
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbuseState {
    pub score: u32,
    pub last_ledger: u32,
    pub strikes: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum AbuseKey {
    Policy(Symbol),
    State(Address, Symbol),
}

pub fn set_abuse_policy(env: &Env, resource: &Symbol, policy: &AbusePolicy) -> Result<(), Error> {
    if policy.max_score == 0 || policy.window_ledgers == 0 {
        return Err(Error::ConfigInvalid);
    }
    persistent_set(env, &AbuseKey::Policy(resource.clone()), policy);
    Ok(())
}

pub fn get_abuse_policy(env: &Env, resource: &Symbol) -> AbusePolicy {
    persistent_get(env, &AbuseKey::Policy(resource.clone())).unwrap_or_default()
}

pub fn get_abuse_state(env: &Env, actor: &Address, resource: &Symbol) -> AbuseState {
    persistent_get(env, &AbuseKey::State(actor.clone(), resource.clone())).unwrap_or(AbuseState {
        score: 0,
        last_ledger: env.ledger().sequence(),
        strikes: 0,
    })
}

pub fn record_abuse(
    env: &Env,
    actor: &Address,
    resource: &Symbol,
    weight: u32,
) -> Result<AbuseState, Error> {
    let policy = get_abuse_policy(env, resource);
    let mut state = get_abuse_state(env, actor, resource);
    let elapsed = env.ledger().sequence().saturating_sub(state.last_ledger);
    if elapsed >= policy.window_ledgers {
        let windows = elapsed / policy.window_ledgers;
        state.score = state
            .score
            .saturating_sub(policy.decay_per_window.saturating_mul(windows));
    }
    state.score = state.score.saturating_add(weight);
    state.strikes = state.strikes.saturating_add(1);
    state.last_ledger = env.ledger().sequence();
    persistent_set(
        env,
        &AbuseKey::State(actor.clone(), resource.clone()),
        &state,
    );
    if state.score > policy.max_score {
        return Err(Error::QuotaExceeded);
    }
    Ok(state)
}

/// Cross-boundary trust decision for abuse scoring.
///
/// The abuse module is the boundary between an untrusted actor and the
/// resource it is trying to consume. Before any operation is authorized,
/// the caller must check whether the actor's accumulated score exceeds the
/// policy maximum. This is the guard that makes the boundary decision
/// explicit rather than implicit in the caller.
///
/// Returns `true` when the actor is at or above the policy maximum and
/// the caller must reject the operation. Returns `false` when the actor
/// is within bounds.
pub fn is_abuse_blocked(env: &Env, actor: &Address, resource: &Symbol) -> bool {
    let policy = get_abuse_policy(env, resource);
    let state = get_abuse_state(env, actor, resource);
    state.score >= policy.max_score
}

// ---------------------------------------------------------------------------
// Risk-Scored Abuse Detection for High-Impact Operations (Issue #242)
// ---------------------------------------------------------------------------

use crate::risk_scoring::{
    assess_and_record, evaluate_risk, ActionContext, HighImpactAction, RiskAssessment, RiskVerdict,
};

/// High-impact abuse context payload for suspicious operation detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HighImpactAbuseContext {
    pub action: HighImpactAction,
    pub actor: Address,
    pub resource: Symbol,
    pub amount: i128,
    pub max_reference_amount: i128,
    pub recipient_is_known: bool,
    pub is_batch: bool,
    pub batch_size: u32,
}

/// Evaluates explainable risk for a high-impact operation layered with actor abuse state.
/// Incorporates prior accumulated strikes and checks if the actor is already abuse-blocked.
pub fn evaluate_high_impact_abuse(
    env: &Env,
    ctx: &HighImpactAbuseContext,
) -> RiskAssessment {
    let state = get_abuse_state(env, &ctx.actor, &ctx.resource);
    let action_ctx = ActionContext {
        action: ctx.action,
        actor: ctx.actor.clone(),
        amount: ctx.amount,
        max_reference_amount: ctx.max_reference_amount,
        recipient_is_known: ctx.recipient_is_known,
        is_batch: ctx.is_batch,
        batch_size: ctx.batch_size,
        prior_strikes: state.strikes,
    };
    evaluate_risk(env, &action_ctx)
}

/// Assesses risk-scored abuse detection for suspicious high-impact operations.
///
/// - Checks if the actor is blocked by abuse quota.
/// - Gathers prior abuse strikes to feed into the explainable risk evaluation engine.
/// - If the operation produces a suspicious verdict (`RequireDualAuth`, `Throttle`, or `Block`):
///   increments abuse strikes and updates decayed abuse score.
/// - Legitimate low-risk operations (`Allow`) proceed without accumulating strikes or blocking legitimate use.
pub fn assess_high_impact_abuse(
    env: &Env,
    ctx: &HighImpactAbuseContext,
) -> Result<RiskAssessment, Error> {
    if is_abuse_blocked(env, &ctx.actor, &ctx.resource) {
        return Err(Error::QuotaExceeded);
    }

    let state = get_abuse_state(env, &ctx.actor, &ctx.resource);
    let action_ctx = ActionContext {
        action: ctx.action,
        actor: ctx.actor.clone(),
        amount: ctx.amount,
        max_reference_amount: ctx.max_reference_amount,
        recipient_is_known: ctx.recipient_is_known,
        is_batch: ctx.is_batch,
        batch_size: ctx.batch_size,
        prior_strikes: state.strikes,
    };

    let assessment = evaluate_risk(env, &action_ctx);

    match assessment.verdict {
        RiskVerdict::Block => {
            // High severity abuse: record significant weight and return QuotaExceeded
            let _ = record_abuse(env, &ctx.actor, &ctx.resource, 40);
            Err(Error::QuotaExceeded)
        }
        RiskVerdict::Throttle => {
            // Velocity burst anomaly: record moderate abuse weight and throttle
            let _ = record_abuse(env, &ctx.actor, &ctx.resource, 20);
            Err(Error::QuotaExceeded)
        }
        RiskVerdict::RequireDualAuth => {
            // Elevated risk step-up: record light abuse tracking and require step-up authorization
            let _ = record_abuse(env, &ctx.actor, &ctx.resource, 10);
            Err(Error::Unauthorized)
        }
        RiskVerdict::Allow => {
            // Low risk operation passes cleanly without false-positive penalty
            assess_and_record(env, &action_ctx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup() -> Env {
        Env::default()
    }

    #[test]
    fn record_abuse_accumulates_score_and_strikes() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "invite");
        let state = record_abuse(&env, &actor, &resource, 5).unwrap();
        assert_eq!(state.score, 5);
        assert_eq!(state.strikes, 1);
    }

    #[test]
    fn record_abuse_rejects_when_max_score_exceeded() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 10,
            decay_per_window: 1,
            window_ledgers: 10,
        };
        set_abuse_policy(&env, &resource, &policy).unwrap();
        let result = record_abuse(&env, &actor, &resource, 11);
        assert!(result.is_err());
    }

    #[test]
    fn is_abuse_blocked_respects_policy_max() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 10,
            decay_per_window: 1,
            window_ledgers: 10,
        };
        set_abuse_policy(&env, &resource, &policy).unwrap();
        assert!(!is_abuse_blocked(&env, &actor, &resource));
        let _ = record_abuse(&env, &actor, &resource, 10);
        assert!(is_abuse_blocked(&env, &actor, &resource));
    }

    #[test]
    fn set_abuse_policy_rejects_zero_max_score() {
        let env = setup();
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 0,
            decay_per_window: 1,
            window_ledgers: 10,
        };
        assert_eq!(set_abuse_policy(&env, &resource, &policy), Err(Error::ConfigInvalid));
    }

    #[test]
    fn set_abuse_policy_rejects_zero_window() {
        let env = setup();
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 10,
            decay_per_window: 1,
            window_ledgers: 0,
        };
        assert_eq!(set_abuse_policy(&env, &resource, &policy), Err(Error::ConfigInvalid));
    }

    #[test]
    fn test_high_impact_abuse_allows_legitimate_low_risk() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "treasury");

        let ctx = HighImpactAbuseContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            resource: resource.clone(),
            amount: 500,
            max_reference_amount: 100_000,
            recipient_is_known: true,
            is_batch: false,
            batch_size: 1,
        };

        let assessment = evaluate_high_impact_abuse(&env, &ctx);
        assert_eq!(assessment.verdict, RiskVerdict::Allow);
        assert_eq!(assessment.total_score, 0);

        let res = assess_high_impact_abuse(&env, &ctx);
        assert!(res.is_ok());

        // Legitimate operation does not penalize actor with strikes or abuse score
        let state = get_abuse_state(&env, &actor, &resource);
        assert_eq!(state.strikes, 0);
        assert_eq!(state.score, 0);
    }

    #[test]
    fn test_high_impact_abuse_triggers_step_up_and_accumulates_strikes() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "treasury");

        let ctx = HighImpactAbuseContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            resource: resource.clone(),
            amount: 60_000,
            max_reference_amount: 100_000,
            recipient_is_known: false,
            is_batch: false,
            batch_size: 1,
        };

        // First attempt evaluates to RequireDualAuth due to large amount & unknown recipient
        let res1 = assess_high_impact_abuse(&env, &ctx);
        assert_eq!(res1.err(), Some(Error::Unauthorized));

        // Strikes accumulated
        let state1 = get_abuse_state(&env, &actor, &resource);
        assert_eq!(state1.strikes, 1);
        assert_eq!(state1.score, 10);

        // Next evaluation factors in prior strikes
        let assessment2 = evaluate_high_impact_abuse(&env, &ctx);
        assert!(assessment2.total_score > 400);
    }

    #[test]
    fn test_high_impact_abuse_critical_risk_blocks_and_escalates() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "batch_exec");

        let ctx = HighImpactAbuseContext {
            action: HighImpactAction::BatchExecution,
            actor: actor.clone(),
            resource: resource.clone(),
            amount: 95_000,
            max_reference_amount: 100_000,
            recipient_is_known: false,
            is_batch: true,
            batch_size: 30,
        };

        let res = assess_high_impact_abuse(&env, &ctx);
        assert_eq!(res.err(), Some(Error::QuotaExceeded));

        let state = get_abuse_state(&env, &actor, &resource);
        assert_eq!(state.strikes, 1);
        assert_eq!(state.score, 40);
    }

    #[test]
    fn test_high_impact_abuse_blocks_already_abusive_actor() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "treasury");

        let policy = AbusePolicy {
            max_score: 50,
            decay_per_window: 5,
            window_ledgers: 100,
        };
        set_abuse_policy(&env, &resource, &policy).unwrap();

        // Push score to max
        let _ = record_abuse(&env, &actor, &resource, 50);
        assert!(is_abuse_blocked(&env, &actor, &resource));

        let ctx = HighImpactAbuseContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            resource: resource.clone(),
            amount: 10,
            max_reference_amount: 100_000,
            recipient_is_known: true,
            is_batch: false,
            batch_size: 1,
        };

        // Even low risk action is rejected if actor is abuse blocked
        let res = assess_high_impact_abuse(&env, &ctx);
        assert_eq!(res.err(), Some(Error::QuotaExceeded));
    }
}

