#[cfg(test)]
mod tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env,
    };

    use crate::errors::Error;
    use crate::risk_scoring::{
        assess_and_record, evaluate_risk, get_actor_profile, reset_actor_risk,
        set_actor_exemption, set_risk_policy, ActionContext, HighImpactAction,
        RiskPolicy, RiskTier, RiskVerdict,
    };

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let admin = Address::generate(&env);
        let actor = Address::generate(&env);
        crate::auth::set_admin(&env, &admin);
        (env, admin, actor)
    }

    #[test]
    fn test_normal_low_risk_action_allowed() {
        let (env, _admin, actor) = setup();

        let ctx = ActionContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            amount: 1_000,
            max_reference_amount: 100_000,
            recipient_is_known: true,
            is_batch: false,
            batch_size: 1,
            prior_strikes: 0,
        };

        let assessment = evaluate_risk(&env, &ctx);
        assert_eq!(assessment.total_score, 0);
        assert_eq!(assessment.tier, RiskTier::Minimal);
        assert_eq!(assessment.verdict, RiskVerdict::Allow);
        assert_eq!(assessment.factors.len(), 0);

        let res = assess_and_record(&env, &ctx);
        assert!(res.is_ok());
    }

    #[test]
    fn test_excessive_amount_and_unrecognized_recipient_triggers_dual_auth() {
        let (env, _admin, actor) = setup();

        let ctx = ActionContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            amount: 60_000,
            max_reference_amount: 100_000,
            recipient_is_known: false,
            is_batch: false,
            batch_size: 1,
            prior_strikes: 1,
        };

        let custom_policy = RiskPolicy {
            block_threshold: 800,
            dual_auth_threshold: 400,
            throttle_threshold: 650,
            velocity_window_ledgers: 120,
            velocity_burst_limit: 4,
            dormancy_window_ledgers: 17_280,
            decay_per_window: 50,
        };
        set_risk_policy(&env, &_admin, HighImpactAction::TreasuryWithdrawal, &custom_policy).unwrap();

        let assessment = evaluate_risk(&env, &ctx);
        assert_eq!(assessment.tier, RiskTier::Medium);
        assert_eq!(assessment.verdict, RiskVerdict::RequireDualAuth);
        assert!(assessment.factors.len() >= 3);

        let res = assess_and_record(&env, &ctx);
        assert_eq!(res.err(), Some(Error::Unauthorized));
    }

    #[test]
    fn test_velocity_burst_triggers_throttle() {
        let (env, admin, actor) = setup();

        let policy = RiskPolicy {
            block_threshold: 900,
            dual_auth_threshold: 700,
            throttle_threshold: 200,
            velocity_window_ledgers: 50,
            velocity_burst_limit: 2,
            dormancy_window_ledgers: 17_280,
            decay_per_window: 10,
        };
        set_risk_policy(&env, &admin, HighImpactAction::EscrowRelease, &policy).unwrap();

        let ctx = ActionContext {
            action: HighImpactAction::EscrowRelease,
            actor: actor.clone(),
            amount: 100,
            max_reference_amount: 100_000,
            recipient_is_known: true,
            is_batch: false,
            batch_size: 1,
            prior_strikes: 0,
        };

        // 1st action
        env.ledger().set_sequence_number(100);
        assert!(assess_and_record(&env, &ctx).is_ok());

        // 2nd action
        env.ledger().set_sequence_number(102);
        assert!(assess_and_record(&env, &ctx).is_ok());

        // 3rd action exceeds burst limit of 2 within window
        env.ledger().set_sequence_number(103);
        let res = assess_and_record(&env, &ctx);
        assert_eq!(res.err(), Some(Error::QuotaExceeded));
    }

    #[test]
    fn test_critical_score_triggers_block() {
        let (env, _admin, actor) = setup();

        let ctx = ActionContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            amount: 98_000,
            max_reference_amount: 100_000,
            recipient_is_known: false,
            is_batch: true,
            batch_size: 35,
            prior_strikes: 3,
        };

        let assessment = evaluate_risk(&env, &ctx);
        assert_eq!(assessment.tier, RiskTier::Critical);
        assert_eq!(assessment.verdict, RiskVerdict::Block);
        assert!(assessment.total_score >= 800);

        let res = assess_and_record(&env, &ctx);
        assert_eq!(res.err(), Some(Error::QuotaExceeded));
    }

    #[test]
    fn test_admin_exemption_and_reset_remediation() {
        let (env, admin, actor) = setup();

        let ctx = ActionContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            amount: 95_000,
            max_reference_amount: 100_000,
            recipient_is_known: false,
            is_batch: true,
            batch_size: 20,
            prior_strikes: 2,
        };

        // Without exemption: blocked
        let assessment = evaluate_risk(&env, &ctx);
        assert_eq!(assessment.verdict, RiskVerdict::Block);

        // Grant exemption
        set_actor_exemption(&env, &admin, &actor, true).unwrap();
        let exempt_assessment = evaluate_risk(&env, &ctx);
        assert_eq!(exempt_assessment.verdict, RiskVerdict::Allow);
        assert_eq!(exempt_assessment.total_score, 0);

        // Reset profile
        let reset_res = reset_actor_risk(&env, &admin, &actor);
        assert!(reset_res.is_ok());
        let profile = get_actor_profile(&env, &actor).unwrap();
        assert_eq!(profile.total_actions_in_window, 0);
    }

    #[test]
    fn test_authorization_checks() {
        let (env, _admin, actor) = setup();
        let attacker = Address::generate(&env);

        let policy = RiskPolicy {
            block_threshold: 800,
            dual_auth_threshold: 500,
            throttle_threshold: 650,
            velocity_window_ledgers: 120,
            velocity_burst_limit: 5,
            dormancy_window_ledgers: 17_280,
            decay_per_window: 20,
        };

        // Attacker rejected from setting policy
        let err1 = set_risk_policy(&env, &attacker, HighImpactAction::ContractUpgrade, &policy);
        assert_eq!(err1.err(), Some(Error::Unauthorized));

        // Attacker rejected from granting exemption
        let err2 = set_actor_exemption(&env, &attacker, &actor, true);
        assert_eq!(err2.err(), Some(Error::Unauthorized));

        // Attacker rejected from resetting profile
        let err3 = reset_actor_risk(&env, &attacker, &actor);
        assert_eq!(err3.err(), Some(Error::Unauthorized));
    }

    #[test]
    fn test_dormancy_factor_detected() {
        let (env, _admin, actor) = setup();

        let ctx = ActionContext {
            action: HighImpactAction::TreasuryWithdrawal,
            actor: actor.clone(),
            amount: 1_000,
            max_reference_amount: 100_000,
            recipient_is_known: true,
            is_batch: false,
            batch_size: 1,
            prior_strikes: 0,
        };

        // First action at ledger 100
        env.ledger().set_sequence_number(100);
        assert!(assess_and_record(&env, &ctx).is_ok());

        // Second action after dormancy window (default 17_280 ledgers)
        env.ledger().set_sequence_number(100 + 20_000);
        let assessment = evaluate_risk(&env, &ctx);
        assert!(assessment.total_score >= 150);
        assert!(assessment.factors.iter().any(|f| f.factor_type == crate::risk_scoring::RiskFactorType::UnusualDormancy));
    }
}

