#![cfg(test)]

use soroban_sdk::{
    testutils::Address as _, testutils::Events as _, testutils::Ledger as _, Address, Env, String,
};

use crate::policy_preview::{
    commit_policy_change, default_policy_parameters, get_active_policy, get_simulation_preview,
    rollback_policy_change, set_active_policy, simulate_policy_preview,
    validate_parameters, ExpectedSideEffectKind, PolicyImpactSeverity, PolicyModule,
    PolicyParameters, PolicySimulationError, PolicyType, ProposedPolicyChange,
    TOPIC_POLICY_COMMIT, TOPIC_POLICY_ROLLBACK,
};

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.ledger().set_sequence_number(1_000);
    let admin = Address::generate(&env);
    let co_admin = Address::generate(&env);
    crate::auth::set_admin(&env, &admin).unwrap();
    (env, admin, co_admin)
}

#[test]
fn test_default_policy_parameters_across_modules() {
    let treasury_params = default_policy_parameters(PolicyType::TreasuryLimits);
    assert!(treasury_params.primary_limit > 0);
    assert_eq!(treasury_params.max_tier, 3);
    assert!(!treasury_params.irreversible_flag);

    let aid_params = default_policy_parameters(PolicyType::AidDisbursement);
    assert_eq!(aid_params.max_tier, 2);
    assert!(aid_params.region_restriction);

    let ref_params = default_policy_parameters(PolicyType::ReferralCommission);
    assert_eq!(ref_params.primary_limit, 500);

    let gov_params = default_policy_parameters(PolicyType::GovernanceQuorum);
    assert_eq!(gov_params.primary_limit, 6000);

    let ora_params = default_policy_parameters(PolicyType::OracleVarianceBounds);
    assert_eq!(ora_params.primary_limit, 500);

    let market_params = default_policy_parameters(PolicyType::MarketplaceFeeSchedule);
    assert_eq!(market_params.primary_limit, 250);
}

#[test]
fn test_simulate_low_impact_policy_preview() {
    let (env, admin, _) = setup();
    let current_default = default_policy_parameters(PolicyType::TreasuryLimits);

    // Propose an expanded limit (relaxed constraint)
    let change = ProposedPolicyChange {
        module: PolicyModule::Treasury,
        policy_type: PolicyType::TreasuryLimits,
        new_params: PolicyParameters {
            primary_limit: current_default.primary_limit * 2,
            ..current_default
        },
        rationale: String::from_str(&env, "Increasing treasury withdrawal limit for operations"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 100, 50).unwrap();
    assert_eq!(preview.module, PolicyModule::Treasury);
    assert_eq!(preview.severity, PolicyImpactSeverity::Medium);
    assert_eq!(preview.affected_records_count, 0);
    assert_eq!(preview.affected_users_count, 0);
    assert!(preview.rollback_constraints.is_reversible);
    assert!(!preview.rollback_constraints.requires_dual_signoff);
    assert_eq!(preview.simulated_at_ledger, 1_000);
    assert_eq!(preview.valid_until_ledger, 1_500);
}

#[test]
fn test_simulate_high_impact_tightening_preview() {
    let (env, admin, _) = setup();
    let current_default = default_policy_parameters(PolicyType::TreasuryLimits);

    // Propose tightening limit by 60% (critical/high severity)
    let change = ProposedPolicyChange {
        module: PolicyModule::Treasury,
        policy_type: PolicyType::TreasuryLimits,
        new_params: PolicyParameters {
            primary_limit: current_default.primary_limit * 4 / 10,
            ..current_default
        },
        rationale: String::from_str(&env, "Tightening withdrawal limit due to market risk"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 200, 100).unwrap();
    assert_eq!(preview.severity, PolicyImpactSeverity::Critical);
    assert_eq!(preview.affected_records_count, 120); // 60% of 200
    assert_eq!(preview.affected_users_count, 60); // 60% of 100
    assert!(preview.rollback_constraints.requires_dual_signoff);
    assert!(preview.rollback_constraints.is_reversible);
    assert_eq!(preview.expected_side_effects.len(), 1);
    assert_eq!(
        preview.expected_side_effects.get(0).unwrap().kind,
        ExpectedSideEffectKind::WithdrawalsThrottled
    );
}

#[test]
fn test_commit_requires_dual_signoff_for_high_impact() {
    let (env, admin, co_admin) = setup();
    let current_default = default_policy_parameters(PolicyType::AidDisbursement);

    let change = ProposedPolicyChange {
        module: PolicyModule::Aid,
        policy_type: PolicyType::AidDisbursement,
        new_params: PolicyParameters {
            primary_limit: current_default.primary_limit / 2, // 50% cut
            ..current_default
        },
        rationale: String::from_str(&env, "Lowering aid cap"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 50, 20).unwrap();
    assert!(preview.rollback_constraints.requires_dual_signoff);

    // Attempt commit without co-signer fails
    let err_no_signer = commit_policy_change(&env, &admin, preview.preview_id, None);
    assert_eq!(err_no_signer, Err(PolicySimulationError::DualSignoffRequired));

    // Attempt commit with same maintainer as co-signer fails
    let err_self_signer = commit_policy_change(&env, &admin, preview.preview_id, Some(&admin));
    assert_eq!(err_self_signer, Err(PolicySimulationError::DualSignoffRequired));

    // Commit with independent co-signer succeeds
    let commit_res = commit_policy_change(&env, &admin, preview.preview_id, Some(&co_admin));
    assert!(commit_res.is_ok());

    let updated = get_active_policy(&env, PolicyModule::Aid);
    assert_eq!(updated.primary_limit, current_default.primary_limit / 2);
}

#[test]
fn test_rollback_committed_policy_change() {
    let (env, admin, co_admin) = setup();
    let initial_default = default_policy_parameters(PolicyType::TreasuryLimits);
    set_active_policy(&env, PolicyModule::Treasury, &initial_default);

    let change = ProposedPolicyChange {
        module: PolicyModule::Treasury,
        policy_type: PolicyType::TreasuryLimits,
        new_params: PolicyParameters {
            primary_limit: initial_default.primary_limit / 4,
            ..initial_default
        },
        rationale: String::from_str(&env, "Emergency restriction"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 100, 10).unwrap();
    commit_policy_change(&env, &admin, preview.preview_id, Some(&co_admin)).unwrap();

    assert_eq!(
        get_active_policy(&env, PolicyModule::Treasury).primary_limit,
        initial_default.primary_limit / 4
    );

    // Rollback to prior parameters
    let restored = rollback_policy_change(&env, &admin, PolicyModule::Treasury).unwrap();
    assert_eq!(restored.primary_limit, initial_default.primary_limit);
    assert_eq!(
        get_active_policy(&env, PolicyModule::Treasury).primary_limit,
        initial_default.primary_limit
    );
}

#[test]
fn test_expired_preview_cannot_be_committed() {
    let (env, admin, _) = setup();
    let default_params = default_policy_parameters(PolicyType::TreasuryLimits);

    let change = ProposedPolicyChange {
        module: PolicyModule::Treasury,
        policy_type: PolicyType::TreasuryLimits,
        new_params: PolicyParameters {
            primary_limit: default_params.primary_limit + 100,
            ..default_params
        },
        rationale: String::from_str(&env, "Tuning limit"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 10, 5).unwrap();

    // Fast-forward ledger sequence past preview validity
    env.ledger().set_sequence_number(preview.valid_until_ledger + 1);

    let res = commit_policy_change(&env, &admin, preview.preview_id, None);
    assert_eq!(res, Err(PolicySimulationError::SimulationPreviewExpired));
}

#[test]
fn test_irreversible_policy_change_blocks_rollback() {
    let (env, admin, co_admin) = setup();
    let default_params = default_policy_parameters(PolicyType::GovernanceQuorum);

    let change = ProposedPolicyChange {
        module: PolicyModule::Governance,
        policy_type: PolicyType::GovernanceQuorum,
        new_params: PolicyParameters {
            primary_limit: 8000,
            irreversible_flag: true,
            ..default_params
        },
        rationale: String::from_str(&env, "Irreversible governance overhaul"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 10, 5).unwrap();
    assert!(!preview.rollback_constraints.is_reversible);
    assert_eq!(preview.rollback_constraints.rollback_window_ledgers, 0);

    // Can commit with dual signoff
    let commit_res = commit_policy_change(&env, &admin, preview.preview_id, Some(&co_admin));
    assert!(commit_res.is_ok());
}

#[test]
fn test_unauthorized_user_cannot_commit_or_rollback() {
    let (env, admin, _) = setup();
    let non_admin = Address::generate(&env);
    let default_params = default_policy_parameters(PolicyType::TreasuryLimits);

    let change = ProposedPolicyChange {
        module: PolicyModule::Treasury,
        policy_type: PolicyType::TreasuryLimits,
        new_params: default_params,
        rationale: String::from_str(&env, "No-op change"),
    };

    let preview = simulate_policy_preview(&env, &admin, &change, 0, 0).unwrap();

    let commit_res = commit_policy_change(&env, &non_admin, preview.preview_id, None);
    assert_eq!(commit_res, Err(PolicySimulationError::Unauthorized));

    let rollback_res = rollback_policy_change(&env, &non_admin, PolicyModule::Treasury);
    assert_eq!(rollback_res, Err(PolicySimulationError::Unauthorized));
}

#[test]
fn test_invalid_parameters_rejected() {
    let bad_params = PolicyParameters {
        primary_limit: -1,
        secondary_limit: 10,
        window_or_rate: 10,
        max_tier: 1,
        region_restriction: false,
        irreversible_flag: false,
    };
    assert_eq!(
        validate_parameters(&bad_params),
        Err(PolicySimulationError::InvalidPolicyConfig)
    );

    let zero_window = PolicyParameters {
        primary_limit: 100,
        secondary_limit: 10,
        window_or_rate: 0,
        max_tier: 1,
        region_restriction: false,
        irreversible_flag: false,
    };
    assert_eq!(
        validate_parameters(&zero_window),
        Err(PolicySimulationError::InvalidPolicyConfig)
    );
}
