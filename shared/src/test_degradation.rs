#![cfg(test)]

use soroban_sdk::{
    symbol_short, testutils::Address as _, testutils::Ledger as _, Address, Env,
};

use crate::degradation::{
    default_matrix_entry, evaluate_dependency_decision, execute_with_fallback,
    get_dependency_entry, initialize_standard_matrix, record_dependency_check,
    recover_dependency, register_dependency_entry, DegradationError, DegradationLevel,
    DegradationModule, DependencyFailureMode, ExternalDependencyKind, FallbackDecision,
    FallbackStrategy,
};
use crate::errors::Error;
use crate::health::{get_dependency_health, set_dependency_health, DependencyStatus};

fn setup() -> (Env, Address) {
    let env = Env::default();
    let admin = Address::generate(&env);
    crate::auth::set_admin(&env, &admin);
    (env, admin)
}

#[test]
fn test_default_matrix_generation_for_all_modules() {
    let (env, _) = setup();
    let ledger = 100u32;

    // Verify default mappings across modules
    let treasury_entry = default_matrix_entry(
        DegradationModule::Treasury,
        ExternalDependencyKind::StellarAssetContract,
        ledger,
    );
    assert_eq!(treasury_entry.module, DegradationModule::Treasury);
    assert_eq!(treasury_entry.fallback_strategy, FallbackStrategy::FailSafeRejection);
    assert_eq!(treasury_entry.current_level, DegradationLevel::Nominal);

    let aid_entry = default_matrix_entry(
        DegradationModule::Aid,
        ExternalDependencyKind::PaymentGateway,
        ledger,
    );
    assert_eq!(aid_entry.module, DegradationModule::Aid);
    assert_eq!(aid_entry.fallback_strategy, FallbackStrategy::EscrowHoldWithRefundGuarantee);

    let ref_entry = default_matrix_entry(
        DegradationModule::Referral,
        ExternalDependencyKind::IndexerRelayer,
        ledger,
    );
    assert_eq!(ref_entry.module, DegradationModule::Referral);
    assert_eq!(ref_entry.fallback_strategy, FallbackStrategy::LinearBaseCalculation);

    let gov_entry = default_matrix_entry(
        DegradationModule::Governance,
        ExternalDependencyKind::IndexerRelayer,
        ledger,
    );
    assert_eq!(gov_entry.module, DegradationModule::Governance);
    assert_eq!(gov_entry.fallback_strategy, FallbackStrategy::ReadOnlyInspection);

    let oracle_entry = default_matrix_entry(
        DegradationModule::Oracle,
        ExternalDependencyKind::ExternalOracleFeed,
        ledger,
    );
    assert_eq!(oracle_entry.module, DegradationModule::Oracle);
    assert_eq!(oracle_entry.fallback_strategy, FallbackStrategy::CachedLastKnownGood);

    let mkt_entry = default_matrix_entry(
        DegradationModule::Marketplace,
        ExternalDependencyKind::StellarAssetContract,
        ledger,
    );
    assert_eq!(mkt_entry.module, DegradationModule::Marketplace);
    assert_eq!(mkt_entry.fallback_strategy, FallbackStrategy::EscrowHoldWithRefundGuarantee);
}

#[test]
fn test_initialize_standard_matrix() {
    let (env, admin) = setup();

    let count = initialize_standard_matrix(&env, &admin).unwrap();
    assert_eq!(count, 7);

    // Verify entries exist in persistent storage
    let trs = get_dependency_entry(&env, DegradationModule::Treasury, ExternalDependencyKind::StellarAssetContract);
    assert!(trs.is_some());
    assert_eq!(trs.unwrap().current_level, DegradationLevel::Nominal);

    let ora = get_dependency_entry(&env, DegradationModule::Oracle, ExternalDependencyKind::ExternalOracleFeed);
    assert!(ora.is_some());
    assert_eq!(ora.unwrap().fallback_strategy, FallbackStrategy::CachedLastKnownGood);
}

#[test]
fn test_automated_health_check_degradation_trigger() {
    let (env, admin) = setup();
    initialize_standard_matrix(&env, &admin).unwrap();

    let module = DegradationModule::Oracle;
    let dep = ExternalDependencyKind::ExternalOracleFeed;

    // Nominal before failures
    assert_eq!(
        evaluate_dependency_decision(&env, module, dep),
        FallbackDecision::ProceedPrimary
    );

    // 1 failure -> Minor
    let level1 = record_dependency_check(&env, module, dep, false, 500);
    assert_eq!(level1, DegradationLevel::DegradedMinor);

    // 2 failures -> Reaches threshold (2) -> DegradedMajor
    let level2 = record_dependency_check(&env, module, dep, false, 500);
    assert_eq!(level2, DegradationLevel::DegradedMajor);

    // Decision now requires safe fallback
    assert_eq!(
        evaluate_dependency_decision(&env, module, dep),
        FallbackDecision::ProceedFallback(FallbackStrategy::CachedLastKnownGood)
    );

    // Additional failures -> Critical failure
    record_dependency_check(&env, module, dep, false, 500);
    let level4 = record_dependency_check(&env, module, dep, false, 500);
    assert_eq!(level4, DegradationLevel::CriticalFailure);
}

#[test]
fn test_execute_with_fallback_invocation() {
    let (env, admin) = setup();
    initialize_standard_matrix(&env, &admin).unwrap();

    let module = DegradationModule::Aid;
    let dep = ExternalDependencyKind::PaymentGateway;

    // Normal execution succeeds on primary
    let res = execute_with_fallback(
        &env,
        module,
        dep,
        || Ok(100u64),
        |_strat| Ok(50u64),
    );
    assert_eq!(res.unwrap(), 100);

    // Primary failure triggers safe fallback immediately
    let res_fallback = execute_with_fallback(
        &env,
        module,
        dep,
        || Err(Error::InvalidArgument),
        |strat| {
            assert_eq!(strat, FallbackStrategy::EscrowHoldWithRefundGuarantee);
            Ok(999u64)
        },
    );
    assert_eq!(res_fallback.unwrap(), 999);
}

#[test]
fn test_recovery_workflow_and_receipt() {
    let (env, admin) = setup();
    initialize_standard_matrix(&env, &admin).unwrap();

    let module = DegradationModule::Treasury;
    let dep = ExternalDependencyKind::StellarAssetContract;

    // Degrade dependency
    record_dependency_check(&env, module, dep, false, 400);
    record_dependency_check(&env, module, dep, false, 400);

    let entry_before = get_dependency_entry(&env, module, dep).unwrap();
    assert_eq!(entry_before.current_level, DegradationLevel::DegradedMajor);

    // Perform recovery
    let receipt = recover_dependency(&env, &admin, module, dep, true).unwrap();
    assert_eq!(receipt.restored_level, DegradationLevel::Nominal);
    assert!(receipt.rollback_executed);

    let entry_after = get_dependency_entry(&env, module, dep).unwrap();
    assert_eq!(entry_after.current_level, DegradationLevel::Nominal);

    // Primary path is restored
    assert_eq!(
        evaluate_dependency_decision(&env, module, dep),
        FallbackDecision::ProceedPrimary
    );
}

#[test]
fn test_critical_failure_rejection_for_failsafe() {
    let (env, admin) = setup();
    initialize_standard_matrix(&env, &admin).unwrap();

    let module = DegradationModule::Treasury;
    let dep = ExternalDependencyKind::StellarAssetContract;

    // Mark dependency down in health system
    set_dependency_health(&env, &dep.as_symbol(), DependencyStatus::Down);

    let decision = evaluate_dependency_decision(&env, module, dep);
    assert_eq!(
        decision,
        FallbackDecision::RejectOperation(DegradationError::DependencyDown)
    );

    // Execute with fallback rejects operation
    let res = execute_with_fallback(
        &env,
        module,
        dep,
        || Ok(123u64),
        |_strat| Ok(456u64),
    );
    assert_eq!(res.unwrap_err(), Error::DependencyDegraded);
}
