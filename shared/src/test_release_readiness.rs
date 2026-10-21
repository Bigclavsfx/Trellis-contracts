use soroban_sdk::{symbol_short, testutils::Address as _, Address, BytesN, Env, Symbol, Vec};

use crate::migration::RollbackStrategy;
use crate::release_readiness::{
    create_gate_check, emergency_bypass_signoff, evaluate_release_readiness, get_readiness_report,
    get_rehearsal_count, get_rehearsal_receipt, is_release_ready, rehearse_rollback,
    signoff_release, verify_initialized_addresses, verify_migration_readiness,
    verify_rollback_readiness, verify_smoke_test_readiness, GateCheckStatus, GateKind,
    InitializedAddress, ReleaseGateError, ReleaseManifest, ReleaseModule, RollbackRehearsalParams,
};

#[test]
fn test_release_readiness_gate_all_modules_passing() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Treasury);
    modules.push_back(ReleaseModule::Aid);
    modules.push_back(ReleaseModule::Referral);
    modules.push_back(ReleaseModule::Governance);
    modules.push_back(ReleaseModule::Oracle);
    modules.push_back(ReleaseModule::Marketplace);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    for i in 0..modules.len() {
        let module = modules.get(i).unwrap();

        // 1. Migration Gate
        checks.push_back(create_gate_check(
            symbol_short!("mig_v2"),
            GateKind::Migration,
            module,
            GateCheckStatus::Passed,
            symbol_short!("mig_ok"),
            now,
        ));

        // 2. Security Gate
        checks.push_back(create_gate_check(
            symbol_short!("sec_aud"),
            GateKind::Security,
            module,
            GateCheckStatus::Passed,
            symbol_short!("aud_ok"),
            now,
        ));

        // 3. Smoke Test Gate
        checks.push_back(create_gate_check(
            symbol_short!("smk_wir"),
            GateKind::SmokeTest,
            module,
            GateCheckStatus::Passed,
            symbol_short!("smk_ok"),
            now,
        ));

        // 4. Rollback Rehearsal Gate
        checks.push_back(create_gate_check(
            symbol_short!("rlb_reh"),
            GateKind::RollbackRehearsal,
            module,
            GateCheckStatus::Passed,
            symbol_short!("rlb_ok"),
            now,
        ));
    }

    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_2_0"),
        modules,
        checks,
        signoff_admin: admin,
        exception_marker: None,
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(report.is_ready);
    assert_eq!(report.passed_checks, 24);
    assert_eq!(report.failed_checks, 0);
    assert_eq!(report.missing_gates, 0);
    assert_eq!(report.bypassed_checks, 0);

    assert!(is_release_ready(&env, &symbol_short!("rel_2_0")));
    let retrieved = get_readiness_report(&env, &symbol_short!("rel_2_0")).unwrap();
    assert_eq!(retrieved.release_version, symbol_short!("rel_2_0"));
    assert!(retrieved.is_ready);
}

#[test]
fn test_blocks_release_when_migration_missing() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Aid);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    // Missing GateKind::Migration!
    checks.push_back(create_gate_check(
        symbol_short!("sec_aud"),
        GateKind::Security,
        ReleaseModule::Aid,
        GateCheckStatus::Passed,
        symbol_short!("aud_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("smk_wir"),
        GateKind::SmokeTest,
        ReleaseModule::Aid,
        GateCheckStatus::Passed,
        symbol_short!("smk_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("rlb_reh"),
        GateKind::RollbackRehearsal,
        ReleaseModule::Aid,
        GateCheckStatus::Passed,
        symbol_short!("rlb_ok"),
        now,
    ));

    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_aid"),
        modules,
        checks,
        signoff_admin: admin,
        exception_marker: None,
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(!report.is_ready);
    assert_eq!(report.missing_gates, 1);
    assert!(!is_release_ready(&env, &symbol_short!("rel_aid")));
}

#[test]
fn test_blocks_release_when_security_check_missing() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Treasury);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    checks.push_back(create_gate_check(
        symbol_short!("mig_v2"),
        GateKind::Migration,
        ReleaseModule::Treasury,
        GateCheckStatus::Passed,
        symbol_short!("mig_ok"),
        now,
    ));
    // Missing GateKind::Security!
    checks.push_back(create_gate_check(
        symbol_short!("smk_wir"),
        GateKind::SmokeTest,
        ReleaseModule::Treasury,
        GateCheckStatus::Passed,
        symbol_short!("smk_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("rlb_reh"),
        GateKind::RollbackRehearsal,
        ReleaseModule::Treasury,
        GateCheckStatus::Passed,
        symbol_short!("rlb_ok"),
        now,
    ));

    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_trs"),
        modules,
        checks,
        signoff_admin: admin,
        exception_marker: None,
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(!report.is_ready);
    assert_eq!(report.missing_gates, 1);
}

#[test]
fn test_blocks_release_when_smoke_test_missing() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Marketplace);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    checks.push_back(create_gate_check(
        symbol_short!("mig_v2"),
        GateKind::Migration,
        ReleaseModule::Marketplace,
        GateCheckStatus::Passed,
        symbol_short!("mig_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("sec_aud"),
        GateKind::Security,
        ReleaseModule::Marketplace,
        GateCheckStatus::Passed,
        symbol_short!("aud_ok"),
        now,
    ));
    // Missing GateKind::SmokeTest!
    checks.push_back(create_gate_check(
        symbol_short!("rlb_reh"),
        GateKind::RollbackRehearsal,
        ReleaseModule::Marketplace,
        GateCheckStatus::Passed,
        symbol_short!("rlb_ok"),
        now,
    ));

    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_mkt"),
        modules,
        checks,
        signoff_admin: admin,
        exception_marker: None,
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(!report.is_ready);
    assert_eq!(report.missing_gates, 1);
}

#[test]
fn test_blocks_release_when_rollback_verification_missing() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Oracle);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    checks.push_back(create_gate_check(
        symbol_short!("mig_v2"),
        GateKind::Migration,
        ReleaseModule::Oracle,
        GateCheckStatus::Passed,
        symbol_short!("mig_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("sec_aud"),
        GateKind::Security,
        ReleaseModule::Oracle,
        GateCheckStatus::Passed,
        symbol_short!("aud_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("smk_wir"),
        GateKind::SmokeTest,
        ReleaseModule::Oracle,
        GateCheckStatus::Passed,
        symbol_short!("smk_ok"),
        now,
    ));
    // Missing GateKind::RollbackRehearsal!

    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_orc"),
        modules,
        checks,
        signoff_admin: admin,
        exception_marker: None,
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(!report.is_ready);
    assert_eq!(report.missing_gates, 1);
}

#[test]
fn test_blocks_release_on_failed_or_pending_check() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Referral);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    checks.push_back(create_gate_check(
        symbol_short!("mig_v2"),
        GateKind::Migration,
        ReleaseModule::Referral,
        GateCheckStatus::Failed, // Check failed!
        symbol_short!("err_mig"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("sec_aud"),
        GateKind::Security,
        ReleaseModule::Referral,
        GateCheckStatus::Passed,
        symbol_short!("aud_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("smk_wir"),
        GateKind::SmokeTest,
        ReleaseModule::Referral,
        GateCheckStatus::Passed,
        symbol_short!("smk_ok"),
        now,
    ));
    checks.push_back(create_gate_check(
        symbol_short!("rlb_reh"),
        GateKind::RollbackRehearsal,
        ReleaseModule::Referral,
        GateCheckStatus::Passed,
        symbol_short!("rlb_ok"),
        now,
    ));

    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_ref"),
        modules,
        checks,
        signoff_admin: admin,
        exception_marker: None,
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(!report.is_ready);
    assert_eq!(report.failed_checks, 1);
}

#[test]
fn test_emergency_exception_marker_bypass() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let mut modules = Vec::new(&env);
    modules.push_back(ReleaseModule::Governance);

    let mut checks = Vec::new(&env);
    let now = 1_000_000u64;

    // Has exception marker
    let manifest = ReleaseManifest {
        release_version: symbol_short!("rel_emrg"),
        modules,
        checks, // empty checks bypassed by emergency exception
        signoff_admin: admin,
        exception_marker: Some(symbol_short!("emrg_fix")),
    };

    let report = evaluate_release_readiness(&env, &manifest).unwrap();
    assert!(report.is_ready);
    assert_eq!(report.missing_gates, 0);
    assert_eq!(report.bypassed_checks, 4);
    assert!(is_release_ready(&env, &symbol_short!("rel_emrg")));
}

#[test]
fn test_rollback_rehearsal_revert_strategy() {
    let env = Env::default();
    let prev_hash = BytesN::from_array(&env, &[7u8; 32]);

    let params = RollbackRehearsalParams {
        module: ReleaseModule::Aid,
        current_version: 1,
        target_version: 2,
        previous_wasm_hash: prev_hash,
        strategy: RollbackStrategy::Revert,
        simulate_regression: true,
    };

    let receipt = rehearse_rollback(&env, &params).unwrap();
    assert_eq!(receipt.rehearsal_id, 1);
    assert_eq!(receipt.module, ReleaseModule::Aid);
    assert_eq!(receipt.from_version, 2);
    assert_eq!(receipt.restored_version, 1);
    assert!(receipt.state_intact);
    assert!(receipt.passed);

    assert_eq!(get_rehearsal_count(&env), 1);
    let fetched = get_rehearsal_receipt(&env, 1).unwrap();
    assert_eq!(fetched.rehearsal_id, 1);
    assert!(fetched.passed);
}

#[test]
fn test_rollback_rehearsal_forward_fix_strategy() {
    let env = Env::default();
    let prev_hash = BytesN::from_array(&env, &[8u8; 32]);

    let params = RollbackRehearsalParams {
        module: ReleaseModule::Treasury,
        current_version: 1,
        target_version: 2,
        previous_wasm_hash: prev_hash,
        strategy: RollbackStrategy::ForwardFix,
        simulate_regression: true,
    };

    let receipt = rehearse_rollback(&env, &params).unwrap();
    assert_eq!(receipt.restored_version, 2);
    assert!(receipt.state_intact);
    assert!(receipt.passed);
}

#[test]
fn test_rollback_rehearsal_manual_strategy_blocks() {
    let env = Env::default();
    let prev_hash = BytesN::from_array(&env, &[9u8; 32]);

    let params = RollbackRehearsalParams {
        module: ReleaseModule::Governance,
        current_version: 1,
        target_version: 2,
        previous_wasm_hash: prev_hash,
        strategy: RollbackStrategy::Manual,
        simulate_regression: true,
    };

    let receipt = rehearse_rollback(&env, &params).unwrap();
    // Manual strategy cannot automatically recover without operator action!
    assert!(!receipt.passed);
    assert!(!receipt.state_intact);
}

#[test]
fn test_rehearsal_rejects_invalid_version_order() {
    let env = Env::default();
    let prev_hash = BytesN::from_array(&env, &[1u8; 32]);

    let params = RollbackRehearsalParams {
        module: ReleaseModule::Marketplace,
        current_version: 2,
        target_version: 2, // Must be > current_version
        previous_wasm_hash: prev_hash,
        strategy: RollbackStrategy::Revert,
        simulate_regression: false,
    };

    let err = rehearse_rollback(&env, &params).unwrap_err();
    assert_eq!(err, ReleaseGateError::RehearsalSimulationFailed);
}

#[test]
fn test_verify_migration_readiness_normal_and_failure() {
    let now = 100_000u64;
    // Normal pass: version increments, dry run journal present, 0 unmigrated records
    let check = verify_migration_readiness(ReleaseModule::Treasury, 1, 2, true, 0, now).unwrap();
    assert_eq!(check.status, GateCheckStatus::Passed);
    assert_eq!(check.kind, GateKind::Migration);

    // Failure: unmigrated records > 0
    let err1 = verify_migration_readiness(ReleaseModule::Treasury, 1, 2, true, 5, now).unwrap_err();
    assert_eq!(err1, ReleaseGateError::MissingMigrationVerification);

    // Failure: missing dry run journal
    let err2 = verify_migration_readiness(ReleaseModule::Treasury, 1, 2, false, 0, now).unwrap_err();
    assert_eq!(err2, ReleaseGateError::MissingMigrationVerification);

    // Failure: invalid version order
    let err3 = verify_migration_readiness(ReleaseModule::Treasury, 2, 2, true, 0, now).unwrap_err();
    assert_eq!(err3, ReleaseGateError::MissingMigrationVerification);
}

#[test]
fn test_verify_smoke_test_readiness_normal_and_failure() {
    let now = 100_000u64;
    // Normal pass
    let check = verify_smoke_test_readiness(ReleaseModule::Aid, true, true, true, now).unwrap();
    assert_eq!(check.status, GateCheckStatus::Passed);
    assert_eq!(check.kind, GateKind::SmokeTest);

    // Failure: RPC unhealthy
    let err1 = verify_smoke_test_readiness(ReleaseModule::Aid, false, true, true, now).unwrap_err();
    assert_eq!(err1, ReleaseGateError::MissingSmokeTest);

    // Failure: getter liveness broken
    let err2 = verify_smoke_test_readiness(ReleaseModule::Aid, true, false, true, now).unwrap_err();
    assert_eq!(err2, ReleaseGateError::MissingSmokeTest);

    // Failure: client binding broken
    let err3 = verify_smoke_test_readiness(ReleaseModule::Aid, true, true, false, now).unwrap_err();
    assert_eq!(err3, ReleaseGateError::MissingSmokeTest);
}

#[test]
fn test_verify_rollback_readiness_normal_and_failure() {
    let now = 100_000u64;
    // Normal pass: Revert strategy, snapshot stored, rehearsal passed
    let check = verify_rollback_readiness(ReleaseModule::Referral, RollbackStrategy::Revert, true, true, now).unwrap();
    assert_eq!(check.status, GateCheckStatus::Passed);
    assert_eq!(check.kind, GateKind::RollbackRehearsal);

    // Failure: snapshot missing
    let err1 = verify_rollback_readiness(ReleaseModule::Referral, RollbackStrategy::Revert, false, true, now).unwrap_err();
    assert_eq!(err1, ReleaseGateError::MissingRollbackRehearsal);

    // Failure: rehearsal failed
    let err2 = verify_rollback_readiness(ReleaseModule::Referral, RollbackStrategy::Revert, true, false, now).unwrap_err();
    assert_eq!(err2, ReleaseGateError::MissingRollbackRehearsal);

    // Failure: Manual strategy cannot automatically recover
    let err3 = verify_rollback_readiness(ReleaseModule::Referral, RollbackStrategy::Manual, true, true, now).unwrap_err();
    assert_eq!(err3, ReleaseGateError::MissingRollbackRehearsal);
}

#[test]
fn test_release_signoff_authorization() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    crate::auth::set_admin(&env, &admin);

    let rel_version = symbol_short!("rel_test");

    // Attacker cannot signoff
    let err = signoff_release(&env, &attacker, &rel_version);
    assert_eq!(err.err(), Some(crate::errors::Error::Unauthorized));

    // Admin cannot signoff if release is not evaluated/ready
    let err2 = signoff_release(&env, &admin, &rel_version);
    assert_eq!(err2.err(), Some(crate::errors::Error::ConfigInvalid));
}

#[test]
fn test_emergency_dual_bypass_signoff() {
    let env = Env::default();
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);
    crate::auth::set_admin(&env, &admin1);

    let rel_version = symbol_short!("rel_emrg");

    // Single admin twice rejected
    let err1 = emergency_bypass_signoff(&env, &admin1, &admin1, &rel_version, symbol_short!("hotfix"));
    assert_eq!(err1.err(), Some(crate::errors::Error::InvalidArgument));

    // Set secondary admin permissions
    crate::auth::grant_role(&env, &admin1, &admin2, crate::auth::Role::Admin).unwrap();
    let res = emergency_bypass_signoff(&env, &admin1, &admin2, &rel_version, symbol_short!("hotfix"));
    assert!(res.is_ok());
}

#[test]
fn test_initialized_addresses_all_set_passes_smoke_gate() {
    let env = Env::default();
    let mut entries = Vec::new(&env);
    entries.push_back(InitializedAddress {
        label: Symbol::new(&env, "aid_treasury"),
        address: Some(Address::generate(&env)),
    });
    entries.push_back(InitializedAddress {
        label: Symbol::new(&env, "treasury_referral"),
        address: Some(Address::generate(&env)),
    });

    let check = verify_initialized_addresses(ReleaseModule::Aid, &entries, 1_000).unwrap();

    assert_eq!(check.kind, GateKind::SmokeTest);
    assert_eq!(check.module, ReleaseModule::Aid);
    assert_eq!(check.status, GateCheckStatus::Passed);
    assert_eq!(check.executed_at, 1_000);
}

#[test]
fn test_initialized_addresses_one_unset_entry_fails_smoke_gate() {
    let env = Env::default();
    let mut entries = Vec::new(&env);
    entries.push_back(InitializedAddress {
        label: Symbol::new(&env, "aid_treasury"),
        address: Some(Address::generate(&env)),
    });
    entries.push_back(InitializedAddress {
        label: Symbol::new(&env, "treasury_referral"),
        address: None,
    });

    let result = verify_initialized_addresses(ReleaseModule::Aid, &entries, 1_000);

    assert_eq!(result, Err(ReleaseGateError::MissingSmokeTest));
}

#[test]
fn test_initialized_addresses_empty_list_fails_smoke_gate() {
    let env = Env::default();
    let entries: Vec<InitializedAddress> = Vec::new(&env);

    let result = verify_initialized_addresses(ReleaseModule::Aid, &entries, 1_000);

    assert_eq!(result, Err(ReleaseGateError::MissingSmokeTest));
}
