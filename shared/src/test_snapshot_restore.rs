use soroban_sdk::{symbol_short, Env, String, Symbol, Vec};

use crate::snapshot_restore::{
    clear_quarantine, execute_restore_verification_and_rebuild, get_latest_restore_receipt,
    get_stored_derived_view, is_module_quarantined, rebuild_derived_views,
    reconcile_derived_views, rollback_restore, verify_critical_data_invariants,
    CanonicalRestoreRecord, CriticalRecordKind, DerivedViewEntry, DerivedViewKind,
    RestoreModule, RestoreSeverity, RestoreVerificationFailure, SnapshotRestoreError,
};

#[test]
fn test_treasury_clean_restore_and_derived_view_rebuild() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    // 1. Vault reserve balance
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Treasury,
        kind: CriticalRecordKind::TreasuryBalance,
        record_id: 1,
        parent_id: 0,
        entity_symbol: symbol_short!("reserve"),
        amount: 50_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // 2. Rewards category balance
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Treasury,
        kind: CriticalRecordKind::TreasuryBalance,
        record_id: 2,
        parent_id: 0,
        entity_symbol: symbol_short!("rewards"),
        amount: 25_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // 3. Tracked internal liability
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Treasury,
        kind: CriticalRecordKind::TreasuryLiability,
        record_id: 3,
        parent_id: 0,
        entity_symbol: symbol_short!("liab"),
        amount: 60_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // 4. Whitelisted strategy
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Treasury,
        kind: CriticalRecordKind::TreasuryStrategy,
        record_id: 101,
        parent_id: 0,
        entity_symbol: symbol_short!("strat_a"),
        amount: 10_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });

    let existing_derived = Vec::new(&env);

    let report = execute_restore_verification_and_rebuild(
        &env,
        RestoreModule::Treasury,
        &canonical_records,
        &existing_derived,
        false, // not dry-run
        false, // not strict
    )
    .unwrap();

    assert!(report.receipt.passed);
    assert_eq!(report.receipt.canonical_records_checked, 4);
    assert_eq!(report.receipt.derived_views_rebuilt, 3); // strat_idx + 2 cat_bal
    assert_eq!(report.receipt.mismatches_count, 0);
    assert!(!report.receipt.quarantined);

    // Verify stored views in contract state
    let stored_strat = get_stored_derived_view(&env, RestoreModule::Treasury, symbol_short!("strat_idx"), 101);
    assert!(stored_strat.is_some());
    let strat = stored_strat.unwrap();
    assert_eq!(strat.numeric_value, 10_000);
    assert!(strat.is_active);
}

#[test]
fn test_treasury_solvency_deficit_fails_loudly_with_repair_steps() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    // Vault reserve is only 20,000
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Treasury,
        kind: CriticalRecordKind::TreasuryBalance,
        record_id: 1,
        parent_id: 0,
        entity_symbol: symbol_short!("reserve"),
        amount: 20_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // Internal liability is 50,000 (deficit of 30,000)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Treasury,
        kind: CriticalRecordKind::TreasuryLiability,
        record_id: 2,
        parent_id: 0,
        entity_symbol: symbol_short!("liab"),
        amount: 50_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });

    let existing_derived = Vec::new(&env);

    let report_res = execute_restore_verification_and_rebuild(
        &env,
        RestoreModule::Treasury,
        &canonical_records,
        &existing_derived,
        false,
        true, // strict mode: must return Err
    );

    assert_eq!(report_res.unwrap_err(), SnapshotRestoreError::SolvencyDeficit);

    // Verify module is quarantined in instance storage
    assert!(is_module_quarantined(&env, RestoreModule::Treasury));

    // Inspect mismatches via non-strict mode
    let report = execute_restore_verification_and_rebuild(
        &env,
        RestoreModule::Treasury,
        &canonical_records,
        &existing_derived,
        true, // dry_run
        false,
    );
    // Dry-run should succeed in returning report or fail if quarantined
    // Clear quarantine to test inspection
    clear_quarantine(&env, RestoreModule::Treasury);
    let dry_report = execute_restore_verification_and_rebuild(
        &env,
        RestoreModule::Treasury,
        &canonical_records,
        &existing_derived,
        true,
        false,
    )
    .unwrap();

    assert!(!dry_report.receipt.passed);
    assert_eq!(dry_report.mismatches.len(), 1);
    let mismatch = dry_report.mismatches.get(0).unwrap();
    assert_eq!(mismatch.failure_kind, RestoreVerificationFailure::SolvencyDeficit);
    assert_eq!(mismatch.expected_val, 50_000);
    assert_eq!(mismatch.actual_val, 20_000);
    assert_eq!(mismatch.severity, RestoreSeverity::Critical);
}

#[test]
fn test_aid_orphaned_claim_and_duplicate_record_detection() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    // Valid Aid disbursement ID 201
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Aid,
        kind: CriticalRecordKind::AidRecord,
        record_id: 201,
        parent_id: 0,
        entity_symbol: symbol_short!("donor_1"),
        amount: 15_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // Duplicate Aid disbursement ID 201
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Aid,
        kind: CriticalRecordKind::AidRecord,
        record_id: 201,
        parent_id: 0,
        entity_symbol: symbol_short!("donor_1"),
        amount: 15_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // Orphaned Claim referencing non-existent Aid disbursement ID 999
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Aid,
        kind: CriticalRecordKind::AidClaim,
        record_id: 501,
        parent_id: 999, // Missing parent!
        entity_symbol: symbol_short!("recip_1"),
        amount: 5_000,
        status: symbol_short!("claimed"),
        auxiliary_value: 0,
    });

    let mismatches = verify_critical_data_invariants(&env, RestoreModule::Aid, &canonical_records);
    assert_eq!(mismatches.len(), 2);

    let m1 = mismatches.get(0).unwrap();
    assert_eq!(m1.failure_kind, RestoreVerificationFailure::DuplicateRecordKey);
    assert_eq!(m1.target_id, 201);
    assert_eq!(m1.severity, RestoreSeverity::High);

    let m2 = mismatches.get(1).unwrap();
    assert_eq!(m2.failure_kind, RestoreVerificationFailure::OrphanedRecord);
    assert_eq!(m2.target_id, 501);
    assert_eq!(m2.expected_val, 999);
    assert_eq!(m2.severity, RestoreSeverity::High);
}

#[test]
fn test_referral_orphaned_node_and_boundary_exceeded() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    // Referral edge with parent 888 (missing from state)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Referral,
        kind: CriticalRecordKind::ReferralEdge,
        record_id: 301,
        parent_id: 888, // Missing upline!
        entity_symbol: symbol_short!("partner_a"),
        amount: 0,
        status: symbol_short!("active"),
        auxiliary_value: 12_500, // 12,500 bps exceeds max 10,000 bps
    });

    let mismatches = verify_critical_data_invariants(&env, RestoreModule::Referral, &canonical_records);
    assert_eq!(mismatches.len(), 2);

    let m_orphan = mismatches.get(0).unwrap();
    assert_eq!(m_orphan.failure_kind, RestoreVerificationFailure::OrphanedRecord);
    assert_eq!(m_orphan.target_id, 301);

    let m_bound = mismatches.get(1).unwrap();
    assert_eq!(m_bound.failure_kind, RestoreVerificationFailure::BoundaryExceeded);
    assert_eq!(m_bound.target_id, 301);
    assert_eq!(m_bound.expected_val, 10_000);
    assert_eq!(m_bound.actual_val, 12_500);
}

#[test]
fn test_governance_tally_and_active_proposals_rebuild() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    // Proposal 1: Active
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Governance,
        kind: CriticalRecordKind::GovernanceProposal,
        record_id: 1,
        parent_id: 0,
        entity_symbol: symbol_short!("prop_1"),
        amount: 0,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });
    // Proposal 2: Executed (should NOT be in active proposals index)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Governance,
        kind: CriticalRecordKind::GovernanceProposal,
        record_id: 2,
        parent_id: 0,
        entity_symbol: symbol_short!("prop_2"),
        amount: 0,
        status: symbol_short!("executed"),
        auxiliary_value: 0,
    });
    // Ballot 1 for Proposal 1: 500 votes FOR (auxiliary_value = 1)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Governance,
        kind: CriticalRecordKind::GovernanceBallot,
        record_id: 10,
        parent_id: 1,
        entity_symbol: symbol_short!("voter_a"),
        amount: 500,
        status: symbol_short!("voted"),
        auxiliary_value: 1,
    });
    // Ballot 2 for Proposal 1: 200 votes AGAINST (auxiliary_value = 0)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Governance,
        kind: CriticalRecordKind::GovernanceBallot,
        record_id: 11,
        parent_id: 1,
        entity_symbol: symbol_short!("voter_b"),
        amount: 200,
        status: symbol_short!("voted"),
        auxiliary_value: 0,
    });

    let views = rebuild_derived_views(&env, RestoreModule::Governance, &canonical_records);

    // Should produce 3 views: 1 act_prop (Proposal 1), 1 tally_for (500), 1 tally_agt (200)
    assert_eq!(views.len(), 3);

    let v0 = views.get(0).unwrap();
    assert_eq!(v0.view_name, symbol_short!("act_prop"));
    assert_eq!(v0.key_id, 1);

    let v1 = views.get(1).unwrap();
    assert_eq!(v1.view_name, symbol_short!("tally_for"));
    assert_eq!(v1.numeric_value, 500);

    let v2 = views.get(2).unwrap();
    assert_eq!(v2.view_name, symbol_short!("tally_agt"));
    assert_eq!(v2.numeric_value, 200);
}

#[test]
fn test_marketplace_floor_price_and_listings_rebuild() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    // Listing 1: Open, price 1,000
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Marketplace,
        kind: CriticalRecordKind::MarketplaceListing,
        record_id: 1,
        parent_id: 0,
        entity_symbol: symbol_short!("art_col"),
        amount: 1_000,
        status: symbol_short!("open"),
        auxiliary_value: 0,
    });
    // Listing 2: Open, price 750 (lowest ask -> floor price)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Marketplace,
        kind: CriticalRecordKind::MarketplaceListing,
        record_id: 2,
        parent_id: 0,
        entity_symbol: symbol_short!("art_col"),
        amount: 750,
        status: symbol_short!("open"),
        auxiliary_value: 0,
    });
    // Listing 3: Sold, price 500 (should NOT be in open listings or floor calculation)
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Marketplace,
        kind: CriticalRecordKind::MarketplaceListing,
        record_id: 3,
        parent_id: 0,
        entity_symbol: symbol_short!("art_col"),
        amount: 500,
        status: symbol_short!("sold"),
        auxiliary_value: 0,
    });

    let views = rebuild_derived_views(&env, RestoreModule::Marketplace, &canonical_records);

    // 2 open listings + 1 floor price
    assert_eq!(views.len(), 3);

    let floor_view = views.get(2).unwrap();
    assert_eq!(floor_view.view_name, symbol_short!("floor_p"));
    assert_eq!(floor_view.numeric_value, 750);
}

#[test]
fn test_derived_view_drift_detection_and_reconciliation() {
    let env = Env::default();

    // Rebuilt authoritative views
    let mut rebuilt = Vec::new(&env);
    rebuilt.push_back(DerivedViewEntry {
        module: RestoreModule::Treasury,
        view_name: symbol_short!("cat_bal"),
        kind: DerivedViewKind::Cache,
        key_id: 0,
        key_symbol: symbol_short!("reserve"),
        numeric_value: 80_000,
        is_active: true,
    });
    rebuilt.push_back(DerivedViewEntry {
        module: RestoreModule::Treasury,
        view_name: symbol_short!("strat_idx"),
        kind: DerivedViewKind::Index,
        key_id: 101,
        key_symbol: symbol_short!("strat_a"),
        numeric_value: 10_000,
        is_active: true,
    });

    // Existing derived views with drift:
    // 1. Stale counter: cat_bal has 60,000 instead of 80,000
    // 2. Missing strat_idx 101
    // 3. Orphaned index entry 999
    let mut existing = Vec::new(&env);
    existing.push_back(DerivedViewEntry {
        module: RestoreModule::Treasury,
        view_name: symbol_short!("cat_bal"),
        kind: DerivedViewKind::Cache,
        key_id: 0,
        key_symbol: symbol_short!("reserve"),
        numeric_value: 60_000, // Stale!
        is_active: true,
    });
    existing.push_back(DerivedViewEntry {
        module: RestoreModule::Treasury,
        view_name: symbol_short!("strat_idx"),
        kind: DerivedViewKind::Index,
        key_id: 999, // Orphaned!
        key_symbol: symbol_short!("orphan"),
        numeric_value: 5_000,
        is_active: true,
    });

    let drifts = reconcile_derived_views(&env, RestoreModule::Treasury, &rebuilt, &existing);

    // Expect 3 drift findings:
    // 1. cat_bal stale counter mismatch
    // 2. strat_idx 101 missing from existing
    // 3. strat_idx 999 orphaned in existing
    assert_eq!(drifts.len(), 3);

    let d0 = drifts.get(0).unwrap();
    assert_eq!(d0.failure_kind, RestoreVerificationFailure::DerivedViewDrift);
    assert_eq!(d0.expected_val, 80_000);
    assert_eq!(d0.actual_val, 60_000);

    let d1 = drifts.get(1).unwrap();
    assert_eq!(d1.failure_kind, RestoreVerificationFailure::DerivedViewDrift);
    assert_eq!(d1.target_id, 101);

    let d2 = drifts.get(2).unwrap();
    assert_eq!(d2.failure_kind, RestoreVerificationFailure::DerivedViewDrift);
    assert_eq!(d2.target_id, 999);
}

#[test]
fn test_rollback_restores_pre_verification_derived_state() {
    let env = Env::default();

    let mut canonical_records = Vec::new(&env);
    canonical_records.push_back(CanonicalRestoreRecord {
        module: RestoreModule::Aid,
        kind: CriticalRecordKind::AidRecord,
        record_id: 201,
        parent_id: 0,
        entity_symbol: symbol_short!("donor"),
        amount: 25_000,
        status: symbol_short!("active"),
        auxiliary_value: 0,
    });

    let mut existing_derived = Vec::new(&env);
    // Prior state had old search index entry 100
    existing_derived.push_back(DerivedViewEntry {
        module: RestoreModule::Aid,
        view_name: symbol_short!("search"),
        kind: DerivedViewKind::Index,
        key_id: 100,
        key_symbol: symbol_short!("old_donor"),
        numeric_value: 10_000,
        is_active: true,
    });

    let report = execute_restore_verification_and_rebuild(
        &env,
        RestoreModule::Aid,
        &canonical_records,
        &existing_derived,
        false,
        false,
    )
    .unwrap();

    let receipt_id = report.receipt.receipt_id;

    // Derived view was rebuilt with record 201
    let stored_new = get_stored_derived_view(&env, RestoreModule::Aid, symbol_short!("search"), 201);
    assert!(stored_new.is_some());

    // Execute rollback
    let rollback_receipt = rollback_restore(&env, receipt_id).unwrap();
    assert_eq!(rollback_receipt.receipt_id, receipt_id);
    assert!(!rollback_receipt.passed);
    assert!(!rollback_receipt.quarantined);

    // Prior view (100) is restored
    let restored_old = get_stored_derived_view(&env, RestoreModule::Aid, symbol_short!("search"), 100);
    assert!(restored_old.is_some());
    assert_eq!(restored_old.unwrap().numeric_value, 10_000);

    // Rollback cannot be applied twice
    let double_rollback = rollback_restore(&env, receipt_id);
    assert_eq!(double_rollback.unwrap_err(), SnapshotRestoreError::RollbackAlreadyApplied);
}
