use soroban_sdk::{Env, Vec};
use crate::reconciliation::{run_reconciliation, SourceRecord, DriftType};

#[test]
fn test_reconciliation_scenarios() {
    let env = Env::default();

    // Setup records
    let mut ledger_records = Vec::new(&env);
    let mut db_records = Vec::new(&env);
    let mut user_records = Vec::new(&env);

    let current_timestamp = 10000;

    // 1. Missing Record
    // Ledger has id:1, DB is missing it
    ledger_records.push_back(SourceRecord { id: 1, amount: 100, timestamp: current_timestamp });

    // 2. Inconsistent Balance
    // Ledger has id:2 amount: 200, DD has id:2 amount: 150
    ledger_records.push_back(SourceRecord { id: 2, amount: 200, timestamp: current_timestamp });
    db_records.push_back(SourceRecord { id: 2, amount: 150, timestamp: current_timestamp });

    // 3. Stale Record
    // Ledger has id:3 timestamp: 5000, DB has id:3 timestamp: 3000 (diff > 1000)
    ledger_records.push_back(SourceRecord { id: 3, amount: 300, timestamp: 5000 });
    db_records.push_back(SourceRecord { id: 3, amount: 300, timestamp: 3000 });

    // 4. Duplicate Record in DB
    // DE has two records with id:4
    ledger_records.push_back(SourceRecord { id: 4, amount: 400, timestamp: current_timestamp });
    db_records.push_back(SourceRecord { id: 4, amount: 400, timestamp: current_timestamp });
    db_records.push_back(SourceRecord { id: 4, amount: 400, timestamp: current_timestamp });

    // 5. Orphan DB record (not in ledger)
    db_records.push_back(SourceRecord { id: 5, amount: 500, timestamp: current_timestamp });

    // Populate user_records with some values to prevent missing record drifts for all of them
    user_records.push_back(SourceRecord { id: 1, amount: 100, timestamp: current_timestamp });
    user_records.push_back(SourceRecord { id: 2, amount: 200, timestamp: current_timestamp });
    user_records.push_back(SourceRecord { id: 3, amount: 300, timestamp: current_timestamp });
    user_records.push_back(SourceRecord { id: 4, amount: 400, timestamp: current_timestamp });

    let report = run_reconciliation(&env, ledger_records, db_records, user_records, current_timestamp);

    let mut missing = false;
    let mut inconsistent = false;
    let mut stale = false;
    let mut duplicate = false;
    let mut orphan = false;

    for drift in report.drifts_detected {
        match drift.drift_type {
            DriftType::MissingRecord => {
                if drift.record_id == 1 { missing = true; }
                if drift.record_id == 5 { orphan = true; }
            },
            DriftType::InconsistentBalance => {
                if drift.record_id == 2 { inconsistent = true; }
            },
            DriftType::StaleRecord => {
                if drift.record_id == 3 { stale = true; }
            },
            DriftType::DuplicateRecord => {
                if drift.record_id == 4 { duplicate = true; }
            }
        }
    }

    assert!(missing, "Expected MissingRecord drift for id 1");
    assert!(inconsistent, "Expected InconsistentBalance drift for id 2");
    assert!(stale, "Expected StaleRecord drift for id 3");
    assert!(duplicate, "Expected DuplicateRecord drift for id 4");
    assert!(orphan, "Expected MissingRecord drift for id 5 (orphan in DB)");
}

// ===========================================================================
// Comprehensive Automated Tests for Issue #238 Projection Reconciliation Job
// ===========================================================================

use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, Address, Symbol,
};
use crate::reconciliation::{
    execute_projection_repairs, reconcile_aid_storage, reconcile_governance_storage,
    reconcile_marketplace_storage, reconcile_oracle_storage, reconcile_referral_storage,
    reconcile_treasury_storage, run_paginated_projection_reconciliation,
    run_projection_reconciliation, PaginationParams, ProjectionDriftKind,
    ProjectionRepairInstruction, ReconciliationError, ReconciliationModule,
    ReconciliationScopeConfig, ReconciliationSeverity, AID_DONOR_CNT,
    AID_RCP_CNT, AID_RECORD, AID_SEARCH_CNT, AID_SEARCH_PAGE, GOV_ADMIN_CNT,
    GOV_ADMIN_SET, GOV_APPROVAL, GOV_PROPOSAL, MKT_CANONICAL_AUCTION, MKT_CANONICAL_LISTING,
    MKT_COLL_AUCTIONS, MKT_COLL_LISTINGS, ORACLE_LATEST_CNT, ORACLE_LATEST_TS,
    ORACLE_SUBMISSIONS, REF_ACCRUED, REF_ADDR, REF_CODE, REF_LIFETIME, TREASURY_STRAT_LST,
    TREASURY_STRAT_OK, TREASURY_STRAT_POS, TREASURY_STRAT_TOT,
};
use crate::storage::{instance_set, persistent_read, persistent_set};

#[contract]
pub struct DummyContract;

#[contractimpl]
impl DummyContract {
    pub fn noop(_env: Env) {}
}

#[test]
fn test_clean_state_projection_reconciliation() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let admin = Address::generate(&env);
        crate::auth::set_admin(&env, &admin);

        let mut config = ReconciliationScopeConfig::new(&env);

        // 1. Clean Treasury setup
        let strategy = Address::generate(&env);
        let token = Address::generate(&env);
        let category = symbol_short!("cat_a");
        persistent_set(&env, &(TREASURY_STRAT_POS, token.clone(), category.clone(), strategy.clone()), &500_i128);
        persistent_set(&env, &(TREASURY_STRAT_TOT, strategy.clone()), &500_i128);
        persistent_set(&env, &(TREASURY_STRAT_OK, strategy.clone()), &true);
        let mut strat_list = Vec::new(&env);
        strat_list.push_back(strategy.clone());
        instance_set(&env, &TREASURY_STRAT_LST, &strat_list);

        config.treasury_strategies.push_back(strategy.clone());
        config.treasury_tokens.push_back(token);
        config.treasury_categories.push_back(category);

        // 2. Clean Aid setup
        let donor = Address::generate(&env);
        let recipient = Address::generate(&env);
        let aid_id = 1_u64;
        persistent_set(&env, &(AID_RECORD, aid_id), &(donor.clone(), recipient.clone(), 100_i128));
        persistent_set(&env, &AID_SEARCH_CNT, &1_u32);
        let mut search_page = Vec::new(&env);
        search_page.push_back(aid_id);
        persistent_set(&env, &(AID_SEARCH_PAGE, 0_u32), &search_page);
        persistent_set(&env, &(AID_DONOR_CNT, donor.clone()), &1_u32);
        persistent_set(&env, &(AID_RCP_CNT, recipient.clone()), &1_u32);

        config.aid_ids.push_back(aid_id);
        config.aid_donors.push_back(donor.clone());
        config.aid_recipients.push_back(recipient.clone());

        // 3. Clean Referral setup
        let ref_addr = Address::generate(&env);
        let ref_code = symbol_short!("VIP_CODE");
        persistent_set(&env, &(REF_ADDR, ref_addr.clone()), &ref_code);
        persistent_set(&env, &(REF_CODE, ref_code.clone()), &ref_addr);
        persistent_set(&env, &(REF_ACCRUED, ref_addr.clone()), &100_i128);
        persistent_set(&env, &(REF_LIFETIME, ref_addr.clone()), &200_i128);

        config.referral_addresses.push_back(ref_addr);
        config.referral_codes.push_back(ref_code);

        // 4. Clean Governance setup
        let mut admin_set = Vec::new(&env);
        admin_set.push_back(admin.clone());
        instance_set(&env, &GOV_ADMIN_SET, &admin_set);
        instance_set(&env, &GOV_ADMIN_CNT, &1_u32);
        let prop_id = 42_u32;
        persistent_set(&env, &(GOV_APPROVAL, prop_id, admin.clone()), &true);
        persistent_set(&env, &(GOV_PROPOSAL, prop_id), &1_u32);

        config.governance_proposal_ids.push_back(prop_id);

        // 5. Clean Oracle setup
        let feed_id = symbol_short!("XLM_USD");
        let mut subs = Vec::new(&env);
        subs.push_back((Address::generate(&env), 120_000_i128, 5000_u64));
        persistent_set(&env, &(ORACLE_SUBMISSIONS, feed_id.clone()), &subs);
        persistent_set(&env, &(ORACLE_LATEST_CNT, feed_id.clone()), &1_u32);
        persistent_set(&env, &(ORACLE_LATEST_TS, feed_id.clone()), &5000_u64);

        config.oracle_feed_ids.push_back(feed_id);

        // 6. Clean Marketplace setup
        let collection = Address::generate(&env);
        let listing_id = 7_u64;
        let auction_id = 8_u64;
        persistent_set(&env, &(MKT_CANONICAL_LISTING, listing_id), &(collection.clone(), true));
        persistent_set(&env, &(MKT_CANONICAL_AUCTION, auction_id), &(collection.clone(), true));
        persistent_set(&env, &(MKT_COLL_LISTINGS, collection.clone()), &1_u32);
        persistent_set(&env, &(MKT_COLL_AUCTIONS, collection.clone()), &1_u32);

        config.marketplace_collections.push_back(collection);
        config.marketplace_listing_ids.push_back(listing_id);
        config.marketplace_auction_ids.push_back(auction_id);

        // Run dry-run reconciliation
        let report = run_projection_reconciliation(&env, &config);

        assert!(report.is_clean, "Expected clean reconciliation report with zero drift");
        assert_eq!(report.drifts_detected.len(), 0);
        assert_eq!(report.scanned_modules.len(), 6);
    });
}

#[test]
fn test_treasury_drift_detection_and_root_cause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let strategy = Address::generate(&env);
        let token = Address::generate(&env);
        let category = symbol_short!("res_cat");

        // Canonical position is 1000
        persistent_set(&env, &(TREASURY_STRAT_POS, token.clone(), category.clone(), strategy.clone()), &1000_i128);
        // Cached projection drifted to 800
        persistent_set(&env, &(TREASURY_STRAT_TOT, strategy.clone()), &800_i128);

        // Strategy is approved canonically, but omitted from STRATEGY_LIST vector
        persistent_set(&env, &(TREASURY_STRAT_OK, strategy.clone()), &true);
        let empty_list: Vec<Address> = Vec::new(&env);
        instance_set(&env, &TREASURY_STRAT_LST, &empty_list);

        let mut strategies = Vec::new(&env);
        strategies.push_back(strategy.clone());
        let mut tokens = Vec::new(&env);
        tokens.push_back(token);
        let mut categories = Vec::new(&env);
        categories.push_back(category);

        let drifts = reconcile_treasury_storage(&env, &strategies, &tokens, &categories);

        assert_eq!(drifts.len(), 2);

        let balance_drift = drifts.get(0).unwrap();
        assert_eq!(balance_drift.module, ReconciliationModule::Treasury);
        assert_eq!(balance_drift.kind, ProjectionDriftKind::RunningBalanceMismatch);
        assert_eq!(balance_drift.expected_value, 1000);
        assert_eq!(balance_drift.actual_value, 800);
        assert_eq!(balance_drift.severity, ReconciliationSeverity::Critical);
        assert!(balance_drift.root_cause_hint.len() > 0);

        let whitelist_drift = drifts.get(1).unwrap();
        assert_eq!(whitelist_drift.module, ReconciliationModule::Treasury);
        assert_eq!(whitelist_drift.kind, ProjectionDriftKind::MissingIndexEntry);
        assert_eq!(whitelist_drift.expected_value, 1);
        assert_eq!(whitelist_drift.actual_value, 0);
        assert_eq!(whitelist_drift.severity, ReconciliationSeverity::Warning);
    });
}

#[test]
fn test_aid_drift_detection_and_root_cause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let donor = Address::generate(&env);
        let recipient = Address::generate(&env);

        // Canonical records for aid 1 and aid 2
        persistent_set(&env, &(AID_RECORD, 1_u64), &(donor.clone(), recipient.clone(), 150_i128));
        persistent_set(&env, &(AID_RECORD, 2_u64), &(donor.clone(), recipient.clone(), 250_i128));

        // Stale search count: 1 instead of 2
        persistent_set(&env, &AID_SEARCH_CNT, &1_u32);

        // Search page only contains id 1, missing id 2
        let mut page = Vec::new(&env);
        page.push_back(1_u64);
        persistent_set(&env, &(AID_SEARCH_PAGE, 0_u32), &page);

        // Donor count is stale: 0 instead of 2
        persistent_set(&env, &(AID_DONOR_CNT, donor.clone()), &0_u32);
        // Recipient count is correct: 2
        persistent_set(&env, &(AID_RCP_CNT, recipient.clone()), &2_u32);

        let mut aid_ids = Vec::new(&env);
        aid_ids.push_back(1_u64);
        aid_ids.push_back(2_u64);

        let mut donors = Vec::new(&env);
        donors.push_back(donor);

        let mut recipients = Vec::new(&env);
        recipients.push_back(recipient);

        let drifts = reconcile_aid_storage(&env, &aid_ids, &donors, &recipients);

        assert_eq!(drifts.len(), 3);

        let count_drift = drifts.get(0).unwrap();
        assert_eq!(count_drift.module, ReconciliationModule::Aid);
        assert_eq!(count_drift.kind, ProjectionDriftKind::CountMismatch);
        assert_eq!(count_drift.expected_value, 2);
        assert_eq!(count_drift.actual_value, 1);

        let page_drift = drifts.get(1).unwrap();
        assert_eq!(page_drift.module, ReconciliationModule::Aid);
        assert_eq!(page_drift.kind, ProjectionDriftKind::MissingIndexEntry);
        assert_eq!(page_drift.expected_value, 2);

        let donor_drift = drifts.get(2).unwrap();
        assert_eq!(donor_drift.module, ReconciliationModule::Aid);
        assert_eq!(donor_drift.kind, ProjectionDriftKind::CountMismatch);
        assert_eq!(donor_drift.expected_value, 2);
        assert_eq!(donor_drift.actual_value, 0);
    });
}

#[test]
fn test_referral_drift_detection_and_root_cause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let addr = Address::generate(&env);
        let code = symbol_short!("BROKEN");

        // Address maps to code, but code reverse mapping is absent
        persistent_set(&env, &(REF_ADDR, addr.clone()), &code);

        // Accrued claimable reward exceeds LifetimeAccrued ceiling
        persistent_set(&env, &(REF_ACCRUED, addr.clone()), &500_i128);
        persistent_set(&env, &(REF_LIFETIME, addr.clone()), &300_i128);

        let mut addresses = Vec::new(&env);
        addresses.push_back(addr);
        let mut codes = Vec::new(&env);
        codes.push_back(code);

        let drifts = reconcile_referral_storage(&env, &addresses, &codes);

        assert_eq!(drifts.len(), 2);

        let map_drift = drifts.get(0).unwrap();
        assert_eq!(map_drift.module, ReconciliationModule::Referral);
        assert_eq!(map_drift.kind, ProjectionDriftKind::AsymmetricMapping);

        let ceiling_drift = drifts.get(1).unwrap();
        assert_eq!(ceiling_drift.module, ReconciliationModule::Referral);
        assert_eq!(ceiling_drift.kind, ProjectionDriftKind::InconsistentState);
        assert_eq!(ceiling_drift.expected_value, 500);
        assert_eq!(ceiling_drift.actual_value, 300);
        assert_eq!(ceiling_drift.severity, ReconciliationSeverity::Critical);
    });
}

#[test]
fn test_governance_drift_detection_and_root_cause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let admin1 = Address::generate(&env);
        let admin2 = Address::generate(&env);

        let mut admin_set = Vec::new(&env);
        admin_set.push_back(admin1.clone());
        admin_set.push_back(admin2.clone());
        instance_set(&env, &GOV_ADMIN_SET, &admin_set);

        // Drifted admin count: 1 instead of 2
        instance_set(&env, &GOV_ADMIN_CNT, &1_u32);

        // Proposal 99 has 2 approvals canonically, but cached tally is 1
        let prop_id = 99_u32;
        persistent_set(&env, &(GOV_APPROVAL, prop_id, admin1), &true);
        persistent_set(&env, &(GOV_APPROVAL, prop_id, admin2), &true);
        persistent_set(&env, &(GOV_PROPOSAL, prop_id), &1_u32);

        let mut prop_ids: Vec<u32> = Vec::new(&env);
        prop_ids.push_back(prop_id);

        let drifts = reconcile_governance_storage(&env, &prop_ids);

        assert_eq!(drifts.len(), 2);

        let adm_drift = drifts.get(0).unwrap();
        assert_eq!(adm_drift.module, ReconciliationModule::Governance);
        assert_eq!(adm_drift.kind, ProjectionDriftKind::CountMismatch);
        assert_eq!(adm_drift.expected_value, 2);
        assert_eq!(adm_drift.actual_value, 1);

        let tally_drift = drifts.get(1).unwrap();
        assert_eq!(tally_drift.module, ReconciliationModule::Governance);
        assert_eq!(tally_drift.kind, ProjectionDriftKind::TallyMismatch);
        assert_eq!(tally_drift.expected_value, 2);
        assert_eq!(tally_drift.actual_value, 1);
    });
}

#[test]
fn test_oracle_drift_detection_and_root_cause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let feed_id = symbol_short!("BTC_USD");

        let mut subs = Vec::new(&env);
        subs.push_back((Address::generate(&env), 95_000_i128, 1000_u64));
        subs.push_back((Address::generate(&env), 95_100_i128, 2000_u64));
        persistent_set(&env, &(ORACLE_SUBMISSIONS, feed_id.clone()), &subs);

        // Drifted submission count: 1 instead of 2
        persistent_set(&env, &(ORACLE_LATEST_CNT, feed_id.clone()), &1_u32);
        // Stale timestamp: 1000 instead of 2000
        persistent_set(&env, &(ORACLE_LATEST_TS, feed_id.clone()), &1000_u64);

        let mut feeds = Vec::new(&env);
        feeds.push_back(feed_id);

        let drifts = reconcile_oracle_storage(&env, &feeds);

        assert_eq!(drifts.len(), 2);

        let cnt_drift = drifts.get(0).unwrap();
        assert_eq!(cnt_drift.module, ReconciliationModule::Oracle);
        assert_eq!(cnt_drift.kind, ProjectionDriftKind::CountMismatch);
        assert_eq!(cnt_drift.expected_value, 2);
        assert_eq!(cnt_drift.actual_value, 1);

        let ts_drift = drifts.get(1).unwrap();
        assert_eq!(ts_drift.module, ReconciliationModule::Oracle);
        assert_eq!(ts_drift.kind, ProjectionDriftKind::StaleTimestamp);
        assert_eq!(ts_drift.expected_value, 2000);
        assert_eq!(ts_drift.actual_value, 1000);
    });
}

#[test]
fn test_marketplace_drift_detection_and_root_cause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let coll = Address::generate(&env);

        // 2 active listings canonically
        persistent_set(&env, &(MKT_CANONICAL_LISTING, 1_u64), &(coll.clone(), true));
        persistent_set(&env, &(MKT_CANONICAL_LISTING, 2_u64), &(coll.clone(), true));
        // Cached listings count is 1
        persistent_set(&env, &(MKT_COLL_LISTINGS, coll.clone()), &1_u32);

        // 1 active auction canonically
        persistent_set(&env, &(MKT_CANONICAL_AUCTION, 10_u64), &(coll.clone(), true));
        // Cached auctions count is 0
        persistent_set(&env, &(MKT_COLL_AUCTIONS, coll.clone()), &0_u32);

        let mut collections = Vec::new(&env);
        collections.push_back(coll);
        let mut listing_ids = Vec::new(&env);
        listing_ids.push_back(1_u64);
        listing_ids.push_back(2_u64);
        let mut auction_ids = Vec::new(&env);
        auction_ids.push_back(10_u64);

        let drifts = reconcile_marketplace_storage(&env, &collections, &listing_ids, &auction_ids);

        assert_eq!(drifts.len(), 2);

        let list_drift = drifts.get(0).unwrap();
        assert_eq!(list_drift.module, ReconciliationModule::Marketplace);
        assert_eq!(list_drift.kind, ProjectionDriftKind::CountMismatch);
        assert_eq!(list_drift.expected_value, 2);
        assert_eq!(list_drift.actual_value, 1);

        let auct_drift = drifts.get(1).unwrap();
        assert_eq!(auct_drift.module, ReconciliationModule::Marketplace);
        assert_eq!(auct_drift.kind, ProjectionDriftKind::CountMismatch);
        assert_eq!(auct_drift.expected_value, 1);
        assert_eq!(auct_drift.actual_value, 0);
    });
}

#[test]
fn test_dry_run_safety_guarantee() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let mut config = ReconciliationScopeConfig::new(&env);

        // Setup a drifting state in Treasury
        let strategy = Address::generate(&env);
        let token = Address::generate(&env);
        let category = symbol_short!("yield_cat");
        persistent_set(&env, &(TREASURY_STRAT_POS, token.clone(), category.clone(), strategy.clone()), &999_i128);
        persistent_set(&env, &(TREASURY_STRAT_TOT, strategy.clone()), &333_i128);

        config.treasury_strategies.push_back(strategy.clone());
        config.treasury_tokens.push_back(token.clone());
        config.treasury_categories.push_back(category.clone());

        // Execute dry run
        let report = run_projection_reconciliation(&env, &config);
        assert_eq!(report.drifts_detected.len(), 1);

        // Verify storage was NOT modified whatsoever
        let total_after_dry_run = persistent_read::<_, i128>(&env, &(TREASURY_STRAT_TOT, strategy)).unwrap();
        assert_eq!(total_after_dry_run, 333_i128, "Dry-run must not mutate storage");
    });
}

#[test]
fn test_repair_execution_and_canonical_immutability() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let admin = Address::generate(&env);
        crate::auth::set_admin(&env, &admin);

        // 1. Setup drifting treasury total
        let strategy = Address::generate(&env);
        let token = Address::generate(&env);
        let category = symbol_short!("gov_cat");
        persistent_set(&env, &(TREASURY_STRAT_POS, token.clone(), category.clone(), strategy.clone()), &1250_i128);
        persistent_set(&env, &(TREASURY_STRAT_TOT, strategy.clone()), &500_i128);

        // 2. Setup drifting governance proposal tally
        let prop_id = 101_u32;
        persistent_set(&env, &(GOV_APPROVAL, prop_id, admin.clone()), &true);
        persistent_set(&env, &(GOV_PROPOSAL, prop_id), &0_u32);

        // Formulate repair instructions
        let mut instructions = Vec::new(&env);
        instructions.push_back(ProjectionRepairInstruction {
            module: ReconciliationModule::Treasury,
            entity: soroban_sdk::String::from_str(&env, "treasury.strategy_total"),
            kind: ProjectionDriftKind::RunningBalanceMismatch,
            target_key: TREASURY_STRAT_TOT,
            target_id: 0,
            target_address: Some(strategy.clone()),
            repaired_value: 1250_i128,
        });
        instructions.push_back(ProjectionRepairInstruction {
            module: ReconciliationModule::Governance,
            entity: soroban_sdk::String::from_str(&env, "governance.proposal_approval_tally"),
            kind: ProjectionDriftKind::TallyMismatch,
            target_key: GOV_PROPOSAL,
            target_id: prop_id as u64,
            target_address: None,
            repaired_value: 1_i128,
        });

        // Execute repair
        let receipts = execute_projection_repairs(&env, &admin, &instructions).unwrap();
        assert_eq!(receipts.len(), 2);

        // Assert derived projections are now repaired
        let repaired_total = persistent_read::<_, i128>(&env, &(TREASURY_STRAT_TOT, strategy.clone())).unwrap();
        assert_eq!(repaired_total, 1250);
        let repaired_tally = persistent_read::<_, u32>(&env, &(GOV_PROPOSAL, prop_id)).unwrap();
        assert_eq!(repaired_tally, 1);

        // Assert canonical records remain strictly UNMUTATED
        let canonical_position = persistent_read::<_, i128>(
            &env,
            &(TREASURY_STRAT_POS, token, category, strategy),
        ).unwrap();
        assert_eq!(canonical_position, 1250);
        let canonical_approval = persistent_read::<_, bool>(&env, &(GOV_APPROVAL, prop_id, admin)).unwrap();
        assert!(canonical_approval);
    });
}

#[test]
fn test_repair_idempotency() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, DummyContract);

    let admin = Address::generate(&env);
    let mut instructions = Vec::new(&env);
    instructions.push_back(ProjectionRepairInstruction {
        module: ReconciliationModule::Governance,
        entity: soroban_sdk::String::from_str(&env, "governance.admin_count"),
        kind: ProjectionDriftKind::CountMismatch,
        target_key: GOV_ADMIN_CNT,
        target_id: 0,
        target_address: None,
        repaired_value: 1_i128,
    });

    // Frame 1: Setup and execute first repair
    env.as_contract(&contract_id, || {
        crate::auth::set_admin(&env, &admin);

        let mut admin_set = Vec::new(&env);
        admin_set.push_back(admin.clone());
        instance_set(&env, &GOV_ADMIN_SET, &admin_set);
        // Drifting admin count
        instance_set(&env, &GOV_ADMIN_CNT, &0_u32);

        // Run repair first time
        let receipts1 = execute_projection_repairs(&env, &admin, &instructions).unwrap();
        assert_eq!(receipts1.get(0).unwrap().previous_value, 0);
        assert_eq!(receipts1.get(0).unwrap().new_value, 1);
    });

    // Frame 2: Execute second repair in separate transaction frame (idempotency check)
    env.as_contract(&contract_id, || {
        let receipts2 = execute_projection_repairs(&env, &admin, &instructions).unwrap();
        assert_eq!(receipts2.get(0).unwrap().previous_value, 1);
        assert_eq!(receipts2.get(0).unwrap().new_value, 1);

        // Run governance check to confirm clean state
        let prop_ids: Vec<u32> = Vec::new(&env);
        let drifts = reconcile_governance_storage(&env, &prop_ids);
        assert_eq!(drifts.len(), 0, "Idempotent repair should leave state fully reconciled");
    });
}

#[test]
fn test_repair_authorization_failure() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        crate::auth::set_admin(&env, &admin);

        let instructions: Vec<ProjectionRepairInstruction> = Vec::new(&env);
        let result = execute_projection_repairs(&env, &attacker, &instructions);

        assert_eq!(result, Err(ReconciliationError::Unauthorized));
    });
}

#[test]
fn test_paginated_reconciliation_bounding() {
    let env = Env::default();

    let mut drifts = Vec::new(&env);
    let mut i = 0;
    while i < 5 {
        drifts.push_back(crate::reconciliation::ProjectionDriftItem {
            module: ReconciliationModule::Treasury,
            entity: soroban_sdk::String::from_str(&env, "item"),
            kind: ProjectionDriftKind::RunningBalanceMismatch,
            expected_value: 100,
            actual_value: 50,
            severity: ReconciliationSeverity::Warning,
            root_cause_hint: soroban_sdk::String::from_str(&env, "hint"),
            repair_instruction: ProjectionRepairInstruction {
                module: ReconciliationModule::Treasury,
                entity: soroban_sdk::String::from_str(&env, "item"),
                kind: ProjectionDriftKind::RunningBalanceMismatch,
                target_key: TREASURY_STRAT_TOT,
                target_id: 0,
                target_address: None,
                repaired_value: 100,
            },
        });
        i += 1;
    }

    // Page 1: limit 2, offset 0
    let page1 = run_paginated_projection_reconciliation(
        &env,
        &drifts,
        &PaginationParams { offset: 0, limit: 2 },
    ).unwrap();
    assert_eq!(page1.report.drifts_detected.len(), 2);
    assert_eq!(page1.next_offset, 2);
    assert!(page1.has_more);

    // Page 2: limit 2, offset 2
    let page2 = run_paginated_projection_reconciliation(
        &env,
        &drifts,
        &PaginationParams { offset: 2, limit: 2 },
    ).unwrap();
    assert_eq!(page2.report.drifts_detected.len(), 2);
    assert_eq!(page2.next_offset, 4);
    assert!(page2.has_more);

    // Page 3: limit 2, offset 4
    let page3 = run_paginated_projection_reconciliation(
        &env,
        &drifts,
        &PaginationParams { offset: 4, limit: 2 },
    ).unwrap();
    assert_eq!(page3.report.drifts_detected.len(), 1);
    assert_eq!(page3.next_offset, 5);
    assert!(!page3.has_more);

    // Invalid pagination: limit 0
    let err = run_paginated_projection_reconciliation(
        &env,
        &drifts,
        &PaginationParams { offset: 0, limit: 0 },
    );
    assert_eq!(err, Err(ReconciliationError::InvalidPagination));
}


