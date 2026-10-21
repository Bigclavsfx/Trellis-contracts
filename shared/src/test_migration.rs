use soroban_sdk::{symbol_short, Env, String, Vec};

use crate::migration::{
    dry_run_cross_contract, ContractMigrationPlan, MigrationError, MigrationPlan, MigrationStep,
    MigrationStepKind, RollbackStrategy,
};

fn step(id: u32, affected_records: u32, destructive: bool) -> MigrationStep {
    MigrationStep {
        id,
        name: symbol_short!("remap"),
        kind: MigrationStepKind::Storage,
        affected_records,
        destructive,
    }
}

fn plan(env: &Env, from_version: u32, to_version: u32, steps: &[MigrationStep]) -> MigrationPlan {
    let mut v = Vec::new(env);
    for s in steps {
        v.push_back(s.clone());
    }
    MigrationPlan {
        from_version,
        to_version,
        steps: v,
        rollback: RollbackStrategy::Revert,
        rollback_notes: String::from_str(env, "restore pre-migration snapshot"),
    }
}

fn entry(contract: soroban_sdk::Symbol, plan: MigrationPlan) -> ContractMigrationPlan {
    ContractMigrationPlan { contract, plan }
}

#[test]
fn valid_batch_aggregates_records_and_destructive_steps() {
    let env = Env::default();
    let mut plans = Vec::new(&env);
    plans.push_back(entry(
        symbol_short!("aid"),
        plan(&env, 1, 2, &[step(1, 10, false)]),
    ));
    plans.push_back(entry(
        symbol_short!("treasury"),
        plan(&env, 1, 2, &[step(1, 5, true)]),
    ));

    let report = dry_run_cross_contract(&env, &plans);

    assert!(report.batch_valid);
    assert_eq!(report.contract_count, 2);
    assert_eq!(report.affected_records, 15);
    assert_eq!(report.destructive_steps, 1);
    assert!(report.requires_approval);
    assert_eq!(report.first_invalid, None);
    assert_eq!(report.per_contract.len(), 2);
}

#[test]
fn invalid_plan_marks_batch_invalid_and_is_excluded_from_totals() {
    let env = Env::default();
    let mut plans = Vec::new(&env);
    plans.push_back(entry(
        symbol_short!("aid"),
        plan(&env, 1, 2, &[step(1, 10, false)]),
    ));
    // to_version must be greater than from_version.
    plans.push_back(entry(
        symbol_short!("referral"),
        plan(&env, 3, 3, &[step(1, 99, false)]),
    ));

    let report = dry_run_cross_contract(&env, &plans);

    assert!(!report.batch_valid);
    assert_eq!(report.first_invalid, Some(symbol_short!("referral")));
    assert_eq!(report.affected_records, 10);
    let referral = report.per_contract.get(1).unwrap();
    assert!(!referral.report.plan_valid);
    assert_eq!(
        referral.report.error_code,
        MigrationError::InvalidPlan as u32
    );
}

#[test]
fn same_contract_listed_twice_is_flagged_as_duplicate() {
    let env = Env::default();
    let mut plans = Vec::new(&env);
    plans.push_back(entry(
        symbol_short!("aid"),
        plan(&env, 1, 2, &[step(1, 10, false)]),
    ));
    plans.push_back(entry(
        symbol_short!("aid"),
        plan(&env, 1, 2, &[step(1, 10, false)]),
    ));

    let report = dry_run_cross_contract(&env, &plans);

    assert!(!report.batch_valid);
    assert_eq!(report.first_invalid, Some(symbol_short!("aid")));
    // Only the first aid plan counts toward the totals.
    assert_eq!(report.affected_records, 10);
    let duplicate = report.per_contract.get(1).unwrap();
    assert!(!duplicate.report.plan_valid);
    assert_eq!(
        duplicate.report.error_code,
        MigrationError::InvalidPlan as u32
    );
}

#[test]
fn empty_batch_is_never_valid() {
    let env = Env::default();
    let plans: Vec<ContractMigrationPlan> = Vec::new(&env);

    let report = dry_run_cross_contract(&env, &plans);

    assert!(!report.batch_valid);
    assert_eq!(report.contract_count, 0);
    assert_eq!(report.affected_records, 0);
    assert!(report.per_contract.is_empty());
}

#[test]
fn affected_record_totals_saturate_instead_of_overflowing() {
    let env = Env::default();
    let mut plans = Vec::new(&env);
    plans.push_back(entry(
        symbol_short!("aid"),
        plan(&env, 1, 2, &[step(1, u32::MAX, false)]),
    ));
    plans.push_back(entry(
        symbol_short!("treasury"),
        plan(&env, 1, 2, &[step(1, u32::MAX, false)]),
    ));

    let report = dry_run_cross_contract(&env, &plans);

    assert!(report.batch_valid);
    assert_eq!(report.affected_records, u32::MAX);
}
