use crate::{auth::set_admin, resumable_repair::*};
use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, Address, Env, Vec,
};

#[contract]
struct RepairFixture;
#[contractimpl]
impl RepairFixture {
    pub fn step(env: Env, admin: Address, id: u64, cursor: u32) {
        advance_repair(&env, &admin, id, cursor, 1).unwrap();
    }
}
fn fixture() -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, RepairFixture);
    let admin = Address::generate(&env);
    let orphan = Address::generate(&env);
    let missing = Address::generate(&env);
    env.as_contract(&id, || {
        set_admin(&env, &admin);
        env.storage().instance().set(
            &symbol_short!("strat_lst"),
            &Vec::from_array(&env, [orphan.clone(), orphan.clone()]),
        );
        env.storage()
            .persistent()
            .set(&(symbol_short!("strat_ok"), missing.clone()), &true);
    });
    (env, id, admin, orphan, missing)
}
fn index(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&symbol_short!("strat_lst"))
        .unwrap()
}

#[test]
fn resumable_repair_removes_orphans_restores_missing_and_rolls_back() {
    let (env, id, admin, orphan, missing) = fixture();
    macro_rules! frame {
        ($e:expr) => {
            env.as_contract(&id, || $e)
        };
    }
    {
        let job = frame!(start_repair(
            &env,
            &admin,
            1,
            &Vec::from_array(&env, [missing.clone()])
        ))
        .unwrap();
        assert_eq!(job.candidates.len(), 2);
        assert_eq!(
            frame!(start_repair(&env, &admin, 2, &Vec::new(&env))),
            Err(RepairError::Busy)
        );
    }
    // Distinct invocations discard local state; progress comes exclusively from storage.
    let client = RepairFixtureClient::new(&env, &id);
    client.step(&admin, &1, &0);
    {
        assert!(frame!(index(&env)).is_empty());
        let job = frame!(get_repair_job(&env, 1)).unwrap();
        assert_eq!(job.cursor, 1);
        assert_eq!(
            frame!(advance_repair(&env, &admin, 1, 0, 1)),
            Ok(job.clone())
        );
        assert_eq!(
            frame!(advance_repair(&env, &admin, 1, 2, 1)),
            Err(RepairError::InvalidCursor)
        );
        assert_eq!(frame!(get_repair_job(&env, 1)).unwrap(), job);
    }
    client.step(&admin, &1, &1);
    {
        let completed = frame!(get_repair_job(&env, 1)).unwrap();
        assert_eq!(completed.status, RepairStatus::Completed);
        assert_eq!(
            frame!(index(&env)),
            Vec::from_array(&env, [missing.clone()])
        );
        assert_eq!(frame!(advance_repair(&env, &admin, 1, 1, 1)), Ok(completed));
        frame!(rollback_repair(&env, &admin, 1)).unwrap();
        assert_eq!(
            frame!(index(&env)),
            Vec::from_array(&env, [orphan.clone(), orphan])
        );
        assert_eq!(
            frame!(rollback_repair(&env, &admin, 1)).unwrap().status,
            RepairStatus::RolledBack
        );
        assert_eq!(
            frame!(advance_repair(&env, &admin, 1, 0, 1)),
            Err(RepairError::Terminal)
        );
    }
}

#[test]
fn concurrent_changes_stop_repair_and_rollback_without_overwriting() {
    let (env, id, admin, _, missing) = fixture();
    macro_rules! frame {
        ($e:expr) => {
            env.as_contract(&id, || $e)
        };
    }
    {
        frame!(start_repair(
            &env,
            &admin,
            1,
            &Vec::from_array(&env, [missing.clone()])
        ))
        .unwrap();
        frame!(advance_repair(&env, &admin, 1, 0, 1)).unwrap();
        let concurrent = Vec::from_array(&env, [missing.clone()]);
        frame!(env
            .storage()
            .instance()
            .set(&symbol_short!("strat_lst"), &concurrent));
        assert_eq!(
            frame!(advance_repair(&env, &admin, 1, 1, 1)),
            Err(RepairError::Conflict)
        );
        assert_eq!(
            frame!(rollback_repair(&env, &admin, 1)),
            Err(RepairError::Conflict)
        );
        assert_eq!(frame!(index(&env)), concurrent);
        assert_eq!(frame!(get_repair_job(&env, 1)).unwrap().cursor, 1);
        frame!(abandon_repair(&env, &admin, 1)).unwrap();
        assert_eq!(
            frame!(get_repair_job(&env, 1)).unwrap().status,
            RepairStatus::Abandoned
        );
        frame!(start_repair(&env, &admin, 2, &Vec::new(&env))).unwrap();
        assert_eq!(
            frame!(advance_repair(&env, &admin, 2, 0, 1))
                .unwrap()
                .status,
            RepairStatus::Completed
        );
    }
}

#[test]
fn repair_authorization_bounds_and_current_canonical_state() {
    let (env, id, admin, orphan, missing) = fixture();
    macro_rules! frame {
        ($e:expr) => {
            env.as_contract(&id, || $e)
        };
    }
    {
        let stranger = Address::generate(&env);
        assert_eq!(
            frame!(start_repair(&env, &stranger, 1, &Vec::new(&env))),
            Err(RepairError::Unauthorized)
        );
        assert_eq!(frame!(get_repair_job(&env, 1)), None);
        let mut too_many = Vec::new(&env);
        for _ in 0..=MAX_REPAIR_STRATEGIES {
            too_many.push_back(missing.clone());
        }
        assert_eq!(
            frame!(start_repair(&env, &admin, 1, &too_many)),
            Err(RepairError::InvalidPlan)
        );
        frame!(start_repair(
            &env,
            &admin,
            1,
            &Vec::from_array(&env, [missing.clone()])
        ))
        .unwrap();
        assert_eq!(
            frame!(advance_repair(&env, &stranger, 1, 0, 1)),
            Err(RepairError::Unauthorized)
        );
        assert_eq!(
            frame!(rollback_repair(&env, &stranger, 1)),
            Err(RepairError::Unauthorized)
        );
        assert_eq!(
            frame!(abandon_repair(&env, &stranger, 1)),
            Err(RepairError::Unauthorized)
        );
        assert_eq!(
            frame!(advance_repair(&env, &admin, 1, 0, 0)),
            Err(RepairError::InvalidPlan)
        );
        assert_eq!(
            frame!(advance_repair(&env, &admin, 1, 0, MAX_REPAIR_BATCH + 1)),
            Err(RepairError::InvalidPlan)
        );
        // Approval changed since planning: use current canonical truth, not the plan.
        frame!(env
            .storage()
            .persistent()
            .set(&(symbol_short!("strat_ok"), orphan.clone()), &true));
        frame!(env
            .storage()
            .persistent()
            .remove(&(symbol_short!("strat_ok"), missing.clone())));
        frame!(advance_repair(&env, &admin, 1, 0, 2)).unwrap();
        assert_eq!(frame!(index(&env)), Vec::from_array(&env, [orphan]));
        assert_eq!(
            frame!(start_repair(&env, &admin, 1, &Vec::new(&env))),
            Err(RepairError::Conflict)
        );
        assert_eq!(
            frame!(advance_repair(&env, &admin, 99, 0, 1)),
            Err(RepairError::NotFound)
        );
    }
}

#[test]
fn repair_requires_admin_signature() {
    let env = Env::default();
    let id = env.register_contract(None, RepairFixture);
    let admin = Address::generate(&env);
    env.as_contract(&id, || set_admin(&env, &admin));
    assert!(RepairFixtureClient::new(&env, &id)
        .try_step(&admin, &1, &0)
        .is_err());
}
