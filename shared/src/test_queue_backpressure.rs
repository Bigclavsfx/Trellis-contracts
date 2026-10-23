extern crate std;
use crate::{auth::set_admin, errors::Error, jobs::*};
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env};
use std::cell::Cell;
#[contract]
struct Fixture;
#[contractimpl]
impl Fixture {
    pub fn capacity(env: Env, admin: Address, value: u32) -> Result<(), JobError> {
        configure_queue_capacity(&env, &admin, value)
    }
}

struct ScriptedHandler(Cell<u32>);
impl JobHandler for ScriptedHandler {
    fn handle(&self, _env: &Env, _job: &Job) -> Result<(), Error> {
        let remaining = self.0.get();
        if remaining == 0 {
            Ok(())
        } else {
            self.0.set(remaining - 1);
            Err(Error::Expired)
        }
    }
}
fn setup(env: &Env) -> (Address, Address) {
    env.mock_all_auths();
    let id = env.register_contract(None, Fixture);
    let admin = Address::generate(env);
    env.as_contract(&id, || set_admin(env, &admin));
    (id, admin)
}
#[test]
fn bounded_admission_preserves_retries_and_releases_slots() {
    let env = Env::default();
    let (id, admin) = setup(&env);
    let worker = Address::generate(&env);
    macro_rules! frame {
        ($e:expr) => {
            env.as_contract(&id, || $e)
        };
    }
    assert_eq!(
        frame!(configure_queue_capacity(&env, &Address::generate(&env), 2)),
        Err(JobError::Unauthorized)
    );
    assert_eq!(
        frame!(configure_queue_capacity(&env, &admin, 0)),
        Err(JobError::InvalidCapacity)
    );
    assert_eq!(
        frame!(configure_queue_capacity(
            &env,
            &admin,
            MAX_QUEUE_CAPACITY + 1
        )),
        Err(JobError::InvalidCapacity)
    );
    frame!(configure_queue_capacity(&env, &admin, 1)).unwrap();
    let first = dedupe_key_u64(&env, 261, 1);
    let second = dedupe_key_u64(&env, 261, 2);
    assert_eq!(
        frame!(enqueue_job(&env, JobPayload::None, first.clone(), 0, None)),
        Ok(EnqueueOutcome::Created(1))
    );
    assert_eq!(
        frame!(enqueue_job(&env, JobPayload::None, first.clone(), 0, None)),
        Ok(EnqueueOutcome::AlreadyPending(1))
    );
    assert_eq!(
        frame!(enqueue_job(&env, JobPayload::None, second.clone(), 0, None)),
        Err(JobError::QueueFull)
    );
    let handler = ScriptedHandler(Cell::new(1));
    assert!(matches!(
        frame!(run_due_job(&env, &worker, 0, &handler)),
        Ok(RunOutcome::Retried(_))
    ));
    assert_eq!(frame!(pending_job_ids(&env)).len(), 1);
    assert!(matches!(
        frame!(run_due_job(&env, &worker, 60, &handler)),
        Ok(RunOutcome::Succeeded(_))
    ));
    assert_eq!(
        frame!(enqueue_job(&env, JobPayload::None, first, 60, None)),
        Ok(EnqueueOutcome::AlreadyCompleted(1))
    );
    assert_eq!(
        frame!(enqueue_job(&env, JobPayload::None, second, 60, None)),
        Ok(EnqueueOutcome::Created(2))
    );
    assert_eq!(frame!(job_stats(&env)).counters.enqueued_total, 2);
}
#[test]
fn dead_letters_reserve_capacity_and_discarded_requeues_check_admission() {
    let env = Env::default();
    let (id, admin) = setup(&env);
    macro_rules! frame {
        ($e:expr) => {
            env.as_contract(&id, || $e)
        };
    }
    frame!(configure_queue_capacity(&env, &admin, 1)).unwrap();
    let worker = Address::generate(&env);
    frame!(enqueue_job(
        &env,
        JobPayload::None,
        dedupe_key_u64(&env, 261, 1),
        0,
        Some(RetryPolicy::no_retry())
    ))
    .unwrap();
    let fail = ScriptedHandler(Cell::new(10));
    assert!(matches!(
        frame!(run_due_job(&env, &worker, 0, &fail)),
        Ok(RunOutcome::DeadLettered(_))
    ));
    assert_eq!(
        frame!(enqueue_job(
            &env,
            JobPayload::None,
            dedupe_key_u64(&env, 261, 2),
            0,
            None
        )),
        Err(JobError::QueueFull)
    );
    assert_eq!(
        frame!(requeue_dead_letter(&env, &Address::generate(&env), 1, 0)),
        Err(JobError::Unauthorized)
    );
    frame!(requeue_dead_letter(&env, &admin, 1, 0)).unwrap();
    assert!(matches!(
        frame!(run_due_job(&env, &worker, 0, &fail)),
        Ok(RunOutcome::DeadLettered(_))
    ));
    frame!(discard_dead_letter(&env, &admin, 1)).unwrap();
    frame!(enqueue_job(
        &env,
        JobPayload::None,
        dedupe_key_u64(&env, 261, 2),
        0,
        None
    ))
    .unwrap();
    assert_eq!(
        frame!(requeue_dead_letter(&env, &admin, 1, 0)),
        Err(JobError::QueueFull)
    );
    assert_eq!(
        frame!(get_job(&env, 1)).unwrap().status,
        JobStatus::DeadLettered
    );
    frame!(pause_worker(&env, &admin)).unwrap();
    assert_eq!(
        frame!(requeue_dead_letter(&env, &admin, 1, 0)),
        Err(JobError::Disabled)
    );
}

#[test]
fn capacity_reduction_drains_without_dropping_accepted_work() {
    let env = Env::default();
    let (id, admin) = setup(&env);
    macro_rules! frame {
        ($e:expr) => {
            env.as_contract(&id, || $e)
        };
    }
    frame!(configure_queue_capacity(&env, &admin, 2)).unwrap();
    for value in [1, 2] {
        frame!(enqueue_job(
            &env,
            JobPayload::None,
            dedupe_key_u64(&env, 261, value),
            0,
            None
        ))
        .unwrap();
    }
    frame!(configure_queue_capacity(&env, &admin, 1)).unwrap();
    let worker = Address::generate(&env);
    let handler = ScriptedHandler(Cell::new(0));
    assert!(matches!(
        frame!(run_due_job(&env, &worker, 0, &handler)),
        Ok(RunOutcome::Succeeded(_))
    ));
    assert_eq!(
        frame!(enqueue_job(
            &env,
            JobPayload::None,
            dedupe_key_u64(&env, 261, 3),
            0,
            None
        )),
        Err(JobError::QueueFull)
    );
    assert!(matches!(
        frame!(run_due_job(&env, &worker, 0, &handler)),
        Ok(RunOutcome::Succeeded(_))
    ));
    assert_eq!(
        frame!(enqueue_job(
            &env,
            JobPayload::None,
            dedupe_key_u64(&env, 261, 3),
            0,
            None
        )),
        Ok(EnqueueOutcome::Created(3))
    );
}

#[test]
fn capacity_change_requires_admin_signature() {
    let env = Env::default();
    let id = env.register_contract(None, Fixture);
    let admin = Address::generate(&env);
    env.as_contract(&id, || set_admin(&env, &admin));
    assert!(FixtureClient::new(&env, &id)
        .try_capacity(&admin, &1)
        .is_err());
    assert_eq!(
        env.as_contract(&id, || queue_capacity(&env)),
        DEFAULT_QUEUE_CAPACITY
    );
}
