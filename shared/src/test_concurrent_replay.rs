//! Replay explicit ledger schedules rather than relying on nondeterministic threads.
extern crate std;
use crate::{auth::set_admin, errors::Error, jobs::*, ledger_sequence::LedgerSequenceHarness};
use soroban_sdk::{contract, symbol_short, testutils::Address as _, Address, Env};
use std::vec::Vec as StdVec;

#[contract]
struct ReplayFixture;

struct WriteOnce;
impl JobHandler for WriteOnce {
    fn handle(&self, env: &Env, job: &Job) -> Result<(), Error> {
        // Fail before touching application state; a retry must perform exactly one write.
        if job.attempts == 1 {
            return Err(Error::Expired);
        }
        let key = symbol_short!("writes");
        let writes: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(writes + 1));
        Ok(())
    }
}

fn replay(order: [u64; 2]) -> (StdVec<(u32, u32, u64, u64)>, u32) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, ReplayFixture);
    let admin = Address::generate(&env);
    let worker = Address::generate(&env);
    let mut clock = LedgerSequenceHarness::from_state(&env, 10);
    env.as_contract(&id, || {
        set_admin(&env, &admin);
        configure_queue_capacity(&env, &admin, 2).unwrap();
        let policy = RetryPolicy {
            max_attempts: 3,
            base_backoff_ledgers: 1,
            max_backoff_ledgers: 4,
        };
        for value in order {
            let key = dedupe_key_u64(&env, 260, value);
            assert!(matches!(
                enqueue_job(&env, JobPayload::None, key.clone(), 10, Some(policy)),
                Ok(EnqueueOutcome::Created(_))
            ));
            assert!(matches!(
                enqueue_job(&env, JobPayload::None, key, 999, Some(policy)),
                Ok(EnqueueOutcome::AlreadyPending(_))
            ));
        }
        let stranger = Address::generate(&env);
        assert_eq!(
            configure_queue_capacity(&env, &stranger, 256),
            Err(JobError::Unauthorized)
        );
    });
    let mut trace = StdVec::new();
    for ledger in [10, 10, 10, 11, 11, 12] {
        clock.at(ledger).unwrap();
        env.as_contract(&id, || {
            let outcome = run_due_job(&env, &worker, ledger, &WriteOnce).unwrap();
            if ledger == 10 {
                assert!(!matches!(outcome, RunOutcome::Succeeded(_)));
            }
            let stats = job_stats(&env);
            trace.push((
                ledger,
                stats.pending,
                stats.counters.failed_attempts_total,
                stats.counters.succeeded_total,
            ));
        });
    }
    env.as_contract(&id, || {
        for value in order {
            let key = dedupe_key_u64(&env, 260, value);
            let receipt = get_receipt(&env, &key).unwrap();
            assert_eq!(receipt.attempts, 2);
            assert_eq!(receipt.completed_ledger, 11);
            assert_eq!(
                enqueue_job(&env, JobPayload::None, key, 12, None),
                Ok(EnqueueOutcome::AlreadyCompleted(receipt.job_id))
            );
            assert!(matches!(
                reprocess_job(&env, &worker, receipt.job_id, 12, &WriteOnce),
                Ok(RunOutcome::AlreadyCompleted(_))
            ));
        }
        let writes: u32 = env
            .storage()
            .persistent()
            .get(&symbol_short!("writes"))
            .unwrap();
        assert_eq!(writes, 2);
        (trace, writes)
    })
}

#[test]
fn concurrent_producers_and_worker_retries_replay_deterministically() {
    let first = replay([1, 2]);
    assert_eq!(first, replay([1, 2]));
    assert_eq!(first, replay([2, 1]));
    assert_eq!(
        first.0,
        std::vec![
            (10, 2, 1, 0),
            (10, 2, 2, 0),
            (10, 2, 2, 0),
            (11, 1, 2, 1),
            (11, 0, 2, 2),
            (12, 0, 2, 2)
        ]
    );
}
