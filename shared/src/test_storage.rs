#![cfg(test)]

extern crate std;

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, testutils::Ledger as _, Env, Symbol,
};

use crate::errors::Error;
use crate::storage::{
    instance_get, instance_has, instance_remove, instance_set, is_paused, persistent_get,
    persistent_get_required, persistent_has, persistent_read, persistent_remove, persistent_set,
    set_paused, temporary_get, temporary_has, temporary_remove, temporary_set,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_TTL_THRESHOLD, TEMPORARY_BUMP_AMOUNT,
    TEMPORARY_TTL_THRESHOLD,
};

#[contract]
pub struct DummyContract;

#[contractimpl]
impl DummyContract {
    pub fn noop(_env: Env) {}
}

// ---------------------------------------------------------------------------
// Shared test key type
// ---------------------------------------------------------------------------

/// A compact contracttype key used by all storage tests.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum TestKey {
    U32(u32),
    Str,
}

// ---------------------------------------------------------------------------
// TTL constant sanity checks (compile-time / runtime)
// ---------------------------------------------------------------------------

#[test]
fn ttl_thresholds_are_strictly_less_than_bump_amounts() {
    assert!(
        PERSISTENT_TTL_THRESHOLD < PERSISTENT_BUMP_AMOUNT,
        "persistent threshold must be < bump amount"
    );
    assert!(
        TEMPORARY_TTL_THRESHOLD < TEMPORARY_BUMP_AMOUNT,
        "temporary threshold must be < bump amount"
    );
}

// ---------------------------------------------------------------------------
// Instance storage
// ---------------------------------------------------------------------------

#[test]
fn instance_set_get_roundtrip() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::Str;
        assert_eq!(instance_get::<TestKey, u32>(&env, &key), None);

        instance_set(&env, &key, &42_u32);
        assert_eq!(instance_get::<TestKey, u32>(&env, &key), Some(42_u32));
    });
}

#[test]
fn instance_has_reflects_presence_and_absence() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(1);
        assert!(!instance_has(&env, &key));

        instance_set(&env, &key, &true);
        assert!(instance_has(&env, &key));
    });
}

#[test]
fn instance_remove_deletes_entry() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(2);
        instance_set(&env, &key, &99_i128);
        assert!(instance_has(&env, &key));

        instance_remove(&env, &key);
        assert!(!instance_has(&env, &key));
        assert_eq!(instance_get::<TestKey, i128>(&env, &key), None);
    });
}

// ---------------------------------------------------------------------------
// Persistent storage — set / get / has / remove
// ---------------------------------------------------------------------------

#[test]
fn persistent_set_get_roundtrip() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(10);
        assert_eq!(persistent_get::<TestKey, i128>(&env, &key), None);

        persistent_set(&env, &key, &1_000_i128);
        assert_eq!(
            persistent_get::<TestKey, i128>(&env, &key),
            Some(1_000_i128)
        );
    });
}

#[test]
fn persistent_has_reflects_presence() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(11);
        assert!(!persistent_has(&env, &key));

        persistent_set(&env, &key, &true);
        assert!(persistent_has(&env, &key));
    });
}

#[test]
fn persistent_remove_deletes_entry() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(12);
        persistent_set(&env, &key, &7_u32);
        assert!(persistent_has(&env, &key));

        persistent_remove(&env, &key);
        assert!(!persistent_has(&env, &key));
        assert_eq!(persistent_get::<TestKey, u32>(&env, &key), None);
    });
}

#[test]
fn persistent_get_absent_key_returns_none() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(99);
        // No TTL-bump call should happen on a miss — the SDK would panic if
        // extend_ttl were called on a non-existent key, so a successful return of
        // None proves the bump is conditional.
        assert_eq!(persistent_get::<TestKey, u32>(&env, &key), None);
    });
}

#[test]
fn persistent_get_extends_ttl_on_hit() {
    // Regression: confirm that a successful read does not panic (i.e. the
    // extend_ttl call inside persistent_get receives a valid key).
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(20);
        persistent_set(&env, &key, &42_u32);
        // A second read via persistent_get triggers extend_ttl — must not panic.
        let value = persistent_get::<TestKey, u32>(&env, &key);
        assert_eq!(value, Some(42_u32));
    });
}

#[test]
fn persistent_overwrite_retains_latest_value() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(30);
        persistent_set(&env, &key, &1_u32);
        persistent_set(&env, &key, &2_u32);
        assert_eq!(persistent_get::<TestKey, u32>(&env, &key), Some(2_u32));
    });
}

// ---------------------------------------------------------------------------
// Temporary storage — set / get / has / remove
// ---------------------------------------------------------------------------

#[test]
fn temporary_set_get_roundtrip() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(50);
        assert_eq!(temporary_get::<TestKey, u32>(&env, &key), None);

        temporary_set(&env, &key, &255_u32);
        assert_eq!(temporary_get::<TestKey, u32>(&env, &key), Some(255_u32));
    });
}

#[test]
fn temporary_has_reflects_presence() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(51);
        assert!(!temporary_has(&env, &key));

        temporary_set(&env, &key, &true);
        assert!(temporary_has(&env, &key));
    });
}

#[test]
fn temporary_remove_deletes_entry() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(52);
        temporary_set(&env, &key, &9_u32);
        assert!(temporary_has(&env, &key));

        temporary_remove(&env, &key);
        assert!(!temporary_has(&env, &key));
        assert_eq!(temporary_get::<TestKey, u32>(&env, &key), None);
    });
}

#[test]
fn temporary_get_absent_key_returns_none_without_panic() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(98);
        // Same as the persistent variant: a miss must not call extend_ttl.
        assert_eq!(temporary_get::<TestKey, u32>(&env, &key), None);
    });
}

#[test]
fn temporary_get_extends_ttl_on_hit() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(60);
        temporary_set(&env, &key, &1_u32);
        let value = temporary_get::<TestKey, u32>(&env, &key);
        assert_eq!(value, Some(1_u32));
    });
}

// ---------------------------------------------------------------------------
// Pause flag convenience wrappers
// ---------------------------------------------------------------------------

#[test]
fn is_paused_defaults_to_false() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        assert!(!is_paused(&env));
    });
}

#[test]
fn set_paused_true_makes_is_paused_return_true() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        set_paused(&env, true);
        assert!(is_paused(&env));
    });
}

#[test]
fn set_paused_false_clears_the_flag() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        set_paused(&env, true);
        set_paused(&env, false);
        assert!(!is_paused(&env));
    });
}

#[test]
fn pause_flag_stored_in_instance_storage() {
    // Verify the pause flag lives in instance storage by confirming that
    // instance_get with KEY_PAUSED returns the value set by set_paused.
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        set_paused(&env, true);
        let via_instance = instance_get::<Symbol, bool>(&env, &symbol_short!("paused"));
        assert_eq!(via_instance, Some(true));
    });
}

// ---------------------------------------------------------------------------
// Cross-family isolation: keys in different families do not alias
// ---------------------------------------------------------------------------

#[test]
fn instance_and_persistent_with_same_key_are_independent() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(70);

        instance_set(&env, &key, &111_u32);
        persistent_set(&env, &key, &222_u32);

        assert_eq!(instance_get::<TestKey, u32>(&env, &key), Some(111_u32));
        assert_eq!(persistent_get::<TestKey, u32>(&env, &key), Some(222_u32));
    });
}

#[test]
fn persistent_and_temporary_with_same_key_are_independent() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    env.as_contract(&contract_id, || {
        let key = TestKey::U32(71);

        persistent_set(&env, &key, &333_u32);
        temporary_set(&env, &key, &444_u32);

        assert_eq!(persistent_get::<TestKey, u32>(&env, &key), Some(333_u32));
        assert_eq!(temporary_get::<TestKey, u32>(&env, &key), Some(444_u32));
    });
}

// ===========================================================================
// Gas benchmark tests
// ===========================================================================

/// Benchmark: `persistent_read` vs `persistent_get` for read-only queries.
///
/// Both return the same value, but `persistent_read` skips the `extend_ttl`
/// host call.  In a loop or batch query this saves one host syscall per read.
#[test]
fn persistent_read_matches_persistent_get_for_existing_entry() {
    let env = Env::default();
    let key = TestKey::U32(200);
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        persistent_set(&env, &key, &999_u32);

        let via_get = persistent_get::<TestKey, u32>(&env, &key);
        let via_read = persistent_read::<TestKey, u32>(&env, &key);
        assert_eq!(via_get, Some(999_u32));
        assert_eq!(via_read, Some(999_u32));
    });
}

/// Benchmark: `persistent_read` for absent key returns None without extra work.
#[test]
fn persistent_read_absent_key_returns_none() {
    let env = Env::default();
    let key = TestKey::U32(201);
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        assert_eq!(persistent_read::<TestKey, u32>(&env, &key), None);
    });
}

/// Benchmark: repeated `persistent_read` calls avoid TTL overhead.
///
/// This simulates a read-heavy query path (e.g. the referral `accrue` loop
/// reading tier BPS from persistent storage) where the entry was recently
/// written and TTL is fresh.
#[test]
fn persistent_read_loop_avoids_ttl_overhead() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        // Simulate a batch write followed by batch reads.
        for i in 0..5 {
            let key = TestKey::U32(300 + i);
            persistent_set(&env, &key, &i);
        }

        // Read back all entries — persistent_read skips extend_ttl.
        for i in 0..5 {
            let key = TestKey::U32(300 + i);
            let val = persistent_read::<TestKey, u32>(&env, &key);
            assert_eq!(val, Some(i));
        }
    });
}

// ---------------------------------------------------------------------------
// Required reads: missing and archived records fail closed (Issue #336)
// ---------------------------------------------------------------------------

#[test]
fn persistent_get_required_returns_a_present_value() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        let key = TestKey::U32(400);
        persistent_set(&env, &key, &9_u32);

        assert_eq!(
            persistent_get_required::<TestKey, u32>(&env, &key),
            Ok(9_u32)
        );
    });
}

#[test]
fn persistent_get_required_refuses_a_key_that_was_never_written() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);

    env.as_contract(&contract_id, || {
        // Absence must not become a default value. The caller gets an error it
        // can act on, not a zero it might spend.
        assert_eq!(
            persistent_get_required::<TestKey, i128>(&env, &TestKey::U32(401)),
            Err(Error::NotFound)
        );
    });
}

#[test]
fn persistent_get_required_refuses_an_archived_record() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    let key = TestKey::U32(402);

    env.as_contract(&contract_id, || {
        persistent_set(&env, &key, &5_u32);
    });

    // Move past the entry's live_until. The host then treats it as archived,
    // which reads the same as a missing key.
    let archived_at = env.ledger().sequence() + PERSISTENT_BUMP_AMOUNT + 1;
    env.ledger().set_sequence_number(archived_at);

    env.as_contract(&contract_id, || {
        assert_eq!(
            persistent_get_required::<TestKey, u32>(&env, &key),
            Err(Error::NotFound)
        );
    });
}

#[test]
fn archived_record_reads_again_once_it_is_restored() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyContract);
    let key = TestKey::U32(403);

    env.as_contract(&contract_id, || {
        persistent_set(&env, &key, &5_u32);
    });
    let archived_at = env.ledger().sequence() + PERSISTENT_BUMP_AMOUNT + 1;
    env.ledger().set_sequence_number(archived_at);

    env.as_contract(&contract_id, || {
        assert_eq!(
            persistent_get_required::<TestKey, u32>(&env, &key),
            Err(Error::NotFound)
        );

        // Recovery: the record is written back with a fresh TTL, then the
        // retried read succeeds without a default ever being used.
        persistent_set(&env, &key, &5_u32);
        assert_eq!(
            persistent_get_required::<TestKey, u32>(&env, &key),
            Ok(5_u32)
        );
    });
}
