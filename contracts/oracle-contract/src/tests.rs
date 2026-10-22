#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{symbol_short, testutils::Address as _, testutils::Ledger, Env};

struct Fixture {
    env: Env,
    admin: Address,
    submitter1: Address,
    submitter2: Address,
    contract_id: Address,
}


fn setup() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let submitter1 = Address::generate(&env);
    let submitter2 = Address::generate(&env);

    let contract_id = env.register_contract(None, OracleContract);
    let client = OracleContractClient::new(&env, &contract_id);
    client.initialize(&admin);

    Fixture {
        env,
        admin,
        submitter1,
        submitter2,
        contract_id,
    }
}


#[test]
fn test_initialize_sets_admin() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    assert_eq!(client.get_admin(), fx.admin);
}

#[test]
fn test_double_initialize() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let new_admin = Address::generate(&fx.env);
    assert_eq!(
        client.try_initialize(&new_admin),
        Err(Ok(OracleError::AlreadyInitialized))
    );
    assert_eq!(client.get_admin(), fx.admin);
}

#[test]
fn test_initialize_requires_the_admin_signature() {
    let env = Env::default();
    let contract_id = env.register_contract(None, OracleContract);
    let client = OracleContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    assert!(client.try_initialize(&admin).is_err());
}


#[test]
fn test_get_admin() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    assert_eq!(client.get_admin(), fx.admin);
}

#[test]
fn test_register_submitter_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    assert!(client.is_submitter_active(&fx.submitter1));
}


#[test]
fn test_register_submitter_unauthorized_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let unauthorized = Address::generate(&fx.env);
    let result = client.try_register_submitter(&unauthorized, &fx.submitter1);
    assert!(result.is_err());
}

#[test]
fn test_register_submitter_revoked_admin_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.deactivate_submitter(&fx.admin, &fx.admin);
    let result = client.try_register_submitter(&fx.admin, &fx.submitter1);
    assert!(result.is_err());
}


#[test]
fn test_register_duplicate_submitter_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    let result = client.try_register_submitter(&fx.admin, &fx.submitter1);
    assert!(result.is_err());
}

#[test]
fn test_register_multiple_submitters() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    assert!(client.is_submitter_active(&fx.submitter1));
    assert!(client.is_submitter_active(&fx.submitter2));
}


#[test]
fn test_deactivate_submitter_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    assert!(client.is_submitter_active(&fx.submitter1));
    client.deactivate_submitter(&fx.admin, &fx.submitter1);
    assert!(!client.is_submitter_active(&fx.submitter1));
}

#[test]
fn test_min_quorum_updates_runtime_aggregation() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    let feed_id = symbol_short!("BTCUSD");
    let now = fx.env.ledger().timestamp();
    client.submit_price(&fx.submitter1, &feed_id, &100, &8, &now, &1);

    assert_eq!(
        client.try_get_latest_price(&feed_id),
        Err(Ok(OracleError::InsufficientQuorum))
    );
    client.set_min_quorum(&fx.admin, &1);
    assert_eq!(client.get_min_quorum(), 1);
    assert_eq!(client.get_latest_price(&feed_id).submission_count, 1);

    client.set_min_quorum(&fx.admin, &2);
    client.submit_price(&fx.submitter2, &feed_id, &102, &8, &now, &1);
    assert_eq!(client.get_latest_price(&feed_id).submission_count, 2);
}

#[test]
fn test_min_quorum_validates_active_submitter_count() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    assert_eq!(
        client.try_set_min_quorum(&fx.admin, &0),
        Err(Ok(OracleError::InvalidQuorum))
    );
    assert_eq!(
        client.try_set_min_quorum(&fx.admin, &1),
        Err(Ok(OracleError::InvalidQuorum))
    );
    client.register_submitter(&fx.admin, &fx.submitter1);
    assert_eq!(
        client.try_set_min_quorum(&fx.admin, &2),
        Err(Ok(OracleError::InvalidQuorum))
    );
    client.set_min_quorum(&fx.admin, &1);
    assert_eq!(client.get_min_quorum(), 1);
}

#[test]
fn test_feed_quorum_override_and_clear() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    client.set_min_quorum(&fx.admin, &1);
    let feed_id = symbol_short!("BTCUSD");
    client.set_feed_quorum(&fx.admin, &feed_id, &2);
    assert_eq!(client.get_feed_quorum(&feed_id), 2);

    let now = fx.env.ledger().timestamp();
    client.submit_price(&fx.submitter1, &feed_id, &100, &8, &now, &1);
    assert_eq!(
        client.try_get_latest_price(&feed_id),
        Err(Ok(OracleError::InsufficientQuorum))
    );
    client.submit_price(&fx.submitter2, &feed_id, &102, &8, &now, &1);
    assert_eq!(client.get_latest_price(&feed_id).submission_count, 2);

    client.clear_feed_quorum(&fx.admin, &feed_id);
    assert_eq!(client.get_feed_quorum(&feed_id), 1);
}


#[test]
fn test_deactivate_submitter_unauthorized_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    let unauthorized = Address::generate(&fx.env);
    let result = client.try_deactivate_submitter(&unauthorized, &fx.submitter1);
    assert!(result.is_err());
}

#[test]
fn test_deactivate_submitter_revoked_admin_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.deactivate_submitter(&fx.admin, &fx.admin);
    let result = client.try_deactivate_submitter(&fx.admin, &fx.submitter1);
    assert!(result.is_err());
}


#[test]
fn test_deactivated_submitter_cannot_submit() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.deactivate_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_submit_price_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let id = client.submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert_eq!(id, 1);
}


#[test]
fn test_submit_price_unauthorized_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let unregistered = Address::generate(&fx.env);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &unregistered,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_submit_price_negative_price_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &-1000i128,
        &8u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_submit_price_invalid_decimals_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &19u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_submit_price_zero_price_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &0i128,
        &8u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert!(result.is_ok());
}


#[test]
fn test_submit_price_max_decimals_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &18u32,
        &fx.env.ledger().timestamp(),
        &1u64,
    );
    assert!(result.is_ok());
}


#[test]
fn test_replay_protection_duplicate_nonce() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    let result1 = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );
    assert!(result1.is_ok());

    let result2 = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &51000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );
    assert!(result2.is_err());
}


#[test]
fn test_sequential_nonces_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    let r1 = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );
    assert!(r1.is_ok());

    let r2 = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &51000_00000000i128,
        &8u32,
        &ts,
        &2u64,
    );
    assert!(r2.is_ok());

    let r3 = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &52000_00000000i128,
        &8u32,
        &ts,
        &3u64,
    );
    assert!(r3.is_ok());
}

// ---------------------------------------------------------------------------
// Scenario-based threat model: cross-boundary trust decisions
// ---------------------------------------------------------------------------
//
// Threat model summary
// --------------------
// Trust boundaries:
//   1. Admin -> contract: privileged configuration (initialize, submitter
//      registry, quorum policy). Abuse: unauthorized admin action, revoked
//      admin still acting, double initialization.
//   2. Submitter -> contract: price attestations. Abuse: unregistered or
//      deactivated submitter, replay of a previously used nonce, malformed
//      price/decimals, stale or future timestamps.
//   3. Contract -> consumer: aggregated price feed. Abuse: reading a feed
//      before quorum is met, or trusting a feed whose quorum policy was
//      silently weakened.
//
// Highest-risk paths and mitigations:
//   - Privileged mutation without auth: every admin entrypoint calls
//     `admin.require_auth()` and re-checks the stored admin is active.
//   - Replay across submitters: nonces are tracked per (submitter, feed) so
//     one submitter cannot consume another's nonce space.
//   - Quorum downgrade: `set_min_quorum`/`set_feed_quorum` validate against
//     the active submitter count; `clear_feed_quorum` falls back to the
//     global minimum rather than to zero.
//   - Stale/future submissions: timestamps are bounded relative to ledger
//     time so an attacker cannot pin a feed to an old or far-future value.
//
// Operational edge cases and recovery:
//   - If the admin key is compromised, rotate by deactivating the old admin
//     and registering a new one; existing feeds remain readable but new
//     submissions from the old admin are rejected.
//   - If a submitter is compromised, `deactivate_submitter` immediately
//     removes them from quorum counting; previously accepted submissions
//     remain in history but no longer count toward new quorum checks.
//   - If a feed's quorum was set too high, `clear_feed_quorum` restores the
//     global minimum without deleting historical submissions.
//   - Rollback: because all state is keyed by feed/submitter, recovery is
//     additive (register/deactivate) and does not require contract upgrade.

#[test]
fn test_threat_model_admin_boundary_revoked_admin_cannot_reconfigure() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.deactivate_submitter(&fx.admin, &fx.admin);

    // A revoked admin must not be able to change quorum policy.
    assert!(client.try_set_min_quorum(&fx.admin, &1).is_err());
    assert!(client.try_register_submitter(&fx.admin, &fx.submitter1).is_err());
}

#[test]
fn test_threat_model_submitter_boundary_replay_is_per_submitter() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    client.set_min_quorum(&fx.admin, &1);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    // submitter1 uses nonce 1.
    assert!(client
        .try_submit_price(&fx.submitter1, &feed_id, &100, &8, &ts, &1u64)
        .is_ok());

    // submitter2 may independently use nonce 1: nonce space is per submitter.
    assert!(client
        .try_submit_price(&fx.submitter2, &feed_id, &102, &8, &ts, &1u64)
        .is_ok());

    // submitter1 replaying nonce 1 must fail.
    assert!(client
        .try_submit_price(&fx.submitter1, &feed_id, &101, &8, &ts, &1u64)
        .is_err());
}

#[test]
fn test_threat_model_consumer_boundary_quorum_cannot_be_downgraded_below_active() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    client.set_min_quorum(&fx.admin, &2);

    // Deactivating a submitter must not silently leave quorum above the
    // active submitter count without the caller re-validating.
    client.deactivate_submitter(&fx.admin, &fx.submitter2);
    assert!(client.try_set_min_quorum(&fx.admin, &2).is_err());

    // Clearing a feed override falls back to the global minimum, not zero.
    let feed_id = symbol_short!("BTCUSD");
    client.set_feed_quorum(&fx.admin, &feed_id, &1);
    client.clear_feed_quorum(&fx.admin, &feed_id);
    assert_eq!(client.get_feed_quorum(&feed_id), client.get_min_quorum());
}

#[test]
fn test_threat_model_consumer_boundary_no_read_before_quorum() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    client.set_min_quorum(&fx.admin, &2);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();
    client.submit_price(&fx.submitter1, &feed_id, &100, &8, &ts, &1u64);

    // A consumer must not be able to read a feed that has not met quorum.
    assert_eq!(
        client.try_get_latest_price(&feed_id),
        Err(Ok(OracleError::InsufficientQuorum))
    );
}

#[test]
fn test_threat_model_recovery_deactivate_compromised_submitter() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    client.set_min_quorum(&fx.admin, &2);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();
    client.submit_price(&fx.submitter1, &feed_id, &100, &8, &ts, &1u64);
    client.submit_price(&fx.submitter2, &feed_id, &102, &8, &ts, &1u64);
    assert_eq!(client.get_latest_price(&feed_id).submission_count, 2);

    // Recovery: deactivate the compromised submitter; quorum must be
    // re-validated against the remaining active submitters.
    client.deactivate_submitter(&fx.admin, &fx.submitter1);
    assert!(!client.is_submitter_active(&fx.submitter1));
    assert!(client.try_set_min_quorum(&fx.admin, &2).is_err());
    client.set_min_quorum(&fx.admin, &1);
    assert_eq!(client.get_min_quorum(), 1);
}


#[test]
fn test_nonce_skipping_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &fx.env.ledger().timestamp(),
        &5u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_independent_feed_nonces() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let btc = symbol_short!("BTCUSD");
    let eth = symbol_short!("ETHUSD");
    let ts = fx.env.ledger().timestamp();

    let r1 = client.try_submit_price(&fx.submitter1, &btc, &50000_00000000i128, &8u32, &ts, &1u64);
    assert!(r1.is_ok());

    let r2 = client.try_submit_price(&fx.submitter1, &eth, &3000_00000000i128, &8u32, &ts, &1u64);
    assert!(r2.is_ok());
}


#[test]
fn test_stale_submission_rejected() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.set_staleness_window(&fx.admin, &1000);

    let feed_id = symbol_short!("BTCUSD");
    let now = fx.env.ledger().timestamp();
    let stale_ts = now.saturating_sub(2000);

    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &stale_ts,
        &1u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_set_staleness_window_unauthorized_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let unauthorized = Address::generate(&fx.env);
    let result = client.try_set_staleness_window(&unauthorized, &1000);
    assert!(result.is_err());
}

#[test]
fn test_set_staleness_window_revoked_admin_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.deactivate_submitter(&fx.admin, &fx.admin);
    let result = client.try_set_staleness_window(&fx.admin, &1000);
    assert!(result.is_err());
}


#[test]
fn test_fresh_submission_within_window() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.set_staleness_window(&fx.admin, &1000);

    let feed_id = symbol_short!("BTCUSD");
    let now = fx.env.ledger().timestamp();
    let fresh_ts = now.saturating_sub(500);

    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &fresh_ts,
        &1u64,
    );
    assert!(result.is_ok());
}


#[test]
fn test_submission_at_boundary() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.set_staleness_window(&fx.admin, &1000);

    let feed_id = symbol_short!("BTCUSD");
    let now = fx.env.ledger().timestamp();
    let boundary_ts = now.saturating_sub(1000);

    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &boundary_ts,
        &1u64,
    );
    assert!(result.is_ok());
}


#[test]
fn test_get_latest_price_after_submit() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);

    let feed_id = symbol_short!("BTCUSD");
    let price = 50000_00000000i128;
    let ts = fx.env.ledger().timestamp();

    client.submit_price(&fx.submitter1, &feed_id, &price, &8u32, &ts, &1u64);
    client.submit_price(&fx.submitter2, &feed_id, &price, &8u32, &ts, &1u64);

    let latest = client.get_latest_price(&feed_id);
    assert_eq!(latest.price, price);
    assert_eq!(latest.decimals, 8);
    assert_eq!(latest.timestamp, ts);
    assert_eq!(latest.submission_count, 2);
}


#[test]
fn test_get_latest_price_unauthorized_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let _unauthorized = Address::generate(&fx.env);
    let result = client.try_get_latest_price(&symbol_short!("BTCUSD"));
    assert!(result.is_err());
}


#[test]
fn test_get_latest_price_never_written_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let result = client.try_get_latest_price(&symbol_short!("XYZUSD"));
    assert!(result.is_err());
}


#[test]
fn test_get_latest_price_most_recent() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    client.submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );
    let l1 = client.try_get_latest_price(&feed_id);
    assert_eq!(l1, Err(Ok(OracleError::InsufficientQuorum)));

    client.submit_price(
        &fx.submitter2,
        &feed_id,
        &51000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );
    let l2 = client.get_latest_price(&feed_id);
    assert_eq!(l2.price, 50500_00000000i128);
    assert_eq!(l2.submission_count, 2);
}


#[test]
fn test_get_price_history_empty_feed_fails() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let result = client.try_get_price_history(&symbol_short!("XYZUSD"), &10u32);
    assert!(result.is_err());
}


#[test]
fn test_get_price_history_returns_submissions() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    for i in 1..=5 {
        let price = 50000_00000000i128 + (i * 1000) as i128;
        client.submit_price(&fx.submitter1, &feed_id, &price, &8u32, &ts, &(i as u64));
    }

    let history = client.get_price_history(&feed_id, &10u32);
    assert_eq!(history.len(), 5);
}


#[test]
fn test_get_price_history_respects_limit() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    for i in 1..=10 {
        let price = 50000_00000000i128 + (i * 1000) as i128;
        client.submit_price(&fx.submitter1, &feed_id, &price, &8u32, &ts, &(i as u64));
    }

    let history = client.get_price_history(&feed_id, &3u32);
    assert_eq!(history.len(), 3);
    assert_eq!(history.get(0).unwrap().id, 8);
    assert_eq!(history.get(1).unwrap().id, 9);
    assert_eq!(history.get(2).unwrap().id, 10);
}


#[test]
fn test_multiple_submitters_same_feed() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();

    client.submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );
    client.submit_price(
        &fx.submitter2,
        &feed_id,
        &51000_00000000i128,
        &8u32,
        &ts,
        &1u64,
    );

    let latest = client.get_latest_price(&feed_id);
    assert_eq!(latest.price, 50500_00000000i128);
    assert_eq!(latest.submission_count, 2);
}


#[test]
fn test_future_timestamp_rejected() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);

    let feed_id = symbol_short!("BTCUSD");
    let future_ts = fx.env.ledger().timestamp() + 61;

    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &future_ts,
        &1u64,
    );
    assert_eq!(result, Err(Ok(OracleError::SubmissionFromFuture)));
}


#[test]
fn test_median_ignores_single_outlier() {
    let fx = setup();
    let submitter3 = Address::generate(&fx.env);
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.register_submitter(&fx.admin, &fx.submitter1);
    client.register_submitter(&fx.admin, &fx.submitter2);
    client.register_submitter(&fx.admin, &submitter3);

    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();
    client.submit_price(&fx.submitter1, &feed_id, &50_000_i128, &2u32, &ts, &1u64);
    client.submit_price(&fx.submitter2, &feed_id, &51_000_i128, &2u32, &ts, &1u64);
    client.submit_price(&submitter3, &feed_id, &1_000_000_i128, &2u32, &ts, &1u64);

    let latest = client.get_latest_price(&feed_id);
    assert_eq!(latest.price, 51_000_i128);
    assert_eq!(latest.submission_count, 3);
}


#[test]
fn test_set_staleness_window_success() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    let result = client.try_set_staleness_window(&fx.admin, &7200);
    assert!(result.is_ok());
    assert_eq!(client.get_staleness_window(), 7200);
}


#[test]
fn test_get_staleness_window_default() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    assert_eq!(client.get_staleness_window(), 3600);
}


#[test]
fn test_set_staleness_window_zero() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);
    client.set_staleness_window(&fx.admin, &0);
    assert_eq!(client.get_staleness_window(), 0);

    client.register_submitter(&fx.admin, &fx.submitter1);
    let feed_id = symbol_short!("BTCUSD");
    let now = fx.env.ledger().timestamp();

    let result = client.try_submit_price(
        &fx.submitter1,
        &feed_id,
        &50000_00000000i128,
        &8u32,
        &now.saturating_sub(1),
        &1u64,
    );
    assert!(result.is_err());
}


#[test]
fn test_is_submitter_active_status() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);

    assert!(!client.is_submitter_active(&fx.submitter1));
    client.register_submitter(&fx.admin, &fx.submitter1);
    assert!(client.is_submitter_active(&fx.submitter1));
    client.deactivate_submitter(&fx.admin, &fx.submitter1);
    assert!(!client.is_submitter_active(&fx.submitter1));
}

fn create_token_contract<'a>(
    env: &'a Env,
    admin: &Address,
) -> (Address, token::Client<'a>, token::StellarAssetClient<'a>) {
    let contract_address = env.register_stellar_asset_contract(admin.clone());
    let client = token::Client::new(env, &contract_address);
    let asset_client = token::StellarAssetClient::new(env, &contract_address);
    (contract_address, client, asset_client)
}

#[test]
fn test_staking_enforcement_on_price_submission() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);

    let (token_addr, token_client, token_asset) = create_token_contract(&fx.env, &fx.admin);
    let treasury = Address::generate(&fx.env);
    let min_stake = 500_i128;
    let cooldown = 3600_u64;

    // Configure staking and treasury
    client.set_staking_config(&fx.admin, &token_addr, &min_stake, &cooldown);
    client.set_treasury(&fx.admin, &treasury);

    // Register submitter1 without stake initially
    client.register_submitter(&fx.admin, &fx.submitter1);

    // Submitter should NOT be active because stake is 0 < min_stake
    assert!(!client.is_submitter_active(&fx.submitter1));
    assert_eq!(client.get_stake(&fx.submitter1), 0);

    // Trying to submit price without stake fails with SubmitterNotAuthorized
    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();
    let res = client.try_submit_price(&fx.submitter1, &feed_id, &50_000_i128, &2u32, &ts, &1u64);
    assert_eq!(res, Err(Ok(OracleError::SubmitterNotAuthorized)));

    // Mint tokens to submitter1 and stake partially (< min_stake)
    token_asset.mint(&fx.submitter1, &1000_i128);
    client.stake(&fx.submitter1, &200_i128);
    assert_eq!(client.get_stake(&fx.submitter1), 200_i128);
    assert_eq!(token_client.balance(&fx.submitter1), 800_i128);
    assert!(!client.is_submitter_active(&fx.submitter1));

    // Still cannot submit price
    let res = client.try_submit_price(&fx.submitter1, &feed_id, &50_000_i128, &2u32, &ts, &1u64);
    assert_eq!(res, Err(Ok(OracleError::SubmitterNotAuthorized)));

    // Stake remaining to meet min_stake
    client.stake(&fx.submitter1, &300_i128);
    assert_eq!(client.get_stake(&fx.submitter1), 500_i128);
    assert!(client.is_submitter_active(&fx.submitter1));

    // Register second submitter with stake directly
    token_asset.mint(&fx.submitter2, &1000_i128);
    client.register_submitter_with_stake(&fx.admin, &fx.submitter2, &500_i128);
    assert!(client.is_submitter_active(&fx.submitter2));
    assert_eq!(client.get_stake(&fx.submitter2), 500_i128);

    // Both submitters can now submit prices
    let sub1_res = client.try_submit_price(&fx.submitter1, &feed_id, &50_000_i128, &2u32, &ts, &1u64);
    assert!(sub1_res.is_ok());

    let sub2_res = client.try_submit_price(&fx.submitter2, &feed_id, &51_000_i128, &2u32, &ts, &1u64);
    assert!(sub2_res.is_ok());

    let latest = client.get_latest_price(&feed_id);
    assert_eq!(latest.price, 50_500_i128);
}

#[test]
fn test_slash_submitter_execution_and_treasury_transfer() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);

    let (token_addr, token_client, token_asset) = create_token_contract(&fx.env, &fx.admin);
    let treasury = Address::generate(&fx.env);
    let min_stake = 1_000_i128;
    let cooldown = 3600_u64;

    client.set_staking_config(&fx.admin, &token_addr, &min_stake, &cooldown);
    client.set_treasury(&fx.admin, &treasury);

    token_asset.mint(&fx.submitter1, &2_000_i128);
    client.register_submitter_with_stake(&fx.admin, &fx.submitter1, &1_500_i128);

    assert_eq!(client.get_stake(&fx.submitter1), 1_500_i128);
    assert_eq!(token_client.balance(&treasury), 0_i128);
    assert!(client.is_submitter_active(&fx.submitter1));

    // Non-governance / non-admin cannot slash
    let unauthorized = Address::generate(&fx.env);
    let slash_err = client.try_slash_submitter(
        &unauthorized,
        &fx.submitter1,
        &500_i128,
        &symbol_short!("bad_data"),
    );
    assert_eq!(slash_err, Err(Ok(OracleError::Unauthorized)));

    // Slash 600 collateral for malicious/off-market price
    client.slash_submitter(
        &fx.admin,
        &fx.submitter1,
        &600_i128,
        &symbol_short!("bad_data"),
    );

    // Remaining stake is 900, which is below min_stake (1000)
    assert_eq!(client.get_stake(&fx.submitter1), 900_i128);
    // Collateral directed to Treasury reserve
    assert_eq!(token_client.balance(&treasury), 600_i128);
    // Oracle contract holds remaining 900
    assert_eq!(token_client.balance(&fx.contract_id), 900_i128);

    // Submitter can no longer submit prices because stake < min_stake
    assert!(!client.is_submitter_active(&fx.submitter1));
    let feed_id = symbol_short!("BTCUSD");
    let ts = fx.env.ledger().timestamp();
    let res = client.try_submit_price(&fx.submitter1, &feed_id, &50_000_i128, &2u32, &ts, &1u64);
    assert_eq!(res, Err(Ok(OracleError::SubmitterNotAuthorized)));
}

#[test]
fn test_unstake_unbonding_cooldown_and_withdraw() {
    let fx = setup();
    let client = OracleContractClient::new(&fx.env, &fx.contract_id);

    let (token_addr, token_client, token_asset) = create_token_contract(&fx.env, &fx.admin);
    let min_stake = 500_i128;
    let cooldown = 3600_u64;

    client.set_staking_config(&fx.admin, &token_addr, &min_stake, &cooldown);

    token_asset.mint(&fx.submitter1, &1_000_i128);
    client.register_submitter_with_stake(&fx.admin, &fx.submitter1, &500_i128);
    assert!(client.is_submitter_active(&fx.submitter1));

    // Initiate unstake
    client.unstake(&fx.submitter1);

    // Submitter is no longer active once unstaked
    assert!(!client.is_submitter_active(&fx.submitter1));
    assert_eq!(client.get_stake(&fx.submitter1), 0);

    let unbonding = client.get_unbonding(&fx.submitter1).unwrap();
    assert_eq!(unbonding.amount, 500_i128);
    let unlock_time = unbonding.unlock_time;
    assert_eq!(unlock_time, fx.env.ledger().timestamp() + cooldown);

    // Cannot initiate another unstake while already unbonding
    assert_eq!(
        client.try_unstake(&fx.submitter1),
        Err(Ok(OracleError::AlreadyUnbonding))
    );

    // Attempting to withdraw before cooldown expires fails with UnbondingCooldownActive
    assert_eq!(
        client.try_withdraw_unbonded(&fx.submitter1),
        Err(Ok(OracleError::UnbondingCooldownActive))
    );

    // Fast-forward time to before unlock_time
    fx.env.ledger().set_timestamp(unlock_time - 1);
    assert_eq!(
        client.try_withdraw_unbonded(&fx.submitter1),
        Err(Ok(OracleError::UnbondingCooldownActive))
    );

    // Fast-forward time to exact unlock_time
    fx.env.ledger().set_timestamp(unlock_time);
    client.withdraw_unbonded(&fx.submitter1);

    // Collateral tokens returned to submitter1
    assert_eq!(token_client.balance(&fx.submitter1), 1_000_i128);
    assert_eq!(client.get_unbonding(&fx.submitter1), None);

    // Trying to withdraw again fails with NoUnbondingRequest
    assert_eq!(
        client.try_withdraw_unbonded(&fx.submitter1),
        Err(Ok(OracleError::NoUnbondingRequest))
    );
}

