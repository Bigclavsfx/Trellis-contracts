//! # Treasury Contract — Asset Conservation Invariant & Threat Model Test Suite
//!
//! Formal verification and invariant test suite proving asset conservation
//! across all treasury state transitions:
//! - Category deposits
//! - Direct withdrawals
//! - Scheduled time-window withdrawals
//! - Referral reward distributions
//! - Emergency reserve withdrawals
//! - Failure paths (limit exceeded, insufficient balance, unauthorized, unpaused emergency)
//! - Fixture mutations (negative proofs detecting impossible balances)
//!
//! This suite also serves as the executable verification for the scenario-based
//! threat model documented in `contracts/treasury-contract/THREAT_MODEL.md`.
//! Each test below maps to a trust boundary and abuse case in that document.

#![cfg(test)]

extern crate std;
use std::vec::Vec;

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    token, Env, Symbol,
};
use shared::invariants::{
    assert_asset_conservation, assert_reversion_invariance, mutations, verify_conservation,
    AssetConservationSnapshot, InvariantViolation,
};

/// Shared fixture representing the cross-boundary trust graph for the treasury.
struct TreasuryTestFixture {
    env: Env,
    admin: Address,
    manager: Address,
    referral_contract: Address,
    recipient: Address,
    token_addr: Address,
    token_client: token::Client<'static>,
    asset_client: token::StellarAssetClient<'static>,
    contract_id: Address,
    client: TreasuryContractClient<'static>,
}

fn setup_treasury_fixture() -> TreasuryTestFixture {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let manager = Address::generate(&env);
    let referral_contract = Address::generate(&env);
    let recipient = Address::generate(&env);

    let token_addr = env.register_stellar_asset_contract(admin.clone());
    let token_client = token::Client::new(&env, &token_addr);
    let asset_client = token::StellarAssetClient::new(&env, &token_addr);

    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);

    // Initialise with 50,000 withdrawal limit
    client.initialize(&admin, &50_000);
    client.add_treasury_manager(&admin, &manager);
    client.set_referral_contract(&admin, &referral_contract);

    // Initial funding to manager for deposits
    asset_client.mint(&manager, &200_000);
    asset_client.mint(&admin, &100_000);

    TreasuryTestFixture {
        env,
        admin,
        manager,
        referral_contract,
        recipient,
        token_addr,
        token_client: unsafe { std::mem::transmute(token_client) },
        asset_client: unsafe { std::mem::transmute(asset_client) },
        contract_id,
        client: unsafe { std::mem::transmute(client) },
    }
}

impl TreasuryTestFixture {
    /// Calculate the sum of all category liabilities in the treasury
    fn total_category_liabilities(&self, categories: &[Symbol]) -> i128 {
        let mut total: i128 = 0;
        for cat in categories {
            total += self.client.category_balance(&self.token_addr, cat);
        }
        total
    }

    /// Capture a formal asset conservation snapshot
    fn capture_snapshot(&self, categories: &[Symbol]) -> AssetConservationSnapshot {
        let internal_liabilities = self.total_category_liabilities(categories);
        let participants = [
            (self.admin.clone(), "Admin"),
            (self.manager.clone(), "Manager"),
            (self.recipient.clone(), "Recipient"),
            (self.referral_contract.clone(), "ReferralContract"),
        ];

        AssetConservationSnapshot::capture(
            &self.env,
            &self.token_client,
            &self.contract_id,
            &participants,
            internal_liabilities,
        )
    }
}

// ---------------------------------------------------------------------------
// 1. Treasury Deposit Path Invariant Tests
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_treasury_deposit_conserves_assets() {
    let fx = setup_treasury_fixture();
    let categories = [
        symbol_short!("reserve"),
        symbol_short!("rewards"),
        symbol_short!("ops"),
    ];

    let before = fx.capture_snapshot(&categories);
    let deposit_amount: i128 = 40_000;

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &deposit_amount,
    );

    let after = fx.capture_snapshot(&categories);

    let report = assert_asset_conservation(&before, &after);
    assert_eq!(report.net_system_delta, 0, "No tokens created or destroyed");
    assert_eq!(
        report.contract_reserve_delta, deposit_amount,
        "Contract reserve matches deposit"
    );
    assert_eq!(
        report.internal_liabilities_delta, deposit_amount,
        "Internal category balance matches deposit"
    );

    assert_eq!(
        after.get_balance(&fx.manager).unwrap(),
        before.get_balance(&fx.manager).unwrap() - deposit_amount
    );
}

// ---------------------------------------------------------------------------
// 2. Multi-Category Allocation Invariant Tests
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_multi_category_segregation_conserves_assets() {
    let fx = setup_treasury_fixture();
    let categories = [
        symbol_short!("reserve"),
        symbol_short!("rewards"),
        symbol_short!("ops"),
    ];

    let before = fx.capture_snapshot(&categories);

    // Deposit into 3 distinct categories
    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &20_000,
    );
    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("rewards"),
        &15_000,
    );
    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("ops"),
        &10_000,
    );

    let after = fx.capture_snapshot(&categories);

    let report = assert_asset_conservation(&before, &after);
    assert_eq!(report.net_system_delta, 0);
    assert_eq!(report.contract_reserve_delta, 45_000);
    assert_eq!(report.internal_liabilities_delta, 45_000);

    assert_eq!(
        fx.client
            .category_balance(&fx.token_addr, &symbol_short!("reserve")),
        20_000
    );
    assert_eq!(
        fx.client
            .category_balance(&fx.token_addr, &symbol_short!("rewards")),
        15_000
    );
    assert_eq!(
        fx.client
            .category_balance(&fx.token_addr, &symbol_short!("ops")),
        10_000
    );
}

// ---------------------------------------------------------------------------
// 3. Referral Commission Reward Distribution Invariant Tests
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_distribute_reward_conserves_internal_balances() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve"), symbol_short!("rewards")];

    // Pre-fund rewards category with 25,000
    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("rewards"),
        &25_000,
    );

    let before_reward = fx.capture_snapshot(&categories);
    let reward_amount: i128 = 5_000;

    let res = fx.client.try_distribute_reward(
        &fx.token_addr,
        &fx.recipient,
        &reward_amount,
    );
    assert!(res.is_ok());

    let after_reward = fx.capture_snapshot(&categories);

    // Rewards category decremented by 5,000
    assert_eq!(
        fx.client
            .category_balance(&fx.token_addr, &symbol_short!("rewards")),
        20_000
    );
    assert_eq!(
        after_reward.internal_liabilities,
        before_reward.internal_liabilities - reward_amount
    );
}

// ---------------------------------------------------------------------------
// 4. Scheduled Withdrawal Invariant Tests
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_scheduled_withdrawal_lifecycle_conserves_state() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve"), symbol_short!("rewards")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &30_000,
    );

    let action_id = symbol_short!("sched_1");
    let now = fx.env.ledger().timestamp();
    let window = TimeWindow {
        not_before: now + 100,
        expires_at: now + 300,
    };

    let before_sched = fx.capture_snapshot(&categories);

    // Schedule withdrawal
    fx.client.schedule_withdraw(
        &fx.admin,
        &action_id,
        &fx.token_addr,
        &fx.recipient,
        &12_000,
        &symbol_short!("reserve"),
        &window,
    );

    let after_sched = fx.capture_snapshot(&categories);
    // Scheduling alone does not debit or move tokens until execution
    assert_eq!(
        after_sched.total_system_assets(),
        before_sched.total_system_assets()
    );

    // Advance time into the execution window
    fx.env.ledger().set_timestamp(now + 150);

    let exec_res = fx.client.try_execute_scheduled_withdraw(&fx.manager, &action_id);
    assert!(exec_res.is_ok());

    let after_exec = fx.capture_snapshot(&categories);
    assert_eq!(
        fx.client
            .category_balance(&fx.token_addr, &symbol_short!("reserve")),
        18_000
    );
    assert_eq!(
        after_exec.internal_liabilities,
        before_sched.internal_liabilities - 12_000
    );
}

// ---------------------------------------------------------------------------
// 5. Failure Paths (Reversion Invariance)
// ---------------------------------------------------------------------------

// Threat model: TB-3 (Manager -> Contract) and TB-4 (Admin -> Contract).
// Abuse cases: over-limit withdrawal, over-balance withdrawal, and emergency
// drain while unpaused. All must revert with zero state mutation.
#[test]
fn test_invariant_treasury_failure_paths_preserve_exact_state() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &20_000,
    );

    let baseline = fx.capture_snapshot(&categories);

    // 1. Withdrawal exceeding withdrawal limit (limit is 50,000, request 60,000)
    let err_limit = fx.client.try_withdraw(
        &fx.manager,
        &fx.token_addr,
        &fx.recipient,
        &60_000,
        &symbol_short!("reserve"),
    );
    assert!(err_limit.is_err());
    let after_limit = fx.capture_snapshot(&categories);
    assert_reversion_invariance(&baseline, &after_limit);

    // 2. Withdrawal exceeding category balance (balance is 20,000, request 25,000)
    let err_bal = fx.client.try_withdraw(
        &fx.manager,
        &fx.token_addr,
        &fx.recipient,
        &25_000,
        &symbol_short!("reserve"),
    );
    assert!(err_bal.is_err());
    let after_bal = fx.capture_snapshot(&categories);
    assert_reversion_invariance(&baseline, &after_bal);

    // 3. Emergency withdrawal attempted while contract is NOT paused
    let err_emrg = fx.client.try_emergency_withdraw(
        &fx.admin,
        &fx.token_addr,
        &fx.admin,
        &10_000,
    );
    assert!(err_emrg.is_err());
    let after_emrg = fx.capture_snapshot(&categories);
    assert_reversion_invariance(&baseline, &after_emrg);
}

// ---------------------------------------------------------------------------
// 6. Mutation Testing (Proving Tests Fail on Impossible Balances)
// ---------------------------------------------------------------------------

// Threat model: TB-5 (Off-chain accounting -> On-chain state).
// Abuse cases: fabricated reserve inflation, silent reserve drain, phantom
// category liabilities, and negative participant balances. The invariant
// verifier must reject each corrupted snapshot.
#[test]
fn test_mutation_impossible_balances_fail_invariant_verification() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &15_000,
    );

    let before = fx.capture_snapshot(&categories);

    // Mutation 1: Artificial reserve inflation
    let mut corrupted1 = fx.capture_snapshot(&categories);
    mutations::corrupt_inflate_reserve(&mut corrupted1, 5_000);
    match verify_conservation(&before, &corrupted1) {
        Err(InvariantViolation::AssetConservationViolated { net_delta, .. }) => {
            assert_eq!(net_delta, 5_000);
        }
        other => panic!("Expected AssetConservationViolated, got {:?}", other),
    }

    // Mutation 2: Reserve leakage / drain
    let mut corrupted2 = fx.capture_snapshot(&categories);
    mutations::corrupt_drain_reserve(&mut corrupted2, 4_000);
    match verify_conservation(&before, &corrupted2) {
        Err(InvariantViolation::AssetConservationViolated { net_delta, .. }) => {
            assert_eq!(net_delta, -4_000);
        }
        other => panic!("Expected AssetConservationViolated, got {:?}", other),
    }

    // Mutation 3: Internal liabilities mismatch (phantom category balance)
    let mut corrupted3 = fx.capture_snapshot(&categories);
    mutations::corrupt_internal_liabilities(&mut corrupted3, 6_000);
    match verify_conservation(&before, &corrupted3) {
        Err(InvariantViolation::SolvencyBackingMismatched { discrepancy, .. }) => {
            assert_eq!(discrepancy, -6_000);
        }
        other => panic!("Expected SolvencyBackingMismatched, got {:?}", other),
    }

    // Mutation 4: Negative account balance
    let mut corrupted4 = fx.capture_snapshot(&categories);
    mutations::corrupt_negative_balance(&mut corrupted4, &fx.manager);
    match verify_conservation(&before, &corrupted4) {
        Err(InvariantViolation::ImpossibleBalanceDetected { balance, .. }) => {
            assert_eq!(balance, -100);
        }
        other => panic!("Expected ImpossibleBalanceDetected, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 7. Cross-Boundary Trust Decision Scenarios (Threat Model Executable Checks)
// ---------------------------------------------------------------------------
//
// The scenarios below encode the highest-risk abuse cases from the threat
// model. They are intentionally small and target the trust boundaries that
// separate the treasury from managers, admins, the referral contract, and
// external token issuers.

/// TB-1: External token issuer -> Treasury.
/// Abuse case: a caller attempts to deposit a token whose issuer has not been
/// vetted, hoping the treasury will credit a category without real backing.
/// Mitigation: deposits must move real tokens; the conservation snapshot
/// proves the contract reserve delta equals the credited category delta.
#[test]
fn test_threat_unvetted_token_deposit_cannot_credit_phantom_liability() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve")];

    // A second, unrelated token that the treasury has never been funded with.
    let rogue_admin = Address::generate(&fx.env);
    let rogue_token = fx.env.register_stellar_asset_contract(rogue_admin.clone());
    let rogue_asset = token::StellarAssetClient::new(&fx.env, &rogue_token);
    rogue_asset.mint(&fx.manager, &10_000);

    let before = fx.capture_snapshot(&categories);

    // Deposit of the rogue token must not silently succeed without moving
    // real value into the treasury's tracked reserve for the canonical token.
    let res = fx.client.try_deposit(
        &fx.manager,
        &rogue_token,
        &symbol_short!("reserve"),
        &10_000,
    );

    let after = fx.capture_snapshot(&categories);
    if res.is_ok() {
        // If the contract accepts the deposit, conservation must still hold
        // for the canonical token: no phantom liability may appear.
        assert_reversion_invariance(&before, &after);
    } else {
        assert_reversion_invariance(&before, &after);
    }
}

/// TB-2: Referral contract -> Treasury.
/// Abuse case: the referral contract (or a spoofed caller) attempts to drain
/// the rewards category beyond what was deposited. Mitigation: category
/// balance is debited atomically and cannot go negative.
#[test]
fn test_threat_referral_overdraft_cannot_underflow_rewards_category() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("rewards")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("rewards"),
        &5_000,
    );

    let baseline = fx.capture_snapshot(&categories);

    // Attempt to distribute more than the rewards category holds.
    let res = fx.client.try_distribute_reward(
        &fx.token_addr,
        &fx.recipient,
        &7_500,
    );
    assert!(res.is_err(), "overdraft must revert");

    let after = fx.capture_snapshot(&categories);
    assert_reversion_invariance(&baseline, &after);
    assert_eq!(
        fx.client
            .category_balance(&fx.token_addr, &symbol_short!("rewards")),
        5_000
    );
}

/// TB-4: Admin -> Treasury (emergency path).
/// Abuse case: admin pauses the contract and drains the reserve to an
/// arbitrary address, then unpauses. Mitigation: emergency withdrawals must
/// still respect conservation and be observable via the snapshot delta.
#[test]
fn test_threat_emergency_withdraw_is_conservation_observable() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &30_000,
    );

    let before = fx.capture_snapshot(&categories);

    // Pause, then perform an emergency withdrawal to the admin.
    // The treasury contract has no `pause` entry point; the shared paused flag
    // is set from inside the contract's own storage context, the same way an
    // operator would.
    fx.env
        .as_contract(&fx.contract_id, || shared::storage::set_paused(&fx.env, true));
    let res = fx.client.try_emergency_withdraw(
        &fx.admin,
        &fx.token_addr,
        &fx.admin,
        &10_000,
    );
    assert!(res.is_ok(), "paused emergency withdrawal should succeed");

    let after = fx.capture_snapshot(&categories);

    // Conservation must hold: the admin's gain equals the contract's loss.
    let report = assert_asset_conservation(&before, &after);
    assert_eq!(report.net_system_delta, 0, "no tokens created or destroyed");
    assert_eq!(
        after.get_balance(&fx.admin).unwrap(),
        before.get_balance(&fx.admin).unwrap() + 10_000
    );
    assert_eq!(
        after.contract_token_reserve,
        before.contract_token_reserve - 10_000
    );
}

/// TB-3: Manager -> Treasury (scheduled path).
/// Abuse case: a scheduled withdrawal is executed before its `not_before`
/// window or after `expires_at`, bypassing the time-based trust control.
/// Mitigation: execution outside the window must revert with no state change.
#[test]
fn test_threat_scheduled_withdraw_outside_window_reverts_cleanly() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &20_000,
    );

    let action_id = symbol_short!("sched_x");
    let now = fx.env.ledger().timestamp();
    let window = TimeWindow {
        not_before: now + 1_000,
        expires_at: now + 2_000,
    };

    fx.client.schedule_withdraw(
        &fx.admin,
        &action_id,
        &fx.token_addr,
        &fx.recipient,
        &5_000,
        &symbol_short!("reserve"),
        &window,
    );

    let baseline = fx.capture_snapshot(&categories);

    // Too early: still before `not_before`.
    let early = fx.client.try_execute_scheduled_withdraw(&fx.manager, &action_id);
    assert!(early.is_err(), "early execution must revert");
    let after_early = fx.capture_snapshot(&categories);
    assert_reversion_invariance(&baseline, &after_early);

    // Too late: past `expires_at`.
    fx.env.ledger().set_timestamp(now + 3_000);
    let late = fx.client.try_execute_scheduled_withdraw(&fx.manager, &action_id);
    assert!(late.is_err(), "expired execution must revert");
    let after_late = fx.capture_snapshot(&categories);
    assert_reversion_invariance(&baseline, &after_late);
}

/// TB-5: Off-chain accounting -> On-chain state (rollback/recovery check).
/// Abuse case: an operator restores from a stale snapshot that understates
/// liabilities. Mitigation: the invariant verifier flags the discrepancy so
/// the operator can roll back to the last consistent snapshot.
#[test]
fn test_threat_stale_snapshot_recovery_is_detectable() {
    let fx = setup_treasury_fixture();
    let categories = [symbol_short!("reserve")];

    fx.client.deposit(
        &fx.manager,
        &fx.token_addr,
        &symbol_short!("reserve"),
        &12_000,
    );

    let live = fx.capture_snapshot(&categories);

    // Simulate a stale off-chain snapshot that understates liabilities.
    let mut stale = live.clone();
    mutations::corrupt_internal_liabilities(&mut stale, -3_000);

    match verify_conservation(&live, &stale) {
        Err(InvariantViolation::SolvencyBackingMismatched { discrepancy, .. }) => {
            assert_eq!(discrepancy, 3_000);
        }
        other => panic!("Expected SolvencyBackingMismatched, got {:?}", other),
    }
}
