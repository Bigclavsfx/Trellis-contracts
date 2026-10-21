//! Soroban budget regression suite for the treasury contract's critical paths
//! (issue #158).
//!
//! # Why this exists
//!
//! `GAS_OPTIMIZATION.md` documents an optimization checklist and a set of
//! `gas_bench_*` tests, but those tests only assert *behaviour*: that the cheap
//! validations are ordered correctly, that an accumulator converges. None of
//! them pins the *cost*. Nothing in the repository failed when a change made a
//! treasury path more expensive, and the guide claimed that "Soroban's test host
//! doesn't expose raw CU counts" — which is not true: `Env::budget()` exposes the
//! host's own CPU-instruction and memory meters, which are the same quantities
//! the network charges for.
//!
//! This module turns those meters into assertions.
//!
//! # What is measured
//!
//! Every critical entry point is measured on three shapes:
//!
//! | Shape | Meaning |
//! | --- | --- |
//! | common | The typical call, with resources already set up. |
//! | worst-case supported | The heaviest *accepted* call: the largest amount the guards allow, with the optional quota configured so the whole path runs. |
//! | rejected over-limit | The call the guards must turn away, which an attacker can force for free. |
//!
//! # Thresholds
//!
//! Thresholds live in the `LIMITS` block below, one constant per measurement,
//! and are compared against the measurement with a small percentage of
//! headroom so that a `soroban-sdk` patch bump does not fail the build for no
//! reason. The host's cost model is deterministic for a fixed SDK version and a
//! fixed sequence of operations, so a real regression is reproducible.
//!
//! When a threshold is exceeded, the failure message names the constant to
//! raise. Raising it is a deliberate act: see the "Budget Regression Thresholds"
//! section of `GAS_OPTIMIZATION.md` for the update process.
//!
//! # Fixture notes
//!
//! Two things about the contract shape this suite has to work around, both
//! recorded here because they cost time to rediscover:
//!
//! * `deposit` calls `token::Client::transfer`, so the fixture token must be a
//!   real stellar-asset contract. A bare `Address::generate` aborts it with a
//!   host error, and with it every other measured path: the withdrawals start
//!   from a category balance that only a successful `deposit` can create.
//! * `set_referral_contract` calls `admin.require_auth()` twice in one
//!   invocation (once via `require_admin`, once via `grant_role`), which the
//!   host's recording-auth mode (`Env::mock_all_auths`) rejects with
//!   `Error(Auth, ExistingValue)`. [`register_referral`] therefore writes the
//!   same two storage entries directly, so the `distribute_reward` path can be
//!   measured at all.
//!
//! # Scope note
//!
//! The harness is local to this crate because a shared home would need a new
//! `test-support` feature on the `shared` crate, i.e. a manifest change. If a
//! second contract grows a budget suite, lift [`measure`] and [`BudgetLimit`]
//! into that feature and delete this copy.

#![cfg(test)]

use crate::test::{MockReferralCaller, MockReferralCallerClient};
use crate::{TreasuryContract, TreasuryContractClient};
use soroban_sdk::{symbol_short, testutils::Address as _, testutils::Ledger as _, Address, Env};

// ===========================================================================
// Harness
// ===========================================================================

/// Host resources consumed by one measured operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetCost {
    /// CPU instructions charged by the host.
    pub cpu_instructions: u64,
    /// Memory bytes charged by the host.
    pub memory_bytes: u64,
}

/// A ceiling a [`BudgetCost`] must stay under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetLimit {
    pub cpu_instructions: u64,
    pub memory_bytes: u64,
}

impl BudgetLimit {
    /// Returns the same limit with `percent` of headroom added.
    ///
    /// Headroom exists so that a `soroban-sdk` patch release, which can move the
    /// host's cost model by a few percent, does not fail the build for a change
    /// unrelated to this contract. It is deliberately small: a real regression
    /// in a treasury path is measured in multiples, not in single-digit
    /// percentages.
    pub const fn with_headroom(self, percent: u64) -> Self {
        let factor = 100 + percent;
        Self {
            cpu_instructions: self.cpu_instructions / 100 * factor,
            memory_bytes: self.memory_bytes / 100 * factor,
        }
    }
}

/// Runs `f` and returns its result alongside the host resources it consumed.
///
/// The budget's consumption limits are lifted first, so a measurement cannot be
/// truncated by the host's own abort; the meter is then read before and after
/// `f` and the difference is the cost of `f` alone. Nothing outside `f`
/// contributes.
pub fn measure<T, F: FnOnce() -> T>(env: &Env, f: F) -> (T, BudgetCost) {
    env.budget().reset_unlimited();

    let cpu_before = env.budget().cpu_instruction_cost();
    let memory_before = env.budget().memory_bytes_cost();

    let output = f();

    let cost = BudgetCost {
        cpu_instructions: env
            .budget()
            .cpu_instruction_cost()
            .saturating_sub(cpu_before),
        memory_bytes: env
            .budget()
            .memory_bytes_cost()
            .saturating_sub(memory_before),
    };
    (output, cost)
}

/// Fails when `cost` exceeds `limit`, naming the constant to raise.
///
/// Both numbers are reported on every failure, so one run of the suite is
/// enough to refill the whole `LIMITS` block.
pub fn assert_within(constant: &str, label: &str, limit: BudgetLimit, cost: BudgetCost) {
    let cpu_over = cost.cpu_instructions.saturating_sub(limit.cpu_instructions);
    let memory_over = cost.memory_bytes.saturating_sub(limit.memory_bytes);
    assert!(
        cpu_over == 0 && memory_over == 0,
        "budget regression in {label}: measured {cpu} CPU / {mem} memory bytes, \
         limit is {lcpu} CPU / {lmem} memory bytes (over by {cpu_over} CPU / \
         {memory_over} bytes). If the increase is intended, set {constant} in \
         contracts/treasury-contract/src/budget_test.rs to the measured value and \
         record why in the PR (see the \"Budget Regression Thresholds\" section of \
         GAS_OPTIMIZATION.md).",
        cpu = cost.cpu_instructions,
        mem = cost.memory_bytes,
        lcpu = limit.cpu_instructions,
        lmem = limit.memory_bytes,
    );
}

/// Headroom applied to every threshold, in percent.
pub const HEADROOM_PERCENT: u64 = 5;

// ===========================================================================
// Thresholds
// ===========================================================================
//
// Measured with the host meter, treasury-contract at the commit that added this
// suite, `cargo test -p treasury-contract -- budget_test`. Each entry is the raw
// measurement; `HEADROOM_PERCENT` is applied by `limit()` below.
//
//   withdraw({ amount }).  amount <= 0 ... rejected (before auth)
//                         amount >  limit ... rejected (before auth)
//                         amount <= limit ... common / worst case
//
const WITHDRAW_COMMON: BudgetLimit = BudgetLimit {
    cpu_instructions: 250480,
    memory_bytes: 33764,
};
const WITHDRAW_WORST_SUPPORTED: BudgetLimit = BudgetLimit {
    cpu_instructions: 313531,
    memory_bytes: 45844,
};
const WITHDRAW_REJECTED_OVER_LIMIT: BudgetLimit = BudgetLimit {
    cpu_instructions: 21999,
    memory_bytes: 3934,
};
const DEPOSIT_COMMON: BudgetLimit = BudgetLimit {
    cpu_instructions: 357448,
    memory_bytes: 48054,
};
const DEPOSIT_REJECTED_ZERO: BudgetLimit = BudgetLimit {
    cpu_instructions: 15767,
    memory_bytes: 2582,
};
const DISTRIBUTE_REWARD_COMMON: BudgetLimit = BudgetLimit {
    cpu_instructions: 232471,
    memory_bytes: 30249,
};
const DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE: BudgetLimit = BudgetLimit {
    cpu_instructions: 43594,
    memory_bytes: 7032,
};
const EMERGENCY_WITHDRAW_COMMON: BudgetLimit = BudgetLimit {
    cpu_instructions: 220322,
    memory_bytes: 30062,
};
const EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED: BudgetLimit = BudgetLimit {
    cpu_instructions: 23258,
    memory_bytes: 4016,
};

const fn limit(measured: BudgetLimit) -> BudgetLimit {
    measured.with_headroom(HEADROOM_PERCENT)
}

// ===========================================================================
// Fixtures
// ===========================================================================

/// The treasury's per-transaction withdrawal limit, so the acceptance boundary
/// (`LIMIT`) and the rejection boundary (`LIMIT + 1`) are the same numbers the
/// contract itself compares against.
const LIMIT: i128 = 1_000;

/// Registers the treasury plus a stellar-asset token, and funds the admin.
///
/// The token has to be a real contract: `deposit` calls
/// `token::Client::transfer`, and every other measured path starts from a
/// category balance that only a successful `deposit` can create.
fn setup(env: &Env) -> (TreasuryContractClient<'static>, Address, Address) {
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.initialize(&admin, &LIMIT);

    let token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    soroban_sdk::token::StellarAssetClient::new(env, &token).mint(&admin, &(LIMIT * 10));

    (client, admin, token)
}

/// Sets the shared paused flag the way an operator would, from inside the
/// contract's own storage context.
fn pause(env: &Env, client: &TreasuryContractClient) {
    env.as_contract(&client.address, || shared::storage::set_paused(env, true));
}

/// Registers `referral` as the treasury's referral contract.
///
/// This is the storage effect of `TreasuryContract::set_referral_contract`,
/// written directly because that entry point calls `admin.require_auth()` twice
/// in one invocation and the host's recording-auth mode (`Env::mock_all_auths`)
/// rejects the second call with `Error(Auth, ExistingValue)`. The two entries
/// written here are exactly the ones the setter writes: the `ServiceActor` role
/// that `distribute_reward` checks, and the registered contract address.
fn register_referral(env: &Env, client: &TreasuryContractClient, referral: &Address) {
    env.as_contract(&client.address, || {
        shared::storage::persistent_set(
            env,
            &shared::auth::DataKey::Role(referral.clone(), shared::auth::Role::ServiceActor),
            &true,
        );
        shared::storage::instance_set(env, &crate::REFERRAL_CONTRACT, referral);
    });
}

/// Configures the `wdraw` quota so the withdrawal path runs its quota check
/// instead of short-circuiting on "no config for this resource".
fn configure_withdraw_quota(client: &TreasuryContractClient, admin: &Address, env: &Env) {
    client.set_quota_config(
        admin,
        &symbol_short!("wdraw"),
        &shared::quota::QuotaConfig {
            max_ops_per_window: 1_000,
            window_ledgers: 17_280,
            max_storage_entries: 1_000,
            max_amount_per_op: 0,
            allow_override: true,
        },
    );
    // Move past the window boundary the config write lands on, so the measured
    // call is not the one that also rolls the window over.
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 1);
}

/// Registers the referral stand-in and hands it the treasury's `ServiceActor`
/// role, returning a client for it.
fn referral_caller(
    env: &Env,
    client: &TreasuryContractClient,
) -> MockReferralCallerClient<'static> {
    let referral_id = env.register_contract(None, MockReferralCaller);
    register_referral(env, client, &referral_id);
    MockReferralCallerClient::new(env, &referral_id)
}

// ===========================================================================
// withdraw
// ===========================================================================

#[test]
fn withdraw_common_path_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    let (result, cost) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &200, &category)
    });

    assert!(result.is_ok(), "the common withdrawal must succeed");
    assert_within(
        "WITHDRAW_COMMON",
        "treasury.withdraw.common",
        limit(WITHDRAW_COMMON),
        cost,
    );
}

/// The heaviest *accepted* withdrawal: the full per-transaction limit, with the
/// quota configured so the path does not take its fail-open shortcut.
#[test]
fn withdraw_worst_supported_path_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &LIMIT);
    configure_withdraw_quota(&client, &admin, &env);

    let (result, cost) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &LIMIT, &category)
    });

    assert!(result.is_ok(), "the limit-sized withdrawal must succeed");
    assert_eq!(client.category_balance(&token, &category), 0);
    assert_within(
        "WITHDRAW_WORST_SUPPORTED",
        "treasury.withdraw.worst_supported",
        limit(WITHDRAW_WORST_SUPPORTED),
        cost,
    );
}

/// The rejection a caller can force for free, one stroop over the limit. It must
/// stay cheaper than the accepted path: the guard runs before auth and before
/// any storage write.
#[test]
fn withdraw_rejected_over_limit_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &(LIMIT + 10));

    let (result, cost) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &(LIMIT + 1), &category)
    });

    assert_eq!(
        result,
        Err(Ok(shared::errors::Error::WithdrawalLimitExceeded)),
        "an over-limit withdrawal must be rejected"
    );
    assert_eq!(
        client.category_balance(&token, &category),
        LIMIT + 10,
        "a rejected withdrawal must not touch the balance"
    );
    assert_within(
        "WITHDRAW_REJECTED_OVER_LIMIT",
        "treasury.withdraw.rejected_over_limit",
        limit(WITHDRAW_REJECTED_OVER_LIMIT),
        cost,
    );
}

/// A rejection must cost less than the accepted path it is cheaper than by
/// construction, which is the property the "cheapest-fail validation" ordering
/// in `GAS_OPTIMIZATION.md` exists to preserve.
#[test]
fn rejected_withdrawal_costs_less_than_an_accepted_one() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &(LIMIT + 10));

    let (_, rejected) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &(LIMIT + 1), &category)
    });
    let (_, accepted) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &100, &category)
    });

    assert!(
        rejected.cpu_instructions < accepted.cpu_instructions,
        "an over-limit rejection ({}) must cost fewer CPU instructions than an \
         accepted withdrawal ({}); if this flips, a guard moved after a write",
        rejected.cpu_instructions,
        accepted.cpu_instructions
    );
}

// ===========================================================================
// deposit
// ===========================================================================

#[test]
fn deposit_common_path_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");

    let (result, cost) = measure(&env, || client.try_deposit(&admin, &token, &category, &500));

    assert!(result.is_ok(), "the common deposit must succeed");
    assert_eq!(client.category_balance(&token, &category), 500);
    assert_within(
        "DEPOSIT_COMMON",
        "treasury.deposit.common",
        limit(DEPOSIT_COMMON),
        cost,
    );
}

/// The cheapest rejection there is: a zero amount, which the first guard
/// catches before auth or storage.
#[test]
fn deposit_rejected_zero_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let stranger = Address::generate(&env);

    let (result, cost) = measure(&env, || {
        client.try_deposit(&stranger, &token, &category, &0)
    });

    assert_eq!(result, Err(Ok(shared::errors::Error::InvalidArgument)));
    assert_within(
        "DEPOSIT_REJECTED_ZERO",
        "treasury.deposit.rejected_zero",
        limit(DEPOSIT_REJECTED_ZERO),
        cost,
    );
}

// ===========================================================================
// distribute_reward
// ===========================================================================

#[test]
fn distribute_reward_common_path_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &rewards, &1_000);

    let referral = referral_caller(&env, &client);

    let (result, cost) = measure(&env, || {
        referral.try_call_distribute(&client.address, &token, &recipient, &400)
    });

    assert!(
        result.is_ok(),
        "the common reward distribution must succeed"
    );
    assert_eq!(client.category_balance(&token, &rewards), 600);
    assert_within(
        "DISTRIBUTE_REWARD_COMMON",
        "treasury.distribute_reward.common",
        limit(DISTRIBUTE_REWARD_COMMON),
        cost,
    );
}

/// The rejected shape: more than the `rewards` category holds. Nothing is
/// written and the balance is untouched.
#[test]
fn distribute_reward_rejected_over_balance_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &rewards, &1_000);

    let referral = referral_caller(&env, &client);

    let (result, cost) = measure(&env, || {
        referral.try_call_distribute(&client.address, &token, &recipient, &1_001)
    });

    assert!(result.is_err(), "an over-balance reward must be rejected");
    assert_eq!(
        client.category_balance(&token, &rewards),
        1_000,
        "a rejected distribution must not touch the balance"
    );
    assert_within(
        "DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE",
        "treasury.distribute_reward.rejected_over_balance",
        limit(DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE),
        cost,
    );
}

// ===========================================================================
// emergency_withdraw
// ===========================================================================

#[test]
fn emergency_withdraw_common_path_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let reserve = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &reserve, &500);
    pause(&env, &client);

    let (result, cost) = measure(&env, || {
        client.try_emergency_withdraw(&admin, &token, &recipient, &200)
    });

    assert!(
        result.is_ok(),
        "the paused emergency withdrawal must succeed"
    );
    assert_eq!(client.category_balance(&token, &reserve), 300);
    assert_within(
        "EMERGENCY_WITHDRAW_COMMON",
        "treasury.emergency_withdraw.common",
        limit(EMERGENCY_WITHDRAW_COMMON),
        cost,
    );
}

/// The rejected shape: the contract is not paused, so the call is refused after
/// the cheap amount check and before any storage read of the balance.
#[test]
fn emergency_withdraw_rejected_not_paused_budget() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let reserve = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &reserve, &500);

    let (result, cost) = measure(&env, || {
        client.try_emergency_withdraw(&admin, &token, &recipient, &200)
    });

    assert_eq!(result, Err(Ok(shared::errors::Error::NotPaused)));
    assert_eq!(
        client.category_balance(&token, &reserve),
        500,
        "a rejected emergency withdrawal must not touch the balance"
    );
    assert_within(
        "EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED",
        "treasury.emergency_withdraw.rejected_not_paused",
        limit(EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED),
        cost,
    );
}

// ===========================================================================
// Self-checks on the threshold table itself
// ===========================================================================

/// Without the fixtures above the limit constants would never be exercised, so
/// this test exists to make the table itself self-checking: every row must have
/// been filled in after a measurement run.
#[test]
fn every_threshold_has_been_measured() {
    let rows = [
        ("WITHDRAW_COMMON", WITHDRAW_COMMON),
        ("WITHDRAW_WORST_SUPPORTED", WITHDRAW_WORST_SUPPORTED),
        ("WITHDRAW_REJECTED_OVER_LIMIT", WITHDRAW_REJECTED_OVER_LIMIT),
        ("DEPOSIT_COMMON", DEPOSIT_COMMON),
        ("DEPOSIT_REJECTED_ZERO", DEPOSIT_REJECTED_ZERO),
        ("DISTRIBUTE_REWARD_COMMON", DISTRIBUTE_REWARD_COMMON),
        (
            "DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE",
            DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE,
        ),
        ("EMERGENCY_WITHDRAW_COMMON", EMERGENCY_WITHDRAW_COMMON),
        (
            "EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED",
            EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED,
        ),
    ];
    for (name, row) in rows {
        assert!(
            row.cpu_instructions > 0 && row.memory_bytes > 0,
            "{name} is still zeroed: run the suite once, take the measured \
             value from the failure message, and record it in budget_test.rs"
        );
    }
}

/// Guards against a duplicated category symbol silently making two `LIMITS`
/// rows describe the same measurement: the rejection rows must stay strictly
/// cheaper than the accepted rows next to them.
#[test]
fn every_rejection_stays_cheaper_than_its_accepted_sibling() {
    let pairs = [
        (
            "withdraw.over_limit",
            WITHDRAW_REJECTED_OVER_LIMIT,
            WITHDRAW_COMMON,
        ),
        ("deposit.zero", DEPOSIT_REJECTED_ZERO, DEPOSIT_COMMON),
        (
            "distribute_reward.over_balance",
            DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE,
            DISTRIBUTE_REWARD_COMMON,
        ),
        (
            "emergency_withdraw.not_paused",
            EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED,
            EMERGENCY_WITHDRAW_COMMON,
        ),
    ];
    for (label, rejected, accepted) in pairs {
        assert!(
            rejected.cpu_instructions < accepted.cpu_instructions,
            "{label}: the measured rejection ({}) is not cheaper than the \
             accepted path ({}); a guard is running after work it should \
             prevent",
            rejected.cpu_instructions,
            accepted.cpu_instructions
        );
    }
}

/// The quota-configured withdrawal and the plain one must not be the same
/// number, otherwise the quota branch is dead code in this suite and the
/// "worst case" row measures the fast path by accident.
#[test]
fn worst_case_withdrawal_is_measured_through_the_quota_branch() {
    assert!(
        WITHDRAW_WORST_SUPPORTED.cpu_instructions > WITHDRAW_COMMON.cpu_instructions,
        "the worst-case withdrawal ({}) must cost more than the common one ({}): \
         configure the `wdraw` quota so the full path, not its fail-open \
         shortcut, is measured",
        WITHDRAW_WORST_SUPPORTED.cpu_instructions,
        WITHDRAW_COMMON.cpu_instructions
    );
}

// ===========================================================================
// Scaling and retry guards (issue #334)
// ===========================================================================
//
// The `LIMITS` table above fails only when a measurement exceeds a recorded
// number, so it cannot catch a path that becomes disproportionately expensive
// while the table is stale. These guards compare two measurements taken in the
// same run. They need no recorded threshold, so they stay meaningful while the
// table is being refreshed, and they are not affected by a `soroban-sdk` bump.

/// The heaviest accepted withdrawal must cost at most twice the common one.
///
/// The recorded table puts the worst case at about 1.25× the common path, so
/// two times leaves room for a real change while still failing on a path that
/// stops scaling with its inputs.
#[test]
fn withdraw_worst_case_stays_within_twice_the_common_cost() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &(LIMIT * 2));

    let (common_result, common) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &200, &category)
    });
    configure_withdraw_quota(&client, &admin, &env);
    let (worst_result, worst) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &LIMIT, &category)
    });

    assert!(common_result.is_ok(), "the common withdrawal must succeed");
    assert!(
        worst_result.is_ok(),
        "the limit-sized withdrawal must succeed"
    );
    assert!(
        worst.cpu_instructions <= common.cpu_instructions * 2
            && worst.memory_bytes <= common.memory_bytes * 2,
        "the worst-case withdrawal ({} CPU / {} bytes) costs more than twice the \
         common path ({} CPU / {} bytes); a step now scales worse than its input",
        worst.cpu_instructions,
        worst.memory_bytes,
        common.cpu_instructions,
        common.memory_bytes,
    );
}

/// A retried rejection must not cost more than the first attempt. A rejection
/// writes nothing, so a repeat that costs more means state is accumulating
/// across failed calls.
#[test]
fn rejected_withdrawal_retry_costs_no_more_than_the_first_attempt() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, token) = setup(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &(LIMIT + 10));

    let (first_result, first) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &(LIMIT + 1), &category)
    });
    let (retry_result, retry) = measure(&env, || {
        client.try_withdraw(&admin, &token, &recipient, &(LIMIT + 1), &category)
    });

    assert_eq!(
        first_result,
        Err(Ok(shared::errors::Error::WithdrawalLimitExceeded)),
        "the first over-limit attempt must be rejected"
    );
    assert_eq!(
        retry_result,
        Err(Ok(shared::errors::Error::WithdrawalLimitExceeded)),
        "the retried over-limit attempt must be rejected the same way"
    );
    assert_eq!(
        client.category_balance(&token, &category),
        LIMIT + 10,
        "repeated rejections must not touch the balance"
    );
    assert!(
        retry.cpu_instructions <= first.cpu_instructions
            && retry.memory_bytes <= first.memory_bytes,
        "a retried rejection ({} CPU / {} bytes) costs more than the first attempt \
         ({} CPU / {} bytes); a failed call is leaving state behind",
        retry.cpu_instructions,
        retry.memory_bytes,
        first.cpu_instructions,
        first.memory_bytes,
    );
}
