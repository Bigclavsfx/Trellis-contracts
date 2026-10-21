# Gas Optimization Guide

> A living checklist for contributors adding new features or modifying
> existing Soroban smart contracts in this workspace.

---

## Table of Contents

- [Principles](#principles)
- [Checklist for New Features](#checklist-for-new-features)
- [Identified Hotspots & Applied Optimizations](#identified-hotspots--applied-optimizations)
- [Benchmark Infrastructure](#benchmark-infrastructure)
- [CI Gas Regression Checks](#ci-gas-regression-checks)
- [Budget Regression Thresholds](#budget-regression-thresholds)
- [Scaling and Retry Guards](#scaling-and-retry-guards-issue-334)

---

## Principles

Soroban "gas" is measured in **compute units (CUs)** and **storage I/O**. Every
host function call (storage read/write, event publish, cross-contract invoke)
has a CU cost. The primary levers for reducing gas are:

1. **Fewer storage I/O operations** — each `env.storage().*()` call is a host
   syscall. Combine reads, avoid redundant reads, and skip writes when the value
   hasn't changed.
2. **Cheapest-fail validation** — reorder guard checks so trivial rejections
   (amount <= 0) happen before expensive ones (auth commitments, storage reads).
3. **Short-circuit early** — return immediately on the most common failure
   paths; don't fall through to expensive operations.
4. **Conditional TTL bumps** — use `persistent_read` (no TTL bump) for read-
   only queries and loop-internal reads. Use `persistent_get` only when you
   need the entry to stay alive.
5. **Pre-cache stable data** — if a value is read multiple times in a loop and
   doesn't change, read it once before the loop.
6. **Avoid unnecessary serialization** — don't deserialize a full collection
   when a lightweight check (e.g., last-element peek) suffices.

---

## Checklist for New Features

Use this checklist before submitting a PR that adds or modifies contract logic.

### Storage

- [ ] **Read-write pairing**: Does every `persistent_set` have a corresponding
  `persistent_get` (or `persistent_read`)? If you write but never read, the
  TTL bump is wasted gas.
- [ ] **`persistent_read` vs `persistent_get`**: Are you using `persistent_read`
  for query-only paths and loop-internal reads? Only use `persistent_get`
  when you need the TTL extension.
- [ ] **Batch reads**: Can you read all needed values before a loop instead of
  re-reading inside it? (See referral `accrue` tier BPS caching.)
- [ ] **Avoid full-collection deserialization**: If you only need to check
  whether an element exists, use a targeted check (e.g., peek at the last
  element) instead of deserializing the entire Vec/Map.

### Validation Ordering

- [ ] **Cheapest first**: Arrange guard checks from cheapest to most expensive.
  Recommended order:
  1. Amount/value bounds (`amount <= 0`, range checks)
  2. State flags (is_paused, status enum match)
  3. Storage reads (lookup balance, config)
  4. Auth commitment (`require_auth()`, `require_role()`, `require_admin()`)
  5. Cross-contract calls (token transfers, treasury interactions)
- [ ] **Short-circuit on common failures**: If 80% of failures are "amount
  zero", check that first.

### Events

- [ ] **Emit once**: Don't emit duplicate events for the same logical action.
  Prefer the typed helpers in `shared::events` over the generic `emit()`.
- [ ] **Event payload size**: Keep event data compact. Avoid embedding large
  structs; use IDs that can be looked up off-chain.

### Math & Types

- [ ] **Use `#[inline]`** on small hot-path helper functions (< 5 statements).
- [ ] **Derive `Copy`** on small enums used in `match` arms to avoid cloning.
- [ ] **Use `checked_*` arithmetic** — overflow panics are cheaper than
  underflow panics but both waste gas on failure. Design so the common path
  never overflows.

### Cross-Contract Calls

- [ ] **Minimize calls**: Each `env.invoke_contract()` or
  `env.try_invoke_contract()` is expensive. Batch operations if possible.
- [ ] **Cache addresses**: Don't re-read a stored contract address if you
  already have it in a local variable.

---

## Identified Hotspots & Applied Optimizations

### 1. Shared Storage: `persistent_read` (NEW)

**File**: `shared/src/storage.rs`

**Problem**: `persistent_get` always calls `extend_ttl`, even for read-only
query paths where the entry was recently written and TTL is fresh.

**Solution**: Added `persistent_read<K, V>()` — a lightweight read that skips
the TTL extension entirely.

**Impact**: Every read-only query across all contracts saves one host syscall.
This affects:
- `accrued_balance()` / `lifetime_accrued()` getters in referral contract
- `get_aid()` query in aid contract
- `get_contract()` / `get_version_history()` in registry contract
- Loop-internal reads in referral `accrue`

### 2. Referral Contract: `accrue` Tier BPS Pre-Caching

**File**: `contracts/referral-contract/src/lib.rs`

**Before**: Each iteration of the tier loop called `read_tier_bps()`, which is
an instance-storage read. With N tiers, that's N redundant reads.

**After**: All tier BPS values are pre-cached into a `Vec` before the loop.
Each iteration reads from the local Vec (essentially free) instead of storage.

**Estimated savings**: ~2 host syscalls per tier × number of tiers.

### 3. Registry Contract: `set_contract` Fast-Path

**File**: `contracts/registry-contract/src/lib.rs`

**Before**: Every `set_contract` call deserialized the full history `Vec` and
ran a linear scan to check for duplicates.

**After**: The last version in the Vec is checked first (O(1)). If it matches,
the full Vec deserialization + linear scan is skipped entirely. This is the
common case when re-registering the same version.

**Estimated savings**: 1 Vec deserialization + 1 linear scan in the common
(fast-path) case.

### 4. Treasury Contract: Validation Reordering

**File**: `contracts/treasury-contract/src/lib.rs`

**Before**: `withdraw`, `deposit`, `distribute_reward`, and
`emergency_withdraw` ran the auth check (`require_role` / `require_admin`)
before cheap validation (amount <= 0).

**After**: Cheap validation runs first. A zero/negative amount is rejected
with a single integer comparison before the expensive auth commitment.

**Impact**: Saves the full auth cost on every trivial reject. Auth involves
crypto verification in the host — the most expensive single operation.

---

## Benchmark Infrastructure

### Running Benchmarks

```bash
# Run all gas benchmarks
cargo test -p aid-contract -- gas_bench
cargo test -p treasury-contract -- gas_bench
cargo test -p referral-contract -- gas_bench
cargo test -p registry-contract -- gas_bench
cargo test -p shared -- persistent_read

# Run all benchmarks at once
cargo test -- gas_bench persistent_read
```

### What the Benchmarks Measure

The `gas_bench_*` tests below measure **behavioral correctness of optimized
paths**, not cost. They assert that a cheap validation runs before an expensive
one, not how many instructions either consumes — for the paths that carry a hard
ceiling, see [Budget Regression Thresholds](#budget-regression-thresholds).

The test host *does* expose its own cost meters (`Env::budget()`), which is what
the budget suite below reads. The earlier claim that it does not was wrong.

- `gas_bench_accrue_3_tier`: Verifies pre-cached tier BPS produces correct
  results for a 3-tier chain.
- `gas_bench_accrue_max_depth`: Stress-tests the 10-tier worst case.
- `gas_bench_claim_rewards`: Verifies the claim flow reads/writes correctly.
- `gas_bench_withdraw_rejects_zero_before_auth`: Verifies zero-amount is
  rejected before auth.
- `gas_bench_deposit_rejects_zero_before_auth`: Same pattern for deposit.
- `gas_bench_distribute_reward_rejects_zero_before_auth`: Same pattern.
- `gas_bench_emergency_withdraw_rejects_zero_before_auth`: Same pattern.
- `gas_bench_set_contract_same_version_skips_history`: Verifies the fast-path
  doesn't corrupt history.
- `persistent_read_*`: Verifies `persistent_read` returns correct values.

### Adding New Benchmarks

When adding a new contract function:

1. Write a `#[test]` named `gas_bench_<function_name>()` that exercises the
   optimized path.
2. Test both the happy path and the most common error path.
3. If the function reads storage in a loop, verify the cached values are
   correct.

---

## CI Gas Regression Checks

Gas regression checks run via the CI workflow at `.github/workflows/gas-check.yml`.
The workflow:

1. Runs `cargo test` for all contracts.
2. Runs the gas benchmark tests specifically (`-- gas_bench persistent_read`).
3. Fails the build if any benchmark test fails.

This ensures that future changes don't silently break gas optimizations.

---

---

## Budget Regression Thresholds

`gas_bench_*` proves validation *ordering*; it does not fail when a path gets more
expensive. `contracts/treasury-contract/src/budget_test.rs` closes that gap: it
runs the treasury's critical entry points against the host's own cost meters
(`Env::budget().cpu_instruction_cost()` / `memory_bytes_cost()`) and asserts the
measurement stays under a recorded ceiling.

### Running the Suite

```bash
cargo test -p treasury-contract -- budget_test
```

Every measurement is taken after `budget().reset_unlimited()`, so the host's own
consumption limit cannot truncate a run, and the meter is read immediately before
and after the call under test so nothing outside it contributes.

### What Each Path Is Measured On

| Shape | Meaning |
| --- | --- |
| common | The typical call, with resources already set up. |
| worst-case supported | The heaviest *accepted* call — the largest amount the guards allow, with the optional quota configured so the whole path runs instead of its fail-open shortcut. |
| rejected over-limit | The call the guards must turn away, which an attacker can force for free. |

### Recorded Thresholds

Raw host measurements at the commit that added the suite, `soroban-sdk 21.7.7`.
`HEADROOM_PERCENT` in `budget_test.rs` (currently 5%) is applied on top of these
by `limit()` before comparison, so the effective ceiling is the raw value plus
5%.

| Constant | Path | Raw CPU instructions | Raw memory bytes |
| --- | --- | ---: | ---: |
| `WITHDRAW_COMMON` | `withdraw`, 200 of a 1,000 limit | 250,480 | 33,764 |
| `WITHDRAW_WORST_SUPPORTED` | `withdraw`, full 1,000 limit, `wdraw` quota configured | 313,531 | 45,844 |
| `WITHDRAW_REJECTED_OVER_LIMIT` | `withdraw`, 1,001 — rejected before auth | 21,999 | 3,934 |
| `DEPOSIT_COMMON` | `deposit`, 500 | 357,448 | 48,054 |
| `DEPOSIT_REJECTED_ZERO` | `deposit`, 0 — rejected before auth | 15,767 | 2,582 |
| `DISTRIBUTE_REWARD_COMMON` | `distribute_reward`, 400 via the referral contract | 232,471 | 30,249 |
| `DISTRIBUTE_REWARD_REJECTED_OVER_BALANCE` | `distribute_reward`, 1,001 against a 1,000 balance | 43,594 | 7,032 |
| `EMERGENCY_WITHDRAW_COMMON` | `emergency_withdraw`, 200 while paused | 220,322 | 30,062 |
| `EMERGENCY_WITHDRAW_REJECTED_NOT_PAUSED` | `emergency_withdraw` while not paused | 23,258 | 4,016 |

Two invariants are asserted on top of the table, so a stale row cannot stay
silent:

* every rejection row must be **strictly cheaper** than the accepted row beside
  it — that property is the whole point of the validation ordering, and it is
  what breaks first if a guard moves after a storage write;
* the quota-configured withdrawal must cost **more** than the plain one,
  otherwise the "worst case" row is measuring the fail-open shortcut by accident.

`every_threshold_has_been_measured` additionally fails while any row is still
zeroed, so a half-filled table cannot be merged.

### Updating a Threshold

Raising a ceiling is a deliberate act, not a fix for a red build:

1. Run `cargo test -p treasury-contract -- budget_test`.
2. Read the measured value out of the failure message — it reports CPU and memory
   for the path that failed.
3. Confirm the increase is intended (a new event, an extra audit write, a wider
   loop) and not an accidental reordering that moved work ahead of a guard.
4. Set the constant in `contracts/treasury-contract/src/budget_test.rs` to the
   measured value and record the reason in the pull request description.

A few percent of drift after a `soroban-sdk` patch bump is absorbed by
`HEADROOM_PERCENT`. A genuine regression on these paths shows up as a multiple,
not as single digits.

### Fixture Caveats

Two constraints the suite has to respect, worth knowing before extending it:

* `deposit` calls `token::Client::transfer`, so the fixture token must be a real
  stellar-asset contract (`env.register_stellar_asset_contract_v2`). A bare
  `Address::generate` aborts it with a host error — and with it every withdrawal
  path, which needs a category balance to withdraw from.
* `set_referral_contract` calls `admin.require_auth()` twice in one invocation
  (once through `require_admin`, once through `grant_role`). The host's
  recording-auth mode (`Env::mock_all_auths`) rejects the second call with
  `Error(Auth, ExistingValue)`, so the suite registers the referral contract by
  writing the same two storage entries directly — see `register_referral` in
  `budget_test.rs`.

## Scaling and Retry Guards (Issue #334)

The recorded thresholds fail only when a measurement exceeds a fixed number. A
path that becomes disproportionately expensive can slip past a stale table. The
guards below compare two measurements taken in the same run, so they need no
recorded value and stay meaningful while the table is being refreshed.

| Test | Property | Edge case it covers |
| --- | --- | --- |
| `withdraw_worst_case_stays_within_twice_the_common_cost` | The heaviest accepted withdrawal costs at most 2x the common one, in both CPU and memory. | The quota-configured path against the fail-open path. |
| `rejected_withdrawal_retry_costs_no_more_than_the_first_attempt` | A retried over-limit rejection costs no more than the first attempt and leaves the balance unchanged. | Retry: a failed call must not leave state that makes the next one more expensive. |

Authorization is not measured here. The suite runs under `mock_all_auths`, so
an unauthorized caller cannot be simulated. The rejection tests cover the
rejection paths that run before auth.

**Operational edge cases.** A guard failure means a path now costs more relative
to its own baseline, which is a stronger signal than a raw threshold breach. Do
not raise the 2x bound to make a failure pass. Find the step that stopped scaling
first.

**Rollback.** These are test-only additions to `budget_test.rs`. Removing them
changes no contract code and no recorded threshold.

## Soroban Cost Reference

Approximate CU costs for common host operations (subject to change per
Soroban version):

| Operation                    | ~CU Cost |
|------------------------------|----------|
| Instance storage read        | ~500     |
| Instance storage write       | ~1,000   |
| Persistent storage read      | ~1,000   |
| Persistent storage write     | ~2,000   |
| Persistent storage extend_ttl| ~500     |
| Event publish                | ~500     |
| `require_auth()`             | ~1,000+  |
| Cross-contract invoke        | ~5,000+  |

These costs are additive — every syscall counts. The optimizations in this
workspace target the highest-frequency operations (storage reads in loops,
auth on trivial rejects, redundant deserialization).
