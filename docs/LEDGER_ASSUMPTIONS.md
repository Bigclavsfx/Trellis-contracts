# Ledger Assumptions in Contract Tests

Every contract in this repository reads the ledger sequence
(`env.ledger().sequence()`) or the ledger timestamp
(`env.ledger().timestamp()`) to decide whether an operation is allowed. Those
decisions are exact-comparison boundaries, so a test that is off by one ledger
asserts the wrong behaviour and a test that depends on the host clock is not
reproducible.

This document is the contributor-facing record of those boundaries, together
with the deterministic harness that makes them testable. It accompanies
Issue #156.

## The harness

`shared::ledger_sequence::LedgerSequenceHarness` (test-only, behind
`#[cfg(test)]`) is the control for ledger progression in tests. It sets the
clock explicitly and adds:

* **A derived timestamp.** The timestamp is always
  `GENESIS_TIMESTAMP + (sequence - GENESIS_SEQUENCE) * SECONDS_PER_LEDGER`
  (5 s per ledger, matching `testing::sandbox::LEDGERS_PER_DAY`). Nothing reads
  the host clock, so `advance(1)` moves both values by a fixed, reviewable
  amount.
* **Forward-only control.** `at(sequence)` refuses to move the clock backwards;
  a rewind returns `LedgerControlError::Backwards { requested, current }` and
  leaves the clock untouched. This is what stops a test from silently observing
  an older ledger after a newer one, or from "repairing" a stale submission by
  rewinding time.
* **Ordering and boundary classification.** `order_of(submitted_at)` reports
  `SameLedger`, `NextLedger` or `OutOfOrder` for a submission stamp against the
  highest ledger the harness has consumed, and
  `classify(submitted_at, landed_at, deadline)` reports the acceptance-criteria
  case for a submission: `OutOfOrder` when the execution lands behind the stamp
  it carries, else `Expired` when `landed_at > deadline`, else `SameLedger` when
  `landed_at == submitted_at`, else `NextLedger`.

```rust
use shared::ledger_sequence::{LedgerBoundary, LedgerSequenceHarness};
use soroban_sdk::Env;

let env = Env::default();
let mut ledger = LedgerSequenceHarness::from_state(&env, 1_000);
let deadline = ledger.deadline(1);        // 1_001

ledger.advance(1);                        // sequence 1_001, timestamp +5 s
assert_eq!(ledger.sequence(), 1_001);
assert_eq!(
    ledger.classify(1_000, 1_001, deadline),
    LedgerBoundary::NextLedger,
);
```

`from_genesis(env)` starts from ledger 1 at `GENESIS_TIMESTAMP`;
`from_state(env, sequence)` starts from an explicit ledger. Both constructors
are deterministic: the same scenario produces the same sequence, timestamp and
classification on every run and on every machine.

### Why this lives in `shared`

The `testing` crate's `helpers` module already wraps ledger mutation, but on
`main` that crate does not compile (`mocks.rs`, `fuzzing.rs`, `simulation.rs`
and `examples.rs` fail; tracked separately from this issue). Putting the harness
in `shared` means it is compiled and executed by
`cargo test -p shared --lib`, and it can reach the real
`shared::payments` / `shared::idempotency` / `shared::lifecycle` code directly.
Once the `testing` crate builds again, `testing::ledger_sequence` can re-export
this harness rather than duplicating it.

## Boundary table

| Rule | Implementing code | Boundary behaviour |
| --- | --- | --- |
| An escrow's `expiry_ledger` must be **strictly** after the current ledger | `shared::payments::create_escrow` | `expiry == current` → `Error::InvalidArgument` |
| An escrow may be released **at** its expiry ledger | `shared::payments::release_escrow` | `current == expiry` → released; `current == expiry + 1` → `Error::PaymentEscrowExpired` |
| An escrow may be refunded once, and only once | `shared::payments::refund_escrow` | second refund → `Error::PaymentEscrowAlreadyRefunded` (state is checked before the transfer) |
| Aid settles **at or before** expiry and refunds **strictly after** it | `shared::lifecycle::AidStateMachine` | `current == expiry` → settle `Ok`, refund `Error::AidNotExpiredYet`; `current == expiry + 1` → settle `Error::Expired`, refund `Ok` |
| A future expiry must sit inside the configured window | `shared::semantic::validate_future_expiry` | `expiry < current + min_delay_ledgers` or `expiry > current + max_delay_ledgers` → `Error::InvalidArgument` |
| A queued job runs on or after its `next_attempt_ledger` | `shared::jobs::run_due_job` | `now < next_attempt_ledger` → job is not run |
| A duplicate job submission never rewrites the schedule | `shared::jobs::enqueue_job` | second submission → `EnqueueOutcome::AlreadyPending(id)` with the original `due_ledger` |
| A completed request is replayed, not repeated | `shared::idempotency::begin` / `complete` | second `begin` → `Ok(Some(completed record))`; `complete` again → `IdempotencyError::AlreadyCompleted` |
| A key reused for a different request is rejected | `shared::idempotency::begin` | different `request_hash` → `IdempotencyError::ConflictingRequest` |
| A signed payload expires on a timestamp, not a sequence | `shared::replay::consume_payload` | `payload.expiry < env.ledger().timestamp()` → replay rejected |
| A scheduled action before its window is rejected | `shared::schedule::validate_window` | `now < not_before` → `Error::ActionTooEarly` |
| A scheduled action inside its window executes | `shared::schedule::validate_window` | `not_before <= now <= expires_at` → `Ok(())` |
| A scheduled action after expiry is rejected | `shared::schedule::validate_window` | `now > expires_at` → `Error::ActionExpired` |
| A stale scheduled action is rejected before execution | `shared::schedule::execute_action` | `now > expires_at` → `Error::ActionStale`, no state mutation |
| A window with `not_before > expires_at` is refused | `shared::schedule::validate_window` | inverted window → `Error::InvalidArgument` |

The escrow creation/release asymmetry (creation strict, release inclusive) is
deliberate: a deposit whose expiry equals the creation ledger would be
immediately releasable and immediately refundable, so creation requires at
least one ledger of runway, while release accepts the whole expiry ledger.

Scheduled actions use the same inclusive-boundary convention as release: an
action is executable on both `not_before` and `expires_at`, so the window is
closed rather than half-open and an off-by-one regression fails the test.

## Scenarios and coverage

`shared/src/test_ledger_sequence.rs` covers the four acceptance-criteria cases
against the real contract logic:

| Scenario | Test | What it pins |
| --- | --- | --- |
| Same ledger | `same_ledger_creation_and_release_are_deterministic`, `same_ledger_expiry_is_rejected` | Release on the creation ledger succeeds; a repeated release is `PaymentEscrowAlreadyReleased` and pays the beneficiary once; creation with `expiry == current` is refused and leaves no record. |
| Next ledger | `next_ledger_release_exactly_at_expiry_is_allowed` | Release still succeeds on the expiry ledger itself, and the refund path is closed for that escrow. |
| Expired ledger | `expired_ledger_is_rejected_then_refundable` | One ledger past expiry the release fails (`PaymentEscrowExpired`) and the refund succeeds exactly once, irreversibly. |
| Same/next/expired | `aid_settlement_and_refund_boundaries_follow_the_ledger` | The aid state machine flips exactly at `expiry + 1` and terminal states reject re-settlement. |
| Out of order | `out_of_order_submission_cannot_rewind_the_ledger` | A stamp behind the consumed ledger is `OutOfOrder`; the harness refuses to rewind; a stale deadline is rejected by the contract instead of minting a born-expired escrow. |
| Repeated submissions | `repeated_submission_does_not_duplicate_release`, `repeated_submission_with_a_different_payload_is_rejected` | Two identical submissions produce one effect and replay the stored result; the same key with a different payload is `ConflictingRequest`, never a replay. |
| Harness controls | `harness_clock_is_deterministic`, `expiry_window_boundary_is_deterministic` | Sequence ⇒ timestamp, forward-only control, and the future-expiry window at its edges. |
| Scheduled action early | `scheduled_action_before_window_is_rejected` | `now == not_before - 1` → `Error::ActionTooEarly`; the action record is untouched. |
| Scheduled action valid | `scheduled_action_inside_window_executes` | `now == not_before` and `now == expires_at` both execute; the effect is applied exactly once. |
| Scheduled action late | `scheduled_action_after_window_is_rejected` | `now == expires_at + 1` → `Error::ActionExpired`; the action record is untouched. |
| Scheduled action boundary | `scheduled_action_window_boundaries_are_inclusive` | Both `not_before` and `expires_at` are executable; `not_before - 1` and `expires_at + 1` are refused. |
| Scheduled action manipulated timestamp | `scheduled_action_rejects_manipulated_timestamp` | A submission stamped behind the consumed ledger is `OutOfOrder`; the harness refuses to rewind; a stale window is rejected instead of executing. |

Which boundary-table rows are pinned by the suite above: escrow creation,
release and refund; the aid state machine; `validate_future_expiry`; and the
idempotency guard. The `jobs::run_due_job` / `jobs::enqueue_job` and
`replay::consume_payload` rows are documented from the code and are the natural
next additions — the `shared` workers module and `test_replay.rs` currently need
a contract frame before they can be driven from a test.

The scheduled-action rows are pinned by `shared/src/test_schedule.rs`, which
drives `shared::schedule` through the harness and covers early, valid, late,
boundary, and manipulated-timestamp scenarios.

Run just this suite:

```bash
cargo test -p shared --lib test_ledger_sequence
```

The full `cargo test -p shared --lib` run has pre-existing, unrelated failures
in `feature_flags`, `recovery`, `test_auth` and `test_replay` (storage accessed
outside a contract frame, and an auth-tree host error). They are not caused by,
and are not fixed by, this harness.

## Rules for new ledger tests

1. Set the ledger explicitly with `LedgerSequenceHarness`; never rely on the
   `Env::default()` ledger value.
2. Never read the host clock (`std::time`) or OS entropy in a contract test; the
   harness timestamp is the only time source.
3. Assert both sides of a boundary — the allowed ledger and the refused one — so
   an off-by-one regression fails the test rather than passing it.
4. Express a relative window as `ledger.deadline(n)` rather than a magic number.
5. Wrap storage access in `env.as_contract(...)` (or a `#[contractimpl]`
   wrapper, as the harness fixture does); storage is not accessible from a bare
   `Env`.

## Migration, configuration and deployment

No migration, configuration or deployment steps are required. The harness is
test-only code (`#[cfg(test)]`) in the `shared` library; it is not compiled into
any contract wasm, adds no runtime dependency, and changes no contract entry
point.

## Edge-case fixtures (Issue #335)

`shared/src/test_ledger_fixtures.rs` pins the harness at its numeric edges with
literal expected values. Each row is a fixture, so a failing row names the
case and can be checked by hand.

| Edge | Behaviour | Recovery / caller guidance |
| --- | --- | --- |
| Advance by zero | No-op on sequence and timestamp. | None needed. |
| Advance past `u32::MAX` | The sequence saturates at `u32::MAX`. The timestamp is re-derived from the sequence, so it stays at the ceiling value (`23_115_831_670`). | Tests that reach the ceiling should assert the saturated sequence, not keep advancing. |
| Rewind (`at` behind the clock) | Refused with `LedgerControlError::Backwards`; the clock is unchanged. | Fix the test's ordering. A rewind is never a valid way to "repair" a stale stamp. |
| Same ledger (`at` to the current sequence) | Allowed; not a rewind. | None needed. |
| `deadline(n)` past the ceiling | Clamps to `u32::MAX`. | A contract that requires `expiry > current` rejects a clamped deadline at the ceiling, which is the intended fail-closed result. |
| Classify at the deadline / one past it | `NextLedger` at the deadline, `Expired` one past it. | Matches the release rule in the table above. |
| Classify out of order | `OutOfOrder` takes precedence over `Expired`. | Re-compose the submission against the current ledger. Do not replay it. |

Before this change, `advance` saturated the sequence but kept adding
`SECONDS_PER_LEDGER` to the timestamp. A clock that overshot the ceiling
therefore ran ahead of the ledger it reported. The fixture
`advance_fixtures_keep_the_timestamp_derived_from_the_sequence` fails on the old
code and passes on the new.

**Rollback:** the fixtures are test-only, and the `advance` change only affects
test harness time. Reverting the commit restores the old (skewed) behaviour in
tests and changes nothing on-chain.
