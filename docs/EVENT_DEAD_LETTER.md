# Dead-Letter Recovery for Domain-Event Handlers

`shared::event_dead_letter` (Issue #335) gives an in-contract reaction to a
`shared::domain_events::DomainEvent` the same dead-letter discipline
`shared::jobs` already gives background work, without changing either
module.

## The gap this closes

`shared::domain_events` validates and publishes events, but has no concept
of a consumer that reacts to one in the same contract (updating an index,
a downstream side effect, cross-module notification, …). If that reaction
fails today, there are only two options: let the error propagate and abort
the whole transaction — including the event publish itself — or swallow it
silently and lose the failure. Neither is acceptable for a handler whose
failure must not block the primary action but also must not disappear.

## Design in one paragraph

`dispatch_event` runs a `DomainEventHandler` against an event. On success,
nothing is stored. On failure, instead of propagating the error, it records
an `EventDeadLetter` and returns which outcome occurred, so the caller's own
transaction can still commit. The letter carries a `shared::jobs::RetryPolicy`
captured at creation time — this module reuses that type and
`shared::jobs::is_retryable_error` directly rather than inventing a second
retry-policy type. `retry_dead_letter` is the permissionless, backoff-gated
retry path: anyone can call it once a pending letter's `next_attempt_ledger`
has passed, mirroring `shared::jobs::run_due_job`. `requeue_dead_letter` and
`discard_dead_letter` are the admin-gated recovery/rollback path for a letter
that has exhausted its retries, mirroring `shared::jobs`'s own functions of
the same name (hence the aliased crate-root re-exports —
`requeue_event_dead_letter` / `discard_event_dead_letter` — since the
unaliased names are already taken by `shared::jobs`).

## Public surface

| Item | Purpose |
|---|---|
| `DomainEventHandler` | Trait a contract implements: `handle(&self, env, event) -> Result<(), Error>`. Must be idempotent — a retried letter calls `handle` again with the exact same event. |
| `dispatch_event` | Run the handler; dead-letter instead of propagating on failure. |
| `retry_dead_letter` | Permissionless, backoff-gated retry of a `Pending` letter. |
| `requeue_dead_letter` / `discard_dead_letter` | Admin-gated recovery/rollback for a `DeadLettered` letter. |
| `get_dead_letter` / `pending_dead_letter_ids` / `dead_letter_ids` | Inspection. |

## Who can do what

| Action | Required role / condition |
|---|---|
| Dispatch an event, or retry a due `Pending` letter | Anyone — permissionless, same model as `shared::jobs::run_due_job` |
| Requeue or discard a `DeadLettered` letter | `Role::Admin` (via `shared::auth::require_admin`) |
| Read a letter or list ids | Anyone (read-only) |

## Operational edge cases

| Situation | Behavior |
|---|---|
| Handler succeeds (first attempt or a retry) | `DispatchOutcome::Succeeded`; no record is kept (a retry's existing record is deleted). |
| Handler fails with a non-retryable error code, or `policy.max_attempts == 1` | Dead-lettered immediately, no retry scheduled. |
| Handler fails with a retryable error code and attempts remain | `DispatchOutcome::Retried`; `next_attempt_ledger` is set from `policy.backoff_after`. |
| `retry_dead_letter` called before `next_attempt_ledger` | `Error::ActionTooEarly` — the letter is untouched, no attempt is consumed. |
| `retry_dead_letter` called on an id that is already `DeadLettered` or does not exist | `Error::InvalidTransition` / `Error::NotFound`; dead letters must go through `requeue_dead_letter` first. |
| `requeue_dead_letter` / `discard_dead_letter` on a `Pending` letter | `Error::InvalidTransition` — only exhausted (`DeadLettered`) letters can be requeued or discarded. |
| Non-admin calls `requeue_dead_letter` / `discard_dead_letter` | `Error::Unauthorized` before the record is touched. |
| Invalid `RetryPolicy` passed to `dispatch_event` | `Error::ConfigInvalid`, the same validation `RetryPolicy::validate` already enforces for background jobs. |

## Rollback and recovery

1. **A handler bug caused a batch of letters to dead-letter.** Fix and
   redeploy the handler, then call `requeue_dead_letter` for each affected
   id (iterate `dead_letter_ids`) to give them a fresh attempt budget. The
   original event payload is preserved exactly, so replay is deterministic.
2. **A dead letter should not be retried at all** (e.g. the underlying event
   is now obsolete): call `discard_dead_letter`. The record itself is kept
   for audit — only its membership in the dead-letter index is cleared —
   mirroring `shared::jobs::discard_dead_letter`.
3. **A dependency the handler needs was degraded and is now healthy again**,
   and letters are still inside their backoff window: there is no need to
   wait them out — `requeue_dead_letter` resets `next_attempt_ledger` to
   "now" immediately.
4. **A bad `RetryPolicy` was used.** `dispatch_event` takes the policy per
   call rather than reading global, persistent configuration, so correcting
   it only affects events dispatched after the fix; already-stored letters
   keep the policy they were created with, exactly like
   `shared::jobs::Job.policy`.

## Compatibility

Purely additive: new storage keys, no changes to `shared::domain_events`,
`shared::jobs`, or any contract interface. A contract adopts it by calling
`dispatch_event` after (or instead of) directly invoking its own handler
logic for a published event; nothing changes until that call is wired in.
