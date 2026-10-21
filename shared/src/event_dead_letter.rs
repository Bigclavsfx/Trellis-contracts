//! Dead-letter recovery for failed domain-event handlers (Issue #335).
//!
//! `shared::domain_events` validates and publishes [`DomainEvent`]s, but has
//! no concept of an in-contract consumer that reacts to one (indexing
//! bookkeeping, a downstream side effect, cross-module notification, …). If
//! that reaction fails, the options today are: let the error propagate and
//! abort the whole transaction — including the event publish itself — or
//! swallow it silently and lose the failure. Neither is acceptable for a
//! handler whose failure must not block the primary action but also must
//! not disappear.
//!
//! This module gives domain-event handler dispatch the same dead-letter
//! discipline `shared::jobs` already gives background work, and reuses
//! [`RetryPolicy`] directly rather than inventing a second retry-policy type:
//!
//! - [`dispatch_event`] runs the handler. On success nothing is stored. On
//!   failure, instead of propagating the error, it records an
//!   [`EventDeadLetter`] and returns which outcome occurred — the caller's
//!   own transaction (e.g. the code that published the event) can still
//!   commit.
//! - [`retry_dead_letter`] is the permissionless, backoff-gated retry path:
//!   anyone can call it once a pending dead letter's `next_attempt_ledger`
//!   has passed; it re-runs the handler and either clears the letter,
//!   reschedules it, or marks it dead-lettered once retries are exhausted.
//! - [`requeue_dead_letter`] / [`discard_dead_letter`] are the admin-gated
//!   recovery/rollback path for a letter that has exhausted its retries.
//!
//! Nothing in `shared::domain_events` or `shared::jobs` changes: this module
//! only reads their public types ([`DomainEvent`], [`RetryPolicy`],
//! `is_retryable_error`) and adds its own storage and entry points.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Handler succeeds (first attempt or a retry) | `DispatchOutcome::Succeeded`; no record is kept. |
//! | Handler fails with a non-retryable error code, or `policy.max_attempts == 1` | Dead-lettered immediately, no retry scheduled. |
//! | Handler fails with a retryable error code and attempts remain | `DispatchOutcome::Retried`; `next_attempt_ledger` is set from `policy.backoff_after`. |
//! | `retry_dead_letter` called before `next_attempt_ledger` | `Error::ActionTooEarly` — the letter is untouched, no attempt is consumed. |
//! | `retry_dead_letter` called on an id that is already `DeadLettered` or does not exist | `Error::InvalidTransition` / `Error::NotFound`; dead letters must go through `requeue_dead_letter` first. |
//! | `requeue_dead_letter` / `discard_dead_letter` on a `Pending` letter | `Error::InvalidTransition` — only exhausted (`DeadLettered`) letters can be requeued or discarded. |
//! | Non-admin calls `requeue_dead_letter` / `discard_dead_letter` | `Error::Unauthorized` before the record is touched. |
//! | Invalid `RetryPolicy` passed to `dispatch_event` | `Error::ConfigInvalid`, same validation `shared::jobs::RetryPolicy::validate` already enforces. |
//!
//! ## Recovery / rollback
//!
//! 1. **A handler bug caused a batch of letters to dead-letter.** Fix and
//!    redeploy the handler, then call `requeue_dead_letter` for each
//!    affected id (or iterate `dead_letter_ids`) to give them a fresh
//!    attempt budget. The original event payload is preserved exactly, so
//!    replay is deterministic.
//! 2. **A dead letter should not be retried at all** (e.g. the underlying
//!    event is now obsolete): call `discard_dead_letter`. The record itself
//!    is kept for audit — only its membership in the dead-letter index is
//!    cleared — mirroring `shared::jobs::discard_dead_letter`.
//! 3. **A dependency the handler needs was degraded and is now healthy
//!    again**, and letters are still inside their backoff window: there is
//!    no need to wait them out — `requeue_dead_letter` resets
//!    `next_attempt_ledger` to "now" immediately.
//! 4. **Rollback of a bad `RetryPolicy`**: `dispatch_event` takes the policy
//!    per call (it is not global, persistent configuration), so correcting
//!    it only affects events dispatched after the fix; already-stored
//!    letters keep the policy they were created with, exactly like
//!    `shared::jobs::Job.policy`.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `shared::domain_events`,
//! `shared::jobs`, or any contract interface. A contract adopts it by calling
//! `dispatch_event` after (or instead of) directly invoking its own handler
//! logic for a published event.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::domain_events::DomainEvent;
use crate::errors::Error;
use crate::jobs::{is_retryable_error, RetryPolicy};
use crate::storage::{instance_get, instance_set, persistent_get, persistent_remove, persistent_set};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Where a dispatched event's handler stands.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDispatchStatus {
    /// Failed at least once; retried automatically once due.
    Pending,
    /// Exhausted its retries; inspectable, not retried automatically.
    DeadLettered,
}

/// A failed domain-event handler invocation awaiting retry or admin recovery.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDeadLetter {
    pub id: u64,
    pub event: DomainEvent,
    pub status: EventDispatchStatus,
    /// Failed attempts so far (the successful attempt, if any, is never counted here).
    pub attempts: u32,
    /// Retry policy captured when this letter was first created.
    pub policy: RetryPolicy,
    /// Contract error code of the most recent failure.
    pub last_error: u32,
    pub first_failed_ledger: u32,
    pub last_attempt_ledger: u32,
    /// Earliest ledger the next retry may run on (only meaningful while `Pending`).
    pub next_attempt_ledger: u32,
}

/// Result of attempting a handler, whether for a fresh event or a retry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    /// The handler succeeded on this attempt; no letter exists afterward.
    Succeeded,
    /// The handler failed; a letter exists and will be retried once due.
    Retried(u64),
    /// The handler failed and exhausted its retries (or was never retryable).
    DeadLettered(u64),
}

/// In-contract reaction to a domain event.
///
/// Implementations must be idempotent: a retried letter calls `handle` again
/// with the exact same event.
pub trait DomainEventHandler {
    fn handle(&self, env: &Env, event: &DomainEvent) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------
// Storage keys and events
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum EventDeadLetterKey {
    Counter,
    Record(u64),
    Pending,
    DeadLetters,
}

/// Topic prefix for every dead-letter event.
pub const EVENT_DLQ_TOPIC: Symbol = symbol_short!("evt_dlq");
/// A handler succeeded on a retried letter.
pub const EVENT_DLQ_RESOLVED: Symbol = symbol_short!("resolved");
/// A handler failed and the letter will be retried.
pub const EVENT_DLQ_RETRIED: Symbol = symbol_short!("retried");
/// A handler failed and the letter exhausted its retries.
pub const EVENT_DLQ_DEAD_LETTERED: Symbol = symbol_short!("deadltr");
/// A dead letter was put back on the retry path by an admin.
pub const EVENT_DLQ_REQUEUED: Symbol = symbol_short!("requeued");

fn publish(env: &Env, event: Symbol, id: u64) {
    env.events().publish((EVENT_DLQ_TOPIC, event), id);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn apply_failure(record: &mut EventDeadLetter, err: Error, now: u32) -> bool {
    let code = soroban_sdk::Error::from(err).get_code();
    record.last_error = code;
    record.last_attempt_ledger = now;
    let retryable = is_retryable_error(code) && record.attempts < record.policy.max_attempts;
    if retryable {
        record.status = EventDispatchStatus::Pending;
        record.next_attempt_ledger = now.saturating_add(record.policy.backoff_after(record.attempts));
    } else {
        record.status = EventDispatchStatus::DeadLettered;
    }
    retryable
}

/// Runs `handler` against `event`. On success nothing is stored. On failure,
/// records a new [`EventDeadLetter`] instead of propagating the error, so the
/// caller's own transaction can still commit.
///
/// `policy` defaults to [`RetryPolicy::maintenance`] when `None`. Returns
/// [`Error::ConfigInvalid`] if an explicit policy fails
/// [`RetryPolicy::validate`].
pub fn dispatch_event<H: DomainEventHandler>(
    env: &Env,
    event: DomainEvent,
    policy: Option<RetryPolicy>,
    handler: &H,
) -> Result<DispatchOutcome, Error> {
    let policy = policy.unwrap_or_else(RetryPolicy::maintenance);
    policy.validate().map_err(|_| Error::ConfigInvalid)?;

    match handler.handle(env, &event) {
        Ok(()) => Ok(DispatchOutcome::Succeeded),
        Err(err) => {
            let now = env.ledger().sequence();
            let id = next_dead_letter_id(env);
            let mut record = EventDeadLetter {
                id,
                event,
                status: EventDispatchStatus::Pending,
                attempts: 1,
                policy,
                last_error: 0,
                first_failed_ledger: now,
                last_attempt_ledger: now,
                next_attempt_ledger: now,
            };
            let retried = apply_failure(&mut record, err, now);
            save_record(env, &record);
            if retried {
                index_push(env, &EventDeadLetterKey::Pending, id);
                publish(env, EVENT_DLQ_RETRIED, id);
                Ok(DispatchOutcome::Retried(id))
            } else {
                index_push(env, &EventDeadLetterKey::DeadLetters, id);
                publish(env, EVENT_DLQ_DEAD_LETTERED, id);
                Ok(DispatchOutcome::DeadLettered(id))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Retry (permissionless, backoff-gated)
// ---------------------------------------------------------------------------

/// Re-attempts `handler` against a `Pending` letter, if it is due.
///
/// Permissionless: anyone can crank a due letter, the same way
/// `shared::jobs::run_due_job` is permissionless. Returns
/// [`Error::ActionTooEarly`] if `now < next_attempt_ledger`, and
/// [`Error::InvalidTransition`] if the letter is already `DeadLettered`
/// (use [`requeue_dead_letter`] first).
pub fn retry_dead_letter<H: DomainEventHandler>(
    env: &Env,
    id: u64,
    now: u32,
    handler: &H,
) -> Result<DispatchOutcome, Error> {
    let mut record = get_dead_letter(env, id).ok_or(Error::NotFound)?;
    if record.status != EventDispatchStatus::Pending {
        return Err(Error::InvalidTransition);
    }
    if record.next_attempt_ledger > now {
        return Err(Error::ActionTooEarly);
    }
    record.attempts = record.attempts.saturating_add(1);

    match handler.handle(env, &record.event) {
        Ok(()) => {
            index_remove(env, &EventDeadLetterKey::Pending, id);
            persistent_remove(env, &EventDeadLetterKey::Record(id));
            publish(env, EVENT_DLQ_RESOLVED, id);
            Ok(DispatchOutcome::Succeeded)
        }
        Err(err) => {
            let retried = apply_failure(&mut record, err, now);
            save_record(env, &record);
            if retried {
                publish(env, EVENT_DLQ_RETRIED, id);
                Ok(DispatchOutcome::Retried(id))
            } else {
                index_remove(env, &EventDeadLetterKey::Pending, id);
                index_push(env, &EventDeadLetterKey::DeadLetters, id);
                publish(env, EVENT_DLQ_DEAD_LETTERED, id);
                Ok(DispatchOutcome::DeadLettered(id))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Admin recovery / rollback
// ---------------------------------------------------------------------------

/// Gives a `DeadLettered` letter a fresh attempt budget, admin-gated.
///
/// Returns [`Error::InvalidTransition`] unless the letter is currently
/// `DeadLettered`.
pub fn requeue_dead_letter(
    env: &Env,
    admin: &Address,
    id: u64,
    now: u32,
) -> Result<EventDeadLetter, Error> {
    require_admin(env, admin)?;
    let mut record = get_dead_letter(env, id).ok_or(Error::NotFound)?;
    if record.status != EventDispatchStatus::DeadLettered {
        return Err(Error::InvalidTransition);
    }
    record.status = EventDispatchStatus::Pending;
    record.attempts = 0;
    record.last_error = 0;
    record.next_attempt_ledger = now;
    save_record(env, &record);
    index_remove(env, &EventDeadLetterKey::DeadLetters, id);
    index_push(env, &EventDeadLetterKey::Pending, id);
    publish(env, EVENT_DLQ_REQUEUED, id);
    Ok(record)
}

/// Drops a `DeadLettered` letter from the dead-letter index, keeping the
/// record itself for audit. Admin-gated.
///
/// Returns [`Error::InvalidTransition`] unless the letter is currently
/// `DeadLettered`.
pub fn discard_dead_letter(env: &Env, admin: &Address, id: u64) -> Result<EventDeadLetter, Error> {
    require_admin(env, admin)?;
    let record = get_dead_letter(env, id).ok_or(Error::NotFound)?;
    if record.status != EventDispatchStatus::DeadLettered {
        return Err(Error::InvalidTransition);
    }
    index_remove(env, &EventDeadLetterKey::DeadLetters, id);
    Ok(record)
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/// Reads one dead-letter record by id.
pub fn get_dead_letter(env: &Env, id: u64) -> Option<EventDeadLetter> {
    persistent_get(env, &EventDeadLetterKey::Record(id))
}

/// Ids currently awaiting a due retry.
pub fn pending_dead_letter_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &EventDeadLetterKey::Pending).unwrap_or_else(|| Vec::new(env))
}

/// Ids that exhausted their retries.
pub fn dead_letter_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &EventDeadLetterKey::DeadLetters).unwrap_or_else(|| Vec::new(env))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn save_record(env: &Env, record: &EventDeadLetter) {
    persistent_set(env, &EventDeadLetterKey::Record(record.id), record);
}

fn next_dead_letter_id(env: &Env) -> u64 {
    let current: u64 = instance_get(env, &EventDeadLetterKey::Counter).unwrap_or(0);
    let next = current.saturating_add(1);
    instance_set(env, &EventDeadLetterKey::Counter, &next);
    next
}

fn index_push(env: &Env, key: &EventDeadLetterKey, id: u64) {
    let mut ids: Vec<u64> = persistent_get(env, key).unwrap_or_else(|| Vec::new(env));
    if ids.first_index_of(id).is_none() {
        ids.push_back(id);
        persistent_set(env, key, &ids);
    }
}

fn index_remove(env: &Env, key: &EventDeadLetterKey, id: u64) {
    let mut ids: Vec<u64> = persistent_get(env, key).unwrap_or_else(|| Vec::new(env));
    if let Some(position) = ids.first_index_of(id) {
        let _ = ids.remove(position);
        if ids.is_empty() {
            persistent_remove(env, key);
        } else {
            persistent_set(env, key, &ids);
        }
    }
}
