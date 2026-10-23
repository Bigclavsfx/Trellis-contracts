//! Background worker framework for delayed and retryable work (Issue #35).
//!
//! Soroban contracts cannot spawn threads, so "background" here means
//! **ledger-driven**: a job is an on-chain record with a `due_ledger`, a
//! retry policy and a deterministic idempotency key, and a permissionless
//! [`run_due_job`] call advances at most one job per invocation. A crank bot,
//! a keeper service, or a developer running `stellar contract invoke` all use
//! the same entry point, so long-running and retryable work moves out of the
//! request path without adding an off-chain source of truth.
//!
//! ## Lifecycle
//!
//! ```text
//!                    enqueue_job                run_due_job (handler Ok)
//!   (caller)  ───────────────────▶  Pending  ─────────────────────────▶ Succeeded
//!                                      │                                   │
//!                                      │ handler Err, attempts < max       │ JobReceipt written
//!                                      ▼                                   ▼
//!                                   Pending (next_attempt_ledger =      re-enqueue or
//!                                      now + backoff)                  reprocess returns
//!                                      │                               AlreadyCompleted
//!                                      │ handler Err, attempts == max
//!                                      ▼
//!                                DeadLettered  ─── requeue_dead_letter / discard_dead_letter
//! ```
//!
//! ## Design decisions
//!
//! - **One job per call.** Bounded work per invocation keeps fees predictable
//!   and avoids a single unbounded loop aborting on the instruction budget.
//! - **The retry policy travels with the job.** `Job.policy` is written at
//!   enqueue time, so a later config change can never change the retry
//!   behaviour of already-queued work (reproducible history).
//! - **Idempotency is keyed, not timed.** Every job carries a 32-byte
//!   `dedupe_key`. While a job is queued the key maps to its id, so a second
//!   enqueue returns the existing job instead of duplicating it; once the job
//!   succeeds the key maps to a [`JobReceipt`], so replays and crashes are
//!   safely absorbed.
//! - **Failure context is preserved.** A failed attempt records the contract
//!   error code, the ledger it happened on, the attempt count and the worker
//!   address, so a dead letter can be diagnosed without replaying the ledger.
//!
//! See `docs/WORKERS.md` for local development and operating instructions.

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{instance_get, instance_set, persistent_get, persistent_remove, persistent_set};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Framework-level failures, separate from the domain error a handler returns.
///
/// Keeping these out of the shared [`Error`] enum means the framework can be
/// added to a contract without exhausting that enum's XDR case budget.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum JobError {
    /// The worker is disabled by configuration.
    Disabled = 1,
    /// The supplied retry policy is not usable.
    InvalidPolicy = 2,
    /// No job exists with the supplied id.
    NotFound = 3,
    /// The job already has a completion receipt.
    AlreadyCompleted = 4,
    /// The job is not due yet.
    NotDue = 5,
    /// The job is dead-lettered and must be requeued first.
    NotRetryable = 6,
    /// Only the contract admin may manage the worker.
    Unauthorized = 7,
    /// Pending plus retained dead-letter work has reached capacity.
    QueueFull = 8,
    /// Queue capacity must be between 1 and MAX_QUEUE_CAPACITY.
    InvalidCapacity = 9,
}

// ---------------------------------------------------------------------------
// Job description
// ---------------------------------------------------------------------------

/// Low-cardinality job classification, used for events and dashboards.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobKind {
    /// Refund an escrow deposit once its expiry ledger has passed.
    EscrowRefund,
    /// Caller-defined work dispatched by a custom [`JobHandler`].
    Custom,
}

impl JobKind {
    /// Stable symbol used in job events.
    pub fn as_symbol(&self) -> Symbol {
        match self {
            JobKind::EscrowRefund => symbol_short!("esc_ref"),
            JobKind::Custom => symbol_short!("custom"),
        }
    }
}

/// Work description carried by a job.
///
/// The variant determines [`JobKind`], so a job can never be enqueued with a
/// kind that disagrees with its payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobPayload {
    /// No arguments — the handler decides what to do.
    None,
    /// `payments::refund_escrow`: `(token, escrow_id)`.
    EscrowRefund(Address, u64),
}

impl JobPayload {
    /// The kind implied by this payload.
    pub fn kind(&self) -> JobKind {
        match self {
            JobPayload::None => JobKind::Custom,
            JobPayload::EscrowRefund(_, _) => JobKind::EscrowRefund,
        }
    }
}

/// Where a job is in its lifecycle.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStatus {
    /// Waiting for its next attempt.
    Pending,
    /// Attempted at least once and gave up; inspectable, not retried.
    DeadLettered,
    /// Finished successfully.
    Succeeded,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackoffMode {
    /// Exponential backoff: `base * 2^(attempt - 1)` capped at max.
    Exponential,
    /// Linear backoff: `base * attempt` capped at max.
    Linear,
    /// Fixed interval backoff: constant `base`.
    Fixed,
    /// Jittered backoff: pseudorandomized backoff using deterministic seed.
    Jittered,
}

/// Classify error codes into retryable (transient) vs terminal (permanent).
pub fn is_retryable_error(code: u32) -> bool {
    use crate::errors::Error as E;
    // Permanent non-retryable errors that must immediately dead-letter
    let permanent = [
        E::Unauthorized as u32,
        E::NotFound as u32,
        E::InvalidAmount as u32,
        E::Overflow as u32,
        E::ContractPaused as u32,
        E::AlreadyClaimed as u32,
        E::InsufficientBalance as u32,
        E::WithdrawalLimitExceeded as u32,
        E::InvalidArgument as u32,
        E::NotPaused as u32,
        E::ProposalNotFound as u32,
        E::AlreadyApproved as u32,
        E::BelowThreshold as u32,
        E::AlreadyExecuted as u32,
        E::ImmutableEntry as u32,
        E::InvalidHash as u32,
        E::MetadataNotFound as u32,
        E::AlreadyInitialized as u32,
        E::UnsupportedSchemaVersion as u32,
        E::UnsafeSecret as u32,
        E::ProposalExpired as u32,
        E::ProposalCancelled as u32,
    ];

    for &perm in &permanent {
        if code == perm {
            return false;
        }
    }
    true
}

/// Detailed forensic record of a dead-lettered job for maintainer inspection.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadLetterRecord {
    pub job_id: u64,
    pub kind: JobKind,
    pub payload: JobPayload,
    pub attempts: u32,
    pub last_error: u32,
    pub failed_at_ledger: u32,
    pub worker: Option<Address>,
    pub dedupe_key: BytesN<32>,
}

/// Retry policy written into every job at enqueue time.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Total attempts allowed, including the first one. Must be >= 1.
    pub max_attempts: u32,
    /// Backoff after the first failure, in ledgers. Must be >= 1.
    pub base_backoff_ledgers: u32,
    /// Ceiling for the exponential backoff. Must be >= `base_backoff_ledgers`.
    pub max_backoff_ledgers: u32,
}

impl RetryPolicy {
    /// A conservative default for maintenance work: 5 attempts, 5 minutes
    /// (60 ledgers) doubling up to ~1 day (17 280 ledgers).
    pub const fn maintenance() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 5,
            base_backoff_ledgers: 60,
            max_backoff_ledgers: 17_280,
        }
    }

    /// A policy that never retries.
    pub const fn no_retry() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 1,
            base_backoff_ledgers: 1,
            max_backoff_ledgers: 1,
        }
    }

    /// Reject policies that could never make progress.
    pub fn validate(self) -> Result<(), JobError> {
        if self.max_attempts == 0
            || self.base_backoff_ledgers == 0
            || self.max_backoff_ledgers < self.base_backoff_ledgers
        {
            return Err(JobError::InvalidPolicy);
        }
        Ok(())
    }

    /// Backoff to apply after `attempt` (1-based) failed.
    ///
    /// `base * 2^(attempt-1)`, saturating and capped at `max_backoff_ledgers`.
    pub fn backoff_after(self, attempt: u32) -> u32 {
        let shift = attempt.saturating_sub(1).min(31);
        self.base_backoff_ledgers
            .saturating_mul(1u32 << shift)
            .min(self.max_backoff_ledgers)
    }

    /// Backoff calculation supporting Linear, Fixed, Exponential, and Jittered backoff modes.
    pub fn backoff_with_mode(self, attempt: u32, mode: BackoffMode, seed: u64) -> u32 {
        match mode {
            BackoffMode::Exponential => self.backoff_after(attempt),
            BackoffMode::Linear => {
                let interval = self.base_backoff_ledgers.saturating_mul(attempt.max(1));
                interval.min(self.max_backoff_ledgers)
            }
            BackoffMode::Fixed => self.base_backoff_ledgers.min(self.max_backoff_ledgers),
            BackoffMode::Jittered => {
                let base = self.backoff_after(attempt);
                let jitter = ((seed % 7) as u32).saturating_mul(self.base_backoff_ledgers / 4);
                base.saturating_add(jitter).min(self.max_backoff_ledgers)
            }
        }
    }
}

/// A unit of delayed work.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Job {
    /// Monotonic id, also the storage key suffix.
    pub id: u64,
    /// Kind implied by `payload`.
    pub kind: JobKind,
    /// Work description handed to the handler.
    pub payload: JobPayload,
    /// Idempotency key: replays of the same logical job share this key.
    pub dedupe_key: BytesN<32>,
    /// Current lifecycle state.
    pub status: JobStatus,
    /// Failed attempts so far.
    pub attempts: u32,
    /// Retry policy captured at enqueue time.
    pub policy: RetryPolicy,
    /// Ledger the job was created on.
    pub enqueued_ledger: u32,
    /// Earliest ledger the job wanted to run on.
    pub due_ledger: u32,
    /// Earliest ledger the *next* attempt may run on.
    pub next_attempt_ledger: u32,
    /// Ledger of the most recent attempt (0 = never attempted).
    pub last_attempt_ledger: u32,
    /// Contract error code of the most recent failure (0 = none).
    pub last_error: u32,
    /// Ledger the job succeeded on (0 = not finished).
    pub completed_ledger: u32,
    /// Address of the worker that made the most recent attempt.
    pub worker: Option<Address>,
}

/// Proof that a job's work is done, keyed by `dedupe_key`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobReceipt {
    /// Job that produced this receipt.
    pub job_id: u64,
    /// Kind of the completed job.
    pub kind: JobKind,
    /// Ledger the job succeeded on.
    pub completed_ledger: u32,
    /// Attempts it took, including the successful one.
    pub attempts: u32,
    /// Ledger the job was enqueued on, for tracing back to the request.
    pub correlation_id: u64,
}

/// Worker configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerConfig {
    /// When false, enqueueing and running both fail closed.
    pub enabled: bool,
    /// Policy copied into newly enqueued jobs.
    pub policy: RetryPolicy,
}

/// Running totals, stored in instance storage.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobCounters {
    pub enqueued_total: u64,
    pub succeeded_total: u64,
    pub failed_attempts_total: u64,
    pub dead_lettered_total: u64,
}

impl JobCounters {
    pub const fn zero() -> JobCounters {
        JobCounters {
            enqueued_total: 0,
            succeeded_total: 0,
            failed_attempts_total: 0,
            dead_lettered_total: 0,
        }
    }
}

/// Inspection view of the queue: stored counters plus live queue depth.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStats {
    pub counters: JobCounters,
    /// Jobs still waiting for an attempt.
    pub pending: u32,
    /// Jobs that exhausted their retries.
    pub dead_letters: u32,
    /// Earliest `next_attempt_ledger` across pending jobs, if any.
    pub next_due_ledger: Option<u32>,
}

/// Result of an enqueue attempt.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnqueueOutcome {
    /// A new job was created.
    Created(u64),
    /// A job with the same dedupe key is already queued (same id returned).
    AlreadyPending(u64),
    /// A job with the same dedupe key already finished (same id returned).
    AlreadyCompleted(u64),
}

/// Result of advancing a job.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    /// Nothing was due.
    Empty,
    /// The job is not due yet.
    Skipped(Job),
    /// The handler succeeded.
    Succeeded(Job),
    /// The handler failed and the job will be attempted again.
    Retried(Job),
    /// The handler failed and the job ran out of attempts.
    DeadLettered(Job),
    /// The job had already completed; no handler ran.
    AlreadyCompleted(JobReceipt),
}

/// Domain work the worker dispatches to.
///
/// Implementations must be idempotent: the framework suppresses replays it can
/// see (receipts and dedupe keys), but a handler that mutates state before
/// returning an error will be called again on retry.
pub trait JobHandler {
    fn handle(&self, env: &Env, job: &Job) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------
// Storage keys and events
// ---------------------------------------------------------------------------

/// Storage keys used by the framework.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerKey {
    /// `WorkerConfig` (instance).
    Config,
    /// `u64` id allocator (instance).
    Counter,
    /// `JobCounters` (instance).
    Counters,
    /// `Vec<u64>` ids awaiting an attempt (persistent).
    Pending,
    /// `Vec<u64>` ids that exhausted their retries (persistent).
    DeadLetters,
    /// `Job`.
    Job(u64),
    /// `DeadLetterRecord` forensic record.
    DeadLetterRecord(u64),
    /// `JobReceipt` for a completed dedupe key.
    Receipt(BytesN<32>),
    /// `u64` id currently holding a dedupe key.
    Dedupe(BytesN<32>),
}

/// Topic prefix for every job event.
pub const JOB_TOPIC: Symbol = symbol_short!("job");
/// A job was created.
pub const JOB_ENQUEUED: Symbol = symbol_short!("enqueued");
/// An attempt failed and the job was rescheduled.
pub const JOB_RETRIED: Symbol = symbol_short!("retried");
/// A job finished successfully.
pub const JOB_SUCCEEDED: Symbol = symbol_short!("succeeded");
/// A job exhausted its retries.
pub const JOB_DEAD_LETTERED: Symbol = symbol_short!("deadltr");
/// A dead letter was put back on the queue.
pub const JOB_REQUEUED: Symbol = symbol_short!("requeued");

/// Topics: `("job", event, job_id)`; data: `Job`.
fn publish_job_event(env: &Env, event: Symbol, job: &Job) {
    env.events()
        .publish((JOB_TOPIC, event, job.id), job.clone());
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default configuration: enabled, with the maintenance retry policy.
pub fn default_worker_config() -> WorkerConfig {
    WorkerConfig {
        enabled: true,
        policy: RetryPolicy::maintenance(),
    }
}

/// Read the worker configuration, falling back to the default.
pub fn worker_config(env: &Env) -> WorkerConfig {
    instance_get(env, &WorkerKey::Config).unwrap_or_else(default_worker_config)
}

/// Bounds both queue scans and retained dead-letter work without changing WorkerConfig XDR.
pub const MAX_QUEUE_CAPACITY: u32 = 256;
pub const DEFAULT_QUEUE_CAPACITY: u32 = 64;
const CAPACITY_KEY: Symbol = symbol_short!("job_cap");

pub fn queue_capacity(env: &Env) -> u32 {
    instance_get(env, &CAPACITY_KEY).unwrap_or(DEFAULT_QUEUE_CAPACITY)
}

/// Lowering below current occupancy blocks admission but still permits draining.
pub fn configure_queue_capacity(
    env: &Env,
    caller: &Address,
    capacity: u32,
) -> Result<(), JobError> {
    require_admin(env, caller).map_err(|_| JobError::Unauthorized)?;
    if capacity == 0 || capacity > MAX_QUEUE_CAPACITY {
        return Err(JobError::InvalidCapacity);
    }
    instance_set(env, &CAPACITY_KEY, &capacity);
    Ok(())
}

fn require_queue_slot(env: &Env) -> Result<(), JobError> {
    if pending_job_ids(env)
        .len()
        .saturating_add(dead_letter_job_ids(env).len())
        >= queue_capacity(env)
    {
        return Err(JobError::QueueFull);
    }
    Ok(())
}

/// Update the worker configuration. Admin only.
pub fn configure_worker(
    env: &Env,
    caller: &Address,
    config: WorkerConfig,
) -> Result<(), JobError> {
    require_admin(env, caller).map_err(|_| JobError::Unauthorized)?;
    config.policy.validate()?;
    instance_set(env, &WorkerKey::Config, &config);
    Ok(())
}

/// Stop accepting new work and refuse to run jobs. Admin only.
pub fn pause_worker(env: &Env, caller: &Address) -> Result<(), JobError> {
    let mut config = worker_config(env);
    config.enabled = false;
    configure_worker(env, caller, config)
}

/// Resume the worker. Admin only.
pub fn resume_worker(env: &Env, caller: &Address) -> Result<(), JobError> {
    let mut config = worker_config(env);
    config.enabled = true;
    configure_worker(env, caller, config)
}

// ---------------------------------------------------------------------------
// Dedupe keys
// ---------------------------------------------------------------------------

/// Deterministic 32-byte idempotency key from a tag and a single value.
///
/// This builds the key structurally instead of hashing, so two different
/// `(tag, value)` pairs can never collide.
pub fn dedupe_key_u64(env: &Env, tag: u32, value: u64) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&tag.to_be_bytes());
    bytes[4..12].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

/// Deterministic key from a tag and two values.
pub fn dedupe_key_pair(env: &Env, tag: u32, first: u64, second: u64) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&tag.to_be_bytes());
    bytes[4..12].copy_from_slice(&first.to_be_bytes());
    bytes[12..20].copy_from_slice(&second.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

// ---------------------------------------------------------------------------
// Enqueue
// ---------------------------------------------------------------------------

/// Create a job unless an equivalent one is already queued or finished.
///
/// `dedupe_key` is the caller's idempotency key — use [`dedupe_key_u64`] or
/// [`dedupe_key_pair`] to derive it deterministically from the work identity.
/// `due_ledger` is the earliest ledger the job may run on; use the current
/// ledger for immediate work.
pub fn enqueue_job(
    env: &Env,
    payload: JobPayload,
    dedupe_key: BytesN<32>,
    due_ledger: u32,
    policy: Option<RetryPolicy>,
) -> Result<EnqueueOutcome, JobError> {
    let config = worker_config(env);
    if !config.enabled {
        return Err(JobError::Disabled);
    }
    let policy = policy.unwrap_or(config.policy);
    policy.validate()?;

    // Finished work is never repeated.
    if let Some(receipt) = load_receipt(env, &dedupe_key) {
        return Ok(EnqueueOutcome::AlreadyCompleted(receipt.job_id));
    }

    // Work still queued (or dead-lettered) is not duplicated.
    if let Some(existing) = load_dedupe_owner(env, &dedupe_key) {
        if load_job(env, existing).is_some() {
            return Ok(EnqueueOutcome::AlreadyPending(existing));
        }
    }

    // Admission is checked after dedupe and before allocating or writing anything.
    require_queue_slot(env)?;
    let now = env.ledger().sequence();
    let id = next_job_id(env);
    let job = Job {
        id,
        kind: payload.kind(),
        payload,
        dedupe_key: dedupe_key.clone(),
        status: JobStatus::Pending,
        attempts: 0,
        policy,
        enqueued_ledger: now,
        due_ledger,
        next_attempt_ledger: due_ledger,
        last_attempt_ledger: 0,
        last_error: 0,
        completed_ledger: 0,
        worker: None,
    };

    save_job(env, &job);
    persistent_set(env, &WorkerKey::Dedupe(dedupe_key), &id);
    index_push(env, &WorkerKey::Pending, id);
    persist_counters(env, |c| {
        c.enqueued_total += 1;
    });
    publish_job_event(env, JOB_ENQUEUED, &job);

    Ok(EnqueueOutcome::Created(id))
}

/// Convenience wrapper for the escrow-refund job, deduped by escrow id.
pub fn enqueue_escrow_refund(
    env: &Env,
    token: Address,
    escrow_id: u64,
    due_ledger: u32,
) -> Result<EnqueueOutcome, JobError> {
    let key = dedupe_key_u64(env, ESCROW_REFUND_TAG, escrow_id);
    enqueue_job(
        env,
        JobPayload::EscrowRefund(token, escrow_id),
        key,
        due_ledger,
        None,
    )
}

/// Tag identifying escrow-refund jobs in dedupe keys.
pub const ESCROW_REFUND_TAG: u32 = 0x6573_6372; // "escr"

// ---------------------------------------------------------------------------
// Running jobs
// ---------------------------------------------------------------------------

/// Attempt the earliest due job, if any.
///
/// Permissionless: anyone can crank the queue. The calling address is recorded
/// on the job for accountability.
pub fn run_due_job<H: JobHandler>(
    env: &Env,
    worker: &Address,
    now: u32,
    handler: &H,
) -> Result<RunOutcome, JobError> {
    require_enabled(env)?;
    let Some(id) = earliest_due_job(env, now) else {
        return Ok(RunOutcome::Empty);
    };
    attempt_job(env, worker, id, now, handler)
}

/// Attempt one specific job, whether or not it is due.
///
/// Used to replay a dead letter after inspection, or to run a known job on
/// demand. A job that already finished returns its receipt instead of running
/// the handler again.
pub fn reprocess_job<H: JobHandler>(
    env: &Env,
    worker: &Address,
    job_id: u64,
    now: u32,
    handler: &H,
) -> Result<RunOutcome, JobError> {
    require_enabled(env)?;
    if load_job(env, job_id).is_none() {
        return Err(JobError::NotFound);
    }
    attempt_job(env, worker, job_id, now, handler)
}

fn attempt_job<H: JobHandler>(
    env: &Env,
    worker: &Address,
    job_id: u64,
    now: u32,
    handler: &H,
) -> Result<RunOutcome, JobError> {
    let mut job = load_job(env, job_id).ok_or(JobError::NotFound)?;

    if job.status == JobStatus::Succeeded {
        let receipt = load_receipt(env, &job.dedupe_key).unwrap_or_else(|| receipt_for(&job));
        return Ok(RunOutcome::AlreadyCompleted(receipt));
    }
    if job.status == JobStatus::DeadLettered {
        return Err(JobError::NotRetryable);
    }
    if job.next_attempt_ledger > now {
        return Ok(RunOutcome::Skipped(job));
    }

    job.attempts = job.attempts.saturating_add(1);
    job.last_attempt_ledger = now;
    job.worker = Some(worker.clone());

    match handler.handle(env, &job) {
        Ok(()) => {
            job.status = JobStatus::Succeeded;
            job.completed_ledger = now;
            job.last_error = 0;
            save_job(env, &job);
            index_remove(env, &WorkerKey::Pending, job.id);
            let receipt = receipt_for(&job);
            persistent_set(env, &WorkerKey::Receipt(job.dedupe_key.clone()), &receipt);
            persist_counters(env, |c| {
                c.succeeded_total += 1;
            });
            publish_job_event(env, JOB_SUCCEEDED, &job);
            Ok(RunOutcome::Succeeded(job))
        }
        Err(err) => {
            let code = contract_error_code(err);
            job.last_error = code;
            let retryable = is_retryable_error(code);
            if !retryable || job.attempts >= job.policy.max_attempts {
                job.status = JobStatus::DeadLettered;
                save_job(env, &job);
                let dl_record = DeadLetterRecord {
                    job_id: job.id,
                    kind: job.kind,
                    payload: job.payload.clone(),
                    attempts: job.attempts,
                    last_error: code,
                    failed_at_ledger: now,
                    worker: job.worker.clone(),
                    dedupe_key: job.dedupe_key.clone(),
                };
                persistent_set(env, &WorkerKey::DeadLetterRecord(job.id), &dl_record);
                index_remove(env, &WorkerKey::Pending, job.id);
                index_push(env, &WorkerKey::DeadLetters, job.id);
                persist_counters(env, |c| {
                    c.failed_attempts_total += 1;
                    c.dead_lettered_total += 1;
                });
                publish_job_event(env, JOB_DEAD_LETTERED, &job);
                Ok(RunOutcome::DeadLettered(job))
            } else {
                job.status = JobStatus::Pending;
                job.next_attempt_ledger = now.saturating_add(job.policy.backoff_after(job.attempts));
                save_job(env, &job);
                persist_counters(env, |c| {
                    c.failed_attempts_total += 1;
                });
                publish_job_event(env, JOB_RETRIED, &job);
                Ok(RunOutcome::Retried(job))
            }
        }
    }
}

/// Put a dead letter back on the queue with a fresh attempt budget. Admin only.
pub fn requeue_dead_letter(
    env: &Env,
    caller: &Address,
    job_id: u64,
    now: u32,
) -> Result<Job, JobError> {
    require_admin(env, caller).map_err(|_| JobError::Unauthorized)?;
    require_enabled(env)?;
    let mut job = load_job(env, job_id).ok_or(JobError::NotFound)?;
    if job.status != JobStatus::DeadLettered {
        return Err(JobError::NotRetryable);
    }
    // Indexed dead letters already reserve a slot. Discarded records do not.
    if dead_letter_job_ids(env).first_index_of(job_id).is_none() {
        require_queue_slot(env)?;
    }
    job.status = JobStatus::Pending;
    job.attempts = 0;
    job.last_error = 0;
    job.next_attempt_ledger = now;
    job.completed_ledger = 0;
    save_job(env, &job);
    index_remove(env, &WorkerKey::DeadLetters, job_id);
    index_push(env, &WorkerKey::Pending, job_id);
    publish_job_event(env, JOB_REQUEUED, &job);
    Ok(job)
}

/// Drop a dead letter from the queue, keeping the job record for audit.
/// Admin only.
pub fn discard_dead_letter(
    env: &Env,
    caller: &Address,
    job_id: u64,
) -> Result<Job, JobError> {
    require_admin(env, caller).map_err(|_| JobError::Unauthorized)?;
    let job = load_job(env, job_id).ok_or(JobError::NotFound)?;
    if job.status != JobStatus::DeadLettered {
        return Err(JobError::NotRetryable);
    }
    index_remove(env, &WorkerKey::DeadLetters, job_id);
    Ok(job)
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/// Read one job.
pub fn get_job(env: &Env, job_id: u64) -> Option<Job> {
    load_job(env, job_id)
}

/// Read forensic dead letter record.
pub fn get_dead_letter_record(env: &Env, job_id: u64) -> Option<DeadLetterRecord> {
    persistent_get(env, &WorkerKey::DeadLetterRecord(job_id))
}

/// Retrieve dead letter records for maintainer inspection.
pub fn list_dead_letters(env: &Env, cursor: Option<u64>, limit: u32) -> Vec<DeadLetterRecord> {
    let ids = dead_letter_job_ids(env);
    let mut records = Vec::new(env);
    let total = ids.len();
    let mut start_idx = 0u32;
    if let Some(c) = cursor {
        let mut i = 0u32;
        while i < total {
            if ids.get(i).unwrap_or(0) > c {
                start_idx = i;
                break;
            }
            i += 1;
        }
        if i == total {
            return records;
        }
    }

    let mut idx = start_idx;
    while idx < total && (records.len() as u32) < limit {
        let id = ids.get(idx).unwrap_or(0);
        if let Some(rec) = get_dead_letter_record(env, id) {
            records.push_back(rec);
        } else if let Some(job) = load_job(env, id) {
            records.push_back(DeadLetterRecord {
                job_id: job.id,
                kind: job.kind,
                payload: job.payload,
                attempts: job.attempts,
                last_error: job.last_error,
                failed_at_ledger: job.last_attempt_ledger,
                worker: job.worker,
                dedupe_key: job.dedupe_key,
            });
        }
        idx += 1;
    }
    records
}

/// Read the completion receipt for a dedupe key.
pub fn get_receipt(env: &Env, dedupe_key: &BytesN<32>) -> Option<JobReceipt> {
    load_receipt(env, dedupe_key)
}

/// Ids waiting for an attempt.
pub fn pending_job_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &WorkerKey::Pending).unwrap_or_else(|| Vec::new(env))
}

/// Ids that exhausted their retries.
pub fn dead_letter_job_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &WorkerKey::DeadLetters).unwrap_or_else(|| Vec::new(env))
}

/// Earliest `next_attempt_ledger` across pending jobs.
pub fn next_due_ledger(env: &Env) -> Option<u32> {
    let mut earliest: Option<u32> = None;
    for id in pending_job_ids(env).iter() {
        let Some(job) = load_job(env, id) else {
            continue;
        };
        earliest = Some(match earliest {
            Some(current) if current <= job.next_attempt_ledger => current,
            _ => job.next_attempt_ledger,
        });
    }
    earliest
}

/// Stored counters plus live queue depth.
pub fn job_stats(env: &Env) -> JobStats {
    JobStats {
        counters: load_counters(env),
        pending: pending_job_ids(env).len(),
        dead_letters: dead_letter_job_ids(env).len(),
        next_due_ledger: next_due_ledger(env),
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn require_enabled(env: &Env) -> Result<(), JobError> {
    if worker_config(env).enabled {
        Ok(())
    } else {
        Err(JobError::Disabled)
    }
}

fn receipt_for(job: &Job) -> JobReceipt {
    JobReceipt {
        job_id: job.id,
        kind: job.kind,
        completed_ledger: job.completed_ledger,
        attempts: job.attempts,
        correlation_id: job.enqueued_ledger as u64,
    }
}

fn contract_error_code(err: Error) -> u32 {
    soroban_sdk::Error::from(err).get_code()
}

fn load_job(env: &Env, job_id: u64) -> Option<Job> {
    persistent_get(env, &WorkerKey::Job(job_id))
}

fn save_job(env: &Env, job: &Job) {
    persistent_set(env, &WorkerKey::Job(job.id), job);
}

fn load_receipt(env: &Env, dedupe_key: &BytesN<32>) -> Option<JobReceipt> {
    persistent_get(env, &WorkerKey::Receipt(dedupe_key.clone()))
}

fn load_dedupe_owner(env: &Env, dedupe_key: &BytesN<32>) -> Option<u64> {
    persistent_get(env, &WorkerKey::Dedupe(dedupe_key.clone()))
}

fn next_job_id(env: &Env) -> u64 {
    let current: u64 = instance_get(env, &WorkerKey::Counter).unwrap_or(0);
    let next = current.saturating_add(1);
    instance_set(env, &WorkerKey::Counter, &next);
    next
}

fn earliest_due_job(env: &Env, now: u32) -> Option<u64> {
    let mut best: Option<(u64, u32)> = None;
    for id in pending_job_ids(env).iter() {
        let Some(job) = load_job(env, id) else {
            continue;
        };
        if job.next_attempt_ledger > now {
            continue;
        }
        let replace = match best {
            Some((_, due)) => job.next_attempt_ledger < due,
            None => true,
        };
        if replace {
            best = Some((id, job.next_attempt_ledger));
        }
    }
    best.map(|(id, _)| id)
}

fn load_counters(env: &Env) -> JobCounters {
    instance_get(env, &WorkerKey::Counters).unwrap_or_else(JobCounters::zero)
}

fn persist_counters<F: FnOnce(&mut JobCounters)>(env: &Env, update: F) {
    let mut counters = load_counters(env);
    update(&mut counters);
    instance_set(env, &WorkerKey::Counters, &counters);
}

fn index_push(env: &Env, key: &WorkerKey, id: u64) {
    let mut ids: Vec<u64> = persistent_get(env, key).unwrap_or_else(|| Vec::new(env));
    if ids.first_index_of(id).is_none() {
        ids.push_back(id);
        persistent_set(env, key, &ids);
    }
}

fn index_remove(env: &Env, key: &WorkerKey, id: u64) {
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
