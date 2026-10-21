//! Deterministic ledger-sequence harness controls (Issue #156).
//!
//! Soroban tests must be reproducible: no wall clock, no OS entropy, and an
//! explicit ledger for every boundary a test asserts on. The ledger helpers in
//! `shared`'s sibling crate (`testing::helpers`) cover the mechanics, but the
//! `testing` crate does not build on `main` (pre-existing breakage in
//! `mocks.rs`, `fuzzing.rs`, `simulation.rs` and `examples.rs`, tracked
//! separately), so the boundary logic that lives **in this crate** gets its
//! own test-only control here.
//!
//! [`LedgerSequenceHarness`] adds the two things a raw
//! `env.ledger().set_sequence_number(..)` call does not give a test:
//!
//! 1. a **deterministic timestamp** derived from the sequence
//!    ([`SECONDS_PER_LEDGER`] per ledger), so time never comes from the host
//!    clock, and
//! 2. **ordering**: the harness tracks the highest ledger it has consumed, so
//!    a caller cannot silently move the clock backwards and a submission
//!    stamped behind that high-water mark is reported as
//!    [`LedgerOrder::OutOfOrder`] instead of being replayed.
//!
//! ## Ledger assumptions this harness pins
//!
//! | Rule | Code | Boundary |
//! | --- | --- | --- |
//! | An escrow's `expiry_ledger` must be strictly after the current ledger | [`crate::payments::create_escrow`] | `expiry == current` → `Error::InvalidArgument` |
//! | An escrow can be released **at** its expiry ledger | [`crate::payments::release_escrow`] | `current == expiry` → released, `current == expiry + 1` → `Error::PaymentEscrowExpired` |
//! | Aid settles at or before expiry, refunds strictly after it | [`crate::lifecycle::AidStateMachine`] | `current == expiry` → settle `Ok` / refund `Err`, `current == expiry + 1` → settle `Err` / refund `Ok` |
//! | A future expiry must sit inside the configured window | [`crate::semantic::validate_future_expiry`] | `expiry < current + min_delay_ledgers` → `Error::InvalidArgument` |
//! | A queued job never moves earlier, and re-submitting it never rewrites the schedule | [`crate::jobs::enqueue_job`] | duplicate submission → `EnqueueOutcome::AlreadyPending` with the original `due_ledger` |
//! | A completed request is replayed, not repeated | [`crate::idempotency::begin`] | second `begin` → the stored completed record; a different `request_hash` → `IdempotencyError::ConflictingRequest` |
//!
//! The scenario tests live in [`crate::test_ledger_sequence`] and cover the
//! four acceptance-criteria cases: same-ledger, next-ledger, expired-ledger
//! and out-of-order. See `docs/LEDGER_ASSUMPTIONS.md` for the
//! contributor-facing version of this table.

use soroban_sdk::{testutils::Ledger as _, Env};

/// Seconds per ledger used by the deterministic clock.
///
/// Matches the ~5 s close time the repository targets elsewhere (see the
/// `testing` crate's `sandbox::LEDGERS_PER_DAY`).
pub const SECONDS_PER_LEDGER: u64 = 5;

/// Ledger sequence [`LedgerSequenceHarness::from_genesis`] starts from.
pub const GENESIS_SEQUENCE: u32 = 1;

/// Timestamp [`LedgerSequenceHarness::from_genesis`] starts from
/// (2022-01-01T00:00:00Z).
pub const GENESIS_TIMESTAMP: u64 = 1_640_995_200;

/// A submission's ledger stamp relative to the harness high-water mark.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LedgerOrder {
    /// The same ledger as the high-water mark — two submissions in one ledger.
    SameLedger,
    /// At or ahead of the next ledger. A submission that rolls the clock
    /// forward is still in order.
    NextLedger,
    /// Behind the high-water mark: the submission arrived out of order and
    /// must not be replayed on top of newer state.
    OutOfOrder,
}

/// The acceptance-criteria classification of a submission that lands on
/// `landed_at` and carries a `deadline`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LedgerBoundary {
    /// Executed on the ledger it was submitted on, at or before the deadline.
    SameLedger,
    /// Executed after the submitting ledger but at or before the deadline —
    /// the "next ledger" case, including execution exactly at the deadline.
    NextLedger,
    /// Landed after the deadline: the window is closed.
    Expired,
    /// Submitted from a ledger behind the harness high-water mark.
    OutOfOrder,
}

/// Why the harness refused a ledger control call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LedgerControlError {
    /// The requested sequence is behind the current ledger. Tests must move
    /// the clock forward; a rewind is an out-of-order control call.
    Backwards { requested: u32, current: u32 },
}

/// Explicit, deterministic control over the test ledger sequence and
/// timestamp.
///
/// The harness never reads the host clock: the timestamp is always
/// `GENESIS_TIMESTAMP + (sequence - GENESIS_SEQUENCE) * SECONDS_PER_LEDGER`
/// when a sequence is set directly, and advances by [`SECONDS_PER_LEDGER`] per
/// ledger. Two runs of the same scenario therefore produce identical
/// sequences, timestamps and boundary classifications.
pub struct LedgerSequenceHarness<'a> {
    env: &'a Env,
    /// Highest ledger the harness has consumed, if any.
    high_water: Option<u32>,
}

impl<'a> LedgerSequenceHarness<'a> {
    /// Start from the genesis ledger (sequence 1) and consume it, so the
    /// high-water mark is [`GENESIS_SEQUENCE`].
    pub fn from_genesis(env: &'a Env) -> Self {
        env.ledger().set_sequence_number(GENESIS_SEQUENCE);
        env.ledger().set_timestamp(GENESIS_TIMESTAMP);
        Self {
            env,
            high_water: Some(GENESIS_SEQUENCE),
        }
    }

    /// Start from an explicit ledger, deriving the timestamp deterministically
    /// instead of reading the host clock.
    pub fn from_state(env: &'a Env, sequence: u32) -> Self {
        env.ledger().set_sequence_number(sequence);
        env.ledger().set_timestamp(timestamp_for(sequence));
        Self {
            env,
            high_water: Some(sequence),
        }
    }

    /// The current ledger sequence.
    pub fn sequence(&self) -> u32 {
        self.env.ledger().sequence()
    }

    /// The current ledger timestamp, derived from the sequence.
    pub fn timestamp(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    /// The highest ledger this harness has consumed.
    pub fn high_water(&self) -> Option<u32> {
        self.high_water
    }

    /// Move the clock forward by `ledgers` ledgers, advancing the timestamp by
    /// [`SECONDS_PER_LEDGER`] per ledger.
    ///
    /// The sequence saturates at `u32::MAX`. The timestamp is re-derived from
    /// the resulting sequence rather than accumulated, so it cannot run ahead
    /// of the ledger when the sequence stops advancing.
    pub fn advance(&mut self, ledgers: u32) {
        let next = self.sequence().saturating_add(ledgers);
        self.env.ledger().set_sequence_number(next);
        self.env.ledger().set_timestamp(timestamp_for(next));
        self.consume(next);
    }

    /// Jump to an absolute ledger. Forward-only: rewinding is refused so a
    /// test cannot accidentally observe an older ledger after a newer one.
    pub fn at(&mut self, sequence: u32) -> Result<(), LedgerControlError> {
        let current = self.sequence();
        if sequence < current {
            return Err(LedgerControlError::Backwards {
                requested: sequence,
                current,
            });
        }
        self.env.ledger().set_sequence_number(sequence);
        self.env.ledger().set_timestamp(timestamp_for(sequence));
        self.consume(sequence);
        Ok(())
    }

    /// Sequence reached `delay_ledgers` after the current ledger — the
    /// deadline/expiry ledger a test usually asserts on.
    pub fn deadline(&self, delay_ledgers: u32) -> u32 {
        self.sequence().saturating_add(delay_ledgers)
    }

    /// Order of a submission stamped at `submitted_at` relative to the
    /// high-water mark.
    pub fn order_of(&self, submitted_at: u32) -> LedgerOrder {
        match self.high_water {
            Some(high) if submitted_at < high => LedgerOrder::OutOfOrder,
            Some(high) if submitted_at == high => LedgerOrder::SameLedger,
            _ => LedgerOrder::NextLedger,
        }
    }

    /// Classify a submission against a deadline.
    ///
    /// `submitted_at` is the ledger the submission was created on, `landed_at`
    /// the ledger it executed on, and `deadline` the expiry/due ledger it must
    /// respect.
    ///
    /// A submission that lands on a ledger behind its own stamp is out of
    /// order — it was composed for a newer ledger than the one it executed on,
    /// which a live chain cannot produce and a test must never manufacture.
    /// Staleness of the *stamp* itself (a submission that arrives after the
    /// ledger the harness already consumed) is reported separately by
    /// [`Self::order_of`], because only the caller knows when the submission
    /// was composed.
    pub fn classify(&self, submitted_at: u32, landed_at: u32, deadline: u32) -> LedgerBoundary {
        if landed_at < submitted_at {
            return LedgerBoundary::OutOfOrder;
        }
        if landed_at > deadline {
            return LedgerBoundary::Expired;
        }
        if landed_at == submitted_at {
            LedgerBoundary::SameLedger
        } else {
            LedgerBoundary::NextLedger
        }
    }

    fn consume(&mut self, sequence: u32) {
        self.high_water = Some(match self.high_water {
            Some(high) if high > sequence => high,
            _ => sequence,
        });
    }
}

/// Deterministic timestamp for an absolute ledger sequence.
fn timestamp_for(sequence: u32) -> u64 {
    GENESIS_TIMESTAMP
        + (sequence.saturating_sub(GENESIS_SEQUENCE) as u64).saturating_mul(SECONDS_PER_LEDGER)
}
