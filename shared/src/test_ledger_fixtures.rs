//! Deterministic fixtures for ledger-sequence edge cases (Issue #335).
//!
//! [`crate::test_ledger_sequence`] covers the four acceptance-criteria
//! scenarios through the contract logic. This module pins the harness itself
//! at its numeric edges, using literal expected values so a failure names the
//! row and a reviewer can check it by hand:
//!
//! * the genesis ledger and the first advance,
//! * the `u32::MAX` ceiling, where the sequence saturates,
//! * rewinds, which must be refused without moving the clock,
//! * classification at the deadline, one past it, and out of order.
//!
//! `docs/LEDGER_ASSUMPTIONS.md` ("Edge-case fixtures") records the recovery
//! guidance for each row.

use soroban_sdk::Env;

use crate::ledger_sequence::{
    LedgerBoundary, LedgerControlError, LedgerOrder, LedgerSequenceHarness,
};

/// Timestamp of ledger 1: `GENESIS_TIMESTAMP`.
const GENESIS_TS: u64 = 1_640_995_200;

/// Timestamp of ledger `u32::MAX`: `GENESIS_TS + (u32::MAX - 1) * 5`.
const CEILING_TS: u64 = 23_115_831_670;

/// `(start sequence, ledgers to advance, expected sequence, expected timestamp)`
const ADVANCE_FIXTURES: [(u32, u32, u32, u64); 6] = [
    // Advancing by zero is a no-op.
    (1, 0, 1, GENESIS_TS),
    // The first real ledger after genesis moves the timestamp by 5 s.
    (1, 1, 2, 1_640_995_205),
    // An ordinary mid-range advance.
    (1_000, 1, 1_001, 1_641_000_200),
    // Reaching the ceiling exactly.
    (u32::MAX - 1, 1, u32::MAX, CEILING_TS),
    // Overshooting the ceiling: the sequence saturates and the timestamp must
    // stay at the ceiling value rather than running on by 20 s.
    (u32::MAX - 1, 5, u32::MAX, CEILING_TS),
    // Already at the ceiling: nothing moves.
    (u32::MAX, 1, u32::MAX, CEILING_TS),
];

/// `(submitted_at, landed_at, deadline, expected boundary)`
const BOUNDARY_FIXTURES: [(u32, u32, u32, LedgerBoundary); 7] = [
    // Executed on the submitting ledger, deadline equal to it.
    (100, 100, 100, LedgerBoundary::SameLedger),
    // Executed on the submitting ledger with room to spare.
    (100, 100, 101, LedgerBoundary::SameLedger),
    // Executed one ledger later, exactly at the deadline: still allowed.
    (100, 101, 101, LedgerBoundary::NextLedger),
    // Executed one ledger past the deadline: closed.
    (100, 102, 101, LedgerBoundary::Expired),
    // Landed behind its own stamp, deadline still open: out of order.
    (100, 99, 200, LedgerBoundary::OutOfOrder),
    // Out of order takes precedence over expired.
    (100, 99, 98, LedgerBoundary::OutOfOrder),
    // The ceiling itself: same-ledger, deadline equal to the ledger.
    (u32::MAX, u32::MAX, u32::MAX, LedgerBoundary::SameLedger),
];

#[test]
fn advance_fixtures_keep_the_timestamp_derived_from_the_sequence() {
    for (start, ledgers, expected_sequence, expected_timestamp) in ADVANCE_FIXTURES {
        let env = Env::default();
        let mut ledger = LedgerSequenceHarness::from_state(&env, start);

        ledger.advance(ledgers);

        assert_eq!(
            ledger.sequence(),
            expected_sequence,
            "sequence after advancing {start} by {ledgers}"
        );
        assert_eq!(
            ledger.timestamp(),
            expected_timestamp,
            "timestamp after advancing {start} by {ledgers}"
        );
    }
}

#[test]
fn boundary_fixtures_classify_each_edge() {
    let env = Env::default();
    let ledger = LedgerSequenceHarness::from_genesis(&env);

    for (submitted, landed, deadline, expected) in BOUNDARY_FIXTURES {
        assert_eq!(
            ledger.classify(submitted, landed, deadline),
            expected,
            "classify(submitted={submitted}, landed={landed}, deadline={deadline})"
        );
    }
}

#[test]
fn order_fixtures_compare_stamps_against_the_high_water_mark() {
    let env = Env::default();
    let mut ledger = LedgerSequenceHarness::from_state(&env, 500);

    assert_eq!(ledger.order_of(499), LedgerOrder::OutOfOrder);
    assert_eq!(ledger.order_of(500), LedgerOrder::SameLedger);
    assert_eq!(ledger.order_of(501), LedgerOrder::NextLedger);

    ledger.advance(10);

    assert_eq!(ledger.high_water(), Some(510));
    assert_eq!(ledger.order_of(500), LedgerOrder::OutOfOrder);
    assert_eq!(ledger.order_of(510), LedgerOrder::SameLedger);
}

#[test]
fn rewind_is_refused_at_the_ceiling_and_leaves_the_clock_untouched() {
    let env = Env::default();
    let mut ledger = LedgerSequenceHarness::from_state(&env, u32::MAX - 1);

    assert_eq!(
        ledger.at(u32::MAX - 1),
        Ok(()),
        "same ledger is not a rewind"
    );
    assert_eq!(ledger.at(u32::MAX), Ok(()));
    assert_eq!(
        ledger.at(u32::MAX - 1),
        Err(LedgerControlError::Backwards {
            requested: u32::MAX - 1,
            current: u32::MAX,
        })
    );
    assert_eq!(ledger.sequence(), u32::MAX);
    assert_eq!(ledger.timestamp(), CEILING_TS);
}

#[test]
fn deadline_saturates_at_the_ceiling_instead_of_wrapping() {
    let env = Env::default();
    let ledger = LedgerSequenceHarness::from_state(&env, u32::MAX - 2);

    // A deadline past the ceiling clamps to it. It equals the current ledger
    // here, so a contract that requires `expiry > current` rejects it.
    assert_eq!(ledger.deadline(10), u32::MAX);
    assert_eq!(
        ledger.classify(u32::MAX - 2, u32::MAX - 2, ledger.deadline(10)),
        LedgerBoundary::SameLedger
    );
}
