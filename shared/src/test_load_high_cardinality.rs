#![cfg(test)]

//! Load tests for high-cardinality workflows (Issue #353).
//!
//! Each test drives one protection under volume: label admission, redaction,
//! telemetry sampling, and paginated scans over large id sets. Volumes are
//! fixed so runs are reproducible; the budget is lifted so the tests exercise
//! the logic rather than the host's default instruction limit.

extern crate std;

use std::format;

use soroban_sdk::{
    contract, contractimpl,
    testutils::Events as _,
    Bytes, Env, Vec,
};

use crate::errors::Error;
use crate::pagination::{
    paginate_id_list, Direction, PageRequest, PageResponse, DEFAULT_MAX_SCAN, MAX_PAGE_LIMIT,
};
use crate::sanitize::{
    redact_telemetry_value, sanitize_telemetry_label, should_sample, MAX_TELEMETRY_LABEL_LEN,
    REDACTED_TOKEN,
};
use crate::telemetry::{
    publish_protected, ActorType, TelemetryEvent, TelemetryResult, OP_PAYMENT_TRANSFER,
    SAMPLE_DENOMINATOR,
};

const HIGH_CARDINALITY_KEYS: u32 = 1_000;
const LABEL_VALUES: u32 = 1_000;
const TELEMETRY_EVENTS: u64 = 4_096;
const PAGINATION_IDS: u64 = 10_000;

const SECRET: &str = "SCZANGBA5YHTNYVS3ZSXQ7KFUNXAGMGKSSLTPJHLAOBQEVKUYNNVPFH";

#[contract]
pub struct LoadHarness;

#[contractimpl]
impl LoadHarness {
    pub fn noop(_env: Env) {}
}

// ---------------------------------------------------------------------------
// Label admission
// ---------------------------------------------------------------------------

#[test]
fn high_cardinality_keys_are_all_dropped_under_load() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let address = Bytes::from_slice(&env, b"GABC1234567890");

    let mut dropped = 0u32;
    for i in 0..HIGH_CARDINALITY_KEYS {
        let key = Bytes::from_slice(&env, format!("wallet_{i}").as_bytes());
        match sanitize_telemetry_label(&env, &key, &address, 0) {
            Err(Error::InvalidArgument) => dropped += 1,
            other => panic!("key wallet_{i} must be dropped, got {other:?}"),
        }
    }
    assert_eq!(dropped, HIGH_CARDINALITY_KEYS);
}

#[test]
fn bounded_values_are_admitted_only_within_the_length_budget() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let key = Bytes::from_slice(&env, b"status");

    let mut admitted = 0u32;
    let mut rejected = 0u32;
    for i in 0..LABEL_VALUES {
        // Every tenth value is oversized to exercise the length guard.
        let raw = if i % 10 == 9 {
            "x".repeat(MAX_TELEMETRY_LABEL_LEN as usize + 1)
        } else {
            format!("status-{i}")
        };
        let value = Bytes::from_slice(&env, raw.as_bytes());
        match sanitize_telemetry_label(&env, &key, &value, 0) {
            Ok(safe) => {
                assert_eq!(safe, value);
                admitted += 1;
            }
            Err(Error::InvalidArgument) => rejected += 1,
            Err(other) => panic!("value {i}: unexpected error {other:?}"),
        }
    }
    assert_eq!(rejected, LABEL_VALUES / 10);
    assert_eq!(admitted, LABEL_VALUES - LABEL_VALUES / 10);
}

#[test]
fn sensitive_values_never_pass_through_under_load() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let secret = Bytes::from_slice(&env, SECRET.as_bytes());
    let token = Bytes::from_slice(&env, REDACTED_TOKEN);

    for i in 0..LABEL_VALUES {
        // Retries of the same input must produce the same redacted output.
        let key = Bytes::from_slice(&env, format!("api_secret_{i}").as_bytes());
        for _ in 0..2 {
            assert_eq!(
                redact_telemetry_value(&env, &key, &secret),
                Ok(token.clone()),
                "api_secret_{i} leaked its value"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

#[test]
fn sampling_keeps_exactly_one_in_rate_over_a_large_entropy_range() {
    let rate = 100_u32;
    let range = 100_000_u64;
    let emitted = (0..range)
        .filter(|entropy| should_sample(*entropy, rate))
        .count() as u64;
    assert_eq!(emitted, range.div_ceil(rate as u64));
    assert!(should_sample(0, rate));
    assert!(!should_sample(1, rate));
}

#[test]
fn telemetry_emits_only_sampled_events_under_load() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let contract_id = env.register_contract(None, LoadHarness);

    env.as_contract(&contract_id, || {
        for correlation_id in 0..TELEMETRY_EVENTS {
            publish_protected(
                &env,
                &TelemetryEvent {
                    operation: OP_PAYMENT_TRANSFER,
                    actor: ActorType::User,
                    result: TelemetryResult::Success,
                    latency_ledgers: 1,
                    correlation_id,
                },
            );
        }
    });

    // One event survives per SAMPLE_DENOMINATOR correlation ids, so the count
    // is fixed by the volume rather than by timing or randomness.
    let expected = TELEMETRY_EVENTS.div_ceil(SAMPLE_DENOMINATOR as u64);
    assert_eq!(env.events().all().len() as u64, expected);
}

// ---------------------------------------------------------------------------
// Paginated scans over large id sets
// ---------------------------------------------------------------------------

fn sparse_ids(env: &Env) -> Vec<u64> {
    let mut ids: Vec<u64> = Vec::new(env);
    for i in 0..PAGINATION_IDS {
        ids.push_back(i * 3 + 7);
    }
    ids
}

#[test]
fn pagination_visits_every_id_exactly_once_in_order() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let ids = sparse_ids(&env);

    let mut visited = 0u64;
    let mut previous: Option<u64> = None;
    let mut cursor: Option<u64> = None;
    let mut pages = 0u32;
    loop {
        let request = PageRequest {
            cursor,
            limit: MAX_PAGE_LIMIT,
            direction: Direction::Ascending,
        };
        let page: PageResponse<u64> =
            paginate_id_list(&env, &ids, &request, DEFAULT_MAX_SCAN, |id| Some(id)).unwrap();
        pages += 1;

        for i in 0..page.items.len() {
            let id = page.items.get(i).unwrap();
            if let Some(prev) = previous {
                assert!(id > prev, "ids must be strictly ascending: {prev} then {id}");
            }
            previous = Some(id);
            visited += 1;
        }

        if !page.has_more {
            assert!(page.next_cursor.is_none());
            break;
        }
        assert!(page.next_cursor.is_some(), "a page with more results needs a cursor");
        cursor = page.next_cursor;
        assert!(pages <= PAGINATION_IDS as u32, "pagination must terminate");
    }

    assert_eq!(visited, PAGINATION_IDS);
    assert_eq!(pages as u64, PAGINATION_IDS.div_ceil(MAX_PAGE_LIMIT as u64));
}

#[test]
fn pagination_past_the_last_id_returns_an_empty_page() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let ids = sparse_ids(&env);
    let last = ids.get(ids.len() - 1).unwrap();

    let request = PageRequest {
        cursor: Some(last),
        limit: MAX_PAGE_LIMIT,
        direction: Direction::Ascending,
    };
    let page: PageResponse<u64> =
        paginate_id_list(&env, &ids, &request, DEFAULT_MAX_SCAN, |id| Some(id)).unwrap();
    assert_eq!(page.items.len(), 0);
    assert!(!page.has_more);
    assert!(page.next_cursor.is_none());
}

#[test]
fn repeated_page_requests_return_identical_results() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let ids = sparse_ids(&env);
    let request = PageRequest {
        cursor: Some(1_000),
        limit: MAX_PAGE_LIMIT,
        direction: Direction::Ascending,
    };

    let first: PageResponse<u64> =
        paginate_id_list(&env, &ids, &request, DEFAULT_MAX_SCAN, |id| Some(id)).unwrap();
    for _ in 0..2 {
        let retry: PageResponse<u64> =
            paginate_id_list(&env, &ids, &request, DEFAULT_MAX_SCAN, |id| Some(id)).unwrap();
        assert_eq!(retry.items, first.items);
        assert_eq!(retry.next_cursor, first.next_cursor);
        assert_eq!(retry.has_more, first.has_more);
    }
}
