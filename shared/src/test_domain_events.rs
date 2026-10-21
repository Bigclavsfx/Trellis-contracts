//! Schema-compatibility tests for versioned domain events (Issue #337).
//!
//! `docs/EVENT_SCHEMAS.md` makes promises that consumers depend on, and these
//! tests pin each one:
//!
//! * a published event carries `(name, version)` as its topic, so a consumer
//!   subscribed to one version never receives another,
//! * a payload that does not match its schema is never emitted, including on
//!   a retry that still fails validation,
//! * schema drift (a renamed field, a new field, version `0`) is rejected
//!   rather than emitted with guessed semantics,
//! * a consumer falls back only to the newest version that is no newer than
//!   the producer's, and never guesses forward.
//!
//! Event publication has no caller auth of its own. Authorization is enforced
//! by the contract entry point before it calls [`publish_event`], so it is out
//! of scope here.

use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Events as _, Env, IntoVal, Map, Symbol,
    TryFromVal, Val, Vec,
};

use crate::domain_events::{
    consumer_version, publish_event, validate_event, DomainEvent, EventSchema, EventValidationError,
};

#[contract]
struct DummyEventContract;

#[contractimpl]
impl DummyEventContract {}

/// Version 1 of the `payment` event: `amount` and `actor`.
fn schema_v1(env: &Env) -> EventSchema {
    let mut required_fields = Vec::new(env);
    required_fields.push_back(symbol_short!("amount"));
    required_fields.push_back(symbol_short!("actor"));
    EventSchema {
        name: symbol_short!("payment"),
        version: 1,
        required_fields,
    }
}

/// Version 2 adds `memo`. Adding a field is a new version, never an in-place
/// change to version 1.
fn schema_v2(env: &Env) -> EventSchema {
    let mut required_fields = Vec::new(env);
    required_fields.push_back(symbol_short!("amount"));
    required_fields.push_back(symbol_short!("actor"));
    required_fields.push_back(symbol_short!("memo"));
    EventSchema {
        name: symbol_short!("payment"),
        version: 2,
        required_fields,
    }
}

/// A payload that satisfies [`schema_v1`].
fn payload_v1(env: &Env) -> Map<Symbol, Val> {
    let mut payload = Map::new(env);
    payload.set(symbol_short!("amount"), 10_i128.into_val(env));
    payload.set(symbol_short!("actor"), 1_u32.into_val(env));
    payload
}

/// A payload that satisfies [`schema_v2`].
fn payload_v2(env: &Env) -> Map<Symbol, Val> {
    let mut payload = payload_v1(env);
    payload.set(symbol_short!("memo"), symbol_short!("thanks").into_val(env));
    payload
}

#[test]
fn published_event_uses_name_and_version_as_its_topic() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyEventContract);
    let schema = schema_v1(&env);

    env.as_contract(&contract_id, || {
        publish_event(&env, &schema, payload_v1(&env)).unwrap();
    });

    let events = env.events().all();
    assert_eq!(events.len(), 1);

    let (emitter, topics, data) = events.get(0).unwrap();
    assert_eq!(emitter, contract_id);
    assert_eq!(topics, (symbol_short!("payment"), 1_u32).into_val(&env));

    let decoded = DomainEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(decoded.name, symbol_short!("payment"));
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.payload, payload_v1(&env));
}

#[test]
fn a_consumer_on_one_version_never_sees_another_versions_events() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyEventContract);
    let v1 = schema_v1(&env);
    let v2 = schema_v2(&env);

    env.as_contract(&contract_id, || {
        publish_event(&env, &v1, payload_v1(&env)).unwrap();
        publish_event(&env, &v2, payload_v2(&env)).unwrap();
    });

    let events = env.events().all();
    assert_eq!(events.len(), 2);

    let (_, v1_topics, _) = events.get(0).unwrap();
    let (_, v2_topics, _) = events.get(1).unwrap();
    assert_eq!(v1_topics, (symbol_short!("payment"), 1_u32).into_val(&env));
    assert_eq!(v2_topics, (symbol_short!("payment"), 2_u32).into_val(&env));
    assert_ne!(v1_topics, v2_topics);
}

#[test]
fn a_payload_missing_a_required_field_is_not_emitted() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyEventContract);
    let schema = schema_v1(&env);

    let mut missing = Map::new(&env);
    missing.set(symbol_short!("amount"), 10_i128.into_val(&env));

    let result = env.as_contract(&contract_id, || publish_event(&env, &schema, missing));

    assert_eq!(result, Err(EventValidationError::MissingRequiredField));
    assert_eq!(
        env.events().all().len(),
        0,
        "a rejected event must not be emitted"
    );
}

#[test]
fn a_retry_with_a_corrected_payload_emits_exactly_once() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyEventContract);
    let schema = schema_v1(&env);

    let mut bad = Map::new(&env);
    bad.set(symbol_short!("amount"), 10_i128.into_val(&env));
    let first = env.as_contract(&contract_id, || publish_event(&env, &schema, bad));
    assert_eq!(first, Err(EventValidationError::MissingRequiredField));
    assert_eq!(env.events().all().len(), 0);

    let retry = env.as_contract(&contract_id, || {
        publish_event(&env, &schema, payload_v1(&env))
    });
    assert_eq!(retry, Ok(()));
    assert_eq!(
        env.events().all().len(),
        1,
        "the successful retry emits once"
    );
}

#[test]
fn a_renamed_field_is_schema_drift_and_is_rejected() {
    // Producer renamed `recipient` to `destination`. The consumer's schema still
    // requires `recipient`, so the payload must be refused, not reinterpreted.
    let env = Env::default();
    let mut required_fields = Vec::new(&env);
    required_fields.push_back(symbol_short!("amount"));
    required_fields.push_back(symbol_short!("recipient"));
    let schema = EventSchema {
        name: symbol_short!("payout"),
        version: 1,
        required_fields,
    };

    let mut drifted = Map::new(&env);
    drifted.set(symbol_short!("amount"), 10_i128.into_val(&env));
    drifted.set(Symbol::new(&env, "destination"), 1_u32.into_val(&env));

    assert_eq!(
        validate_event(&schema, &drifted),
        Err(EventValidationError::MissingRequiredField)
    );
}

#[test]
fn an_extra_field_is_rejected_as_an_undocumented_field() {
    let env = Env::default();
    let schema = schema_v1(&env);

    let mut extra = payload_v1(&env);
    extra.set(
        symbol_short!("memo"),
        symbol_short!("thanks").into_val(&env),
    );

    assert_eq!(
        validate_event(&schema, &extra),
        Err(EventValidationError::UnknownField)
    );
}

#[test]
fn adding_a_field_requires_a_new_version_in_both_directions() {
    let env = Env::default();
    let v1 = schema_v1(&env);
    let v2 = schema_v2(&env);

    // A v2 payload is not valid under v1: the new field is undocumented there.
    assert_eq!(
        validate_event(&v1, &payload_v2(&env)),
        Err(EventValidationError::UnknownField)
    );
    // A v1 payload is not valid under v2: the new field is required there.
    assert_eq!(
        validate_event(&v2, &payload_v1(&env)),
        Err(EventValidationError::MissingRequiredField)
    );
    // Each payload validates under its own version.
    assert_eq!(validate_event(&v1, &payload_v1(&env)), Ok(()));
    assert_eq!(validate_event(&v2, &payload_v2(&env)), Ok(()));
}

#[test]
fn version_zero_is_never_emitted() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyEventContract);
    let mut schema = schema_v1(&env);
    schema.version = 0;

    let result = env.as_contract(&contract_id, || {
        publish_event(&env, &schema, payload_v1(&env))
    });

    assert_eq!(result, Err(EventValidationError::UnsupportedVersion));
    assert_eq!(env.events().all().len(), 0);
}

#[test]
fn consumer_falls_back_to_the_newest_version_not_newer_than_the_producer() {
    let env = Env::default();
    let supported = soroban_sdk::vec![&env, 1_u32, 2_u32, 4_u32];

    assert_eq!(consumer_version(3, &supported), Some(2));
    assert_eq!(consumer_version(4, &supported), Some(4));
    assert_eq!(consumer_version(5, &supported), Some(4));
}

#[test]
fn consumer_never_guesses_forward_to_a_newer_version() {
    let env = Env::default();

    // Every supported version is newer than the producer: nothing is decodable.
    assert_eq!(consumer_version(2, &soroban_sdk::vec![&env, 3_u32]), None);
    assert_eq!(
        consumer_version(1, &soroban_sdk::vec![&env, 2_u32, 3_u32]),
        None
    );
    // An unversioned producer (0) has no decodable version either.
    assert_eq!(consumer_version(0, &soroban_sdk::vec![&env, 1_u32]), None);
    // A consumer that supports nothing decodes nothing.
    assert_eq!(consumer_version(7, &Vec::<u32>::new(&env)), None);
}

#[test]
fn fallback_version_decodes_with_its_own_schema_only() {
    // The consumer picks v1 for a v2 producer. It must validate with the v1
    // schema, not the v2 one.
    let env = Env::default();
    let chosen = consumer_version(2, &soroban_sdk::vec![&env, 1_u32]).unwrap();
    assert_eq!(chosen, 1);

    let v1 = schema_v1(&env);
    assert_eq!(validate_event(&v1, &payload_v1(&env)), Ok(()));
    // The v2-only field is not part of the v1 contract, so it is not accepted.
    assert_eq!(
        validate_event(&v1, &payload_v2(&env)),
        Err(EventValidationError::UnknownField)
    );
}

#[test]
fn event_data_round_trips_through_the_domain_event_type() {
    let env = Env::default();
    let contract_id = env.register_contract(None, DummyEventContract);
    let schema = schema_v2(&env);

    env.as_contract(&contract_id, || {
        publish_event(&env, &schema, payload_v2(&env)).unwrap();
    });

    let events = env.events().all();
    let (_, _, data) = events.get(0).unwrap();
    let decoded = DomainEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.payload, payload_v2(&env));
}
