# Versioned domain events

Trellis domain events are public contract data. Producers should publish a
`DomainEvent` with an explicit `name` and non-zero `version`, and validate the
payload against an `EventSchema` before emitting it. Required fields form the
schema allow-list: a missing required field or an undocumented field is
rejected before publication.

Consumers advertise the versions they can decode. The compatibility rule is
to use the newest supported version that is no newer than the producer's
version. If no such version exists, the event must be rejected or routed to a
dead-letter/review path; consumers must not guess from payload shape.

Adding an optional field requires a new schema version and a decoder fallback.
Removing or changing the meaning of a field requires a new event name or a
major version. Existing consumers remain compatible because the producer's
version is carried in the event topics and payload.

The helpers and focused tests live in `shared::domain_events`.

## Compatibility tests (Issue #337)

`shared/src/test_domain_events.rs` pins each promise above against the real
`publish_event`, `validate_event` and `consumer_version` functions.

| Promise | Test |
| --- | --- |
| The topic is `(name, version)`, so one version's consumers never see another's events. | `published_event_uses_name_and_version_as_its_topic`, `a_consumer_on_one_version_never_sees_another_versions_events` |
| A payload that fails its schema is never emitted. | `a_payload_missing_a_required_field_is_not_emitted` |
| A retry after a rejected payload emits exactly once, once the payload is valid. | `a_retry_with_a_corrected_payload_emits_exactly_once` |
| A renamed field is schema drift and is refused, not reinterpreted. | `a_renamed_field_is_schema_drift_and_is_rejected` |
| An undocumented field is refused. | `an_extra_field_is_rejected_as_an_undocumented_field` |
| Adding a field is a new version, in both directions. | `adding_a_field_requires_a_new_version_in_both_directions` |
| Version `0` is never emitted. | `version_zero_is_never_emitted` |
| A consumer falls back to the newest version not newer than the producer. | `consumer_falls_back_to_the_newest_version_not_newer_than_the_producer` |
| A consumer never guesses forward, and an empty support list decodes nothing. | `consumer_never_guesses_forward_to_a_newer_version` |
| A fallback version validates with its own schema only. | `fallback_version_decodes_with_its_own_schema_only` |
| Emitted data decodes back to the `DomainEvent` envelope. | `event_data_round_trips_through_the_domain_event_type` |

**Operational edge cases.** A rejected publish emits nothing, so an operator who
sees a missing event should check the producer's validation error before
assuming the event was lost. A consumer that receives a version newer than it
supports must route the event to dead-letter or review, as the rule above
requires. It must not decode it with a guessed schema.

**Authorization.** Event publication does not check the caller. The contract
entry point that calls `publish_event` enforces authorization before it
publishes, so these tests do not cover it.

**Rollback.** The tests are test-only and change no emitted event. Reverting the
commit removes the tests and leaves every published event unchanged.
