# Workflow Correlation IDs (Issue #330)

A workflow such as "fund aid, claim, then settle" spans several contracts, and
each contract emits its own events. A **workflow correlation ID** is a shared
identifier that every step of the workflow carries, so an indexer can join those
events back into one workflow.

The policy lives in [`shared::workflow_correlation`](../shared/src/workflow_correlation.rs).
It is pure: it reads no storage and checks no caller.

## Policy

| Rule | Value |
|---|---|
| Non-empty | required |
| Maximum length | `MAX_WORKFLOW_ID_LEN` = 64 bytes |
| Allowed bytes | ASCII letters, digits, `-`, `_` |
| Error on violation | `shared::Error::InvalidArgument` |

Two functions enforce it:

- `validate_workflow_id(&Bytes)` checks one ID.
- `check_workflow_chain(&Vec<Bytes>)` checks that every step carries the same
  valid ID and returns it. An empty chain fails.

## Normal, retry, and failure paths

| Scenario | Result |
|---|---|
| Every step of a workflow uses one ID | Accepted; the ID is returned |
| A step is retried and reuses the ID | Accepted (retries are idempotent for correlation) |
| Two different IDs appear in one chain | Rejected with `InvalidArgument` |
| One step's ID is malformed, even if the others match | Rejected |
| Empty chain | Rejected |

## Operational edge cases

- **Mixed IDs across a retry.** A client that generates a fresh ID on retry
  splits one workflow into two. The chain check then rejects it. Generate the ID
  once when the workflow starts and reuse it for every retry.
- **Length boundary.** A 64-byte ID is accepted; a 65-byte ID is rejected. Keep
  IDs short, for example a UUID without dashes (32 hex characters) plus a
  prefix.
- **Spaces and separators.** `.`, `:`, `/`, and spaces are rejected. Use `-` or
  `_` as separators.

## Authorization

The policy does not authorize callers. A contract that accepts a correlation ID
must still check the caller before it emits events under that ID. Correlation
IDs are labels, not credentials: anyone who knows an ID can reuse it, so never
treat one as proof that a workflow was authorized.

## Recovery

A rejected chain changes no state, because the check runs before any write. To
recover, find the step whose ID differs from the rest of the chain, correct it
to the workflow's original ID, and retry that step. No rollback is required.

## Compatibility

This is an additive shared helper. Existing per-record correlation in
`contracts/aid-contract/src/correlation.rs` is unchanged and keeps its lenient
behavior.
