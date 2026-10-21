# Cross-Repo Client Request Validation

`shared::client_validation` (Issue #336) validates the request envelopes
`shared::client` defines for SDK/API-server integrations, checks the
authenticated caller against the request's claimed identity, and gives a
flaky cross-repo client a safe retry path — without changing
`shared::client`, `shared::semantic`, or `shared::idempotency`.

## The gap this closes

`shared::client`'s `CreateAidRequest`, `CreateEscrowRequest`,
`CreateProposalRequest`, `CreateListingRequest`, and `RebalanceRequest` are
typed envelopes with a schema fingerprint, but nothing:

- rejects a request tagged with a schema version this contract doesn't
  understand,
- checks field bounds (amounts, expiries, slippage) before a contract acts
  on the request,
- confirms the authenticated caller is actually the party the request
  claims to be acting as, or
- protects against the same logical request being resubmitted after a
  client-side timeout.

## Design in one paragraph

Each `validate_*_request` function runs three checks in order: schema
compatibility (`ensure_supported_client_schema_version`, the same
bounded-range pattern `shared::canonical`/`shared::export` use for their own
versions), field semantics (reusing `shared::semantic::validate_amount` /
`validate_distinct_parties` / `validate_future_expiry` rather than
duplicating bounds logic), and authorization (where the request names an
acting party — `donor`, `depositor`, `seller` — the caller must equal it
before `Address::require_auth` runs). Separately, `fingerprint_request` is a
generic, domain-separated digest of any `#[contracttype]` request, and
`begin_idempotent_request` / `complete_idempotent_request` wrap
`shared::idempotency::begin` / `::complete` around it, so a client that
resends the same call under the same idempotency key gets the prior result
instead of a repeated side effect.

## Public surface

| Item | Purpose |
|---|---|
| `ensure_supported_client_schema_version` | Schema-version gate shared by every validator. |
| `validate_create_aid_request` / `validate_create_escrow_request` / `validate_create_listing_request` | Schema + field + identity-matching authorization checks. |
| `validate_create_proposal_request` / `validate_rebalance_request` | Schema + field checks; authentication only (no identity field exists on these requests — see below). |
| `fingerprint_request` | Generic, tagged fingerprint of any `#[contracttype]` request. |
| `begin_idempotent_request` / `complete_idempotent_request` | Retry-safe wrapper around `shared::idempotency`, keyed by `fingerprint_request`. |

## Who can do what

| Action | Required condition |
|---|---|
| Validate a `CreateAidRequest` / `CreateEscrowRequest` / `CreateListingRequest` | Caller must equal the request's `donor` / `depositor` / `seller` and authenticate |
| Validate a `CreateProposalRequest` / `RebalanceRequest` | Caller must authenticate; *which* callers may act is the governance/treasury contract's own permission check, since neither request carries an acting-party field |
| Begin/complete an idempotent request | Anyone — the idempotency key itself is the access boundary, scoped by whatever authorization the matching `validate_*_request` already enforced |

## Operational edge cases

| Situation | Behavior |
|---|---|
| `schema_version` outside `[MIN_SUPPORTED_CLIENT_SCHEMA_VERSION, MAX_SUPPORTED_CLIENT_SCHEMA_VERSION]` | `Error::UnsupportedSchemaVersion`, checked before any field is read. |
| Request party field does not match the authenticated caller | `Error::Unauthorized`, before `require_auth` runs. |
| Amount/price is zero, negative, or outside the documented rule | `Error::InvalidAmount` or `Error::InvalidArgument`. |
| Two parties that must differ are the same address | `Error::InvalidArgument`. |
| `expiry_ledger` is not far enough (or too far) in the future | `Error::InvalidArgument`. |
| `RebalanceRequest.max_slippage_bps > 10_000` | `Error::PaymentInvalidFeeRate` — the same basis-point bound payments already enforce. |
| `RebalanceRequest.asset_in == asset_out` | `Error::InvalidArgument`. |
| Idempotency key reused for the *same* request after it already completed | `begin_idempotent_request` returns `Ok(Some(record))` with the prior result; the caller must not repeat side effects. |
| Idempotency key reused for a *different* request, or malformed | `Error::InvalidArgument`, surfaced before any state changes. |
| Idempotency key still mid-flight, or `complete_idempotent_request` called twice | `Error::AlreadyClaimed`. |

## Rollback and recovery

This module writes nothing persistent beyond what `shared::idempotency`
already does (a temporary, TTL-bounded record per key):

1. **A client retried after a genuine failure** that never reached
   `complete_idempotent_request`: the key's record stays pending until its
   TTL lapses, after which a fresh submission under that key is treated as
   new. Choose a shorter `ttl_ledgers` for faster recovery than the default.
2. **Schema drift between an SDK and this contract**: bump
   `shared::client::CLIENT_SCHEMA_VERSION` and
   `MAX_SUPPORTED_CLIENT_SCHEMA_VERSION` together, and keep
   `MIN_SUPPORTED_CLIENT_SCHEMA_VERSION` at the oldest version still
   accepted — the same migration shape `shared::canonical` documents for its
   own encoding version.
3. **A validation rule was too strict or too loose**: the rules are plain
   constants evaluated fresh on every call; changing them takes effect on
   the very next request, since nothing validated here is itself persisted.

## Compatibility

Purely additive: no changes to `shared::client`'s request/response types,
`shared::semantic`, `shared::idempotency`, or any contract interface. A
contract adopts this by calling the matching `validate_*_request` (and,
where retries matter, the idempotency wrappers) before acting on a
cross-repo request.
