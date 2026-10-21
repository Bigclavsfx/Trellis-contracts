//! Request validation for cross-repo Trellis clients (Issue #336).
//!
//! `shared::client` defines the typed request/response envelopes an SDK or
//! API server uses to talk to these contracts, plus a schema fingerprint —
//! but nothing validates an incoming request against that schema, checks
//! that its claimed identity matches the authenticated caller, or protects
//! a contract from a flaky client retrying the same call twice. This module
//! adds all three without changing `shared::client`, `shared::semantic`, or
//! `shared::idempotency`.
//!
//! ## Design
//!
//! - **Schema compatibility.** [`ensure_supported_client_schema_version`]
//!   rejects a request tagged with a schema version this build does not
//!   understand, the same bounded-range pattern `shared::canonical` and
//!   `shared::export` already use for their own schema versions.
//! - **Field validation.** Each `validate_*_request` function reuses
//!   `shared::semantic`'s generic rules (`validate_amount`,
//!   `validate_distinct_parties`, `validate_future_expiry`) instead of
//!   duplicating bounds-checking logic per request type.
//! - **Authorization.** Where a request carries a field naming the party
//!   acting (`donor`, `depositor`, `seller`), the matching `validate_*`
//!   function requires the authenticated `caller` to equal it before calling
//!   `Address::require_auth` — an API server cannot submit a request on
//!   behalf of an address it does not control. `CreateProposalRequest` and
//!   `RebalanceRequest` carry no such field; those functions still require
//!   the caller to authenticate, and leave which caller is actually allowed
//!   (role/permission checks) to the contract entry point that wires them
//!   in, since that is domain-specific, not a cross-repo concern.
//! - **Retry.** [`begin_idempotent_request`] / [`complete_idempotent_request`]
//!   wrap `shared::idempotency::begin` / `::complete` with a generic request
//!   fingerprint ([`fingerprint_request`]), so a client that resends the
//!   same logical request under the same idempotency key is told the prior
//!   outcome instead of repeating the operation's side effects. This works
//!   for any `#[contracttype]` request, not only the five defined in
//!   `shared::client` today.
//!
//! None of this is wired into a contract entry point by this change; a
//! contract adopts it by calling `validate_*_request` (and, where retries
//! matter, the idempotency wrappers) before acting on a cross-repo request.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | `schema_version` outside `[MIN_SUPPORTED_CLIENT_SCHEMA_VERSION, MAX_SUPPORTED_CLIENT_SCHEMA_VERSION]` | `Error::UnsupportedSchemaVersion`, checked before any field is read. |
//! | Request party field (`donor`/`depositor`/`seller`) does not match the authenticated caller | `Error::Unauthorized`, before `require_auth` runs. |
//! | Amount/price is zero, negative, or outside the documented rule | `Error::InvalidAmount` or `Error::InvalidArgument` (see `shared::semantic::validate_amount`). |
//! | Two parties that must differ are the same address | `Error::InvalidArgument` (`shared::semantic::validate_distinct_parties`). |
//! | `expiry_ledger` is not far enough (or too far) in the future | `Error::InvalidArgument` (`shared::semantic::validate_future_expiry`). |
//! | `RebalanceRequest.max_slippage_bps > 10_000` | `Error::PaymentInvalidFeeRate` — the same basis-point bound payments already enforce. |
//! | `RebalanceRequest.asset_in == asset_out` | `Error::InvalidArgument`. |
//! | Idempotency key reused for the *same* request after it already succeeded | `begin_idempotent_request` returns `Ok(Some(record))` with the prior result; the caller must not repeat side effects. |
//! | Idempotency key reused for a *different* request, or malformed (empty/oversized) | `Error::InvalidArgument`, surfaced before any state changes. |
//! | Idempotency key still mid-flight, or `complete_idempotent_request` called twice | `Error::AlreadyClaimed`. |
//!
//! ## Recovery / rollback
//!
//! This module performs no persistent writes of its own beyond what
//! `shared::idempotency` already does (a temporary, TTL-bounded record per
//! key), so there is nothing here to roll back:
//!
//! 1. **A client retried after a genuine failure** (the prior attempt never
//!    reached `complete_idempotent_request`): the key's record stays
//!    `Pending` until its TTL lapses, after which `begin_idempotent_request`
//!    treats a fresh submission under that key as new. A contract that wants
//!    faster recovery than the TTL can choose a shorter `ttl_ledgers`.
//! 2. **Schema drift between an SDK and this contract**: bump
//!    `shared::client::CLIENT_SCHEMA_VERSION` and
//!    `MAX_SUPPORTED_CLIENT_SCHEMA_VERSION` together, and keep
//!    `MIN_SUPPORTED_CLIENT_SCHEMA_VERSION` at the oldest version still
//!    accepted — exactly the migration shape `shared::canonical` already
//!    documents for its own encoding version.
//! 3. **A validation rule was too strict or too loose**: the rules
//!    (`AmountRule`/`ExpiryRule` instances, `MAX_SLIPPAGE_BPS`) are plain
//!    constants evaluated fresh on every call; changing them takes effect on
//!    the next request with no migration of stored data, since nothing
//!    validated here is itself persisted.
//!
//! ## Compatibility
//!
//! Purely additive: no changes to `shared::client`'s request/response types,
//! `shared::semantic`, `shared::idempotency`, or any contract interface.

use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};

use crate::client::{
    CreateAidRequest, CreateEscrowRequest, CreateListingRequest, CreateProposalRequest,
    RebalanceRequest, CLIENT_SCHEMA_VERSION,
};
use crate::errors::Error;
use crate::idempotency::{self, IdempotencyError, Record};
use crate::semantic::{validate_amount, validate_distinct_parties, validate_future_expiry, AmountRule, ExpiryRule};

// ---------------------------------------------------------------------------
// Schema compatibility
// ---------------------------------------------------------------------------

/// Oldest client schema version this build still accepts.
pub const MIN_SUPPORTED_CLIENT_SCHEMA_VERSION: u32 = 1;

/// Newest client schema version this build accepts (== current).
pub const MAX_SUPPORTED_CLIENT_SCHEMA_VERSION: u32 = CLIENT_SCHEMA_VERSION;

/// Rejects a request tagged with a schema version outside the supported range.
pub fn ensure_supported_client_schema_version(version: u32) -> Result<(), Error> {
    if (MIN_SUPPORTED_CLIENT_SCHEMA_VERSION..=MAX_SUPPORTED_CLIENT_SCHEMA_VERSION).contains(&version) {
        Ok(())
    } else {
        Err(Error::UnsupportedSchemaVersion)
    }
}

// ---------------------------------------------------------------------------
// Validation rules
// ---------------------------------------------------------------------------

/// Largest number of ledgers (~1 year at 5s/ledger) an expiry may be set into
/// the future. Shared across request types that carry an `expiry_ledger`.
const MAX_EXPIRY_DELAY_LEDGERS: u32 = 6_307_200;

fn positive_amount_rule() -> AmountRule {
    AmountRule {
        min: 1,
        max: i128::MAX,
        allow_zero: false,
    }
}

fn default_expiry_rule() -> ExpiryRule {
    ExpiryRule {
        min_delay_ledgers: 1,
        max_delay_ledgers: MAX_EXPIRY_DELAY_LEDGERS,
    }
}

/// Largest accepted basis-point value, matching `Error::PaymentInvalidFeeRate`'s
/// own 0-10,000 bound.
pub const MAX_SLIPPAGE_BPS: u32 = 10_000;

// ---------------------------------------------------------------------------
// Per-request validation
// ---------------------------------------------------------------------------

/// Validates a cross-repo `CreateAidRequest`.
///
/// `caller` must equal `request.donor` and authenticate.
pub fn validate_create_aid_request(
    env: &Env,
    caller: &Address,
    schema_version: u32,
    request: &CreateAidRequest,
) -> Result<(), Error> {
    ensure_supported_client_schema_version(schema_version)?;
    validate_distinct_parties(&request.donor, &request.recipient)?;
    validate_amount(request.amount, &positive_amount_rule())?;
    validate_future_expiry(env, request.expiry_ledger, &default_expiry_rule())?;
    if *caller != request.donor {
        return Err(Error::Unauthorized);
    }
    caller.require_auth();
    Ok(())
}

/// Validates a cross-repo `CreateEscrowRequest`.
///
/// `caller` must equal `request.depositor` and authenticate.
pub fn validate_create_escrow_request(
    env: &Env,
    caller: &Address,
    schema_version: u32,
    request: &CreateEscrowRequest,
) -> Result<(), Error> {
    ensure_supported_client_schema_version(schema_version)?;
    validate_distinct_parties(&request.depositor, &request.beneficiary)?;
    validate_amount(request.amount, &positive_amount_rule())?;
    validate_future_expiry(env, request.expiry_ledger, &default_expiry_rule())?;
    if *caller != request.depositor {
        return Err(Error::Unauthorized);
    }
    caller.require_auth();
    Ok(())
}

/// Validates a cross-repo `CreateProposalRequest`.
///
/// `CreateProposalRequest` carries no field naming the proposer, so there is
/// no claimed identity to check here beyond authentication; which callers
/// may actually create a proposal is the governance contract's own
/// permission check, not a cross-repo concern.
pub fn validate_create_proposal_request(
    _env: &Env,
    caller: &Address,
    schema_version: u32,
    _request: &CreateProposalRequest,
) -> Result<(), Error> {
    ensure_supported_client_schema_version(schema_version)?;
    caller.require_auth();
    Ok(())
}

/// Validates a cross-repo `CreateListingRequest`.
///
/// `caller` must equal `request.seller` and authenticate.
pub fn validate_create_listing_request(
    _env: &Env,
    caller: &Address,
    schema_version: u32,
    request: &CreateListingRequest,
) -> Result<(), Error> {
    ensure_supported_client_schema_version(schema_version)?;
    validate_amount(request.price, &positive_amount_rule())?;
    if *caller != request.seller {
        return Err(Error::Unauthorized);
    }
    caller.require_auth();
    Ok(())
}

/// Validates a cross-repo `RebalanceRequest`.
///
/// Carries no field naming an acting party, so only authentication is
/// required here; role/permission checks belong to the treasury/rebalancer
/// contract entry point.
pub fn validate_rebalance_request(
    _env: &Env,
    caller: &Address,
    schema_version: u32,
    request: &RebalanceRequest,
) -> Result<(), Error> {
    ensure_supported_client_schema_version(schema_version)?;
    if request.asset_in == request.asset_out {
        return Err(Error::InvalidArgument);
    }
    if request.amount == 0 {
        return Err(Error::InvalidAmount);
    }
    if request.max_slippage_bps > MAX_SLIPPAGE_BPS {
        return Err(Error::PaymentInvalidFeeRate);
    }
    caller.require_auth();
    Ok(())
}

// ---------------------------------------------------------------------------
// Retry: idempotent request fingerprinting
// ---------------------------------------------------------------------------

fn hash_vals(env: &Env, parts: &Vec<Val>) -> BytesN<32> {
    env.crypto().sha256(&parts.clone().to_xdr(env)).to_bytes()
}

/// Deterministic fingerprint of `request`, domain-separated by `tag` so
/// fingerprints of different request types (or versions) can never collide.
///
/// Generic over any `#[contracttype]` request, not only the five defined in
/// `shared::client`.
pub fn fingerprint_request<T>(env: &Env, tag: &str, request: &T) -> BytesN<32>
where
    T: Clone + IntoVal<Env, Val>,
{
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(Symbol::new(env, tag).into_val(env));
    parts.push_back(request.clone().into_val(env));
    hash_vals(env, &parts)
}

fn map_idempotency_error(err: IdempotencyError) -> Error {
    match err {
        IdempotencyError::EmptyKey
        | IdempotencyError::KeyTooLong
        | IdempotencyError::ConflictingRequest => Error::InvalidArgument,
        IdempotencyError::InProgress | IdempotencyError::AlreadyCompleted => Error::AlreadyClaimed,
    }
}

/// Reserves `idempotency_key` for `request` — the retry path for a client
/// that may resend the same call.
///
/// - `Ok(None)`: fresh request; proceed with the operation.
/// - `Ok(Some(record))`: this exact request already completed;
///   `record.result` is the prior outcome — do not repeat its side effects.
/// - `Err(Error::AlreadyClaimed)`: the key is mid-flight, or was already
///   completed and `complete_idempotent_request` was called again.
/// - `Err(Error::InvalidArgument)`: the key is empty/oversized, or was
///   already used for a *different* request.
pub fn begin_idempotent_request<T>(
    env: &Env,
    idempotency_key: &Bytes,
    tag: &str,
    request: &T,
    ttl_ledgers: u32,
) -> Result<Option<Record>, Error>
where
    T: Clone + IntoVal<Env, Val>,
{
    let fingerprint = fingerprint_request(env, tag, request);
    idempotency::begin(env, idempotency_key, &fingerprint, ttl_ledgers).map_err(map_idempotency_error)
}

/// Marks `idempotency_key` complete with `result`.
///
/// Must be called with the exact same `tag`/`request` passed to
/// [`begin_idempotent_request`]; a mismatched request is treated as a
/// conflicting use of the same key.
pub fn complete_idempotent_request<T>(
    env: &Env,
    idempotency_key: &Bytes,
    tag: &str,
    request: &T,
    result: u64,
) -> Result<(), Error>
where
    T: Clone + IntoVal<Env, Val>,
{
    let fingerprint = fingerprint_request(env, tag, request);
    idempotency::complete(env, idempotency_key, &fingerprint, result).map_err(map_idempotency_error)
}
