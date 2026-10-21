// API problem-details taxonomy for the Aid contract.
//
// The canonical `AidError` enum lives in `src/lib.rs` under the
// 100-199 numeric range (as documented in `shared/README.md`). This module
// provides a stable, machine-readable problem-details layer on top of that
// enum so off-chain clients can react to failures without parsing free
// text. The codes are stable: they must never be renumbered or reused.
//
// This module is deliberately pure (no storage access) so it is cheap to
// call from any contract entry point and trivially testable.

use crate::AidError;

/// Stable machine code for a problem details response.
///
/// The numeric value is the contract error code and is part of the
/// public API. It is assigned explicitly (never derived from the enum
/// discriminant) so reordering the enum cannot silently change the wire
/// format. New codes are appended; existing codes are never reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Eq)]
#[repr(u32)]
pub enum AidProblemCode {
    /// The contract is not initialized.
    NotInitialized = 100,
    /// The contract has already been initialized.
    AlreadyInitialized = 101,
    /// The caller is not authorized for this operation.
    Unauthorized = 102,
    /// The requested aid package does not exist.
    PackageNotFound = 103,
    /// The requested aid package is not active.
    PackageInactive = 104,
    /// The recipient has already claimed this package.
    AlreadyClaimed = 105,
    /// The recipient is not eligible for this package.
    NotEligible = 106,
    /// The treasury lacks sufficient funds to settle the claim.
    InsufficientFunds = 107,
    /// An amount argument was zero or otherwise invalid.
    InvalidAmount = 108,
    /// A claim expired before being settled.
    ClaimExpired = 109,
    /// A referral code was not found or is inactive.
    InvalidReferral = 110,
    /// A governance proposal is not in a state that allows the action.
    InvalidProposalState = 111,
    /// An oracle price is stale or missing.
    OraclePriceUnavailable = 112,
    /// A marketplace listing is not available for purchase.
    ListingUnavailable = 113,
    /// An internal invariant was violated; treat as a bug.
    InternalInvariant = 199,
}

/// Safe, user-facing problem details derived from an `AidError`.
///
/// The `status` is an HTHP-like class (e.g. 400, 403, 409, 422, 500) and
/// the `type_uri` points at the documentation for the code. Messages are
/// deliberately generic and never include internal details or P2P data.
#[derive(Clone, Debug, Eq, PartialEq, Eq)]
pub struct AidProblemDetails {
    /// Stable machine code.
    pub code: AidProblemCode,
    /// HTHP-like status class for transport mapping.
    pub status: u32,
    /// Stable resolution identifier, e.g. `aid/not-initialized`.
    pub type_uri: &'static str,
    /// Safe, non-leaking message suitable for end users.
    pub title: &'static str,
    /// Actionable remediation hint for clients and operators.
    pu remediation: &'static str,
}
