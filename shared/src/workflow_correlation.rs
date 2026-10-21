//! Multi-contract workflow correlation IDs (Issue #330).
//!
//! A workflow such as "fund aid, claim, then settle" touches several contracts,
//! and each one emits its own events. A shared correlation ID lets an indexer
//! stitch those events back into one workflow.
//!
//! ## Policy
//!
//! - Non-empty and at most [`MAX_WORKFLOW_ID_LEN`] bytes.
//! - ASCII letters, digits, `-` and `_` only.
//!
//! ## Retries
//!
//! A retried step reuses the ID of the workflow it belongs to, so the same ID
//! may appear more than once in a chain. Only an ID that differs from the rest
//! of the chain is rejected.
//!
//! ## Scope
//!
//! This module is pure: it reads no storage and checks no caller. A contract
//! that accepts a correlation ID must still authorize the call before it emits
//! events under that ID.
//!
//! See `docs/WORKFLOW_CORRELATION.md` for the operator-facing edge cases.

use soroban_sdk::{Bytes, Vec};

use crate::errors::Error;

/// Maximum length of a workflow correlation ID in bytes.
pub const MAX_WORKFLOW_ID_LEN: u32 = 64;

/// Validates a single correlation ID against the workflow policy.
///
/// Fails with [`Error::InvalidArgument`] when the ID is empty, longer than
/// [`MAX_WORKFLOW_ID_LEN`], or contains a byte outside the allowed set.
pub fn validate_workflow_id(id: &Bytes) -> Result<(), Error> {
    let len = id.len();
    if len == 0 || len > MAX_WORKFLOW_ID_LEN {
        return Err(Error::InvalidArgument);
    }
    for i in 0..len {
        let b = id.get(i).ok_or(Error::InvalidArgument)?;
        let is_allowed = b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
        if !is_allowed {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}

/// Checks that every step of a workflow carries the same valid correlation ID.
///
/// Returns the shared ID on success. An empty chain, an invalid ID, or any ID
/// that differs from the first one fails with [`Error::InvalidArgument`].
pub fn check_workflow_chain(chain: &Vec<Bytes>) -> Result<Bytes, Error> {
    let first = chain.get(0).ok_or(Error::InvalidArgument)?;
    for id in chain.iter() {
        validate_workflow_id(&id)?;
        if id != first {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(first)
}
