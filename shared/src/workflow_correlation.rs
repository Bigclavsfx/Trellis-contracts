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

// ---------------------------------------------------------------------------
// Request correlation across API, workers, and external calls (Issue #268)
// ---------------------------------------------------------------------------

/// Maximum number of hops allowed across API, workers, and external calls
/// to prevent runaway distributed call chains and protect execution budget.
pub const MAX_CORRELATION_HOPS: u32 = 8;

/// Logical stage in a distributed request lifecycle.
#[soroban_sdk::contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CorrelationStage {
    /// Ingress from user, frontend, or partner API gateway.
    Api = 1,
    /// Background job enqueued on-chain or off-chain.
    WorkerEnqueue = 2,
    /// Background job currently executing an attempt.
    WorkerExecute = 3,
    /// Cross-contract or external protocol call.
    ExternalCall = 4,
    /// Terminal settlement, refund, or finalization.
    Settlement = 5,
}

/// Request correlation envelope tracking root transaction origin and causation hops.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCorrelationContext {
    /// Root correlation ID created at ingress boundary (unchanged across hops).
    pub root_id: Bytes,
    /// Causation ID identifying the immediate parent action that triggered this step.
    pub parent_causation_id: Bytes,
    /// Current lifecycle stage of the request.
    pub stage: CorrelationStage,
    /// Number of hops traversed so far (bounded by `MAX_CORRELATION_HOPS`).
    pub hop_count: u32,
    /// Retry attempt counter (1-based; incremented on worker retries).
    pub attempt: u32,
}

/// Validates an entire request correlation context.
pub fn validate_correlation_context(ctx: &RequestCorrelationContext) -> Result<(), Error> {
    validate_workflow_id(&ctx.root_id)?;
    if ctx.hop_count > 0 {
        validate_workflow_id(&ctx.parent_causation_id)?;
    }
    if ctx.hop_count > MAX_CORRELATION_HOPS || ctx.attempt == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Initializes a new request correlation context at the API boundary.
pub fn create_request_context(
    env: &soroban_sdk::Env,
    root_id: &Bytes,
) -> Result<RequestCorrelationContext, Error> {
    validate_workflow_id(root_id)?;
    let empty_parent = Bytes::new(env);
    let ctx = RequestCorrelationContext {
        root_id: root_id.clone(),
        parent_causation_id: empty_parent,
        stage: CorrelationStage::Api,
        hop_count: 0,
        attempt: 1,
    };
    validate_correlation_context(&ctx)?;
    Ok(ctx)
}

/// Propagates an existing request context into an enqueued background worker job.
///
/// Fails with [`Error::Unauthorized`] if caller lacks permission, or [`Error::InvalidArgument`]
/// if hop limits or validation checks fail.
pub fn propagate_to_worker(
    _env: &soroban_sdk::Env,
    ctx: &RequestCorrelationContext,
    authorized: bool,
) -> Result<RequestCorrelationContext, Error> {
    if !authorized {
        return Err(Error::Unauthorized);
    }
    validate_correlation_context(ctx)?;

    let next_hop = ctx.hop_count + 1;
    if next_hop > MAX_CORRELATION_HOPS {
        return Err(Error::InvalidArgument);
    }

    // Causation becomes the previous root or step identifier
    let parent_id = if ctx.hop_count == 0 {
        ctx.root_id.clone()
    } else {
        ctx.parent_causation_id.clone()
    };

    let worker_ctx = RequestCorrelationContext {
        root_id: ctx.root_id.clone(),
        parent_causation_id: parent_id,
        stage: CorrelationStage::WorkerEnqueue,
        hop_count: next_hop,
        attempt: ctx.attempt,
    };
    validate_correlation_context(&worker_ctx)?;
    Ok(worker_ctx)
}

/// Advances a worker execution attempt during retry, preserving root correlation
/// while incrementing the retry attempt counter.
pub fn advance_worker_retry(
    _env: &soroban_sdk::Env,
    ctx: &RequestCorrelationContext,
    next_attempt: u32,
) -> Result<RequestCorrelationContext, Error> {
    validate_correlation_context(ctx)?;
    if next_attempt <= ctx.attempt {
        return Err(Error::InvalidArgument);
    }

    let retry_ctx = RequestCorrelationContext {
        root_id: ctx.root_id.clone(),
        parent_causation_id: ctx.parent_causation_id.clone(),
        stage: CorrelationStage::WorkerExecute,
        hop_count: ctx.hop_count,
        attempt: next_attempt,
    };
    validate_correlation_context(&retry_ctx)?;
    Ok(retry_ctx)
}

/// Propagates correlation context into a downstream external cross-contract call.
pub fn propagate_to_external_call(
    _env: &soroban_sdk::Env,
    ctx: &RequestCorrelationContext,
) -> Result<RequestCorrelationContext, Error> {
    validate_correlation_context(ctx)?;

    let next_hop = ctx.hop_count + 1;
    if next_hop > MAX_CORRELATION_HOPS {
        return Err(Error::InvalidArgument);
    }

    let ext_ctx = RequestCorrelationContext {
        root_id: ctx.root_id.clone(),
        parent_causation_id: ctx.root_id.clone(),
        stage: CorrelationStage::ExternalCall,
        hop_count: next_hop,
        attempt: ctx.attempt,
    };
    validate_correlation_context(&ext_ctx)?;
    Ok(ext_ctx)
}

