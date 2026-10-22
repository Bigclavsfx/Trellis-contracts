//! Maintainer action approval flow with signed intent receipts (Issue #228).
//!
//! High-impact contract actions (moving treasury funds, changing a
//! risk parameter, widening a pause scope, rotating a maintainer key) used to
//! be a single privileged call: whoever held the role could act immediately,
//! and the only evidence afterwards was a generic audit-ledger row. That makes
//! two things hard for an operator:
//!
//! - **Intent is implicit.** The ledger shows *that* an action happened, not
//!   *what was signed before it happened*, so a reviewer cannot tell whether
//!   the action matched the intent that was communicated to the second
//!   maintainer.
//! - **Post-hoc review is lossy.** After a failure, the only record is an
//!   error code; there is no artifact that binds the approvers, the intent,
//!   and the outcome together.
//!
//! This module adds a small, opt-in approval layer that closes both gaps:
//!
//! - **Explicit intent.** A maintainer publishes an [`ActionIntent`]: a
//!   module, an action, a target, canonically-encoded parameters, and an
//!   expiry. The intent is *signed* with the maintainer's registered Ed25519
//!   key over a domain-separated digest, so the parameters that were approved
//!   are cryptographically bound to the approval.
//! - **Threshold approval.** A per-module [`ApprovalPolicy`] fixes how many
//!   *distinct* maintainers must approve. Approvals are also signed, so the
//!   receipt carries the evidence, not just a boolean.
//! - **Signed intent receipts.** When the action completes — successfully or
//!   not — an [`IntentReceipt`] is appended. Receipts are hash-chained per
//!   module (`prev_receipt` → `receipt_hash`), so an edited, reordered, or
//!   removed receipt is detectable by [`verify_receipts`]. The receipt
//!   contains the intent digest, every approval (approver address, key,
//!   signature), the outcome, and the failure reason, which makes the flow
//!   reviewable *after completion or failure*.
//!
//! ## Design
//!
//! ```text
//!  propose_intent            approve_intent (xN)         begin_execution
//!  -------------             -------------------          --------------
//!  Pending ────(threshold)──▶ Approved ──────────────────▶ Executing
//!      │                            │                          │
//!      │ cancel_intent              │ reject_intent            │
//!      ▼                            ▼                          ▼
//!  Cancelled                   Rejected            record_success / record_failure
//!                                                                    │
//!                                                                    ▼
//!                                                          Executed / Failed
//!                                                 (+ an IntentReceipt in both cases)
//! ```
//!
//! - **Two-phase execution.** [`begin_execution`] does not perform the action;
//!   it validates the approval state and hands the approved parameters back to
//!   the calling contract, which then performs the action and reports the
//!   outcome with [`record_success`] or [`record_failure`]. This keeps the
//!   module generic (it never knows what "withdraw 500 XLM" means) while
//!   still guaranteeing that only approved intents can be executed.
//! - **Signed, not just hashed.** Every maintainer registers an Ed25519 public
//!   key. The proposer signs the intent digest, and every approver signs the
//!   same digest. Signatures are checked with the host's `ed25519_verify`,
//!   which aborts the transaction when a signature does not match — the same
//!   trap-on-failure semantics `Address::require_auth` uses elsewhere in this
//!   workspace, and the same precedent as `shared::snapshot`. Nothing is
//!   written when a signature is rejected.
//! - **Separation of duties.** A proposer cannot approve their own intent
//!   unless the module policy explicitly allows it, and each maintainer may
//!   approve a given intent at most once.
//! - **Fail-safe defaults.** Any action is treated as high-impact until an
//!   administrator explicitly marks it as low-impact, and the default policy
//!   requires two approvals.
//! - **Bounded work.** Parameter counts, approval counts, receipt-chain scans,
//!   and export sizes are all capped so a single call cannot be used to burn
//!   an unbounded amount of budget.
//!
//! ## Hash definitions
//!
//! ```text
//! params_digest = sha256(canonical_bytes(params))          // shared::canonical
//! intent_hash   = sha256(xdr(["trellis_maintainer_approval", schema_version,
//!                            module, action, proposer, target,
//!                            params_digest, expires_ledger]))
//! receipt_hash  = sha256(xdr(["trellis_maintainer_receipt", schema_version,
//!                            module, receipt_id, intent_id, action, target,
//!                            proposer, executor, outcome, reason,
//!                            intent_hash, prev_receipt]))
//! ```
//!
//! `intent_hash` is the exact 32-byte message every approver signs, and
//! `receipt_hash` is the chain link of the per-module receipt ledger.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Caller is not a registered maintainer | [`ApprovalError::UnknownMaintainer`] before any state is read or written. |
//! | Maintainer's key is not the registered key | [`ApprovalError::InvalidSignature`]; the signature is never checked. |
//! | Signature does not match the intent digest | The host aborts inside `ed25519_verify`; no intent, approval, or receipt is written. |
//! | Proposer tries to approve their own intent | [`ApprovalError::SelfApproval`] (unless the policy allows it). |
//! | Same maintainer approves twice | [`ApprovalError::DuplicateApproval`]; the existing approval list is untouched. |
//! | Approvals below the policy threshold | [`ApprovalError::ThresholdNotMet`]; `begin_execution` refuses to run. |
//! | Intent is past `expires_ledger` | [`ApprovalError::Expired`]; approvals and executions are refused. [`sweep_expired`] moves it to the `Expired` state. |
//! | Execution is attempted on a non-approved intent | [`ApprovalError::InvalidState`]. |
//! | Action fails on-chain | The contract calls [`record_failure`]; a receipt with outcome `Failed` and the reason is appended, so the failure is reviewable. |
//! | Execution never reports an outcome | The intent stays `Executing`; an administrator can close it with [`record_failure`] (reason `abandoned`) or re-run it with [`begin_execution`]. |
//! | Receipt chain is edited or reordered | [`verify_receipts`] reports [`ReceiptVerificationFailure::ChainBroken`] / `HashMismatch` and the first bad receipt id. |
//! | Chain longer than [`MAX_VERIFY_RECEIPTS`] | [`ReceiptVerificationFailure::ScanLimitExceeded`]; verify bounded ranges or use [`export_receipts`]. |
//! | Maintainer key is revoked | The key can no longer propose or approve; receipts already produced keep the (now-revoked) key so history stays verifiable. |
//!
//! ## Recovery / rollback
//!
//! Receipts are append-only: there is no update or delete entry point, so a
//! bad receipt cannot be quietly edited away. If a maintainer key is
//! compromised:
//! 1. Call [`revoke_maintainer`] so no further intents or approvals can be
//!    attributed to that key.
//! 2. Run [`verify_receipts`] and [`list_receipts`] to bound how much of the
//!    chain predates the compromise; everything before the first bad receipt
//!    is still trustworthy.
//! 3. Reject or cancel any in-flight intent that the compromised maintainer
//!    proposed or approved, then re-propose it with a clean key.
//!
//! Rolling the contract back (upgrade revert) to a state behind the published
//! receipt head is detected the same way `shared::audit_ledger` detects it:
//! the next [`verify_receipts`] call reports
//! [`ReceiptVerificationFailure::HeadMismatch`] because the re-derived head no
//! longer matches the stored one.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, new events, no changes to any existing
//! module, contract interface, error code, or event payload. A contract opts
//! in by calling [`propose_intent`], [`approve_intent`], [`begin_execution`],
//! and [`record_success`] / [`record_failure`] from whichever entry points it
//! wants to gate.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal,
    Symbol, Val, Vec,
};

use crate::audit_ledger::{append_privileged, AuditEventKind};
use crate::auth::{has_role, Role};
use crate::canonical::{canonical_fingerprint, CanonicalPart};
use crate::retention::{put_record, DataClass, RetentionRecord};
use crate::storage::{
    instance_get, instance_set, persistent_get, persistent_has, persistent_remove, persistent_set,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current approval-flow schema version. Bump only with a documented
/// migration; it is mixed into both the intent digest and the receipt hash.
pub const MAINTAINER_APPROVAL_SCHEMA_VERSION: u32 = 1;

/// Domain separator mixed into the intent digest.
pub const APPROVAL_DOMAIN: &str = "trellis_maintainer_approval";

/// Domain separator mixed into the receipt hash.
pub const RECEIPT_DOMAIN: &str = "trellis_maintainer_receipt";

/// Default number of distinct approvals required before an intent is
/// executable.
pub const DEFAULT_APPROVAL_THRESHOLD: u32 = 2;

/// Smallest threshold a policy may configure.
pub const MIN_APPROVAL_THRESHOLD: u32 = 1;

/// Largest threshold a policy may configure.
pub const MAX_APPROVAL_THRESHOLD: u32 = 16;

/// Default intent lifetime, in ledgers (17_280 ledgers ~ 24 h at 5 s/ledger).
pub const DEFAULT_INTENT_TTL_LEDGERS: u64 = 17_280;

/// Longest intent lifetime a policy may configure.
pub const MAX_INTENT_TTL_LEDGERS: u64 = 604_800;

/// Largest number of parameters one intent may carry.
pub const MAX_INTENT_PARAMS: u32 = 32;

/// Largest number of approvals one intent may collect.
pub const MAX_APPROVALS_PER_INTENT: u32 = 16;

/// Largest number of receipts one [`verify_receipts`] call walks.
pub const MAX_VERIFY_RECEIPTS: u64 = 2_000;

/// Page size used when a listing caller passes `0`.
pub const DEFAULT_RECEIPT_PAGE_LIMIT: u32 = 20;

/// Largest number of receipts one page may contain.
pub const MAX_RECEIPT_PAGE_LIMIT: u32 = 100;

/// Largest number of receipts one export bundle may contain.
pub const MAX_EXPORT_RECEIPTS: u32 = 100;

/// Event topic emitted for every approval-flow state change.
pub const APPROVAL_TOPIC: &str = "approval";

// ---------------------------------------------------------------------------
// Errors (range 1200-1219)
// ---------------------------------------------------------------------------

/// Maintainer approval flow error codes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ApprovalError {
    /// The caller is not allowed to perform this step of the flow.
    Unauthorized = 1200,
    /// A supplied argument is structurally invalid.
    InvalidArgument = 1201,
    /// The referenced intent or receipt does not exist.
    NotFound = 1202,
    /// The signature does not match the registered key or the signed message.
    InvalidSignature = 1203,
    /// The caller is not a registered maintainer.
    UnknownMaintainer = 1204,
    /// The maintainer (or key) is already registered.
    AlreadyExists = 1205,
    /// The approval threshold has not been reached yet.
    ThresholdNotMet = 1206,
    /// The intent is not in a state that allows this operation.
    InvalidState = 1207,
    /// The intent has expired.
    Expired = 1208,
    /// The proposer tried to approve their own intent.
    SelfApproval = 1209,
    /// The maintainer already approved this intent.
    DuplicateApproval = 1210,
    /// A counter or identifier would overflow.
    Overflow = 1211,
    /// The audit ledger rejected the privileged event for this flow.
    AuditLedgerFailure = 1212,
    /// The intent carries more parameters than allowed.
    TooManyParams = 1213,
    /// The intent already collected the maximum number of approvals.
    TooManyApprovals = 1214,
    /// The requested page or export size is not supported.
    LimitExceeded = 1215,
    /// The caller is not authorized to review or export receipts.
    UnauthorizedReview = 1216,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Lifecycle state of an [`ActionIntent`].
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentStatus {
    /// Proposed, waiting for approvals.
    Pending = 0,
    /// The approval threshold was reached; the intent may be executed.
    Approved = 1,
    /// Execution has started; the outcome is not recorded yet.
    Executing = 2,
    /// The action completed successfully.
    Executed = 3,
    /// The action was attempted and failed.
    Failed = 4,
    /// A reviewer rejected the intent.
    Rejected = 5,
    /// The proposer cancelled the intent.
    Cancelled = 6,
    /// The intent passed its expiry without being executed.
    Expired = 7,
}

/// Terminal outcome recorded in an [`IntentReceipt`].
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    /// The action completed successfully.
    Succeeded = 0,
    /// The action was attempted and failed.
    Failed = 1,
    /// The intent was rejected before execution.
    Rejected = 2,
    /// The intent was cancelled before execution.
    Cancelled = 3,
}

/// A single approval of an intent, signed by the approver's registered key.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    /// The approving maintainer.
    pub approver: Address,
    /// Ed25519 public key registered for `approver`.
    pub approver_key: BytesN<32>,
    /// Signature over the intent digest, produced by `approver_key`.
    pub signature: BytesN<64>,
    /// Ledger sequence at which the approval was recorded.
    pub approved_ledger: u32,
    /// Ledger timestamp at which the approval was recorded.
    pub approved_at: u64,
}

/// A high-impact action proposed by a maintainer, pending approval.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionIntent {
    /// Schema version of the approval flow that produced this intent.
    pub schema_version: u32,
    /// 1-based, monotonically increasing id within `module`.
    pub intent_id: u64,
    /// Subsystem the action belongs to (e.g. `treasury`).
    pub module: Symbol,
    /// Stable action code (e.g. `withdraw`).
    pub action: Symbol,
    /// Maintainer that proposed the intent.
    pub proposer: Address,
    /// Address the action targets (recipient, contract, or role holder).
    pub target: Address,
    /// Canonically-encoded action parameters.
    pub params: Vec<CanonicalPart>,
    /// Digest over `params`; see the module-level hash definitions.
    pub params_digest: BytesN<32>,
    /// Digest over the whole intent; the message every approver signs.
    pub intent_hash: BytesN<32>,
    /// Ledger sequence at which the intent was proposed.
    pub created_ledger: u32,
    /// Ledger timestamp at which the intent was proposed.
    pub created_at: u64,
    /// Last ledger sequence at which the intent may still be approved/executed.
    pub expires_ledger: u32,
    /// Current lifecycle state.
    pub status: IntentStatus,
    /// Number of approvals collected so far.
    pub approval_count: u32,
    /// Maintainer that started execution, if any.
    pub executor: Option<Address>,
    /// Number of execution attempts started for this intent.
    pub attempts: u32,
}

/// Approval policy for one module.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPolicy {
    /// Subsystem the policy applies to.
    pub module: Symbol,
    /// Number of distinct approvals required before execution.
    pub threshold: u32,
    /// Maximum intent lifetime, in ledgers.
    pub ttl_ledgers: u64,
    /// Whether the proposer may also approve their own intent.
    pub allow_self_approval: bool,
}

/// Per-module receipt-chain checkpoint.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptHead {
    /// Number of receipts in the chain.
    pub length: u64,
    /// Hash of the most recent receipt.
    pub head_hash: BytesN<32>,
}

/// Immutable evidence of one completed (or refused) intent.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentReceipt {
    /// Schema version of the approval flow that produced this receipt.
    pub schema_version: u32,
    /// 1-based, monotonically increasing id within `module`.
    pub receipt_id: u64,
    /// The intent this receipt closes.
    pub intent_id: u64,
    /// Subsystem the intent belonged to.
    pub module: Symbol,
    /// Action code that was proposed.
    pub action: Symbol,
    /// Address the action targeted.
    pub target: Address,
    /// Maintainer that proposed the intent.
    pub proposer: Address,
    /// Maintainer that executed the action (empty for rejections/cancellations).
    pub executor: Option<Address>,
    /// Terminal outcome.
    pub outcome: ReceiptOutcome,
    /// Stable reason code (e.g. `insufficient_balance`, `abandoned`).
    pub reason: Symbol,
    /// Every approval collected for the intent.
    pub approvals: Vec<Approval>,
    /// Number of approvals collected (mirrors `approvals.len()`).
    pub approval_count: u32,
    /// Digest of the intent the receipt closes.
    pub intent_hash: BytesN<32>,
    /// Previous receipt's hash in this module's chain.
    pub prev_receipt: BytesN<32>,
    /// Digest over this receipt's fields; the chain link.
    pub receipt_hash: BytesN<32>,
    /// Ledger sequence at which the receipt was recorded.
    pub recorded_ledger: u32,
    /// Ledger timestamp at which the receipt was recorded.
    pub recorded_at: u64,
}

/// First failure [`verify_receipts`] encountered.
#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptVerificationFailure {
    /// The chain verified.
    None = 0,
    /// A receipt id in `1..=length` has no stored entry.
    MissingEntry = 1,
    /// A receipt's `prev_receipt` link does not match the previous receipt.
    ChainBroken = 2,
    /// A receipt's stored `receipt_hash` does not match its own fields.
    HashMismatch = 3,
    /// The re-derived chain does not reproduce the stored head.
    HeadMismatch = 4,
    /// The chain exceeds [`MAX_VERIFY_RECEIPTS`].
    ScanLimitExceeded = 5,
    /// A receipt stores a different number of approvals than it reports.
    ApprovalCountMismatch = 6,
}

/// Result of walking a module's receipt chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptVerificationReport {
    /// Number of receipts checked.
    pub checked: u64,
    /// The first failure found, or `None`.
    pub failure: ReceiptVerificationFailure,
    /// The receipt id that failed, or `0` when there is no single bad id.
    pub first_invalid_id: u64,
}

/// A bounded, self-contained range of a module's receipt chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptExportBundle {
    /// Schema version of the approval flow.
    pub schema_version: u32,
    /// Subsystem the receipts belong to.
    pub module: Symbol,
    /// First receipt id in the bundle.
    pub from_id: u64,
    /// Last receipt id in the bundle.
    pub to_id: u64,
    /// Whether more receipts follow the bundle.
    pub has_more: bool,
    /// The `prev_receipt` the first entry must chain from.
    pub start_prev_receipt: BytesN<32>,
    /// The receipts themselves.
    pub receipts: Vec<IntentReceipt>,
    /// Digest over the bundle metadata and every receipt hash.
    pub digest: BytesN<32>,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

/// Storage keys used by the approval flow.
///
/// Exposed so operators (and the tamper-detection tests) can reason about
/// exactly where an intent, its approvals, and a receipt live.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalKey {
    /// Presence of this key means the address is a registered maintainer.
    Maintainer(Address),
    /// The Ed25519 key registered for a maintainer.
    MaintainerKey(Address),
    /// Reverse index: the maintainer that registered a public key.
    KeyOwner(BytesN<32>),
    /// Approval policy of a module (instance storage).
    Policy(Symbol),
    /// High-impact flag of `(module, action)` (instance storage).
    Impact(Symbol, Symbol),
    /// Next intent id of a module (instance storage).
    IntentHead(Symbol),
    /// A stored intent.
    Intent(Symbol, u64),
    /// The approvals collected for an intent.
    Approvals(Symbol, u64),
    /// Per-module receipt chain checkpoint (instance storage).
    ReceiptHead(Symbol),
    /// A stored receipt.
    Receipt(Symbol, u64),
}

// ---------------------------------------------------------------------------
// Maintainer registry
// ---------------------------------------------------------------------------

/// Registers `maintainer` together with the Ed25519 key it signs with.
///
/// Admin-gated: `admin` must hold [`Role::Admin`] and authenticate. The key
/// may not already belong to another maintainer, and a maintainer may not be
/// registered twice.
pub fn register_maintainer(
    env: &Env,
    admin: &Address,
    maintainer: &Address,
    key: &BytesN<32>,
) -> Result<(), ApprovalError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(ApprovalError::Unauthorized);
    }
    admin.require_auth();

    if is_maintainer(env, maintainer) {
        return Err(ApprovalError::AlreadyExists);
    }
    if !is_maintainer_key_free(env, key) {
        return Err(ApprovalError::AlreadyExists);
    }

    persistent_set(env, &ApprovalKey::Maintainer(maintainer.clone()), &true);
    persistent_set(
        env,
        &ApprovalKey::MaintainerKey(maintainer.clone()),
        key,
    );
    persistent_set(env, &ApprovalKey::KeyOwner(key.clone()), maintainer);
    Ok(())
}

/// Revokes `maintainer`.
///
/// Admin-gated. The maintainer can no longer propose or approve. Receipts and
/// intents that already reference the maintainer keep pointing at it, so
/// history stays verifiable (and reviewable) after the revocation.
pub fn revoke_maintainer(
    env: &Env,
    admin: &Address,
    maintainer: &Address,
) -> Result<(), ApprovalError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(ApprovalError::Unauthorized);
    }
    admin.require_auth();

    persistent_remove(env, &ApprovalKey::Maintainer(maintainer.clone()));
    if let Some(key) = maintainer_key(env, maintainer) {
        persistent_remove(env, &ApprovalKey::MaintainerKey(maintainer.clone()));
        persistent_remove(env, &ApprovalKey::KeyOwner(key));
    }
    Ok(())
}

/// Returns `true` when `maintainer` is currently registered.
pub fn is_maintainer(env: &Env, maintainer: &Address) -> bool {
    persistent_has(env, &ApprovalKey::Maintainer(maintainer.clone()))
}

/// Returns the Ed25519 key registered for `maintainer`, if any.
pub fn maintainer_key(env: &Env, maintainer: &Address) -> Option<BytesN<32>> {
    persistent_get(env, &ApprovalKey::MaintainerKey(maintainer.clone()))
}

/// Returns `true` when no maintainer is registered with `key`.
fn is_maintainer_key_free(env: &Env, key: &BytesN<32>) -> bool {
    !persistent_has(env, &ApprovalKey::KeyOwner(key.clone()))
}

/// Maps a public key to the maintainer that registered it.
pub fn key_owner(env: &Env, key: &BytesN<32>) -> Option<Address> {
    persistent_get(env, &ApprovalKey::KeyOwner(key.clone()))
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Default policy applied to a module that has no explicit policy.
pub fn default_policy(module: Symbol) -> ApprovalPolicy {
    ApprovalPolicy {
        module,
        threshold: DEFAULT_APPROVAL_THRESHOLD,
        ttl_ledgers: DEFAULT_INTENT_TTL_LEDGERS,
        allow_self_approval: false,
    }
}

/// Sets the approval policy of `module`.
///
/// Admin-gated. `threshold` must be within
/// [`MIN_APPROVAL_THRESHOLD`]..=[`MAX_APPROVAL_THRESHOLD`] and `ttl_ledgers`
/// must not exceed [`MAX_INTENT_TTL_LEDGERS`].
pub fn set_policy(
    env: &Env,
    admin: &Address,
    module: Symbol,
    threshold: u32,
    ttl_ledgers: u64,
    allow_self_approval: bool,
) -> Result<ApprovalPolicy, ApprovalError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(ApprovalError::Unauthorized);
    }
    admin.require_auth();

    if threshold < MIN_APPROVAL_THRESHOLD || threshold > MAX_APPROVAL_THRESHOLD {
        return Err(ApprovalError::InvalidArgument);
    }
    if ttl_ledgers == 0 || ttl_ledgers > MAX_INTENT_TTL_LEDGERS {
        return Err(ApprovalError::InvalidArgument);
    }

    let policy = ApprovalPolicy {
        module: module.clone(),
        threshold,
        ttl_ledgers,
        allow_self_approval,
    };
    instance_set(env, &ApprovalKey::Policy(module), &policy);
    Ok(policy)
}

/// Returns the approval policy of `module`, falling back to the defaults.
pub fn get_policy(env: &Env, module: Symbol) -> ApprovalPolicy {
    instance_get::<ApprovalKey, ApprovalPolicy>(env, &ApprovalKey::Policy(module.clone()))
        .unwrap_or_else(|| default_policy(module))
}

/// Marks `action` of `module` as high-impact (default) or low-impact.
///
/// Admin-gated. High-impact actions require an approved intent; low-impact
/// actions may be executed directly by the contract.
pub fn set_action_impact(
    env: &Env,
    admin: &Address,
    module: Symbol,
    action: Symbol,
    high_impact: bool,
) -> Result<(), ApprovalError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(ApprovalError::Unauthorized);
    }
    admin.require_auth();
    instance_set(env, &ApprovalKey::Impact(module, action), &high_impact);
    Ok(())
}

/// Returns `true` when `action` of `module` requires an approved intent.
///
/// Fail-safe default: an action is treated as high-impact until an
/// administrator explicitly marks it as low-impact.
pub fn is_high_impact(env: &Env, module: Symbol, action: Symbol) -> bool {
    instance_get::<ApprovalKey, bool>(env, &ApprovalKey::Impact(module, action)).unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

fn domain_symbol(env: &Env, domain: &str) -> Symbol {
    Symbol::new(env, domain)
}

fn hash_vals(env: &Env, parts: &Vec<Val>) -> BytesN<32> {
    env.crypto().sha256(&parts.clone().to_xdr(env)).to_bytes()
}

/// Digest over the canonically-encoded parameters of an intent.
pub fn params_digest(
    env: &Env,
    params: &Vec<CanonicalPart>,
) -> Result<BytesN<32>, ApprovalError> {
    canonical_fingerprint(env, params).map_err(|_| ApprovalError::InvalidArgument)
}

/// Digest over an intent — the exact 32-byte message approvers sign.
///
/// The digest is bound to the module, the action, the proposer, the target,
/// the parameter digest and the expiry, so an approval cannot be re-used for
/// a different action, a different target, different parameters, or a longer
/// lifetime.
#[allow(clippy::too_many_arguments)]
pub fn intent_hash(
    env: &Env,
    module: &Symbol,
    action: &Symbol,
    proposer: &Address,
    target: &Address,
    params_digest: &BytesN<32>,
    expires_ledger: u32,
) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(domain_symbol(env, APPROVAL_DOMAIN).into_val(env));
    parts.push_back(MAINTAINER_APPROVAL_SCHEMA_VERSION.into_val(env));
    parts.push_back(module.clone().into_val(env));
    parts.push_back(action.clone().into_val(env));
    parts.push_back(proposer.clone().into_val(env));
    parts.push_back(target.clone().into_val(env));
    parts.push_back(params_digest.clone().into_val(env));
    parts.push_back(expires_ledger.into_val(env));
    hash_vals(env, &parts)
}

/// The 32-byte message a maintainer signs to approve an intent.
pub fn intent_message(env: &Env, intent_hash: &BytesN<32>) -> Bytes {
    Bytes::from_slice(env, &intent_hash.to_array())
}

/// Digest over a receipt — the chain link of the per-module receipt ledger.
#[allow(clippy::too_many_arguments)]
fn receipt_hash(
    env: &Env,
    receipt: &IntentReceipt,
    outcome_code: u32,
    executor: &Option<Address>,
) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(domain_symbol(env, RECEIPT_DOMAIN).into_val(env));
    parts.push_back(receipt.schema_version.into_val(env));
    parts.push_back(receipt.module.clone().into_val(env));
    parts.push_back(receipt.receipt_id.into_val(env));
    parts.push_back(receipt.intent_id.into_val(env));
    parts.push_back(receipt.action.clone().into_val(env));
    parts.push_back(receipt.target.clone().into_val(env));
    parts.push_back(receipt.proposer.clone().into_val(env));
    match executor {
        Some(addr) => parts.push_back(addr.clone().into_val(env)),
        None => parts.push_back(().into_val(env)),
    }
    parts.push_back(outcome_code.into_val(env));
    parts.push_back(receipt.reason.clone().into_val(env));
    parts.push_back(receipt.intent_hash.clone().into_val(env));
    parts.push_back(receipt.prev_receipt.clone().into_val(env));
    hash_vals(env, &parts)
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

fn genesis_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

/// Current receipt-chain checkpoint of `module`.
pub fn receipt_head(env: &Env, module: Symbol) -> ReceiptHead {
    instance_get::<ApprovalKey, ReceiptHead>(env, &ApprovalKey::ReceiptHead(module.clone()))
        .unwrap_or_else(|| ReceiptHead {
            length: 0,
            head_hash: genesis_hash(env),
        })
}

/// Returns the intent at `(module, intent_id)`, if it exists.
pub fn get_intent(env: &Env, module: Symbol, intent_id: u64) -> Option<ActionIntent> {
    if intent_id == 0 {
        return None;
    }
    persistent_get(env, &ApprovalKey::Intent(module, intent_id))
}

/// Returns the approvals collected for `(module, intent_id)`.
pub fn get_approvals(env: &Env, module: Symbol, intent_id: u64) -> Vec<Approval> {
    persistent_get::<ApprovalKey, Vec<Approval>>(
        env,
        &ApprovalKey::Approvals(module, intent_id),
    )
    .unwrap_or_else(|| Vec::new(env))
}

/// Returns the receipt at `(module, receipt_id)`, if it exists.
pub fn get_receipt(env: &Env, module: Symbol, receipt_id: u64) -> Option<IntentReceipt> {
    if receipt_id == 0 {
        return None;
    }
    persistent_get(env, &ApprovalKey::Receipt(module, receipt_id))
}

/// Number of receipts recorded for `module`.
pub fn receipt_count(env: &Env, module: Symbol) -> u64 {
    receipt_head(env, module).length
}

/// Returns the receipts of `module` in the range `from_id..=from_id + limit - 1`.
///
/// `limit` of `0` uses [`DEFAULT_RECEIPT_PAGE_LIMIT`]; the effective limit is
/// capped at [`MAX_RECEIPT_PAGE_LIMIT`].
pub fn list_receipts(
    env: &Env,
    module: Symbol,
    from_id: u64,
    limit: u32,
) -> Vec<IntentReceipt> {
    let limit = effective_limit(limit);
    let head = receipt_head(env, module.clone());
    let mut out: Vec<IntentReceipt> = Vec::new(env);
    let mut id = from_id;
    while id <= head.length && out.len() < limit {
        if let Some(receipt) = get_receipt(env, module.clone(), id) {
            out.push_back(receipt);
        }
        id += 1;
    }
    out
}

/// Returns the intents of `module` in the range `from_id..=from_id + limit - 1`.
pub fn list_intents(env: &Env, module: Symbol, from_id: u64, limit: u32) -> Vec<ActionIntent> {
    let limit = effective_limit(limit);
    let head = instance_get::<ApprovalKey, u64>(env, &ApprovalKey::IntentHead(module.clone()))
        .unwrap_or(0);
    let mut out: Vec<ActionIntent> = Vec::new(env);
    let mut id = from_id;
    while id <= head && out.len() < limit {
        if let Some(intent) = get_intent(env, module.clone(), id) {
            out.push_back(intent);
        }
        id += 1;
    }
    out
}

/// Returns the intents of `module` that are still waiting for approval.
pub fn pending_intents(env: &Env, module: Symbol, limit: u32) -> Vec<ActionIntent> {
    let limit = effective_limit(limit);
    let head = instance_get::<ApprovalKey, u64>(env, &ApprovalKey::IntentHead(module.clone()))
        .unwrap_or(0);
    let mut out: Vec<ActionIntent> = Vec::new(env);
    let mut id = 1;
    while id <= head && out.len() < limit {
        if let Some(intent) = get_intent(env, module.clone(), id) {
            if intent.status == IntentStatus::Pending
                || intent.status == IntentStatus::Approved
                || intent.status == IntentStatus::Executing
            {
                out.push_back(intent);
            }
        }
        id += 1;
    }
    out
}

fn effective_limit(limit: u32) -> u32 {
    if limit == 0 {
        DEFAULT_RECEIPT_PAGE_LIMIT
    } else if limit > MAX_RECEIPT_PAGE_LIMIT {
        MAX_RECEIPT_PAGE_LIMIT
    } else {
        limit
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verifies `signature` over `message` for the key registered for `maintainer`.
///
/// The registered key is checked first, so a caller cannot make the contract
/// verify an arbitrary key. When the key matches, the host's `ed25519_verify`
/// aborts the transaction if the signature does not verify — nothing is
/// written in that case, which is the same trap-on-failure contract used by
/// `shared::snapshot`.
fn verify_signature(
    env: &Env,
    maintainer: &Address,
    message: &Bytes,
    signature: &BytesN<64>,
) -> Result<(), ApprovalError> {
    let key = maintainer_key(env, maintainer).ok_or(ApprovalError::UnknownMaintainer)?;
    if key == BytesN::from_array(env, &[0u8; 32]) {
        return Err(ApprovalError::InvalidSignature);
    }
    if signature == &BytesN::from_array(env, &[0u8; 64]) {
        return Err(ApprovalError::InvalidSignature);
    }
    env.crypto().ed25519_verify(&key, message, signature);
    Ok(())
}

/// Requires `caller` to be a registered maintainer.
fn require_maintainer(env: &Env, caller: &Address) -> Result<(), ApprovalError> {
    if !is_maintainer(env, caller) {
        return Err(ApprovalError::UnknownMaintainer);
    }
    Ok(())
}

/// Requires `caller` to be a maintainer or an administrator.
fn require_maintainer_or_admin(env: &Env, caller: &Address) -> Result<(), ApprovalError> {
    if is_maintainer(env, caller) {
        return Ok(());
    }
    if has_role(env, caller, Role::Admin) {
        return Ok(());
    }
    Err(ApprovalError::Unauthorized)
}

// ---------------------------------------------------------------------------
// Intent lifecycle
// ---------------------------------------------------------------------------

/// Proposes a new intent for `module`.
///
/// `proposer` must be a registered maintainer and authenticate. The signature
/// must be produced by the maintainer's registered key over the intent digest
/// ([`intent_hash`]); the digest is bound to the parameters and the expiry, so
/// the approved intent cannot be altered afterwards.
///
/// `expires_ledger` must be in the future relative to the current ledger and
/// no further away than the module policy allows.
pub fn propose_intent(
    env: &Env,
    proposer: &Address,
    module: Symbol,
    action: Symbol,
    target: Address,
    params: Vec<CanonicalPart>,
    expires_ledger: u32,
    signature: BytesN<64>,
) -> Result<ActionIntent, ApprovalError> {
    require_maintainer(env, proposer)?;
    proposer.require_auth();

    if params.len() > MAX_INTENT_PARAMS {
        return Err(ApprovalError::TooManyParams);
    }

    let policy = get_policy(env, module.clone());
    let now = env.ledger().sequence();
    if expires_ledger <= now {
        return Err(ApprovalError::Expired);
    }
    let max_expiry = now.saturating_add(policy.ttl_ledgers as u32);
    if expires_ledger > max_expiry {
        return Err(ApprovalError::InvalidArgument);
    }

    let digest = params_digest(env, &params)?;
    let hash = intent_hash(
        env,
        &module,
        &action,
        proposer,
        &target,
        &digest,
        expires_ledger,
    );
    let message = intent_message(env, &hash);
    verify_signature(env, proposer, &message, &signature)?;

    let head = instance_get::<ApprovalKey, u64>(env, &ApprovalKey::IntentHead(module.clone()))
        .unwrap_or(0);
    let intent_id = head.checked_add(1).ok_or(ApprovalError::Overflow)?;

    let intent = ActionIntent {
        schema_version: MAINTAINER_APPROVAL_SCHEMA_VERSION,
        intent_id,
        module: module.clone(),
        action,
        proposer: proposer.clone(),
        target,
        params,
        params_digest: digest,
        intent_hash: hash,
        created_ledger: now,
        created_at: env.ledger().timestamp(),
        expires_ledger,
        status: IntentStatus::Pending,
        approval_count: 0,
        executor: None,
        attempts: 0,
    };

    persistent_set(env, &ApprovalKey::Intent(module.clone(), intent_id), &intent);
    persistent_set(
        env,
        &ApprovalKey::Approvals(module.clone(), intent_id),
        &Vec::<Approval>::new(env),
    );
    instance_set(env, &ApprovalKey::IntentHead(module.clone()), &intent_id);

    emit(env, &module, symbol_short!("proposed"), intent_id);
    append_audit(
        env,
        &module,
        &intent.action,
        proposer,
        Some(&intent.target),
        symbol_short!("intent"),
    )?;

    Ok(intent)
}

/// Approves the intent `(module, intent_id)`.
///
/// `approver` must be a registered maintainer and authenticate. The signature
/// must be produced by the approver's registered key over the intent digest.
/// A maintainer may approve an intent only once, and (by default) cannot
/// approve an intent they proposed themselves.
pub fn approve_intent(
    env: &Env,
    approver: &Address,
    module: Symbol,
    intent_id: u64,
    signature: BytesN<64>,
) -> Result<IntentStatus, ApprovalError> {
    require_maintainer(env, approver)?;
    approver.require_auth();

    let mut intent = get_intent(env, module.clone(), intent_id).ok_or(ApprovalError::NotFound)?;
    if intent.status != IntentStatus::Pending {
        return Err(ApprovalError::InvalidState);
    }
    if env.ledger().sequence() > intent.expires_ledger {
        return Err(ApprovalError::Expired);
    }

    let policy = get_policy(env, module.clone());
    if intent.proposer == *approver && !policy.allow_self_approval {
        return Err(ApprovalError::SelfApproval);
    }

    let mut approvals = get_approvals(env, module.clone(), intent_id);
    if approvals.len() >= MAX_APPROVALS_PER_INTENT as u32 {
        return Err(ApprovalError::TooManyApprovals);
    }
    for i in 0..approvals.len() {
        if let Some(existing) = approvals.get(i) {
            if existing.approver == *approver {
                return Err(ApprovalError::DuplicateApproval);
            }
        }
    }

    let message = intent_message(env, &intent.intent_hash);
    verify_signature(env, approver, &message, &signature)?;

    approvals.push_back(Approval {
        approver: approver.clone(),
        approver_key: maintainer_key(env, approver).ok_or(ApprovalError::UnknownMaintainer)?,
        signature,
        approved_ledger: env.ledger().sequence(),
        approved_at: env.ledger().timestamp(),
    });

    let count = approvals.len();
    if count >= policy.threshold {
        intent.status = IntentStatus::Approved;
    }
    intent.approval_count = count;

    persistent_set(
        env,
        &ApprovalKey::Approvals(module.clone(), intent_id),
        &approvals,
    );
    persistent_set(env, &ApprovalKey::Intent(module.clone(), intent_id), &intent);

    emit(env, &module, symbol_short!("approved"), intent_id);
    append_audit(
        env,
        &module,
        &intent.action,
        approver,
        Some(&intent.target),
        symbol_short!("intent_ok"),
    )?;

    Ok(intent.status)
}

/// Starts the execution of an approved intent and returns it.
///
/// The returned intent carries the approved parameters, so the calling
/// contract can perform exactly the action that was approved. Only an
/// approved, unexpired intent can be started, and only a maintainer or an
/// administrator may start it.
pub fn begin_execution(
    env: &Env,
    executor: &Address,
    module: Symbol,
    intent_id: u64,
) -> Result<ActionIntent, ApprovalError> {
    require_maintainer_or_admin(env, executor)?;
    executor.require_auth();

    let mut intent = get_intent(env, module.clone(), intent_id).ok_or(ApprovalError::NotFound)?;
    if intent.status != IntentStatus::Approved && intent.status != IntentStatus::Executing {
        return Err(ApprovalError::InvalidState);
    }
    if env.ledger().sequence() > intent.expires_ledger {
        return Err(ApprovalError::Expired);
    }

    let policy = get_policy(env, module.clone());
    let approvals = get_approvals(env, module.clone(), intent_id);
    if approvals.len() < policy.threshold {
        return Err(ApprovalError::ThresholdNotMet);
    }

    intent.status = IntentStatus::Executing;
    intent.executor = Some(executor.clone());
    intent.attempts = intent.attempts.saturating_add(1);
    persistent_set(env, &ApprovalKey::Intent(module.clone(), intent_id), &intent);

    emit(env, &module, symbol_short!("executing"), intent_id);
    Ok(intent)
}

/// Records a successful execution and appends the intent receipt.
///
/// The intent must be in the `Executing` state. After this call the intent is
/// closed (`Executed`) and cannot be executed again.
pub fn record_success(
    env: &Env,
    executor: &Address,
    module: Symbol,
    intent_id: u64,
) -> Result<IntentReceipt, ApprovalError> {
    close_intent(env, executor, module, intent_id, ReceiptOutcome::Succeeded, symbol_short!("ok"))
}

/// Records a failed execution and appends the intent receipt.
///
/// The intent must be in the `Executing` state. The receipt keeps the reason,
/// the approvals and the intent digest, so the failure is reviewable. A
/// failed intent may be retried with [`begin_execution`] while it is still
/// within its expiry.
pub fn record_failure(
    env: &Env,
    executor: &Address,
    module: Symbol,
    intent_id: u64,
    reason: Symbol,
) -> Result<IntentReceipt, ApprovalError> {
    close_intent(
        env,
        executor,
        module,
        intent_id,
        ReceiptOutcome::Failed,
        reason,
    )
}

/// Closes an intent and appends its receipt.
fn close_intent(
    env: &Env,
    actor: &Address,
    module: Symbol,
    intent_id: u64,
    outcome: ReceiptOutcome,
    reason: Symbol,
) -> Result<IntentReceipt, ApprovalError> {
    require_maintainer_or_admin(env, actor)?;
    actor.require_auth();

    let mut intent = get_intent(env, module.clone(), intent_id).ok_or(ApprovalError::NotFound)?;
    if intent.status != IntentStatus::Executing {
        return Err(ApprovalError::InvalidState);
    }

    intent.status = match outcome {
        ReceiptOutcome::Succeeded => IntentStatus::Executed,
        ReceiptOutcome::Failed => IntentStatus::Failed,
        _ => IntentStatus::Rejected,
    };
    persistent_set(env, &ApprovalKey::Intent(module.clone(), intent_id), &intent);

    let approvals = get_approvals(env, module.clone(), intent_id);
    let receipt = append_receipt(
        env,
        &module,
        &intent,
        &approvals,
        outcome,
        reason,
        Some(actor.clone()),
    )?;

    emit(env, &module, symbol_short!("receipt"), receipt.receipt_id);
    Ok(receipt)
}

/// Rejects an intent before execution.
///
/// `reviewer` must be a registered maintainer or an administrator. A rejected
/// intent is closed and gets a receipt with outcome `Rejected`, so the
/// decision is part of the reviewable trail.
pub fn reject_intent(
    env: &Env,
    reviewer: &Address,
    module: Symbol,
    intent_id: u64,
    reason: Symbol,
) -> Result<IntentReceipt, ApprovalError> {
    require_maintainer_or_admin(env, reviewer)?;
    reviewer.require_auth();

    let mut intent = get_intent(env, module.clone(), intent_id).ok_or(ApprovalError::NotFound)?;
    if intent.status != IntentStatus::Pending && intent.status != IntentStatus::Approved {
        return Err(ApprovalError::InvalidState);
    }
    intent.status = IntentStatus::Rejected;
    persistent_set(env, &ApprovalKey::Intent(module.clone(), intent_id), &intent);

    let approvals = get_approvals(env, module.clone(), intent_id);
    let receipt = append_receipt(
        env,
        &module,
        &intent,
        &approvals,
        ReceiptOutcome::Rejected,
        reason,
        Some(reviewer.clone()),
    )?;

    emit(env, &module, symbol_short!("rejected"), intent_id);
    Ok(receipt)
}

/// Cancels an intent proposed by the caller.
///
/// Only the proposer may cancel their own intent, and only while it has not
/// been executed. The cancellation is recorded as a receipt.
pub fn cancel_intent(
    env: &Env,
    proposer: &Address,
    module: Symbol,
    intent_id: u64,
    reason: Symbol,
) -> Result<IntentReceipt, ApprovalError> {
    proposer.require_auth();

    let mut intent = get_intent(env, module.clone(), intent_id).ok_or(ApprovalError::NotFound)?;
    if intent.proposer != *proposer {
        return Err(ApprovalError::Unauthorized);
    }
    if intent.status != IntentStatus::Pending && intent.status != IntentStatus::Approved {
        return Err(ApprovalError::InvalidState);
    }
    intent.status = IntentStatus::Cancelled;
    persistent_set(env, &ApprovalKey::Intent(module.clone(), intent_id), &intent);

    let approvals = get_approvals(env, module.clone(), intent_id);
    let receipt = append_receipt(
        env,
        &module,
        &intent,
        &approvals,
        ReceiptOutcome::Cancelled,
        reason,
        Some(proposer.clone()),
    )?;

    emit(env, &module, symbol_short!("cancelled"), intent_id);
    Ok(receipt)
}

/// Marks every expired, still-open intent of `module` as expired.
///
/// Bounded by `limit` so a sweep cannot exceed the caller's budget. Returns
/// the number of intents that were moved to the `Expired` state.
pub fn sweep_expired(env: &Env, module: Symbol, limit: u32) -> Result<u32, ApprovalError> {
    let limit = effective_limit(limit);
    let head = instance_get::<ApprovalKey, u64>(env, &ApprovalKey::IntentHead(module.clone()))
        .unwrap_or(0);
    let now = env.ledger().sequence();
    let mut swept = 0u32;
    let mut id = 1u64;
    while id <= head && swept < limit {
        if let Some(mut intent) = get_intent(env, module.clone(), id) {
            let open = intent.status == IntentStatus::Pending
                || intent.status == IntentStatus::Approved
                || intent.status == IntentStatus::Executing;
            if open && now > intent.expires_ledger {
                intent.status = IntentStatus::Expired;
                persistent_set(env, &ApprovalKey::Intent(module.clone(), id), &intent);
                swept += 1;
            }
        }
        id += 1;
    }
    Ok(swept)
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Appends a receipt for `intent` to `module`'s receipt chain.
fn append_receipt(
    env: &Env,
    module: &Symbol,
    intent: &ActionIntent,
    approvals: &Vec<Approval>,
    outcome: ReceiptOutcome,
    reason: Symbol,
    executor: Option<Address>,
) -> Result<IntentReceipt, ApprovalError> {
    let head = receipt_head(env, module.clone());
    let receipt_id = head.length.checked_add(1).ok_or(ApprovalError::Overflow)?;
    let audit_note = reason.clone();

    let mut receipt = IntentReceipt {
        schema_version: MAINTAINER_APPROVAL_SCHEMA_VERSION,
        receipt_id,
        intent_id: intent.intent_id,
        module: module.clone(),
        action: intent.action.clone(),
        target: intent.target.clone(),
        proposer: intent.proposer.clone(),
        executor: executor.clone(),
        outcome,
        reason,
        approvals: approvals.clone(),
        approval_count: approvals.len(),
        intent_hash: intent.intent_hash.clone(),
        prev_receipt: head.head_hash.clone(),
        receipt_hash: genesis_hash(env),
        recorded_ledger: env.ledger().sequence(),
        recorded_at: env.ledger().timestamp(),
    };
    receipt.receipt_hash = receipt_hash(env, &receipt, outcome as u32, &executor);

    persistent_set(env, &ApprovalKey::Receipt(module.clone(), receipt_id), &receipt);
    instance_set(
        env,
        &ApprovalKey::ReceiptHead(module.clone()),
        &ReceiptHead {
            length: receipt_id,
            head_hash: receipt.receipt_hash.clone(),
        },
    );

    register_receipt_retention(env, &receipt)?;
    let audit_actor = match &executor {
        Some(actor) => actor.clone(),
        None => intent.proposer.clone(),
    };
    append_audit(
        env,
        module,
        &intent.action,
        &audit_actor,
        Some(&intent.target),
        audit_note,
    )?;

    Ok(receipt)
}

fn register_receipt_retention(
    env: &Env,
    receipt: &IntentReceipt,
) -> Result<(), ApprovalError> {
    // `RetentionRecord.id` is a `Symbol`, and `no_std` contracts cannot build
    // one from a module name and a numeric id. Receipts therefore share one
    // stable retention slot per deployed contract (the same approach as
    // `shared::snapshot`): only the newest receipt's retention is tracked.
    let record = RetentionRecord {
        id: symbol_short!("approval"),
        class: DataClass::Export,
        created_ledger: receipt.recorded_ledger,
        bytes: receipt.approval_count.saturating_mul(128),
    };
    put_record(env, &record).map_err(|_| ApprovalError::InvalidArgument)
}

/// Re-derives `module`'s receipt chain from storage and reports the first
/// inconsistency, instead of a bare boolean, so an operator can bound how much
/// of the chain is still trustworthy.
pub fn verify_receipts(env: &Env, module: Symbol) -> ReceiptVerificationReport {
    let current = receipt_head(env, module.clone());
    if current.length > MAX_VERIFY_RECEIPTS {
        return ReceiptVerificationReport {
            checked: 0,
            failure: ReceiptVerificationFailure::ScanLimitExceeded,
            first_invalid_id: 0,
        };
    }

    let mut prev = genesis_hash(env);
    let mut id: u64 = 1;
    while id <= current.length {
        let receipt = match get_receipt(env, module.clone(), id) {
            Some(receipt) => receipt,
            None => {
                return ReceiptVerificationReport {
                    checked: id - 1,
                    failure: ReceiptVerificationFailure::MissingEntry,
                    first_invalid_id: id,
                }
            }
        };
        if receipt.prev_receipt != prev {
            return ReceiptVerificationReport {
                checked: id - 1,
                failure: ReceiptVerificationFailure::ChainBroken,
                first_invalid_id: id,
            };
        }
        if receipt.approval_count != receipt.approvals.len() {
            return ReceiptVerificationReport {
                checked: id - 1,
                failure: ReceiptVerificationFailure::ApprovalCountMismatch,
                first_invalid_id: id,
            };
        }
        let recomputed = receipt_hash(
            env,
            &receipt,
            receipt.outcome as u32,
            &receipt.executor,
        );
        if recomputed != receipt.receipt_hash {
            return ReceiptVerificationReport {
                checked: id - 1,
                failure: ReceiptVerificationFailure::HashMismatch,
                first_invalid_id: id,
            };
        }
        prev = recomputed;
        id += 1;
    }

    if prev != current.head_hash {
        return ReceiptVerificationReport {
            checked: current.length,
            failure: ReceiptVerificationFailure::HeadMismatch,
            first_invalid_id: 0,
        };
    }

    ReceiptVerificationReport {
        checked: current.length,
        failure: ReceiptVerificationFailure::None,
        first_invalid_id: 0,
    }
}

/// Exports a bounded, self-contained range of `module`'s receipt chain.
///
/// Admin-gated. The bundle carries the `prev_receipt` the first entry must
/// chain from and a digest over its own metadata, so an off-chain reviewer
/// can check it without touching contract storage.
pub fn export_receipts(
    env: &Env,
    admin: &Address,
    module: Symbol,
    from_id: u64,
    limit: u32,
) -> Result<ReceiptExportBundle, ApprovalError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(ApprovalError::UnauthorizedReview);
    }
    admin.require_auth();

    let limit = effective_limit(limit).min(MAX_EXPORT_RECEIPTS);
    if from_id == 0 {
        return Err(ApprovalError::InvalidArgument);
    }

    let head = receipt_head(env, module.clone());
    let start_prev_receipt = if from_id <= 1 {
        genesis_hash(env)
    } else {
        match get_receipt(env, module.clone(), from_id - 1) {
            Some(receipt) => receipt.receipt_hash,
            None => return Err(ApprovalError::NotFound),
        }
    };

    let mut receipts: Vec<IntentReceipt> = Vec::new(env);
    let mut id = from_id;
    while id <= head.length && receipts.len() < limit {
        if let Some(receipt) = get_receipt(env, module.clone(), id) {
            receipts.push_back(receipt);
        }
        id += 1;
    }

    let to_id = match receipts.len() {
        0 => from_id.saturating_sub(1),
        len => match receipts.get(len - 1) {
            Some(last) => last.receipt_id,
            None => from_id.saturating_sub(1),
        },
    };
    let has_more = head.length > to_id;

    let mut bundle = ReceiptExportBundle {
        schema_version: MAINTAINER_APPROVAL_SCHEMA_VERSION,
        module: module.clone(),
        from_id,
        to_id,
        has_more,
        start_prev_receipt,
        receipts: receipts.clone(),
        digest: genesis_hash(env),
    };
    bundle.digest = export_digest(env, &bundle);
    Ok(bundle)
}

/// Digest over an export bundle's metadata and every receipt hash.
pub fn export_digest(env: &Env, bundle: &ReceiptExportBundle) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(domain_symbol(env, RECEIPT_DOMAIN).into_val(env));
    parts.push_back(bundle.schema_version.into_val(env));
    parts.push_back(bundle.module.clone().into_val(env));
    parts.push_back(bundle.from_id.into_val(env));
    parts.push_back(bundle.to_id.into_val(env));
    parts.push_back(bundle.has_more.into_val(env));
    parts.push_back(bundle.start_prev_receipt.clone().into_val(env));
    for i in 0..bundle.receipts.len() {
        if let Some(receipt) = bundle.receipts.get(i) {
            parts.push_back(receipt.receipt_hash.into_val(env));
        }
    }
    hash_vals(env, &parts)
}

/// Verifies an export bundle off-chain-style, without contract storage.
///
/// Returns [`ReceiptVerificationFailure::None`] when the bundle is internally
/// consistent: the digest matches, every receipt re-derives its own hash, and
/// the chain links hold inside the bundle.
pub fn verify_export(env: &Env, bundle: &ReceiptExportBundle) -> ReceiptVerificationReport {
    if export_digest(env, bundle) != bundle.digest {
        return ReceiptVerificationReport {
            checked: 0,
            failure: ReceiptVerificationFailure::HashMismatch,
            first_invalid_id: 0,
        };
    }

    let mut prev = bundle.start_prev_receipt.clone();
    for i in 0..bundle.receipts.len() {
        let receipt = match bundle.receipts.get(i) {
            Some(receipt) => receipt,
            None => {
                return ReceiptVerificationReport {
                    checked: i as u64,
                    failure: ReceiptVerificationFailure::MissingEntry,
                    first_invalid_id: 0,
                }
            }
        };
        if receipt.prev_receipt != prev {
            return ReceiptVerificationReport {
                checked: i as u64,
                failure: ReceiptVerificationFailure::ChainBroken,
                first_invalid_id: receipt.receipt_id,
            };
        }
        let recomputed = receipt_hash(env, &receipt, receipt.outcome as u32, &receipt.executor);
        if recomputed != receipt.receipt_hash {
            return ReceiptVerificationReport {
                checked: i as u64,
                failure: ReceiptVerificationFailure::HashMismatch,
                first_invalid_id: receipt.receipt_id,
            };
        }
        prev = recomputed;
    }

    ReceiptVerificationReport {
        checked: bundle.receipts.len() as u64,
        failure: ReceiptVerificationFailure::None,
        first_invalid_id: 0,
    }
}

// ---------------------------------------------------------------------------
// Events & audit integration
// ---------------------------------------------------------------------------

fn emit(env: &Env, module: &Symbol, kind: Symbol, intent_id: u64) {
    env.events()
        .publish((symbol_short!("approval"), module.clone(), kind), intent_id);
}

/// Mirrors the flow into the shared audit ledger so a reviewer has a single
/// privileged trail next to the contract-specific receipts.
fn append_audit(
    env: &Env,
    module: &Symbol,
    action: &Symbol,
    actor: &Address,
    subject: Option<&Address>,
    note: Symbol,
) -> Result<(), ApprovalError> {
    append_privileged(
        env,
        AuditEventKind::PrivilegedAction,
        module.clone(),
        actor.clone(),
        subject.cloned(),
        Some(action.clone()),
        Some(note),
    )
    .map(|_| ())
    .map_err(|_| ApprovalError::AuditLedgerFailure)
}
