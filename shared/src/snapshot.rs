//! Signed state snapshot export for audit and debugging (Issue #301).
//!
//! Support and audit investigations need a point-in-time picture of a
//! contract's state that is both **authenticated** (an auditor can prove who
//! captured it and that it has not been altered since) and **chained** (a
//! later snapshot cannot silently replace an earlier one without breaking a
//! verifiable link). This module adds that capability as an opt-in library:
//! contracts assemble the fields they want captured, hand them to
//! [`capture_snapshot`] together with a signature from a registered auditor
//! key, and get back a [`SignedStateSnapshot`] that is stored on-chain and can be
//! walked or exported for off-chain review.
//!
//! ## Design
//!
//! - **Signed, not just hashed.** [`register_signer`] lets an admin authorize
//!   an Ed25519 public key held by an auditor or an operations tool. Capturing
//!   a snapshot requires a signature from a registered key over the
//!   snapshot's [`chain_hash`] — an unregistered or revoked key is rejected
//!   before any cryptographic check runs, and a key whose signature does not
//!   verify aborts the transaction via the host's `ed25519_verify` (the same
//!   trap-on-failure behavior `Address::require_auth` already uses elsewhere
//!   in this workspace).
//! - **Chained, not just timestamped.** Every snapshot for a `module` carries
//!   `prev_root`, the previous snapshot's [`chain_hash`] (or
//!   [`genesis_hash`] for the first one). [`verify_chain`] re-derives every
//!   link from storage, so an inserted, reordered, or edited snapshot is
//!   detectable even if its own fields still hash correctly in isolation.
//! - **Field content is canonical.** Field values reuse
//!   [`crate::canonical::CanonicalPart`], so the same logical value always
//!   produces the same [`SignedStateSnapshot::state_root`] regardless of how a
//!   caller assembled it.
//! - **Bounded and exportable.** [`export_snapshots`] returns a paged,
//!   self-contained bundle (admin-only) that [`verify_export`] can check
//!   off-chain without any contract storage access, mirroring
//!   `shared::audit_ledger`'s export/verify split.
//!
//! ## Hash definitions
//!
//! ```text
//! state_root  = sha256(xdr(["trellis_state_snapshot", schema_version,
//!                           field_1.name, field_1.value, ..., field_n.name, field_n.value]))
//! chain_hash  = sha256(xdr(["trellis_state_snapshot", schema_version,
//!                           module, snapshot_id, created_ledger, created_at,
//!                           generator, reason, state_root, prev_root]))
//! ```
//!
//! `chain_hash` is the exact message an authorized signer's Ed25519 key must
//! sign off-chain before the snapshot is captured.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Caller lacks `Admin`/`Support` | [`SnapshotError::Unauthorized`] before any field or signature is touched. |
//! | No fields supplied | [`SnapshotError::EmptyFields`] — a snapshot must capture something. |
//! | More than [`MAX_SNAPSHOT_FIELDS`] fields | [`SnapshotError::TooManyFields`], bounding gas per call. |
//! | Signer key never registered, or revoked | [`SnapshotError::UnknownSigner`] — checked before the Ed25519 call. |
//! | Signer key registered but signature invalid | Transaction aborts inside `ed25519_verify` (no partial write). |
//! | Reading a snapshot id beyond the chain head | `None` from [`get_snapshot`] / [`SnapshotError::SnapshotNotFound`] from [`export_snapshots`]. |
//! | `verify_chain` on a chain with a tampered/missing entry | Reports the first bad id and the specific [`SnapshotVerificationFailure`] instead of a bare boolean. |
//! | Chain longer than [`MAX_VERIFY_SNAPSHOTS`] | [`SnapshotVerificationFailure::ScanLimitExceeded`]; export and verify in ranges instead. |
//! | Admin rotates signer keys | Register the new key, then revoke the old one; snapshots already captured keep whichever key signed them, so history remains verifiable against a since-revoked key. |
//!
//! ## Recovery / rollback
//!
//! Snapshots are append-only: there is no update or delete entry point, by
//! design, so a bad capture cannot be quietly edited away. If a snapshot was
//! captured with a compromised signer key:
//! 1. Call [`revoke_signer`] immediately so no further snapshots can be
//!    attributed to that key.
//! 2. Run [`verify_chain`] to bound how much of the chain predates the
//!    compromise — everything up to `first_invalid_id - 1` (or the full
//!    length, if verification is clean) is still trustworthy.
//! 3. Capture a fresh snapshot with a newly registered key; auditors treat
//!    the old key's snapshots as attributed-but-suspect rather than deleting
//!    them, preserving the evidence trail.
//!
//! A contract rollback (upgrade revert, restored snapshot) that rewinds
//! storage behind the published chain head is caught the same way
//! `shared::audit_ledger` catches it: the next [`verify_chain`] call reports
//! [`SnapshotVerificationFailure::HeadMismatch`] because the re-derived head
//! no longer matches the stored one.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to existing modules or
//! contract interfaces. Contracts adopt it by calling [`capture_snapshot`]
//! from whichever entry point they want to expose for audit/debug tooling.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal,
    Symbol, Val, Vec,
};

use crate::auth::{has_role, Role};
use crate::canonical::CanonicalPart;
use crate::retention::{put_record, DataClass, RetentionRecord};
use crate::storage::{
    instance_get, instance_set, persistent_get, persistent_has, persistent_remove,
    persistent_set,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current snapshot schema version. Bump only with a documented migration;
/// it is mixed into both [`SignedStateSnapshot::state_root`] and
/// [`SignedStateSnapshot::chain_hash`].
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Domain separator mixed into every hash, preventing cross-subsystem
/// collisions with other hashed/signed payloads in this workspace.
pub const SNAPSHOT_DOMAIN: &str = "trellis_state_snapshot";

/// Largest number of fields one snapshot may capture.
pub const MAX_SNAPSHOT_FIELDS: u32 = 64;

/// Largest number of snapshots one [`verify_chain`] call will walk.
pub const MAX_VERIFY_SNAPSHOTS: u64 = 2_000;

/// Page size used when an export caller passes `0`.
pub const DEFAULT_SNAPSHOT_EXPORT_LIMIT: u32 = 20;

/// Largest number of snapshots one export bundle may contain.
pub const MAX_SNAPSHOT_EXPORT_LIMIT: u32 = 100;

// ---------------------------------------------------------------------------
// Errors (range 1100-1119)
// ---------------------------------------------------------------------------

/// State snapshot export error codes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SnapshotError {
    /// The caller does not hold a role authorized to capture or export snapshots.
    Unauthorized = 1100,
    /// A supplied argument is structurally invalid.
    InvalidArgument = 1101,
    /// A snapshot must capture at least one field.
    EmptyFields = 1102,
    /// The field count exceeds [`MAX_SNAPSHOT_FIELDS`].
    TooManyFields = 1103,
    /// The supplied signer key is not registered (or was revoked).
    UnknownSigner = 1104,
    /// The requested snapshot id does not exist in this module's chain.
    SnapshotNotFound = 1105,
    /// The chain-length counter would overflow.
    Overflow = 1106,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One named, canonically-encoded field captured in a snapshot.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotField {
    pub name: Symbol,
    pub value: CanonicalPart,
}

/// A single point-in-time, signed, chained state capture.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStateSnapshot {
    pub schema_version: u32,
    /// Contract-defined subsystem identifier; snapshots are chained per module.
    pub module: Symbol,
    /// 1-based, monotonically increasing id within `module`'s chain.
    pub snapshot_id: u64,
    pub created_ledger: u32,
    pub created_at: u64,
    /// Authenticated caller that requested the capture.
    pub generator: Address,
    /// Stable reason code (e.g. `audit`, `debug`, `incident`).
    pub reason: Symbol,
    pub fields: Vec<SnapshotField>,
    /// Digest over `fields` alone; see the module-level hash definition.
    pub state_root: BytesN<32>,
    /// The previous snapshot's `chain_hash` in this module ([`genesis_hash`] for the first).
    pub prev_root: BytesN<32>,
    /// Digest over every field of this snapshot except `signer_key`/`signature`;
    /// this is the message the signer's key signed.
    pub chain_hash: BytesN<32>,
    /// Ed25519 public key that signed `chain_hash`.
    pub signer_key: BytesN<32>,
    pub signature: BytesN<64>,
}

/// Per-module chain checkpoint.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotHead {
    pub length: u64,
    pub head_hash: BytesN<32>,
}

/// First failure [`verify_chain`] encountered, or [`SnapshotVerificationFailure::None`].
#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotVerificationFailure {
    None = 0,
    /// A sequence in `1..=length` has no stored entry.
    MissingEntry = 1,
    /// A stored entry's `fields` no longer hash to its `state_root`.
    StateRootMismatch = 2,
    /// A stored entry's `prev_root`/`chain_hash` link is broken.
    ChainBroken = 3,
    /// The re-derived chain does not reproduce the stored head.
    HeadMismatch = 4,
    /// The chain exceeds [`MAX_VERIFY_SNAPSHOTS`]; verify in bounded ranges instead.
    ScanLimitExceeded = 5,
}

/// Result of walking a module's snapshot chain from storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotVerificationReport {
    pub checked: u64,
    pub failure: SnapshotVerificationFailure,
    /// The id that failed, or `0` when `failure` is [`SnapshotVerificationFailure::None`]
    /// or [`SnapshotVerificationFailure::HeadMismatch`] (which has no single bad id).
    pub first_invalid_id: u64,
}

/// A bounded, self-contained range of a module's snapshot chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotExportBundle {
    pub schema_version: u32,
    pub module: Symbol,
    pub from_id: u64,
    pub to_id: u64,
    pub has_more: bool,
    /// The `prev_root` the first entry in `entries` must chain from.
    pub start_prev_root: BytesN<32>,
    pub entries: Vec<SignedStateSnapshot>,
    /// Digest over the bundle's metadata and every entry's `chain_hash`.
    pub digest: BytesN<32>,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum SnapshotKey {
    /// Presence of this key means `BytesN<32>` is an authorized signer.
    Signer(BytesN<32>),
    /// Per-module chain checkpoint (instance storage: contract-level config).
    Head(Symbol),
    /// A stored snapshot by `(module, snapshot_id)`.
    Entry(Symbol, u64),
}

// ---------------------------------------------------------------------------
// Signer registry
// ---------------------------------------------------------------------------

/// Authorizes `signer_key` to sign future snapshots. Admin-gated and idempotent.
pub fn register_signer(
    env: &Env,
    admin: &Address,
    signer_key: &BytesN<32>,
) -> Result<(), SnapshotError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(SnapshotError::Unauthorized);
    }
    admin.require_auth();
    persistent_set(env, &SnapshotKey::Signer(signer_key.clone()), &true);
    Ok(())
}

/// Revokes `signer_key`. Admin-gated. No-op (returns `Ok`) if not registered.
///
/// Snapshots already captured under a revoked key remain stored and their
/// `chain_hash` links remain verifiable; only future captures are affected.
pub fn revoke_signer(
    env: &Env,
    admin: &Address,
    signer_key: &BytesN<32>,
) -> Result<(), SnapshotError> {
    if !has_role(env, admin, Role::Admin) {
        return Err(SnapshotError::Unauthorized);
    }
    admin.require_auth();
    persistent_remove(env, &SnapshotKey::Signer(signer_key.clone()));
    Ok(())
}

/// Returns `true` when `signer_key` is currently authorized.
pub fn is_registered_signer(env: &Env, signer_key: &BytesN<32>) -> bool {
    persistent_has(env, &SnapshotKey::Signer(signer_key.clone()))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// All-zero anchor used as `prev_root` for the first snapshot in a chain.
pub fn genesis_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn domain_symbol(env: &Env) -> Symbol {
    Symbol::new(env, SNAPSHOT_DOMAIN)
}

fn hash_vals(env: &Env, parts: &Vec<Val>) -> BytesN<32> {
    env.crypto().sha256(&parts.clone().to_xdr(env)).to_bytes()
}

/// Digest over `fields` alone — the value an identical field set always
/// reproduces, independent of `module`, `snapshot_id`, or chain position.
pub fn compute_state_root(env: &Env, fields: &Vec<SnapshotField>) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(domain_symbol(env).into_val(env));
    parts.push_back(SNAPSHOT_SCHEMA_VERSION.into_val(env));
    for i in 0..fields.len() {
        let field = fields.get(i).unwrap();
        parts.push_back(field.name.into_val(env));
        parts.push_back(field.value.into_val(env));
    }
    hash_vals(env, &parts)
}

/// Digest over every field of `snapshot` except `signer_key`/`signature` —
/// the exact message an authorized signer must sign.
pub fn chain_hash(env: &Env, snapshot: &SignedStateSnapshot) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(domain_symbol(env).into_val(env));
    parts.push_back(snapshot.schema_version.into_val(env));
    parts.push_back(snapshot.module.clone().into_val(env));
    parts.push_back(snapshot.snapshot_id.into_val(env));
    parts.push_back(snapshot.created_ledger.into_val(env));
    parts.push_back(snapshot.created_at.into_val(env));
    parts.push_back(snapshot.generator.clone().into_val(env));
    parts.push_back(snapshot.reason.clone().into_val(env));
    parts.push_back(snapshot.state_root.clone().into_val(env));
    parts.push_back(snapshot.prev_root.clone().into_val(env));
    hash_vals(env, &parts)
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

fn empty_head(env: &Env) -> SnapshotHead {
    SnapshotHead {
        length: 0,
        head_hash: genesis_hash(env),
    }
}

/// Current chain checkpoint for `module`. Reading never creates state.
pub fn head(env: &Env, module: Symbol) -> SnapshotHead {
    instance_get::<SnapshotKey, SnapshotHead>(env, &SnapshotKey::Head(module))
        .unwrap_or_else(|| empty_head(env))
}

/// Returns the snapshot at `(module, snapshot_id)`, if it exists.
pub fn get_snapshot(env: &Env, module: Symbol, snapshot_id: u64) -> Option<SignedStateSnapshot> {
    if snapshot_id == 0 {
        return None;
    }
    persistent_get::<SnapshotKey, SignedStateSnapshot>(env, &SnapshotKey::Entry(module, snapshot_id))
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

fn register_snapshot_retention(env: &Env, snapshot: &SignedStateSnapshot) -> Result<(), SnapshotError> {
    // `RetentionRecord.id` is a `Symbol`, and `no_std` contracts cannot build
    // one from a module name and a numeric id. Snapshots therefore share one
    // stable retention slot per deployed contract (matches `shared::export`'s
    // `register_export_artifact`): only the newest snapshot's retention is
    // actively tracked, which matches the "most recent audit capture is what
    // matters for cleanup" model.
    let record = RetentionRecord {
        id: symbol_short!("snapshot"),
        class: DataClass::Export,
        created_ledger: snapshot.created_ledger,
        bytes: snapshot.fields.len().saturating_mul(96),
    };
    put_record(env, &record).map_err(|_| SnapshotError::InvalidArgument)
}

/// Captures a new signed, chained snapshot for `module`.
///
/// `caller` must hold [`Role::Admin`] or [`Role::Support`] and authenticate.
/// `signer_key` must already be authorized via [`register_signer`]; the
/// signature is verified over this snapshot's [`chain_hash`] using the host's
/// `ed25519_verify`, which aborts the transaction (rather than returning an
/// error) if the signature does not match — the same trap-on-failure
/// semantics `Address::require_auth` already uses elsewhere in this
/// workspace. No snapshot is written unless the signature checks out.
pub fn capture_snapshot(
    env: &Env,
    caller: &Address,
    module: Symbol,
    reason: Symbol,
    fields: Vec<SnapshotField>,
    signer_key: BytesN<32>,
    signature: BytesN<64>,
) -> Result<SignedStateSnapshot, SnapshotError> {
    if !(has_role(env, caller, Role::Admin) || has_role(env, caller, Role::Support)) {
        return Err(SnapshotError::Unauthorized);
    }
    caller.require_auth();

    if fields.is_empty() {
        return Err(SnapshotError::EmptyFields);
    }
    if fields.len() > MAX_SNAPSHOT_FIELDS {
        return Err(SnapshotError::TooManyFields);
    }
    if !is_registered_signer(env, &signer_key) {
        return Err(SnapshotError::UnknownSigner);
    }

    let current = head(env, module.clone());
    let snapshot_id = current
        .length
        .checked_add(1)
        .ok_or(SnapshotError::Overflow)?;
    let prev_root = current.head_hash;

    let state_root = compute_state_root(env, &fields);

    let mut snapshot = SignedStateSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        module: module.clone(),
        snapshot_id,
        created_ledger: env.ledger().sequence(),
        created_at: env.ledger().timestamp(),
        generator: caller.clone(),
        reason,
        fields,
        state_root,
        prev_root,
        chain_hash: genesis_hash(env),
        signer_key: signer_key.clone(),
        signature: signature.clone(),
    };
    let computed_chain_hash = chain_hash(env, &snapshot);
    snapshot.chain_hash = computed_chain_hash.clone();

    let message = Bytes::from_slice(env, &computed_chain_hash.to_array());
    env.crypto()
        .ed25519_verify(&signer_key, &message, &signature);

    persistent_set(
        env,
        &SnapshotKey::Entry(module.clone(), snapshot_id),
        &snapshot,
    );
    instance_set(
        env,
        &SnapshotKey::Head(module.clone()),
        &SnapshotHead {
            length: snapshot_id,
            head_hash: computed_chain_hash.clone(),
        },
    );
    register_snapshot_retention(env, &snapshot)?;

    env.events().publish(
        (symbol_short!("snapshot"), module),
        (snapshot_id, computed_chain_hash),
    );

    Ok(snapshot)
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// Re-derives `module`'s entire chain from storage and reports the first
/// inconsistency, instead of a bare boolean, so an operator can bound how
/// much of the chain is still trustworthy.
pub fn verify_chain(env: &Env, module: Symbol) -> SnapshotVerificationReport {
    let current = head(env, module.clone());
    if current.length > MAX_VERIFY_SNAPSHOTS {
        return SnapshotVerificationReport {
            checked: 0,
            failure: SnapshotVerificationFailure::ScanLimitExceeded,
            first_invalid_id: 0,
        };
    }

    let mut prev = genesis_hash(env);
    let mut id: u64 = 1;
    while id <= current.length {
        let entry = match get_snapshot(env, module.clone(), id) {
            Some(entry) => entry,
            None => {
                return SnapshotVerificationReport {
                    checked: id - 1,
                    failure: SnapshotVerificationFailure::MissingEntry,
                    first_invalid_id: id,
                }
            }
        };
        if entry.prev_root != prev {
            return SnapshotVerificationReport {
                checked: id - 1,
                failure: SnapshotVerificationFailure::ChainBroken,
                first_invalid_id: id,
            };
        }
        if compute_state_root(env, &entry.fields) != entry.state_root {
            return SnapshotVerificationReport {
                checked: id - 1,
                failure: SnapshotVerificationFailure::StateRootMismatch,
                first_invalid_id: id,
            };
        }
        let recomputed = chain_hash(env, &entry);
        if recomputed != entry.chain_hash {
            return SnapshotVerificationReport {
                checked: id - 1,
                failure: SnapshotVerificationFailure::ChainBroken,
                first_invalid_id: id,
            };
        }
        prev = recomputed;
        id += 1;
    }

    if prev != current.head_hash {
        return SnapshotVerificationReport {
            checked: current.length,
            failure: SnapshotVerificationFailure::HeadMismatch,
            first_invalid_id: 0,
        };
    }

    SnapshotVerificationReport {
        checked: current.length,
        failure: SnapshotVerificationFailure::None,
        first_invalid_id: 0,
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

fn export_digest(
    env: &Env,
    module: &Symbol,
    from_id: u64,
    to_id: u64,
    start_prev_root: &BytesN<32>,
    entries: &Vec<SignedStateSnapshot>,
) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(domain_symbol(env).into_val(env));
    parts.push_back(SNAPSHOT_SCHEMA_VERSION.into_val(env));
    parts.push_back(module.clone().into_val(env));
    parts.push_back(from_id.into_val(env));
    parts.push_back(to_id.into_val(env));
    parts.push_back(start_prev_root.clone().into_val(env));
    for i in 0..entries.len() {
        parts.push_back(entries.get(i).unwrap().chain_hash.into_val(env));
    }
    hash_vals(env, &parts)
}

/// Returns a bounded, self-contained range of `module`'s snapshot chain,
/// starting at `from_id` (`0` means "from the beginning").
///
/// Admin-only. `limit` is capped at [`MAX_SNAPSHOT_EXPORT_LIMIT`] and defaults
/// to [`DEFAULT_SNAPSHOT_EXPORT_LIMIT`] when `0`.
pub fn export_snapshots(
    env: &Env,
    caller: &Address,
    module: Symbol,
    from_id: u64,
    limit: u32,
) -> Result<SnapshotExportBundle, SnapshotError> {
    if !has_role(env, caller, Role::Admin) {
        return Err(SnapshotError::Unauthorized);
    }
    caller.require_auth();

    let current = head(env, module.clone());
    let from = if from_id == 0 { 1 } else { from_id };
    let page = if limit == 0 {
        DEFAULT_SNAPSHOT_EXPORT_LIMIT
    } else {
        limit.min(MAX_SNAPSHOT_EXPORT_LIMIT)
    };

    let start_prev_root = if from <= 1 {
        genesis_hash(env)
    } else if from - 1 > current.length {
        return Err(SnapshotError::SnapshotNotFound);
    } else {
        get_snapshot(env, module.clone(), from - 1)
            .ok_or(SnapshotError::SnapshotNotFound)?
            .chain_hash
    };

    let mut entries: Vec<SignedStateSnapshot> = Vec::new(env);
    let mut id = from;
    let mut count = 0u32;
    while id <= current.length && count < page {
        let entry = get_snapshot(env, module.clone(), id).ok_or(SnapshotError::SnapshotNotFound)?;
        entries.push_back(entry);
        id += 1;
        count += 1;
    }
    let to_id = if entries.is_empty() { from } else { id - 1 };
    let has_more = id <= current.length;

    let digest = export_digest(env, &module, from, to_id, &start_prev_root, &entries);

    Ok(SnapshotExportBundle {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        module,
        from_id: from,
        to_id,
        has_more,
        start_prev_root,
        entries,
        digest,
    })
}

/// Storage-free verification of an exported bundle: recomputes the bundle
/// digest and re-walks every entry's chain link and state root. Does not
/// re-check signatures (capture time already enforced authenticity); this
/// checks that the bundle's data has not been altered since it was exported.
pub fn verify_export(env: &Env, bundle: &SnapshotExportBundle) -> bool {
    if bundle.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return false;
    }
    let recomputed = export_digest(
        env,
        &bundle.module,
        bundle.from_id,
        bundle.to_id,
        &bundle.start_prev_root,
        &bundle.entries,
    );
    if recomputed != bundle.digest {
        return false;
    }

    let mut prev = bundle.start_prev_root.clone();
    for i in 0..bundle.entries.len() {
        let entry = bundle.entries.get(i).unwrap();
        if entry.prev_root != prev {
            return false;
        }
        if compute_state_root(env, &entry.fields) != entry.state_root {
            return false;
        }
        let recomputed_entry = chain_hash(env, &entry);
        if recomputed_entry != entry.chain_hash {
            return false;
        }
        prev = recomputed_entry;
    }
    true
}
