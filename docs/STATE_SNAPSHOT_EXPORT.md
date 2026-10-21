# Signed State Snapshot Export

`shared::snapshot` (Issue #301) lets a contract capture a point-in-time,
cryptographically **signed**, hash-**chained** picture of its own state for
audit investigations and debugging, separate from the event stream and from
the existing `shared::audit_ledger` (which records privileged/financial
*actions*, not a *state* capture) and `shared::export` (which streams
*records* under a permission matrix, not a signed snapshot chain).

## Design in one paragraph

An admin registers the Ed25519 public key of an auditor or ops tool with
[`register_signer`](../shared/src/snapshot.rs). To capture a snapshot, an
`Admin` or `Support` caller assembles the fields to record (each a
`(Symbol name, CanonicalPart value)` pair), computes the snapshot's
`chain_hash` off-chain or lets the contract compute it, has the registered
key sign that hash, and calls `capture_snapshot` with the fields and
signature. The contract re-derives `chain_hash` itself, verifies the
signature with the host's `ed25519_verify`, and only then stores the
snapshot and advances the per-module chain head. Nothing is written if the
signature does not verify.

```text
state_root  = sha256(xdr(["trellis_state_snapshot", schema_version,
                          field_1.name, field_1.value, ..., field_n.name, field_n.value]))
chain_hash  = sha256(xdr(["trellis_state_snapshot", schema_version,
                          module, snapshot_id, created_ledger, created_at,
                          generator, reason, state_root, prev_root]))
```

`chain_hash` is the exact message the signer's Ed25519 key signs. `prev_root`
is the previous snapshot's `chain_hash` (the all-zero `genesis_hash` for the
first one in a module's chain), so editing, reordering, or dropping a past
snapshot breaks every later link — the same tamper-evidence model
`shared::audit_ledger` uses for its event chain.

## Public surface

| Item | Purpose |
|---|---|
| `register_signer` / `revoke_signer` | Admin-gated authorization of Ed25519 signer keys. |
| `is_registered_signer` | Read-only check of signer authorization. |
| `capture_snapshot` | Validate, hash, verify signature, and append a new snapshot. |
| `head` / `get_snapshot` | Read the chain checkpoint or one stored snapshot. |
| `compute_state_root` / `chain_hash` | Recompute either digest off-chain or on-chain. |
| `verify_chain` | Full re-derivation of a module's chain against its stored head. |
| `export_snapshots` | Bounded, admin-only, self-contained range export. |
| `verify_export` | Storage-free verification of an exported bundle. |

Re-exported from the crate root as `snapshot_genesis_hash`, `snapshot_head`,
`verify_snapshot_chain`, and `verify_snapshot_export` — the unaliased names
(`genesis_hash`, `head`, `verify_chain`, `verify_export`) are already taken by
`shared::audit_ledger`'s crate-root re-export.

## Who can do what

| Action | Required role |
|---|---|
| Register / revoke a signer key | `Role::Admin` |
| Capture a snapshot | `Role::Admin` or `Role::Support` |
| Export a bundle | `Role::Admin` |
| Read the head, a snapshot, verify a chain or a bundle | Anyone (read-only, no auth required) |

## Operational edge cases

| Situation | Behavior |
|---|---|
| Caller lacks `Admin`/`Support` | `SnapshotError::Unauthorized` before any field or signature is touched. |
| No fields supplied | `SnapshotError::EmptyFields`. |
| More than `MAX_SNAPSHOT_FIELDS` (64) fields | `SnapshotError::TooManyFields`, bounding gas per call. |
| Signer key never registered, or revoked | `SnapshotError::UnknownSigner` — checked before the Ed25519 call runs. |
| Signer key registered but signature invalid | The transaction aborts inside `ed25519_verify`; no partial write. This mirrors `Address::require_auth`'s own trap-on-failure behavior elsewhere in this workspace. |
| Reading a snapshot id beyond the chain head | `None` from `get_snapshot`, `SnapshotError::SnapshotNotFound` from `export_snapshots`. |
| `verify_chain` on a chain with a tampered or missing entry | Reports the first bad id and the specific `SnapshotVerificationFailure` instead of a bare boolean. |
| Chain longer than `MAX_VERIFY_SNAPSHOTS` (2,000) | `SnapshotVerificationFailure::ScanLimitExceeded`; export and verify in bounded ranges against a checkpoint instead. |
| Admin rotates signer keys | Register the new key, then revoke the old one; snapshots already captured keep whichever key signed them, so history stays verifiable even against a since-revoked key. |
| Two contract subsystems want independent evidence trails | Call every function with a distinct `module` symbol; chains, heads, and ids are all scoped per module. |

## Rollback and recovery

Snapshots are append-only by design — there is no update or delete entry
point, so a bad capture cannot be quietly edited away.

1. **Compromised signer key.** Call `revoke_signer` immediately so no further
   snapshots can be attributed to that key. Run `verify_chain`; everything up
   to `first_invalid_id - 1` (or the full length, if verification is clean)
   remains trustworthy. Capture a fresh snapshot under a newly registered
   key. Auditors treat the old key's snapshots as attributed-but-suspect
   rather than deleting them, preserving the evidence trail.
2. **Contract rollback (upgrade revert, restored snapshot) behind the
   published head.** The next `verify_chain` call reports
   `SnapshotVerificationFailure::HeadMismatch`, because the re-derived chain
   no longer reproduces the stored head — the same signal
   `shared::audit_ledger` gives for the same situation. Re-anchor by
   publishing the re-derived head off-chain once the cause is understood;
   history itself is never rewritten.
3. **Suspected tamper of stored fields.** `verify_chain`'s
   `StateRootMismatch`/`ChainBroken` failures identify the first affected
   `snapshot_id`. Export `1..first_invalid_id - 1` with `export_snapshots`
   and archive it with `verify_export` as the trusted prefix before
   investigating further.

## Compatibility and migration

Purely additive: new storage keys (`SnapshotKey::Signer`, `SnapshotKey::Head`,
`SnapshotKey::Entry`), no changes to any existing module or contract
interface. A contract adopts it by calling `capture_snapshot` from whichever
entry point it wants to expose for audit/debug tooling; no existing behavior
changes until that call is wired in. Schema version `1` is the only version
today; a future bump must document the migration here and in
`shared::snapshot`'s module docs before `SNAPSHOT_SCHEMA_VERSION` changes.
