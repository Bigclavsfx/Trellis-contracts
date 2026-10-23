# Shared contract library

The `shared` crate contains types and utilities reused by every contract in the
workspace.

## Error codes

All contracts must return stable and documented numeric error codes. Stable
codes allow backend and frontend applications to map contract failures to
consistent user-facing messages without depending on error strings.

The shared error enum can be imported through either path:

```rust
shared::Error
shared::errors::Error
```

## Error-code namespaces

Numeric codes are stable within an error domain. Never change or reuse a
published value. The source enums are `shared::errors::Error`, each contract's
local `#[contracterror]` enum, and `shared::batch::BatchError`.

| Domain / enum | Numeric codes | Notes |
|---|---:|---|
| `Shared` / `Error` | `1-28` | Common authorization, validation, state, and configuration errors (reserved values are not assigned). |
| `Aid` / `AidError` | `100-107` | Aid lifecycle and authorization errors. |
| `AccessControl` / `AccessControlError` | `200-214` | Roles, invitations, authorization, and rate limiting. |
| `Oracle` / `OracleError` | `500-510` | Feed, submitter, freshness, and validation errors. |
| `Payments` / `Error` | `700-711` | Payment and escrow errors. |
| `Batch` / `BatchError` | `800-805` | Bounded multi-operation execution. |
| `Upgradeability` / `UpgradeError` | `900-911` | Upgrade registry, proposal, validation, and migration failures. |
| `Import` / `ImportError` | `940-948` | Import validation and execution. |
| `SupportAccess` / `ImpersonationError` | `960-973` | Time-bounded, explicitly scoped support sessions and audit failures. |
| `Shared` / `Error` | `950-952` | Aid compatibility errors retained in the shared enum. |
| `Shared` / `Error` | `1000-1008` | Marketplace compatibility aliases retained in the shared enum. |
| `Marketplace` / `MarketError` | `2000-2023` | Marketplace-local errors. |
| `Snapshot` / `SnapshotError` | `1100-1106` | Signed state snapshot export errors (`shared::snapshot`). |

`ErrorDomain` disambiguates overlapping or legacy numeric spaces. `describe_error`
maps supported domain/code pairs to a stable public string, category,
retryability, safe message, and recovery guidance. Add a mapping and update the
coverage test whenever a contract error is added. Unrecognized pairs use the
safe `UNEXPECTED_ERROR` fallback.

## Usage

Contracts can import and return the re-exported enum directly:

```rust
use shared::Error;

pub fn example() -> Result<(), Error> {
    Err(Error::InvalidArgument)
}
```

The Aid contract initialization function provides the first workspace example.
It returns `Error::AlreadyInitialized` when initialization is attempted more
than once.

## Maintenance rules

1. Never change the numeric value of a published error variant.
2. Never assign the same numeric value to multiple variants.
3. Put module-specific errors inside the module's assigned range.
4. Use the `900-999` range only for errors shared by multiple contracts.
5. Update `docs/ERRORS.md` and this catalog whenever a public error is introduced.
6. Add/extend the exhaustive mapping test for the affected error domain.

## Compatibility, quota, and config helpers

| Module | Purpose | Docs |
|---|---|---|
| `shared::compat` | Schema version metadata (`CURRENT_RECORD_SCHEMA_VERSION = 2`), `migrate_v1_to_v2` / `downgrade_v2_to_v1` transforms, `VersionedAidRecord` envelope | `docs/COMPATIBILITY.md` |
| `shared::quota` | Per-actor `(actor, resource)` quota enforcement (`check_and_consume`), maintainer `get_quota_status` / `reset_quota` diagnostics, fail-open when unconfigured | `docs/QUOTA.md` |
| `shared::config` | Typed env validation (`validate_full_config`, `Environment`), `UnsafeSecret` / `ConfigMissing` fail-fast errors, `RedactedSecret` previews that never print full secrets | `docs/CONFIGURATION.md` |
| `shared::timeline` | User-facing activity timeline: `Public` / `Participant` / `Maintainer` visibility filtering, stable `ResourceLink` anchors, cursor pagination, and a maintainer-only audit store that is structurally separate from the user timeline | `docs/TIMELINE.md` |
| `shared::operational_metadata` | Data minimization review and retention enforcement for operational metadata across Treasury, Aid, Referral, Governance, Oracle, and Marketplace modules with testable two-phase deletion, hold management, and migration adapters | `docs/OPERATIONAL_METADATA_RETENTION.md` |
| `shared::audit_ledger` | Tamper-evident, hash-chained ledger for privileged and financial events: `append_event` / `append_privileged` / `append_financial`, `verify_chain`, bounded `export_ledger` + storage-free `verify_export`, and a `publish_head_checkpoint` anchor event | `docs/AUDIT_LEDGER.md` |
| `shared::impersonation` | Authenticated support sessions restricted to explicit resource scopes, scope-checked and audited actions, expiry/revocation events, and a user-safe expiry notice | `docs/SCOPED_IMPERSONATION.md` |
| `shared::ledger_sequence` | Test-only deterministic ledger control (`LedgerSequenceHarness`): explicit sequence plus derived timestamp, forward-only `at()`, and `order_of` / `classify` boundary classification for same-ledger, next-ledger, expired-ledger and out-of-order submissions | `docs/LEDGER_ASSUMPTIONS.md` |
| `shared::rollout_guard` | Feature-flag rollout guard with telemetry monitoring, automated rollback triggers (consecutive failures, error rates, invariant breaches), clean state verification across Treasury, Aid, Referral, Governance, Oracle, and Marketplace, and re-arming protection | `docs/FEATURE_FLAG_ROLLOUT_GUARD.md` |
| `shared::export` | Permission-aware export pipeline across Treasury, Aid, Referral, Governance, Oracle, and Marketplace: bounded memory chunking (`DEFAULT_EXPORT_CHUNK_SIZE = 25`, `MAX_EXPORT_CHUNK_SIZE = 50`), in-flight cancellation (`cancel_export_stream`), forbidden field purging, and cumulative integrity digests | `docs/EXPORT_PIPELINE.md` |

Ledger boundary tests run with `cargo test -p shared --lib test_ledger_sequence`
(see `docs/LEDGER_ASSUMPTIONS.md` for the boundary table and determinism rules).

Contributor health checks live in `scripts/diagnostics.sh` (see
`docs/DIAGNOSTICS.md`); deployment config gating lives in
`scripts/validate-config.sh`.

## Event schemas

Protocol events use stable two-part topic tuples. Off-chain indexers should
match both topic symbols and decode the data using the documented order and
types.

The legacy single-symbol constants and generic `emit` helper remain available
for backward compatibility. New protocol code should use the typed helpers in
`shared::events`.

| Event | Helper | Topics | Data |
|---|---|---|---|
| `AidCreated` | `emit_aid_created` | `("aid", "created")` | `(u64 aid_id, Address donor, Address recipient, i128 amount, u64 created_at, u64 expires_at)` |
| `AidClaimed` | `emit_aid_claimed` | `("aid", "claimed")` | `(u64 aid_id, Address claimant, u64 claimed_at)` |
| `AidSettled` | `emit_aid_settled` | `("aid", "settled")` | `(u64 aid_id, Address recipient, i128 amount, u64 settled_at)` |
| `AidRefunded` | `emit_aid_refunded` | `("aid", "refunded")` | `(u64 aid_id, Address donor, i128 amount, u64 refunded_at)` |
| `CommissionPaid` | `emit_commission_paid` | `("comm", "paid")` | `(Address recipient, i128 amount, u64 paid_at)` |
| `TreasuryDeposit` | `emit_treasury_deposit` | `("treasury", "deposit")` | `(Symbol category, Address depositor, i128 amount, i128 new_balance)` |
| `TreasuryWithdrawal` | `emit_treasury_withdrawal` | `("treasury", "withdraw")` | `(Symbol category, Address recipient, i128 amount, i128 remaining_balance)` |
| `ContractPaused` | `emit_contract_paused` | `("contract", "paused")` | `(Address actor, u64 paused_at)` |
| `ContractResumed` | `emit_contract_resumed` | `("contract", "resumed")` | `(Address actor, u64 resumed_at)` |
| `ContractUpgraded` | `emit_contract_upgraded` | `("contract", "upgraded")` | `(Address actor, BytesN<32> wasm_hash, u64 upgraded_at)` |
| `AuditHeadCheckpoint` | `publish_head_checkpoint` (`shared::audit_ledger`) | `("audit", "head")` | `(u64 length, BytesN<32> head_hash, u32 last_ledger, u64 last_timestamp)` |
| `ModuleInitialized` | `emit_module_initialized` | `("logging", "initialized")` | `(Symbol module, u32 version, Address caller, u64 initialized_at)` |
| `ActionExecuted` | `emit_action_executed` | `("logging", "action")` | `(Symbol module, Symbol action, Address caller, bool success, u64 executed_at)` |
| `PermissionChanged` | `emit_permission_changed` | `("logging", "permission")` | `(Symbol module, Symbol role, Address subject, bool granted, u64 changed_at)` |

### Event stability rules

1. Do not change a published event's topic tuple.
2. Do not reorder, remove, or change the type of existing data fields.
3. Add new event versions instead of silently changing an existing schema.
4. Use the typed helper whenever one exists.
5. Update this table and the event tests whenever a new schema is introduced.
