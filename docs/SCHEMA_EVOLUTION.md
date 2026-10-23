# Schema Evolution Guardrails

This document describes the schema evolution guardrails implemented in [`shared::schema_evolution`](../shared/src/schema_evolution.rs) for stored records and public API responses across the Trellis Soroban contract suite.

---

## 1. Motivation & Objectives

In decentralized contract ecosystems, data structures and client interfaces evolve across versions. Without deterministic evolution guardrails:
1. **Silent Drift**: Unrecognized or unexpected fields might be silently dropped or stored, creating state drift or deserialization panics.
2. **Backward Incompatibility**: Older indexers, frontends, or partner contracts might break when fields are renamed, removed, or changed.
3. **Write Pollution**: Deprecated fields might continue to be written by outdated clients, preventing legacy data retirement.
4. **Security Vulnerabilities**: Re-introducing retired or tombstoned field semantics can cause unauthorized state mutations.

The schema evolution framework provides **deterministic, compile-time and runtime guardrails** for both persistent ledger records and public API response payloads.

---

## 2. Core Concepts & Lifecycle States

### Field Status (`FieldStatus`)
Every field in a schema is categorized into an explicit lifecycle state:

| Status | Code | Description |
|:---|:---:|:---|
| `Active` | 1 | Required field. Must exist in writes; fully supported in reads and API responses. |
| `Optional` | 2 | Permissible field. May be omitted by clients or stored records. |
| `Deprecated` | 3 | Legacy field flagged for retirement. Handled according to `DeprecatedFieldPolicy`. |
| `Tombstoned` | 4 | Permanently retired and forbidden field. Presence in any payload strictly fails. |

### Unknown Field Policy (`UnknownFieldPolicy`)
Governs behavior when a payload contains fields not declared in the registered schema:

- **`Reject` (Strict / Fail-Closed)**: Rejects the operation with `SchemaEvolutionError::UnknownField`. Recommended for all state-writing operations and security-critical endpoints.
- **`Ignore` (Permissive / Forward-Compatible)**: Safely ignores undeclared fields. Suitable for read paths or flexible query endpoints.

### Deprecated Field Policy (`DeprecatedFieldPolicy`)
Governs behavior when a payload contains fields marked as `Deprecated`:

- **`Allow`**: Deprecated fields are accepted and processed.
- **`Reject`**: Deprecated fields are rejected with `SchemaEvolutionError::DeprecatedField`.
- **`DisallowOnWrite`**: Deprecated fields are rejected on write paths (`is_write = true`) to prevent new legacy entries, but accepted on read or migration paths.

---

## 3. Versioned Envelopes

### Stored Record Envelope (`StoredRecordEnvelope<T>`)
Wraps persistent ledger records with schema metadata:

```rust
pub struct StoredRecordEnvelope<T> {
    pub schema_version: u32,
    pub schema_id: Symbol,
    pub is_migrated: bool,
    pub record: T,
}
```

- **Read Guard (`validate_read`)**: Validates that `schema_id` matches and that `schema_version` falls within `[min_compatible_version, max_compatible_version]`.
- Emits `MigrationRequired` if the record's version is older than `min_compatible_version`.
- Emits `UnsupportedVersion` if the record's version exceeds `max_compatible_version`.

### Public API Response Envelope (`PublicApiResponseEnvelope<T>`)
Standardized response wrapper for contract queries and external consumers:

```rust
pub struct PublicApiResponseEnvelope<T> {
    pub schema_version: u32,
    pub min_supported_version: u32,
    pub max_supported_version: u32,
    pub is_deprecated: bool,
    pub deprecation_warning: Option<Symbol>,
    pub payload: T,
}
```

- **Client Version Negotiation (`new_for_client`)**:
  - Validates that the requested client version is within supported bounds.
  - Automatically flags older client requests as deprecated (`is_deprecated = true`) and attaches warning guidance (`deprecation_warning = Some(symbol_short!("deprec"))`).

---

## 4. Canonical Module Schemas

The framework includes canonical schema builders for key Trellis modules:

| Module | Schema ID | Active Version | Compatible Range | Unknown Policy | Deprecated Policy |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Aid Disbursement (Record)** | `aid_rec` | 2 | [1, 2] | `Reject` | `DisallowOnWrite` |
| **Aid Disbursement (API)** | `aid_api` | 2 | [1, 2] | `Reject` | `Allow` |
| **Treasury Reserves** | `treas_rec` | 2 | [1, 2] | `Reject` | `DisallowOnWrite` |
| **Referral Tracking** | `ref_rec` | 1 | [1, 1] | `Reject` | `Reject` |
| **Governance Proposals** | `gov_prop` | 1 | [1, 1] | `Reject` | `Reject` |
| **Oracle Submissions** | `ora_sub` | 1 | [1, 1] | `Reject` | `Reject` |
| **Marketplace Listings** | `mkt_list` | 1 | [1, 1] | `Reject` | `Reject` |

---

## 5. Error Taxonomy & Codes

Schema evolution errors map deterministically to protocol error codes in [`shared::errors`](../shared/src/errors.rs) and the error taxonomy in [`shared::error_taxonomy`](../shared/src/error_taxonomy.rs):

| Schema Evolution Error | Error Code | Name | Description |
|:---|:---:|:---|:---|
| `UnknownField` | 41 | `UNKNOWN_FIELD` | Payload contained an undeclared field under a strict policy. |
| `DeprecatedField` | 42 | `DEPRECATED_FIELD` | Payload contained a deprecated field rejected by policy. |
| `TombstonedField` | 41 | `UNKNOWN_FIELD` | Payload contained a permanently forbidden tombstoned field. |
| `MissingRequiredField` | 41 | `UNKNOWN_FIELD` | An `Active` field was omitted from the write payload. |
| `UnsupportedVersion` | 41 | `UNKNOWN_FIELD` | Schema version falls outside supported compatibility bounds. |
| `MigrationRequired` | 41 | `UNKNOWN_FIELD` | Record schema version is too old and requires prior migration. |
| `IncompatibleRange` | 41 | `UNKNOWN_FIELD` | Schema definition min/max bounds are internally inverted or invalid. |

---

## 6. Schema Evolution Lifecycle Runbook

### Adding a New Field
1. Register field with `FieldStatus::Optional` in version $V+1$.
2. Once all indexers and clients are upgraded, transition field to `FieldStatus::Active` in version $V+2$.

### Deprecating a Field
1. Transition field status to `FieldStatus::Deprecated`.
2. Set schema `deprecated_policy` to `DeprecatedFieldPolicy::DisallowOnWrite`. New writes cannot use the field, but existing data can still be read.
3. API endpoints return `is_deprecated: true` and `deprecation_warning: Some("deprec")` to guide consumers.

### Tombstoning a Field
1. Transition field status to `FieldStatus::Tombstoned`.
2. Any presence of this field in read, write, or API interactions is strictly rejected.
