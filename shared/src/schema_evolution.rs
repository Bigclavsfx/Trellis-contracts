//! Schema evolution guardrails for stored records and public API responses.
//!
//! Provides deterministic guardrails when contracts or external clients evolve:
//! - Versioned schema definitions with explicit field states: [`FieldStatus::Active`],
//!   [`FieldStatus::Optional`], [`FieldStatus::Deprecated`], and [`FieldStatus::Tombstoned`].
//! - Explicit, configurable failure behavior for unknown and deprecated fields:
//!   [`UnknownFieldPolicy::Reject`] vs [`UnknownFieldPolicy::Ignore`], and
//!   [`DeprecatedFieldPolicy::Allow`], [`DeprecatedFieldPolicy::Reject`], or [`DeprecatedFieldPolicy::DisallowOnWrite`].
//! - Versioned envelopes for stored records ([`StoredRecordEnvelope`]) and public API responses
//!   ([`PublicApiResponseEnvelope`]).
//! - Migration notes and compatibility bounds checking across modules (Aid, Treasury, Referral,
//!   Governance, Oracle, and Marketplace).

use soroban_sdk::{contracterror, contracttype, symbol_short, Env, Map, Symbol, Val, Vec};

use crate::errors::Error;

/// Lifecycle state of an individual field within a versioned schema.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FieldStatus {
    /// Active field: must be present in writes; fully supported in reads and APIs.
    Active = 1,
    /// Optional field: may be omitted by clients or stored records.
    Optional = 2,
    /// Deprecated field: retained for backward compatibility, but flagged for removal.
    /// Rejected on writes or queries depending on [`DeprecatedFieldPolicy`].
    Deprecated = 3,
    /// Tombstoned field: permanently retired and forbidden. Presence in any record
    /// or API payload is strictly rejected to prevent security or data drift.
    Tombstoned = 4,
}

/// Guardrail policy for fields present in payload that are not declared in the schema.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum UnknownFieldPolicy {
    /// Strict / fail-closed: reject any undeclared field with an error.
    /// Recommended for write operations and sensitive endpoints.
    Reject = 1,
    /// Permissive / forward-compatible: safely ignore undeclared fields on read/query paths.
    Ignore = 2,
}

/// Guardrail policy for deprecated fields encountered in payloads or client requests.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DeprecatedFieldPolicy {
    /// Deprecated fields are accepted and processed (may annotate response with warning).
    Allow = 1,
    /// Strict: deprecated fields are rejected immediately with an error.
    Reject = 2,
    /// Write-safe: deprecated fields are rejected on write operations to prevent new legacy entries,
    /// but accepted on read/migration paths.
    DisallowOnWrite = 3,
}

/// Specification of a single field within a versioned schema.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldDefinition {
    /// Field identifier.
    pub name: Symbol,
    /// Current evolution status of this field.
    pub status: FieldStatus,
    /// Schema version when this field was introduced.
    pub since_version: u32,
    /// Schema version when this field was deprecated (if applicable).
    pub deprecated_at: Option<u32>,
    /// Declarative migration note for developers and indexers.
    pub migration_note: Option<Symbol>,
}

/// Comprehensive versioned schema definition for stored records or API responses.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedSchema {
    /// Canonical schema identifier (e.g. "aid_rec", "aid_api", "ref_rec").
    pub schema_id: Symbol,
    /// Active / current schema version.
    pub version: u32,
    /// Oldest schema version supported without mandatory prior migration.
    pub min_compatible_version: u32,
    /// Highest schema version this contract build is capable of decoding.
    pub max_compatible_version: u32,
    /// List of registered field definitions.
    pub fields: Vec<FieldDefinition>,
    /// Policy for unknown / undeclared fields.
    pub unknown_policy: UnknownFieldPolicy,
    /// Policy for deprecated fields.
    pub deprecated_policy: DeprecatedFieldPolicy,
}

/// Deterministic errors emitted by schema evolution guardrails.
#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SchemaEvolutionError {
    /// Requested or decoded version is outside supported compatibility bounds.
    UnsupportedVersion = 1,
    /// A required active field is missing from the payload.
    MissingRequiredField = 2,
    /// An unknown field was supplied under `UnknownFieldPolicy::Reject`.
    UnknownField = 3,
    /// A deprecated field was supplied under `DeprecatedFieldPolicy::Reject` or on write.
    DeprecatedField = 4,
    /// A tombstoned (permanently retired) field was detected.
    TombstonedField = 5,
    /// The stored record version is older than `min_compatible_version` and must be migrated.
    MigrationRequired = 6,
    /// Schema definition bounds are invalid (e.g. min > max or version out of range).
    IncompatibleRange = 7,
    /// Schema migration transformation failed validation.
    MigrationFailed = 8,
}

impl From<SchemaEvolutionError> for Error {
    fn from(err: SchemaEvolutionError) -> Self {
        match err {
            SchemaEvolutionError::UnsupportedVersion => Error::UnsupportedSchemaVersion,
            SchemaEvolutionError::MissingRequiredField => Error::InvalidArgument,
            SchemaEvolutionError::UnknownField => Error::UnknownField,
            SchemaEvolutionError::DeprecatedField => Error::DeprecatedField,
            SchemaEvolutionError::TombstonedField => Error::DeprecatedField,
            SchemaEvolutionError::MigrationRequired => Error::UnsupportedSchemaVersion,
            SchemaEvolutionError::IncompatibleRange => Error::ConfigInvalid,
            SchemaEvolutionError::MigrationFailed => Error::SchemaMigrationFailed,
        }
    }
}

/// Validates a raw payload map against a versioned schema and evolution policy.
///
/// # Invariants Enforced:
/// 1. Schema bounds: `min_compatible_version <= version <= max_compatible_version`.
/// 2. Missing required fields: Every field marked [`FieldStatus::Active`] must exist in `payload`.
/// 3. Tombstoned fields: Any field marked [`FieldStatus::Tombstoned`] is strictly rejected.
/// 4. Unknown fields: Any field in `payload` not declared in `schema.fields` is rejected
///    if `schema.unknown_policy == UnknownFieldPolicy::Reject`.
/// 5. Deprecated fields: Any field marked [`FieldStatus::Deprecated`] is rejected if:
///    - `schema.deprecated_policy == DeprecatedFieldPolicy::Reject`, or
///    - `is_write == true` and `schema.deprecated_policy == DeprecatedFieldPolicy::DisallowOnWrite`.
pub fn validate_fields(
    schema: &VersionedSchema,
    payload: &Map<Symbol, Val>,
    is_write: bool,
) -> Result<(), SchemaEvolutionError> {
    if schema.min_compatible_version > schema.max_compatible_version
        || schema.version < schema.min_compatible_version
        || schema.version > schema.max_compatible_version
    {
        return Err(SchemaEvolutionError::IncompatibleRange);
    }

    // 1. Ensure all active (required) fields are present.
    for field in schema.fields.iter() {
        if field.status == FieldStatus::Active && !payload.contains_key(field.name.clone()) {
            return Err(SchemaEvolutionError::MissingRequiredField);
        }
    }

    // 2. Validate all supplied fields against the schema allow-list and status.
    for supplied_key in payload.keys() {
        let mut found_def: Option<FieldDefinition> = None;
        for field in schema.fields.iter() {
            if field.name == supplied_key {
                found_def = Some(field);
                break;
            }
        }

        match found_def {
            None => {
                // Undeclared / unknown field.
                if schema.unknown_policy == UnknownFieldPolicy::Reject {
                    return Err(SchemaEvolutionError::UnknownField);
                }
            }
            Some(def) => {
                // Tombstoned field is always forbidden.
                if def.status == FieldStatus::Tombstoned {
                    return Err(SchemaEvolutionError::TombstonedField);
                }

                // Deprecated field check.
                if def.status == FieldStatus::Deprecated {
                    match schema.deprecated_policy {
                        DeprecatedFieldPolicy::Reject => {
                            return Err(SchemaEvolutionError::DeprecatedField);
                        }
                        DeprecatedFieldPolicy::DisallowOnWrite => {
                            if is_write {
                                return Err(SchemaEvolutionError::DeprecatedField);
                            }
                        }
                        DeprecatedFieldPolicy::Allow => {}
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validates version compatibility for a given record or client version.
pub fn ensure_version_compatible(
    schema: &VersionedSchema,
    target_version: u32,
) -> Result<(), SchemaEvolutionError> {
    if target_version < schema.min_compatible_version {
        return Err(SchemaEvolutionError::MigrationRequired);
    }
    if target_version > schema.max_compatible_version {
        return Err(SchemaEvolutionError::UnsupportedVersion);
    }
    Ok(())
}

/// Versioned storage envelope for persistent or instance ledger records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecordEnvelope<T> {
    /// Schema version stamped on this record when written.
    pub schema_version: u32,
    /// Schema identifier matching the registered record type.
    pub schema_id: Symbol,
    /// Whether this record was transformed via forward migration.
    pub is_migrated: bool,
    /// Typed payload.
    pub record: T,
}

impl<T> StoredRecordEnvelope<T> {
    /// Construct a new stored record envelope for current writes.
    pub fn new(schema_version: u32, schema_id: Symbol, record: T) -> Self {
        Self {
            schema_version,
            schema_id,
            is_migrated: false,
            record,
        }
    }

    /// Guarded read check ensuring the envelope version is within supported bounds.
    pub fn validate_read(&self, schema: &VersionedSchema) -> Result<(), SchemaEvolutionError> {
        if self.schema_id != schema.schema_id {
            return Err(SchemaEvolutionError::UnsupportedVersion);
        }
        ensure_version_compatible(schema, self.schema_version)
    }
}

/// Versioned public API response envelope for contract queries and external consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicApiResponseEnvelope<T> {
    /// Schema version of the returned response.
    pub schema_version: u32,
    /// Minimum client version supported by this endpoint.
    pub min_supported_version: u32,
    /// Maximum client version supported by this endpoint.
    pub max_supported_version: u32,
    /// True if the client requested a deprecated schema version or the endpoint is transitioning.
    pub is_deprecated: bool,
    /// Human-readable deprecation warning or migration guidance symbol.
    pub deprecation_warning: Option<Symbol>,
    /// Typed payload.
    pub payload: T,
}

impl<T> PublicApiResponseEnvelope<T> {
    /// Construct a response for the current active schema version.
    pub fn new_current(schema: &VersionedSchema, payload: T) -> Self {
        Self {
            schema_version: schema.version,
            min_supported_version: schema.min_compatible_version,
            max_supported_version: schema.max_compatible_version,
            is_deprecated: false,
            deprecation_warning: None,
            payload,
        }
    }

    /// Construct a response negotiating client-requested version compatibility.
    ///
    /// # Error Behavior:
    /// - If `client_version < min_compatible_version`: Returns [`SchemaEvolutionError::UnsupportedVersion`].
    /// - If `client_version > max_compatible_version`: Returns [`SchemaEvolutionError::UnsupportedVersion`].
    /// - If `client_version` is an older, deprecated version: Emits payload with `is_deprecated = true`
    ///   and sets `deprecation_warning = Some("deprec")`.
    pub fn new_for_client(
        schema: &VersionedSchema,
        client_version: Option<u32>,
        payload: T,
    ) -> Result<Self, SchemaEvolutionError> {
        let version = client_version.unwrap_or(schema.version);
        if version < schema.min_compatible_version || version > schema.max_compatible_version {
            return Err(SchemaEvolutionError::UnsupportedVersion);
        }

        let is_deprecated = version < schema.version;
        let deprecation_warning = if is_deprecated {
            Some(symbol_short!("deprec"))
        } else {
            None
        };

        Ok(Self {
            schema_version: version,
            min_supported_version: schema.min_compatible_version,
            max_supported_version: schema.max_compatible_version,
            is_deprecated,
            deprecation_warning,
            payload,
        })
    }
}

/// Declarative migration notes describing a schema transition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationStepNote {
    pub from_version: u32,
    pub to_version: u32,
    pub summary: Symbol,
    pub added_fields: Vec<Symbol>,
    pub deprecated_fields: Vec<Symbol>,
    pub tombstoned_fields: Vec<Symbol>,
    pub rollback_safe: bool,
}

// ---------------------------------------------------------------------------
// Canonical Schema Builders for Trellis Modules
// ---------------------------------------------------------------------------

/// Builds the canonical versioned schema for Aid Disbursement stored records.
pub fn build_aid_record_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);

    // V1 fields
    fields.push_back(FieldDefinition {
        name: symbol_short!("id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("donor"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("recip"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("amount"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("expiry"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("status"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });

    // V2 additions
    fields.push_back(FieldDefinition {
        name: symbol_short!("token"),
        status: FieldStatus::Active,
        since_version: 2,
        deprecated_at: None,
        migration_note: Some(symbol_short!("tok_bind")),
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("sch_ver"),
        status: FieldStatus::Active,
        since_version: 2,
        deprecated_at: None,
        migration_note: None,
    });

    // Legacy unhashed notes field: deprecated in V2, tombstoned if V3
    if version >= 3 {
        fields.push_back(FieldDefinition {
            name: symbol_short!("raw_memo"),
            status: FieldStatus::Tombstoned,
            since_version: 1,
            deprecated_at: Some(2),
            migration_note: Some(symbol_short!("tombstone")),
        });
    } else {
        fields.push_back(FieldDefinition {
            name: symbol_short!("raw_memo"),
            status: FieldStatus::Deprecated,
            since_version: 1,
            deprecated_at: Some(2),
            migration_note: Some(symbol_short!("use_hash")),
        });
    }

    VersionedSchema {
        schema_id: symbol_short!("aid_rec"),
        version,
        min_compatible_version: 1,
        max_compatible_version: core::cmp::max(2, version),
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::DisallowOnWrite,
    }
}

/// Builds the canonical versioned schema for Aid Disbursement public API responses.
pub fn build_aid_api_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);
    fields.push_back(FieldDefinition {
        name: symbol_short!("aid_id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("donor"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("recip"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("token"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("amount"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("expiry"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("status"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("sch_ver"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("legacy_id"),
        status: FieldStatus::Deprecated,
        since_version: 1,
        deprecated_at: Some(2),
        migration_note: Some(symbol_short!("aid_id_v2")),
    });

    VersionedSchema {
        schema_id: symbol_short!("aid_api"),
        version,
        min_compatible_version: 1,
        max_compatible_version: 2,
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::Allow,
    }
}

/// Builds the canonical versioned schema for Treasury balance/reserve records.
pub fn build_treasury_record_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);
    fields.push_back(FieldDefinition {
        name: symbol_short!("token"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("category"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("amount"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("last_sync"),
        status: FieldStatus::Optional,
        since_version: 2,
        deprecated_at: None,
        migration_note: Some(Symbol::new(env, "audit_sync")),
    });

    VersionedSchema {
        schema_id: symbol_short!("treas_rec"),
        version,
        min_compatible_version: 1,
        max_compatible_version: 2,
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::DisallowOnWrite,
    }
}

/// Builds the canonical versioned schema for Referral tracking records.
pub fn build_referral_record_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);
    fields.push_back(FieldDefinition {
        name: symbol_short!("wallet"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("referrer"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("commiss"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("tier"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });

    VersionedSchema {
        schema_id: symbol_short!("ref_rec"),
        version,
        min_compatible_version: 1,
        max_compatible_version: 1,
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::Reject,
    }
}

/// Builds the canonical versioned schema for Governance proposals.
pub fn build_governance_proposal_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);
    fields.push_back(FieldDefinition {
        name: symbol_short!("prop_id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("proposer"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("action"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("approvals"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("status"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: Symbol::new(env, "created_at"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: Symbol::new(env, "expires_at"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });

    VersionedSchema {
        schema_id: symbol_short!("gov_prop"),
        version,
        min_compatible_version: 1,
        max_compatible_version: 1,
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::Reject,
    }
}

/// Builds the canonical versioned schema for Oracle price submissions.
pub fn build_oracle_submission_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);
    fields.push_back(FieldDefinition {
        name: symbol_short!("id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("submitter"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("feed_id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("price"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("decimals"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("timestamp"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("nonce"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });

    VersionedSchema {
        schema_id: symbol_short!("ora_sub"),
        version,
        min_compatible_version: 1,
        max_compatible_version: 1,
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::Reject,
    }
}

/// Builds the canonical versioned schema for Marketplace listings.
pub fn build_marketplace_listing_schema(env: &Env, version: u32) -> VersionedSchema {
    let mut fields = Vec::new(env);
    fields.push_back(FieldDefinition {
        name: symbol_short!("id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("seller"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: Symbol::new(env, "collection"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("token_id"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("amount"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("price"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("currency"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("status"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });
    fields.push_back(FieldDefinition {
        name: symbol_short!("meta_hash"),
        status: FieldStatus::Active,
        since_version: 1,
        deprecated_at: None,
        migration_note: None,
    });

    VersionedSchema {
        schema_id: symbol_short!("mkt_list"),
        version,
        min_compatible_version: 1,
        max_compatible_version: 1,
        fields,
        unknown_policy: UnknownFieldPolicy::Reject,
        deprecated_policy: DeprecatedFieldPolicy::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, Env, IntoVal};

    fn make_valid_aid_payload(env: &Env) -> Map<Symbol, Val> {
        let mut map = Map::new(env);
        map.set(symbol_short!("id"), 1_u64.into_val(env));
        map.set(symbol_short!("donor"), 100_u32.into_val(env));
        map.set(symbol_short!("recip"), 200_u32.into_val(env));
        map.set(symbol_short!("amount"), 1000_i128.into_val(env));
        map.set(symbol_short!("expiry"), 5000_u32.into_val(env));
        map.set(symbol_short!("status"), 0_u32.into_val(env));
        map.set(symbol_short!("token"), 300_u32.into_val(env));
        map.set(symbol_short!("sch_ver"), 2_u32.into_val(env));
        map
    }

    #[test]
    fn valid_schema_payload_passes_validation() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let payload = make_valid_aid_payload(&env);

        let res = validate_fields(&schema, &payload, true);
        assert!(res.is_ok());
    }

    #[test]
    fn missing_required_field_fails_validation() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let mut payload = make_valid_aid_payload(&env);
        payload.remove(symbol_short!("amount"));

        let res = validate_fields(&schema, &payload, true);
        assert_eq!(res, Err(SchemaEvolutionError::MissingRequiredField));
    }

    #[test]
    fn unknown_field_fails_when_policy_is_reject() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let mut payload = make_valid_aid_payload(&env);
        payload.set(symbol_short!("unknown_f"), 42_u32.into_val(&env));

        let res = validate_fields(&schema, &payload, true);
        assert_eq!(res, Err(SchemaEvolutionError::UnknownField));
    }

    #[test]
    fn unknown_field_is_permitted_when_policy_is_ignore() {
        let env = Env::default();
        let mut schema = build_aid_record_schema(&env, 2);
        schema.unknown_policy = UnknownFieldPolicy::Ignore;

        let mut payload = make_valid_aid_payload(&env);
        payload.set(symbol_short!("unknown_f"), 42_u32.into_val(&env));

        let res = validate_fields(&schema, &payload, true);
        assert!(res.is_ok());
    }

    #[test]
    fn deprecated_field_fails_on_write_when_disallow_on_write() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);
        let mut payload = make_valid_aid_payload(&env);
        payload.set(symbol_short!("raw_memo"), 999_u32.into_val(&env));

        // On write path -> rejected
        let write_res = validate_fields(&schema, &payload, true);
        assert_eq!(write_res, Err(SchemaEvolutionError::DeprecatedField));

        // On read path -> allowed
        let read_res = validate_fields(&schema, &payload, false);
        assert!(read_res.is_ok());
    }

    #[test]
    fn deprecated_field_rejected_when_policy_is_reject() {
        let env = Env::default();
        let mut schema = build_aid_record_schema(&env, 2);
        schema.deprecated_policy = DeprecatedFieldPolicy::Reject;

        let mut payload = make_valid_aid_payload(&env);
        payload.set(symbol_short!("raw_memo"), 999_u32.into_val(&env));

        let res = validate_fields(&schema, &payload, false);
        assert_eq!(res, Err(SchemaEvolutionError::DeprecatedField));
    }

    #[test]
    fn tombstoned_field_is_strictly_rejected() {
        let env = Env::default();
        // Schema V3 tombstones raw_memo
        let schema = build_aid_record_schema(&env, 3);
        let mut payload = make_valid_aid_payload(&env);
        payload.set(symbol_short!("raw_memo"), 999_u32.into_val(&env));

        let res = validate_fields(&schema, &payload, false);
        assert_eq!(res, Err(SchemaEvolutionError::TombstonedField));
    }

    #[test]
    fn stored_record_envelope_read_guardrail() {
        let env = Env::default();
        let schema = build_aid_record_schema(&env, 2);

        // V2 record in envelope -> succeeds
        let env_v2 = StoredRecordEnvelope::new(2, symbol_short!("aid_rec"), 100_u64);
        assert!(env_v2.validate_read(&schema).is_ok());

        // V1 record in envelope (compatible) -> succeeds
        let env_v1 = StoredRecordEnvelope::new(1, symbol_short!("aid_rec"), 100_u64);
        assert!(env_v1.validate_read(&schema).is_ok());

        // V0 record (below min_compatible) -> migration required
        let env_v0 = StoredRecordEnvelope::new(0, symbol_short!("aid_rec"), 100_u64);
        assert_eq!(
            env_v0.validate_read(&schema),
            Err(SchemaEvolutionError::MigrationRequired)
        );

        // V99 future record (above max_compatible) -> unsupported
        let env_v99 = StoredRecordEnvelope::new(99, symbol_short!("aid_rec"), 100_u64);
        assert_eq!(
            env_v99.validate_read(&schema),
            Err(SchemaEvolutionError::UnsupportedVersion)
        );
    }

    #[test]
    fn public_api_response_envelope_negotiation() {
        let env = Env::default();
        let schema = build_aid_api_schema(&env, 2);

        // Current client requested version 2
        let current_resp =
            PublicApiResponseEnvelope::new_for_client(&schema, Some(2), 500_u32).unwrap();
        assert_eq!(current_resp.schema_version, 2);
        assert!(!current_resp.is_deprecated);
        assert_eq!(current_resp.deprecation_warning, None);

        // Legacy client requested version 1 (supported but deprecated)
        let legacy_resp =
            PublicApiResponseEnvelope::new_for_client(&schema, Some(1), 500_u32).unwrap();
        assert_eq!(legacy_resp.schema_version, 1);
        assert!(legacy_resp.is_deprecated);
        assert_eq!(legacy_resp.deprecation_warning, Some(symbol_short!("deprec")));

        // Unsupported old client version 0
        let too_old = PublicApiResponseEnvelope::new_for_client(&schema, Some(0), 500_u32);
        assert_eq!(too_old, Err(SchemaEvolutionError::UnsupportedVersion));

        // Unsupported future client version 99
        let too_new = PublicApiResponseEnvelope::new_for_client(&schema, Some(99), 500_u32);
        assert_eq!(too_new, Err(SchemaEvolutionError::UnsupportedVersion));
    }

    #[test]
    fn cross_module_schemas_are_well_formed() {
        let env = Env::default();
        let treas_schema = build_treasury_record_schema(&env, 2);
        assert_eq!(treas_schema.schema_id, symbol_short!("treas_rec"));
        assert_eq!(treas_schema.version, 2);

        let ref_schema = build_referral_record_schema(&env, 1);
        assert_eq!(ref_schema.schema_id, symbol_short!("ref_rec"));

        let gov_schema = build_governance_proposal_schema(&env, 1);
        assert_eq!(gov_schema.schema_id, symbol_short!("gov_prop"));

        let ora_schema = build_oracle_submission_schema(&env, 1);
        assert_eq!(ora_schema.schema_id, symbol_short!("ora_sub"));

        let mkt_schema = build_marketplace_listing_schema(&env, 1);
        assert_eq!(mkt_schema.schema_id, symbol_short!("mkt_list"));
    }
}
