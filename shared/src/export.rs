//! Data export workflow with privacy-safe schemas and retention limits (Issue #36).
//!
//! Users and maintainers need structured exports that include useful operational
//! data without leaking unrelated private information. This module makes that
//! boundary **explicit, reviewable, and testable**.
//!
//! ## Design
//!
//! - Every export is stamped with a **schema version** and **generation
//!   metadata** (who generated it, when, in what format, and when it expires),
//!   so a consumer can tell what they are looking at without guessing.
//! - Exports are **scoped**: a caller may only ever receive records inside
//!   their authorization scope. [`ExportScope::OwnRecords`] is limited to the
//!   caller's own records, [`ExportScope::Operational`] adds non-restricted
//!   operational records, and [`ExportScope::Full`] (maintainer only) includes
//!   everything. Out-of-scope records are **filtered out, never returned**.
//! - Record fields are **redacted** against an allow-list of safe fields
//!   ([`is_safe_field`]). Anything not on the list is dropped, so a sensitive
//!   field can never leak into an export by accident.
//! - Generated artifacts **expire**: every artifact carries an
//!   `expires_ledger`, and [`ExportArtifact::is_expired`] lets a consumer
//!   reject a stale artifact. Artifacts are also registered with the retention
//!   module under [`DataClass::Export`] so the standard cleanup workflow
//!   reclaims them.
//!
//! ## Schema history
//!
//! | Version | Changes |
//! |---:|---|
//! | `1` (current) | Initial export schema: metadata envelope + redacted record fields. |
//!
//! See `docs/EXPORT.md` for the workflow, scope table, and maintainer runbook.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, String,
    Symbol, Val, Vec,
};

use crate::auth::{has_role, Role};
use crate::errors::Error;
use crate::retention::{days_to_ledgers, put_record, DataClass, RetentionRecord};
use crate::storage::{persistent_get, persistent_has, persistent_set};

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

/// First export schema version.
pub const EXPORT_SCHEMA_V1: u32 = 1;

/// Current export schema version. All new exports must use this version.
pub const CURRENT_EXPORT_SCHEMA_VERSION: u32 = EXPORT_SCHEMA_V1;

/// Oldest export schema version still accepted on read paths.
pub const MIN_SUPPORTED_EXPORT_SCHEMA_VERSION: u32 = EXPORT_SCHEMA_V1;

/// Newest export schema version accepted on read paths (== current).
pub const MAX_SUPPORTED_EXPORT_SCHEMA_VERSION: u32 = CURRENT_EXPORT_SCHEMA_VERSION;

/// Returns `true` when `version` can be read by this build.
pub fn is_supported_version(version: u32) -> bool {
    (MIN_SUPPORTED_EXPORT_SCHEMA_VERSION..=MAX_SUPPORTED_EXPORT_SCHEMA_VERSION)
        .contains(&version)
}

/// Fail fast on unsupported schema versions for read and write paths.
pub fn ensure_supported_version(version: u32) -> Result<(), Error> {
    if is_supported_version(version) {
        Ok(())
    } else {
        Err(Error::UnsupportedSchemaVersion)
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Default maximum number of records in a single export.
pub const DEFAULT_MAX_EXPORT_RECORDS: u32 = 1_000;

/// Absolute maximum allowed records in one export (gas ceiling).
pub const ABSOLUTE_MAX_EXPORT_RECORDS: u32 = 10_000;

/// Default artifact validity window: 7 days at ~5 s/ledger.
pub const DEFAULT_EXPORT_TTL_LEDGERS: u32 = days_to_ledgers(7);

/// Hard ceiling on artifact validity. Matches the default retention window for
/// [`DataClass::Export`] (180 days) so an artifact never outlives the retention
/// policy that governs it.
pub const MAX_EXPORT_TTL_LEDGERS: u32 = days_to_ledgers(180);

/// Default chunk size for bounded memory streaming (records per chunk).
pub const DEFAULT_EXPORT_CHUNK_SIZE: u32 = 25;

/// Absolute maximum records per chunk to enforce gas & memory boundedness.
pub const MAX_EXPORT_CHUNK_SIZE: u32 = 50;

/// Storage key prefix for export streaming sessions.
const EXPORT_SESSION_KEY: Symbol = symbol_short!("exp_ses");

// ---------------------------------------------------------------------------
// Error codes (range 920–927)
// ---------------------------------------------------------------------------

/// Export workflow error codes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ExportError {
    /// The caller is not authorized for the requested export scope.
    ScopeDenied = 920,
    /// A specific record is outside the caller's authorization scope.
    RecordNotVisible = 921,
    /// The export exceeds the maximum allowed record count.
    ExportTooLarge = 922,
    /// The requested export scope is not recognised.
    InvalidScope = 923,
    /// The export artifact has expired.
    ExportExpired = 924,
    /// The requested TTL exceeds the maximum allowed validity window.
    TtlTooLong = 925,
    /// The export schema version is not supported.
    UnsupportedSchemaVersion = 926,
    /// The export request contains invalid parameters.
    InvalidRequest = 927,
    /// The export stream was cancelled by an authorized operator.
    ExportCancelled = 928,
    /// A forbidden field was detected in a record during strict export.
    ForbiddenFieldDetected = 929,
    /// The requested export streaming session was not found.
    SessionNotFound = 930,
    /// The provided chunk exceeds the bounded memory chunk size limit.
    ChunkTooLarge = 931,
    /// The export session is not in Active state (e.g. already completed or cancelled).
    SessionNotActive = 932,
    /// The submission cursor or sequence does not match the active session cursor.
    CursorMismatch = 933,
    /// The caller is unauthorized for export operations on this module.
    UnauthorizedModule = 934,
}

// ---------------------------------------------------------------------------
// Privacy-safe records
// ---------------------------------------------------------------------------

/// How sensitive an exportable record is. Controls record-level visibility
/// within an export scope.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordSensitivity {
    /// Safe for any caller to see (e.g. aggregate statistics).
    Public,
    /// Operational data; visible to support and maintainers.
    Operational,
    /// Restricted data; visible only under [`ExportScope::Full`].
    Restricted,
}

/// One privacy-safe field within an exportable record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportField {
    /// Field name. Must pass [`is_safe_field`] to appear in an export.
    pub name: Symbol,
    /// Field value, already sanitised by the producer.
    pub value: String,
}

/// A record that may be included in an export.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportRecord {
    /// Stable record identifier.
    pub id: Symbol,
    /// Record type (e.g. `aid`, `payment`, `escrow`).
    pub record_type: Symbol,
    /// Address that owns the record. Used for scope filtering.
    pub owner: Address,
    /// Ledger the record was created at.
    pub created_ledger: u32,
    /// Sensitivity classification.
    pub sensitivity: RecordSensitivity,
    /// Privacy-safe fields. Sensitive fields must be removed before export.
    pub fields: Vec<ExportField>,
}

/// Returns `true` when `field` may appear in an export.
///
/// Allow-list: only these (and only these) may carry an export field. Any
/// field not on the list is treated as sensitive and dropped during redaction.
pub fn is_safe_field(field: &Symbol) -> bool {
    field == &symbol_short!("id")
        || field == &symbol_short!("type")
        || field == &symbol_short!("status")
        || field == &symbol_short!("amount")
        || field == &symbol_short!("created")
        || field == &symbol_short!("expiry")
        || field == &symbol_short!("region")
        || field == &symbol_short!("role")
        || field == &symbol_short!("tier")
        || field == &symbol_short!("version")
        || field == &symbol_short!("network")
        || field == &symbol_short!("count")
}

/// Returns `true` when `field` carries identifying or secret material.
pub fn is_sensitive_field(field: &Symbol) -> bool {
    !is_safe_field(field)
}

/// Redact fields against the safe-field allow-list.
///
/// Returns the safe fields and the count of fields dropped. A field not on the
/// allow-list is removed, so a sensitive field can never leak into an export
/// by accident.
pub fn redact_fields(env: &Env, fields: &Vec<ExportField>) -> (Vec<ExportField>, u32) {
    let mut safe = Vec::new(env);
    let mut redacted: u32 = 0;
    for i in 0..fields.len() {
        let Some(field) = fields.get(i) else {
            continue;
        };
        if is_safe_field(&field.name) {
            safe.push_back(field);
        } else {
            redacted = redacted.saturating_add(1);
        }
    }
    (safe, redacted)
}

/// Returns `true` when `field` is strictly forbidden from appearing in any export.
///
/// Forbidden fields include secret material, raw nonces/entropy, private keys,
/// credentials, and module-specific sensitive internal data.
pub fn is_forbidden_field(field: &Symbol) -> bool {
    field == &symbol_short!("priv_key")
        || field == &symbol_short!("sec_key")
        || field == &symbol_short!("seed")
        || field == &symbol_short!("entropy")
        || field == &symbol_short!("token_sec")
        || field == &symbol_short!("auth_sig")
        || field == &symbol_short!("password")
        || field == &symbol_short!("ssn")
        || field == &symbol_short!("tax_id")
        || field == &symbol_short!("bank_wire")
        || field == &symbol_short!("card_num")
        || field == &symbol_short!("admin_key")
        || field == &symbol_short!("res_seed")
        || field == &symbol_short!("raw_pii")
        || field == &symbol_short!("bal_slt")
        || field == &symbol_short!("sign_key")
        || field == &symbol_short!("raw_nonce")
        || field == &symbol_short!("ip_addr")
}

/// Checks whether any field in `fields` is forbidden.
pub fn contains_forbidden_fields(fields: &Vec<ExportField>) -> bool {
    for i in 0..fields.len() {
        if let Some(f) = fields.get(i) {
            if is_forbidden_field(&f.name) {
                return true;
            }
        }
    }
    false
}

/// Strip any forbidden fields from `fields`. Returns safe non-forbidden fields and count of forbidden fields purged.
pub fn purge_forbidden_fields(env: &Env, fields: &Vec<ExportField>) -> (Vec<ExportField>, u32) {
    let mut safe = Vec::new(env);
    let mut purged: u32 = 0;
    for i in 0..fields.len() {
        let Some(f) = fields.get(i) else {
            continue;
        };
        if is_forbidden_field(&f.name) {
            purged = purged.saturating_add(1);
        } else {
            safe.push_back(f);
        }
    }
    (safe, purged)
}

// ---------------------------------------------------------------------------
// Authorization & scoping
// ---------------------------------------------------------------------------

/// The scope of data a caller may export.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportScope {
    /// Only records owned by the caller.
    OwnRecords,
    /// Non-restricted operational records across all users.
    Operational,
    /// All records, including restricted (maintainer only).
    Full,
}

/// A request to generate an export.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportRequest {
    /// The scope the caller is requesting.
    pub scope: ExportScope,
    /// Only export records of these types; empty means all types.
    pub record_types: Vec<Symbol>,
    /// Maximum records to include; 0 selects [`DEFAULT_MAX_EXPORT_RECORDS`].
    pub max_records: u32,
    /// How long the artifact stays valid, in ledgers; 0 selects
    /// [`DEFAULT_EXPORT_TTL_LEDGERS`].
    pub ttl_ledgers: u32,
}

impl ExportRequest {
    /// Effective max records after applying the default.
    pub fn effective_max_records(&self) -> u32 {
        if self.max_records == 0 {
            DEFAULT_MAX_EXPORT_RECORDS
        } else {
            self.max_records
        }
    }

    /// Effective TTL after applying the default.
    pub fn effective_ttl_ledgers(&self) -> u32 {
        if self.ttl_ledgers == 0 {
            DEFAULT_EXPORT_TTL_LEDGERS
        } else {
            self.ttl_ledgers
        }
    }

    /// Validate the request parameters.
    pub fn validate(&self) -> Result<(), ExportError> {
        if self.max_records > ABSOLUTE_MAX_EXPORT_RECORDS {
            return Err(ExportError::InvalidRequest);
        }
        let ttl = self.effective_ttl_ledgers();
        if ttl > MAX_EXPORT_TTL_LEDGERS {
            return Err(ExportError::TtlTooLong);
        }
        Ok(())
    }
}

/// Authorize a caller for the requested export scope.
///
/// - [`ExportScope::OwnRecords`]: any authenticated caller.
/// - [`ExportScope::Operational`]: [`Role::Support`] or [`Role::Admin`].
/// - [`ExportScope::Full`]: [`Role::Admin`] only.
///
/// Returns [`ExportError::ScopeDenied`] when the caller lacks the required
/// role. The caller's signature is always required.
pub fn authorize_export(env: &Env, caller: &Address, scope: ExportScope) -> Result<(), ExportError> {
    match scope {
        ExportScope::OwnRecords => {
            caller.require_auth();
            Ok(())
        }
        ExportScope::Operational => {
            if has_role(env, caller, Role::Support) || has_role(env, caller, Role::Admin) {
                caller.require_auth();
                Ok(())
            } else {
                Err(ExportError::ScopeDenied)
            }
        }
        ExportScope::Full => {
            if has_role(env, caller, Role::Admin) {
                caller.require_auth();
                Ok(())
            } else {
                Err(ExportError::ScopeDenied)
            }
        }
    }
}

/// Target contract module for export operations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl ExportModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            ExportModule::Treasury => symbol_short!("treasury"),
            ExportModule::Aid => symbol_short!("aid"),
            ExportModule::Referral => symbol_short!("referral"),
            ExportModule::Governance => symbol_short!("gov"),
            ExportModule::Oracle => symbol_short!("oracle"),
            ExportModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Authorize a caller for the requested export scope on a specific module.
///
/// Multi-module permission matrix:
/// - [`ExportScope::OwnRecords`]: any authenticated caller.
/// - [`ExportScope::Operational`]:
///   - `Treasury`: [`Role::TreasuryManager`] or [`Role::Admin`].
///   - `Aid`: [`Role::Support`] or [`Role::Admin`].
///   - `Referral`: [`Role::ReferralManager`] or [`Role::Admin`].
///   - `Governance`: [`Role::Support`] or [`Role::Admin`].
///   - `Oracle`: [`Role::OracleSigner`] or [`Role::Admin`].
///   - `Marketplace`: [`Role::Support`] or [`Role::Admin`].
/// - [`ExportScope::Full`]: [`Role::Admin`] only across all modules.
pub fn authorize_module_export(
    env: &Env,
    caller: &Address,
    module: ExportModule,
    scope: ExportScope,
) -> Result<(), ExportError> {
    match scope {
        ExportScope::OwnRecords => {
            caller.require_auth();
            Ok(())
        }
        ExportScope::Operational => {
            let is_admin = has_role(env, caller, Role::Admin);
            let has_module_role = match module {
                ExportModule::Treasury => has_role(env, caller, Role::TreasuryManager),
                ExportModule::Aid => has_role(env, caller, Role::Support),
                ExportModule::Referral => has_role(env, caller, Role::ReferralManager),
                ExportModule::Governance => has_role(env, caller, Role::Support),
                ExportModule::Oracle => has_role(env, caller, Role::OracleSigner),
                ExportModule::Marketplace => has_role(env, caller, Role::Support),
            };
            if is_admin || has_module_role {
                caller.require_auth();
                Ok(())
            } else {
                Err(ExportError::ScopeDenied)
            }
        }
        ExportScope::Full => {
            if has_role(env, caller, Role::Admin) {
                caller.require_auth();
                Ok(())
            } else {
                Err(ExportError::ScopeDenied)
            }
        }
    }
}

/// Returns `true` when `record` is visible to `caller` under `scope`.
///
/// - [`ExportScope::OwnRecords`]: only the caller's own records.
/// - [`ExportScope::Operational`]: any non-[`RecordSensitivity::Restricted`]
///   record.
/// - [`ExportScope::Full`]: every record.
pub fn scope_allows_record(scope: ExportScope, record: &ExportRecord, caller: &Address) -> bool {
    match scope {
        ExportScope::OwnRecords => record.owner == *caller,
        ExportScope::Operational => record.sensitivity != RecordSensitivity::Restricted,
        ExportScope::Full => true,
    }
}

/// Assert that every record in `records` is visible to `caller` under `scope`.
///
/// Unlike the silent filtering in [`generate_export`], this raises
/// [`ExportError::RecordNotVisible`] for the first out-of-scope record, so a
/// caller that names specific record IDs gets an actionable error instead of
/// a silently truncated result.
pub fn assert_records_visible(
    scope: ExportScope,
    records: &Vec<ExportRecord>,
    caller: &Address,
) -> Result<(), ExportError> {
    for i in 0..records.len() {
        let Some(record) = records.get(i) else {
            continue;
        };
        if !scope_allows_record(scope, &record, caller) {
            return Err(ExportError::RecordNotVisible);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generation metadata & artifact
// ---------------------------------------------------------------------------

/// Format of the generated export artifact.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Generation metadata stamped on every export artifact.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportMetadata {
    /// Schema version of this export.
    pub schema_version: u32,
    /// Ledger the export was generated at.
    pub generated_ledger: u32,
    /// Timestamp the export was generated at.
    pub generated_timestamp: u64,
    /// Address that generated the export.
    pub generator: Address,
    /// Scope the export was generated under.
    pub scope: ExportScope,
    /// Format of the export artifact.
    pub format: ExportFormat,
    /// Number of records included in the export.
    pub record_count: u32,
    /// Ledger at which the artifact expires.
    pub expires_ledger: u32,
}

/// Summary of what an export generation did.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportReport {
    /// Total records considered.
    pub total_records: u32,
    /// Records included in the export.
    pub included: u32,
    /// Fields dropped by redaction.
    pub redacted_fields: u32,
    /// Records suppressed because they were outside the caller's scope.
    pub suppressed_out_of_scope: u32,
}

/// A generated, privacy-safe export artifact.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportArtifact {
    /// Generation metadata.
    pub metadata: ExportMetadata,
    /// The redacted, in-scope records.
    pub records: Vec<ExportRecord>,
    /// What the generation did.
    pub report: ExportReport,
}

impl ExportArtifact {
    /// Returns `true` when the artifact has expired at `now_ledger`.
    pub fn is_expired(&self, now_ledger: u32) -> bool {
        now_ledger >= self.metadata.expires_ledger
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a privacy-safe export artifact.
///
/// The workflow:
///
/// 1. Validate the request ([`ExportRequest::validate`]).
/// 2. Authorize the caller for the requested scope ([`authorize_export`]).
/// 3. Filter records to those visible under the scope
///    ([`scope_allows_record`]) and, when `request.record_types` is non-empty,
///    to the requested types.
/// 4. Reject the export if the filtered count exceeds the effective
///    `max_records` ([`ExportError::ExportTooLarge`]). Callers should paginate
///    rather than receive a silently truncated export.
/// 5. Redact every record's fields against the safe-field allow-list
///    ([`redact_fields`]).
/// 6. Stamp [`ExportMetadata`] with the current schema version, ledger,
///    timestamp, generator, scope, format, record count, and expiry.
///
/// An export with no matching records is **valid**: it produces an empty
/// artifact with complete metadata and `record_count == 0`.
pub fn generate_export(
    env: &Env,
    caller: &Address,
    request: &ExportRequest,
    records: &Vec<ExportRecord>,
) -> Result<ExportArtifact, ExportError> {
    request.validate()?;
    authorize_export(env, caller, request.scope)?;

    let max_records = request.effective_max_records();
    let ttl = request.effective_ttl_ledgers();
    let now = env.ledger().sequence();

    // Filter by scope and (optionally) by record type.
    let mut included: Vec<ExportRecord> = Vec::new(env);
    let mut suppressed_out_of_scope: u32 = 0;
    let type_filter_empty = request.record_types.len() == 0;

    for i in 0..records.len() {
        let Some(record) = records.get(i) else {
            continue;
        };
        if !scope_allows_record(request.scope, &record, caller) {
            suppressed_out_of_scope = suppressed_out_of_scope.saturating_add(1);
            continue;
        }
        if !type_filter_empty {
            let mut type_matches = false;
            for j in 0..request.record_types.len() {
                let Some(t) = request.record_types.get(j) else {
                    continue;
                };
                if t == record.record_type {
                    type_matches = true;
                    break;
                }
            }
            if !type_matches {
                continue;
            }
        }
        included.push_back(record);
    }

    if included.len() > max_records {
        return Err(ExportError::ExportTooLarge);
    }

    // Redact fields against the safe-field allow-list.
    let mut redacted_fields: u32 = 0;
    let mut redacted: Vec<ExportRecord> = Vec::new(env);
    for i in 0..included.len() {
        let Some(record) = included.get(i) else {
            continue;
        };
        let (safe_fields, dropped) = redact_fields(env, &record.fields);
        redacted_fields = redacted_fields.saturating_add(dropped);
        redacted.push_back(ExportRecord {
            fields: safe_fields,
            ..record
        });
    }

    let record_count = redacted.len();
    let metadata = ExportMetadata {
        schema_version: CURRENT_EXPORT_SCHEMA_VERSION,
        generated_ledger: now,
        generated_timestamp: env.ledger().timestamp(),
        generator: caller.clone(),
        scope: request.scope,
        format: ExportFormat::Json,
        record_count,
        expires_ledger: now.saturating_add(ttl),
    };

    let report = ExportReport {
        total_records: records.len(),
        included: record_count,
        redacted_fields,
        suppressed_out_of_scope,
    };

    Ok(ExportArtifact {
        metadata,
        records: redacted,
        report,
    })
}

/// Register a generated artifact with the retention module under
/// [`DataClass::Export`] so the standard cleanup workflow reclaims it.
///
/// The artifact id is derived from the generator and ledger so repeated
/// exports by the same caller at the same ledger refresh rather than
/// accumulate. Authorization is enforced by the calling contract entry point;
/// this helper only validates and persists.
pub fn register_export_artifact(env: &Env, artifact: &ExportArtifact) -> Result<(), Error> {
    // `RetentionRecord.id` is a `Symbol`, and `no_std` contracts cannot build a
    // formatted string. Export artifacts therefore share one stable retention
    // slot; a newer export replaces the previous artifact's retention record,
    // which matches the artifact-expiry model (only the newest artifact for a
    // caller is retained).
    let id = symbol_short!("export");
    let record = RetentionRecord {
        id,
        class: DataClass::Export,
        created_ledger: artifact.metadata.generated_ledger,
        bytes: artifact.records.len().saturating_mul(256),
    };
    put_record(env, &record)
}

/// Convenience wrapper: generate an export and register it for retention in
/// one call. Intended for contract entry points that want the full workflow.
pub fn create_export(
    env: &Env,
    caller: &Address,
    request: &ExportRequest,
    records: &Vec<ExportRecord>,
) -> Result<ExportArtifact, ExportError> {
    let artifact = generate_export(env, caller, request, records)?;
    // Registration is best-effort at the storage layer: a failure here must
    // not discard an already-generated, already-authorised export.
    let _ = register_export_artifact(env, &artifact);
    Ok(artifact)
}

// ---------------------------------------------------------------------------
// Streaming Export Pipeline (Bounded Memory & Cancellation)
// ---------------------------------------------------------------------------

/// Lifecycle state of an export streaming session.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportStreamStatus {
    Active,
    Completed,
    Cancelled,
    Failed,
}

/// A streaming export session tracking bounded incremental chunk processing.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportSession {
    /// Unique session identifier.
    pub session_id: Symbol,
    /// Initiating caller.
    pub generator: Address,
    /// Target module.
    pub module: ExportModule,
    /// Authorized scope.
    pub scope: ExportScope,
    /// Current stream status.
    pub status: ExportStreamStatus,
    /// Next expected record cursor/index.
    pub cursor: u32,
    /// Cumulative count of records successfully streamed.
    pub total_exported: u32,
    /// Maximum allowed records for this export stream.
    pub max_records: u32,
    /// Memory bounded chunk size limit.
    pub chunk_size: u32,
    /// Starting ledger.
    pub started_ledger: u32,
    /// Expiration ledger.
    pub expires_ledger: u32,
    /// Cumulative stream integrity digest (SHA-256).
    pub stream_digest: BytesN<32>,
    /// Cumulative forbidden fields purged during streaming.
    pub purged_forbidden_fields: u32,
}

/// Result returned after streaming an individual bounded chunk.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamChunkResult {
    pub session_id: Symbol,
    pub chunk_index: u32,
    pub records_in_chunk: u32,
    pub cursor: u32,
    pub total_exported: u32,
    pub purged_forbidden_fields: u32,
    pub chunk_digest: BytesN<32>,
    pub is_complete: bool,
}

/// Audit report generated upon cancellation of an export session.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportCancellationReport {
    pub session_id: Symbol,
    pub cancelled_by: Address,
    pub cancelled_at_ledger: u32,
    pub records_streamed_prior: u32,
    pub reason: Symbol,
}

/// Compute cryptographic integrity digest for a single streaming chunk.
pub fn compute_chunk_digest(
    env: &Env,
    session_id: &Symbol,
    chunk_index: u32,
    records: &Vec<ExportRecord>,
) -> BytesN<32> {
    let mut parts: Vec<Val> = Vec::new(env);
    parts.push_back(session_id.clone().into_val(env));
    parts.push_back(chunk_index.into_val(env));
    parts.push_back(records.len().into_val(env));
    for i in 0..records.len() {
        if let Some(r) = records.get(i) {
            parts.push_back(r.id.into_val(env));
            parts.push_back(r.created_ledger.into_val(env));
        }
    }
    env.crypto().sha256(&parts.to_xdr(env)).into()
}

/// Combine cumulative stream digest with the newest chunk digest.
pub fn combine_stream_digests(env: &Env, prev: &BytesN<32>, chunk: &BytesN<32>) -> BytesN<32> {
    let mut b = Bytes::new(env);
    let p_bytes: Bytes = prev.clone().into();
    let c_bytes: Bytes = chunk.clone().into();
    b.append(&p_bytes);
    b.append(&c_bytes);
    env.crypto().sha256(&b).into()
}

/// Retrieve an active or archived export session by its session ID.
pub fn get_export_session(env: &Env, session_id: &Symbol) -> Result<ExportSession, ExportError> {
    persistent_get(env, &(EXPORT_SESSION_KEY, session_id.clone()))
        .ok_or(ExportError::SessionNotFound)
}

/// Initialize a new bounded memory export streaming session.
pub fn init_export_stream(
    env: &Env,
    caller: &Address,
    module: ExportModule,
    request: &ExportRequest,
    session_id: &Symbol,
) -> Result<ExportSession, ExportError> {
    request.validate()?;
    authorize_module_export(env, caller, module, request.scope)?;

    if persistent_has(env, &(EXPORT_SESSION_KEY, session_id.clone())) {
        return Err(ExportError::InvalidRequest);
    }

    let now = env.ledger().sequence();
    let ttl = request.effective_ttl_ledgers();
    let max_records = request.effective_max_records();
    let chunk_size = DEFAULT_EXPORT_CHUNK_SIZE;

    let session = ExportSession {
        session_id: session_id.clone(),
        generator: caller.clone(),
        module,
        scope: request.scope,
        status: ExportStreamStatus::Active,
        cursor: 0,
        total_exported: 0,
        max_records,
        chunk_size,
        started_ledger: now,
        expires_ledger: now.saturating_add(ttl),
        stream_digest: BytesN::from_array(env, &[0u8; 32]),
        purged_forbidden_fields: 0,
    };

    persistent_set(env, &(EXPORT_SESSION_KEY, session_id.clone()), &session);
    Ok(session)
}

/// Process a single bounded memory chunk within an active export stream.
///
/// Ensures:
/// 1. Caller authentication and ownership.
/// 2. Session is active, unexpired, and not cancelled.
/// 3. Memory boundedness (`records.len() <= chunk_size` and `<= MAX_EXPORT_CHUNK_SIZE`).
/// 4. Scope visibility and automatic forbidden fields purging.
/// 5. Cumulative integrity digest update.
pub fn stream_export_chunk(
    env: &Env,
    caller: &Address,
    session_id: &Symbol,
    chunk_records: &Vec<ExportRecord>,
) -> Result<StreamChunkResult, ExportError> {
    let mut session = get_export_session(env, session_id)?;
    caller.require_auth();

    if *caller != session.generator {
        return Err(ExportError::ScopeDenied);
    }

    if session.status == ExportStreamStatus::Cancelled {
        return Err(ExportError::ExportCancelled);
    }
    if session.status != ExportStreamStatus::Active {
        return Err(ExportError::SessionNotActive);
    }

    let now = env.ledger().sequence();
    if now >= session.expires_ledger {
        return Err(ExportError::ExportExpired);
    }

    if chunk_records.len() > session.chunk_size || chunk_records.len() > MAX_EXPORT_CHUNK_SIZE {
        return Err(ExportError::ChunkTooLarge);
    }

    let new_total = session.total_exported.saturating_add(chunk_records.len());
    if new_total > session.max_records {
        return Err(ExportError::ExportTooLarge);
    }

    let mut sanitized_records: Vec<ExportRecord> = Vec::new(env);
    let mut chunk_purged: u32 = 0;

    for i in 0..chunk_records.len() {
        let Some(rec) = chunk_records.get(i) else {
            continue;
        };
        if !scope_allows_record(session.scope, &rec, caller) {
            continue;
        }
        let (non_forbidden, purged) = purge_forbidden_fields(env, &rec.fields);
        chunk_purged = chunk_purged.saturating_add(purged);
        let (safe_fields, _dropped) = redact_fields(env, &non_forbidden);
        sanitized_records.push_back(ExportRecord {
            fields: safe_fields,
            ..rec
        });
    }

    let chunk_index = session.cursor / session.chunk_size;
    let chunk_digest = compute_chunk_digest(env, session_id, chunk_index, &sanitized_records);
    let new_digest = combine_stream_digests(env, &session.stream_digest, &chunk_digest);

    session.cursor = session.cursor.saturating_add(chunk_records.len());
    session.total_exported = new_total;
    session.purged_forbidden_fields = session.purged_forbidden_fields.saturating_add(chunk_purged);
    session.stream_digest = new_digest;

    let is_complete = session.total_exported >= session.max_records;
    if is_complete {
        session.status = ExportStreamStatus::Completed;
    }

    persistent_set(env, &(EXPORT_SESSION_KEY, session_id.clone()), &session);

    Ok(StreamChunkResult {
        session_id: session_id.clone(),
        chunk_index,
        records_in_chunk: sanitized_records.len(),
        cursor: session.cursor,
        total_exported: session.total_exported,
        purged_forbidden_fields: session.purged_forbidden_fields,
        chunk_digest,
        is_complete,
    })
}

/// Cancel an active export stream, preventing any further chunk processing.
///
/// Can be invoked by the session generator or an administrator.
pub fn cancel_export_stream(
    env: &Env,
    caller: &Address,
    session_id: &Symbol,
    reason: &Symbol,
) -> Result<ExportCancellationReport, ExportError> {
    let mut session = get_export_session(env, session_id)?;
    caller.require_auth();

    let is_generator = *caller == session.generator;
    let is_admin = has_role(env, caller, Role::Admin);

    if !is_generator && !is_admin {
        return Err(ExportError::ScopeDenied);
    }

    if session.status == ExportStreamStatus::Completed {
        return Err(ExportError::SessionNotActive);
    }

    let now = env.ledger().sequence();
    session.status = ExportStreamStatus::Cancelled;
    persistent_set(env, &(EXPORT_SESSION_KEY, session_id.clone()), &session);

    Ok(ExportCancellationReport {
        session_id: session_id.clone(),
        cancelled_by: caller.clone(),
        cancelled_at_ledger: now,
        records_streamed_prior: session.total_exported,
        reason: reason.clone(),
    })
}

/// Finalize an active export stream into a sealed artifact.
pub fn finalize_export_stream(
    env: &Env,
    caller: &Address,
    session_id: &Symbol,
) -> Result<ExportArtifact, ExportError> {
    let mut session = get_export_session(env, session_id)?;
    caller.require_auth();

    if *caller != session.generator {
        return Err(ExportError::ScopeDenied);
    }

    if session.status == ExportStreamStatus::Cancelled {
        return Err(ExportError::ExportCancelled);
    }

    session.status = ExportStreamStatus::Completed;
    persistent_set(env, &(EXPORT_SESSION_KEY, session_id.clone()), &session);

    let now = env.ledger().sequence();
    let metadata = ExportMetadata {
        schema_version: CURRENT_EXPORT_SCHEMA_VERSION,
        generated_ledger: now,
        generated_timestamp: env.ledger().timestamp(),
        generator: caller.clone(),
        scope: session.scope,
        format: ExportFormat::Json,
        record_count: session.total_exported,
        expires_ledger: session.expires_ledger,
    };

    let report = ExportReport {
        total_records: session.total_exported,
        included: session.total_exported,
        redacted_fields: session.purged_forbidden_fields,
        suppressed_out_of_scope: 0,
    };

    Ok(ExportArtifact {
        metadata,
        records: Vec::new(env),
        report,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DataKey;
    use crate::retention::get_record;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, testutils::Ledger as _};

    /// Minimal contract so unit tests can reach storage-backed helpers:
    /// Soroban only permits storage access inside a contract context.
    #[contract]
    pub struct ExportHarness;

    #[contractimpl]
    impl ExportHarness {
        pub fn noop(_env: Env) {}
    }

    fn with_storage<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        let id = env.register_contract(None, ExportHarness);
        env.as_contract(&id, f)
    }

    fn field(env: &Env, name: &str, value: &str) -> ExportField {
        ExportField {
            name: Symbol::new(env, name),
            value: String::from_str(env, value),
        }
    }

    fn record(env: &Env, id: &str, owner: &Address, sensitivity: RecordSensitivity) -> ExportRecord {
        ExportRecord {
            id: Symbol::new(env, id),
            record_type: symbol_short!("aid"),
            owner: owner.clone(),
            created_ledger: 1_000,
            sensitivity,
            fields: Vec::new(env),
        }
    }

    fn request(scope: ExportScope) -> ExportRequest {
        ExportRequest {
            scope,
            record_types: Vec::new(&Env::default()),
            max_records: 0,
            ttl_ledgers: 0,
        }
    }

    #[test]
    fn schema_version_is_stamped_on_every_artifact() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.metadata.schema_version, CURRENT_EXPORT_SCHEMA_VERSION);
        assert_eq!(CURRENT_EXPORT_SCHEMA_VERSION, EXPORT_SCHEMA_V1);
    }

    #[test]
    fn metadata_includes_generation_details() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(5_000);
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.metadata.generated_ledger, 5_000);
        assert_eq!(artifact.metadata.generator, caller);
        assert_eq!(artifact.metadata.scope, ExportScope::OwnRecords);
        assert_eq!(artifact.metadata.record_count, 1);
        assert_eq!(
            artifact.metadata.expires_ledger,
            5_000 + DEFAULT_EXPORT_TTL_LEDGERS
        );
    }

    #[test]
    fn end_user_is_denied_full_export() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        with_storage(&env, || {
            assert_eq!(
                authorize_export(&env, &caller, ExportScope::Full),
                Err(ExportError::ScopeDenied)
            );
            assert_eq!(
                authorize_export(&env, &caller, ExportScope::Operational),
                Err(ExportError::ScopeDenied)
            );
        });
    }

    #[test]
    fn admin_can_export_full_scope() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(admin.clone(), Role::Admin), &true);
            assert_eq!(authorize_export(&env, &admin, ExportScope::Full), Ok(()));
            assert_eq!(
                authorize_export(&env, &admin, ExportScope::Operational),
                Ok(())
            );
            assert_eq!(
                authorize_export(&env, &admin, ExportScope::OwnRecords),
                Ok(())
            );
        });
    }

    #[test]
    fn support_limited_to_operational_sensitivity() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(support.clone(), Role::Support), &true);
            assert_eq!(
                authorize_export(&env, &support, ExportScope::Operational),
                Ok(())
            );
            assert_eq!(
                authorize_export(&env, &support, ExportScope::Full),
                Err(ExportError::ScopeDenied)
            );
        });
    }

    #[test]
    fn end_user_can_export_own_records() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let other = Address::generate(&env);
        let own = record(&env, "own", &caller, RecordSensitivity::Public);
        let foreign = record(&env, "foreign", &other, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(own);
        records.push_back(foreign);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.total_records, 2);
        assert_eq!(artifact.report.included, 1);
        assert_eq!(artifact.report.suppressed_out_of_scope, 1);
        assert_eq!(artifact.records.len(), 1);
        assert_eq!(artifact.records.get(0).unwrap().id, Symbol::new(&env, "own"));
    }

    #[test]
    fn operational_scope_excludes_restricted_records() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user_a = Address::generate(&env);
        let user_b = Address::generate(&env);
        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(admin.clone(), Role::Admin), &true);
        });

        let public_rec = record(&env, "pub", &user_a, RecordSensitivity::Public);
        let op_rec = record(&env, "op", &user_a, RecordSensitivity::Operational);
        let restricted_rec = record(&env, "restr", &user_b, RecordSensitivity::Restricted);
        let mut records = Vec::new(&env);
        records.push_back(public_rec);
        records.push_back(op_rec);
        records.push_back(restricted_rec);

        let artifact =
            generate_export(&env, &admin, &request(ExportScope::Operational), &records)
                .expect("export should succeed");
        assert_eq!(artifact.report.included, 2);
        assert_eq!(artifact.report.suppressed_out_of_scope, 1);

        let full = generate_export(&env, &admin, &request(ExportScope::Full), &records)
            .expect("export should succeed");
        assert_eq!(full.report.included, 3);
        assert_eq!(full.report.suppressed_out_of_scope, 0);
    }

    #[test]
    fn sensitive_fields_are_redacted() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "status", "settled"));
        fields.push_back(field(&env, "amount", "1000"));
        fields.push_back(field(&env, "wallet", "GABC..."));
        fields.push_back(field(&env, "email", "user@example.com"));

        let rec = ExportRecord {
            id: Symbol::new(&env, "r1"),
            record_type: symbol_short!("aid"),
            owner: caller.clone(),
            created_ledger: 1_000,
            sensitivity: RecordSensitivity::Public,
            fields,
        };
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.redacted_fields, 2);
        let exported = artifact.records.get(0).unwrap();
        assert_eq!(exported.fields.len(), 2);
        assert_eq!(exported.fields.get(0).unwrap().name, symbol_short!("status"));
        assert_eq!(exported.fields.get(1).unwrap().name, symbol_short!("amount"));
    }

    #[test]
    fn large_export_exceeding_max_records_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let mut records = Vec::new(&env);
        for i in 0..DEFAULT_MAX_EXPORT_RECORDS + 1 {
            records.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
            let _ = i;
        }
        let req = ExportRequest {
            max_records: DEFAULT_MAX_EXPORT_RECORDS,
            ..request(ExportScope::OwnRecords)
        };
        assert_eq!(
            generate_export(&env, &caller, &req, &records),
            Err(ExportError::ExportTooLarge)
        );
    }

    #[test]
    fn large_export_within_limit_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let mut records = Vec::new(&env);
        for _ in 0..DEFAULT_MAX_EXPORT_RECORDS {
            records.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
        }
        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.included, DEFAULT_MAX_EXPORT_RECORDS);
        assert_eq!(artifact.metadata.record_count, DEFAULT_MAX_EXPORT_RECORDS);
    }

    #[test]
    fn empty_export_produces_empty_artifact() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let records = Vec::new(&env);
        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.records.len(), 0);
        assert_eq!(artifact.metadata.record_count, 0);
        assert_eq!(artifact.report.total_records, 0);
        assert_eq!(artifact.report.included, 0);
        assert_eq!(artifact.metadata.schema_version, CURRENT_EXPORT_SCHEMA_VERSION);
    }

    #[test]
    fn artifact_expires_after_ttl() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        let expires = artifact.metadata.expires_ledger;
        assert!(!artifact.is_expired(expires - 1));
        assert!(artifact.is_expired(expires));
        assert!(artifact.is_expired(expires + 1_000));
    }

    #[test]
    fn ttl_capped_at_retention_window() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let records = Vec::new(&env);
        let req = ExportRequest {
            ttl_ledgers: MAX_EXPORT_TTL_LEDGERS + 1,
            ..request(ExportScope::OwnRecords)
        };
        assert_eq!(
            generate_export(&env, &caller, &req, &records),
            Err(ExportError::TtlTooLong)
        );
        // Exactly at the cap is allowed.
        let req_at_cap = ExportRequest {
            ttl_ledgers: MAX_EXPORT_TTL_LEDGERS,
            ..request(ExportScope::OwnRecords)
        };
        assert!(generate_export(&env, &caller, &req_at_cap, &records).is_ok());
    }

    #[test]
    fn unsupported_schema_version_rejected() {
        assert!(ensure_supported_version(EXPORT_SCHEMA_V1).is_ok());
        assert_eq!(
            ensure_supported_version(EXPORT_SCHEMA_V1 + 1),
            Err(Error::UnsupportedSchemaVersion)
        );
        assert!(!is_supported_version(EXPORT_SCHEMA_V1 + 1));
    }

    #[test]
    fn record_type_filter_applied() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let aid = ExportRecord {
            record_type: symbol_short!("aid"),
            ..record(&env, "a1", &caller, RecordSensitivity::Public)
        };
        let payment = ExportRecord {
            record_type: symbol_short!("pay"),
            ..record(&env, "p1", &caller, RecordSensitivity::Public)
        };
        let mut records = Vec::new(&env);
        records.push_back(aid);
        records.push_back(payment);

        let mut types = Vec::new(&env);
        types.push_back(symbol_short!("aid"));
        let req = ExportRequest {
            record_types: types,
            ..request(ExportScope::OwnRecords)
        };
        let artifact = generate_export(&env, &caller, &req, &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.included, 1);
        assert_eq!(artifact.records.get(0).unwrap().record_type, symbol_short!("aid"));
    }

    #[test]
    fn export_registered_for_retention() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(7_000);
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        with_storage(&env, || {
            register_export_artifact(&env, &artifact).expect("registration should succeed");
            let id = symbol_short!("export");
            let stored = get_record(&env, &id).expect("record should be stored");
            assert_eq!(stored.class, DataClass::Export);
            assert_eq!(stored.created_ledger, 7_000);
        });
    }

    #[test]
    fn denied_export_writes_nothing() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        with_storage(&env, || {
            let req = ExportRequest {
                scope: ExportScope::Full,
                ..request(ExportScope::Full)
            };
            assert_eq!(
                generate_export(&env, &caller, &req, &records),
                Err(ExportError::ScopeDenied)
            );
            // No retention record was written for the denied export.
            assert!(get_record(&env, &symbol_short!("export")).is_none());
        });
    }

    #[test]
    fn assert_records_visible_raises_for_out_of_scope() {
        let env = Env::default();
        let caller = Address::generate(&env);
        let other = Address::generate(&env);
        let foreign = record(&env, "foreign", &other, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(foreign);
        assert_eq!(
            assert_records_visible(ExportScope::OwnRecords, &records, &caller),
            Err(ExportError::RecordNotVisible)
        );
    }

    #[test]
    fn test_authorize_module_export_all_modules() {
        let env = Env::default();
        env.mock_all_auths();
        let user = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_mgr = Address::generate(&env);
        let support = Address::generate(&env);
        let referral_mgr = Address::generate(&env);
        let oracle_signer = Address::generate(&env);

        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(admin.clone(), Role::Admin), &true);
            persistent_set(&env, &DataKey::Role(treasury_mgr.clone(), Role::TreasuryManager), &true);
            persistent_set(&env, &DataKey::Role(support.clone(), Role::Support), &true);
            persistent_set(&env, &DataKey::Role(referral_mgr.clone(), Role::ReferralManager), &true);
            persistent_set(&env, &DataKey::Role(oracle_signer.clone(), Role::OracleSigner), &true);

            // Treasury: TreasuryManager or Admin allowed for Operational; EndUser denied
            assert_eq!(authorize_module_export(&env, &treasury_mgr, ExportModule::Treasury, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Treasury, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &user, ExportModule::Treasury, ExportScope::Operational), Err(ExportError::ScopeDenied));

            // Aid: Support or Admin allowed for Operational
            assert_eq!(authorize_module_export(&env, &support, ExportModule::Aid, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Aid, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &user, ExportModule::Aid, ExportScope::Operational), Err(ExportError::ScopeDenied));

            // Referral: ReferralManager or Admin allowed for Operational
            assert_eq!(authorize_module_export(&env, &referral_mgr, ExportModule::Referral, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Referral, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &user, ExportModule::Referral, ExportScope::Operational), Err(ExportError::ScopeDenied));

            // Governance: Support or Admin allowed for Operational
            assert_eq!(authorize_module_export(&env, &support, ExportModule::Governance, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Governance, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &user, ExportModule::Governance, ExportScope::Operational), Err(ExportError::ScopeDenied));

            // Oracle: OracleSigner or Admin allowed for Operational
            assert_eq!(authorize_module_export(&env, &oracle_signer, ExportModule::Oracle, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Oracle, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &user, ExportModule::Oracle, ExportScope::Operational), Err(ExportError::ScopeDenied));

            // Marketplace: Support or Admin allowed for Operational
            assert_eq!(authorize_module_export(&env, &support, ExportModule::Marketplace, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Marketplace, ExportScope::Operational), Ok(()));
            assert_eq!(authorize_module_export(&env, &user, ExportModule::Marketplace, ExportScope::Operational), Err(ExportError::ScopeDenied));

            // Full scope: ONLY Admin allowed
            assert_eq!(authorize_module_export(&env, &admin, ExportModule::Treasury, ExportScope::Full), Ok(()));
            assert_eq!(authorize_module_export(&env, &treasury_mgr, ExportModule::Treasury, ExportScope::Full), Err(ExportError::ScopeDenied));
        });
    }

    #[test]
    fn test_streaming_pipeline_bounded_memory_chunks() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);

        with_storage(&env, || {
            let session_id = symbol_short!("sess_1");
            let req = ExportRequest {
                max_records: 50,
                ..request(ExportScope::OwnRecords)
            };

            let session = init_export_stream(&env, &caller, ExportModule::Aid, &req, &session_id)
                .expect("init stream should succeed");
            assert_eq!(session.chunk_size, DEFAULT_EXPORT_CHUNK_SIZE);
            assert_eq!(session.cursor, 0);
            assert_eq!(session.status, ExportStreamStatus::Active);

            // Chunk 1: 25 records
            let mut chunk1 = Vec::new(&env);
            for _ in 0..25 {
                chunk1.push_back(record(&env, "r1", &caller, RecordSensitivity::Public));
            }
            let res1 = stream_export_chunk(&env, &caller, &session_id, &chunk1)
                .expect("chunk 1 should succeed");
            assert_eq!(res1.chunk_index, 0);
            assert_eq!(res1.records_in_chunk, 25);
            assert_eq!(res1.cursor, 25);
            assert_eq!(res1.total_exported, 25);
            assert!(!res1.is_complete);

            // Chunk 2: 25 records
            let mut chunk2 = Vec::new(&env);
            for _ in 0..25 {
                chunk2.push_back(record(&env, "r2", &caller, RecordSensitivity::Public));
            }
            let res2 = stream_export_chunk(&env, &caller, &session_id, &chunk2)
                .expect("chunk 2 should succeed");
            assert_eq!(res2.chunk_index, 1);
            assert_eq!(res2.cursor, 50);
            assert_eq!(res2.total_exported, 50);
            assert!(res2.is_complete);

            // Finalize stream
            let artifact = finalize_export_stream(&env, &caller, &session_id)
                .expect("finalize should succeed");
            assert_eq!(artifact.metadata.record_count, 50);
            assert_eq!(artifact.report.total_records, 50);
        });
    }

    #[test]
    fn test_streaming_chunk_too_large_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);

        with_storage(&env, || {
            let session_id = symbol_short!("sess_ovr");
            let req = ExportRequest {
                max_records: 100,
                ..request(ExportScope::OwnRecords)
            };

            init_export_stream(&env, &caller, ExportModule::Treasury, &req, &session_id)
                .expect("init stream should succeed");

            let mut oversized_chunk = Vec::new(&env);
            for _ in 0..51 {
                oversized_chunk.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
            }

            assert_eq!(
                stream_export_chunk(&env, &caller, &session_id, &oversized_chunk),
                Err(ExportError::ChunkTooLarge)
            );
        });
    }

    #[test]
    fn test_streaming_cancellation_and_rejection() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let stranger = Address::generate(&env);
        let admin = Address::generate(&env);

        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(admin.clone(), Role::Admin), &true);

            let session_id = symbol_short!("sess_can");
            let req = ExportRequest {
                max_records: 50,
                ..request(ExportScope::OwnRecords)
            };

            init_export_stream(&env, &caller, ExportModule::Referral, &req, &session_id)
                .expect("init stream should succeed");

            // Stranger cannot cancel
            assert_eq!(
                cancel_export_stream(&env, &stranger, &session_id, &symbol_short!("abort")),
                Err(ExportError::ScopeDenied)
            );

            // Stream 1 chunk of 10 records
            let mut chunk = Vec::new(&env);
            for _ in 0..10 {
                chunk.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
            }
            stream_export_chunk(&env, &caller, &session_id, &chunk).expect("chunk should succeed");

            // Generator cancels stream
            let cancel_report = cancel_export_stream(&env, &caller, &session_id, &symbol_short!("user_ab"))
                .expect("cancel should succeed");
            assert_eq!(cancel_report.records_streamed_prior, 10);
            assert_eq!(cancel_report.reason, symbol_short!("user_ab"));

            let session = get_export_session(&env, &session_id).expect("session should exist");
            assert_eq!(session.status, ExportStreamStatus::Cancelled);

            // Subsequent streaming or finalization rejected
            assert_eq!(
                stream_export_chunk(&env, &caller, &session_id, &chunk),
                Err(ExportError::ExportCancelled)
            );
            assert_eq!(
                finalize_export_stream(&env, &caller, &session_id),
                Err(ExportError::ExportCancelled)
            );
        });
    }

    #[test]
    fn test_forbidden_fields_purged_in_stream() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);

        with_storage(&env, || {
            let session_id = symbol_short!("sess_forb");
            let req = ExportRequest {
                max_records: 10,
                ..request(ExportScope::OwnRecords)
            };

            init_export_stream(&env, &caller, ExportModule::Governance, &req, &session_id)
                .expect("init stream should succeed");

            let mut fields = Vec::new(&env);
            fields.push_back(field(&env, "status", "active"));
            fields.push_back(field(&env, "amount", "5000"));
            fields.push_back(field(&env, "priv_key", "secret123"));
            fields.push_back(field(&env, "seed", "seed_phrase"));
            fields.push_back(field(&env, "tax_id", "tax999"));

            let rec = ExportRecord {
                id: Symbol::new(&env, "rec_forb"),
                record_type: symbol_short!("gov"),
                owner: caller.clone(),
                created_ledger: 100,
                sensitivity: RecordSensitivity::Public,
                fields,
            };

            let mut chunk = Vec::new(&env);
            chunk.push_back(rec);

            let res = stream_export_chunk(&env, &caller, &session_id, &chunk)
                .expect("stream chunk should succeed");
            assert_eq!(res.purged_forbidden_fields, 3);

            let session = get_export_session(&env, &session_id).expect("session should exist");
            assert_eq!(session.purged_forbidden_fields, 3);
        });
    }

    #[test]
    fn test_streaming_expired_session_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);

        with_storage(&env, || {
            let session_id = symbol_short!("sess_exp");
            let req = ExportRequest {
                max_records: 10,
                ttl_ledgers: 100,
                ..request(ExportScope::OwnRecords)
            };

            let session = init_export_stream(&env, &caller, ExportModule::Marketplace, &req, &session_id)
                .expect("init stream should succeed");

            // Advance ledger past expires_ledger
            env.ledger().set_sequence_number(session.expires_ledger + 10);

            let mut chunk = Vec::new(&env);
            chunk.push_back(record(&env, "r", &caller, RecordSensitivity::Public));

            assert_eq!(
                stream_export_chunk(&env, &caller, &session_id, &chunk),
                Err(ExportError::ExportExpired)
            );
        });
    }

    #[test]
    fn test_large_dataset_streaming_continuous() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);

        with_storage(&env, || {
            let session_id = symbol_short!("sess_lrg");
            let req = ExportRequest {
                max_records: 100,
                ..request(ExportScope::OwnRecords)
            };

            init_export_stream(&env, &caller, ExportModule::Oracle, &req, &session_id)
                .expect("init stream should succeed");

            // Stream 4 chunks of 25 records each
            for i in 0..4 {
                let mut chunk = Vec::new(&env);
                for _ in 0..25 {
                    chunk.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
                }
                let res = stream_export_chunk(&env, &caller, &session_id, &chunk)
                    .expect("chunk should succeed");
                assert_eq!(res.chunk_index, i);
                assert_eq!(res.cursor, (i + 1) * 25);
            }

            let session = get_export_session(&env, &session_id).expect("session should exist");
            assert_eq!(session.total_exported, 100);
            assert_eq!(session.status, ExportStreamStatus::Completed);
        });
    }

}
