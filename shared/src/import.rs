//! Import Pipeline with Dry-Run Validation and Rollback Guidance (Issue #37).
//!
//! Provides a configurable, safe bulk import pipeline for Trellis smart contracts.
//! Designed to handle bulk donor allocations, aid beneficiary lists, or registry
//! entries with validation, duplicate detection, dry-run simulation, idempotency
//! guarantees, and operator rollback guidance.
//!
//! ## Execution Modes
//!
//! | Mode | Behaviour |
//! |------|----------|
//! | `AllOrNothing` | Atomic execution. All rows must validate and succeed. If any row fails, the entire batch is rejected. |
//! | `BestEffort` | Partial execution. Valid rows are committed; invalid rows are skipped and recorded with row-level error details. |
//!
//! ## Duplicate Handling Policies
//!
//! | Policy | Behaviour |
//! |------|----------|
//! | `SkipExisting` | Existing records with matching external IDs are skipped (`skip_count` increments). |
//! | `UpdateExisting` | Existing records are updated with new payload data (`update_count` increments). |
//! | `RejectDuplicate` | Duplicate external IDs (within batch or in storage) are treated as errors (`error_count` increments). |
//!
//! ## Dry-Run Guarantees
//!
//! When `dry_run` is `true`:
//! - **Zero persistent writes**: The pipeline executes validation, duplicate detection, and impact calculation purely against in-memory state and read-only storage lookups.
//! - **Full preview**: Computes accurate `create_count`, `update_count`, `skip_count`, and `error_count`.
//! - **Rollback guidance**: Analyzes validation results and recommends remediation runbooks before any ledger state is altered.
//! - Emits an `("import", "simulated")` ledger event for off-chain indexer visibility.
//!
//! ## Idempotency Guarantees
//!
//! When `external_id` is supplied on rows:
//! - Repeated executions of the same batch with `SkipExisting` result in `create_count = 0`, `update_count = 0`, and `skip_count = total_rows`.
//! - No duplicate persistent records are created on re-runs.

use soroban_sdk:{
    contracterror, contracttype, symbol_short, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

pub use crate::mugration::RollbackStrategy;
use crate::storage:4{
    instance_get, instance_set, persistent_has, persistent_read, persistent_set,
    temporary_has, temporary_remove, temporary_set,
};

// ----------------------------------------------------------------------------
	// Constants
	// ----------------------------------------------------------------------------

/// Default maximum number of rows in a single import batch.
pub const DEFAULT_MAX_IMPORT_SIZE: u32 = 50;

/// Absolute maximum allowed rows in one import transaction (gas ceiling).
pub const ABSOLUTE_MAX_IMPORT_SIZE: u32 = 100;

/// Maximum allowable length in bytes for an external ID.
pub const MAX_EXTERNAL_ID_LEN: u32 = 64;

/// Maximum number of quarantined rows retained per batch for operator review.
pub const MAX_QUARANTINE_ROWS: u32 = 100;

/// Temporary storage reentrancy lock key.
const REENTRANCY_KEY: Symbol = symbol_short!("imp_lck");

/// Instance storage counter key.
const IMPORT_COUNTER_KEY: Symbol = symbol_short!("imp_cnt");

/// Instance storage key for the last committed batch fingerprint (rollback anchor).
const LAST_BATCH_KEY: Symbol = symbol_short!("imp_last");

/// Instance storage key for the last committed batch record count (rollback anchor).
const LAST_BATCH_COUNT_KEY: Symbol = symbol_short!("imp_lcnt");

// ----------------------------------------------------------------------------
// Error Codes (Range 940–949)
// ----------------------------------------------------------------------------

/// Import pipeline error codes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ImportError {
    /// The import batch exceeds the maximum allowed operations.
    BatchTooLarge = 940,
    /// The import batch contains no records.
    EmptyBatch = 941,
    /// The import configuration is invalid (e.g., zero or excessive max_rows).
    InvalidConfig = 942,
    /// Duplicate external identifier detected under RejectDuplicate policy.
    DuplicateExternalId = 943,
    /// One or more rows failed validation in AllOrNothing mode.
    InvalidRow = 944,
    /// Reentrancy detected during import execution.
    ReentrancyDetected = 945,
    /// Row amount is zero or negative.
    InvalidAmount = 946,
    /// Row expiration ledger/timestamp is already expired.
    ExpiredRecord = 947,
    /// External identifier exceeds the maximum permitted length.
    ExternalIdTooLong = 948,
    /// Recipient address is invalid.
    InvalidRecipient = 949,
}

/// A quarantined row captured for operator review and remediation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedRow {
    /// Row sequence number in input batch.
    pub row_id: u32,
    /// External ID if present on the row.
    pub external_id: Option<Bytes>,
    /// Stable numeric contract error code.
    pub error_code: u32,
    /// Short symbol reason (e.g. `zero_amt`, `expired`, `dup_key`).
    pub reason: Symbol,
}

// ----------------------------------------------------------------------------
// Pipeline Types
#/ ----------------------------------------------------------------------------

/// Atomicity mode for executing the import.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportMode {
    /// All rows must succeed or entire batch fails / reverts.
    AllOrNothing,
    /// Valid rows persist; invalid rows are skipped and reported.
    BestEffort,
}

/// Strategy for resolving rows whose external ID already exists.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicatePolicy {
    /// Ignore new row and leave existing record untouched.
    SkipExisting,
    /// Overwrite existing record with new values.
    UpdateExisting,
    /// Reject as an error and record in RowError.
    RejectDuplicate,
}

/// A single row in an import batch.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportItem {
    /// Zero-based row sequence number within the input batch.
    pub row_id: u32,
    /// Optional external client/NGO identifier for idempotency & deduplication.
    pub external_id: Option<Bytes>,
    /// Target recipient address.
    pub recipient: Address,
    /// Disbursement or allocation amount (must be > 0).
    pub amount: i128,
    /// Expiration ledger sequence or timestamp (must be > current ledger).
    pub expiry: u64,
    /// Optional metadata / payload hash (e.g. SHA-256 of off-chain metadata).
    pub metadata_hash: Option<Bytes>,
}

/// Import pipeline execution configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportConfig {
    /// When `true`, validates and calculates diffs without making any persistent writes.
    pub dry_run: bool,
    /// Atomicity mode (`AllOrNothing` vs `BestEffort`).
    pub mode: ImportMode,
    /// How to handle records with duplicate external IDs.
    pub duplicate_policy: DuplicatePolicy,
    /// Batch size ceiling for this invocation (cannot exceed `ABSOLUTE_MAX_IMPORT_SIZE`).
    pub max_rows: u32,
}

/// Detailed error information for an invalid row.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowError {
    /// Row sequence number in input batch.
    pub row_id: u32,
    /// External ID if present on the row.
    pub external_id: Option<Bytes>,
    /// Stable numeric contract error code.
    pub error_code: u32,
    /// Short symbol reason (e.g. `zero_amt`, `expired`, `dup_key`).
    pub reason: Symbol,
}

/// Prescriptive rollback and remediation guidance returned in the import report.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackGuidance {
    /// High-level rollback strategy (`Revert`, `ForwardFix`, `Manual`).
    pub strategy: RollbackStrategy,
    /// Short action code for operators (e.g. `no_action`, `fix_rows`, `reverted`, `part_fix`).
    pub action: Symbol,
    /// Number of records needing attention or remediation.
    pub affected_records: u32,
    /// Runbook reference code for the operational team.
    pub runbook_code: Symbol,
}

/// Comprehensive outcome report for both dry-run previews and committed imports.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportReport {
    /// `true` if this report was generated during a dry-run preview.
    pub is_dry_run: bool,
    /// Total number of rows evaluated.
    pub total_rows: u32,
    /// Number of records created.
    pub create_count: u32,
    /// Number of records updated.
    pub update_count: u32,
    /// Number of records skipped.
    pub skip_count: u32,
    /// Number of rows that encountered validation or duplicate errors.
    pub error_count: u32,
    /// Detailed row-level error entries.
    pub errors: Vec<RowError>,
    /// Rollback and remediation guidance.
    pub rollback_guidance: RollbackGuidance,
    /// Rows quarantined for operator review (unsafe rows rejected from commit).
    pub quarantined: Vec<QuarantinedRow>,
    /// Deterministic 32-byte cryptographic fingerprint of the import batch.
    pub batch_fingerprint: BytesN32>,
}

/// Stored record format for persistent state tracking.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredImportRecord {
    /// Monotonically-assigned internal record identifier.
    pub record_id: u64,
    /// External identifier if one was provided.
    pub external_id: Bytes,
    /// Target recipient address.
    pub recipient: Address,
    /// Allocation amount.
    pub amount: i128,
    /// Expiration timestamp or ledge sequence.
    pub expiry: u64,
    /// Optional metadata hash.
    pub metadata_hash: Option<Bytes>,
    /// Ledger timestamp when the record was imported.
    pub imported_at: u64,
    /// Record schema version.
    pub version: u32,
}

// ----------------------------------------------------------------------------
// Storage Key Helpers
#/ ----------------------------------------------------------------------------

fn external_record_key(external_id: &Bytes) -> (Symbol, Bytes) {
    (symbol_short!("imp_ext"), external_id.clone())
}

/// Storage key for a batch-level traceability marker.
fn batch_marker_key(fingerprint: &BytesN<32>) -> (Symbol, BytesN<32>) {
    (symbol_short!("imp_bat"), fingerprint.clone())
}

// ----------------------------------------------------------------------------
// Reentrancy Guard
#/ ----------------------------------------------------------------------------

fn acquire_reentrancy_guard(env: &Env) -> Result<(), ImportError> {
    if temporary_has(env, &REENTRANCY_KEY) {
        return Err(ImportError::ReentrancyDetected);
    }
    temporary_set(env, &REENTRANCY_KEY, &true);
    Ok(())
}

fn release_reentrancy_guard(env: &Env) {
    temporary_remove(env, &REENTRANCY_KEY);
}

// ----------------------------------------------------------------------------
// Fingerprint & Validation
#/ ----------------------------------------------------------------------------

/// Computes a deterministic SHA-256 fingerprint of the input batch.
pub fn compute_batch_fingerprint(env: &Env, items: &Vec<ImportItem>) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    let len = items.len();
    payload.append(&Bytes::from_slice(env, b"trellis_import_v1:"));

    for i in 0..len {
        let item = items.get(i).unwrap();
        // Pack row_id, amount, expiry
        let mut row_bytes = Bytes::new(env);
        row_bytes.append(&Bytes::from_slice(env, &item.row_id.to_be_bytes()));
        row_bytes.append(&Bytes::from_slice(env, &item.amount.to_be_bytes()));
        row_bytes.append(&Bytes::from_slice(env, &item.expiry.to_be_bytes()));
        if let Some(ext) = &item.external_id {
            row_bytes.append(ext);
        }
        payload.append(&row_bytes);
    }
    env.crypto().sha256(&`ayload).into()
}

/// Validates configuration bounds.
pub fn validate_config(config: &ImportConfig) -> Result<(), ImportError> {
    if config.max_rows == 0 || config.max_rows > ABSOLUTE_MAX_IMPORT_SIZE {
        return Err(ImportError::InvalidConfig);
    }
    Ok(())
}
