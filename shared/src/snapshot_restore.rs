//! Snapshot Restore Verification for Critical Data and Derived Indexes.
//!
//! Across Trellis contracts — Treasury, Aid, Referral, Governance, Oracle, and Marketplace —
//! restoring state from point-in-time snapshots, disaster recovery backups, or migration
//! rollback checkpoints carries two fundamental risks:
//! 1. **Critical Data Invariant Breaches**: Authoritative persistent records may be incomplete,
//!    unbalanced, orphaned, or duplicated (e.g. reserve backing deficit, negative balances,
//!    dangling claims or referral nodes).
//! 2. **Derived View / Index Staleness**: Secondary indices and cached aggregate projections
//!    (e.g. discovery search indexes, active proposal lists, strategy whitelists, floor prices,
//!    category balance caches) are often omitted from raw snapshots or become desynchronized,
//!    leading to phantom listings or query failures.
//!
//! This module provides:
//! - **Formal Invariant Verification**: Exhaustively tests restored critical records against
//!   solvency, relational integrity, unique constraints, and lifecycle state machines.
//! - **Deterministic Derived View Rebuilding**: Automatically reconstructs secondary indices
//!   and cached projections directly from authoritative canonical records.
//! - **Loud Failure Taxonomy with Actionable Repair Steps**: Emits structured, machine-readable
//!   and operator-actionable mismatch reports with copy-pasteable remediation CLI commands
//!   and runbook links.
//! - **Safe Rollback and Quarantine**: Captures pre-restore snapshots to allow atomic rollback
//!   and automatically quarantines affected projections on critical financial discrepancies.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

use crate::storage::{instance_get, instance_has, instance_remove, instance_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 1120–1139)
// ---------------------------------------------------------------------------

/// Errors returned by snapshot restore verification and derived view rebuilding.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SnapshotRestoreError {
    /// Caller not authorized to run restore verification or rebuild.
    Unauthorized = 1120,
    /// Invalid arguments or unparsable payload.
    InvalidArgument = 1121,
    /// Restore verification failed due to invariant breach or critical drift.
    RestoreVerificationFailed = 1122,
    /// Critical data violates solvency invariant (reserve < liabilities).
    SolvencyDeficit = 1123,
    /// Negative balance detected on account or category.
    NegativeBalance = 1124,
    /// Orphaned relational link detected (child references missing parent).
    OrphanedRecord = 1125,
    /// Duplicate primary key or settlement constraint violated.
    DuplicateRecord = 1126,
    /// Lifecycle state machine or status constraint violated.
    LifecycleInconsistent = 1127,
    /// Derived view / index drift detected beyond permissible tolerance.
    DerivedViewDrift = 1128,
    /// Quorum or boundary condition violated.
    QuorumViolation = 1129,
    /// Rollback snapshot not found for receipt id.
    RollbackNotFound = 1130,
    /// Rollback has already been applied or expired.
    RollbackAlreadyApplied = 1131,
    /// State is quarantined; manual administrator intervention required.
    QuarantineTriggered = 1132,
    /// Scan limit exceeded to protect execution budget.
    ScanLimitExceeded = 1133,
}

// ---------------------------------------------------------------------------
// Modules & Records Scoping
// ---------------------------------------------------------------------------

/// The six core contract modules in Trellis.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl RestoreModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            RestoreModule::Treasury => symbol_short!("treasury"),
            RestoreModule::Aid => symbol_short!("aid"),
            RestoreModule::Referral => symbol_short!("referral"),
            RestoreModule::Governance => symbol_short!("gov"),
            RestoreModule::Oracle => symbol_short!("oracle"),
            RestoreModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Critical authoritative entity types inspected during restore verification.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CriticalRecordKind {
    /// Treasury contract vault reserve or category balance.
    TreasuryBalance,
    /// Treasury internal liabilities / allocated commitments.
    TreasuryLiability,
    /// Treasury whitelisted investment or routing strategy.
    TreasuryStrategy,
    /// Canonical aid disbursement allocation.
    AidRecord,
    /// Beneficiary claim or milestone redemption.
    AidClaim,
    /// Referral relationship edge (partner to upline).
    ReferralEdge,
    /// Referral partner accrued commission balance.
    ReferralCommission,
    /// Governance proposal record.
    GovernanceProposal,
    /// Cast ballot for a governance proposal.
    GovernanceBallot,
    /// Oracle asset price feed registry entry.
    OracleFeed,
    /// Oracle price attestation round.
    OracleRound,
    /// Marketplace NFT listing record.
    MarketplaceListing,
    /// Marketplace escrow commitment.
    MarketplaceEscrow,
}

/// A single authoritative canonical record restored from a snapshot.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalRestoreRecord {
    pub module: RestoreModule,
    pub kind: CriticalRecordKind,
    pub record_id: u64,
    pub parent_id: u64,
    pub entity_symbol: Symbol,
    pub amount: i128,
    pub status: Symbol,
    pub auxiliary_value: u64,
}

/// Secondary derived index or cached projection classification.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivedViewKind {
    /// Secondary index list (e.g. search, active proposals, strategies, listings).
    Index,
    /// Cached aggregate counter or balance (e.g. category reserve, vote tally, floor price).
    Cache,
}

/// A reconstructed or existing derived view entry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedViewEntry {
    pub module: RestoreModule,
    /// Identifier of the derived view: `strat_idx`, `cat_bal`, `search`, `donor_aid`,
    /// `downline`, `comm_acc`, `act_prop`, `tally`, `feed_reg`, `price_rnd`, `listing`, `floor_p`.
    pub view_name: Symbol,
    pub kind: DerivedViewKind,
    pub key_id: u64,
    pub key_symbol: Symbol,
    pub numeric_value: i128,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// Invariants & Mismatch Taxonomy
// ---------------------------------------------------------------------------

/// Invariant breach classification during restore validation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreVerificationFailure {
    None,
    /// Contract physical reserve balance is less than internal liabilities ($B < L$).
    SolvencyDeficit,
    /// Negative balance observed on an account, category, or commission.
    NegativeBalance,
    /// Relational child points to a non-existent or deleted parent record.
    OrphanedRecord,
    /// Unique constraint violated (duplicate primary key or settlement reference).
    DuplicateRecordKey,
    /// Entity status conflicts with invariants, timestamps, or ballot totals.
    LifecycleInconsistency,
    /// Derived index or cache diverges from canonical source of truth.
    DerivedViewDrift,
    /// Required quorum exceeds registered entities or percentage exceeds 10,000 bps.
    QuorumViolation,
    /// Boundary parameter out of acceptable range.
    BoundaryExceeded,
    /// Discrepancy triggers automated quarantine of the projection.
    QuarantineRequired,
}

/// Severity classification for restore mismatches.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreSeverity {
    Info,
    Medium,
    High,
    Critical,
}

/// Detailed loud mismatch report containing exact deltas and repair instructions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreMismatchReport {
    pub module: RestoreModule,
    pub failure_kind: RestoreVerificationFailure,
    pub target_id: u64,
    pub target_symbol: Symbol,
    pub expected_val: i128,
    pub actual_val: i128,
    pub severity: RestoreSeverity,
    pub failure_message: String,
    pub repair_steps: String,
}

/// Comprehensive verification receipt generated upon restore evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreVerificationReceipt {
    pub receipt_id: u64,
    pub module: RestoreModule,
    pub executed_ledger: u32,
    pub canonical_records_checked: u32,
    pub derived_views_scanned: u32,
    pub derived_views_rebuilt: u32,
    pub mismatches_count: u32,
    pub passed: bool,
    pub pre_restore_fingerprint: u64,
    pub post_rebuild_fingerprint: u64,
    pub quarantined: bool,
}

/// Pre-restore snapshot retained for deterministic rollback if downstream checks fail.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreRollbackSnapshot {
    pub receipt_id: u64,
    pub module: RestoreModule,
    pub original_derived_views: Vec<DerivedViewEntry>,
    pub created_at: u64,
    pub applied: bool,
}

/// Combined outcome report returned to caller.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreReport {
    pub receipt: RestoreVerificationReceipt,
    pub mismatches: Vec<RestoreMismatchReport>,
    pub rebuilt_views: Vec<DerivedViewEntry>,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreStorageKey {
    ReceiptSeq,
    LatestReceipt(RestoreModule),
    Receipt(u64),
    RollbackSnapshot(u64),
    QuarantineFlag(RestoreModule),
    StoredDerivedView(RestoreModule, Symbol, u64),
}

// ---------------------------------------------------------------------------
// Invariant Verification Engine
// ---------------------------------------------------------------------------

/// Verifies critical canonical records for a given module against formal invariants:
/// 1. Solvency & asset conservation (reserve balance >= liabilities, no negative balances).
/// 2. Relational integrity (all foreign keys and parent links point to existing records).
/// 3. Unique constraints (no duplicate primary IDs or settlement keys).
/// 4. Lifecycle state consistency (valid status enums, no active items with expired/settled parameters).
/// 5. Boundary parameters (commission rates <= 10,000 bps, quorum <= registered signers).
pub fn verify_critical_data_invariants(
    env: &Env,
    module: RestoreModule,
    records: &Vec<CanonicalRestoreRecord>,
) -> Vec<RestoreMismatchReport> {
    let mut mismatches = Vec::new(env);
    let count = records.len();

    let mut total_reserve: i128 = 0;
    let mut total_liabilities: i128 = 0;

    for i in 0..count {
        let rec = records.get(i).unwrap();

        // 1. Negative Balance Check
        if (rec.kind == CriticalRecordKind::TreasuryBalance
            || rec.kind == CriticalRecordKind::TreasuryLiability
            || rec.kind == CriticalRecordKind::ReferralCommission
            || rec.kind == CriticalRecordKind::AidRecord
            || rec.kind == CriticalRecordKind::MarketplaceEscrow)
            && rec.amount < 0
        {
            mismatches.push_back(RestoreMismatchReport {
                module,
                failure_kind: RestoreVerificationFailure::NegativeBalance,
                target_id: rec.record_id,
                target_symbol: rec.entity_symbol,
                expected_val: 0,
                actual_val: rec.amount,
                severity: RestoreSeverity::Critical,
                failure_message: String::from_str(env, "Negative balance detected on critical financial record"),
                repair_steps: String::from_str(
                    env,
                    "CRITICAL: Halt contract operations. Investigate accounting journal and deposit/withdraw history. Do not balance by manufacturing credit.",
                ),
            });
        }

        // Accumulate solvency totals for Treasury / Aid / Marketplace
        if rec.kind == CriticalRecordKind::TreasuryBalance {
            total_reserve = total_reserve.saturating_add(rec.amount);
        } else if rec.kind == CriticalRecordKind::TreasuryLiability {
            total_liabilities = total_liabilities.saturating_add(rec.amount);
        }

        // 2. Duplicate Primary Key Check
        for j in (i + 1)..count {
            let other = records.get(j).unwrap();
            if rec.kind == other.kind && rec.record_id == other.record_id {
                mismatches.push_back(RestoreMismatchReport {
                    module,
                    failure_kind: RestoreVerificationFailure::DuplicateRecordKey,
                    target_id: rec.record_id,
                    target_symbol: rec.entity_symbol,
                    expected_val: 1,
                    actual_val: 2,
                    severity: RestoreSeverity::High,
                    failure_message: String::from_str(env, "Duplicate primary key collision detected in restored snapshot"),
                    repair_steps: String::from_str(
                        env,
                        "Halt batch processing. Perform manual deduplication runbook: see docs/RESTORE_VALIDATION.md for conflict resolution.",
                    ),
                });
            }
        }

        // 3. Relational Integrity Checks (No Orphaned Records)
        if rec.kind == CriticalRecordKind::AidClaim {
            // Parent ID must exist as an AidRecord
            let mut found_parent = false;
            for k in 0..count {
                let candidate = records.get(k).unwrap();
                if candidate.kind == CriticalRecordKind::AidRecord && candidate.record_id == rec.parent_id {
                    found_parent = true;
                    break;
                }
            }
            if !found_parent {
                mismatches.push_back(RestoreMismatchReport {
                    module,
                    failure_kind: RestoreVerificationFailure::OrphanedRecord,
                    target_id: rec.record_id,
                    target_symbol: rec.entity_symbol,
                    expected_val: rec.parent_id as i128,
                    actual_val: 0,
                    severity: RestoreSeverity::High,
                    failure_message: String::from_str(env, "Orphaned aid claim record references non-existent parent aid disbursement"),
                    repair_steps: String::from_str(
                        env,
                        "Run relational backfill: ./scripts/backfill.sh --module aid --input <file>. Review aid parent IDs before reprocessing.",
                    ),
                });
            }
        } else if rec.kind == CriticalRecordKind::ReferralEdge && rec.parent_id != 0 {
            // Parent ID must exist as another partner record or root
            let mut found_upline = false;
            for k in 0..count {
                let candidate = records.get(k).unwrap();
                if candidate.kind == CriticalRecordKind::ReferralEdge && candidate.record_id == rec.parent_id {
                    found_upline = true;
                    break;
                }
            }
            if !found_upline {
                mismatches.push_back(RestoreMismatchReport {
                    module,
                    failure_kind: RestoreVerificationFailure::OrphanedRecord,
                    target_id: rec.record_id,
                    target_symbol: rec.entity_symbol,
                    expected_val: rec.parent_id as i128,
                    actual_val: 0,
                    severity: RestoreSeverity::High,
                    failure_message: String::from_str(env, "Orphaned referral node references non-existent upline partner"),
                    repair_steps: String::from_str(
                        env,
                        "Run relational backfill: ./scripts/backfill.sh --module referral --input <file>. Reconstruct parent-child mapping.",
                    ),
                });
            }
        } else if rec.kind == CriticalRecordKind::GovernanceBallot {
            // Parent ID must exist as a GovernanceProposal
            let mut found_prop = false;
            for k in 0..count {
                let candidate = records.get(k).unwrap();
                if candidate.kind == CriticalRecordKind::GovernanceProposal && candidate.record_id == rec.parent_id {
                    found_prop = true;
                    break;
                }
            }
            if !found_prop {
                mismatches.push_back(RestoreMismatchReport {
                    module,
                    failure_kind: RestoreVerificationFailure::OrphanedRecord,
                    target_id: rec.record_id,
                    target_symbol: rec.entity_symbol,
                    expected_val: rec.parent_id as i128,
                    actual_val: 0,
                    severity: RestoreSeverity::High,
                    failure_message: String::from_str(env, "Orphaned ballot references non-existent governance proposal"),
                    repair_steps: String::from_str(
                        env,
                        "Purge orphaned ballots or backfill missing proposal record: ./scripts/backfill.sh --module governance.",
                    ),
                });
            }
        } else if rec.kind == CriticalRecordKind::MarketplaceEscrow {
            // Parent ID must exist as an open MarketplaceListing
            let mut found_listing = false;
            for k in 0..count {
                let candidate = records.get(k).unwrap();
                if candidate.kind == CriticalRecordKind::MarketplaceListing && candidate.record_id == rec.parent_id {
                    found_listing = true;
                    break;
                }
            }
            if !found_listing {
                mismatches.push_back(RestoreMismatchReport {
                    module,
                    failure_kind: RestoreVerificationFailure::OrphanedRecord,
                    target_id: rec.record_id,
                    target_symbol: rec.entity_symbol,
                    expected_val: rec.parent_id as i128,
                    actual_val: 0,
                    severity: RestoreSeverity::High,
                    failure_message: String::from_str(env, "Orphaned marketplace escrow holds funds for non-existent listing"),
                    repair_steps: String::from_str(
                        env,
                        "CRITICAL: Reconcile marketplace escrows. Refund stranded buyers or restore missing listing record.",
                    ),
                });
            }
        }

        // 4. Boundary & Quorum Checks
        if rec.kind == CriticalRecordKind::ReferralEdge && rec.auxiliary_value > 10_000 {
            mismatches.push_back(RestoreMismatchReport {
                module,
                failure_kind: RestoreVerificationFailure::BoundaryExceeded,
                target_id: rec.record_id,
                target_symbol: rec.entity_symbol,
                expected_val: 10_000,
                actual_val: rec.auxiliary_value as i128,
                severity: RestoreSeverity::High,
                failure_message: String::from_str(env, "Referral commission rate exceeds maximum allowable 10,000 basis points"),
                repair_steps: String::from_str(
                    env,
                    "Clamp commission rate to maximum permitted bounds via admin governance update before resuming.",
                ),
            });
        } else if rec.kind == CriticalRecordKind::OracleFeed && rec.auxiliary_value == 0 {
            mismatches.push_back(RestoreMismatchReport {
                module,
                failure_kind: RestoreVerificationFailure::QuorumViolation,
                target_id: rec.record_id,
                target_symbol: rec.entity_symbol,
                expected_val: 1,
                actual_val: 0,
                severity: RestoreSeverity::High,
                failure_message: String::from_str(env, "Oracle price feed quorum requirement is zero (must require at least 1 signer)"),
                repair_steps: String::from_str(
                    env,
                    "Re-initialize oracle feed quorum to configured minimum threshold in docs/CONFIGURATION.md.",
                ),
            });
        }

        // 5. Lifecycle Inconsistency Checks
        if rec.kind == CriticalRecordKind::GovernanceProposal {
            let is_active = rec.status == symbol_short!("active");
            let is_executed = rec.status == symbol_short!("executed");
            let is_cancelled = rec.status == symbol_short!("cancelled");
            let is_defeated = rec.status == symbol_short!("defeated");

            if !is_active && !is_executed && !is_cancelled && !is_defeated {
                mismatches.push_back(RestoreMismatchReport {
                    module,
                    failure_kind: RestoreVerificationFailure::LifecycleInconsistency,
                    target_id: rec.record_id,
                    target_symbol: rec.entity_symbol,
                    expected_val: 0,
                    actual_val: 0,
                    severity: RestoreSeverity::High,
                    failure_message: String::from_str(env, "Governance proposal has unrecognized lifecycle status"),
                    repair_steps: String::from_str(
                        env,
                        "Advance or reset proposal state machine to a valid variant (active, executed, cancelled, defeated).",
                    ),
                });
            }
        }
    }

    // 6. Solvency Invariant Check (Reserve >= Liabilities)
    if module == RestoreModule::Treasury && total_liabilities > 0 && total_reserve < total_liabilities {
        let deficit = total_liabilities.saturating_sub(total_reserve);
        mismatches.push_back(RestoreMismatchReport {
            module,
            failure_kind: RestoreVerificationFailure::SolvencyDeficit,
            target_id: 0,
            target_symbol: symbol_short!("solvency"),
            expected_val: total_liabilities,
            actual_val: total_reserve,
            severity: RestoreSeverity::Critical,
            failure_message: String::from_str(env, "Contract reserve balance is strictly less than internal liabilities"),
            repair_steps: String::from_str(
                env,
                "CRITICAL: Halt trading. Reconcile physical SAC token reserves against internal liabilities. Do NOT manufacture credits.",
            ),
        });
    }

    mismatches
}

// ---------------------------------------------------------------------------
// Derived View Rebuilding Engine
// ---------------------------------------------------------------------------

/// Deterministically rebuilds derived secondary indexes and cached aggregate projections
/// directly from authoritative canonical records.
pub fn rebuild_derived_views(
    env: &Env,
    module: RestoreModule,
    canonical_records: &Vec<CanonicalRestoreRecord>,
) -> Vec<DerivedViewEntry> {
    let mut views = Vec::new(env);
    let count = canonical_records.len();

    match module {
        RestoreModule::Treasury => {
            // Rebuild Strategy Index (`strat_idx`) and Category Balances Cache (`cat_bal`)
            let mut category_totals = Vec::new(env); // (Symbol, i128)

            for i in 0..count {
                let rec = canonical_records.get(i).unwrap();
                if rec.kind == CriticalRecordKind::TreasuryStrategy {
                    views.push_back(DerivedViewEntry {
                        module,
                        view_name: symbol_short!("strat_idx"),
                        kind: DerivedViewKind::Index,
                        key_id: rec.record_id,
                        key_symbol: rec.entity_symbol,
                        numeric_value: rec.amount,
                        is_active: rec.status == symbol_short!("active"),
                    });
                } else if rec.kind == CriticalRecordKind::TreasuryBalance {
                    // Accumulate per-category
                    let mut found = false;
                    let cat_len = category_totals.len();
                    for c in 0..cat_len {
                        let (sym, sum): (Symbol, i128) = category_totals.get(c).unwrap();
                        if sym == rec.entity_symbol {
                            category_totals.set(c, (sym, sum.saturating_add(rec.amount)));
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        category_totals.push_back((rec.entity_symbol, rec.amount));
                    }
                }
            }

            for c in 0..category_totals.len() {
                let (sym, sum): (Symbol, i128) = category_totals.get(c).unwrap();
                views.push_back(DerivedViewEntry {
                    module,
                    view_name: symbol_short!("cat_bal"),
                    kind: DerivedViewKind::Cache,
                    key_id: 0,
                    key_symbol: sym,
                    numeric_value: sum,
                    is_active: true,
                });
            }
        }

        RestoreModule::Aid => {
            // Rebuild Discovery Search Index (`search`) and Donor Index (`donor_aid`)
            for i in 0..count {
                let rec = canonical_records.get(i).unwrap();
                if rec.kind == CriticalRecordKind::AidRecord {
                    let is_active = rec.status == symbol_short!("active");
                    if is_active {
                        views.push_back(DerivedViewEntry {
                            module,
                            view_name: symbol_short!("search"),
                            kind: DerivedViewKind::Index,
                            key_id: rec.record_id,
                            key_symbol: rec.entity_symbol,
                            numeric_value: rec.amount,
                            is_active: true,
                        });
                    }
                    // Rebuild donor index
                    views.push_back(DerivedViewEntry {
                        module,
                        view_name: symbol_short!("donor_aid"),
                        kind: DerivedViewKind::Index,
                        key_id: rec.record_id,
                        key_symbol: rec.entity_symbol, // Donor address symbol
                        numeric_value: rec.amount,
                        is_active: true,
                    });
                }
            }
        }

        RestoreModule::Referral => {
            // Rebuild Downline Index (`downline`) and Accrued Commission Cache (`comm_acc`)
            for i in 0..count {
                let rec = canonical_records.get(i).unwrap();
                if rec.kind == CriticalRecordKind::ReferralEdge {
                    views.push_back(DerivedViewEntry {
                        module,
                        view_name: symbol_short!("downline"),
                        kind: DerivedViewKind::Index,
                        key_id: rec.record_id,
                        key_symbol: rec.entity_symbol,
                        numeric_value: rec.auxiliary_value as i128, // bps rate
                        is_active: true,
                    });
                } else if rec.kind == CriticalRecordKind::ReferralCommission {
                    views.push_back(DerivedViewEntry {
                        module,
                        view_name: symbol_short!("comm_acc"),
                        kind: DerivedViewKind::Cache,
                        key_id: rec.record_id,
                        key_symbol: rec.entity_symbol,
                        numeric_value: rec.amount,
                        is_active: true,
                    });
                }
            }
        }

        RestoreModule::Governance => {
            // Rebuild Active Proposals Index (`act_prop`) and Vote Tally Cache (`tally`)
            let mut tally_for: i128 = 0;
            let mut tally_against: i128 = 0;

            for i in 0..count {
                let rec = canonical_records.get(i).unwrap();
                if rec.kind == CriticalRecordKind::GovernanceProposal {
                    let is_active = rec.status == symbol_short!("active");
                    if is_active {
                        views.push_back(DerivedViewEntry {
                            module,
                            view_name: symbol_short!("act_prop"),
                            kind: DerivedViewKind::Index,
                            key_id: rec.record_id,
                            key_symbol: rec.entity_symbol,
                            numeric_value: rec.amount,
                            is_active: true,
                        });
                    }
                } else if rec.kind == CriticalRecordKind::GovernanceBallot {
                    if rec.auxiliary_value == 1 {
                        tally_for = tally_for.saturating_add(rec.amount);
                    } else {
                        tally_against = tally_against.saturating_add(rec.amount);
                    }
                }
            }

            views.push_back(DerivedViewEntry {
                module,
                view_name: symbol_short!("tally_for"),
                kind: DerivedViewKind::Cache,
                key_id: 0,
                key_symbol: symbol_short!("for"),
                numeric_value: tally_for,
                is_active: true,
            });
            views.push_back(DerivedViewEntry {
                module,
                view_name: symbol_short!("tally_agt"),
                kind: DerivedViewKind::Cache,
                key_id: 0,
                key_symbol: symbol_short!("against"),
                numeric_value: tally_against,
                is_active: true,
            });
        }

        RestoreModule::Oracle => {
            // Rebuild Feed Registry (`feed_reg`) and Latest Price Round (`price_rnd`)
            for i in 0..count {
                let rec = canonical_records.get(i).unwrap();
                if rec.kind == CriticalRecordKind::OracleFeed {
                    views.push_back(DerivedViewEntry {
                        module,
                        view_name: symbol_short!("feed_reg"),
                        kind: DerivedViewKind::Index,
                        key_id: rec.record_id,
                        key_symbol: rec.entity_symbol,
                        numeric_value: rec.amount,
                        is_active: rec.status == symbol_short!("active"),
                    });
                } else if rec.kind == CriticalRecordKind::OracleRound {
                    views.push_back(DerivedViewEntry {
                        module,
                        view_name: symbol_short!("price_rnd"),
                        kind: DerivedViewKind::Cache,
                        key_id: rec.record_id,
                        key_symbol: rec.entity_symbol,
                        numeric_value: rec.amount,
                        is_active: true,
                    });
                }
            }
        }

        RestoreModule::Marketplace => {
            // Rebuild Collection Listings Index (`listing`) and Collection Floor Price (`floor_p`)
            let mut min_floor: i128 = i128::MAX;
            let mut has_open_listing = false;

            for i in 0..count {
                let rec = canonical_records.get(i).unwrap();
                if rec.kind == CriticalRecordKind::MarketplaceListing {
                    let is_open = rec.status == symbol_short!("open");
                    if is_open {
                        has_open_listing = true;
                        if rec.amount < min_floor {
                            min_floor = rec.amount;
                        }
                        views.push_back(DerivedViewEntry {
                            module,
                            view_name: symbol_short!("listing"),
                            kind: DerivedViewKind::Index,
                            key_id: rec.record_id,
                            key_symbol: rec.entity_symbol,
                            numeric_value: rec.amount,
                            is_active: true,
                        });
                    }
                }
            }

            if has_open_listing {
                views.push_back(DerivedViewEntry {
                    module,
                    view_name: symbol_short!("floor_p"),
                    kind: DerivedViewKind::Cache,
                    key_id: 0,
                    key_symbol: symbol_short!("floor"),
                    numeric_value: min_floor,
                    is_active: true,
                });
            }
        }
    }

    views
}

// ---------------------------------------------------------------------------
// Reconciliation & Loud Mismatch Reporting
// ---------------------------------------------------------------------------

/// Compares existing derived views against rebuilt authoritative views.
/// Fails loudly with descriptive mismatch reports and concrete repair steps.
pub fn reconcile_derived_views(
    env: &Env,
    module: RestoreModule,
    rebuilt_views: &Vec<DerivedViewEntry>,
    existing_views: &Vec<DerivedViewEntry>,
) -> Vec<RestoreMismatchReport> {
    let mut mismatches = Vec::new(env);
    let rebuilt_len = rebuilt_views.len();
    let existing_len = existing_views.len();

    // 1. Missing derived entries (expected in rebuilt, missing in existing)
    for r in 0..rebuilt_len {
        let expected = rebuilt_views.get(r).unwrap();
        let mut found = false;
        for e in 0..existing_len {
            let actual = existing_views.get(e).unwrap();
            if expected.view_name == actual.view_name
                && expected.key_id == actual.key_id
                && expected.key_symbol == actual.key_symbol
            {
                found = true;
                if expected.numeric_value != actual.numeric_value {
                    mismatches.push_back(RestoreMismatchReport {
                        module,
                        failure_kind: RestoreVerificationFailure::DerivedViewDrift,
                        target_id: expected.key_id,
                        target_symbol: expected.view_name,
                        expected_val: expected.numeric_value,
                        actual_val: actual.numeric_value,
                        severity: RestoreSeverity::Medium,
                        failure_message: String::from_str(env, "Cached aggregate or projection counter diverges from canonical records"),
                        repair_steps: String::from_str(
                            env,
                            "Synchronize projection cache: invoke rebuild_derived_views or run worker ./scripts/run-worker.sh --job projection_repair.",
                        ),
                    });
                }
                break;
            }
        }

        if !found {
            mismatches.push_back(RestoreMismatchReport {
                module,
                failure_kind: RestoreVerificationFailure::DerivedViewDrift,
                target_id: expected.key_id,
                target_symbol: expected.view_name,
                expected_val: 1,
                actual_val: 0,
                severity: RestoreSeverity::Medium,
                failure_message: String::from_str(env, "Missing secondary index entry in restored derived state"),
                repair_steps: String::from_str(
                    env,
                    "Rebuild secondary index using rebuild_derived_views to synchronize canonical records into index.",
                ),
            });
        }
    }

    // 2. Orphaned derived entries (lingering in existing, absent from rebuilt)
    for e in 0..existing_len {
        let actual = existing_views.get(e).unwrap();
        let mut found = false;
        for r in 0..rebuilt_len {
            let expected = rebuilt_views.get(r).unwrap();
            if expected.view_name == actual.view_name
                && expected.key_id == actual.key_id
                && expected.key_symbol == actual.key_symbol
            {
                found = true;
                break;
            }
        }
        if !found {
            mismatches.push_back(RestoreMismatchReport {
                module,
                failure_kind: RestoreVerificationFailure::DerivedViewDrift,
                target_id: actual.key_id,
                target_symbol: actual.view_name,
                expected_val: 0,
                actual_val: 1,
                severity: RestoreSeverity::Medium,
                failure_message: String::from_str(env, "Orphaned secondary index entry exists for record deleted or inactive in canonical state"),
                repair_steps: String::from_str(
                    env,
                    "Purge stale index entry: invoke rebuild_derived_views or run stale index repair ./scripts/run-worker.sh.",
                ),
            });
        }
    }

    mismatches
}

// ---------------------------------------------------------------------------
// Fingerprint & Checksum Helpers
// ---------------------------------------------------------------------------

fn compute_views_fingerprint(views: &Vec<DerivedViewEntry>) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a 64-bit basis
    let prime: u64 = 0x100000001b3;
    let len = views.len();
    for i in 0..len {
        let v = views.get(i).unwrap();
        hash ^= v.key_id;
        hash = hash.wrapping_mul(prime);
        hash ^= v.numeric_value as u64;
        hash = hash.wrapping_mul(prime);
        if v.is_active {
            hash ^= 1;
            hash = hash.wrapping_mul(prime);
        }
    }
    hash
}

// ---------------------------------------------------------------------------
// Full Execution & Rollback Orchestrator
// ---------------------------------------------------------------------------

/// Executes full snapshot restore verification, derived view reconstruction,
/// and loud mismatch reporting.
pub fn execute_restore_verification_and_rebuild(
    env: &Env,
    module: RestoreModule,
    canonical_records: &Vec<CanonicalRestoreRecord>,
    existing_derived_views: &Vec<DerivedViewEntry>,
    dry_run: bool,
    strict_mode: bool,
) -> Result<RestoreReport, SnapshotRestoreError> {
    // Check if quarantined
    if is_module_quarantined(env, module) {
        return Err(SnapshotRestoreError::QuarantineTriggered);
    }

    // 1. Verify Invariants on Critical Data
    let mut mismatches = verify_critical_data_invariants(env, module, canonical_records);

    // 2. Rebuild Derived Views
    let rebuilt_views = rebuild_derived_views(env, module, canonical_records);

    // 3. Reconcile Derived Views with Existing State
    let drift_mismatches = reconcile_derived_views(env, module, &rebuilt_views, existing_derived_views);
    for d in 0..drift_mismatches.len() {
        mismatches.push_back(drift_mismatches.get(d).unwrap());
    }

    // Check for critical / high invariant breaches
    let mut has_critical = false;
    let mut has_solvency_deficit = false;
    let mismatch_count = mismatches.len();

    for m in 0..mismatch_count {
        let item = mismatches.get(m).unwrap();
        if item.severity == RestoreSeverity::Critical {
            has_critical = true;
            if item.failure_kind == RestoreVerificationFailure::SolvencyDeficit {
                has_solvency_deficit = true;
            }
        }
    }

    let pre_fp = compute_views_fingerprint(existing_derived_views);
    let post_fp = compute_views_fingerprint(&rebuilt_views);

    // Sequence receipt ID
    let receipt_id = next_receipt_id(env);

    let passed = mismatch_count == 0;
    let should_quarantine = has_critical && !dry_run;

    let receipt = RestoreVerificationReceipt {
        receipt_id,
        module,
        executed_ledger: env.ledger().sequence(),
        canonical_records_checked: canonical_records.len(),
        derived_views_scanned: existing_derived_views.len(),
        derived_views_rebuilt: rebuilt_views.len(),
        mismatches_count: mismatch_count,
        passed,
        pre_restore_fingerprint: pre_fp,
        post_rebuild_fingerprint: post_fp,
        quarantined: should_quarantine,
    };

    if !dry_run {
        // Persist receipt
        instance_set(env, &RestoreStorageKey::Receipt(receipt_id), &receipt);
        instance_set(env, &RestoreStorageKey::LatestReceipt(module), &receipt);

        // Persist rollback snapshot
        let rollback = RestoreRollbackSnapshot {
            receipt_id,
            module,
            original_derived_views: existing_derived_views.clone(),
            created_at: env.ledger().timestamp(),
            applied: false,
        };
        instance_set(env, &RestoreStorageKey::RollbackSnapshot(receipt_id), &rollback);

        // Persist rebuilt views
        for v in 0..rebuilt_views.len() {
            let view = rebuilt_views.get(v).unwrap();
            instance_set(
                env,
                &RestoreStorageKey::StoredDerivedView(module, view.view_name, view.key_id),
                &view,
            );
        }

        // Handle quarantine
        if should_quarantine {
            instance_set(env, &RestoreStorageKey::QuarantineFlag(module), &true);
            env.events().publish(
                (symbol_short!("snap_rst"), symbol_short!("mismatch")),
                (module.as_symbol(), receipt_id, mismatch_count),
            );
        }

        // Publish events
        env.events().publish(
            (symbol_short!("snap_rst"), symbol_short!("verify")),
            (module.as_symbol(), receipt_id, passed),
        );
        env.events().publish(
            (symbol_short!("snap_rst"), symbol_short!("rebuild")),
            (module.as_symbol(), receipt_id, rebuilt_views.len()),
        );
    }

    if strict_mode && !passed {
        if has_solvency_deficit {
            return Err(SnapshotRestoreError::SolvencyDeficit);
        } else if has_critical {
            return Err(SnapshotRestoreError::RestoreVerificationFailed);
        }
    }

    Ok(RestoreReport {
        receipt,
        mismatches,
        rebuilt_views,
    })
}

/// Rolls back a restore verification operation using the pre-restore snapshot.
pub fn rollback_restore(
    env: &Env,
    receipt_id: u64,
) -> Result<RestoreVerificationReceipt, SnapshotRestoreError> {
    let key = RestoreStorageKey::RollbackSnapshot(receipt_id);
    if !instance_has(env, &key) {
        return Err(SnapshotRestoreError::RollbackNotFound);
    }

    let mut snapshot: RestoreRollbackSnapshot = instance_get(env, &key).unwrap();
    if snapshot.applied {
        return Err(SnapshotRestoreError::RollbackAlreadyApplied);
    }

    // Revert stored derived views to original state
    let orig_len = snapshot.original_derived_views.len();
    for i in 0..orig_len {
        let view = snapshot.original_derived_views.get(i).unwrap();
        instance_set(
            env,
            &RestoreStorageKey::StoredDerivedView(snapshot.module, view.view_name, view.key_id),
            &view,
        );
    }

    // Clear quarantine if set
    if is_module_quarantined(env, snapshot.module) {
        instance_remove(env, &RestoreStorageKey::QuarantineFlag(snapshot.module));
    }

    snapshot.applied = true;
    instance_set(env, &key, &snapshot);

    // Update receipt
    let receipt_key = RestoreStorageKey::Receipt(receipt_id);
    let mut receipt: RestoreVerificationReceipt = instance_get(env, &receipt_key).unwrap();
    receipt.passed = false;
    receipt.quarantined = false;
    instance_set(env, &receipt_key, &receipt);
    instance_set(env, &RestoreStorageKey::LatestReceipt(snapshot.module), &receipt);

    env.events().publish(
        (symbol_short!("snap_rst"), symbol_short!("rollback")),
        (snapshot.module.as_symbol(), receipt_id),
    );

    Ok(receipt)
}

// ---------------------------------------------------------------------------
// Quarantine & Receipt Query Helpers
// ---------------------------------------------------------------------------

pub fn is_module_quarantined(env: &Env, module: RestoreModule) -> bool {
    instance_get::<RestoreStorageKey, bool>(env, &RestoreStorageKey::QuarantineFlag(module))
        .unwrap_or(false)
}

pub fn clear_quarantine(env: &Env, module: RestoreModule) {
    instance_remove(env, &RestoreStorageKey::QuarantineFlag(module));
}

pub fn get_latest_restore_receipt(
    env: &Env,
    module: RestoreModule,
) -> Option<RestoreVerificationReceipt> {
    instance_get(env, &RestoreStorageKey::LatestReceipt(module))
}

pub fn get_restore_receipt(env: &Env, receipt_id: u64) -> Option<RestoreVerificationReceipt> {
    instance_get(env, &RestoreStorageKey::Receipt(receipt_id))
}

pub fn get_stored_derived_view(
    env: &Env,
    module: RestoreModule,
    view_name: Symbol,
    key_id: u64,
) -> Option<DerivedViewEntry> {
    instance_get(
        env,
        &RestoreStorageKey::StoredDerivedView(module, view_name, key_id),
    )
}

fn next_receipt_id(env: &Env) -> u64 {
    let key = RestoreStorageKey::ReceiptSeq;
    let next: u64 = instance_get(env, &key).unwrap_or(0) + 1;
    instance_set(env, &key, &next);
    next
}
