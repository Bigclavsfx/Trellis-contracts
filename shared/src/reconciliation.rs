use soroban_sdk::{contracttype, contracterror, Env, String, Vec};

/// Represents a state record as observed by a specific source
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRecord {
    pub id: u64,
    pub amount: i128,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriftType {
    MissingRecord,
    DuplicateRecord,
    StaleRecord,
    InconsistentBalance,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriftItem {
    pub record_id: u64,
    pub drift_type: DriftType,
    pub description: String,
    pub repair_guidance: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationReport {
    pub total_records_scanned: u32,
    pub drifts_detected: Vec<DriftItem>,
}

/// Deterministic key used to identify a candidate duplicate group.
/// Two records are considered candidate duplicates when they share the same
/// `id` and `amount`. The `timestamp` is intentionally excluded so that
/// records that differ only by observation time are still grouped together.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateCandidate {
    pub record_id: u64,
    pub amount: i128,
    pub occurrences: u32,
    pub earliest_timestamp: u64,
    pub latest_timestamp: u64,
    /// Deterministic fingerprint of the candidate group, derived from
    /// `(record_id, amount)` only. Stable across runs and orderings.
    pub fingerprint: u64,
}

/// Lifecycle state of a merge review action.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeReviewState {
    Pending,
    Approved,
    Rejected,
    Applied,
    Reverted,
}

/// A reviewable, auditable merge action for a duplicate candidate.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeReviewAction {
    pub action_id: u64,
    pub candidate: DuplicateCandidate,
    pub state: MergeReviewState,
    pub reviewer: String,
    pub reason: String,
    /// Snapshot of the records that would be collapsed by this merge.
    /// Retained so the action can be reversed (reverted) after application.
    pub affected_records: Vec<SourceRecord>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Errors surfaced by the merge review workflow.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MergeReviewError {
    /// The referenced action id does not exist.
    UnknownAction = 1,
    /// The action is not in a state that permits the requested transition.
    InvalidTransition = 2,
    /// The candidate group no longer matches the underlying records.
    StaleCandidate = 3,
}

/// Deterministic fingerprint for a duplicate candidate group.
/// Uses a fixed FNV-1a style mix over `(record_id, amount)` so that the same
/// inputs always produce the same fingerprint regardless of iteration order.
pub fn duplicate_fingerprint(record_id: u64, amount: i128) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut id = record_id;
    let mut i = 0;
    while i < 8 {
        hash ^= (id & 0xff) as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        id >>= 8;
        i += 1;
    }
    let mut amt = amount as u128;
    let mut j = 0;
    while j < 16 {
        hash ^= (amt & 0xff) as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        amt >>= 8;
        j += 1;
    }
    hash
}

/// Detects candidate duplicates deterministically across a single source.
/// Records are grouped by `(id, amount)`; any group with more than one
/// occurrence is a candidate. Output is sorted by `fingerprint` ascending so
/// that the result is reproducible regardless of input ordering.
pub fn detect_duplicate_candidates(env: &Env, records: Vec<SourceRecord>) -> Vec<DuplicateCandidate> {
    let mut candidates: Vec<DuplicateCandidate> = Vec::new(env);
    let mut i = 0;
    while i < records.len() {
        let rec = records.get(i).unwrap();
        let fp = duplicate_fingerprint(rec.id, rec.amount);

        // Skip if this fingerprint has already been emitted.
        let mut already_emitted = false;
        let mut c = 0;
        while c < candidates.len() {
            if candidates.get(c).unwrap().fingerprint == fp {
                already_emitted = true;
                break;
            }
            c += 1;
        }
        if already_emitted {
            i += 1;
            continue;
        }

        let mut occurrences: u32 = 0;
        let mut earliest: u64 = rec.timestamp;
        let mut latest: u64 = rec.timestamp;
        let mut j = 0;
        while j < records.len() {
            let other = records.get(j).unwrap();
            if other.id == rec.id && other.amount == rec.amount {
                occurrences += 1;
                if other.timestamp < earliest {
                    earliest = other.timestamp;
                }
                if other.timestamp > latest {
                    latest = other.timestamp;
                }
            }
            j += 1;
        }

        if occurrences > 1 {
            candidates.push_back(DuplicateCandidate {
                record_id: rec.id,
                amount: rec.amount,
                occurrences,
                earliest_timestamp: earliest,
                latest_timestamp: latest,
                fingerprint: fp,
            });
        }
        i += 1;
    }

    // Insertion sort by fingerprint for determinism (Vec has no sort in Soroban).
    let mut a = 1;
    while a < candidates.len() {
        let key = candidates.get(a).unwrap();
        let mut b = a;
        while b > 0 {
            let prev = candidates.get(b - 1).unwrap();
            if prev.fingerprint <= key.fingerprint {
                break;
            }
            candidates.set(b, prev);
            b -= 1;
        }
        candidates.set(b, key);
        a += 1;
    }

    candidates
}

/// Runs a dry-run reconciliation across ledger, database, and user-facing records.
/// Checks for invariants and returns a report with detected drift and repair guidance.
pub fn run_reconciliation(
    env: &Env,
    ledger_records: Vec<SourceRecord>,
    db_records: Vec<SourceRecord>,
    user_records: Vec<SourceRecord>,
    current_timestamp: u64,
) -> ReconciliationReport {
    let mut drifts = Vec::new(env);
    let mut total_scanned = 0;
    
    // A simple O(N^2) or linear check approach. Since Soroban Vec doesn't have a HashMap, we'll iterate.
    // For large lists, an off-chain indexer would use a real db, but for contract-level / dry-run logic:
    
    // Check Ledger against DB and User
    let mut i = 0;
    while i < ledger_records.len() {
        let l_rec = ledger_records.get(i).unwrap();
        total_scanned += 1;
        
        let mut found_in_db = false;
        let mut db_rec_match = l_rec.clone();
        
        let mut db_count = 0;
        let mut j = 0;
        while j < db_records.len() {
            let d_rec = db_records.get(j).unwrap();
            if d_rec.id == l_rec.id {
                found_in_db = true;
                db_rec_match = d_rec;
                db_count += 1;
            }
            j += 1;
        }
        
        if db_count > 1 {
            drifts.push_back(DriftItem {
                record_id: l_rec.id,
                drift_type: DriftType::DuplicateRecord,
                description: String::from_str(env, "Record duplicated in database"),
                repair_guidance: String::from_str(env, "Remove duplicates in DB keeping the latest timestamp"),
            });
        }
        
        if !found_in_db {
            drifts.push_back(DriftItem {
                record_id: l_rec.id,
                drift_type: DriftType::MissingRecord,
                description: String::from_str(env, "Ledger record missing in database"),
                repair_guidance: String::from_str(env, "Re-sync database from ledger events"),
            });
        } else {
            // Check balance consistency
            if db_rec_match.amount != l_rec.amount {
                drifts.push_back(DriftItem {
                    record_id: l_rec.id,
                    drift_type: DriftType::InconsistentBalance,
                    description: String::from_str(env, "Database amount does not match ledger"),
                    repair_guidance: String::from_str(env, "Update database amount to match ledger canonical state"),
                });
            }
            
            // Check stale record (e.g. lag > 1000 units)
            if l_rec.timestamp > db_rec_match.timestamp + 1000 {
                drifts.push_back(DriftItem {
                    record_id: l_rec.id,
                    drift_type: DriftType::StaleRecord,
                    description: String::from_str(env, "Database record is stale compared to ledger"),
                    repair_guidance: String::from_str(env, "Trigger a fast-forward sync for this record"),
                });
            }
        }
        
        // Similarly for user records
        let mut found_in_user = false;
        let mut user_rec_match = l_rec.clone();
        
        let mut k = 0;
        while k < user_records.len() {
            let u_rec = user_records.get(k).unwrap();
            if u_rec.id == l_rec.id {
                found_in_user = true;
                user_rec_match = u_rec;
            }
            k += 1;
        }
        
        if !found_in_user {
            // Might be okay if user hasn't refreshed, but flag as missing in cache
            drifts.push_back(DriftItem {
                record_id: l_rec.id,
                drift_type: DriftType::MissingRecord,
                description: String::from_str(env, "Ledger record missing in user view"),
                repair_guidance: String::from_str(env, "Invalidate user cache for this record"),
            });
        } else if user_rec_match.amount != l_rec.amount {
            drifts.push_back(DriftItem {
                record_id: l_rec.id,
                drift_type: DriftType::InconsistentBalance,
                description: String::from_str(env, "User view amount does not match ledger"),
                repair_guidance: String::from_str(env, "Force client refresh of balances"),
            });
        }
        
        i += 1;
    }
    
    // Also check if there are DB records not in ledger
    let mut j = 0;
    while j < db_records.len() {
        let d_rec = db_records.get(j).unwrap();
        let mut found_in_ledger = false;
        
        let mut i = 0;
        while i < ledger_records.len() {
            if ledger_records.get(i).unwrap().id == d_rec.id {
                found_in_ledger = true;
                break;
            }
            i += 1;
        }
        
        if !found_in_ledger {
            drifts.push_back(DriftItem {
                record_id: d_rec.id,
                drift_type: DriftType::MissingRecord,
                description: String::from_str(env, "Database record missing in ledger (orphan)"),
                repair_guidance: String::from_str(env, "Archive or delete orphan database record"),
            });
            total_scanned += 1;
        }
        
        j += 1;
    }

    ReconciliationReport {
        total_records_scanned: total_scanned,
        drifts_detected: drifts,
    }
}

// ===========================================================================
// Multi-Module Projection Reconciliation Engine (Issue #238)
// ===========================================================================

use soroban_sdk::{symbol_short, Address, Symbol};
use crate::storage::{instance_get, instance_set, persistent_read, persistent_set};

/// Storage Keys for Treasury Module Reconciliation
pub const TREASURY_STRAT_OK: Symbol = symbol_short!("strat_ok");
pub const TREASURY_STRAT_LST: Symbol = symbol_short!("strat_lst");
pub const TREASURY_STRAT_POS: Symbol = symbol_short!("strat_pos");
pub const TREASURY_STRAT_TOT: Symbol = symbol_short!("strat_tot");

/// Storage Keys for Aid Module Reconciliation
pub const AID_COUNTER: Symbol = symbol_short!("aid_cnt");
pub const AID_RECORD: Symbol = symbol_short!("aid_rec");
pub const AID_SEARCH_CNT: Symbol = symbol_short!("srch_cnt");
pub const AID_SEARCH_PAGE: Symbol = symbol_short!("srch_pg");
pub const AID_DONOR_CNT: Symbol = symbol_short!("dnr_cnt");
pub const AID_DONOR_PAGE: Symbol = symbol_short!("dnr_pg");
pub const AID_RCP_CNT: Symbol = symbol_short!("rcp_cnt");
pub const AID_RCP_PAGE: Symbol = symbol_short!("rcp_pg");

/// Storage Keys for Referral Module Reconciliation
pub const REF_CODE: Symbol = symbol_short!("ref_code");
pub const REF_ADDR: Symbol = symbol_short!("ref_addr");
pub const REF_ACCRUED: Symbol = symbol_short!("ref_acc");
pub const REF_LIFETIME: Symbol = symbol_short!("ref_life");

/// Storage Keys for Governance Module Reconciliation
pub const GOV_ADMIN_SET: Symbol = symbol_short!("adm_set");
pub const GOV_ADMIN_CNT: Symbol = symbol_short!("adm_cnt");
pub const GOV_PROPOSAL: Symbol = symbol_short!("proposal");
pub const GOV_APPROVAL: Symbol = symbol_short!("approval");

/// Storage Keys for Oracle Module Reconciliation
pub const ORACLE_LATEST_PRICE: Symbol = symbol_short!("orc_prc");
pub const ORACLE_LATEST_CNT: Symbol = symbol_short!("orc_cnt");
pub const ORACLE_LATEST_TS: Symbol = symbol_short!("orc_ts");
pub const ORACLE_SUBMISSIONS: Symbol = symbol_short!("orc_subs");

/// Storage Keys for Marketplace Module Reconciliation
pub const MKT_COLL_LISTINGS: Symbol = symbol_short!("mkt_list");
pub const MKT_COLL_AUCTIONS: Symbol = symbol_short!("mkt_auct");
pub const MKT_CANONICAL_LISTING: Symbol = symbol_short!("listing");
pub const MKT_CANONICAL_AUCTION: Symbol = symbol_short!("auction");

/// Core Trellis contract modules subject to projection reconciliation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl ReconciliationModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            ReconciliationModule::Treasury => symbol_short!("treasury"),
            ReconciliationModule::Aid => symbol_short!("aid"),
            ReconciliationModule::Referral => symbol_short!("referral"),
            ReconciliationModule::Governance => symbol_short!("gov"),
            ReconciliationModule::Oracle => symbol_short!("oracle"),
            ReconciliationModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Operational severity rating for detected projection drift.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationSeverity {
    /// Informational drift, non-critical metrics or non-blocking queries.
    Info,
    /// Degraded discovery, query pagination, or index completeness.
    Warning,
    /// Critical invariant violation, financial divergence, or governance sync failure.
    Critical,
}

/// Classification of projection drift between source of truth and derived state.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionDriftKind {
    /// Materialized running balance differs from the sum of canonical position records.
    RunningBalanceMismatch,
    /// Materialized index or counter size differs from the count of canonical records.
    CountMismatch,
    /// Canonical record is absent from the derived secondary index.
    MissingIndexEntry,
    /// Secondary index references a non-existent or deleted canonical record.
    OrphanedIndexEntry,
    /// Bidirectional vanity or alias mapping is inconsistent or broken.
    AsymmetricMapping,
    /// Proposal or election vote tally does not match the sum of active approval records.
    TallyMismatch,
    /// Feed latest timestamp is older than the newest verified submission.
    StaleTimestamp,
    /// Invariant failure (e.g. claimable balance exceeds cumulative lifetime reward).
    InconsistentState,
}

/// An actionable repair instruction targeting ONLY a derived projection.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRepairInstruction {
    pub module: ReconciliationModule,
    pub entity: String,
    pub kind: ProjectionDriftKind,
    pub target_key: Symbol,
    pub target_id: u64,
    pub target_address: Option<Address>,
    pub repaired_value: i128,
}

/// A structured finding reporting drift in a projection.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionDriftItem {
    pub module: ReconciliationModule,
    pub entity: String,
    pub kind: ProjectionDriftKind,
    pub expected_value: i128,
    pub actual_value: i128,
    pub severity: ReconciliationSeverity,
    pub root_cause_hint: String,
    pub repair_instruction: ProjectionRepairInstruction,
}

/// Overall report emitted by a dry-run or reconciliation scan.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionReconciliationReport {
    pub total_entities_scanned: u32,
    pub drifts_detected: Vec<ProjectionDriftItem>,
    pub is_clean: bool,
    pub scanned_modules: Vec<ReconciliationModule>,
}

/// Audit receipt proving successful application of an idempotent repair.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRepairReceipt {
    pub module: ReconciliationModule,
    pub entity: String,
    pub kind: ProjectionDriftKind,
    pub previous_value: i128,
    pub new_value: i128,
    pub executed_at_ledger: u32,
}

/// Pagination bounds to guarantee bounded gas execution within Soroban budget.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginationParams {
    pub offset: u32,
    pub limit: u32,
}

/// Bounded window of reconciliation results with cursor resumption.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginatedReconciliationResult {
    pub report: ProjectionReconciliationReport,
    pub next_offset: u32,
    pub has_more: bool,
}

/// Stable error taxonomy for reconciliation execution (970-979).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ReconciliationError {
    /// Caller is not the authorized contract administrator.
    Unauthorized = 970,
    /// Offset exceeds the available entity range or limit is zero.
    InvalidPagination = 971,
    /// Precondition for executing the repair was not met.
    RepairPreconditionFailed = 972,
    /// Attempted to mutate canonical source of truth instead of derived projection.
    CanonicalMutationForbidden = 973,
}

/// Configuration specifying scopes to include in a reconciliation run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationScopeConfig {
    pub check_treasury: bool,
    pub check_aid: bool,
    pub check_referral: bool,
    pub check_governance: bool,
    pub check_oracle: bool,
    pub check_marketplace: bool,
    pub treasury_strategies: Vec<Address>,
    pub treasury_tokens: Vec<Address>,
    pub treasury_categories: Vec<Symbol>,
    pub aid_ids: Vec<u64>,
    pub aid_donors: Vec<Address>,
    pub aid_recipients: Vec<Address>,
    pub referral_addresses: Vec<Address>,
    pub referral_codes: Vec<Symbol>,
    pub governance_proposal_ids: Vec<u32>,
    pub oracle_feed_ids: Vec<Symbol>,
    pub marketplace_collections: Vec<Address>,
    pub marketplace_listing_ids: Vec<u64>,
    pub marketplace_auction_ids: Vec<u64>,
}

impl ReconciliationScopeConfig {
    pub fn new(env: &Env) -> Self {
        Self {
            check_treasury: true,
            check_aid: true,
            check_referral: true,
            check_governance: true,
            check_oracle: true,
            check_marketplace: true,
            treasury_strategies: Vec::new(env),
            treasury_tokens: Vec::new(env),
            treasury_categories: Vec::new(env),
            aid_ids: Vec::new(env),
            aid_donors: Vec::new(env),
            aid_recipients: Vec::new(env),
            referral_addresses: Vec::new(env),
            referral_codes: Vec::new(env),
            governance_proposal_ids: Vec::new(env),
            oracle_feed_ids: Vec::new(env),
            marketplace_collections: Vec::new(env),
            marketplace_listing_ids: Vec::new(env),
            marketplace_auction_ids: Vec::new(env),
        }
    }
}

// ---------------------------------------------------------------------------
// Treasury Module Projection Checker (Read-Only)
// ---------------------------------------------------------------------------

pub fn reconcile_treasury_storage(
    env: &Env,
    strategies: &Vec<Address>,
    tokens: &Vec<Address>,
    categories: &Vec<Symbol>,
) -> Vec<ProjectionDriftItem> {
    let mut drifts = Vec::new(env);
    let approved_list = instance_get::<_, Vec<Address>>(env, &TREASURY_STRAT_LST)
        .unwrap_or_else(|| Vec::new(env));

    let mut s = 0;
    while s < strategies.len() {
        let strategy = strategies.get(s).unwrap();

        // 1. Calculate canonical sum of all active positions for this strategy
        let mut canonical_total: i128 = 0;
        let mut t = 0;
        while t < tokens.len() {
            let token = tokens.get(t).unwrap();
            let mut c = 0;
            while c < categories.len() {
                let category = categories.get(c).unwrap();
                let position_key = (
                    TREASURY_STRAT_POS,
                    token.clone(),
                    category.clone(),
                    strategy.clone(),
                );
                let position_val = persistent_read::<_, i128>(env, &position_key).unwrap_or(0);
                canonical_total = canonical_total.saturating_add(position_val);
                c += 1;
            }
            t += 1;
        }

        // 2. Read materialized running total
        let total_key = (TREASURY_STRAT_TOT, strategy.clone());
        let projected_total = persistent_read::<_, i128>(env, &total_key).unwrap_or(0);

        if canonical_total != projected_total {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Treasury,
                entity: String::from_str(env, "treasury.strategy_total"),
                kind: ProjectionDriftKind::RunningBalanceMismatch,
                expected_value: canonical_total,
                actual_value: projected_total,
                severity: ReconciliationSeverity::Critical,
                root_cause_hint: String::from_str(
                    env,
                    "Missed decrement in deallocate_reserve_strategy or revoke_reserve_strategy, or failed harvest_yield accounting.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Treasury,
                    entity: String::from_str(env, "treasury.strategy_total"),
                    kind: ProjectionDriftKind::RunningBalanceMismatch,
                    target_key: TREASURY_STRAT_TOT,
                    target_id: 0,
                    target_address: Some(strategy.clone()),
                    repaired_value: canonical_total,
                },
            });
        }

        // 3. Verify strategy approval flag against approved whitelist vector
        let approval_key = (TREASURY_STRAT_OK, strategy.clone());
        let is_approved = persistent_read::<_, bool>(env, &approval_key).unwrap_or(false);

        let mut in_list = false;
        let mut l = 0;
        while l < approved_list.len() {
            if approved_list.get(l).unwrap() == strategy {
                in_list = true;
                break;
            }
            l += 1;
        }

        if is_approved && !in_list {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Treasury,
                entity: String::from_str(env, "treasury.strategy_whitelist"),
                kind: ProjectionDriftKind::MissingIndexEntry,
                expected_value: 1,
                actual_value: 0,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "Strategy approved via approve_reserve_strategy but omitted from STRATEGY_LIST vector.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Treasury,
                    entity: String::from_str(env, "treasury.strategy_whitelist"),
                    kind: ProjectionDriftKind::MissingIndexEntry,
                    target_key: TREASURY_STRAT_LST,
                    target_id: 0,
                    target_address: Some(strategy.clone()),
                    repaired_value: 1,
                },
            });
        } else if !is_approved && in_list {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Treasury,
                entity: String::from_str(env, "treasury.strategy_whitelist"),
                kind: ProjectionDriftKind::OrphanedIndexEntry,
                expected_value: 0,
                actual_value: 1,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "Strategy revoked via revoke_reserve_strategy but not pruned from STRATEGY_LIST vector.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Treasury,
                    entity: String::from_str(env, "treasury.strategy_whitelist"),
                    kind: ProjectionDriftKind::OrphanedIndexEntry,
                    target_key: TREASURY_STRAT_LST,
                    target_id: 0,
                    target_address: Some(strategy.clone()),
                    repaired_value: 0,
                },
            });
        }

        s += 1;
    }

    drifts
}

// ---------------------------------------------------------------------------
// Aid Module Projection Checker (Read-Only)
// ---------------------------------------------------------------------------

pub fn reconcile_aid_storage(
    env: &Env,
    aid_ids: &Vec<u64>,
    donors: &Vec<Address>,
    recipients: &Vec<Address>,
) -> Vec<ProjectionDriftItem> {
    let mut drifts = Vec::new(env);

    // 1. Check SearchIndexCount against canonical aid count
    let canonical_aid_count = aid_ids.len() as u32;
    let projected_search_count = persistent_read::<_, u32>(env, &AID_SEARCH_CNT).unwrap_or(0);

    if canonical_aid_count != projected_search_count {
        drifts.push_back(ProjectionDriftItem {
            module: ReconciliationModule::Aid,
            entity: String::from_str(env, "aid.search_index_count"),
            kind: ProjectionDriftKind::CountMismatch,
            expected_value: canonical_aid_count as i128,
            actual_value: projected_search_count as i128,
            severity: ReconciliationSeverity::Warning,
            root_cause_hint: String::from_str(
                env,
                "Partial execution during batch_create_aid where Aid record was committed but SearchIndexCount was not updated.",
            ),
            repair_instruction: ProjectionRepairInstruction {
                module: ReconciliationModule::Aid,
                entity: String::from_str(env, "aid.search_index_count"),
                kind: ProjectionDriftKind::CountMismatch,
                target_key: AID_SEARCH_CNT,
                target_id: 0,
                target_address: None,
                repaired_value: canonical_aid_count as i128,
            },
        });
    }

    // 2. Check SearchIndexPage entries (page 0)
    let search_page = persistent_read::<_, Vec<u64>>(env, &(AID_SEARCH_PAGE, 0_u32))
        .unwrap_or_else(|| Vec::new(env));

    let mut i = 0;
    while i < aid_ids.len() {
        let id = aid_ids.get(i).unwrap();
        let mut in_page = false;
        let mut p = 0;
        while p < search_page.len() {
            if search_page.get(p).unwrap() == id {
                in_page = true;
                break;
            }
            p += 1;
        }

        if !in_page {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Aid,
                entity: String::from_str(env, "aid.search_index_page"),
                kind: ProjectionDriftKind::MissingIndexEntry,
                expected_value: id as i128,
                actual_value: 0,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "Aid record stored canonically but omitted from SearchIndexPage; interrupted transaction during batch_create_aid.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Aid,
                    entity: String::from_str(env, "aid.search_index_page"),
                    kind: ProjectionDriftKind::MissingIndexEntry,
                    target_key: AID_SEARCH_PAGE,
                    target_id: id,
                    target_address: None,
                    repaired_value: id as i128,
                },
            });
        }
        i += 1;
    }

    // 3. Check DonorAidCount against actual donor aids
    let mut d = 0;
    while d < donors.len() {
        let donor = donors.get(d).unwrap();
        let mut canonical_donor_aids: u32 = 0;
        let mut a = 0;
        while a < aid_ids.len() {
            let aid_id = aid_ids.get(a).unwrap();
            let aid_key = (AID_RECORD, aid_id);
            if let Some((rec_donor, _rec_rcp, _amount)) =
                persistent_read::<_, (Address, Address, i128)>(env, &aid_key)
            {
                if rec_donor == donor {
                    canonical_donor_aids += 1;
                }
            }
            a += 1;
        }

        let donor_cnt_key = (AID_DONOR_CNT, donor.clone());
        let projected_donor_cnt = persistent_read::<_, u32>(env, &donor_cnt_key).unwrap_or(0);

        if canonical_donor_aids != projected_donor_cnt {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Aid,
                entity: String::from_str(env, "aid.donor_aid_count"),
                kind: ProjectionDriftKind::CountMismatch,
                expected_value: canonical_donor_aids as i128,
                actual_value: projected_donor_cnt as i128,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "claim_aid or refund_aid executed without updating donor index counts.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Aid,
                    entity: String::from_str(env, "aid.donor_aid_count"),
                    kind: ProjectionDriftKind::CountMismatch,
                    target_key: AID_DONOR_CNT,
                    target_id: 0,
                    target_address: Some(donor.clone()),
                    repaired_value: canonical_donor_aids as i128,
                },
            });
        }
        d += 1;
    }

    // 4. Check RecipientAidCount against actual recipient aids
    let mut r = 0;
    while r < recipients.len() {
        let recipient = recipients.get(r).unwrap();
        let mut canonical_rcp_aids: u32 = 0;
        let mut a = 0;
        while a < aid_ids.len() {
            let aid_id = aid_ids.get(a).unwrap();
            let aid_key = (AID_RECORD, aid_id);
            if let Some((_rec_donor, rec_rcp, _amount)) =
                persistent_read::<_, (Address, Address, i128)>(env, &aid_key)
            {
                if rec_rcp == recipient {
                    canonical_rcp_aids += 1;
                }
            }
            a += 1;
        }

        let rcp_cnt_key = (AID_RCP_CNT, recipient.clone());
        let projected_rcp_cnt = persistent_read::<_, u32>(env, &rcp_cnt_key).unwrap_or(0);

        if canonical_rcp_aids != projected_rcp_cnt {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Aid,
                entity: String::from_str(env, "aid.recipient_aid_count"),
                kind: ProjectionDriftKind::CountMismatch,
                expected_value: canonical_rcp_aids as i128,
                actual_value: projected_rcp_cnt as i128,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "claim_aid or refund_aid executed without updating recipient index counts.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Aid,
                    entity: String::from_str(env, "aid.recipient_aid_count"),
                    kind: ProjectionDriftKind::CountMismatch,
                    target_key: AID_RCP_CNT,
                    target_id: 0,
                    target_address: Some(recipient.clone()),
                    repaired_value: canonical_rcp_aids as i128,
                },
            });
        }
        r += 1;
    }

    drifts
}

// ---------------------------------------------------------------------------
// Referral Module Projection Checker (Read-Only)
// ---------------------------------------------------------------------------

pub fn reconcile_referral_storage(
    env: &Env,
    addresses: &Vec<Address>,
    _codes: &Vec<Symbol>,
) -> Vec<ProjectionDriftItem> {
    let mut drifts = Vec::new(env);

    let mut a = 0;
    while a < addresses.len() {
        let addr = addresses.get(a).unwrap();

        // 1. Verify bidirectional vanity code mapping
        let addr_to_code_key = (REF_ADDR, addr.clone());
        if let Some(code) = persistent_read::<_, Symbol>(env, &addr_to_code_key) {
            let code_to_addr_key = (REF_CODE, code.clone());
            let mapped_addr = persistent_read::<_, Address>(env, &code_to_addr_key);
            let symmetric = match mapped_addr {
                Some(ref target) => target == &addr,
                None => false,
            };

            if !symmetric {
                drifts.push_back(ProjectionDriftItem {
                    module: ReconciliationModule::Referral,
                    entity: String::from_str(env, "referral.vanity_code_mapping"),
                    kind: ProjectionDriftKind::AsymmetricMapping,
                    expected_value: 1,
                    actual_value: 0,
                    severity: ReconciliationSeverity::Warning,
                    root_cause_hint: String::from_str(
                        env,
                        "Asymmetric write during set_referral_code; AddressToCode set without corresponding ReferralCode mapping (or vice versa).",
                    ),
                    repair_instruction: ProjectionRepairInstruction {
                        module: ReconciliationModule::Referral,
                        entity: String::from_str(env, "referral.vanity_code_mapping"),
                        kind: ProjectionDriftKind::AsymmetricMapping,
                        target_key: REF_CODE,
                        target_id: 0,
                        target_address: Some(addr.clone()),
                        repaired_value: 1,
                    },
                });
            }
        }

        // 2. Check Accrued <= LifetimeAccrued ceiling invariant
        let accrued_key = (REF_ACCRUED, addr.clone());
        let lifetime_key = (REF_LIFETIME, addr.clone());
        let accrued = persistent_read::<_, i128>(env, &accrued_key).unwrap_or(0);
        let lifetime = persistent_read::<_, i128>(env, &lifetime_key).unwrap_or(0);

        if accrued > lifetime {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Referral,
                entity: String::from_str(env, "referral.accrual_ceiling"),
                kind: ProjectionDriftKind::InconsistentState,
                expected_value: accrued,
                actual_value: lifetime,
                severity: ReconciliationSeverity::Critical,
                root_cause_hint: String::from_str(
                    env,
                    "Accrued claimable reward exceeds LifetimeAccrued; direct balance increment without updating lifetime accumulator in record_referral.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Referral,
                    entity: String::from_str(env, "referral.accrual_ceiling"),
                    kind: ProjectionDriftKind::InconsistentState,
                    target_key: REF_LIFETIME,
                    target_id: 0,
                    target_address: Some(addr.clone()),
                    repaired_value: accrued,
                },
            });
        }

        a += 1;
    }

    drifts
}

// ---------------------------------------------------------------------------
// Governance Module Projection Checker (Read-Only)
// ---------------------------------------------------------------------------

pub fn reconcile_governance_storage(
    env: &Env,
    proposal_ids: &Vec<u32>,
) -> Vec<ProjectionDriftItem> {
    let mut drifts = Vec::new(env);

    // 1. Check KEY_ADMIN_COUNT against KEY_ADMIN_SET.len()
    let admin_set = instance_get::<_, Vec<Address>>(env, &GOV_ADMIN_SET)
        .unwrap_or_else(|| Vec::new(env));
    let canonical_admin_count = admin_set.len() as u32;
    let projected_admin_count = instance_get::<_, u32>(env, &GOV_ADMIN_CNT).unwrap_or(0);

    if canonical_admin_count != projected_admin_count {
        drifts.push_back(ProjectionDriftItem {
            module: ReconciliationModule::Governance,
            entity: String::from_str(env, "governance.admin_count"),
            kind: ProjectionDriftKind::CountMismatch,
            expected_value: canonical_admin_count as i128,
            actual_value: projected_admin_count as i128,
            severity: ReconciliationSeverity::Critical,
            root_cause_hint: String::from_str(
                env,
                "execute_proposal added or removed an admin from KEY_ADMIN_SET without synchronizing adm_cnt.",
            ),
            repair_instruction: ProjectionRepairInstruction {
                module: ReconciliationModule::Governance,
                entity: String::from_str(env, "governance.admin_count"),
                kind: ProjectionDriftKind::CountMismatch,
                target_key: GOV_ADMIN_CNT,
                target_id: 0,
                target_address: None,
                repaired_value: canonical_admin_count as i128,
            },
        });
    }

    // 2. Check Proposal approval tally against active admin approval records
    let mut p = 0;
    while p < proposal_ids.len() {
        let proposal_id = proposal_ids.get(p).unwrap();

        let mut canonical_approvals: u32 = 0;
        let mut a = 0;
        while a < admin_set.len() {
            let admin = admin_set.get(a).unwrap();
            let approval_key = (GOV_APPROVAL, proposal_id, admin);
            if persistent_read::<_, bool>(env, &approval_key).unwrap_or(false) {
                canonical_approvals += 1;
            }
            a += 1;
        }

        let prop_key = (GOV_PROPOSAL, proposal_id);
        let cached_tally = persistent_read::<_, u32>(env, &prop_key).unwrap_or(0);

        if canonical_approvals != cached_tally {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Governance,
                entity: String::from_str(env, "governance.proposal_approval_tally"),
                kind: ProjectionDriftKind::TallyMismatch,
                expected_value: canonical_approvals as i128,
                actual_value: cached_tally as i128,
                severity: ReconciliationSeverity::Critical,
                root_cause_hint: String::from_str(
                    env,
                    "Admin approval cast or admin revocation modified approval records without updating Proposal.approvals tally.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Governance,
                    entity: String::from_str(env, "governance.proposal_approval_tally"),
                    kind: ProjectionDriftKind::TallyMismatch,
                    target_key: GOV_PROPOSAL,
                    target_id: proposal_id as u64,
                    target_address: None,
                    repaired_value: canonical_approvals as i128,
                },
            });
        }

        p += 1;
    }

    drifts
}

// ---------------------------------------------------------------------------
// Oracle Module Projection Checker (Read-Only)
// ---------------------------------------------------------------------------

pub fn reconcile_oracle_storage(
    env: &Env,
    feed_ids: &Vec<Symbol>,
) -> Vec<ProjectionDriftItem> {
    let mut drifts = Vec::new(env);

    let mut f = 0;
    while f < feed_ids.len() {
        let feed_id = feed_ids.get(f).unwrap();

        // 1. Read canonical submissions list
        let subs_key = (ORACLE_SUBMISSIONS, feed_id.clone());
        let submissions = persistent_read::<_, Vec<(Address, i128, u64)>>(env, &subs_key)
            .unwrap_or_else(|| Vec::new(env));
        let canonical_count = submissions.len() as u32;

        let mut canonical_max_ts: u64 = 0;
        let mut s = 0;
        while s < submissions.len() {
            let (_addr, _price, ts) = submissions.get(s).unwrap();
            if ts > canonical_max_ts {
                canonical_max_ts = ts;
            }
            s += 1;
        }

        // 2. Compare against cached FeedLatest submission_count
        let cnt_key = (ORACLE_LATEST_CNT, feed_id.clone());
        let projected_count = persistent_read::<_, u32>(env, &cnt_key).unwrap_or(0);

        if canonical_count != projected_count {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Oracle,
                entity: String::from_str(env, "oracle.feed_submission_count"),
                kind: ProjectionDriftKind::CountMismatch,
                expected_value: canonical_count as i128,
                actual_value: projected_count as i128,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "submit_price round executed partial aggregation or inactive submitter was not pruned from submission_count.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Oracle,
                    entity: String::from_str(env, "oracle.feed_submission_count"),
                    kind: ProjectionDriftKind::CountMismatch,
                    target_key: ORACLE_LATEST_CNT,
                    target_id: 0,
                    target_address: None,
                    repaired_value: canonical_count as i128,
                },
            });
        }

        // 3. Compare cached timestamp against newest submission
        let ts_key = (ORACLE_LATEST_TS, feed_id.clone());
        let projected_ts = persistent_read::<_, u64>(env, &ts_key).unwrap_or(0);

        if canonical_max_ts > 0 && canonical_max_ts != projected_ts {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Oracle,
                entity: String::from_str(env, "oracle.feed_latest_timestamp"),
                kind: ProjectionDriftKind::StaleTimestamp,
                expected_value: canonical_max_ts as i128,
                actual_value: projected_ts as i128,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "Out-of-order submission update corrupted FeedLatest timestamp projection.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Oracle,
                    entity: String::from_str(env, "oracle.feed_latest_timestamp"),
                    kind: ProjectionDriftKind::StaleTimestamp,
                    target_key: ORACLE_LATEST_TS,
                    target_id: 0,
                    target_address: None,
                    repaired_value: canonical_max_ts as i128,
                },
            });
        }

        f += 1;
    }

    drifts
}

// ---------------------------------------------------------------------------
// Marketplace Module Projection Checker (Read-Only)
// ---------------------------------------------------------------------------

pub fn reconcile_marketplace_storage(
    env: &Env,
    collections: &Vec<Address>,
    listing_ids: &Vec<u64>,
    auction_ids: &Vec<u64>,
) -> Vec<ProjectionDriftItem> {
    let mut drifts = Vec::new(env);

    let mut c = 0;
    while c < collections.len() {
        let collection = collections.get(c).unwrap();

        // 1. Calculate canonical active listings for collection
        let mut canonical_listings: u32 = 0;
        let mut l = 0;
        while l < listing_ids.len() {
            let id = listing_ids.get(l).unwrap();
            let listing_key = (MKT_CANONICAL_LISTING, id);
            if let Some((col, is_active)) =
                persistent_read::<_, (Address, bool)>(env, &listing_key)
            {
                if col == collection && is_active {
                    canonical_listings += 1;
                }
            }
            l += 1;
        }

        let listings_key = (MKT_COLL_LISTINGS, collection.clone());
        let projected_listings = persistent_read::<_, u32>(env, &listings_key).unwrap_or(0);

        if canonical_listings != projected_listings {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Marketplace,
                entity: String::from_str(env, "marketplace.collection_active_listings"),
                kind: ProjectionDriftKind::CountMismatch,
                expected_value: canonical_listings as i128,
                actual_value: projected_listings as i128,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "Missing update_collection_stats(-1, 0) during buy_listing or cancel_listing in nft-marketplace.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Marketplace,
                    entity: String::from_str(env, "marketplace.collection_active_listings"),
                    kind: ProjectionDriftKind::CountMismatch,
                    target_key: MKT_COLL_LISTINGS,
                    target_id: 0,
                    target_address: Some(collection.clone()),
                    repaired_value: canonical_listings as i128,
                },
            });
        }

        // 2. Calculate canonical active auctions for collection
        let mut canonical_auctions: u32 = 0;
        let mut a = 0;
        while a < auction_ids.len() {
            let id = auction_ids.get(a).unwrap();
            let auction_key = (MKT_CANONICAL_AUCTION, id);
            if let Some((col, is_active)) =
                persistent_read::<_, (Address, bool)>(env, &auction_key)
            {
                if col == collection && is_active {
                    canonical_auctions += 1;
                }
            }
            a += 1;
        }

        let auctions_key = (MKT_COLL_AUCTIONS, collection.clone());
        let projected_auctions = persistent_read::<_, u32>(env, &auctions_key).unwrap_or(0);

        if canonical_auctions != projected_auctions {
            drifts.push_back(ProjectionDriftItem {
                module: ReconciliationModule::Marketplace,
                entity: String::from_str(env, "marketplace.collection_active_auctions"),
                kind: ProjectionDriftKind::CountMismatch,
                expected_value: canonical_auctions as i128,
                actual_value: projected_auctions as i128,
                severity: ReconciliationSeverity::Warning,
                root_cause_hint: String::from_str(
                    env,
                    "Missing update_collection_stats(0, -1) during finalize_auction or cancel_auction in nft-marketplace.",
                ),
                repair_instruction: ProjectionRepairInstruction {
                    module: ReconciliationModule::Marketplace,
                    entity: String::from_str(env, "marketplace.collection_active_auctions"),
                    kind: ProjectionDriftKind::CountMismatch,
                    target_key: MKT_COLL_AUCTIONS,
                    target_id: 0,
                    target_address: Some(collection.clone()),
                    repaired_value: canonical_auctions as i128,
                },
            });
        }

        c += 1;
    }

    drifts
}

// ---------------------------------------------------------------------------
// Unified Dry-Run Reconciliation Engine
// ---------------------------------------------------------------------------

/// Executes a multi-module dry-run projection reconciliation scan.
/// Reads from persistent/instance storage without making ANY storage modifications.
pub fn run_projection_reconciliation(
    env: &Env,
    config: &ReconciliationScopeConfig,
) -> ProjectionReconciliationReport {
    let mut all_drifts = Vec::new(env);
    let mut scanned_modules = Vec::new(env);
    let mut total_scanned: u32 = 0;

    if config.check_treasury {
        scanned_modules.push_back(ReconciliationModule::Treasury);
        let treasury_drifts = reconcile_treasury_storage(
            env,
            &config.treasury_strategies,
            &config.treasury_tokens,
            &config.treasury_categories,
        );
        total_scanned += config.treasury_strategies.len();
        let mut i = 0;
        while i < treasury_drifts.len() {
            all_drifts.push_back(treasury_drifts.get(i).unwrap());
            i += 1;
        }
    }

    if config.check_aid {
        scanned_modules.push_back(ReconciliationModule::Aid);
        let aid_drifts = reconcile_aid_storage(
            env,
            &config.aid_ids,
            &config.aid_donors,
            &config.aid_recipients,
        );
        total_scanned += config.aid_ids.len() + config.aid_donors.len() + config.aid_recipients.len();
        let mut i = 0;
        while i < aid_drifts.len() {
            all_drifts.push_back(aid_drifts.get(i).unwrap());
            i += 1;
        }
    }

    if config.check_referral {
        scanned_modules.push_back(ReconciliationModule::Referral);
        let ref_drifts = reconcile_referral_storage(
            env,
            &config.referral_addresses,
            &config.referral_codes,
        );
        total_scanned += config.referral_addresses.len();
        let mut i = 0;
        while i < ref_drifts.len() {
            all_drifts.push_back(ref_drifts.get(i).unwrap());
            i += 1;
        }
    }

    if config.check_governance {
        scanned_modules.push_back(ReconciliationModule::Governance);
        let gov_drifts = reconcile_governance_storage(env, &config.governance_proposal_ids);
        total_scanned += 1 + config.governance_proposal_ids.len();
        let mut i = 0;
        while i < gov_drifts.len() {
            all_drifts.push_back(gov_drifts.get(i).unwrap());
            i += 1;
        }
    }

    if config.check_oracle {
        scanned_modules.push_back(ReconciliationModule::Oracle);
        let oracle_drifts = reconcile_oracle_storage(env, &config.oracle_feed_ids);
        total_scanned += config.oracle_feed_ids.len();
        let mut i = 0;
        while i < oracle_drifts.len() {
            all_drifts.push_back(oracle_drifts.get(i).unwrap());
            i += 1;
        }
    }

    if config.check_marketplace {
        scanned_modules.push_back(ReconciliationModule::Marketplace);
        let mkt_drifts = reconcile_marketplace_storage(
            env,
            &config.marketplace_collections,
            &config.marketplace_listing_ids,
            &config.marketplace_auction_ids,
        );
        total_scanned += config.marketplace_collections.len();
        let mut i = 0;
        while i < mkt_drifts.len() {
            all_drifts.push_back(mkt_drifts.get(i).unwrap());
            i += 1;
        }
    }

    let is_clean = all_drifts.is_empty();

    ProjectionReconciliationReport {
        total_entities_scanned: total_scanned,
        drifts_detected: all_drifts,
        is_clean,
        scanned_modules,
    }
}

// ---------------------------------------------------------------------------
// Paginated Execution Support (Resource Budget Bounding)
// ---------------------------------------------------------------------------

pub fn run_paginated_projection_reconciliation(
    env: &Env,
    drifts: &Vec<ProjectionDriftItem>,
    pagination: &PaginationParams,
) -> Result<PaginatedReconciliationResult, ReconciliationError> {
    if pagination.limit == 0 {
        return Err(ReconciliationError::InvalidPagination);
    }

    let total = drifts.len();
    let mut page_drifts = Vec::new(env);

    if pagination.offset < total {
        let end = (pagination.offset + pagination.limit).min(total);
        let mut i = pagination.offset;
        while i < end {
            page_drifts.push_back(drifts.get(i).unwrap());
            i += 1;
        }
    }

    let next_offset = pagination.offset + page_drifts.len();
    let has_more = next_offset < total;

    let mut scanned_mods = Vec::new(env);
    let mut i = 0;
    while i < page_drifts.len() {
        let m = page_drifts.get(i).unwrap().module;
        let mut exists = false;
        let mut j = 0;
        while j < scanned_mods.len() {
            if scanned_mods.get(j).unwrap() == m {
                exists = true;
                break;
            }
            j += 1;
        }
        if !exists {
            scanned_mods.push_back(m);
        }
        i += 1;
    }

    Ok(PaginatedReconciliationResult {
        report: ProjectionReconciliationReport {
            total_entities_scanned: total,
            is_clean: total == 0,
            drifts_detected: page_drifts,
            scanned_modules: scanned_mods,
        },
        next_offset,
        has_more,
    })
}

// ---------------------------------------------------------------------------
// Explicit, Idempotent, Authorization-Gated Repair Execution
// ---------------------------------------------------------------------------

/// Applies projection repairs targeting derived/projected storage keys only.
/// Strictly refuses to mutate canonical source of truth records.
/// Authorized for contract administrator only.
pub fn execute_projection_repairs(
    env: &Env,
    admin: &Address,
    instructions: &Vec<ProjectionRepairInstruction>,
) -> Result<Vec<ProjectionRepairReceipt>, ReconciliationError> {
    // 1. Authorize caller via shared admin verification
    if crate::auth::require_admin(env, admin).is_err() {
        return Err(ReconciliationError::Unauthorized);
    }

    let mut receipts = Vec::new(env);
    let current_ledger = env.ledger().sequence();

    let mut i = 0;
    while i < instructions.len() {
        let instr = instructions.get(i).unwrap();

        // 2. Reject canonical keys immediately to preserve source-of-truth integrity
        if instr.target_key == TREASURY_STRAT_POS
            || instr.target_key == TREASURY_STRAT_OK
            || instr.target_key == AID_RECORD
            || instr.target_key == GOV_ADMIN_SET
            || instr.target_key == GOV_APPROVAL
            || instr.target_key == ORACLE_SUBMISSIONS
            || instr.target_key == MKT_CANONICAL_LISTING
            || instr.target_key == MKT_CANONICAL_AUCTION
        {
            return Err(ReconciliationError::CanonicalMutationForbidden);
        }

        // 3. Mutate strictly derived projection keys
        let (prev_val, new_val) = match instr.module {
            ReconciliationModule::Treasury => {
                if instr.target_key == TREASURY_STRAT_TOT {
                    if let Some(ref strat) = instr.target_address {
                        let total_key = (TREASURY_STRAT_TOT, strat.clone());
                        let prev = persistent_read::<_, i128>(env, &total_key).unwrap_or(0);
                        persistent_set(env, &total_key, &instr.repaired_value);
                        (prev, instr.repaired_value)
                    } else {
                        (0, instr.repaired_value)
                    }
                } else if instr.target_key == TREASURY_STRAT_LST {
                    let mut list = instance_get::<_, Vec<Address>>(env, &TREASURY_STRAT_LST)
                        .unwrap_or_else(|| Vec::new(env));
                    let prev = list.len() as i128;
                    if let Some(ref strat) = instr.target_address {
                        if instr.repaired_value == 1 {
                            // Add if not present
                            let mut exists = false;
                            let mut l = 0;
                            while l < list.len() {
                                if &list.get(l).unwrap() == strat {
                                    exists = true;
                                    break;
                                }
                                l += 1;
                            }
                            if !exists {
                                list.push_back(strat.clone());
                            }
                        } else {
                            // Remove if present
                            let mut new_list = Vec::new(env);
                            let mut l = 0;
                            while l < list.len() {
                                let item = list.get(l).unwrap();
                                if &item != strat {
                                    new_list.push_back(item);
                                }
                                l += 1;
                            }
                            list = new_list;
                        }
                        instance_set(env, &TREASURY_STRAT_LST, &list);
                    }
                    (prev, list.len() as i128)
                } else {
                    (0, instr.repaired_value)
                }
            }
            ReconciliationModule::Aid => {
                if instr.target_key == AID_SEARCH_CNT {
                    let prev = persistent_read::<_, u32>(env, &AID_SEARCH_CNT).unwrap_or(0) as i128;
                    persistent_set(env, &AID_SEARCH_CNT, &(instr.repaired_value as u32));
                    (prev, instr.repaired_value)
                } else if instr.target_key == AID_SEARCH_PAGE {
                    let mut page = persistent_read::<_, Vec<u64>>(env, &(AID_SEARCH_PAGE, 0_u32))
                        .unwrap_or_else(|| Vec::new(env));
                    let prev = page.len() as i128;
                    let target_aid = instr.target_id;
                    let mut exists = false;
                    let mut p = 0;
                    while p < page.len() {
                        if page.get(p).unwrap() == target_aid {
                            exists = true;
                            break;
                        }
                        p += 1;
                    }
                    if !exists && target_aid > 0 {
                        page.push_back(target_aid);
                        persistent_set(env, &(AID_SEARCH_PAGE, 0_u32), &page);
                    }
                    (prev, page.len() as i128)
                } else if instr.target_key == AID_DONOR_CNT {
                    if let Some(ref donor) = instr.target_address {
                        let donor_key = (AID_DONOR_CNT, donor.clone());
                        let prev = persistent_read::<_, u32>(env, &donor_key).unwrap_or(0) as i128;
                        persistent_set(env, &donor_key, &(instr.repaired_value as u32));
                        (prev, instr.repaired_value)
                    } else {
                        (0, instr.repaired_value)
                    }
                } else if instr.target_key == AID_RCP_CNT {
                    if let Some(ref recipient) = instr.target_address {
                        let rcp_key = (AID_RCP_CNT, recipient.clone());
                        let prev = persistent_read::<_, u32>(env, &rcp_key).unwrap_or(0) as i128;
                        persistent_set(env, &rcp_key, &(instr.repaired_value as u32));
                        (prev, instr.repaired_value)
                    } else {
                        (0, instr.repaired_value)
                    }
                } else {
                    (0, instr.repaired_value)
                }
            }
            ReconciliationModule::Referral => {
                if instr.target_key == REF_LIFETIME {
                    if let Some(ref addr) = instr.target_address {
                        let key = (REF_LIFETIME, addr.clone());
                        let prev = persistent_read::<_, i128>(env, &key).unwrap_or(0);
                        persistent_set(env, &key, &instr.repaired_value);
                        (prev, instr.repaired_value)
                    } else {
                        (0, instr.repaired_value)
                    }
                } else if instr.target_key == REF_CODE {
                    // Re-sync vanity mapping
                    if let Some(ref addr) = instr.target_address {
                        if let Some(code) = persistent_read::<_, Symbol>(env, &(REF_ADDR, addr.clone())) {
                            let prev = if persistent_read::<_, Address>(env, &(REF_CODE, code.clone())).is_some() {
                                1
                            } else {
                                0
                            };
                            persistent_set(env, &(REF_CODE, code), addr);
                            (prev, 1)
                        } else {
                            (0, 0)
                        }
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, instr.repaired_value)
                }
            }
            ReconciliationModule::Governance => {
                if instr.target_key == GOV_ADMIN_CNT {
                    let prev = instance_get::<_, u32>(env, &GOV_ADMIN_CNT).unwrap_or(0) as i128;
                    instance_set(env, &GOV_ADMIN_CNT, &(instr.repaired_value as u32));
                    (prev, instr.repaired_value)
                } else if instr.target_key == GOV_PROPOSAL {
                    let prop_key = (GOV_PROPOSAL, instr.target_id as u32);
                    let prev = persistent_read::<_, u32>(env, &prop_key).unwrap_or(0) as i128;
                    persistent_set(env, &prop_key, &(instr.repaired_value as u32));
                    (prev, instr.repaired_value)
                } else {
                    (0, instr.repaired_value)
                }
            }
            ReconciliationModule::Oracle => {
                if instr.target_key == ORACLE_LATEST_CNT {
                    let prev = persistent_read::<_, u32>(env, &ORACLE_LATEST_CNT).unwrap_or(0) as i128;
                    persistent_set(env, &ORACLE_LATEST_CNT, &(instr.repaired_value as u32));
                    (prev, instr.repaired_value)
                } else if instr.target_key == ORACLE_LATEST_TS {
                    let prev = persistent_read::<_, u64>(env, &ORACLE_LATEST_TS).unwrap_or(0) as i128;
                    persistent_set(env, &ORACLE_LATEST_TS, &(instr.repaired_value as u64));
                    (prev, instr.repaired_value)
                } else {
                    (0, instr.repaired_value)
                }
            }
            ReconciliationModule::Marketplace => {
                if instr.target_key == MKT_COLL_LISTINGS {
                    if let Some(ref col) = instr.target_address {
                        let key = (MKT_COLL_LISTINGS, col.clone());
                        let prev = persistent_read::<_, u32>(env, &key).unwrap_or(0) as i128;
                        persistent_set(env, &key, &(instr.repaired_value as u32));
                        (prev, instr.repaired_value)
                    } else {
                        (0, instr.repaired_value)
                    }
                } else if instr.target_key == MKT_COLL_AUCTIONS {
                    if let Some(ref col) = instr.target_address {
                        let key = (MKT_COLL_AUCTIONS, col.clone());
                        let prev = persistent_read::<_, u32>(env, &key).unwrap_or(0) as i128;
                        persistent_set(env, &key, &(instr.repaired_value as u32));
                        (prev, instr.repaired_value)
                    } else {
                        (0, instr.repaired_value)
                    }
                } else {
                    (0, instr.repaired_value)
                }
            }
        };

        // 4. Publish auditable reconciliation event
        env.events().publish(
            (symbol_short!("reconcile"), symbol_short!("repaired"), instr.module.as_symbol()),
            (instr.entity.clone(), instr.repaired_value),
        );

        receipts.push_back(ProjectionRepairReceipt {
            module: instr.module,
            entity: instr.entity.clone(),
            kind: instr.kind,
            previous_value: prev_val,
            new_value: new_val,
            executed_at_ledger: current_ledger,
        });

        i += 1;
    }

    Ok(receipts)
}

