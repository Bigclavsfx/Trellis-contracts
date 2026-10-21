#![no_std]
pub mod abuse;
pub mod accessibility;
pub mod analytics;
pub mod audit_ledger;
pub mod auth;
pub mod backfill;
pub mod batch;
pub mod canonical;
pub mod chaos;
pub mod client;
pub mod client_validation;
pub mod compat;
pub mod config;
pub mod config_version;
pub mod domain_events;
pub mod dashboard;
pub mod degradation;
pub mod diagnostics;
pub mod disclosure;
pub mod error_taxonomy;
pub mod errors;
pub mod event_dead_letter;
pub mod events;
pub mod evidence;
pub mod export;
pub mod feature_flags;
pub mod health;
pub mod health_guard;
pub mod history;
pub mod idempotency;
pub mod impersonation;
pub mod import;
pub mod invariants;
pub mod jobs;
pub mod lifecycle;
pub mod lifecycle_events;
pub mod math;
pub mod migration;
pub mod operational_metadata;
pub mod operator_runbook;
pub mod pagination;
pub mod payments;
pub mod policy;
pub mod policy_preview;
pub mod preflight;
pub mod public_status;
pub mod projection_repair;
pub mod quota;
pub mod reconciliation;
pub mod recovery;
pub mod release_readiness;
pub mod replay;
pub mod risk_scoring;
pub mod rollout_guard;
pub mod retention;
pub mod sanitize;
pub mod semantic;
pub mod snapshot;
pub mod storage;
pub mod stale_state;
pub mod storage_version;
pub mod telemetry;
pub mod timeline;
pub mod time_window;
pub mod utils;
pub mod webhook;
pub mod workflow_correlation;
// Re-export the most commonly-needed items at crate root for ergonomic use.
pub use abuse::{
    assess_high_impact_abuse, evaluate_high_impact_abuse, get_abuse_policy, get_abuse_state,
    is_abuse_blocked, record_abuse, set_abuse_policy, AbusePolicy, AbuseState,
    HighImpactAbuseContext,
};
pub use risk_scoring::{
    assess_and_record, evaluate_risk, get_actor_profile, get_risk_policy, reset_actor_risk,
    set_actor_exemption, set_risk_policy, ActionContext, ActorRiskProfile, HighImpactAction,
    RiskAssessment, RiskError, RiskFactor, RiskFactorType, RiskPolicy, RiskTier, RiskVerdict,
};
pub use audit_ledger::{
append_event, append_financial, append_privileged, checkpoint, entry_hash, export_digest,
export_ledger, genesis_hash, get_entry, head, length, publish_head_checkpoint, verify_chain,
verify_export,
AuditEventClass, AuditEventKind, AuditEventParams, AuditLedgerEntry, AuditLedgerExport,
AuditLedgerHead, AuditLedgerKey, AuditVerificationFailure, AuditVerificationReport,
AUDIT_DOMAIN, AUDIT_LEGDER_SCHEMA_VERSION, DEFAULT_EXPORT_LIMIT, MAX_EXPORT_LIMIT,
MAX_VERIFY_ENTRIES,
};
pub use analytics::{
aggregate_events, is_fully_suppressed, is_safe_dimension, is_sensitive_dimension,
AggregateBucket, AnalyticsReport, PrivacyConfig, RawObservation, ANALYTICS_METRIC_VERSION,
};
pub use auth::{
accept_ownership_transfer, cancel_ownership_transfer, get_admin,
get_pending_ownership_transfer, has_permission, initialize_admin, propose_ownership_transfer,
require_admin, require_not_paused, require_permission, role_for_permission, set_admin,
PendingOwnershipTransfer, Permission, Role,
};
pub use backfill::{
advance_checkpoint, begin_backfill, clear_checkpoint, complete_backfill, dry_run as dry_run_backfill,
fail_backfill, is_resumable as is_backfill_resumable, load_checkpoint as load_backfill_checkpoint,
save_checkpoint as save_backfill_checkpoint, BackfillAction, BackfillCheckpoint, BackfillError,
BackfillItem, BackfillMode, BackfillModule, BackfillPlan, BackfillReport, BackfillStatus,
};
pub use batch::{
batch_invoke_no_args, execute_multi_invoke, execute_multi_transfer, multi_transfer_all,
BatchConfig, BatchError, BatchMode, BatchResult, BatchTransfer, OperationResult,
ABSOLUTE_MAX_BATCH_SIZE, DEFAULT_MAX_BATCH_SIZE,
};
pub use canonical::{
canonical_bytes, canonical_fingerprint, canonicalize_legacy, ensure_supported_encoding,
is_legacy_encoding, normalize_int, normalize_text, parse_legacy_kv, CanonicalPart,
CANONICAL_ENCODING_VERSION, LEGACY_ENCODING_VERSION, MAX_FIELD_LEN,
};
pub use client::{
client_schema_fingerprint, format_client_error, AidSummaryResponse, ClientErrorResponse,
ClientReceipt, CreateAidRequest, CreateEscrowRequest, CreateListingRequest,
CreateProposalRequest, EscrowSummaryResponse, ListingSummaryResponse, OperationStatus,
ProposalSummaryResponse, RebalanceRequest, RebalanceSummaryResponse, CLIENT_SCHEMA_VERSION,
};
pub use client_validation::{
    begin_idempotent_request, complete_idempotent_request, ensure_supported_client_schema_version,
    fingerprint_request, validate_create_aid_request, validate_create_escrow_request,
    validate_create_listing_request, validate_create_proposal_request, validate_rebalance_request,
    MAX_SLIPPAGE_BPS, MAX_SUPPORTED_CLIENT_SCHEMA_VERSION, MIN_SUPPORTED_CLIENT_SCHEMA_VERSION,
};
pub use compat::{
current_schema_version, downgrade_v2_to_v1, ensure_supported_version, from_latest,
is_deprecated_version, is_supported_version, migrate_v1_to_v2, new_current_record, to_latest,
CompatAidStatus, CurrentAidRecord, LegacyAidRecord, VersionedAidRecord,
CURRENT_RECORD_SCHEMA_VERSION, MAX_SUPPORTED_RECORD_SCHEMA_VERSION,
MIN_SUPPORTED_RECORD_SCHEMA_VERSION, RECORD_SCHEMA_V1, RECORD_SCHEMA_V2,
};
pub use config::{
validate_feature_flag, validate_full_config, validate_network_id, validate_rpc_url,
validate_secret_key, Environment, RedactedSecret,
};
pub use domain_events::{consumer_version, publish_event, validate_event, DomainEvent, EventSchema,
EventValidationError};
pub use dashboard::{
add_external_reference, create_partial_failure, generate_dashboard,
generate_enhanced_dashboard, group_by_age, group_by_operation_type, group_by_retryability,
group_by_severity, redact_partial_failure, DashboardReport, ExternalReference, FailureGroup,
FailureSeverity, FailureState, HealthCategory, OperationType, PartialFailure,
RedactedDeadLetter, RedactedPartialFailure,
};
pub use disclosure::{DetailField, DetailSeverity, TransactionDetail, TransactionDetailBuilder};
pub use error_taxonomy::{
    describe_error, problem_details, remediation_hint, ErrorCategory, ErrorDomain, ErrorInfo,
    ProblemDetails, ProblemDetailsCode, ProblemDetailsRegistry, ProblemDetailsSpec,
    PROBLEM_DETAILS_SCHEMA_VERSION,
};
pub use errors::Error;
pub use export::{
authorize_export, authorize_module_export, cancel_export_stream, create_export,
ensure_supported_version as ensure_supported_export_version, finalize_export_stream,
generate_export, get_export_session, init_export_stream, is_forbidden_field, is_safe_field,
is_supported_version as is_supported_export_version, purge_forbidden_fields, redact_fields,
register_export_artifact, scope_allows_record, stream_export_chunk, assert_records_visible,
ExportArtifact, ExportCancellationReport, ExportError, ExportField, ExportFormat,
ExportMetadata, ExportModule, ExportRecord, ExportReport, ExportRequest, ExportScope,
ExportSession, ExportStreamStatus, RecordSensitivity, StreamChunkResult,
ABSOLUTE_MAX_EXPORT_RECORDS, CURRENT_EXPORT_SCHEMA_VERSION, DEFAULT_EXPORT_CHUNK_SIZE,
DEFAULT_EXPORT_TTL_LEDGERS, DEFAULT_MAX_EXPORT_RECORDS, EXPORT_SCHEMA_V1,
MAX_EXPORT_CHUNK_SIZE, MAX_EXPORT_TTL_LEDGERS, MAX_SUPPORTED_EXPORT_SCHEMA_VERSION,
MIN_SUPPORTED_EXPORT_SCHEMA_VERSION,
};
pub use event_dead_letter::{
    dead_letter_ids as event_dead_letter_ids, discard_dead_letter as discard_event_dead_letter,
    dispatch_event, get_dead_letter as get_event_dead_letter, pending_dead_letter_ids,
    requeue_dead_letter as requeue_event_dead_letter, retry_dead_letter, DispatchOutcome,
    DomainEventHandler, EventDeadLetter, EventDispatchStatus, EVENT_DLQ_DEAD_LETTERED,
    EVENT_DLQ_REQUEUED, EVENT_DLQ_RESOLVED, EVENT_DLQ_RETRIED, EVENT_DLQ_TOPIC,
};
pub use events::{
emit, emit_collection_registered, emit_import_committed, emit_import_failed,
emit_import_simulated, emit_nft_auction, emit_nft_bid, emit_nft_listed, emit_nft_offer,
emit_nft_settle, emit_nft_sold, emit_royalty_paid,
};
pub use evidence::*;
pub use chaos::*;
pub use health::{
get_dependency_health, list_dependency_health, set_dependency_health, DependencyHealth,
DependencyStatus,
};
pub use health_guard::{
    breaker_state, check_and_record_attempt, execute_guarded, get_retry_budget,
    is_registered_reporter, register_reporter, report_health_check, reset_breaker,
    revoke_reporter, set_retry_budget, CircuitBreakerState, RetryBudget,
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_COOLDOWN_LEDGERS, DEFAULT_RETRY_WINDOW_LEDGERS,
    TOPIC_HEALTH_GUARD,
};
pub use impersonation::{
check_action_permission, create_session, get_active_sessions_for_impersonator,
get_active_sessions_for_user, get_current_impersonation, is_being_impersonated, record_action,
revoke_session, validate_session, ImpersonationAction, ImpersonationError, ImpersonationScope,
ImpersonationSession, ResourceScope, ResourceType, SessionParams, SessionResult, SessionState,
DEFAULT_SESSION_DURATION, MAX_CONCURRENT_SESSIONS, MAX_SESSION_DURATION,
};
pub use import::{
compute_batch_fingerprint, dry_run as dry_run_import, execute_import,
generate_rollback_guidance, get_import_counter, get_imported_record, has_imported_record,
validate_config as validate_import_config, DuplicatePolicy, ImportConfig, ImportError,
ImportItem, ImportMode, ImportReport, RollbackGuidance, RowError, StoredImportRecord,
ABSOLUTE_MAX_IMPORT_SIZE, DEFAULT_MAX_IMPORT_SIZE, MAX_EXTERNAL_ID_LEN,
};
pub use invariants::*;
pub use jobs::{
configure_worker, dead_letter_job_ids, dedupe_key_pair, dedupe_key_u64, default_worker_config,
discard_dead_letter, enqueue_escrow_refund, enqueue_job, get_job, get_receipt, job_stats,
next_due_ledger, pause_worker, pending_job_ids, reprocess_job, requeue_dead_letter,
resume_worker, run_due_job, worker_config, BackoffMode, DeadLetterRecord, EnqueueOutcome, Job,
JobCounters, JobError, JobHandler, JobKind, JobPayload, JobReceipt, JobStats, JobStatus,
RetryPolicy, RunOutcome, WorkerConfig, WorkerKey, ESCROW_REFUND_TAG, JOB_DEAD_LETTERED,
JOB_ENQUEUED, JOB_REQUEUED, JOB_RETRIED, JOB_SUCCEEDED, JOB_TOPIC,
};
pub use lifecycle_events::{
assert_lifecycle_sequence, emit_aid_event, emit_contract_record_event, emit_escrow_event,
emit_lifecycle_transition, emit_proposal_event, emit_resource_transition, LifecycleEvent,
LifecycleResource, LifecycleTransition, LIFECYCLE_EVENT_SCHEMA_VERSION, LIFECYCLE_TOPIC,
STATE_NONE,
};
pub use migration::{
begin_migration, clear_journal, dry_run, evaluate_post_checks, expected_step, fail_migration,
finish_migration, is_resumable, load_journal, mark_step_complete, resume_index, save_journal,
DryRunReport, MigrationError, MigrationJournal, MigrationPlan, MigrationStatus, MigrationStep,
MigrationStepKind, PostCheck, PostCheckReport, RollbackStrategy,
};
pub use operational_metadata::{
active_operational_hold, apply_operational_cleanup, classify_field,
default_operational_policy, get_effective_operational_policy, get_operational_hold,
get_operational_metadata, get_operational_retention_policy, has_operational_metadata,
minimize_legacy_metadata, plan_operational_cleanup, plan_operational_cleanup_at,
place_operational_hold, release_operational_hold, review_and_minimize,
set_operational_retention_policy, store_operational_metadata, to_shared_retention_record,
FieldSensitivity, MetadataClass, MinimizedField, MinimizationReviewResult,
OperationalCleanupPlan, OperationalCleanupReport, OperationalHold, OperationalModule,
OperationalRetentionPolicy, RawMetadataField, StoredOperationalMetadata,
};
pub use pagination::{
paginate_id_list, paginate_id_range, Direction, PageRequest, PageResponse, DEFAULT_MAX_SCAN,
DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT,
};
pub use payments::{
calculate_fee, calculate_fee_split, create_escrow, deduct_fee, get_escrow, refund_escrow,
release_escrow, safe_transfer, safe_transfer_from_contract, EscrowRecord, EscrowState,
FeeConfig,
};
pub use preflight::{
preflight, require_preflight, requires_preflight, PreflightCheck, PreflightCode,
PreflightInput, PreflightOperation, PreflightReport, PreflightStatus, RiskLevel,
EXPIRY_WARNING_WINDOW_LEGEERS, HIGH_VALUE_WARNING_BPS,
};
pub use public_status::{
    get_public_status, set_public_status, PublicStatus, PublicStatusReason, PublicStatusRecord,
};
pub use projection_repair::{
default_monitor_config, detect_cache_drift, detect_index_drift,
execute_or_queue_projection_repair, get_latest_audit_receipt, get_monitor_config,
get_pending_queue_count, get_queued_item, process_queued_repair, recommend_repair,
rollback_projection_repair, set_monitor_config, ProjectionAuditReceipt,
ProjectionKind, ProjectionModule, ProjectionMonitorConfig, ProjectionRepairAction,
ProjectionRepairError, ProjectionRepairQueueItem, ProjectionRepairSnapshot, ProjectionScope,
ProjectionStalenessSeverity, RepairActionOutcome, RepairRecommendation, StaleDriftKind,
StaleProjectionItem, DEFAULT_MAX_IMMEDIATE_REPAIRS, DEFAULT_MAX_LAG_LEDGERS,
DEFAULT_REBUILD_THRESHOLD_PCT,
};
pub use quota::{
check_and_consume, get_quota_config, get_quota_status, get_usage, reset_quota,
set_quota_config, QuotaConfig, QuotaStatus, QuotaUsage,
};
pub use reconciliation::{
    execute_projection_repairs, reconcile_aid_storage, reconcile_governance_storage,
    reconcile_marketplace_storage, reconcile_oracle_storage, reconcile_referral_storage,
    reconcile_treasury_storage, run_paginated_projection_reconciliation,
    run_projection_reconciliation, run_reconciliation, DriftItem, DriftType,
    PaginatedReconciliationResult, PaginationParams, ProjectionDriftItem, ProjectionDriftKind,
    ProjectionReconciliationReport, ProjectionRepairInstruction, ProjectionRepairReceipt,
    ReconciliationError, ReconciliationModule, ReconciliationReport, ReconciliationScopeConfig,
    ReconciliationSeverity, SourceRecord, AID_COUNTER, AID_DONOR_CNT, AID_DONOR_PAGE,
    AID_RCP_CNT, AID_RCP_PAGE, AID_RECORD, AID_SEARCH_CNT, AID_SEARCH_PAGE, GOV_ADMIN_CNT,
    GOV_ADMIN_SET, GOV_APPROVAL, GOV_PROPOSAL, MKT_CANONICAL_AUCTION, MKT_CANONICAL_LISTING,
    MKT_COLL_AUCTIONS, MKT_COLL_LISTINGS, ORACLE_LATEST_CNT, ORACLE_LATEST_PRICE,
    ORACLE_LATEST_TS, ORACLE_SUBMISSIONS, REF_ACCRUED, REF_ADDR, REF_CODE, REF_LIFETIME,
    TREASURY_STRAT_LST, TREASURY_STRAT_OK, TREASURY_STRAT_POS, TREASURY_STRAT_TOT,
};
pub use recovery::{
abandon, complete_step, diagnostics, fail_step, is_stuck, next_action, open_operation, resume,
OperationKind, OperationState, RecoveryCheckpoint, RecoveryDiagnostics, RecoveryError,
RecoveryStep, StepOutcome,
};
pub use release_readiness::{
create_gate_check, evaluate_release_readiness, get_readiness_report, get_rehearsal_count,
get_rehearsal_receipt, is_release_ready, rehearse_rollback, GateCheck, GateCheckStatus,
GateKind, ReleaseGateError, ReleaseManifest, ReleaseModule, ReleaseReadinessReport,
RollbackRehearsalParams, RollbackRehearsalReceipt,
};
pub use replay::{consume_payload, ReplayKey, SignedPayload};
pub use rollout_guard::{
default_guard_config, evaluate_rollout_guard, get_guard_config, get_health_metrics,
get_last_rollback_audit, get_last_verification_receipt, init_or_update_guard,
is_rollback_verified, rearm_after_verified_rollback, record_execution_outcome,
trigger_auto_rollback, verify_rollback, GuardDecision, GuardHealthStatus,
ModuleConsistencySnapshot, RollbackAuditRecord, RollbackReason, RollbackVerificationReceipt,
RolloutGuardConfig, RolloutHealthMetrics, RolloutModule, RolloutStage, RolloutTarget,
StateAnomalyKind,
};
pub use retention::{
active_hold, apply_cleanup, class_label, classify, days_to_ledgers, default_policy,
get_effective_policy, get_hold, get_record, get_retention_policy, is_frozen, place_hold,
plan_cleanup, plan_cleanup_at, put_record, release_hold, set_retention_policy, CleanupEntry,
CleanupPlan, CleanupReport, DataClass, HoldReason, RetentionHold, RetentionPolicy,
RetentionRecord, HOLD_INDEFINITE, LEDGERS_PER_DAY, MAX_RETAIN_LEDGERS,
};
pub use sanitize::{
sanitize_text, sanitize_url, trim_whitespace, validate_external_url, validate_safe_text,
SafeScheme, MAX_TEXT_LEN, MAX_URL_LEN,
};
pub use semantic::{
validate_amount, validate_distinct_parties, validate_future_expiry, AmountRule, ExpiryRule,
};
pub use storage::{
instance_get, instance_has, instance_remove, instance_set, is_paused, persistent_extend_ttl,
persistent_get, persistent_has, persistent_remove, persistent_set, set_paused, temporary_get,
temporary_has, temporary_remove, temporary_set, PERSISTENT_BUMP_AMOUNT,
PERSISTENT_TTL_THRESHOLD, TEMPORARY_BUMP_AMOUNT, TEMPORARY_TTL_THRESHOLD,
};
pub use snapshot::{
    capture_snapshot, chain_hash, compute_state_root, export_snapshots, genesis_hash as snapshot_genesis_hash,
    get_snapshot, head as snapshot_head, is_registered_signer, register_signer, revoke_signer,
    verify_chain as verify_snapshot_chain, verify_export as verify_snapshot_export,
    SignedStateSnapshot, SnapshotError, SnapshotExportBundle, SnapshotField, SnapshotHead,
    SnapshotVerificationFailure, SnapshotVerificationReport, DEFAULT_SNAPSHOT_EXPORT_LIMIT,
    MAX_SNAPSHOT_EXPORT_LIMIT, MAX_SNAPSHOT_FIELDS, MAX_VERIFY_SNAPSHOTS, SNAPSHOT_DOMAIN,
    SNAPSHOT_SCHEMA_VERSION,
};
pub use stale_state::{
    check_before_replay, complete_operation, detect as detect_stale_state,
    enqueue as enqueue_operation, resolve_conflict as resolve_queued_conflict, ConflictResolution,
    QueueError, QueuedOperation, QueuedOperationStatus, RecoveryAction, StaleStateReason,
    StaleStateReport, StateSnapshot,
};
pub use telemetry::{
emit_failure, emit_operation, emit_outcome, emit_success, ledger_correlation, publish,
ActorType, TelemetryEvent, TelemetryResult, TelemetryTimer, CORE_OPERATIONS, OP_ESCROW_CREATE,
OP_ESCROW_RELEASE, OP_PAYMENT_TRANSFER, OP_QUOTA_CONSUME, OP_REBALANCE, TELEMETRY_TOPIC,
};
pub use timeline::{
action_audit_trail, anonymous_viewer, append_user_event, audit_trail, can_view, delete_entry,
entry_count, entry_exists, entry_is_redacted, is_maintainer, next_audit_seq, next_seq,
record_action_audit_event, record_audit_event, redact_entry, timeline_page, viewer_for,
ActionAuditEntry, AuditEntry, ResourceLink, TimelineEntry, TimelineEventType, TimelineKey,
TimelinePage, Viewer, Visibility, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MAX_SCAN_PER_PAGE,
};
pub use degradation::{
    default_matrix_entry, evaluate_dependency_decision, execute_with_fallback,
    get_dependency_entry, initialize_standard_matrix, record_dependency_check,
    recover_dependency, register_dependency_entry, DegradationError, DegradationLevel,
    DegradationModule, DependencyFailureMode, DependencyMatrixEntry, ExternalDependencyKind,
    FallbackDecision, FallbackStrategy, RecoveryReceipt, TOPIC_DEGRADATION, TOPIC_FALLBACK,
    TOPIC_RECOVERY,
};
pub use policy_preview::{
    commit_policy_change, default_policy_parameters, get_active_policy, get_simulation_preview,
    rollback_policy_change, set_active_policy, simulate_policy_preview, validate_parameters,
    validate_preview_for_commit, ExpectedSideEffectKind, PolicyImpactSeverity, PolicyModule,
    PolicyParameters, PolicySimulationError, PolicySimulationPreview, PolicyType,
    ProposedPolicyChange, RollbackConstraintReport, SideEffectSummary, DEFAULT_PREVIEW_VALIDITY_LEDGERS,
    TOPIC_POLICY_COMMIT, TOPIC_POLICY_ROLLBACK, TOPIC_POLICY_SIMULATION,
};
pub use utils::{is_expired, now};
#[cfg(test)]
mod test_reconciliation;
#[cfg(test)]
mod test_replay;
#[cfg(test)]
mod test_auth;
#[cfg(test)]
mod test_client;
#[cfg(test)]
mod test_disclosure;
#[cfg(test)]
mod test_import;
#[cfg(test)]
mod test_jobs;
#[cfg(test)]
mod test_pagination;
#[cfg(test)]
mod test_audit_ledger;
#[cfg(test)]
mod test_release_readiness;
#[cfg(test)]
mod test_workflow_correlation;
#[cfg(test)]
mod test_migration;
#[cfg(test)]
mod test_accessibility;
#[cfg(test)]
mod test_degradation;
#[cfg(test)]
mod test_diagnostics;
#[cfg(test)]
mod test_policy_preview;
#[cfg(test)]
mod test_risk_scoring;
#[cfg(test)]
mod test_sanitize;
#[cfg(test)]
mod test_storage;
#[cfg(test)]
mod test_timeline;
#[cfg(test)]
mod test_projection_repair;
// Deterministic ledger-sequence harness controls (Issue #156). Test-only: the
// harness sets the ledger sequence/timestamp explicitly and never reads the
// host clock, so boundary tests are reproducible.
#[cfg(test)]
pub mod ledger_sequence;
#[cfg(test)]
mod test_ledger_sequence;
// Edge-case fixtures for the ledger-sequence harness (Issue #335).
#[cfg(test)]
mod test_ledger_fixtures;
// Schema-compatibility tests for versioned domain events (Issue #337).
#[cfg(test)]
mod test_domain_events;
