use soroban_sdk::{contracttype, symbol_short, Env, String, Symbol, Vec};

use crate::health::{list_dependency_health, DependencyStatus};
use crate::jobs::{is_retryable_error, list_dead_letters};
use crate::reconciliation::{run_reconciliation, SourceRecord};

// ---------------------------------------------------------------------------
// Partial Failure Tracking
// ---------------------------------------------------------------------------

/// Severity classification for partial failures.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureSeverity {
    /// User funds or critical data at risk.
    Critical,
    /// User experience degraded but funds safe.
    High,
    /// Background task failed, no immediate user impact.
    Medium,
    /// Low-priority or informational issue.
    Low,
}

/// Operation type classification for grouping failures.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationType {
    /// Payment or escrow operations.
    Payment,
    /// Token transfers or swaps.
    Transfer,
    /// Background worker jobs.
    Worker,
    /// Webhook delivery.
    Webhook,
    /// External API integration.
    ExternalApi,
    /// Database synchronization.
    DatabaseSync,
    /// Other contract operations.
    Contract,
}

/// Lifecycle state of a partial failure.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureState {
    /// Failure occurred and is pending resolution.
    Unresolved,
    /// Failure is retryable and will be attempted again.
    Retryable,
    /// Failure has been manually ignored by operator.
    Ignored,
    /// Failure has been resolved.
    Resolved,
}

/// Kind of caller driving the operation, for diagnostics.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// A wallet-signed action.
    WalletAction,
    /// A backend API call.
    ApiCall,
    /// A webhook delivery.
    Webhook,
    /// A background worker job.
    Worker,
    /// A browser session.
    BrowserSession,
    /// An on-chain contract call.
    ContractCall,
}

/// External reference ID for tracking across systems.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalReference {
    /// External system identifier (e.g., "stripe", "webhook", "api").
    pub system: Symbol,
    /// Reference ID in that system (redacted if sensitive).
    pub reference_id: String,
    /// Timestamp when this reference was recorded.
    pub recorded_at: u64,
}

/// Enhanced partial failure record with rich metadata.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialFailure {
    /// Unique identifier for this failure record.
    pub failure_id: u64,
    /// Type of operation that failed.
    pub operation_type: OperationType,
    /// Current state of the failure.
    pub state: FailureState,
    /// Severity classification.
    pub severity: FailureSeverity,
    /// Operation identifier (correlation ID or job ID).
    pub operation_id: u64,
    /// External reference IDs for cross-system tracking.
    pub external_refs: Vec<ExternalReference>,
    /// Error code that caused the failure.
    pub error_code: u32,
    /// Ledger sequence when the failure occurred.
    pub failed_at_ledger: u32,
    /// Number of retry attempts made.
    pub retry_attempts: u32,
    /// Whether the error is retryable based on error code.
    pub is_retryable: bool,
    /// Kind of caller driving the operation.
    pub operation_kind: OperationKind,
    /// Age in ledgers since failure.
    pub age_ledgers: u32,
    /// Human-readable description (redacted).
    pub description: String,
}

/// Redacted partial failure for dashboard display (no secrets).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedPartialFailure {
    pub failure_id: u64,
    pub operation_type: OperationType,
    pub state: FailureState,
    pub severity: FailureSeverity,
    pub operation_id: u64,
    pub external_systems: Vec<Symbol>,
    pub error_code: u32,
    pub failed_at_ledger: u32,
    pub retry_attempts: u32,
    pub is_retryable: bool,
    pub age_ledgers: u32,
    pub description: String,
    pub retry_link: String,
    pub inspect_link: String,
    pub remediation_link: String,
}

/// Grouped failures by a specific dimension.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureGroup {
    pub dimension: Symbol,
    pub value: Symbol,
    pub count: u32,
    pub critical_count: u32,
    pub retryable_count: u32,
    pub investigation_link: String,
}

/// Enhanced dashboard report with partial failure tracking.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardReport {
    pub categories: Vec<HealthCategory>,
    pub redacted_dead_letters: Vec<RedactedDeadLetter>,
    pub partial_failures: Vec<RedactedPartialFailure>,
    pub failure_groups: Vec<FailureGroup>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedDeadLetter {
    pub job_id: u64,
    pub attempts: u32,
    pub last_error: u32,
    pub failed_at_ledger: u32,
    pub investigation_link: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthCategory {
    pub name: String,
    pub count: u32,
    pub actionable: bool,
    pub investigation_link: String,
}

/// Generates an operational health dashboard summarizing unresolved failures,
/// stale jobs, reconciliation drift, and user-impacting incidents.
pub fn generate_dashboard(
    env: &Env,
    ledger_records: Vec<SourceRecord>,
    db_records: Vec<SourceRecord>,
    user_records: Vec<SourceRecord>,
    current_timestamp: u64,
) -> DashboardReport {
    let dead_letters = list_dead_letters(env, None, 100);
    let unresolved_count = dead_letters.len();

    let mut redacted_dead_letters = Vec::new(env);
    for dl in dead_letters.into_iter() {
        let link = String::from_str(env, "logs/jobs/dead_letter");
        redacted_dead_letters.push_back(RedactedDeadLetter {
            job_id: dl.job_id,
            attempts: dl.attempts,
            last_error: dl.last_error,
            failed_at_ledger: dl.failed_at_ledger,
            investigation_link: link,
        });
    }

    let rec_report = run_reconciliation(
        env,
        ledger_records,
        db_records,
        user_records,
        current_timestamp,
    );
    let drift_count = rec_report.drifts_detected.len();

    let deps = list_dependency_health(env);
    let mut incident_count = 0;
    for dep in deps.iter() {
        if dep.status == DependencyStatus::Degraded || dep.status == DependencyStatus::Down {
            incident_count += 1;
        }
    }

    let mut categories = Vec::new(env);
    categories.push_back(HealthCategory {
        name: String::from_str(env, "Unresolved Failures & Stale Jobs"),
        count: unresolved_count,
        actionable: unresolved_count > 0,
        investigation_link: String::from_str(env, "dashboard/jobs"),
    });
    categories.push_back(HealthCategory {
        name: String::from_str(env, "Reconciliation Drift"),
        count: drift_count,
        actionable: drift_count > 0,
        investigation_link: String::from_str(env, "dashboard/reconciliation"),
    });
    categories.push_back(HealthCategory {
        name: String::from_str(env, "User-Impacting Incidents"),
        count: incident_count,
        actionable: incident_count > 0,
        investigation_link: String::from_str(env, "dashboard/incidents"),
    });

    DashboardReport {
        categories,
        redacted_dead_letters,
        partial_failures: Vec::new(env),
        failure_groups: Vec::new(env),
    }
}

// ---------------------------------------------------------------------------
// Partial Failure Management
// ---------------------------------------------------------------------------

/// Creates a new partial failure record.
pub fn create_partial_failure(
    env: &Env,
    failure_id: u64,
    operation_type: OperationType,
    operation_id: u64,
    error_code: u32,
    failed_at_ledger: u32,
    operation_kind: OperationKind,
    description: String,
) -> PartialFailure {
    let now_ledger = env.ledger().sequence();
    let age_ledgers = now_ledger.saturating_sub(failed_at_ledger);
    let is_retryable = is_retryable_error(error_code);

    let severity = classify_severity(error_code, operation_type, age_ledgers);
    let state = if is_retryable {
        FailureState::Retryable
    } else {
        FailureState::Unresolved
    };

    PartialFailure {
        failure_id,
        operation_type,
        state,
        severity,
        operation_id,
        external_refs: Vec::new(env),
        error_code,
        failed_at_ledger,
        retry_attempts: 0,
        is_retryable,
        operation_kind,
        age_ledgers,
        description,
    }
}

/// Adds an external reference to a partial failure.
pub fn add_external_reference(
    env: &Env,
    failure: &mut PartialFailure,
    system: Symbol,
    reference_id: String,
) {
    let now = env.ledger().timestamp();
    let external_ref = ExternalReference {
        system,
        reference_id,
        recorded_at: now,
    };
    failure.external_refs.push_back(external_ref);
}

/// Classifies the severity of a failure based on error code and context.
fn classify_severity(
    error_code: u32,
    operation_type: OperationType,
    age_ledgers: u32,
) -> FailureSeverity {
    // Critical errors that affect funds or critical data
    match error_code {
        1 | 8 | 16 | 17 => return FailureSeverity::Critical, // Unauthorized, InsufficientBalance, ImmutableEntry, InvalidHash
        _ => {}
    }

    // High severity for payment/transfer operations
    if matches!(
        operation_type,
        OperationType::Payment | OperationType::Transfer
    ) {
        return FailureSeverity::High;
    }

    // Medium severity for worker jobs that are stale
    if age_ledgers > 1000 {
        return FailureSeverity::Medium;
    }

    // Default to low for other cases
    FailureSeverity::Low
}

/// Redacts a partial failure for dashboard display (removes sensitive data).
pub fn redact_partial_failure(env: &Env, failure: &PartialFailure) -> RedactedPartialFailure {
    let mut external_systems = Vec::new(env);
    for ext_ref in failure.external_refs.iter() {
        external_systems.push_back(ext_ref.system.clone());
    }

    let retry_link = if failure.is_retryable {
        String::from_str(env, "api/retry/{id}")
    } else {
        String::from_str(env, "dashboard/not-retryable")
    };

    let inspect_link = String::from_str(env, "api/inspect/{id}");

    let remediation_link = match failure.state {
        FailureState::Unresolved => String::from_str(env, "docs/remediation/unresolved"),
        FailureState::Retryable => String::from_str(env, "docs/remediation/retryable"),
        FailureState::Ignored => String::from_str(env, "docs/remediation/ignored"),
        FailureState::Resolved => String::from_str(env, "docs/remediation/resolved"),
    };

    RedactedPartialFailure {
        failure_id: failure.failure_id,
        operation_type: failure.operation_type,
        state: failure.state,
        severity: failure.severity,
        operation_id: failure.operation_id,
        external_systems,
        error_code: failure.error_code,
        failed_at_ledger: failure.failed_at_ledger,
        retry_attempts: failure.retry_attempts,
        is_retryable: failure.is_retryable,
        age_ledgers: failure.age_ledgers,
        description: failure.description.clone(),
        retry_link,
        inspect_link,
        remediation_link,
    }
}

/// Groups partial failures by operation type.
pub fn group_by_operation_type(env: &Env, failures: &Vec<PartialFailure>) -> Vec<FailureGroup> {
    let mut groups = Vec::new(env);

    let operation_types = [
        OperationType::Payment,
        OperationType::Transfer,
        OperationType::Worker,
        OperationType::Webhook,
        OperationType::ExternalApi,
        OperationType::DatabaseSync,
        OperationType::Contract,
    ];

    for op_type in operation_types.iter() {
        let mut count = 0u32;
        let mut critical_count = 0u32;
        let mut retryable_count = 0u32;

        for failure in failures.iter() {
            if failure.operation_type == *op_type {
                count += 1;
                if failure.severity == FailureSeverity::Critical {
                    critical_count += 1;
                }
                if failure.is_retryable {
                    retryable_count += 1;
                }
            }
        }

        if count > 0 {
            let type_symbol = operation_type_to_symbol(env, op_type);
            groups.push_back(FailureGroup {
                dimension: Symbol::new(env, "operation_type"),
                value: type_symbol,
                count,
                critical_count,
                retryable_count,
                investigation_link: String::from_str(env, "dashboard/by-type/{type}"),
            });
        }
    }

    groups
}

/// Groups partial failures by severity.
pub fn group_by_severity(env: &Env, failures: &Vec<PartialFailure>) -> Vec<FailureGroup> {
    let mut groups = Vec::new(env);

    let severities = [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
    ];

    for severity in severities.iter() {
        let mut count = 0u32;
        let mut critical_count = 0u32;
        let mut retryable_count = 0u32;

        for failure in failures.iter() {
            if failure.severity == *severity {
                count += 1;
                if failure.severity == FailureSeverity::Critical {
                    critical_count += 1;
                }
                if failure.is_retryable {
                    retryable_count += 1;
                }
            }
        }

        if count > 0 {
            let severity_symbol = severity_to_symbol(severity);
            groups.push_back(FailureGroup {
                dimension: symbol_short!("severity"),
                value: severity_symbol,
                count,
                critical_count,
                retryable_count,
                investigation_link: String::from_str(env, "dashboard/by-severity/{severity}"),
            });
        }
    }

    groups
}

/// Groups partial failures by age (stale vs fresh).
pub fn group_by_age(env: &Env, failures: &Vec<PartialFailure>) -> Vec<FailureGroup> {
    let mut groups = Vec::new(env);
    const STALE_THRESHOLD: u32 = 1000; // Consider stale after 1000 ledgers

    let mut fresh_count = 0u32;
    let mut fresh_critical = 0u32;
    let mut fresh_retryable = 0u32;

    let mut stale_count = 0u32;
    let mut stale_critical = 0u32;
    let mut stale_retryable = 0u32;

    for failure in failures.iter() {
        if failure.age_ledgers < STALE_THRESHOLD {
            fresh_count += 1;
            if failure.severity == FailureSeverity::Critical {
                fresh_critical += 1;
            }
            if failure.is_retryable {
                fresh_retryable += 1;
            }
        } else {
            stale_count += 1;
            if failure.severity == FailureSeverity::Critical {
                stale_critical += 1;
            }
            if failure.is_retryable {
                stale_retryable += 1;
            }
        }
    }

    if fresh_count > 0 {
        groups.push_back(FailureGroup {
            dimension: symbol_short!("age"),
            value: symbol_short!("fresh"),
            count: fresh_count,
            critical_count: fresh_critical,
            retryable_count: fresh_retryable,
            investigation_link: String::from_str(env, "dashboard/by-age/fresh"),
        });
    }

    if stale_count > 0 {
        groups.push_back(FailureGroup {
            dimension: symbol_short!("age"),
            value: symbol_short!("stale"),
            count: stale_count,
            critical_count: stale_critical,
            retryable_count: stale_retryable,
            investigation_link: String::from_str(env, "dashboard/by-age/stale"),
        });
    }

    groups
}

/// Groups partial failures by retryability.
pub fn group_by_retryability(env: &Env, failures: &Vec<PartialFailure>) -> Vec<FailureGroup> {
    let mut groups = Vec::new(env);

    let mut retryable_count = 0u32;
    let mut retryable_critical = 0u32;

    let mut non_retryable_count = 0u32;
    let mut non_retryable_critical = 0u32;

    for failure in failures.iter() {
        if failure.is_retryable {
            retryable_count += 1;
            if failure.severity == FailureSeverity::Critical {
                retryable_critical += 1;
            }
        } else {
            non_retryable_count += 1;
            if failure.severity == FailureSeverity::Critical {
                non_retryable_critical += 1;
            }
        }
    }

    if retryable_count > 0 {
        groups.push_back(FailureGroup {
            dimension: Symbol::new(env, "retryability"),
            value: symbol_short!("retryable"),
            count: retryable_count,
            critical_count: retryable_critical,
            retryable_count,
            investigation_link: String::from_str(env, "dashboard/by-retryability/retryable"),
        });
    }

    if non_retryable_count > 0 {
        groups.push_back(FailureGroup {
            dimension: Symbol::new(env, "retryability"),
            value: Symbol::new(env, "non_retryable"),
            count: non_retryable_count,
            critical_count: non_retryable_critical,
            retryable_count: 0,
            investigation_link: String::from_str(env, "dashboard/by-retryability/non-retryable"),
        });
    }

    groups
}

/// Helper function to convert OperationType to Symbol.
fn operation_type_to_symbol(_env: &Env, op_type: &OperationType) -> Symbol {
    match op_type {
        OperationType::Payment => symbol_short!("payment"),
        OperationType::Transfer => symbol_short!("transfer"),
        OperationType::Worker => symbol_short!("worker"),
        OperationType::Webhook => symbol_short!("webhook"),
        OperationType::ExternalApi => symbol_short!("ext_api"),
        OperationType::DatabaseSync => symbol_short!("db_sync"),
        OperationType::Contract => symbol_short!("contract"),
    }
}

/// Helper function to convert FailureSeverity to Symbol.
fn severity_to_symbol(severity: &FailureSeverity) -> Symbol {
    match severity {
        FailureSeverity::Critical => symbol_short!("critical"),
        FailureSeverity::High => symbol_short!("high"),
        FailureSeverity::Medium => symbol_short!("medium"),
        FailureSeverity::Low => symbol_short!("low"),
    }
}

/// Generates an enhanced dashboard with partial failure tracking.
pub fn generate_enhanced_dashboard(
    env: &Env,
    ledger_records: Vec<SourceRecord>,
    db_records: Vec<SourceRecord>,
    user_records: Vec<SourceRecord>,
    current_timestamp: u64,
    partial_failures: Vec<PartialFailure>,
) -> DashboardReport {
    let base_report = generate_dashboard(
        env,
        ledger_records,
        db_records,
        user_records,
        current_timestamp,
    );

    let mut redacted_partial_failures = Vec::new(env);
    for failure in partial_failures.iter() {
        if failure.state != FailureState::Resolved {
            redacted_partial_failures.push_back(redact_partial_failure(env, &failure));
        }
    }

    let operation_type_groups = group_by_operation_type(env, &partial_failures);
    let severity_groups = group_by_severity(env, &partial_failures);
    let age_groups = group_by_age(env, &partial_failures);
    let retryability_groups = group_by_retryability(env, &partial_failures);

    let mut all_groups = Vec::new(env);
    for group in operation_type_groups.iter() {
        all_groups.push_back(group.clone());
    }
    for group in severity_groups.iter() {
        all_groups.push_back(group.clone());
    }
    for group in age_groups.iter() {
        all_groups.push_back(group.clone());
    }
    for group in retryability_groups.iter() {
        all_groups.push_back(group.clone());
    }

    DashboardReport {
        categories: base_report.categories,
        redacted_dead_letters: base_report.redacted_dead_letters,
        partial_failures: redacted_partial_failures,
        failure_groups: all_groups,
    }
}
