//! Operator runbook checks for incident recovery.
//!
//! Provides automated checks and verification steps for operators during
//! incident response and recovery procedures.

use soroban_sdk::{contracterror, contracttype, Env, String, Vec};

/// Incident severity levels.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentSeverity {
    /// Minor issue, no service impact
    Low,
    /// Partial service degradation
    Medium,
    /// Significant service impact
    High,
    /// Complete service outage
    Critical,
}

/// Status of a runbook check.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckStatus {
    /// Check passed
    Passed,
    /// Check failed
    Failed,
    /// Check is in progress
    InProgress,
    /// Check was skipped
    Skipped,
}

/// A single runbook check item.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunbookCheck {
    /// Unique identifier for the check
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Current status
    pub status: CheckStatus,
    /// Severity if this check fails
    pub severity: IncidentSeverity,
    /// Remediation steps if check fails
    pub remediation: String,
    /// Whether this check is mandatory
    pub is_mandatory: bool,
}

/// Complete runbook verification result.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunbookResult {
    /// Incident identifier
    pub incident_id: String,
    /// All checks performed
    pub checks: Vec<RunbookCheck>,
    /// Overall pass/fail status
    pub all_passed: bool,
    /// Timestamp of verification
    pub verified_at: u64,
}

/// Errors for runbook operations.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RunbookError {
    /// Invalid incident ID
    InvalidIncidentId = 1,
    /// Mandatory check failed
    MandatoryCheckFailed = 2,
    /// Runbook already executed
    AlreadyExecuted = 3,
    /// Invalid check status transition
    InvalidTransition = 4,
}

/// Create a new runbook check.
pub fn create_check(
    env: &Env,
    id: &str,
    description: &str,
    severity: IncidentSeverity,
    remediation: &str,
    is_mandatory: bool,
) -> RunbookCheck {
    RunbookCheck {
        id: String::from_str(env, id),
        description: String::from_str(env, description),
        status: CheckStatus::InProgress,
        severity,
        remediation: String::from_str(env, remediation),
        is_mandatory,
    }
}

/// Update a check status.
pub fn update_check_status(
    _env: &Env,
    check: &mut RunbookCheck,
    new_status: CheckStatus,
) -> Result<(), RunbookError> {
    // Validate state transition
    match (check.status, new_status) {
        (CheckStatus::InProgress, CheckStatus::Passed) => Ok(()),
        (CheckStatus::InProgress, CheckStatus::Failed) => Ok(()),
        (CheckStatus::InProgress, CheckStatus::Skipped) => Ok(()),
        (CheckStatus::Failed, CheckStatus::Passed) => Ok(()),
        (CheckStatus::Passed, CheckStatus::Failed) => Ok(()),
        _ => Err(RunbookError::InvalidTransition),
    }?;

    check.status = new_status;
    Ok(())
}

/// Evaluate overall runbook result.
pub fn evaluate_runbook(
    env: &Env,
    incident_id: &str,
    checks: &Vec<RunbookCheck>,
) -> RunbookResult {
    let mut all_passed = true;

    // Check if any mandatory check failed
    let mut i = 0;
    while i < checks.len() {
        let check = checks.get(i).unwrap();
        if check.is_mandatory && check.status == CheckStatus::Failed {
            all_passed = false;
            break;
        }
        i += 1;
    }

    RunbookResult {
        incident_id: String::from_str(env, incident_id),
        checks: checks.clone(),
        all_passed,
        verified_at: env.ledger().timestamp(),
    }
}

/// Get checks that require attention (failed or skipped mandatory).
pub fn get_failed_checks(env: &Env, checks: &Vec<RunbookCheck>) -> Vec<RunbookCheck> {
    let mut failed = Vec::new(env);
    let mut i = 0;
    while i < checks.len() {
        let check = checks.get(i).unwrap();
        if check.status == CheckStatus::Failed {
            failed.push_back(check.clone());
        }
        i += 1;
    }
    failed
}

/// Create a standard incident recovery runbook.
pub fn create_standard_runbook(env: &Env) -> Vec<RunbookCheck> {
    let mut checks = Vec::new(env);

    // 1. Verify contract is accessible
    checks.push_back(create_check(
        env,
        "contract_accessible",
        "Verify contract is accessible and responsive",
        IncidentSeverity::Critical,
        "Check network connectivity and contract address",
        true,
    ));

    // 2. Verify admin access
    checks.push_back(create_check(
        env,
        "admin_access",
        "Verify admin can execute privileged operations",
        IncidentSeverity::High,
        "Check admin key and permissions",
        true,
    ));

    // 3. Verify token transfers
    checks.push_back(create_check(
        env,
        "token_transfers",
        "Verify token transfers are working",
        IncidentSeverity::High,
        "Check token contract and balance",
        true,
    ));

    // 4. Verify data consistency
    checks.push_back(create_check(
        env,
        "data_consistency",
        "Verify data consistency across storage",
        IncidentSeverity::Medium,
        "Run reconciliation checks",
        false,
    ));

    // 5. Verify event emission
    checks.push_back(create_check(
        env,
        "event_emission",
        "Verify events are being emitted correctly",
        IncidentSeverity::Medium,
        "Check event logs",
        false,
    ));

    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, Vec};

    #[test]
    fn test_create_check() {
        let env = Env::default();
        let check = create_check(
            &env,
            "test_check",
            "Test description",
            IncidentSeverity::Medium,
            "Test remediation",
            true,
        );
        assert_eq!(check.status, CheckStatus::InProgress);
        assert!(check.is_mandatory);
    }

    #[test]
    fn test_update_check_status() {
        let env = Env::default();
        let mut check = create_check(
            &env,
            "test_check",
            "Test",
            IncidentSeverity::Medium,
            "Fix it",
            true,
        );

        // Valid transition
        assert!(update_check_status(&env, &mut check, CheckStatus::Passed).is_ok());
        assert_eq!(check.status, CheckStatus::Passed);

        // Valid transition back to failed
        assert!(update_check_status(&env, &mut check, CheckStatus::Failed).is_ok());
        assert_eq!(check.status, CheckStatus::Failed);
    }

    #[test]
    fn test_evaluate_runbook() {
        let env = Env::default();
        let mut checks = Vec::new(&env);

        let mut check1 = create_check(&env, "check1", "Test", IncidentSeverity::Medium, "Fix", true);
        check1.status = CheckStatus::Passed;
        checks.push_back(check1);

        let mut check2 = create_check(&env, "check2", "Test", IncidentSeverity::Medium, "Fix", true);
        check2.status = CheckStatus::Failed;
        checks.push_back(check2);

        let result = evaluate_runbook(&env, "incident-1", &checks);
        assert!(!result.all_passed); // Mandatory check failed
    }
}
