#[cfg(test)]
mod tests {
    use soroban_sdk::{
        symbol_short, testutils::Address as _, Address, Env, Vec,
    };

    use crate::diagnostics::{
        create_diagnostic_check, evaluate_diagnostics, get_last_diagnostic_report,
        record_system_diagnostic, run_self_test, validate_dependency_invariants,
        DiagnosticCategory, DiagnosticCheck, DiagnosticError, DiagnosticStatus,
    };
    use crate::errors::Error;
    use crate::problem_details::{
        problem_details_for_diagnostic_error, problem_details_for_error, ProblemDetails,
    };

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        crate::auth::set_admin(&env, &admin);
        (env, admin, user)
    }

    #[test]
    fn test_normal_healthy_evaluation() {
        let (env, _, _) = setup();
        let now = 1_000u64;
        let mut checks: Vec<DiagnosticCheck> = Vec::new(&env);

        checks.push_back(create_diagnostic_check(
            symbol_short!("rustc"),
            DiagnosticCategory::Toolchain,
            DiagnosticStatus::Passed,
            symbol_short!("v1_80"),
            now,
        ));
        checks.push_back(create_diagnostic_check(
            symbol_short!("soroban"),
            DiagnosticCategory::DependencyInvariants,
            DiagnosticStatus::Passed,
            symbol_short!("v21_7"),
            now,
        ));

        let report = evaluate_diagnostics(&env, &checks, false, now).unwrap();
        assert_eq!(report.passed_count, 2);
        assert_eq!(report.warning_count, 0);
        assert_eq!(report.failed_count, 0);
        assert!(report.is_healthy);
    }

    #[test]
    fn test_warning_allowed_in_standard_mode_but_rejected_in_strict_mode() {
        let (env, _, _) = setup();
        let now = 1_000u64;
        let mut checks: Vec<DiagnosticCheck> = Vec::new(&env);

        checks.push_back(create_diagnostic_check(
            symbol_short!("node"),
            DiagnosticCategory::Environment,
            DiagnosticStatus::Passed,
            symbol_short!("v20"),
            now,
        ));
        checks.push_back(create_diagnostic_check(
            symbol_short!("disk"),
            DiagnosticCategory::Environment,
            DiagnosticStatus::Warning,
            symbol_short!("low_spc"),
            now,
        ));

        // Standard mode: warning passes
        let report = evaluate_diagnostics(&env, &checks, false, now).unwrap();
        assert_eq!(report.passed_count, 1);
        assert_eq!(report.warning_count, 1);
        assert_eq!(report.failed_count, 0);
        assert!(report.is_healthy);

        // Strict mode: warning fails
        let err = evaluate_diagnostics(&env, &checks, true, now).unwrap_err();
        assert_eq!(err, DiagnosticError::DiagnosticValidationFailed);
    }

    #[test]
    fn test_failed_check_rejects_in_all_modes() {
        let (env, _, _) = setup();
        let now = 1_000u64;
        let mut checks: Vec<DiagnosticCheck> = Vec::new(&env);

        checks.push_back(create_diagnostic_check(
            symbol_short!("rustc"),
            DiagnosticCategory::Toolchain,
            DiagnosticStatus::Failed,
            symbol_short!("missing"),
            now,
        ));

        let err = evaluate_diagnostics(&env, &checks, false, now).unwrap_err();
        assert_eq!(err, DiagnosticError::DiagnosticValidationFailed);
    }

    #[test]
    fn test_empty_checks_list_rejected() {
        let (env, _, _) = setup();
        let checks: Vec<DiagnosticCheck> = Vec::new(&env);
        let err = evaluate_diagnostics(&env, &checks, false, 1_000).unwrap_err();
        assert_eq!(err, DiagnosticError::EmptyDiagnosticsList);
    }

    #[test]
    fn test_validate_dependency_invariants() {
        let now = 100u64;

        // Valid: Soroban 21.7.x, Dalek pinned
        let check = validate_dependency_invariants(21, 7, true, now).unwrap();
        assert_eq!(check.status, DiagnosticStatus::Passed);

        // Invalid: Wrong major version
        let err1 = validate_dependency_invariants(20, 0, true, now).unwrap_err();
        assert_eq!(err1, DiagnosticError::DependencyInvariantViolated);

        // Invalid: Dalek unpinned
        let err2 = validate_dependency_invariants(21, 7, false, now).unwrap_err();
        assert_eq!(err2, DiagnosticError::DependencyInvariantViolated);
    }

    #[test]
    fn test_admin_authorization_for_recording_diagnostic() {
        let (env, admin, attacker) = setup();
        let now = 1_000u64;

        let mut checks: Vec<DiagnosticCheck> = Vec::new(&env);
        checks.push_back(create_diagnostic_check(
            symbol_short!("test"),
            DiagnosticCategory::WorkspaceFixtures,
            DiagnosticStatus::Passed,
            symbol_short!("ok"),
            now,
        ));
        let report = evaluate_diagnostics(&env, &checks, false, now).unwrap();

        // Attacker rejected
        let err = record_system_diagnostic(&env, &attacker, &report);
        assert_eq!(err.err(), Some(Error::Unauthorized));

        // Admin succeeds
        let res = record_system_diagnostic(&env, &admin, &report);
        assert!(res.is_ok());

        // Verify stored report
        let stored = get_last_diagnostic_report(&env).unwrap();
        assert_eq!(stored.passed_count, 1);
        assert!(stored.is_healthy);
    }

    #[test]
    fn test_run_self_test() {
        let (env, _, _) = setup();
        let report = run_self_test(&env).unwrap();
        assert!(report.is_healthy);
        assert!(report.passed_count >= 3);
        assert_eq!(report.failed_count, 0);
    }

    #[test]
    fn test_diagnostic_error_problem_details_are_stable() {
        let cases = [
            (
                DiagnosticError::EmptyDiagnosticsList,
                "TRELLIS_DIAG_EMPTY_LIST",
                "diagnostics.empty_list",
            ),
            (
                DiagnosticError::DiagnosticValidationFailed,
                "TRELLIS_DIAG_VALIDATION_FAILED",
                "diagnostics.validation_failed",
            ),
            (
                DiagnosticError::DependencyInvariantViolated,
                "TRELLIS_DIAG_DEPENDENCY_INVARIANT",
                "diagnostics.dependency_invariant",
            ),
        ];

        for (err, code, kind) in cases {
            let details: ProblemDetails = problem_details_for_diagnostic_error(&err);
            assert_eq!(details.code, code);
            assert_eq!(details.kind, kind);
            assert!(!details.remediation.is_empty());
            assert!(!details.docs_url.is_empty());
            assert!(!details.message.is_empty());
        }
    }

    #[test]
    fn test_contract_error_problem_details_are_stable() {
        let details = problem_details_for_error(&Error::Unauthorized);
        assert_eq!(details.code, "TRELLIS_UNAUTHORIZED");
        assert_eq!(details.kind, "auth.unauthorized");
        assert!(!details.remediation.is_empty());
        assert!(!details.docs_url.is_empty());
    }

    #[test]
    fn test_problem_details_do_not_leak_internal_state() {
        let details = problem_details_for_diagnostic_error(
            &DiagnosticError::DependencyInvariantViolated,
        );
        // User-facing message must be safe and must not embed raw debug output.
        assert!(!details.message.contains("DependencyInvariantViolated"));
        assert!(!details.message.contains("panic"));
        assert!(!details.message.contains("unwrap"));
    }
}
