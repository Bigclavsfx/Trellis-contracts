//! RFC 9457 problem-details rendering for contract errors (Issue #243).
//!
//! Contracts return stable numeric error codes. API gateways, CLI tools and
//! client SDKs, however, need a *safe*, *stable* and *actionable* description
//! of what went wrong. This module renders a contract error into a
//! [`ProblemDetails`] document:
//!
//! | Field | Meaning |
//! |---|---|
//! | `code` | Stable machine code (e.g. `TRELLIS_UNAUTHORIZED`). |
//! | `kind` | Stable dotted category (e.g. `auth.unauthorized`). |
//! | `message` | User-safe message. Never contains internal state. |
//! | `remediation` | What the caller should do next. |
//! | `docs_url` | Where the behaviour is documented. |
//!
//! ## Safety
//!
//! The renderer never interpolates raw error values, storage contents, or
//! debug output into the user-facing fields: every field is a `&'static str`
//! chosen from a closed table. That keeps a leaked internal detail from
//! reaching a user, and keeps the rendered document byte-stable across
//! releases.
//!
//! ## Compatibility
//!
//! Additive: a new module with no storage, no events, and no change to any
//! existing error code or contract interface.

use crate::diagnostics::DiagnosticError;
use crate::errors::Error;

/// Base URL of the operator documentation.
const DOCS_BASE: &str = "https://github.com/TRELLIS-STELLAR/Trellis-contracts/blob/main/docs";

/// A safe, stable rendering of a contract error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemDetails {
    /// Stable machine code (e.g. `TRELLIS_UNAUTHORIZED`).
    pub code: &'static str,
    /// Stable dotted category (e.g. `auth.unauthorized`).
    pub kind: &'static str,
    /// User-safe message.
    pub message: &'static str,
    /// Actionable remediation hint.
    pub remediation: &'static str,
    /// Documentation link for this failure mode.
    pub docs_url: &'static str,
}

/// Renders a shared contract error.
pub fn problem_details_for_error(error: &Error) -> ProblemDetails {
    match error {
        Error::Unauthorized => ProblemDetails {
            code: "TRELLIS_UNAUTHORIZED",
            kind: "auth.unauthorized",
            message: "The caller is not allowed to perform this action.",
            remediation: "Authenticate with an account that holds the required role.",
            docs_url: DOCS_BASE,
        },
        Error::NotFound => ProblemDetails {
            code: "TRELLIS_NOT_FOUND",
            kind: "state.not_found",
            message: "The requested record does not exist.",
            remediation: "Check the identifier and refresh the record before retrying.",
            docs_url: DOCS_BASE,
        },
        Error::InvalidAmount => ProblemDetails {
            code: "TRELLIS_INVALID_AMOUNT",
            kind: "validation.invalid_amount",
            message: "The submitted amount is not valid.",
            remediation: "Submit an amount greater than zero.",
            docs_url: DOCS_BASE,
        },
        Error::Overflow => ProblemDetails {
            code: "TRELLIS_OVERFLOW",
            kind: "validation.overflow",
            message: "The computation exceeded the supported range.",
            remediation: "Reduce the input size and retry.",
            docs_url: DOCS_BASE,
        },
        Error::ContractPaused => ProblemDetails {
            code: "TRELLIS_CONTRACT_PAUSED",
            kind: "state.paused",
            message: "The contract is paused and cannot process this request.",
            remediation: "Wait for the pause to be lifted, then retry.",
            docs_url: DOCS_BASE,
        },
        Error::Expired => ProblemDetails {
            code: "TRELLIS_EXPIRED",
            kind: "state.expired",
            message: "The claim or approval window has expired.",
            remediation: "Start a new claim or approval with fresh parameters.",
            docs_url: DOCS_BASE,
        },
        Error::AlreadyClaimed => ProblemDetails {
            code: "TRELLIS_ALREADY_CLAIMED",
            kind: "state.already_claimed",
            message: "The record has already been claimed.",
            remediation: "No action is needed; refresh the record to see its final state.",
            docs_url: DOCS_BASE,
        },
        Error::InsufficientBalance => ProblemDetails {
            code: "TRELLIS_INSUFFICIENT_BALANCE",
            kind: "funds.insufficient_balance",
            message: "The account does not hold enough funds for this operation.",
            remediation: "Fund the account, or reduce the requested amount.",
            docs_url: DOCS_BASE,
        },
        Error::InvalidArgument => ProblemDetails {
            code: "TRELLIS_INVALID_ARGUMENT",
            kind: "validation.invalid_argument",
            message: "One of the supplied arguments is not valid.",
            remediation: "Review the request payload and correct the invalid value.",
            docs_url: DOCS_BASE,
        },
        Error::NotPaused => ProblemDetails {
            code: "TRELLIS_NOT_PAUSED",
            kind: "state.not_paused",
            message: "The operation requires a paused contract.",
            remediation: "Pause the contract before running this operation.",
            docs_url: DOCS_BASE,
        },
        _ => ProblemDetails {
            code: "TRELLIS_UNEXPECTED_ERROR",
            kind: "internal.unexpected",
            message: "The operation could not be completed.",
            remediation: "Contact support and provide the transaction reference.",
            docs_url: DOCS_BASE,
        },
    }
}

/// Renders a diagnostics error.
pub fn problem_details_for_diagnostic_error(error: &DiagnosticError) -> ProblemDetails {
    match error {
        DiagnosticError::EmptyDiagnosticsList => ProblemDetails {
            code: "TRELLIS_DIAG_EMPTY_LIST",
            kind: "diagnostics.empty_list",
            message: "The diagnostics check list is empty.",
            remediation: "Register at least one diagnostics check before running the self-test.",
            docs_url: DOCS_BASE,
        },
        DiagnosticError::DiagnosticValidationFailed => ProblemDetails {
            code: "TRELLIS_DIAG_VALIDATION_FAILED",
            kind: "diagnostics.validation_failed",
            message: "The environment failed the diagnostics validation criteria.",
            remediation: "Review the failing diagnostics check and fix the reported drift.",
            docs_url: DOCS_BASE,
        },
        DiagnosticError::DependencyInvariantViolated => ProblemDetails {
            code: "TRELLIS_DIAG_DEPENDENCY_INVARIANT",
            kind: "diagnostics.dependency_invariant",
            message: "A dependency invariant was violated.",
            remediation: "Align the dependency version with the pinned expectation.",
            docs_url: DOCS_BASE,
        },
        DiagnosticError::StorageSchemaInvalid => ProblemDetails {
            code: "TRELLIS_DIAG_STORAGE_SCHEMA",
            kind: "diagnostics.storage_schema",
            message: "The storage schema does not match the expected version.",
            remediation: "Run the documented migration before retrying the operation.",
            docs_url: DOCS_BASE,
        },
        DiagnosticError::Unauthorized => ProblemDetails {
            code: "TRELLIS_DIAG_UNAUTHORIZED",
            kind: "auth.unauthorized",
            message: "The caller is not allowed to manage diagnostics state.",
            remediation: "Authenticate with an administrator account.",
            docs_url: DOCS_BASE,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_errors_render_a_safe_fallback() {
        let details = problem_details_for_error(&Error::DependencyDegraded);
        assert_eq!(details.code, "TRELLIS_UNEXPECTED_ERROR");
        assert!(!details.message.is_empty());
        assert!(!details.remediation.is_empty());
        assert!(!details.docs_url.is_empty());
    }

    #[test]
    fn rendered_details_never_leak_internal_identifiers() {
        let details = problem_details_for_error(&Error::Unauthorized);
        assert!(!details.message.contains("Unauthorized"));
        assert!(!details.message.contains("panic"));
        assert!(!details.message.contains("unwrap"));
    }
}
