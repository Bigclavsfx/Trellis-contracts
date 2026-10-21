use soroban_contracterror;

/// Oracle-specific error codes (range 500-599 per shared conventions).
///
/// # Stability contract
///
/// These codes are part of the public API surface. Off-chain clients, indexers,
/// and remediation tooling may match on the numeric value and/or the variant
/// name. Do not renumber, remove, or repurpose an existing code without a
/// documented migration plan. New codes must be appended with the next
/// available value in the 500-599 range.
///
/// # Problem-details taxonomy
///
/// Each variant maps to a stable machine code (`OracleErrorCode`), a safe
/// user-facing message, and a remediation hint. The mapping is exposed via
/// `describe()` and is guarded by tests that prevent accidental drift.
///
/// # Operational edge cases and failure modes
///
/// - `InternalError` is a catch-all for invariant breaks. It should never be
///   returned for validatile failures; treat it as an incident signal.
/// - `InsufficientQuorum` and `SubmissionStale` are transient: retry after
///   additional submissions or a fresh submission window.
/// - `Unrecoverable` class errors (auth, configuration) require admin action
///   before retrying; automatic retries will not succeed.
/// - **Rollback/recovery**: oracle state is append-only per submission and
///   quorum is derived at read time. To recover from a bad submission, admins
///   should slash (`InvalidPenaltyAmount`/`Unauthorized`) and require a fresh
///   submission rather than mutating historical records. Configuration
///   errors (`TreasuryNotConfigured`, `StakingConfigNotSet`) are recovered by
///   re-running the idempotent configuration entrypoint.
///
/// # Docs
///
/// See `docs/oracle-errors.md` for the human-readable taxonomy table.
/// The table is generated from `describe()` and verified by tests in
/// `tests/error_taxonomy.rs`.
#contracterror
#[derive(Copy, Clone, Debug, Eq, PartialE, PartialOrd, Ord)]
#[repr(u32)]
pub enum OracleError {
    /// The submitter is not registered or not active.
    SubmitterNotAuthorized = 500,
    /// The submission was already submitted (replay detected).
    DuplicateSubmission = 501,
    /// The feed does not exist or has no submissions.
    FeedNotFound = 502,
    /// The submitter is already registered.
    SubmitterAlreadyRegistered = 503,
    /// The submission is stale (outside the staleness window).
    SubmissionStale = 504,
    /// The price value is invalid (e.g., negative for certain feeds).
    InvalidPrice = 505,
    /// The decimal places value is invalid.
    InvalidDecimals = 506,
    /// The feed identifier is invalid (e.g., empty).
    InvalidFeedId = 507,
    /// The caller is not authorized to perform this action.
    Unauthorized = 508,
    /// A generic error occurred.
    InternalError = 509,
    /// The contract has already been initialized.
    AlreadyInitialized = 510,
    /// The requested quorum is invalid or exceeds the active submitter count.
    InvalidQuorum = 511,
    /// The feed does not currently have enough active submissions to meet quorum.
    InsufficientQuorum = 512,
    /// The submitter stake is below the required minimum.
    InsufficientStake = 513,
    /// An unbonding cooldown period is still active.
    UnbondingCooldownActive = 514,
    /// No unbonding request was found.
    NoUnbondingRequest = 515,
    /// The slash penalty amount is invalid or exceeds the available stake.
    InvalidPenaltyAmount = 516,
    /// Treasury contract is not configured or invalid.
    TreasuryNotConfigured = 517,
    /// Staking configuration has not been set.
    StakingConfigNotSet = 518,
    /// Submitter is already in the process of unbonding.
    AlreadyUnbonding = 519,
    /// Math overflow occurred.
    Overflow = 520,
}

/// Stable machine code for an `OracleError`.
///
/// This is the value clients should match on. It is derived from the
/// contracterror representation and is guaranteed to remain stable across versions
/// for a given variant.
pub fn machine_code(error: OracleError) -> u32 {
    error as u32
}

/// Severity class for an oracle error.
///
/// Used by clients to decide retry strategy and alerting.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#repr(u32)]
pub enum Severity {
    /// Retry after correcting input or waiting for state to change.
    Recoverable = 0,
    /// Requires admin action or configuration change.
    Unrecoverable = 1,
    /// Invariant break or unexpected failure; treat as an incident.
    Incident = 2,
}

/// Stable, safe description of an oracle error for problem-details responses.
///
/// The returned struct is designed to be serialized directly into a
/// problem-details document (IETF RFC 9457). The `title` and `detail` fields
/// are safe to show to end users and contain no internal implementation details.
/// The `code` field is the stable machine code and is the only field clients
/// should branch on.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ErrorDescriptor {
    /// Stable machine code (500-599).
    pub code: u32,
    /// Stable variant name for logs and metrics.
    pub slug: &static str,
    /// Short, safe title for users.
    pub title: &static str,
    /// Safe detail message for users.
    pub detail: &static str,
    /// Actionable remediation hint for clients or operators.
    pub remedy: &static str,
    /// Severity class for retry and alerting decisions.
    pub severity: Severity,
}

/// Return the stable problem-details descriptor for an oracle error.
///
/// This is the single source of truth for the taxonomy. Tests in
/// `tests/error_taxonomy.rs` assert that every variant has a distinct, stable
/// descriptor and that the code matches the `contracterror` representation.
pub fn describe(error: OracleError) -> ErrorDescriptor {
    match error {
        OracleError::SubmitterNotAuthorized => ErrorDescriptor {
            code: 500,
            slug: "submitter_not_authorized",
            title: "Submitter not authorized",
            detail: "The submitter is not registered or is not active.",
            remedy: "Register the submitter and ensure it is active before submitting.",
            severity: Severity::Unrecoverable,
        },
        OracleError::DuplicateSubmission => ErrorDescriptor {
            code: 501,
            slug: "duplicate_submission",
            title: "Duplicate submission",
            detail: "This submission was already recorded.",
            remedy: "Use a fresh submission nonce or wait for the next submission window.",
            severity: Severity::Recoverable,
        },
        OracleError::FeedNotFound => ErrorDescriptor {
            code: 502,
            slug: "feed_not_found",
            title: "Feed not found",
            detail: "The requested feed does not exist or has no submissions.",
            remedy: "Create the feed or wait for an initial submission.",
            severity: Severity::Recoverable,
        },
        OracleError::SubmitterAlreadyRegistered => ErrorDescriptor {
            code: 503,
            slug: "submitter_already_registered",
            title: "Submitter already registered",
            detail: "The submitter is already registered.",
            remedy: "Use the existing registration or update stake instead of re-registering.",
            severity: Severity::Recoverable,
        },
        OracleError::SubmissionStale => ErrorDescriptor {
            code: 504,
            slug: "submission_stale",
            title: "Submission stale",
            detail: "The submission is outside the accepted staleness window.",
            remedy: "Resubmit with a current timestamp within the staleness window.",
            severity: Severity::Recoverable,
        },
        OracleError::InvalidPrice => ErrorDescriptor {
            code: 505,
            slug: "invalid_price",
            title: "Invalid price",
            detail: "The price value is not acceptable for this feed.",
            remedy: "Provide a price within the feed's accepted range.",
            severity: Severity::Recoverable,
        },
        OracleError::InvalidDecimals => ErrorDescriptor {
            code: 506,
            slug: "invalid_decimals",
            title: "Invalid decimals",
            detail: "The decimal places value is not acceptable.",
            remedy: "Provide decimals within the feed's configured range.",
            severity: Severity::Recoverable,
        },
        OracleError::InvalidFeedId => ErrorDescriptor {
            code: 507,
            slug: "invalid_feed_id",
            title: "Invalid feed identifier",
            detail: "The feed identifier is malformed or empty.",
            remedy: "Provide a non-empty, well-formed feed identifier.",
            severity: Severity::Recoverable,
        },
        OracleError::Unauthorized => ErrorDescriptor {
            code: 508,
            slug: "unauthorized",
            title: "Unauthorized",
            detail: "The caller is not authorized to perform this action.",
            remedy: "Use an authorized address or request the required role.",
            severity: Severity::Unrecoverable,
        },
        OracleError::InternalError => ErrorDescriptor {
            code: 509,
            slug: "internal_error",
            title: "Internal error",
            detail: "An unexpected internal error occurred.",
            remedy: "Retry once; if it persists, escalate as an incident with the transaction hash.",
            severity: Severity::Incident,
        },
        OracleError::AlreadyInitialized => ErrorDescriptor {
            code: 510,
            slug: "already_initialized",
            title: "Already initialized",
            detail: "The contract has already been initialized.",
            remedy: "Do not re-initialize; use the configuration entrypoints to change settings.",
            severity: Severity::Unrecoverable,
        },
        OracleError::InvalidQuorum => ErrorDescriptor {
            code: 511,
            slug: "invalid_quorum",
            title: "Invalid quorum",
            detail: "The requested quorum is invalid or exceeds the active submitter count.",
            remedy: "Choose a quorum between 1 and the number of active submitters.",
            severity: Severity::Recoverable,
        },
        OracleError::InsufficientQuorum => ErrorDescriptor {
            code: 512,
            slug: "insufficient_quorum",
            title: "Insufficient quorum",
            detail: "The feed does not have enough active submissions to meet quorum.",
            remedy: "Wait for additional submissions or reduce the quorum through governance.",
            severity: Severity::Recoverable,
        },
        OracleError::InsufficientStake => ErrorDescriptor {
            code: 513,
            slug: "insufficient_stake",
            title: "Insufficient stake",
            detail: "The submitter stake is below the required minimum.",
            remedy: "Increase the submitter's stake to meet the configured minimum.",
            severity: Severity::Recoverable,
        },
        OracleError::UnbondingCooldownActive => ErrorDescriptor {
            code: 514,
            slug: "unbonding_cooldown_active",
            title: "Unbonding cooldown active",
            detail: "An unbonding cooldown period is still active.",
            remedy: "Wait until the cooldown period elapses before completing unbonding.",
            severity: Severity::Recoverable,
        },
        OracleError::NoUnbondingRequest => ErrorDescriptor {
            code: 515,
            slug: "no_unbonding_request",
            title: "No unbonding request",
            detail: "No unbonding request was found for this submitter.",
            remedy: "Initiate an unbonding request before attempting to complete one.",
            severity: Severity::Recoverable,
        },
        OracleError::InvalidPenaltyAmount => ErrorDescriptor {
            code: 516,
            slug: "invalid_penalty_amount",
            title: "Invalid penalty amount",
            detail: "The slash penalty amount is invalid or exceeds the available stake.",
            remedy: "Provide a penalty amount greater than zero and no larger than the stake.",
            severity: Severity::Recoverable,
        },
        OracleError::TreasuryNotConfigured => ErrorDescriptor {
            code: 517,
            slug: "treasury_not_configured",
            title: "Treasury not configured",
            detail: "The treasury contract is not configured or is invalid.",
            remedy: "Configure a valid treasury contract address via the admin entrypoint.",
            severity: Severity::Unrecoverable,
        },
        OracleError::StakingConfigNotSet => ErrorDescriptor {
            code: 518,
            slug: "staking_config_not_set",
            title: "Staking configuration not set",
            detail: "Staking configuration has not been set.",
            remedy: "Set the staking configuration via the admin entrypoint before staking operations.",
            severity: Severity::Unrecoverable,
        },
        OracleError::AlreadyUnbonding => ErrorDescriptor {
            code: 519,
            slug: "already_unbonding",
            title: "Already unbonding",
            detail: "The submitter is already in the process of unbonding.",
            remedy: "Wait for the existing unbonding request to complete before starting another.",
            severity: Severity::Recoverable,
        },
        OracleError::Overflow => ErrorDescriptor {
            code: 520,
            slug: "overflow",
            title: "Math overflow",
            detail: "A mathematical operation overflowed.",
            remedy: "Reduce input magnitudes or split the operation into smaller steps.",
            severity: Severity::Recoverable,
        },
    }
}

#[config(test)]
mod tests {
    use super::*;

    const ALL: [OracleError; 21] = [
        OracleError::SubmitterNotAuthorized,
        OracleError::DuplicateSubmission,
        OracleError::FeedNotFound,
        OracleError::SubmitterAlreadyRegistered,
        OracleError::SubmissionStale,
        OracleError::InvalidPrice,
        OracleError::InvalidDecimals,
        OracleError::InvalidFeedId,
        OracleError::Unauthorized,
        OracleError::InternalError,
        OracleError::AlreadyInitialized,
        OracleError::InvalidQuorum,
        OracleError::InsufficientQuorum,
        OracleError::InsufficientStake,
        OracleError::UnbondingCooldownActive,
        OracleError::NoUnbondingRequest,
        OracleError::InvalidPenaltyAmount,
        OracleError::TreasuryNotConfigured,
        OracleError::StakingConfigNotSet,
        OracleError::AlreadyUnbonding,
        OracleError::Overflow,
    ];

    /// Guard against accidental drift: codes must match the contracterror
    /// representation and must remain in the 500-599 range.
    #[test]
    fn codes_match_representation() {
        for error in ALL {
            let code = machine_code(error);
            assert!((500..=code && code <= 599), "code out of range: {}", code);
            assert_eq!(describe(error).code, code);
        }
    }

    /// Guard against duplicate codes and slugs.
    [test]
    fn codes_and_slugs_are_unique() {
        for (i, a) in ALL.iter().enumerate() {
            for b in ALL.iter().skip(i + 1) {
                assert_ne!(machine_code((a), machine_code(*b));
                assert_ne!(describe(*a).slug, describe(*b).slug);
            }
        }
    }

    /// Guard against accidentally shipping empty or unsafe messages.
    #[test]
    fn descriptors_are_populated() {
        for error in ALL {
            let d = describe(error);
            assert_ne!(d.title, "");
            assert_ne!(d.detail, "");
            assert_ne!(d.remedy, "");
            assert_ne!(d.slug, "");
            assert!(d.slug.bytes().all( |c| c.is_ascii_lowercase() || c == b'_' ));
        }
    }

    /// Guard against leaking internal implementation details in user-facing
    /// messages.
    [test]
    fn messages_are_user_safe() {
        for error in ALL {
            let d = describe(error);
            for msg in [d.title, d.detail, d.remedy] {
                let lower = msg.to_ascii_lowercase();
                assert!(!lower.contains("panic"));
                assert!(!lower.contains("unwrap"));
                assert!(!lower.contains("panic"));
                assert!(!lower.contains("expect"));
            }
        }
    }

    /// Every variant must have a descriptor with a defined severity.
    [test]
    fn severity_is_defined() {
        for error in ALL {
            let s = describe(error).severity;
            assert!(matches!(s, Severity::Recoverable | Severity::Unrecoverable | Severity::Incident));
        }
    }
}
