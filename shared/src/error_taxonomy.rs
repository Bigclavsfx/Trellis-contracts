use soroban_sdk::{contracttype, BytesN, Env, String};

use crate::errors::Error;

pub const UNEXPECTED_ERROR_CODE: &str = "UNEXPECTED_ERROR";

/// Contract family used to disambiguate contract-specific numeric error codes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorDomain {
    Shared,
    Aid,
    Oracle,
    AccessControl,
    Treasury,
    Payments,
    Batch,
    Governance,
    Referral,
    Registry,
    Marketplace,
    Upgradeability,
    Import,
    Export,
}

/// Broad class used by clients to choose safe recovery behavior.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorCategory {
    Validation,
    Authorization,
    NotFound,
    Conflict,
    Settlement,
    Configuration,
    Internal,
}

/// Safe error data for an API or client boundary.
///
/// Contract entrypoints keep returning their existing numeric error enums;
/// this envelope adds stable presentation and support metadata without
/// changing those deployed interfaces.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorInfo {
    pub domain: ErrorDomain,
    pub code: String,
    pub category: ErrorCategory,
    pub retryable: bool,
    pub message: String,
    pub recovery: Option<String>,
    pub correlation_id: BytesN<32>,
}

struct Definition {
    code: &'static str,
    category: ErrorCategory,
    retryable: bool,
    message: &'static str,
    recovery: Option<&'static str>,
}

fn definition(
    code: &'static str,
    category: ErrorCategory,
    retryable: bool,
    message: &'static str,
    recovery: Option<&'static str>,
) -> Definition {
    Definition {
        code,
        category,
        retryable,
        message,
        recovery,
    }
}

fn shared_definition(code: u32) -> Option<Definition> {
    use Error as E;

    Some(match code {
        x if x == E::Unauthorized as u32 => definition(
            "UNAUTHORIZED",
            ErrorCategory::Authorization,
            false,
            "You are not authorized to complete this action.",
            Some("Sign in with an authorized account or contact a maintainer."),
        ),
        x if x == E::NotFound as u32
            || x == E::ProposalNotFound as u32
            || x == E::MetadataNotFound as u32
            || x == E::UpgradeProposalNotFound as u32
            || x == E::ListingNotFound as u32
            || x == E::CollectionNotFound as u32 =>
        {
            definition(
                "RESOURCE_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested item could not be found.",
                Some("Check the identifier and refresh the item before trying again."),
            )
        }
        x if x == E::InvalidAmount as u32
            || x == E::InvalidArgument as u32
            || x == E::InvalidHash as u32
            || x == E::InvalidWasmHash as u32
            || x == E::PaymentInvalidAmount as u32
            || x == E::PaymentInvalidFeeRate as u32
            || x == E::InvalidMetadataHash as u32
            || x == E::InvalidRoyaltyRate as u32
            || x == E::InvalidExtensionWindow as u32
            || x == E::InvalidTransition as u32
            || x == E::InvalidMigrationHook as u32
            || x == E::PaymentTokenNotSupported as u32 =>
        {
            definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "Some of the submitted information is invalid.",
                Some("Review the indicated fields and submit corrected values."),
            )
        }
        x if x == E::ContractPaused as u32 => definition(
            "CONTRACT_PAUSED",
            ErrorCategory::Conflict,
            true,
            "This action is temporarily unavailable while the service is paused.",
            Some("Try again after the service has resumed."),
        ),
        x if x == E::Expired as u32 || x == E::ProposalExpired as u32 => definition(
            "REQUEST_EXPIRED",
            ErrorCategory::Conflict,
            false,
            "This request has expired and can no longer be completed.",
            Some("Start a new request if the action is still needed."),
        ),
        x if x == E::StaleData as u32 => definition(
            "ORACLE_DATA_STALE",
            ErrorCategory::Validation,
            false,
            "The latest price data is too old to safely complete this action.",
            Some("Request a fresh price quote before retrying."),
        ),
        x if x == E::AlreadyClaimed as u32
            || x == E::AlreadyApproved as u32
            || x == E::AlreadyExecuted as u32
            || x == E::AlreadyInitialized as u32
            || x == E::ProposalCancelled as u32
            || x == E::ImmutableEntry as u32
            || x == E::ListingAlreadySold as u32
            || x == E::PaymentEscrowAlreadyReleased as u32
            || x == E::PaymentEscrowAlreadyRefunded as u32
            || x == E::UpgradeAlreadyExecuted as u32
            || x == E::UpgradeAlreadyPending as u32
            || x == E::ContractAlreadyRegistered as u32
            || x == E::CollectionAlreadyRegistered as u32
            || x == E::AidAlreadyRefunded as u32 =>
        {
            definition(
                "INVALID_STATE",
                ErrorCategory::Conflict,
                false,
                "This action is not available in the item's current state.",
                Some("Refresh the item to see its latest status."),
            )
        }
        x if x == E::InsufficientBalance as u32
            || x == E::PaymentInsufficientBalance as u32
            || x == E::PaymentEscrowNotExpired as u32
            || x == E::AidNotExpiredYet as u32
            || x == E::BelowThreshold as u32 =>
        {
            definition(
                "SETTLEMENT_NOT_READY",
                ErrorCategory::Settlement,
                true,
                "The operation cannot be settled with the current balance or status.",
                Some("Check the balance and eligibility, then retry when the required conditions are met."),
            )
        }
        x if x == E::WithdrawalLimitExceeded as u32
            || x == E::QuotaExceeded as u32
            || x == E::PaymentEscrowExpired as u32 =>
        {
            definition(
                "OPERATION_LIMITED",
                ErrorCategory::Conflict,
                x == E::QuotaExceeded as u32,
                "The operation is currently outside its allowed limits.",
                Some("Review the applicable limit or wait for the quota window to reset."),
            )
        }
        x if x == E::PaymentEscrowUnauthorized as u32 || x == E::NotOwner as u32 => definition(
            "UNAUTHORIZED",
            ErrorCategory::Authorization,
            false,
            "You are not authorized to complete this action.",
            Some("Use the account that owns the item or contact a maintainer."),
        ),
        x if x == E::NotUpgrader as u32 => definition(
            "UNAUTHORIZED",
            ErrorCategory::Authorization,
            false,
            "You are not authorized to complete this action.",
            Some("Contact an administrator to request upgrade permission."),
        ),
        x if x == E::ConfigMissing as u32
            || x == E::ConfigInvalid as u32
            || x == E::CurrencyNotWhitelisted as u32 =>
        {
            definition(
            "CONFIGURATION_UNAVAILABLE",
            ErrorCategory::Configuration,
            false,
            "A required service configuration is unavailable.",
            Some("Contact a maintainer and provide the reference ID."),
            )
        }
        x if x == E::ContractNotRegistered as u32
            || x == E::PaymentEscrowNotFound as u32 =>
        {
            definition(
                "RESOURCE_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested item could not be found.",
                Some("Check the identifier and refresh the item before trying again."),
            )
        }
        x if x == E::Overflow as u32
            || x == E::PaymentFeeOverflow as u32
            || x == E::PaymentEscrowIdOverflow as u32
            || x == E::SchemaMigrationFailed as u32
            || x == E::MigrationHookFailed as u32
            || x == E::StorageIncompatible as u32
            || x == E::UnsafeSecret as u32 =>
        {
            definition(
                "OPERATION_FAILED",
                ErrorCategory::Internal,
                false,
                "The operation could not be completed.",
                Some("Contact support and provide the reference ID."),
            )
        }
        x if x == E::UnsupportedSchemaVersion as u32 => definition(
            "UNSUPPORTED_SCHEMA",
            ErrorCategory::Configuration,
            false,
            "This record format is not supported by the current service version.",
            Some("Contact a maintainer before retrying this operation."),
        ),
        x if x == E::DependencyDegraded as u32 => definition(
            "DEPENDENCY_DEGRADED",
            ErrorCategory::Settlement,
            true,
            "An external dependency is degraded or unavailable. Safe fallback behavior has been engaged.",
            Some("Verify dependency status or retry once external services recover."),
        ),
        x if x == E::NotPaused as u32
            || x == E::NoChangeDetected as u32 =>
        {
            definition(
                "INVALID_STATE",
                ErrorCategory::Conflict,
                false,
                "This action is not available in the item's current state.",
                Some("Refresh the item to see its latest status."),
            )
        }
        _ => return None,
    })
}

fn domain_definition(domain: &ErrorDomain, code: u32) -> Option<Definition> {
    match domain {
        ErrorDomain::Aid => Some(match code {
            100 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to complete this action.",
                Some("Use the account that owns the item or contact a maintainer."),
            ),
            101 => definition(
                "AID_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested aid record could not be found.",
                Some("Check the aid identifier and refresh the record."),
            ),
            102 | 106 | 107 => definition(
                "AID_ALREADY_SETTLED",
                ErrorCategory::Conflict,
                false,
                "This aid record can no longer be changed.",
                Some("Refresh the record to see its latest status."),
            ),
            103 => definition(
                "AID_EXPIRED",
                ErrorCategory::Conflict,
                false,
                "This aid record has expired.",
                Some("Create a new aid record if assistance is still needed."),
            ),
            104 => definition(
                "CONTRACT_PAUSED",
                ErrorCategory::Conflict,
                true,
                "This action is temporarily unavailable while the service is paused.",
                Some("Try again after the service has resumed."),
            ),
            105 => definition(
                "AID_NOT_READY",
                ErrorCategory::Settlement,
                true,
                "This aid record is not yet eligible for settlement.",
                Some("Retry after the aid record's expiry time."),
            ),
            _ => return None,
        }),
        ErrorDomain::Oracle => Some(match code {
            500 | 508 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to complete this action.",
                Some("Use a registered oracle account or contact a maintainer."),
            ),
            501 => definition(
                "ORACLE_DUPLICATE_SUBMISSION",
                ErrorCategory::Conflict,
                false,
                "This oracle update has already been submitted.",
                Some("Refresh the feed to see the latest accepted value."),
            ),
            502 => definition(
                "ORACLE_FEED_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested oracle feed could not be found.",
                Some("Check the feed identifier and try again."),
            ),
            503 => definition(
                "ORACLE_SUBMITTER_EXISTS",
                ErrorCategory::Conflict,
                false,
                "This oracle submitter is already registered.",
                Some("Refresh the submitter list before making changes."),
            ),
            504 => definition(
                "ORACLE_UPDATE_STALE",
                ErrorCategory::Validation,
                false,
                "The oracle update is too old to be accepted.",
                Some("Submit a fresh update with the current timestamp."),
            ),
            505..=507 => definition(
                "ORACLE_VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The oracle update contains invalid values.",
                Some("Review the feed identifier, price, and decimal precision."),
            ),
            509 => definition(
                "OPERATION_FAILED",
                ErrorCategory::Internal,
                false,
                "The operation could not be completed.",
                Some("Contact support and provide the reference ID."),
            ),
            510 => definition(
                "INVALID_STATE",
                ErrorCategory::Conflict,
                false,
                "This service has already been initialized.",
                Some("Contact a maintainer if the initialization is unexpected."),
            ),
            _ => return None,
        }),
        ErrorDomain::AccessControl => Some(match code {
            200 | 209 => definition(
                "ROLE_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested role or invitation could not be found.",
                Some("Refresh the role list and check the supplied identifier."),
            ),
            201..=205 | 207 | 210 | 213 => definition(
                "INVALID_ROLE_STATE",
                ErrorCategory::Conflict,
                false,
                "This role change is not valid in the current state.",
                Some("Refresh the role configuration before trying again."),
            ),
            206 | 211 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to complete this action.",
                Some("Contact an administrator to request the required permission."),
            ),
            208 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The supplied role name is invalid.",
                Some("Use a non-empty role name supported by the contract."),
            ),
            212 => definition(
                "RATE_LIMITED",
                ErrorCategory::Conflict,
                true,
                "Too many role invitations were created in a short period.",
                Some("Wait for the invitation limit window to reset."),
            ),
            214 => definition(
                "OPERATION_FAILED",
                ErrorCategory::Internal,
                false,
                "The operation could not be completed.",
                Some("Contact support and provide the reference ID."),
            ),
            _ => return None,
        }),
        ErrorDomain::Marketplace => Some(match code {
            2000 | 2004 => definition(
                "RESOURCE_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested marketplace item could not be found.",
                Some("Check the item identifier and refresh the listing."),
            ),
            2002 | 2015 | 2021 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to complete this action.",
                Some("Use the account that owns the item or contact a maintainer."),
            ),
            2006..=2008 | 2017..=2019 | 2022 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "Some of the submitted information is invalid.",
                Some("Review the supplied values and submit corrected information."),
            ),
            2001 | 2003 | 2009 | 2011 | 2013 | 2014 | 2023 => definition(
                "INVALID_STATE",
                ErrorCategory::Conflict,
                false,
                "This marketplace action is not available in the item's current state.",
                Some("Refresh the listing or offer to see its latest status."),
            ),
            2012 => definition(
                "SETTLEMENT_NOT_READY",
                ErrorCategory::Settlement,
                true,
                "The auction is not ready to be settled.",
                Some("Retry after the auction has ended."),
            ),
            2010 | 2016 => definition(
                "SETTLEMENT_NOT_READY",
                ErrorCategory::Settlement,
                false,
                "The auction cannot be settled with the current bid or price.",
                Some("Review the minimum bid and auction timing, then try again."),
            ),
            2005 => definition(
                "CURRENCY_UNAVAILABLE",
                ErrorCategory::Configuration,
                false,
                "This currency is not available for marketplace transactions.",
                Some("Choose a supported currency."),
            ),
            2020 => definition(
                "CONTRACT_PAUSED",
                ErrorCategory::Conflict,
                true,
                "This action is temporarily unavailable while the service is paused.",
                Some("Try again after the service has resumed."),
            ),
            _ => return None,
        }),
        ErrorDomain::Upgradeability => Some(match code {
            907 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to complete this action.",
                Some("Contact an administrator to request upgrade permission."),
            ),
            900 | 903 => definition(
                "RESOURCE_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested contract or upgrade proposal could not be found.",
                Some("Check the contract identifier and refresh the upgrade registry."),
            ),
            901 | 902 | 904 | 906 | 911 => definition(
                "INVALID_UPGRADE_STATE",
                ErrorCategory::Conflict,
                false,
                "This upgrade is not available in the current state.",
                Some("Refresh the upgrade registry and verify the proposed version."),
            ),
            908 | 910 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The upgrade configuration is invalid.",
                Some("Verify the WASM hash and migration hook address."),
            ),
            905 | 909 => definition(
                "UPGRADE_VALIDATION_FAILED",
                ErrorCategory::Internal,
                false,
                "The upgrade could not be safely applied.",
                Some("Do not retry until a maintainer has reviewed the migration."),
            ),
            _ => return None,
        }),
        ErrorDomain::Payments if code == Error::Expired as u32 => Some(definition(
            "SETTLEMENT_TIMEOUT",
            ErrorCategory::Settlement,
            true,
            "Settlement confirmation was not received.",
            Some("Retry the pending settlement without submitting another transfer."),
        )),
        ErrorDomain::Batch => Some(match code {
            800 => definition(
                "BATCH_TOO_LARGE",
                ErrorCategory::Validation,
                false,
                "The batch exceeds the maximum number of operations.",
                Some("Split the operations into smaller batches and retry."),
            ),
            801 => definition(
                "BATCH_OPERATION_FAILED",
                ErrorCategory::Settlement,
                false,
                "An operation in the atomic batch failed; the batch was rolled back.",
                Some("Inspect the target operation and retry after correcting its cause."),
            ),
            802 => definition(
                "BATCH_CONFIG_INVALID",
                ErrorCategory::Configuration,
                false,
                "The batch configuration is invalid.",
                Some("Set the operation limit within the supported range."),
            ),
            803 => definition(
                "BATCH_OPERATION_INVALID",
                ErrorCategory::Validation,
                false,
                "An operation in the batch contains invalid arguments.",
                Some("Correct the operation inputs and submit the batch again."),
            ),
            804 => definition(
                "BATCH_EMPTY",
                ErrorCategory::Validation,
                false,
                "The batch contains no operations.",
                Some("Include at least one operation."),
            ),
            805 => definition(
                "BATCH_REENTRANCY_DETECTED",
                ErrorCategory::Conflict,
                false,
                "A batch operation is already in progress.",
                Some("Wait for the current operation to finish before retrying."),
            ),
            _ => return None,
        }),
        ErrorDomain::Import => Some(match code {
            940 => definition(
                "BATCH_TOO_LARGE",
                ErrorCategory::Validation,
                false,
                "The import batch exceeds the maximum allowed row count.",
                Some("Split the import into batches of 50 to 100 rows and retry."),
            ),
            941 => definition(
                "EMPTY_BATCH",
                ErrorCategory::Validation,
                false,
                "The import batch contains no records.",
                Some("Include at least one valid record in the batch."),
            ),
            942 => definition(
                "INVALID_CONFIG",
                ErrorCategory::Configuration,
                false,
                "The import configuration is invalid.",
                Some("Check max_rows and duplicate policy parameters."),
            ),
            943 => definition(
                "DUPLICATE_ID",
                ErrorCategory::Conflict,
                false,
                "Duplicate external identifier detected under RejectDuplicate policy.",
                Some("Remove duplicates or select SkipExisting or UpdateExisting policy."),
            ),
            944 => definition(
                "INVALID_ROW",
                ErrorCategory::Validation,
                false,
                "One or more rows failed validation in atomic import mode.",
                Some("Review the row error details, correct the values, and resubmit."),
            ),
            945 => definition(
                "REENTRANCY_DETECTED",
                ErrorCategory::Conflict,
                false,
                "Reentrancy detected during import execution.",
                Some("Wait for ongoing operations to complete before invoking import."),
            ),
            946 => definition(
                "INVALID_AMOUNT",
                ErrorCategory::Validation,
                false,
                "Import row amount must be strictly positive.",
                Some("Correct row amounts to positive values and retry."),
            ),
            947 => definition(
                "RECORD_EXPIRED",
                ErrorCategory::Validation,
                false,
                "Import row expiry ledger or timestamp is in the past.",
                Some("Update expiry values to future timestamps and retry."),
            ),
            948 => definition(
                "EXTERNAL_ID_TOO_LONG",
                ErrorCategory::Validation,
                false,
                "External identifier exceeds the 64-byte limit.",
                Some("Shorten external IDs to 64 bytes or fewer."),
            ),
            _ => return None,
        }),
        ErrorDomain::Export => Some(match code {
            920 | 921 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to complete this action.",
                Some("Use an account with export permission or contact a maintainer."),
            ),
            922 => definition(
                "EXPORT_TOO_LARGE",
                ErrorCategory::Validation,
                false,
                "The export exceeds the maximum number of records.",
                Some("Reduce the requested record count and retry."),
            ),
            923 => definition(
                "EXPORT_INVALID_SCOPE",
                ErrorCategory::Validation,
                false,
                "The requested export scope is invalid.",
                Some("Choose a supported export scope."),
            ),
            924 => definition(
                "EXPORT_EXPIRED",
                ErrorCategory::Conflict,
                false,
                "This export has expired.",
                Some("Generate a new export."),
            ),
            925 => definition(
                "EXPORT_TTL_TOO_LONG",
                ErrorCategory::Validation,
                false,
                "The requested export validity window is too long.",
                Some("Choose a shorter validity window."),
            ),
            926 => definition(
                "UNSUPPORTED_SCHEMA",
                ErrorCategory::Configuration,
                false,
                "This export format is not supported by the current service version.",
                Some("Contact a maintainer before retrying this operation."),
            ),
            927 => definition(
                "EXPORT_INVALID_REQUEST",
                ErrorCategory::Validation,
                false,
                "The export request contains invalid parameters.",
                Some("Review the request parameters and submit corrected values."),
            ),
            _ => return None,
        }),
        _ => None,
    }
}

/// Returns the stable machine code for a raw contract error without needing
/// an `Env`, so off-chain tooling and docs generators can share the same
/// taxonomy as on-chain callers.
pub fn stable_code(domain: ErrorDomain, raw_code: u32) -> &'static str {
    domain_definition(&domain, raw_code)
        .or_else(|| shared_definition(raw_code))
        .map(|details| details.code)
        .unwrap_or(UNEXPECTED_ERROR_CODE)
}

/// Returns true when the raw error is part of the documented taxonomy for the
/// given domain. Used by tests and CI to prevent accidental contract drift.
pub fn is_documented(domain: ErrorDomain, raw_code: u32) -> bool {
    domain_definition(&domain, raw_code).is_some() || shared_definition(raw_code).is_some()
}

/// Converts a raw contract error into a safe, structured response.
///
/// `correlation_id` should be supplied by the calling API or client. A
/// transaction hash is preferred because failed Soroban invocations roll back
/// contract storage and events, so a contract cannot persist a failure ID.
pub fn describe_error(
    env: &Env,
    domain: ErrorDomain,
    raw_code: u32,
    correlation_id: BytesN<32>,
) -> ErrorInfo {
    let details = domain_definition(&domain, raw_code)
        .or_else(|| shared_definition(raw_code))
        .unwrap_or_else(|| {
            definition(
                UNEXPECTED_ERROR_CODE,
                ErrorCategory::Internal,
                false,
                "The operation could not be completed.",
                Some("Contact support and provide the reference ID."),
            )
        });

    ErrorInfo {
        domain,
        code: String::from_str(env, details.code),
        category: details.category,
        retryable: details.retryable,
        message: String::from_str(env, details.message),
        recovery: details.recovery.map(|text| String::from_str(env, text)),
        correlation_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aid::AidError;
    use crate::batch::BatchError;

    fn correlation_id(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0x42; 32])
    }

    #[test]
    fn validation_errors_have_stable_safe_guidance() {
        let env = Env::default();
        let info = describe_error(
            &env,
            ErrorDomain::Shared,
            Error::InvalidArgument as u32,
            correlation_id(&env),
        );

        assert_eq!(info.code, String::from_str(&env, "VALIDATION_FAILED"));
        assert_eq!(info.category, ErrorCategory::Validation);
        assert!(!info.retryable);
        assert!(info.recovery.is_some());
    }

    #[test]
    fn authorization_errors_are_not_retryable() {
        let env = Env::default();
        let info = describe_error(
            &env,
            ErrorDomain::Shared,
            Error::Unauthorized as u32,
            correlation_id(&env),
        );

        assert_eq!(info.code, String::from_str(&env, "UNAUTHORIZED"));
        assert_eq!(info.category, ErrorCategory::Authorization);
        assert!(!info.retryable);
    }

    #[test]
    fn settlement_metadata_preserves_correlation_id() {
        let env = Env::default();
        let id = correlation_id(&env);
        let info = describe_error(
            &env,
            ErrorDomain::Payments,
            Error::PaymentInsufficientBalance as u32,
            id.clone(),
        );

        assert_eq!(info.code, String::from_str(&env, "SETTLEMENT_NOT_READY"));
        assert_eq!(info.category, ErrorCategory::Settlement);
        assert!(info.retryable);
        assert_eq!(info.correlation_id, id);
    }

    #[test]
    fn stale_oracle_data_requires_a_fresh_quote() {
        let env = Env::default();
        let info = describe_error(
            &env,
            ErrorDomain::Shared,
            Error::StaleData as u32,
            correlation_id(&env),
        );

        assert_eq!(info.code, String::from_str(&env, "ORACLE_DATA_STALE"));
        assert_eq!(info.category, ErrorCategory::Validation);
        assert!(!info.retryable);
        assert!(info.recovery.is_some());
    }

    #[test]
    fn settlement_timeout_is_retryable_without_resubmitting_payment() {
        let env = Env::default();
        let info = describe_error(
            &env,
            ErrorDomain::Payments,
            Error::Expired as u32,
            correlation_id(&env),
        );

        assert_eq!(info.code, String::from_str(&env, "SETTLEMENT_TIMEOUT"));
        assert_eq!(info.category, ErrorCategory::Settlement);
        assert!(info.retryable);
    }

    #[test]
    fn unknown_errors_use_generic_safe_fallback() {
        let env = Env::default();
        let info = describe_error(&env, ErrorDomain::Oracle, 99_999, correlation_id(&env));

        assert_eq!(info.code, String::from_str(&env, "UNEXPECTED_ERROR"));
        assert_eq!(info.category, ErrorCategory::Internal);
        assert!(!info.retryable);
        assert!(info.recovery.is_some());
    }

    #[test]
    fn every_shared_error_variant_has_a_stable_catalog_mapping() {
        let env = Env::default();
        let codes = [
            Error::Unauthorized as u32,
            Error::NotFound as u32,
            Error::InvalidAmount as u32,
            Error::Overflow as u32,
            Error::ContractPaused as u32,
            Error::Expired as u32,
            Error::AlreadyClaimed as u32,
            Error::InsufficientBalance as u32,
            Error::WithdrawalLimitExceeded as u32,
            Error::InvalidArgument as u32,
            Error::NotPaused as u32,
            Error::ProposalNotFound as u32,
            Error::AlreadyApproved as u32,
            Error::BelowThreshold as u32,
            Error::AlreadyExecuted as u32,
            Error::ImmutableEntry as u32,
            Error::InvalidHash as u32,
            Error::MetadataNotFound as u32,
            Error::AlreadyInitialized as u32,
            Error::UnsupportedSchemaVersion as u32,
            Error::SchemaMigrationFailed as u32,
            Error::QuotaExceeded as u32,
            Error::ConfigMissing as u32,
            Error::ConfigInvalid as u32,
            Error::UnsafeSecret as u32,
            Error::ProposalExpired as u32,
            Error::ProposalCancelled as u32,
            Error::StaleData as u32,
            Error::ContractNotRegistered as u32,
            Error::ContractAlreadyRegistered as u32,
            Error::NoChangeDetected as u32,
            Error::UpgradeProposalNotFound as u32,
            Error::UpgradeAlreadyExecuted as u32,
            Error::MigrationHookFailed as u32,
            Error::UpgradeAlreadyPending as u32,
            Error::NotUpgrader as u32,
            Error::InvalidWasmHash as u32,
            Error::StorageIncompatible as u32,
            Error::InvalidMigrationHook as u32,
            Error::PaymentInvalidAmount as u32,
            Error::PaymentInsufficientBalance as u32,
            Error::PaymentEscrowNotFound as u32,
            Error::PaymentEscrowAlreadyReleased as u32,
            Error::PaymentEscrowAlreadyRefunded as u32,
            Error::PaymentEscrowUnauthorized as u32,
            Error::PaymentEscrowExpired as u32,
            Error::PaymentEscrowNotExpired as u32,
            Error::PaymentInvalidFeeRate as u32,
            Error::PaymentFeeOverflow as u32,
            Error::PaymentEscrowIdOverflow as u32,
            Error::PaymentTokenNotSupported as u32,
            Error::ListingNotFound as u32,
            Error::ListingAlreadySold as u32,
            Error::NotOwner as u32,
            Error::CollectionAlreadyRegistered as u32,
            Error::CollectionNotFound as u32,
            Error::CurrencyNotWhitelisted as u32,
            Error::InvalidMetadataHash as u32,
            Error::InvalidRoyaltyRate as u32,
            Error::InvalidExtensionWindow as u32,
            Error::InvalidTransition as u32,
            Error::AidNotExpiredYet as u32,
            Error::AidAlreadyRefunded as u32,
        ];

        for raw_code in codes {
            let info = describe_error(&env, ErrorDomain::Shared, raw_code, correlation_id(&env));
            assert_ne!(
                info.code,
                String::from_str(&env, "UNEXPECTED_ERROR"),
                "shared error code {raw_code} must be documented"
            );
        }
    }

    #[test]
    fn every_batch_error_has_a_domain_specific_stable_mapping() {
        let env = Env::default();
        let codes = [
            BatchError::BatchTooLarge as u32,
            BatchError::OperationFailed as u32,
            BatchError::InvalidConfig as u32,
            BatchError::InvalidOperation as u32,
            BatchError::EmptyBatch as u32,
            BatchError::ReentrancyDetected as u32,
        ];

        for raw_code in codes {
            let info = describe_error(&env, ErrorDomain::Batch, raw_code, correlation_id(&env));
            assert_ne!(
                info.code,
                String::from_str(&env, "UNEXPECTED_ERROR"),
                "batch error code {raw_code} must be documented"
            );
            assert!(info.recovery.is_some());
        }
    }

    #[test]
    fn contract_error_ranges_have_stable_domain_mappings() {
        let env = Env::default();
        let ranges = [
            (ErrorDomain::Aid, 100, 107),
            (ErrorDomain::AccessControl, 200, 214),
            (ErrorDomain::Oracle, 500, 510),
            (ErrorDomain::Upgradeability, 900, 911),
            (ErrorDomain::Import, 940, 948),
            (ErrorDomain::Export, 920, 927),
            (ErrorDomain::Marketplace, 2000, 2023),
        ];

        for (domain, first, last) in ranges {
            for raw_code in first..=last {
                let info = describe_error(&env, domain.clone(), raw_code, correlation_id(&env));
                assert_ne!(
                    info.code,
                    String::from_str(&env, "UNEXPECTED_ERROR"),
                    "error code {raw_code} in {domain:?} must be documented"
                );
            }
        }
    }

    #[test]
    fn stable_code_matches_describe_error_for_documented_codes() {
        let env = Env::default();
        let samples = [
            (ErrorDomain::Shared, Error::Unauthorized as u32),
            (ErrorDomain::Shared, Error::InvalidArgument as u32),
            (ErrorDomain::Payments, Error::Expired as u32),
            (ErrorDomain::Batch, BatchError::BatchTooLarge as u32),
            (ErrorDomain::Aid, AidError::Unauthorized as u32),
        ];

        for (domain, raw_code) in samples {
            let info = describe_error(&env, domain.clone(), raw_code, correlation_id(&env));
            assert_eq!(
                info.code,
                String::from_str(&env, stable_code(domain.clone(), raw_code)),
                "stable_code must agree with describe_error for {domain:?}/{raw_code}"
            );
            assert!(is_documented(domain, raw_code));
        }
    }

    #[test]
    fn undocumented_codes_are_reported_as_unexpected() {
        assert_eq!(
            stable_code(ErrorDomain::Oracle, 99_999),
            UNEXPECTED_ERROR_CODE
        );
        assert!(!is_documented(ErrorDomain::Oracle, 99_999));
    }

    #[test]
    fn every_documented_code_has_a_recovery_hint() {
        let env = Env::default();
        let ranges = [
            (ErrorDomain::Aid, 100, 107),
            (ErrorDomain::AccessControl, 200, 214),
            (ErrorDomain::Oracle, 500, 510),
            (ErrorDomain::Upgradeability, 900, 911),
            (ErrorDomain::Export, 920, 927),
            (ErrorDomain::Import, 940, 948),
            (ErrorDomain::Marketplace, 2000, 2023),
        ];

        for (domain, first, last) in ranges {
            for raw_code in first..=last {
                let info =
                    describe_error(&env, domain.clone(), raw_code, correlation_id(&env));
                assert!(
                    info.recovery.is_some(),
                    "error code {raw_code} in {domain:?} must include a recovery hint"
                );
                assert!(
                    !info.message.is_empty(),
                    "error code {raw_code} in {domain:?} must include a safe message"
                );
            }
        }
    }
}
