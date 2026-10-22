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
    SupportAccess,
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
            108 => definition(
                "INVALID_CORRELATION_ID",
                ErrorCategory::Validation,
                false,
                "The correlation ID is malformed or not allowed.",
                Some("Send a valid 32-byte correlation ID, or omit it."),
            ),
            109 => definition(
                "UNSUPPORTED_SCHEMA",
                ErrorCategory::Configuration,
                false,
                "This record uses a schema version this service does not support.",
                Some("Upgrade the client to a supported schema version."),
            ),
            110 => definition(
                "SCHEMA_MIGRATION_FAILED",
                ErrorCategory::Internal,
                false,
                "The record could not be migrated to the current schema.",
                Some("Do not retry unchanged. Contact a maintainer with the reference ID."),
            ),
            111 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "One or more request values are not valid.",
                Some("Review the request fields and submit corrected values."),
            ),
            112 => definition(
                "BATCH_TOO_LARGE",
                ErrorCategory::Validation,
                false,
                "The batch contains more operations than allowed.",
                Some("Split the batch into smaller groups and submit each group."),
            ),
            113 => definition(
                "EMPTY_BATCH",
                ErrorCategory::Validation,
                false,
                "The batch contains no operations.",
                Some("Add at least one operation to the batch."),
            ),
            114 => definition(
                "NOT_MILESTONE_BASED",
                ErrorCategory::Validation,
                false,
                "This aid does not use milestones.",
                Some("Use the standard claim flow for this aid."),
            ),
            115 => definition(
                "INVALID_MILESTONE",
                ErrorCategory::Validation,
                false,
                "The requested milestone does not exist.",
                Some("Check the milestone index and submit it again."),
            ),
            116 => definition(
                "MILESTONE_NOT_VERIFIED",
                ErrorCategory::Settlement,
                true,
                "This milestone has not been verified yet.",
                Some("Wait for an authorized inspector to verify the milestone, then retry."),
            ),
            117 => definition(
                "MILESTONE_ALREADY_CLAIMED",
                ErrorCategory::Conflict,
                false,
                "This milestone has already been claimed.",
                Some("No action is needed. Check the aid's claim history."),
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
            505 => definition(
                "INVALID_PRICE",
                ErrorCategory::Validation,
                false,
                "The submitted price is not valid.",
                Some("Submit a positive price within the allowed range."),
            ),
            506 => definition(
                "INVALID_DECIMALS",
                ErrorCategory::Validation,
                false,
                "The price precision is not supported.",
                Some("Submit the price using the feed's configured decimals."),
            ),
            511 => definition(
                "INVALID_QUORUM",
                ErrorCategory::Validation,
                false,
                "The quorum setting is not valid for this feed.",
                Some("Choose a quorum the feed's submitter set can satisfy."),
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
            201 => definition(
                "ROLE_ALREADY_EXISTS",
                ErrorCategory::Conflict,
                false,
                "That role already exists.",
                Some("Use the existing role or choose a different role name."),
            ),
            202 => definition(
                "ALREADY_MEMBER",
                ErrorCategory::Conflict,
                false,
                "This account already holds the role.",
                Some("No action is needed. Check the account's current roles."),
            ),
            203 => definition(
                "NOT_MEMBER",
                ErrorCategory::NotFound,
                false,
                "This account does not hold the role.",
                Some("Check the account address and role name."),
            ),
            204 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "A role cannot be a parent of itself.",
                Some("Choose a different parent role."),
            ),
            215 => definition(
                "CONTRACT_PAUSED",
                ErrorCategory::Conflict,
                true,
                "This operation is temporarily paused.",
                Some("Try again after the pause is lifted."),
            ),
            216 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The pause scope is not recognised.",
                Some("Use one of the documented pause scopes."),
            ),
            217 => definition(
                "INVALID_ROLE_STATE",
                ErrorCategory::Conflict,
                false,
                "This operation is not paused, so there is nothing to resume.",
                Some("No action is needed."),
            ),
            218 => definition(
                "NO_PENDING_TRANSFER",
                ErrorCategory::NotFound,
                false,
                "No ownership transfer is pending.",
                Some("Propose a new ownership transfer if one is needed."),
            ),
            219 => definition(
                "TRANSFER_EXPIRED",
                ErrorCategory::Conflict,
                false,
                "The pending ownership transfer has expired.",
                Some("Propose the transfer again."),
            ),
            220 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "Only the proposed new owner can accept this transfer.",
                Some("Accept the transfer from the proposed owner's account."),
            ),
            221 => definition(
                "TRANSFER_ALREADY_PENDING",
                ErrorCategory::Conflict,
                false,
                "An ownership transfer is already pending.",
                Some("Accept or cancel the pending transfer before proposing another."),
            ),
            222 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The expiry time is not valid.",
                Some("Submit an expiry time in the future."),
            ),
            223 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The role duration is not valid.",
                Some("Submit a duration greater than zero."),
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
            2006 => definition(
                "INVALID_METADATA_HASH",
                ErrorCategory::Validation,
                false,
                "The metadata hash is not valid.",
                Some("Submit a 32-byte metadata hash in the documented format."),
            ),
            2007 => definition(
                "INVALID_ROYALTY",
                ErrorCategory::Validation,
                false,
                "The royalty rate is outside the allowed range.",
                Some("Submit a royalty rate within the documented maximum."),
            ),
            2008 => definition(
                "INVALID_EXTENSION_WINDOW",
                ErrorCategory::Validation,
                false,
                "The auction extension window is not valid.",
                Some("Submit an extension window within the documented limits."),
            ),
            2017 => definition(
                "INVALID_DUTCH_PRICES",
                ErrorCategory::Validation,
                false,
                "The Dutch auction prices are not valid.",
                Some("Set a starting price higher than the ending price."),
            ),
            2018 => definition(
                "INVALID_AMOUNT",
                ErrorCategory::Validation,
                false,
                "The amount is not valid.",
                Some("Submit an amount within the allowed range."),
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
            912 => definition(
                "UPGRADE_VALIDATION_FAILED",
                ErrorCategory::Internal,
                false,
                "The upgrade did not pass post-upgrade checks.",
                Some("Do not retry automatically. Contact a maintainer with the reference ID."),
            ),
            913 => definition(
                "UPGRADE_ROLLED_BACK",
                ErrorCategory::Internal,
                false,
                "The upgrade was rolled back after a failed check.",
                Some("The previous version stays active. Review the reference ID first."),
            ),
            914 => definition(
                "VALIDATION_FAILED",
                ErrorCategory::Validation,
                false,
                "The timelock delay is outside the allowed range.",
                Some("Submit a delay within the documented bounds."),
            ),
            915 => definition(
                "TIMELOCK_NOT_EXPIRED",
                ErrorCategory::Conflict,
                true,
                "The upgrade timelock has not expired yet.",
                Some("Wait until the timelock expires, then execute the upgrade."),
            ),
            _ => return None,
        }),
        ErrorDomain::Payments => Some(match code {
            x if x == Error::Expired as u32 => definition(
                "SETTLEMENT_TIMEOUT",
                ErrorCategory::Settlement,
                true,
                "Settlement confirmation was not received.",
                Some("Retry the pending settlement without submitting another transfer."),
            ),
            700 => definition(
                "INVALID_AMOUNT",
                ErrorCategory::Validation,
                false,
                "The payment amount is not valid.",
                Some("Submit a strictly positive payment amount."),
            ),
            701 => definition(
                "INSUFFICIENT_BALANCE",
                ErrorCategory::Settlement,
                true,
                "Sender has insufficient balance for this payment.",
                Some("Top up token balance and retry the transfer."),
            ),
            702 => definition(
                "ESCROW_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The specified escrow deposit does not exist.",
                Some("Verify the escrow identifier before retrying."),
            ),
            703 => definition(
                "ESCROW_ALREADY_RELEASED",
                ErrorCategory::Conflict,
                false,
                "This escrow has already been released.",
                Some("No action needed; check escrow completion status."),
            ),
            704 => definition(
                "ESCROW_ALREADY_REFUNDED",
                ErrorCategory::Conflict,
                false,
                "This escrow has already been refunded.",
                Some("No action needed; funds were returned to depositor."),
            ),
            705 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "Caller is not authorized to release or refund this escrow.",
                Some("Authenticate with the depositor or beneficiary account."),
            ),
            706 => definition(
                "ESCROW_EXPIRED",
                ErrorCategory::Conflict,
                false,
                "The escrow has expired and cannot be released.",
                Some("Request a refund or create a new escrow."),
            ),
            707 => definition(
                "ESCROW_NOT_EXPIRED",
                ErrorCategory::Conflict,
                true,
                "The escrow has not yet expired and cannot be refunded.",
                Some("Wait until after the expiry ledger has elapsed to claim refund."),
            ),
            708 => definition(
                "INVALID_FEE_RATE",
                ErrorCategory::Validation,
                false,
                "The fee basis-point rate is out of the valid 0-10,000 range.",
                Some("Provide a valid fee rate between 0 and 10,000 bps."),
            ),
            709 => definition(
                "CALCULATION_OVERFLOW",
                ErrorCategory::Internal,
                false,
                "Fee calculation resulted in arithmetic overflow.",
                Some("Reduce payment amount or contact support."),
            ),
            710 => definition(
                "ID_OVERFLOW",
                ErrorCategory::Internal,
                false,
                "Escrow identifier counter overflowed.",
                Some("Contact protocol administrator."),
            ),
            711 => definition(
                "UNSUPPORTED_TOKEN",
                ErrorCategory::Configuration,
                false,
                "The requested token is not supported by this payment gateway.",
                Some("Use a whitelisted payment token address."),
            ),
            _ => return None,
        }),
        ErrorDomain::Treasury => Some(match code {
            300 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "Caller is not authorized to perform treasury vault operations.",
                Some("Ensure caller holds the required Treasury Admin or Operator role."),
            ),
            301 => definition(
                "INSUFFICIENT_FUNDS",
                ErrorCategory::Settlement,
                true,
                "The treasury vault balance is insufficient for this disbursement.",
                Some("Deposit additional liquidity into the vault before retrying."),
            ),
            302 => definition(
                "WITHDRAWAL_LIMIT_EXCEEDED",
                ErrorCategory::Conflict,
                true,
                "The requested withdrawal amount exceeds configured per-transaction limit.",
                Some("Reduce withdrawal amount or request budget ceiling increase."),
            ),
            303 => definition(
                "TIMELOCK_ACTIVE",
                ErrorCategory::Conflict,
                true,
                "The scheduled treasury withdrawal timelock has not elapsed.",
                Some("Wait for timelock window to open before executing."),
            ),
            304 => definition(
                "PROPOSAL_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The scheduled treasury action proposal does not exist.",
                Some("Verify the proposal identifier."),
            ),
            305 => definition(
                "ALREADY_EXECUTED",
                ErrorCategory::Conflict,
                false,
                "This treasury proposal has already been executed.",
                Some("Review treasury ledger audit history."),
            ),
            _ => return None,
        }),
        ErrorDomain::Governance => Some(match code {
            400 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "Caller is not authorized to create or vote on governance proposals.",
                Some("Ensure voting keys are registered and hold governance power."),
            ),
            401 => definition(
                "PROPOSAL_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested governance proposal does not exist.",
                Some("Check proposal ID and query proposal index."),
            ),
            402 => definition(
                "ALREADY_VOTED",
                ErrorCategory::Conflict,
                false,
                "Caller has already cast a vote for this proposal.",
                Some("Votes are immutable once recorded."),
            ),
            403 => definition(
                "BELOW_THRESHOLD",
                ErrorCategory::Settlement,
                true,
                "Proposal has not yet met the required approval quorum.",
                Some("Await additional voter participation."),
            ),
            404 => definition(
                "PROPOSAL_EXPIRED",
                ErrorCategory::Conflict,
                false,
                "The voting window for this proposal has expired.",
                Some("Submit a new governance proposal if needed."),
            ),
            405 => definition(
                "PROPOSAL_CANCELLED",
                ErrorCategory::Conflict,
                false,
                "This proposal was cancelled by its author or admin.",
                Some("Review governance forum notes."),
            ),
            _ => return None,
        }),
        ErrorDomain::Referral => Some(match code {
            600 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "Caller is not authorized to register or configure referral tiers.",
                Some("Authenticate with referral manager credentials."),
            ),
            601 => definition(
                "REFERRAL_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "Referral code or affiliate record was not found.",
                Some("Verify referral code spelling and status."),
            ),
            602 => definition(
                "REFERRER_ALREADY_SET",
                ErrorCategory::Conflict,
                false,
                "This account has already bound a referrer.",
                Some("Affiliate bindings are single-assignment and permanent."),
            ),
            603 => definition(
                "INVALID_TIER",
                ErrorCategory::Validation,
                false,
                "Referral tier configuration is invalid.",
                Some("Review commission basis-points and threshold ranges."),
            ),
            _ => return None,
        }),
        ErrorDomain::Registry => Some(match code {
            1100 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "Caller is not authorized to modify the contract registry.",
                Some("Authenticate with registry owner or admin account."),
            ),
            1101 => definition(
                "CONTRACT_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The requested contract name or service key is not registered.",
                Some("Check service registration directory."),
            ),
            1102 => definition(
                "CONTRACT_ALREADY_REGISTERED",
                ErrorCategory::Conflict,
                false,
                "A contract with this name is already active in the registry.",
                Some("Update the existing entry or use a unique service identifier."),
            ),
            _ => return None,
        }),
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
            949 => definition(
                "INVALID_RECIPIENT",
                ErrorCategory::Validation,
                false,
                "A recipient in this import is not valid.",
                Some("Correct the recipient in the source row and resubmit the import."),
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
            928 => definition(
                "EXPORT_CANCELLED",
                ErrorCategory::Conflict,
                false,
                "This export was cancelled by an operator.",
                Some("Start a new export if the data is still needed."),
            ),
            929 => definition(
                "EXPORT_FORBIDDEN_FIELD",
                ErrorCategory::Validation,
                false,
                "The export includes a field that cannot be shared.",
                Some("Remove restricted fields from the request and export again."),
            ),
            930 => definition(
                "EXPORT_SESSION_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The export session does not exist or has ended.",
                Some("Start a new export session."),
            ),
            931 => definition(
                "EXPORT_CHUNK_TOO_LARGE",
                ErrorCategory::Validation,
                false,
                "This chunk is larger than the allowed size.",
                Some("Send smaller chunks and retry."),
            ),
            932 => definition(
                "EXPORT_SESSION_INACTIVE",
                ErrorCategory::Conflict,
                false,
                "The export session is no longer active.",
                Some("Start a new export session."),
            ),
            933 => definition(
                "EXPORT_CURSOR_MISMATCH",
                ErrorCategory::Conflict,
                false,
                "The chunk does not follow the expected export position.",
                Some("Resume from the last confirmed cursor."),
            ),
            934 => definition(
                "UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to export data from this module.",
                Some("Use an account with export access to this module."),
            ),
            _ => return None,
        }),
        ErrorDomain::SupportAccess => Some(match code {
            960 => definition(
                "SUPPORT_SESSION_NOT_FOUND",
                ErrorCategory::NotFound,
                false,
                "The support-access session is not active.",
                Some("Refresh the session state or request a new authorized session."),
            ),
            961 => definition(
                "SUPPORT_ACCESS_UNAUTHORIZED",
                ErrorCategory::Authorization,
                false,
                "You are not authorized to open or use support access.",
                Some("Contact an administrator to request the Support role."),
            ),
            962 | 970 => definition(
                "SUPPORT_SCOPE_INVALID",
                ErrorCategory::Validation,
                false,
                "The support-access scope or duration is invalid.",
                Some("Choose an explicit resource scope and a positive duration."),
            ),
            963 => definition(
                "SUPPORT_DURATION_TOO_LONG",
                ErrorCategory::Validation,
                false,
                "The support-access duration exceeds the allowed maximum.",
                Some("Choose a duration of one hour or less."),
            ),
            964 => definition(
                "SUPPORT_SESSION_EXPIRED",
                ErrorCategory::Conflict,
                false,
                "The support-access session has expired.",
                Some("Request a new authorized session if support access is still needed."),
            ),
            965 | 966 => definition(
                "SUPPORT_ACTION_NOT_PERMITTED",
                ErrorCategory::Authorization,
                false,
                "This action is outside the support-access scope.",
                Some("Use an authorized session with the minimum required scope."),
            ),
            967 | 969 => definition(
                "SUPPORT_SESSION_LIMIT",
                ErrorCategory::Conflict,
                false,
                "The support-access session limit has been reached.",
                Some("Revoke or allow an existing session to expire before retrying."),
            ),
            968 => definition(
                "SUPPORT_TARGET_NOT_ALLOWED",
                ErrorCategory::Authorization,
                false,
                "This account cannot be accessed through support impersonation.",
                Some("Use an eligible end-user account."),
            ),
            971 => definition(
                "SUPPORT_AUDIT_UNAVAILABLE",
                ErrorCategory::Internal,
                false,
                "Support access could not be recorded safely.",
                Some("Stop the operation and have an operator verify the audit ledger."),
            ),
            972 => definition(
                "SUPPORT_SESSION_ID_EXHAUSTED",
                ErrorCategory::Internal,
                false,
                "A support session could not be created safely.",
                Some("Stop support access changes and contact an operator."),
            ),
            973 => definition(
                "SUPPORT_TIMESTAMP_OVERFLOW",
                ErrorCategory::Internal,
                false,
                "A support session could not be created safely.",
                Some("Stop support access changes and contact an operator."),
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
            (ErrorDomain::Aid, 100, 117),
            (ErrorDomain::AccessControl, 200, 223),
            (ErrorDomain::Oracle, 500, 511),
            (ErrorDomain::Upgradeability, 900, 915),
            (ErrorDomain::Import, 940, 949),
            (ErrorDomain::Export, 920, 934),
            (ErrorDomain::Marketplace, 2000, 2023),
            (ErrorDomain::SupportAccess, 960, 973),
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
            // Aid `Unauthorized`; the aid contract is not a dependency of `shared`.
            (ErrorDomain::Aid, 100),
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
            (ErrorDomain::Aid, 100, 117),
            (ErrorDomain::AccessControl, 200, 223),
            (ErrorDomain::Oracle, 500, 511),
            (ErrorDomain::Upgradeability, 900, 915),
            (ErrorDomain::Export, 920, 934),
            (ErrorDomain::Import, 940, 949),
            (ErrorDomain::Marketplace, 2000, 2023),
            (ErrorDomain::SupportAccess, 960, 973),
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

    #[test]
    fn newly_explained_rejections_keep_category_and_retry_policy() {
        let env = Env::default();

        let milestone = describe_error(&env, ErrorDomain::Aid, 116, correlation_id(&env));
        assert_eq!(
            milestone.code,
            String::from_str(&env, "MILESTONE_NOT_VERIFIED")
        );
        assert_eq!(milestone.category, ErrorCategory::Settlement);
        assert!(milestone.retryable);

        let transfer = describe_error(&env, ErrorDomain::AccessControl, 220, correlation_id(&env));
        assert_eq!(transfer.category, ErrorCategory::Authorization);
        assert!(!transfer.retryable);

        let timelock = describe_error(&env, ErrorDomain::Upgradeability, 915, correlation_id(&env));
        assert_eq!(timelock.category, ErrorCategory::Conflict);
        assert!(timelock.retryable);

        let cancelled = describe_error(&env, ErrorDomain::Export, 928, correlation_id(&env));
        assert_eq!(cancelled.code, String::from_str(&env, "EXPORT_CANCELLED"));
        assert!(!cancelled.retryable);

        let dutch = describe_error(&env, ErrorDomain::Marketplace, 2017, correlation_id(&env));
        assert_eq!(dutch.code, String::from_str(&env, "INVALID_DUTCH_PRICES"));
        assert_eq!(dutch.category, ErrorCategory::Validation);

        // Verify Issue #329 domains: Payments, Treasury, Governance, Referral, Registry
        let pay_err = describe_error(&env, ErrorDomain::Payments, 700, correlation_id(&env));
        assert_eq!(pay_err.code, String::from_str(&env, "INVALID_AMOUNT"));
        assert_eq!(pay_err.category, ErrorCategory::Validation);
        assert!(!pay_err.retryable);

        let pay_retry = describe_error(&env, ErrorDomain::Payments, 701, correlation_id(&env));
        assert_eq!(pay_retry.code, String::from_str(&env, "INSUFFICIENT_BALANCE"));
        assert_eq!(pay_retry.category, ErrorCategory::Settlement);
        assert!(pay_retry.retryable);

        let treas_err = describe_error(&env, ErrorDomain::Treasury, 300, correlation_id(&env));
        assert_eq!(treas_err.code, String::from_str(&env, "UNAUTHORIZED"));
        assert_eq!(treas_err.category, ErrorCategory::Authorization);
        assert!(!treas_err.retryable);

        let gov_err = describe_error(&env, ErrorDomain::Governance, 401, correlation_id(&env));
        assert_eq!(gov_err.code, String::from_str(&env, "PROPOSAL_NOT_FOUND"));
        assert_eq!(gov_err.category, ErrorCategory::NotFound);

        let ref_err = describe_error(&env, ErrorDomain::Referral, 603, correlation_id(&env));
        assert_eq!(ref_err.code, String::from_str(&env, "INVALID_TIER"));
        assert_eq!(ref_err.category, ErrorCategory::Validation);

        let reg_err = describe_error(&env, ErrorDomain::Registry, 1101, correlation_id(&env));
        assert_eq!(reg_err.code, String::from_str(&env, "CONTRACT_NOT_FOUND"));
        assert_eq!(reg_err.category, ErrorCategory::NotFound);
    }
}
