use soroban_sdk::contracterror;

/// Machine-readable problem-details taxonomy shared by every contract.
///
/// See `docs/errors.md` for the stable code registry and remediation hints.
/// Stable error codes shared by every contract in the workspace.
///
/// Codes from 900 to 999 are reserved for errors whose meaning is shared
/// consistently across multiple contract modules.
#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Caller is not authorised to perform this action.
    Unauthorized = 1,
    /// The requested item was not found in storage.
    NotFound = 2,
    /// The supplied monetary amount is invalid.
    InvalidAmount = 3,
    /// An arithmetic operation would overflow.
    Overflow = 4,
    /// The operation is not permitted while the contract is paused.
    ContractPaused = 5,
    /// The claim link has expired.
    Expired = 6,
    /// The claim has already been used.
    AlreadyClaimed = 7,
    /// Insufficient treasury balance.
    InsufficientBalance = 8,
    /// Requested withdrawal exceeds the configured per-transaction limit.
    WithdrawalLimitExceeded = 9,
    /// A supplied argument is structurally invalid (wrong range, zero amount, etc.).
    InvalidArgument = 10,
    /// The operation requires the contract to be paused but it is currently active.
    NotPaused = 11,
    /// The requested pause scope is not recognised by this contract.
    InvalidPauseScope = 29,
    /// The requested operation is not covered by any registered pause scope.
    UnknownOperation = 30,
    /// The pause scope is already in the requested state.
    PauseScopeUnchanged = 31,
    /// The requested operation is currently paused by the circuit breaker.
    OperationPaused = 32,
    /// The record is not eligible for deactivation.
    RecordNotEligibleForDeactivation = 33,
    /// The record is already active.
    RecordAlreadyActive = 34,
    /// The record is already deactivated.
    RecordAlreadyDeactivated = 35,
    /// The record is deactivated and cannot perform restricted operations.
    RecordDeactivated = 36,
    /// No pending ownership transfer exists.
    NoPendingTransfer = 37,
    /// The pending ownership transfer has expired.
    TransferExpired = 38,
    /// Caller is not the designated pending owner.
    NotPendingOwner = 39,
    /// An ownership transfer is already pending.
    TransferAlreadyPending = 40,
    /// An external dependency is degraded or unavailable and safe fallback behavior was triggered or required.
    DependencyDegraded = 41,
    /// The proposal was not found.
    ProposalNotFound = 12,
    /// The caller has already approved this proposal.
    AlreadyApproved = 13,
    /// The proposal has not reached the approval threshold.
    BelowThreshold = 14,
    /// The proposal has already been executed.
    AlreadyExecuted = 15,
    /// The governance proposal passed its execution window.
    ProposalExpired = 26,
    /// The governance proposal was cancelled by its proposer or super-admin.
    ProposalCancelled = 27,
    /// Price data is older than the configured freshness window.
    StaleData = 28,
    /// Attempted to modify an entry that has been marked immutable.
    ImmutableEntry = 16,
    /// The supplied metadata hash is invalid (wrong length or format).
    InvalidHash = 17,
    /// No metadata entry exists for the given identifier.
    MetadataNotFound = 18,
    /// The contract or component was already initialized.
    AlreadyInitialized = 19,
    /// The record uses a schema version this contract does not support.
    UnsupportedSchemaVersion = 20,
    /// A schema migration was attempted but failed validation.
    SchemaMigrationFailed = 21,
    /// The actor has exceeded its quota for this resource/operation.
    QuotaExceeded = 22,
    /// A required configuration value is missing.
    ConfigMissing = 23,
    /// A configuration value is present but malformed or out of range.
    ConfigInvalid = 24,
    /// A secret is unsafe (placeholder, too short, or production-like in local mode).
    UnsafeSecret = 25,

    // ── Upgradeability errors (900–920) ──────────────────────────────────
    /// The target contract is not registered in the upgrade registry.
    ContractNotRegistered = 900,
    /// A contract with the given name is already registered.
    ContractAlreadyRegistered = 901,
    /// The proposed WASM hash matches the current one (no-op upgrade).
    NoChangeDetected = 902,
    /// The upgrade proposal was not found.
    UpgradeProposalNotFound = 903,
    /// The upgrade proposal has already been executed.
    UpgradeAlreadyExecuted = 904,
    /// The migration hook contract call failed.
    MigrationHookFailed = 905,
    /// The contract is already pending an upgrade.
    UpgradeAlreadyPending = 906,
    /// The caller does not hold the Upgrader role.
    NotUpgrader = 907,
    /// The WASM hash is empty or invalid.
    InvalidWasmHash = 908,
    /// Storage layout incompatibility detected during migration.
    StorageIncompatible = 909,
    /// The migration hook address is not a valid contract.
    InvalidMigrationHook = 910,

    // ── Payment errors (700–720) ──────────────────────────────────────
    /// The payment amount is not strictly positive.
    PaymentInvalidAmount = 700,
    /// The sender has insufficient token balance for this transfer.
    PaymentInsufficientBalance = 701,
    /// The escrow deposit does not exist or has already been released.
    PaymentEscrowNotFound = 702,
    /// The escrow deposit has already been released to the beneficiary.
    PaymentEscrowAlreadyReleased = 703,
    /// The escrow deposit has already been refunded to the depositor.
    PaymentEscrowAlreadyRefunded = 704,
    /// The caller is not authorised to release or refund this escrow.
    PaymentEscrowUnauthorized = 705,
    /// The escrow deposit has expired and cannot be released.
    PaymentEscrowExpired = 706,
    /// The escrow deposit has not yet expired and cannot be refunded.
    PaymentEscrowNotExpired = 707,
    /// The fee basis-point rate is out of the valid 0–10 000 range.
    PaymentInvalidFeeRate = 708,
    /// The fee calculation resulted in an arithmetic overflow.
    PaymentFeeOverflow = 709,
    /// The escrow ID counter has overflowed.
    PaymentEscrowIdOverflow = 710,
    /// The token is not supported by this payment gateway.
    PaymentTokenNotSupported = 711,

    // ── NFT Marketplace errors (1000–1008) ──────────────────────────────
    /// The NFT listing was not found.
    ListingNotFound = 1000,
    /// The NFT listing has already been sold or cancelled.
    ListingAlreadySold = 1001,
    /// The caller is not the owner of this NFT.
    NotOwner = 1002,
    /// The collection is already registered.
    CollectionAlreadyRegistered = 1003,
    /// The collection was not found.
    CollectionNotFound = 1004,
    /// The currency address is not whitelisted.
    CurrencyNotWhitelisted = 1005,
    /// The metadata hash is invalid (wrong length).
    InvalidMetadataHash = 1006,
    /// The royalty basis-point rate is out of range.
    InvalidRoyaltyRate = 1007,
    /// The auto-extension window is invalid.
    InvalidExtensionWindow = 1008,
    /// Illegal state transition.
    InvalidTransition = 950,
    /// Aid not yet expired.
    AidNotExpiredYet = 951,
    /// Aid already refunded.
    AidAlreadyRefunded = 952,
    /// A scheduled action was attempted before its valid time window opened.
    ActionTooEarly = 953,
    /// A scheduled action was attempted after its valid time window closed.
    ActionExpired = 954,
}

/// Stable, machine-readable problem code for an [`Error`].
///
/// The string form is part of the public API: it must not change once
/// released, and is what clients should switch on instead of the numeric
/// discriminant. Numeric discriminants remain stable for on-chain use.
pub fn problem_code(error: Error) -> &'static str {
    match error {
        Error::Unauthorized => "TRELLIS_UNAUTHORIZED",
        Error::NotFound => "TRELLIS_NOT_FOUND",
        Error::InvalidAmount => "TRELLIS_INVALID_AMOUNT",
        Error::Overflow => "TRELLIS_OVERFLOW",
        Error::ContractPaused => "TRELLIS_CONTRACT_PAUSED",
        Error::Expired => "TRELLIS_EXPIRED",
        Error::AlreadyClaimed => "TRELLIS_ALREADY_CLAIMED",
        Error::InsufficientBalance => "TRELLIS_INSUFFICIENT_BALANCE",
        Error::WithdrawalLimitExceeded => "TRELLIS_WITHDRAWAL_LIMIT_EXCEEDED",
        Error::InvalidArgument => "TRELLIS_INVALID_ARGUMENT",
        Error::NotPaused => "TRELLIS_NOT_PAUSED",
        Error::InvalidPauseScope => "TRELLIS_INVALID_PAUSE_SCOPE",
        Error::UnknownOperation => "TRELLIS_UNKNOWN_OPERATION",
        Error::PauseScopeUnchanged => "TRELLIS_PAUSE_SCOPE_UNCHANGED",
        Error::OperationPaused => "TRELLIS_OPERATION_PAUSED",
        Error::RecordNotEligibleForDeactivation => "TRELLIS_RECORD_NOT_ELIGIBLE_FOR_DEACTIVATION",
        Error::RecordAlreadyActive => "TRELLIS_RECORD_ALREADY_ACTIVE",
        Error::RecordAlreadyDeactivated => "TRELLIS_RECORD_ALREADY_DEACTIVATED",
        Error::RecordDeactivated => "TRELLIS_RECORD_DEACTIVATED",
        Error::NoPendingTransfer => "TRELLIS_NO_PENDING_TRANSFER",
        Error::TransferExpired => "TRELLIS_TRANSFER_EXPIRED",
        Error::NotPendingOwner => "TRELLIS_NOT_PENDING_OWNER",
        Error::TransferAlreadyPending => "TRELLIS_TRANSFER_ALREADY_PENDING",
        Error::DependencyDegraded => "TRELLIS_DEPENDENCY_DEGRADED",
        Error::ProposalNotFound => "TRELLIS_PROPOSAL_NOT_FOUND",
        Error::AlreadyApproved => "TRELLIS_ALREADY_APPROVED",
        Error::BelowThreshold => "TRELLIS_BELOW_THRESHOLD",
        Error::AlreadyExecuted => "TRELLIS_ALREADY_EXECUTED",
        Error::ProposalExpired => "TRELLIS_PROPOSAL_EXPIRED",
        Error::ProposalCancelled => "TRELLIS_PROPOSAL_CANCELLED",
        Error::StaleData => "TRELLIS_STALE_DATA",
        Error::ImmutableEntry => "TRELLIS_IMMUTABLE_ENTRY",
        Error::InvalidHash => "TRELLIS_INVALID_HASH",
        Error::MetadataNotFound => "TRELLIS_METADATA_NOT_FOUND",
        Error::AlreadyInitialized => "TRELLIS_ALREADY_INITIALIZED",
        Error::UnsupportedSchemaVersion => "TRELLIS_UNSUPPORTED_SCHEMA_VERSION",
        Error::SchemaMigrationFailed => "TRELLIS_SCHEMA_MIGRATION_FAILED",
        Error::QuotaExceeded => "TRELLIS_QUOTA_EXCEEDED",
        Error::ConfigMissing => "TRELLIS_CONFIG_MISSING",
        Error::ConfigInvalid => "TRELLIS_CONFIG_INVALID",
        Error::UnsafeSecret => "TRELLIS_UNSAFE_SECRET",
        Error::ContractNotRegistered => "TRELLIS_CONTRACT_NOT_REGISTERED",
        Error::ContractAlreadyRegistered => "TRELLIS_CONTRACT_ALREADY_REGISTERED",
        Error::NoChangeDetected => "TRELLIS_NO_CHANGE_DETECTED",
        Error::UpgradeProposalNotFound => "TRELLIS_UPGRADE_PROPOSAL_NOT_FOUND",
        Error::UpgradeAlreadyExecuted => "TRELLIS_UPGRADE_ALREADY_EXECUTED",
        Error::MigrationHookFailed => "TRELLIS_MIGRATION_HOOK_FAILED",
        Error::UpgradeAlreadyPending => "TRELLIS_UPGRADE_ALREADY_PENDING",
        Error::NotUpgrader => "TRELLIS_NOT_UPGRADER",
        Error::InvalidWasmHash => "TRELLIS_INVALID_WASM_HASH",
        Error::StorageIncompatible => "TRELLIS_STORAGE_INCOMPATIBLE",
        Error::InvalidMigrationHook => "TRELLIS_INVALID_MIGRATION_HOOK",
        Error::PaymentInvalidAmount => "TRELLIS_PAYMENT_INVALID_AMOUNT",
        Error::PaymentInsufficientBalance => "TRELLIS_PAYMENT_INSUFFICIENT_BALANCE",
        Error::PaymentEscrowNotFound => "TRELLIS_PAYMENT_ESCROW_NOT_FOUND",
        Error::PaymentEscrowAlreadyReleased => "TRELLIS_PAYMENT_ESCROW_ALREADY_RELEASED",
        Error::PaymentEscrowAlreadyRefunded => "TRELLIS_PAYMENT_ESCROW_ALREADY_REFUNDED",
        Error::PaymentEscrowUnauthorized => "TRELLIS_PAYMENT_ESCROW_UNAUTHORIZED",
        Error::PaymentEscrowExpired => "TRELLIS_PAYMENT_ESCROW_EXPIRED",
        Error::PaymentEscrowNotExpired => "TRELLIS_PAYMENT_ESCROW_NOT_EXPIRED",
        Error::PaymentInvalidFeeRate => "TRELLIS_PAYMENT_INVALID_FEE_RATE",
        Error::PaymentFeeOverflow => "TRELLIS_PAYMENT_FEE_OVERFLOW",
        Error::PaymentEscrowIdOverflow => "TRELLIS_PAYMENT_ESCROW_ID_OVERFLOW",
        Error::PaymentTokenNotSupported => "TRELLIS_PAYMENT_TOKEN_NOT_SUPPORTED",
        Error::ListingNotFound => "TRELLIS_LISTING_NOT_FOUND",
        Error::ListingAlreadySold => "TRELLIS_LISTING_ALREADY_SOLD",
        Error::NotOwner => "TRELLIS_NOT_OWNER",
        Error::CollectionAlreadyRegistered => "TRELLIS_COLLECTION_ALREADY_REGISTERED",
        Error::CollectionNotFound => "TRELLIS_COLLECTION_NOT_FOUND",
        Error::CurrencyNotWhitelisted => "TRELLIS_CURRENCY_NOT_WHITELISTED",
        Error::InvalidMetadataHash => "TRELLIS_INVALID_METADATA_HASH",
        Error::InvalidRoyaltyRate => "TRELLIS_INVALID_ROYALTY_RATE",
        Error::InvalidExtensionWindow => "TRELLIS_INVALID_EXTENSION_WINDOW",
        Error::InvalidTransition => "TRELLIS_INVALID_TRANSITION",
        Error::AidNotExpiredYet => "TRELLIS_AID_NOT_EXPIRED_YET",
        Error::AidAlreadyRefunded => "TRELLIS_AID_ALREADY_REFUNDED",
        Error::ActionTooEarly => "TRELLIS_ACTION_TOO_EARLY",
        Error::ActionExpired => "TRELLIS_ACTION_EXPIRED",
    }
}

/// Safe, user-facing message for an [`Error`].
///
/// These messages must never leak internal state, addresses, or amounts.
pub fn user_message(error: Error) -> &'static str {
    match error {
        Error::Unauthorized => "You are not authorised to perform this action.",
        Error::NotFound => "The requested item could not be found.",
        Error::InvalidAmount => "The amount provided is not valid.",
        Error::Overflow => "The operation would exceed the allowed range.",
        Error::ContractPaused => "This action is temporarily unavailable.",
        Error::Expired => "This link has expired.",
        Error::AlreadyClaimed => "This claim has already been used.",
        Error::InsufficientBalance => "There are not enough funds for this action.",
        Error::WithdrawalLimitExceeded => "The amount exceeds the withdrawal limit.",
        Error::InvalidArgument => "One or more inputs are not valid.",
        Error::NotPaused => "This action requires the contract to be paused.",
        Error::InvalidPauseScope => "The requested pause scope is not recognised.",
        Error::UnknownOperation => "This operation is not covered by any pause scope.",
        Error::PauseScopeUnchanged => "The pause scope is already in the requested state.",
        Error::OperationPaused => "This operation is temporarily unavailable.",
        Error::RecordNotEligibleForDeactivation => "This record cannot be deactivated.",
        Error::RecordAlreadyActive => "This record is already active.",
        Error::RecordAlreadyDeactivated => "This record is already deactivated.",
        Error::RecordDeactivated => "This record is deactivated and cannot be used here.",
        Error::NoPendingTransfer => "There is no pending ownership transfer.",
        Error::TransferExpired => "The ownership transfer has expired.",
        Error::NotPendingOwner => "You are not the designated pending owner.",
        Error::TransferAlreadyPending => "An ownership transfer is already pending.",
        Error::DependencyDegraded => "A required service is temporarily unavailable.",
        Error::ProposalNotFound => "The proposal could not be found.",
        Error::AlreadyApproved => "You have already approved this proposal.",
        Error::BelowThreshold => "The proposal has not reached the approval threshold.",
        Error::AlreadyExecuted => "This proposal has already been executed.",
        Error::ProposalExpired => "The proposal execution window has passed.",
        Error::ProposalCancelled => "This proposal has been cancelled.",
        Error::StaleData => "The available data is too old to use safely.",
        Error::ImmutableEntry => "This entry cannot be modified.",
        Error::InvalidHash => "The provided hash is not valid.",
        Error::MetadataNotFound => "No metadata was found for this identifier.",
        Error::AlreadyInitialized => "This component has already been initialised.",
        Error::UnsupportedSchemaVersion => "This data uses an unsupported schema version.",
        Error::SchemaMigrationFailed => "The schema migration could not be completed.",
        Error::QuotaExceeded => "You have reached the limit for this action.",
        Error::ConfigMissing => "A required configuration value is missing.",
        Error::ConfigInvalid => "A configuration value is invalid.",
        Error::UnsafeSecret => "A configured secret is not safe to use.",
        Error::ContractNotRegistered => "The contract is not registered.",
        Error::ContractAlreadyRegistered => "The contract is already registered.",
        Error::NoChangeDetected => "The requested upgrade would not change anything.",
        Error::UpgradeProposalNotFound => "The upgrade proposal could not be found.",
        Error::UpgradeAlreadyExecuted => "This upgrade has already been executed.",
        Error::MigrationHookFailed => "The migration step could not be completed.",
        Error::UpgradeAlreadyPending => "An upgrade is already pending.",
        Error::NotUpgrader => "You do not have permission to perform upgrades.",
        Error::InvalidWasmHash => "The provided WASM hash is not valid.",
        Error::StorageIncompatible => "The stored data is not compatible with this upgrade.",
        Error::InvalidMigrationHook => "The migration hook address is not valid.",
        Error::PaymentInvalidAmount => "The payment amount must be greater than zero.",
        Error::PaymentInsufficientBalance => "The sender does not have enough funds.",
        Error::PaymentEscrowNotFound => "The escrow deposit could not be found.",
        Error::PaymentEscrowAlreadyReleased => "This escrow has already been released.",
        Error::PaymentEscrowAlreadyRefunded => "This escrow has already been refunded.",
        Error::PaymentEscrowUnauthorized => "You are not authorised to act on this escrow.",
        Error::PaymentEscrowExpired => "This escrow has expired.",
        Error::PaymentEscrowNotExpired => "This escrow has not yet expired.",
        Error::PaymentInvalidFeeRate => "The fee rate is out of range.",
        Error::PaymentFeeOverflow => "The fee calculation exceeded the allowed range.",
        Error::PaymentEscrowIdOverflow => "No further escrows can be created.",
        Error::PaymentTokenNotSupported => "This token is not supported.",
        Error::ListingNotFound => "The listing could not be found.",
        Error::ListingAlreadySold => "This listing is no longer available.",
        Error::NotOwner => "You are not the owner of this item.",
        Error::CollectionAlreadyRegistered => "This collection is already registered.",
        Error::CollectionNotFound => "The collection could not be found.",
        Error::CurrencyNotWhitelisted => "This currency is not supported.",
        Error::InvalidMetadataHash => "The metadata hash is not valid.",
        Error::InvalidRoyaltyRate => "The royalty rate is out of range.",
        Error::InvalidExtensionWindow => "The extension window is not valid.",
        Error::InvalidTransition => "This state change is not allowed.",
        Error::AidNotExpiredYet => "This aid has not yet expired.",
        Error::AidAlreadyRefunded => "This aid has already been refunded.",
        Error::ActionTooEarly => "This action cannot be performed yet.",
        Error::ActionExpired => "The time window for this action has passed.",
    }
}

/// Remediation hint for an [`Error`], describing how a caller can recover.
///
/// Hints are advisory and must not contain secrets or internal identifiers.
pub fn remediation_hint(error: Error) -> &'static str {
    match error {
        Error::Unauthorized => "Authenticate with an account that holds the required role.",
        Error::NotFound => "Verify the identifier and retry; it may have been removed.",
        Error::InvalidAmount => "Supply a positive amount within the configured bounds.",
        Error::Overflow => "Reduce the amount or split the operation into smaller parts.",
        Error::ContractPaused => "Wait for the contract to be unpaused, then retry.",
        Error::Expired => "Request a new link from the issuer.",
        Error::AlreadyClaimed => "Do not retry; the claim has already been settled.",
        Error::InsufficientBalance => "Top up the balance or reduce the requested amount.",
        Error::WithdrawalLimitExceeded => "Reduce the amount or split it across multiple withdrawals.",
        Error::InvalidArgument => "Correct the offending input and retry.",
        Error::NotPaused => "Pause the contract before performing this action.",
        Error::InvalidPauseScope => "Use a pause scope registered by this contract.",
        Error::UnknownOperation => "Register the operation under a pause scope first.",
        Error::PauseScopeUnchanged => "No action needed; the scope is already in the desired state.",
        Error::OperationPaused => "Wait for the operation to be unpaused, then retry.",
        Error::RecordNotEligibleForDeactivation => "Check the record state before retrying.",
        Error::RecordAlreadyActive => "No action needed; the record is already active.",
        Error::RecordAlreadyDeactivated => "No action needed; the record is already deactivated.",
        Error::RecordDeactivated => "Reactivate the record before performing this operation.",
        Error::NoPendingTransfer => "Initiate an ownership transfer first.",
        Error::TransferExpired => "Initiate a new ownership transfer.",
        Error::NotPendingOwner => "Accept the transfer from the designated pending owner account.",
        Error::TransferAlreadyPending => "Accept or cancel the existing transfer before starting a new one.",
        Error::DependencyDegraded => "Retry later or use the documented safe fallback path.",
        Error::ProposalNotFound => "Verify the proposal identifier and retry.",
        Error::AlreadyApproved => "No action needed; your approval is already recorded.",
        Error::BelowThreshold => "Collect additional approvals before executing.",
        Error::AlreadyExecuted => "No action needed; the proposal has already been executed.",
        Error::ProposalExpired => "Submit a new proposal.",
        Error::ProposalCancelled => "Submit a new proposal.",
        Error::StaleData => "Refresh the oracle data or wait for the next update.",
        Error::ImmutableEntry => "Create a new entry instead of modifying this one.",
        Error::InvalidHash => "Provide a hash with the expected length and format.",
        Error::MetadataNotFound => "Attach metadata before reading it.",
        Error::AlreadyInitialized => "Do not re-initialise; use the existing instance.",
        Error::UnsupportedSchemaVersion => "Migrate the data to a supported schema version.",
        Error::SchemaMigrationFailed => "Inspect the migration inputs and retry, or roll back.",
        Error::QuotaExceeded => "Wait for the quota window to reset or request an increase.",
        Error::ConfigMissing => "Set the required configuration value and retry.",
        Error::ConfigInvalid => "Correct the configuration value and retry.",
        Error::UnsafeSecret => "Replace the secret with a strong, non-placeholder value.",
        Error::ContractNotRegistered => "Register the contract before performing this action.",
        Error::ContractAlreadyRegistered => "Use the existing registration or choose a new name.",
        Error::NoChangeDetected => "No action needed; the target state matches the current state.",
        Error::UpgradeProposalNotFound => "Verify the proposal identifier and retry.",
        Error::UpgradeAlreadyExecuted => "No action needed; the upgrade has already been applied.",
        Error::MigrationHookFailed => "Inspect the migration hook and retry, or roll back.",
        Error::UpgradeAlreadyPending => "Execute or cancel the pending upgrade first.",
        Error::NotUpgrader => "Use an account holding the Upgrader role.",
        Error::InvalidWasmHash => "Provide a non-empty, valid WASM hash.",
        Error::StorageIncompatible => "Roll back and prepare a compatible migration.",
        Error::InvalidMigrationHook => "Provide the address of a valid contract.",
        Error::PaymentInvalidAmount => "Supply an amount greater than zero.",
        Error::PaymentInsufficientBalance => "Fund the sender account or reduce the amount.",
        Error::PaymentEscrowNotFound => "Verify the escrow identifier and retry.",
        Error::PaymentEscrowAlreadyReleased => "No action needed; the escrow has been released.",
        Error::PaymentEscrowAlreadyRefunded => "No action needed; the escrow has been refunded.",
        Error::PaymentEscrowUnauthorized => "Use the depositor or beneficiary account.",
        Error::PaymentEscrowExpired => "Refund the escrow instead of releasing it.",
        Error::PaymentEscrowNotExpired => "Wait until the escrow expires before refunding.",
        Error::PaymentInvalidFeeRate => "Use a fee rate between 0 and 10 000 basis points.",
        Error::PaymentFeeOverflow => "Reduce the amount to avoid overflow.",
        Error::PaymentEscrowIdOverflow => "Contact the operator to rotate the escrow namespace.",
        Error::PaymentTokenNotSupported => "Use a whitelisted token.",
        Error::ListingNotFound => "Verify the listing identifier and retry.",
        Error::ListingAlreadySold => "Choose a different listing.",
        Error::NotOwner => "Use the account that owns the item.",
        Error::CollectionAlreadyRegistered => "Use the existing collection registration.",
        Error::CollectionNotFound => "Register the collection first.",
        Error::CurrencyNotWhitelisted => "Use a whitelisted currency.",
        Error::InvalidMetadataHash => "Provide a metadata hash with the expected length.",
        Error::InvalidRoyaltyRate => "Use a royalty rate within the allowed range.",
        Error::InvalidExtensionWindow => "Provide an extension window within the allowed range.",
        Error::InvalidTransition => "Check the current state and use an allowed transition.",
        Error::AidNotExpiredYet => "Wait until the aid expires before refunding.",
        Error::AidAlreadyRefunded => "No action needed; the aid has already been refunded.",
        Error::ActionTooEarly => "Wait until the action window opens and retry.",
        Error::ActionExpired => "Restart the workflow to obtain a new action window.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::arbitrary::std::collections::HashSet;

    /// Every variant must be reachable from the taxonomy helpers.
    const ALL: &[Error] = &[
        Error::Unauthorized,
        Error::NotFound,
        Error::InvalidAmount,
        Error::Overflow,
        Error::ContractPaused,
        Error::Expired,
        Error::AlreadyClaimed,
        Error::InsufficientBalance,
        Error::WithdrawalLimitExceeded,
        Error::InvalidArgument,
        Error::NotPaused,
        Error::InvalidPauseScope,
        Error::UnknownOperation,
        Error::PauseScopeUnchanged,
        Error::OperationPaused,
        Error::RecordNotEligibleForDeactivation,
        Error::RecordAlreadyActive,
        Error::RecordAlreadyDeactivated,
        Error::RecordDeactivated,
        Error::NoPendingTransfer,
        Error::TransferExpired,
        Error::NotPendingOwner,
        Error::TransferAlreadyPending,
        Error::DependencyDegraded,
        Error::ProposalNotFound,
        Error::AlreadyApproved,
        Error::BelowThreshold,
        Error::AlreadyExecuted,
        Error::ProposalExpired,
        Error::ProposalCancelled,
        Error::StaleData,
        Error::ImmutableEntry,
        Error::InvalidHash,
        Error::MetadataNotFound,
        Error::AlreadyInitialized,
        Error::UnsupportedSchemaVersion,
        Error::SchemaMigrationFailed,
        Error::QuotaExceeded,
        Error::ConfigMissing,
        Error::ConfigInvalid,
        Error::UnsafeSecret,
        Error::ContractNotRegistered,
        Error::ContractAlreadyRegistered,
        Error::NoChangeDetected,
        Error::UpgradeProposalNotFound,
        Error::UpgradeAlreadyExecuted,
        Error::MigrationHookFailed,
        Error::UpgradeAlreadyPending,
        Error::NotUpgrader,
        Error::InvalidWasmHash,
        Error::StorageIncompatible,
        Error::InvalidMigrationHook,
        Error::PaymentInvalidAmount,
        Error::PaymentInsufficientBalance,
        Error::PaymentEscrowNotFound,
        Error::PaymentEscrowAlreadyReleased,
        Error::PaymentEscrowAlreadyRefunded,
        Error::PaymentEscrowUnauthorized,
        Error::PaymentEscrowExpired,
        Error::PaymentEscrowNotExpired,
        Error::PaymentInvalidFeeRate,
        Error::PaymentFeeOverflow,
        Error::PaymentEscrowIdOverflow,
        Error::PaymentTokenNotSupported,
        Error::ListingNotFound,
        Error::ListingAlreadySold,
        Error::NotOwner,
        Error::CollectionAlreadyRegistered,
        Error::CollectionNotFound,
        Error::CurrencyNotWhitelisted,
        Error::InvalidMetadataHash,
        Error::InvalidRoyaltyRate,
        Error::InvalidExtensionWindow,
        Error::InvalidTransition,
        Error::AidNotExpiredYet,
        Error::AidAlreadyRefunded,
        Error::ActionTooEarly,
        Error::ActionExpired,
    ];

    #[test]
    fn problem_codes_are_unique_and_stable() {
        let mut seen = HashSet::new();
        for error in ALL {
            let code = problem_code(*error);
            assert!(code.starts_with("TRELLIS_"), "code must be namespaced: {code}");
            assert!(seen.insert(code), "duplicate problem code: {code}");
        }
    }

    #[test]
    fn messages_and_hints_are_non_empty() {
        for error in ALL {
            assert!(!user_message(*error).is_empty());
            assert!(!remediation_hint(*error).is_empty());
        }
    }

    #[test]
    fn numeric_discriminants_are_stable() {
        // Guards against accidental contract drift: these values are on-chain ABI.
        assert_eq!(Error::Unauthorized as u32, 1);
        assert_eq!(Error::UnsafeSecret as u32, 25);
        assert_eq!(Error::ContractNotRegistered as u32, 900);
        assert_eq!(Error::InvalidMigrationHook as u32, 910);
        assert_eq!(Error::PaymentInvalidAmount as u32, 700);
        assert_eq!(Error::PaymentTokenNotSupported as u32, 711);
        assert_eq!(Error::ListingNotFound as u32, 1000);
        assert_eq!(Error::InvalidExtensionWindow as u32, 1008);
        assert_eq!(Error::InvalidTransition as u32, 950);
        assert_eq!(Error::ActionExpired as u32, 954);
    }
}
