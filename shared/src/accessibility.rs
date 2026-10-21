//! Accessibility Coverage for Keyboard, Focus, and Async Status States (Issue #296).
//!
//! Provides deterministic mappings between contract operational states and
//! WCAG 2.1 AA accessible UI attributes, focus trap configurations, keyboard
//! navigation roving tabindex states, and screen reader ARIA live region announcements.
//! Includes regression coverage for dense forms, tables, and error recovery flows.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Env, Symbol,
};

use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 960–969)
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccessibilityError {
    /// Invalid focus trap configuration (e.g. missing return focus target).
    InvalidFocusTrap = 960,
    /// Invalid state transition for async operation status.
    InvalidStateTransition = 961,
    /// Caller unauthorized to set accessibility audit state.
    Unauthorized = 962,
    /// Dense form/table layout missing required accessibility attributes.
    InvalidDenseLayout = 963,
}

impl From<AccessibilityError> for Error {
    fn from(err: AccessibilityError) -> Self {
        match err {
            AccessibilityError::InvalidFocusTrap => Error::InvalidArgument,
            AccessibilityError::InvalidStateTransition => Error::InvalidArgument,
            AccessibilityError::Unauthorized => Error::Unauthorized,
            AccessibilityError::InvalidDenseLayout => Error::InvalidArgument,
        }
    }
}

// ---------------------------------------------------------------------------
// Accessibility Models & Taxonomy
// ---------------------------------------------------------------------------

/// Asynchronous transaction lifecycle states for wallet and contract operations.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AsyncStatusState {
    Idle = 0,
    Validating = 1,
    AwaitingSignature = 2,
    Broadcasting = 3,
    Succeeded = 4,
    RecoverableError = 5,
    FatalError = 6,
}

impl AsyncStatusState {
    pub fn as_symbol(&self) -> Symbol {
        match self {
            AsyncStatusState::Idle => symbol_short!("idle"),
            AsyncStatusState::Validating => symbol_short!("validate"),
            AsyncStatusState::AwaitingSignature => symbol_short!("await_sig"),
            AsyncStatusState::Broadcasting => symbol_short!("broadcast"),
            AsyncStatusState::Succeeded => symbol_short!("tx_ok"),
            AsyncStatusState::RecoverableError => symbol_short!("tx_retry"),
            AsyncStatusState::FatalError => symbol_short!("tx_failed"),
        }
    }

    /// Whether this state represents an in-flight operation (`aria-busy="true"`).
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            AsyncStatusState::Validating
                | AsyncStatusState::AwaitingSignature
                | AsyncStatusState::Broadcasting
        )
    }

    /// Whether this state is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            AsyncStatusState::Succeeded | AsyncStatusState::FatalError
        )
    }

    /// Whether this state allows the user to recover (retry) the operation.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            AsyncStatusState::RecoverableError
                | AsyncStatusState::AwaitingSignature
                | AsyncStatusState::Idle
        )
    }
}

/// ARIA live region announcement priority mode.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AriaLiveMode {
    Off = 0,
    Polite = 1,
    Assertive = 2,
}

/// Semantic ARIA role for assistive technology.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AriaRole {
    Status = 1,
    Alert = 2,
    Progressbar = 3,
    Region = 4,
}

/// Keyboard navigation paradigm.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum KeyboardNavMode {
    LinearTab = 1,
    RovingTabindex = 2,
    ModalTrap = 3,
}

/// Modal focus trap specification for high-impact actions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusTrapConfig {
    pub trap_active: bool,
    pub initial_focus: Symbol,
    pub return_focus: Symbol,
    pub dismissable: bool,
}

/// Consolidated accessibility metadata payload returned to client dApps and indexers.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessibilityMetadata {
    pub state: AsyncStatusState,
    pub aria_live: AriaLiveMode,
    pub aria_busy: bool,
    pub role: AriaRole,
    pub focus_trap: FocusTrapConfig,
    pub keyboard_mode: KeyboardNavMode,
}

/// Accessibility metadata for dense form and table layouts.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenseLayoutConfig {
    /// Whether every form control has an associated accessible label.
    pub labeled_controls: bool,
    /// Whether table headers are programmatically associated with cells.
    pub table_headers_associated: bool,
    /// Whether error messages are announced via live regions.
    pub errors_announced: bool,
    /// Whether the layout respects `prefers-reduced-motion`.
    pub reduced_motion: bool,
    /// Roving tabindex group identifier for composite widgets.
    pub roving_group: Symbol,
}

/// Error recovery flow accessibility metadata.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorRecoveryConfig {
    /// Live region mode used to announce the error.
    pub announce_mode: AriaLiveMode,
    /// Keyboard mode for the recovery action group.
    pub keyboard_mode: KeyboardNavMode,
    /// Focus target that receives focus when the error is announced.
    pub focus_target: Symbol,
    /// Whether the recovery flow is dismissable (escape key).
    pub dismissable: bool,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

const KEY_LAST_A11Y_STATE: Symbol = symbol_short!("last_a11y");
const KEY_LAST_DENSE_LAYOUT: Symbol = symbol_short!("last_dense");
const KEY_LAST_RECOVERY: Symbol = symbol_short!("last_recov");

// ---------------------------------------------------------------------------
// Core Accessibility Functions
// ---------------------------------------------------------------------------

/// Maps any contract asynchronous status state to standardized WCAG 2.1 AA attributes.
pub fn map_state_to_accessibility(
    state: AsyncStatusState,
    return_focus: Symbol,
) -> AccessibilityMetadata {
    let aria_live = match state {
        AsyncStatusState::Idle => AriaLiveMode::Off,
        AsyncStatusState::Validating => AriaLiveMode::Polite,
        AsyncStatusState::AwaitingSignature => AriaLiveMode::Polite,
        AsyncStatusState::Broadcasting => AriaLiveMode::Polite,
        AsyncStatusState::Succeeded => AriaLiveMode::Polite,
        AsyncStatusState::RecoverableError => AriaLiveMode::Assertive,
        AsyncStatusState::FatalError => AriaLiveMode::Assertive,
    };

    let role = match state {
        AsyncStatusState::Idle => AriaRole::Region,
        AsyncStatusState::Validating => AriaRole::Progressbar,
        AsyncStatusState::AwaitingSignature => AriaRole::Status,
        AsyncStatusState::Broadcasting => AriaRole::Progressbar,
        AsyncStatusState::Succeeded => AriaRole::Status,
        AsyncStatusState::RecoverableError => AriaRole::Alert,
        AsyncStatusState::FatalError => AriaRole::Alert,
    };

    let aria_busy = state.is_busy();

    let is_modal = matches!(
        state,
        AsyncStatusState::AwaitingSignature
            | AsyncStatusState::RecoverableError
            | AsyncStatusState::FatalError
    );

    let focus_trap = FocusTrapConfig {
        trap_active: is_modal,
        initial_focus: if is_modal {
            symbol_short!("modal_btn")
        } else {
            symbol_short!("main")
        },
        return_focus,
        dismissable: state != AsyncStatusState::Broadcasting,
    };

    let keyboard_mode = if is_modal {
        KeyboardNavMode::ModalTrap
    } else {
        KeyboardNavMode::LinearTab
    };

    AccessibilityMetadata {
        state,
        aria_live,
        aria_busy,
        role,
        focus_trap,
        keyboard_mode,
    }
}

/// Validates that a focus trap has valid initial and return focus identifiers.
pub fn validate_focus_trap_config(config: &FocusTrapConfig) -> Result<(), AccessibilityError> {
    if config.trap_active {
        if config.initial_focus == symbol_short!("") || config.return_focus == symbol_short!("") {
            return Err(AccessibilityError::InvalidFocusTrap);
        }
    }
    Ok(())
}

/// Validates accessibility attributes required for dense forms and tables.
pub fn validate_dense_layout(config: &DenseLayoutConfig) -> Result<(), AccessibilityError> {
    if !config.labeled_controls
        || !config.table_headers_associated
        || !config.errors_announced
        || !config.reduced_motion
    {
        return Err(AccessibilityError::InvalidDenseLayout);
    }
    if config.roving_group == symbol_short!("") {
        return Err(AccessibilityError::InvalidDenseLayout);
    }
    Ok(())
}

/// Maps an async state to the accessibility attributes of its error recovery flow.
pub fn map_error_recovery(
    state: AsyncStatusState,
    return_focus: Symbol,
) -> ErrorRecoveryConfig {
    let announce_mode = match state {
        AsyncStatusState::RecoverableError => AriaLiveMode::Assertive,
        AsyncStatusState::FatalError => AriaLiveMode::Assertive,
        _ => AriaLiveMode::Polite,
    };

    let keyboard_mode = if state.is_recoverable() {
        KeyboardNavMode::RovingTabindex
    } else {
        KeyboardNavMode::LinearTab
    };

    let focus_target = if state.is_recoverable() {
        symbol_short!("retry_btn")
    } else {
        return_focus
    };

    ErrorRecoveryConfig {
        announce_mode,
        keyboard_mode,
        focus_target,
        dismissable: state != AsyncStatusState::Broadcasting,
    }
}

/// Records accessibility metadata for a dense form/table layout audit.
pub fn record_dense_layout(
    env: &Env,
    caller: &Address,
    config: &DenseLayoutConfig,
) -> Result<(), Error> {
    caller.require_auth();
    validate_dense_layout(config)?;
    persistent_set(env, &KEY_LAST_DENSE_LAYOUT, config);
    env.events().publish(
        (symbol_short!("a11y_dns"), config.roving_group.clone()),
        (caller.clone(), env.ledger().timestamp()),
    );
    Ok(())
}

/// Retrieves the last recorded dense layout accessibility configuration.
pub fn get_last_dense_layout(env: &Env) -> Option<DenseLayoutConfig> {
    persistent_get(env, &KEY_LAST_DENSE_LAYOUT)
}

/// Records accessibility metadata for an audited transaction lifecycle step.
pub fn record_accessibility_state(
    env: &Env,
    caller: &Address,
    metadata: &AccessibilityMetadata,
) -> Result<(), Error> {
    caller.require_auth();

    validate_focus_trap_config(&metadata.focus_trap)?;

    persistent_set(env, &KEY_LAST_A11Y_STATE, metadata);

    env.events().publish(
        (symbol_short!("a11y_upd"), metadata.state.as_symbol()),
        (
            caller.clone(),
            metadata.aria_busy,
            env.ledger().timestamp(),
        ),
    );

    Ok(())
}

/// Retrieves the last recorded accessibility state from storage.
pub fn get_last_accessibility_state(env: &Env) -> Option<AccessibilityMetadata> {
    persistent_get(env, &KEY_LAST_A11Y_STATE)
}

/// Records accessibility metadata for an error recovery flow audit.
pub fn record_error_recovery(
    env: &Env,
    caller: &Address,
    config: &ErrorRecoveryConfig,
) -> Result<(), Error> {
    caller.require_auth();
    if config.focus_target == symbol_short!("") {
        return Err(AccessibilityError::InvalidFocusTrap.into());
    }
    persistent_set(env, &KEY_LAST_RECOVERY, config);
    env.events().publish(
        (symbol_short!("a11y_rec"), config.focus_target.clone()),
        (caller.clone(), env.ledger().timestamp()),
    );
    Ok(())
}

/// Retrieves the last recorded error recovery accessibility configuration.
pub fn get_last_error_recovery(env: &Env) -> Option<ErrorRecoveryConfig> {
    persistent_get(env, &KEY_LAST_RECOVERY)
}
