//! Scoped maintainer impersonation for support debugging.
//!
//! This module allows maintainers to temporarily impersonate users for debugging
//! purposes while maintaining strict security boundaries:
//!
//! - Time-limited sessions with configurable duration
//! - Scoped permissions (read-only, specific operations, etc.)
//! - Comprehensive audit logging of all impersonation activities
//! - Automatic blocking of dangerous mutations
//! - Visible indicators when impersonation is active
//!
//! ## Security Model
//!
//! Impersonation is a privileged operation that requires:
//! - Admin or Support maintainer role
//! - Explicit session creation with defined scope
//! - Time limit enforcement (maximum 1 hour by default)
//! - Audit trail of all impersonated actions
//!
//! ## Session Lifecycle
//!
//! ```text
//! create_session() -> Active -> [time limit or revoke] -> Terminated
//!                      |                |
//!                      v                v
//!                 scoped actions    audit log
//! ```

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::audit_ledger::{append_event, genesis_hash, AuditEventKind, AuditEventParams};
use crate::auth::{has_permission, has_role, Permission, Role};
use crate::storage::{persistent_get, persistent_remove, persistent_set};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Impersonation-specific errors (range 960–979).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ImpersonationError {
    /// The impersonation session does not exist or has expired.
    SessionNotFound = 960,
    /// The caller is not authorized to impersonate users.
    Unauthorized = 961,
    /// The requested impersonation scope is invalid.
    InvalidScope = 962,
    /// The requested duration exceeds the maximum allowed.
    DurationTooLong = 963,
    /// The impersonation session has expired.
    SessionExpired = 964,
    /// The action is not permitted within the current impersonation scope.
    ActionNotPermitted = 965,
    /// Dangerous mutations require explicit confirmation.
    DangerousMutationBlocked = 966,
    /// The impersonation session is already active.
    SessionAlreadyActive = 967,
    /// The target user cannot be impersonated (e.g., another admin).
    TargetNotImpersonatable = 968,
    /// Maximum concurrent impersonation sessions exceeded.
    TooManyActiveSessions = 969,
    /// Session duration must be greater than zero.
    DurationInvalid = 970,
    /// The immutable audit event could not be appended.
    AuditFailure = 971,
    /// Session identifier space is exhausted.
    SessionIdExhausted = 972,
    /// Session expiry timestamp would overflow.
    TimestampOverflow = 973,
}

// ---------------------------------------------------------------------------
// Impersonation Scope
// ---------------------------------------------------------------------------

/// Defines what actions are permitted during an impersonation session.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpersonationScope {
    /// Read-only access to user data.
    ReadOnly,
    /// Read access plus diagnostic operations (no state changes).
    Diagnostic,
    /// Read access plus safe state changes (non-critical operations).
    SafeMutations,
    /// Full access within impersonation time limit (use with caution).
    FullAccess,
}

/// Specific resource types that can be scoped.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceType {
    /// AID (Aid) records.
    Aid,
    /// Payment records.
    Payment,
    /// Escrow records.
    Escrow,
    /// Treasury operations.
    Treasury,
    /// Role management.
    Roles,
    /// Configuration settings.
    Config,
    /// Legacy wildcard; rejected for support sessions.
    All,
}

/// Resource scope definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceScope {
    /// Type of resource.
    pub resource_type: ResourceType,
    /// Specific resource ID (None means all of that type).
    pub resource_id: Option<u64>,
}

// ---------------------------------------------------------------------------
// Impersonation Session
// ---------------------------------------------------------------------------

/// Active impersonation session.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpersonationSession {
    /// Unique session identifier.
    pub session_id: u64,
    /// Maintainer who created the session.
    pub impersonator: Address,
    /// User being impersonated.
    pub target_user: Address,
    /// Permission scope for this session.
    pub scope: ImpersonationScope,
    /// Resource scope limitations.
    pub resource_scopes: Vec<ResourceScope>,
    /// Ledger timestamp when session was created.
    pub created_at: u64,
    /// Ledger timestamp when session expires.
    pub expires_at: u64,
    /// Whether dangerous mutations are allowed.
    pub allow_dangerous_mutations: bool,
    /// Reason for impersonation (for audit).
    pub reason: Symbol,
    /// Current session state.
    pub state: SessionState,
    /// Number of actions taken during this session.
    pub action_count: u32,
}

/// Session lifecycle state.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Session is active and can be used.
    Active,
    /// Session was revoked by admin.
    Revoked,
    /// Session expired naturally.
    Expired,
    /// Session was terminated after completing its purpose.
    Completed,
}

/// Session creation parameters.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionParams {
    /// User to impersonate.
    pub target_user: Address,
    /// Permission scope.
    pub scope: ImpersonationScope,
    /// Resource scope limitations.
    pub resource_scopes: Vec<ResourceScope>,
    /// Session duration in seconds.
    pub duration_sec: u64,
    /// Whether to allow dangerous mutations.
    pub allow_dangerous_mutations: bool,
    /// Reason for impersonation.
    pub reason: Symbol,
}

/// Session result.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionResult {
    /// Created session.
    pub session: ImpersonationSession,
    /// Whether this is a new session or resumed existing one.
    pub is_new: bool,
}

/// Minimal, user-safe notice data for a target account.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportAccessNotice {
    /// Ledger timestamp at which support access expires.
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum session duration in seconds (1 hour).
pub const MAX_SESSION_DURATION: u64 = 3600;
/// Default session duration in seconds (15 minutes).
pub const DEFAULT_SESSION_DURATION: u64 = 900;
/// Maximum concurrent sessions per maintainer.
pub const MAX_CONCURRENT_SESSIONS: u32 = 5;

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ImpersonationKey {
    /// Session by session ID.
    Session(u64),
    /// Active session IDs for a target user.
    ActiveSessions(Address),
    /// Active session IDs for an impersonator.
    ImpersonatorSessions(Address),
    /// Next session ID counter.
    NextSessionId,
    /// Session counter for rate limiting.
    SessionCounter(Address),
}

// ---------------------------------------------------------------------------
// Session Management
// ---------------------------------------------------------------------------

/// Creates a new impersonation session.
///
/// # Requirements
/// - Caller must hold ImpersonateUser permission (Support role)
/// - Target user must not hold a privileged or service role
/// - Duration must not exceed MAX_SESSION_DURATION
/// - At least one explicit resource scope must be provided
///
/// # Returns
/// - SessionResult with the created session and whether it's new
pub fn create_session(
    env: &Env,
    impersonator: &Address,
    params: SessionParams,
) -> Result<SessionResult, ImpersonationError> {
    impersonator.require_auth();

    // Authorization check using permission system
    if !has_permission(env, impersonator, Permission::ImpersonateUser) {
        return Err(ImpersonationError::Unauthorized);
    }

    // Support access is only for ordinary end-user accounts.
    if !is_eligible_target(env, &params.target_user) {
        return Err(ImpersonationError::TargetNotImpersonatable);
    }

    // Validate duration
    if params.duration_sec > MAX_SESSION_DURATION {
        return Err(ImpersonationError::DurationTooLong);
    }
    if params.duration_sec == 0 {
        return Err(ImpersonationError::DurationInvalid);
    }

    // Validate scope
    if !is_valid_scope(&params.scope, &params.resource_scopes) {
        return Err(ImpersonationError::InvalidScope);
    }

    // Expired sessions must not consume the concurrent-session limit.
    let impersonator_sessions = get_impersonator_sessions(env, impersonator);
    let now = env.ledger().timestamp();
    let mut active_session_count = 0;
    for session_id in impersonator_sessions.iter() {
        if let Some(session) = get_session(env, session_id) {
            if session.state == SessionState::Active && now >= session.expires_at {
                expire_session(env, session)?;
            } else if session.state == SessionState::Active {
                active_session_count += 1;
            }
        }
    }
    if active_session_count >= MAX_CONCURRENT_SESSIONS {
        return Err(ImpersonationError::TooManyActiveSessions);
    }

    // Create session
    let session_id = next_session_id(env)?;
    let expires_at = now
        .checked_add(params.duration_sec)
        .ok_or(ImpersonationError::TimestampOverflow)?;

    let session = ImpersonationSession {
        session_id,
        impersonator: impersonator.clone(),
        target_user: params.target_user.clone(),
        scope: params.scope,
        resource_scopes: params.resource_scopes,
        created_at: now,
        expires_at,
        allow_dangerous_mutations: params.allow_dangerous_mutations,
        reason: params.reason.clone(),
        state: SessionState::Active,
        action_count: 0,
    };

    append_support_audit(
        env,
        impersonator,
        &params.target_user,
        session_id,
        symbol_short!("supp_crt"),
        Some(params.scope.as_symbol()),
        Some(i128::from(expires_at)),
        Some(params.reason.clone()),
    )?;

    // Store session only after the required audit entry is committed.
    persistent_set(env, &ImpersonationKey::NextSessionId, &session_id);
    persistent_set(env, &ImpersonationKey::Session(session_id), &session);

    // Index by target user
    let mut target_sessions = get_target_sessions(env, &params.target_user);
    target_sessions.push_back(session_id);
    persistent_set(
        env,
        &ImpersonationKey::ActiveSessions(params.target_user.clone()),
        &target_sessions,
    );

    // Index by impersonator
    let mut impersonator_session_list = get_impersonator_sessions(env, impersonator);
    impersonator_session_list.push_back(session_id);
    persistent_set(
        env,
        &ImpersonationKey::ImpersonatorSessions(impersonator.clone()),
        &impersonator_session_list,
    );

    // Emit event for visibility
    env.events().publish(
        (
            Symbol::new(env, "impersonation"),
            Symbol::new(env, "session_created"),
        ),
        (
            session_id,
            impersonator.clone(),
            params.target_user,
            expires_at,
        ),
    );

    Ok(SessionResult {
        session,
        is_new: true,
    })
}

/// Revokes an active impersonation session.
///
/// # Requirements
/// - Caller must be the session creator or have ImpersonateUser permission
/// - Session must be active
pub fn revoke_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<(), ImpersonationError> {
    caller.require_auth();
    let mut session = get_session(env, session_id).ok_or(ImpersonationError::SessionNotFound)?;

    // Authorization: only creator or someone with impersonation permission can revoke
    if session.impersonator != *caller && !has_permission(env, caller, Permission::ImpersonateUser)
    {
        return Err(ImpersonationError::Unauthorized);
    }

    if session.state != SessionState::Active {
        return Err(ImpersonationError::SessionNotFound);
    }
    if env.ledger().timestamp() >= session.expires_at {
        expire_session(env, session)?;
        return Err(ImpersonationError::SessionExpired);
    }

    append_support_audit(
        env,
        caller,
        &session.target_user,
        session_id,
        symbol_short!("supp_rvk"),
        None,
        None,
        Some(session.reason.clone()),
    )?;

    // Mark as revoked only after the required audit entry is committed.
    session.state = SessionState::Revoked;
    persistent_set(env, &ImpersonationKey::Session(session_id), &session);

    // Remove from active indexes
    remove_from_active_indexes(env, &session);

    // Emit event
    env.events().publish(
        (
            Symbol::new(env, "impersonation"),
            Symbol::new(env, "session_revoked"),
        ),
        (session_id, caller.clone()),
    );

    Ok(())
}

/// Validates and returns an active session if it exists and is not expired.
pub fn validate_session(
    env: &Env,
    session_id: u64,
) -> Result<ImpersonationSession, ImpersonationError> {
    let session = get_session(env, session_id).ok_or(ImpersonationError::SessionNotFound)?;

    if session.state != SessionState::Active {
        return Err(ImpersonationError::SessionNotFound);
    }

    let now = env.ledger().timestamp();
    if now >= session.expires_at {
        expire_session(env, session)?;
        return Err(ImpersonationError::SessionExpired);
    }
    if !is_eligible_target(env, &session.target_user) {
        revoke_for_target_role(env, session)?;
        return Err(ImpersonationError::TargetNotImpersonatable);
    }

    Ok(session)
}

/// Checks if an action is permitted within the session scope.
pub fn check_action_permission(
    env: &Env,
    session: &ImpersonationSession,
    action_type: ImpersonationAction,
    resource_type: ResourceType,
    resource_id: Option<u64>,
) -> Result<(), ImpersonationError> {
    let active_session = validate_session(env, session.session_id)?;
    if active_session != *session {
        return Err(ImpersonationError::SessionNotFound);
    }
    if active_session
        .resource_scopes
        .iter()
        .any(|scope| scope.resource_type == ResourceType::All)
    {
        return Err(ImpersonationError::ActionNotPermitted);
    }

    // Check scope-based permissions
    match active_session.scope {
        ImpersonationScope::ReadOnly => {
            if is_mutation_action(action_type) {
                return Err(ImpersonationError::ActionNotPermitted);
            }
        }
        ImpersonationScope::Diagnostic => {
            if is_mutation_action(action_type) && !is_diagnostic_mutation(action_type) {
                return Err(ImpersonationError::ActionNotPermitted);
            }
        }
        ImpersonationScope::SafeMutations => {
            if is_dangerous_action(action_type) && !active_session.allow_dangerous_mutations {
                return Err(ImpersonationError::DangerousMutationBlocked);
            }
        }
        ImpersonationScope::FullAccess => {
            // Full access still respects dangerous mutation flag
            if is_dangerous_action(action_type) && !active_session.allow_dangerous_mutations {
                return Err(ImpersonationError::DangerousMutationBlocked);
            }
        }
    }

    // Check resource scope
    if !is_resource_permitted(&active_session.resource_scopes, resource_type, resource_id) {
        return Err(ImpersonationError::ActionNotPermitted);
    }

    Ok(())
}

/// Records an authorized action attempt before the protected operation.
pub fn record_action(
    env: &Env,
    session_id: u64,
    action_type: ImpersonationAction,
    resource_type: ResourceType,
    resource_id: Option<u64>,
) -> Result<(), ImpersonationError> {
    let mut session = validate_session(env, session_id)?;
    session.impersonator.require_auth();
    check_action_permission(env, &session, action_type, resource_type, resource_id)?;

    append_support_audit(
        env,
        &session.impersonator,
        &session.target_user,
        session_id,
        symbol_short!("supp_act"),
        Some(action_type.as_symbol()),
        resource_id.map(i128::from),
        Some(resource_type.as_symbol()),
    )?;

    // Increment action count
    session.action_count = session.action_count.saturating_add(1);
    persistent_set(env, &ImpersonationKey::Session(session_id), &session);

    // Emit event
    env.events().publish(
        (
            Symbol::new(env, "impersonation"),
            Symbol::new(env, "action_recorded"),
        ),
        (
            session_id,
            action_type.as_symbol(),
            resource_type.as_symbol(),
        ),
    );

    Ok(())
}

/// Gets active impersonation sessions for a target user.
pub fn get_active_sessions_for_user(env: &Env, target_user: &Address) -> Vec<ImpersonationSession> {
    let session_ids = get_target_sessions(env, target_user);
    let mut active_sessions = Vec::new(env);

    for session_id in session_ids.iter() {
        if let Ok(session) = validate_session(env, session_id) {
            active_sessions.push_back(session);
        }
    }

    active_sessions
}

/// Gets active impersonation sessions for an impersonator.
pub fn get_active_sessions_for_impersonator(
    env: &Env,
    impersonator: &Address,
) -> Vec<ImpersonationSession> {
    let session_ids = get_impersonator_sessions(env, impersonator);
    let mut active_sessions = Vec::new(env);

    for session_id in session_ids.iter() {
        if let Ok(session) = validate_session(env, session_id) {
            active_sessions.push_back(session);
        }
    }

    active_sessions
}

/// Checks if a user is currently being impersonated.
pub fn is_being_impersonated(env: &Env, target_user: &Address) -> bool {
    let sessions = get_active_sessions_for_user(env, target_user);
    !sessions.is_empty()
}

/// Gets the current impersonation session for a target user (if any).
pub fn get_current_impersonation(env: &Env, target_user: &Address) -> Option<ImpersonationSession> {
    let sessions = get_active_sessions_for_user(env, target_user);
    sessions.first()
}

/// Returns only the expiry timestamp for user-safe support-access notices.
///
/// The result intentionally omits the maintainer identity, reason, and scope.
pub fn support_access_notice(
    env: &Env,
    target_user: &Address,
) -> Option<SupportAccessNotice> {
    let now = env.ledger().timestamp();
    for session_id in get_target_sessions(env, target_user).iter() {
        if let Some(session) = get_session(env, session_id) {
            if session.state == SessionState::Active
                && now < session.expires_at
                && is_eligible_target(env, target_user)
            {
                return Some(SupportAccessNotice {
                    expires_at: session.expires_at,
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Action Types
// ---------------------------------------------------------------------------

/// Types of actions that can be taken during impersonation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpersonationAction {
    /// Read operation (always allowed in read-only scope).
    Read,
    /// Diagnostic operation (allowed in diagnostic and higher scopes).
    Diagnostic,
    /// Safe state change (allowed in safe mutations and higher scopes).
    SafeMutation,
    /// Dangerous mutation (requires explicit permission).
    DangerousMutation,
    /// Configuration change (requires appropriate scope).
    ConfigChange,
    /// Role management (requires full access or explicit permission).
    RoleManagement,
    /// Treasury operation (requires full access and explicit permission).
    TreasuryOperation,
}

impl ImpersonationAction {
    fn as_symbol(&self) -> Symbol {
        match self {
            ImpersonationAction::Read => symbol_short!("read"),
            ImpersonationAction::Diagnostic => symbol_short!("diagnos"),
            ImpersonationAction::SafeMutation => symbol_short!("safemut"),
            ImpersonationAction::DangerousMutation => symbol_short!("dangmut"),
            ImpersonationAction::ConfigChange => symbol_short!("cfgchg"),
            ImpersonationAction::RoleManagement => symbol_short!("rolemgmt"),
            ImpersonationAction::TreasuryOperation => symbol_short!("tres_op"),
        }
    }
}

impl ImpersonationScope {
    fn as_symbol(&self) -> Symbol {
        match self {
            ImpersonationScope::ReadOnly => symbol_short!("readonly"),
            ImpersonationScope::Diagnostic => symbol_short!("diagnos"),
            ImpersonationScope::SafeMutations => symbol_short!("safemut"),
            ImpersonationScope::FullAccess => symbol_short!("full"),
        }
    }
}

impl ResourceType {
    fn as_symbol(&self) -> Symbol {
        match self {
            ResourceType::Aid => symbol_short!("aid"),
            ResourceType::Payment => symbol_short!("payment"),
            ResourceType::Escrow => symbol_short!("escrow"),
            ResourceType::Treasury => symbol_short!("treasury"),
            ResourceType::Roles => symbol_short!("roles"),
            ResourceType::Config => symbol_short!("config"),
            ResourceType::All => symbol_short!("all"),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

fn is_eligible_target(env: &Env, target_user: &Address) -> bool {
    for role in [
        Role::Admin,
        Role::Upgrader,
        Role::TreasuryManager,
        Role::Pauser,
        Role::ReferralManager,
        Role::OracleSigner,
        Role::ServiceActor,
        Role::Support,
    ] {
        if has_role(env, target_user, role) {
            return false;
        }
    }
    true
}

fn is_valid_scope(
    scope: &ImpersonationScope,
    resource_scopes: &Vec<ResourceScope>,
) -> bool {
    if resource_scopes.is_empty() {
        return false;
    }

    // Basic validation: scope should match resource scopes
    match scope {
        ImpersonationScope::ReadOnly | ImpersonationScope::Diagnostic => {
            // Read-only support must not expose privileged resources.
            for rs in resource_scopes.iter() {
                if matches!(
                    rs.resource_type,
                    ResourceType::Treasury | ResourceType::Roles | ResourceType::Config
                ) {
                    return false;
                }
            }
        }
        _ => {}
    }
    resource_scopes
        .iter()
        .all(|scope| scope.resource_type != ResourceType::All)
}

fn is_mutation_action(action: ImpersonationAction) -> bool {
    matches!(
        action,
        ImpersonationAction::SafeMutation
            | ImpersonationAction::DangerousMutation
            | ImpersonationAction::ConfigChange
            | ImpersonationAction::RoleManagement
            | ImpersonationAction::TreasuryOperation
    )
}

fn is_diagnostic_mutation(action: ImpersonationAction) -> bool {
    matches!(action, ImpersonationAction::Diagnostic)
}

fn is_dangerous_action(action: ImpersonationAction) -> bool {
    matches!(
        action,
        ImpersonationAction::DangerousMutation
            | ImpersonationAction::RoleManagement
            | ImpersonationAction::TreasuryOperation
            | ImpersonationAction::ConfigChange
    )
}

fn is_resource_permitted(
    resource_scopes: &Vec<ResourceScope>,
    resource_type: ResourceType,
    resource_id: Option<u64>,
) -> bool {
    for scope in resource_scopes.iter() {
        if scope.resource_type == resource_type {
            // If resource_id is None in scope, all of that type are permitted
            if scope.resource_id.is_none() {
                return true;
            }
            // If resource_id matches, it's permitted
            if scope.resource_id == resource_id {
                return true;
            }
        }
    }

    false
}

fn get_session(env: &Env, session_id: u64) -> Option<ImpersonationSession> {
    persistent_get(env, &ImpersonationKey::Session(session_id))
}

fn get_target_sessions(env: &Env, target_user: &Address) -> Vec<u64> {
    persistent_get(env, &ImpersonationKey::ActiveSessions(target_user.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

fn get_impersonator_sessions(env: &Env, impersonator: &Address) -> Vec<u64> {
    persistent_get(
        env,
        &ImpersonationKey::ImpersonatorSessions(impersonator.clone()),
    )
    .unwrap_or_else(|| Vec::new(env))
}

fn next_session_id(env: &Env) -> Result<u64, ImpersonationError> {
    let current: u64 = persistent_get(env, &ImpersonationKey::NextSessionId).unwrap_or(0);
    let next = current
        .checked_add(1)
        .ok_or(ImpersonationError::SessionIdExhausted)?;
    Ok(next)
}

fn remove_from_active_indexes(env: &Env, session: &ImpersonationSession) {
    // Remove from target user index
    let mut target_sessions = get_target_sessions(env, &session.target_user);
    if let Some(pos) = target_sessions.first_index_of(session.session_id) {
        let _ = target_sessions.remove(pos);
        if target_sessions.is_empty() {
            persistent_remove(
                env,
                &ImpersonationKey::ActiveSessions(session.target_user.clone()),
            );
        } else {
            persistent_set(
                env,
                &ImpersonationKey::ActiveSessions(session.target_user.clone()),
                &target_sessions,
            );
        }
    }

    // Remove from impersonator index
    let mut impersonator_sessions = get_impersonator_sessions(env, &session.impersonator);
    if let Some(pos) = impersonator_sessions.first_index_of(session.session_id) {
        let _ = impersonator_sessions.remove(pos);
        if impersonator_sessions.is_empty() {
            persistent_remove(
                env,
                &ImpersonationKey::ImpersonatorSessions(session.impersonator.clone()),
            );
        } else {
            persistent_set(
                env,
                &ImpersonationKey::ImpersonatorSessions(session.impersonator.clone()),
                &impersonator_sessions,
            );
        }
    }
}

fn append_support_audit(
    env: &Env,
    actor: &Address,
    target_user: &Address,
    session_id: u64,
    module: Symbol,
    attribute: Option<Symbol>,
    previous_amount: Option<i128>,
    note: Option<Symbol>,
) -> Result<(), ImpersonationError> {
    append_event(
        env,
        AuditEventParams {
            kind: AuditEventKind::PrivilegedAction,
            module,
            actor: actor.clone(),
            subject: Some(target_user.clone()),
            resource: None,
            attribute,
            amount: Some(i128::from(session_id)),
            previous_amount,
            note,
            correlation_id: genesis_hash(env),
        },
    )
    .map(|_| ())
    .map_err(|_| ImpersonationError::AuditFailure)
}

fn expire_session(
    env: &Env,
    mut session: ImpersonationSession,
) -> Result<(), ImpersonationError> {
    append_support_audit(
        env,
        &session.impersonator,
        &session.target_user,
        session.session_id,
        symbol_short!("supp_exp"),
        None,
        Some(i128::from(session.expires_at)),
        Some(session.reason.clone()),
    )?;
    session.state = SessionState::Expired;
    persistent_set(
        env,
        &ImpersonationKey::Session(session.session_id),
        &session,
    );
    remove_from_active_indexes(env, &session);
    env.events().publish(
        (
            Symbol::new(env, "impersonation"),
            Symbol::new(env, "session_expired"),
        ),
        (session.session_id, session.target_user),
    );
    Ok(())
}

fn revoke_for_target_role(
    env: &Env,
    mut session: ImpersonationSession,
) -> Result<(), ImpersonationError> {
    append_support_audit(
        env,
        &session.impersonator,
        &session.target_user,
        session.session_id,
        symbol_short!("supp_rvk"),
        Some(symbol_short!("targrole")),
        Some(i128::from(session.expires_at)),
        Some(session.reason.clone()),
    )?;
    session.state = SessionState::Revoked;
    persistent_set(
        env,
        &ImpersonationKey::Session(session.session_id),
        &session,
    );
    remove_from_active_indexes(env, &session);
    env.events().publish(
        (
            Symbol::new(env, "impersonation"),
            Symbol::new(env, "session_revoked"),
        ),
        (session.session_id, session.impersonator),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger as _};

    fn resource_scope(env: &Env, resource_type: ResourceType) -> Vec<ResourceScope> {
        let mut scopes = Vec::new(env);
        scopes.push_back(ResourceScope {
            resource_type,
            resource_id: None,
        });
        scopes
    }

    #[test]
    fn test_create_session_basic() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin first
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);

        // Grant Support role to impersonator
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params);
        assert!(result.is_ok());

        let session_result = result.unwrap();
        assert!(session_result.is_new);
        assert_eq!(session_result.session.impersonator, support);
        assert_eq!(session_result.session.target_user, target_user);
        assert_eq!(session_result.session.state, SessionState::Active);
        assert_eq!(crate::audit_ledger::length(&env), 1);
        assert!(crate::audit_ledger::verify_chain(&env).verified);
    }

    #[test]
    fn test_unauthorized_session_creation() {
        let env = Env::default();
        env.mock_all_auths();
        let unauthorized = Address::generate(&env);
        let target_user = Address::generate(&env);

        let params = SessionParams {
            target_user,
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &unauthorized, params);
        assert_eq!(result, Err(ImpersonationError::Unauthorized));
    }

    #[test]
    fn test_duration_too_long() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user,
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: MAX_SESSION_DURATION + 1,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params);
        assert_eq!(result, Err(ImpersonationError::DurationTooLong));
    }

    #[test]
    fn test_session_expiration() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: 10, // 10 seconds
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params).unwrap();
        let session_id = result.session.session_id;

        // Advance time past expiration
        env.ledger().set_timestamp(env.ledger().timestamp() + 15);

        let validation = validate_session(&env, session_id);
        assert_eq!(validation, Err(ImpersonationError::SessionExpired));
        assert_eq!(crate::audit_ledger::length(&env), 2);
        assert!(crate::audit_ledger::verify_chain(&env).verified);
    }

    #[test]
    fn test_read_only_scope_blocks_mutations() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params).unwrap();
        let session = result.session;

        // Try a mutation action
        let permission = check_action_permission(
            &env,
            &session,
            ImpersonationAction::SafeMutation,
            ResourceType::Aid,
            Some(1),
        );
        assert_eq!(permission, Err(ImpersonationError::ActionNotPermitted));
        assert_eq!(
            record_action(
                &env,
                session.session_id,
                ImpersonationAction::SafeMutation,
                ResourceType::Aid,
                Some(1),
            ),
            Err(ImpersonationError::ActionNotPermitted)
        );
        assert_eq!(crate::audit_ledger::length(&env), 1);

        // Read action should be allowed
        let read_permission = check_action_permission(
            &env,
            &session,
            ImpersonationAction::Read,
            ResourceType::Aid,
            Some(1),
        );
        assert!(read_permission.is_ok());
        record_action(
            &env,
            session.session_id,
            ImpersonationAction::Read,
            ResourceType::Aid,
            Some(1),
        )
        .unwrap();
        assert_eq!(crate::audit_ledger::length(&env), 2);
        assert!(crate::audit_ledger::verify_chain(&env).verified);
    }

    #[test]
    fn test_dangerous_mutation_blocked() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::SafeMutations,
            resource_scopes: resource_scope(&env, ResourceType::Treasury),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false, // Dangerous mutations not allowed
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params).unwrap();
        let session = result.session;

        // Try a dangerous action
        let permission = check_action_permission(
            &env,
            &session,
            ImpersonationAction::TreasuryOperation,
            ResourceType::Treasury,
            None,
        );
        assert_eq!(
            permission,
            Err(ImpersonationError::DangerousMutationBlocked)
        );
    }

    #[test]
    fn test_session_revocation() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params).unwrap();
        let session_id = result.session.session_id;
        assert!(support_access_notice(&env, &target_user).is_some());

        // Revoke the session
        let revoke_result = revoke_session(&env, &support, session_id);
        assert!(revoke_result.is_ok());

        // Verify session is revoked
        let validation = validate_session(&env, session_id);
        assert_eq!(validation, Err(ImpersonationError::SessionNotFound));
        assert!(support_access_notice(&env, &target_user).is_none());
        assert_eq!(crate::audit_ledger::length(&env), 2);
        assert!(crate::audit_ledger::verify_chain(&env).verified);
    }

    #[test]
    fn test_resource_scope_filtering() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let mut resource_scopes = Vec::new(&env);
        resource_scopes.push_back(ResourceScope {
            resource_type: ResourceType::Aid,
            resource_id: Some(1),
        });

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::ReadOnly,
            resource_scopes,
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params).unwrap();
        let session = result.session;

        // Access to allowed resource should work
        let allowed = check_action_permission(
            &env,
            &session,
            ImpersonationAction::Read,
            ResourceType::Aid,
            Some(1),
        );
        assert!(allowed.is_ok());

        // Access to different resource should be blocked
        let blocked = check_action_permission(
            &env,
            &session,
            ImpersonationAction::Read,
            ResourceType::Payment,
            Some(1),
        );
        assert_eq!(blocked, Err(ImpersonationError::ActionNotPermitted));
    }

    #[test]
    fn test_is_being_impersonated() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let params = SessionParams {
            target_user: target_user.clone(),
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let _ = create_session(&env, &support, params).unwrap();

        assert!(is_being_impersonated(&env, &target_user));

        // Revoke session
        let sessions = get_active_sessions_for_user(&env, &target_user);
        if !sessions.is_empty() {
            let _ = revoke_session(&env, &support, sessions.get(0).unwrap().session_id);
        }

        assert!(!is_being_impersonated(&env, &target_user));
    }

    #[test]
    fn test_concurrent_session_limit() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);

        // Setup admin and grant Support role
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        // Create maximum number of sessions
        for i in 0..MAX_CONCURRENT_SESSIONS {
            let target_user = Address::generate(&env);
            let params = SessionParams {
                target_user,
                scope: ImpersonationScope::ReadOnly,
                resource_scopes: resource_scope(&env, ResourceType::Aid),
                duration_sec: DEFAULT_SESSION_DURATION,
                allow_dangerous_mutations: false,
                reason: Symbol::new(&env, "debug_issue"),
            };
            let _ = create_session(&env, &support, params).unwrap();
        }

        // Try to create one more - should fail
        let target_user = Address::generate(&env);
        let params = SessionParams {
            target_user,
            scope: ImpersonationScope::ReadOnly,
            resource_scopes: resource_scope(&env, ResourceType::Aid),
            duration_sec: DEFAULT_SESSION_DURATION,
            allow_dangerous_mutations: false,
            reason: Symbol::new(&env, "debug_issue"),
        };

        let result = create_session(&env, &support, params);
        assert_eq!(result, Err(ImpersonationError::TooManyActiveSessions));
    }

    #[test]
    fn test_unscoped_session_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let result = create_session(
            &env,
            &support,
            SessionParams {
                target_user,
                scope: ImpersonationScope::ReadOnly,
                resource_scopes: Vec::new(&env),
                duration_sec: DEFAULT_SESSION_DURATION,
                allow_dangerous_mutations: false,
                reason: Symbol::new(&env, "debug_issue"),
            },
        );
        assert_eq!(result, Err(ImpersonationError::InvalidScope));

        let all_resources = create_session(
            &env,
            &support,
            SessionParams {
                target_user: Address::generate(&env),
                scope: ImpersonationScope::ReadOnly,
                resource_scopes: resource_scope(&env, ResourceType::All),
                duration_sec: DEFAULT_SESSION_DURATION,
                allow_dangerous_mutations: false,
                reason: Symbol::new(&env, "debug_issue"),
            },
        );
        assert_eq!(all_resources, Err(ImpersonationError::InvalidScope));

        let privileged_target = Address::generate(&env);
        let _ = crate::auth::grant_role(
            &env,
            &admin,
            &privileged_target,
            Role::TreasuryManager,
        );
        let privileged_session = create_session(
            &env,
            &support,
            SessionParams {
                target_user: privileged_target,
                scope: ImpersonationScope::ReadOnly,
                resource_scopes: resource_scope(&env, ResourceType::Aid),
                duration_sec: DEFAULT_SESSION_DURATION,
                allow_dangerous_mutations: false,
                reason: Symbol::new(&env, "debug_issue"),
            },
        );
        assert_eq!(
            privileged_session,
            Err(ImpersonationError::TargetNotImpersonatable)
        );
        assert_eq!(crate::audit_ledger::length(&env), 0);
    }

    #[test]
    fn test_session_is_revoked_if_target_becomes_privileged() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        let target_user = Address::generate(&env);
        let admin = Address::generate(&env);
        let _ = crate::auth::initialize_admin(&env, &admin);
        let _ = crate::auth::grant_role(&env, &admin, &support, Role::Support);

        let created = create_session(
            &env,
            &support,
            SessionParams {
                target_user: target_user.clone(),
                scope: ImpersonationScope::ReadOnly,
                resource_scopes: resource_scope(&env, ResourceType::Aid),
                duration_sec: DEFAULT_SESSION_DURATION,
                allow_dangerous_mutations: false,
                reason: Symbol::new(&env, "debug_issue"),
            },
        )
        .unwrap();
        let _ = crate::auth::grant_role(
            &env,
            &admin,
            &target_user,
            Role::TreasuryManager,
        );

        assert_eq!(
            validate_session(&env, created.session.session_id),
            Err(ImpersonationError::TargetNotImpersonatable)
        );
        assert!(support_access_notice(&env, &target_user).is_none());
        assert_eq!(crate::audit_ledger::length(&env), 2);
        assert!(crate::audit_ledger::verify_chain(&env).verified);
    }
}
