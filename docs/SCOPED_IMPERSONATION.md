# Scoped Maintainer Impersonation for Support Debugging

## Overview

The Scoped Maintainer Impersonation feature allows authorized maintainers to temporarily impersonate users for debugging purposes while maintaining strict security boundaries. This enables safe reproduction of user-reported issues without granting broad access to private data or enabling irreversible actions.

## Features

### 1. Time-Limited Sessions
- Configurable session duration (default: 15 minutes, maximum: 1 hour)
- Automatic session expiration
- Manual session revocation capability
- Session state tracking (Active, Revoked, Expired, Completed)

### 2. Scoped Permissions
- **ReadOnly**: Read-only access to user data
- **Diagnostic**: Read access plus diagnostic operations (no state changes)
- **SafeMutations**: Read access plus safe state changes (non-critical operations)
- **FullAccess**: Full access within time limit (use with caution)

### 3. Resource-Level Scoping
- Limit impersonation to specific resource types (AID, Payment, Escrow, Treasury, Roles, Config)
- Restrict to specific resource IDs for fine-grained control
- Empty resource scopes and `ResourceType::All` are rejected
- Read-only and diagnostic sessions cannot include Treasury, Roles, or Config
- Prevents accidental access to unrelated user data

### 4. Dangerous Mutation Blocking
- Automatically blocks dangerous operations unless explicitly allowed
- Treasury operations, role management, and critical changes require explicit permission
- Prevents accidental irreversible actions during debugging

### 5. Comprehensive Audit Logging
- Session creation, revocation, expiry, and permitted actions are appended to the immutable hash-chained audit ledger
- Events are also emitted for real-time monitoring

### 6. Visible Indicators
- Ledger events for session creation, revocation, and actions
- `is_being_impersonated()` function to check active sessions
- Session metadata includes impersonator, target, scope, and duration
- Clear distinction between normal and impersonated operations

## Usage

### Creating an Impersonation Session

```rust
use trellis_contracts::{
    create_session, revoke_session, validate_session, check_action_permission,
    record_action, ImpersonationScope, ResourceType, ResourceScope, SessionParams,
    ImpersonationAction, SessionState,
};

// Prepare session parameters
let params = SessionParams {
    target_user: user_address,
    scope: ImpersonationScope::ReadOnly,
    resource_scopes: Vec::from_array(
        &env,
        [ResourceScope {
            resource_type: ResourceType::Aid,
            resource_id: None,
        }],
    ),
    duration_sec: 900, // 15 minutes
    allow_dangerous_mutations: false,
    reason: symbol_short!("debug_user_issue"),
};

// Create the session (requires Support role)
let result = create_session(&env, &maintainer_address, params)?;
let session = result.session;

println!("Session {} created for {}", session.session_id, session.target_user);
```

### Checking Action Permissions

```rust
// Before performing an action, check if it's permitted
let permission = check_action_permission(
    &env,
    &session,
    ImpersonationAction::Read,
    ResourceType::Aid,
    Some(aid_id),
);

match permission {
    Ok(()) => {
        // Action is permitted, proceed and record it
        record_action(
            &env,
            session.session_id,
            ImpersonationAction::Read,
            ResourceType::Aid,
            Some(aid_id),
        )?;
        // Perform the actual action...
    }
    Err(ImpersonationError::ActionNotPermitted) => {
        // Action not permitted in current scope
        return Err(Error::Unauthorized);
    }
    Err(ImpersonationError::DangerousMutationBlocked) => {
        // Dangerous action requires explicit permission
        return Err(Error::ContractPaused); // Or appropriate error
    }
    Err(e) => {
        // Other error (session expired, etc.)
        return Err(Error::from(e));
    }
}
```

### Resource-Level Scoping

```rust
// Limit impersonation to specific AID record
let mut resource_scopes = Vec::new(&env);
resource_scopes.push_back(ResourceScope {
    resource_type: ResourceType::Aid,
    resource_id: Some(123), // Only AID #123
});

let params = SessionParams {
    target_user: user_address,
    scope: ImpersonationScope::Diagnostic,
    resource_scopes,
    duration_sec: 900,
    allow_dangerous_mutations: false,
    reason: symbol_short!("debug_specific_aid"),
};
```

### Checking Active Impersonation

```rust
// Show the user-safe notice without exposing internal support details.
if let Some(notice) = support_access_notice(&env, &user_address) {
    show_notice_until(notice.expires_at);
}
```

### Revoking a Session

```rust
// Revoke an active session
revoke_session(&env, &maintainer_address, session_id)?;
```

## Security Model

### Authorization Requirements

To create an impersonation session, the caller must authenticate and:
- Hold the `Support` role
- Be authorized with `Permission::ImpersonateUser`

To revoke a session, the caller must:
- Authenticate
- Be the session creator, OR
- Hold `Permission::ImpersonateUser`

Every recorded action also requires the session creator's authorization.

### Target User Restrictions

- Accounts holding a privileged or service role (Admin, Upgrader, TreasuryManager, Pauser, ReferralManager, OracleSigner, ServiceActor, or Support) cannot be impersonated
- Session creation validates target user eligibility

### Scope Validation

- `ReadOnly` and `Diagnostic` scopes cannot include Treasury, Roles, or Config resources
- Empty resource lists and `ResourceType::All` are rejected
- Resource scopes must be compatible with the chosen permission scope
- Invalid scope combinations are rejected at session creation

### Time Limits

- Maximum session duration: 1 hour (3600 seconds)
- Default session duration: 15 minutes (900 seconds)
- Zero-duration sessions are rejected. Protected actions are denied at `now >= expires_at`
- Expired sessions are finalized on the next session validation or when the creator opens another session; no background timer is assumed
- Expired sessions are automatically cleaned from active indexes

### Concurrent Session Limits

- Maximum 5 concurrent sessions per impersonator
- Prevents session abuse and helps maintain accountability
- Attempts to exceed limit return `TooManyActiveSessions` error

## Immutable Audit Trail

Impersonation lifecycle and action records are appended to the hash-chained
`shared::audit_ledger` as `PrivilegedAction` events. The module symbols
`supp_crt`, `supp_rvk`, `supp_exp`, and `supp_act` distinguish creation,
revocation, expiry, and authorized action attempts. Entries link to the target
account and session ID; creation records include the chosen scope and expiry,
and action records include action and resource type. The mutable session
record is operational state, not the authoritative audit trail.

Every protected handler must validate the session, call
`check_action_permission`, and call `record_action` before accessing or
changing the protected resource. `record_action` repeats the session and scope checks and requires the
impersonator's authorization. It records the authorized attempt before the
domain operation; the domain operation must still report its own outcome.
Propagate its result and do not proceed unless it succeeds.

If the immutable audit append fails, the helper returns `AuditFailure` and
does not update session state. Callers must propagate the error so Soroban
rolls back the entire invocation; never catch it and continue without a record.

### Event Notifications

```rust
// Events are indexer notifications; the hash-chained ledger is authoritative.
env.events().publish(
    (symbol_short!("impersonation"), symbol_short!("session_created")),
    (session_id, impersonator, target_user, expires_at),
);
```

### Action Events

```rust
// Emitted for each action during impersonation
env.events().publish(
    (symbol_short!("impersonation"), symbol_short!("action_recorded")),
    (session_id, action_type.as_symbol(), resource_type.as_symbol()),
);

```

### User-Safe Notice

`support_access_notice(env, target_user)` returns only the active session's
expiry timestamp. It intentionally omits the support actor, internal reason,
and resource scope so a frontend can display a notice without exposing
maintainer-only details. It returns `None` when no unexpired session is active.

### Operational Edge Cases and Recovery

| Situation | Behavior and operator response |
|---|---|
| A session expires between page loads or transactions | Protected actions revalidate against the current ledger timestamp. Access is denied at `now >= expires_at`; the next validation appends an expiry record and cleans active indexes. |
| The audit ledger rejects an event (for example, timestamp/ledger regression or sequence overflow) | Fail closed with `AuditFailure`. Inspect `audit_ledger::verify_chain` and the last externally anchored checkpoint before resuming. |
| A write fails after a required audit append | Propagate the error from the contract entry point. Soroban rolls back the append and related state changes atomically. Confirm the live head before retrying. |
| A deployment rollback restores an earlier snapshot | Compare the restored head with the latest published/archive checkpoint. If older, pause support access and restore a matching audited snapshot; do not delete or rewrite entries. |
| An active-session index is stale | Validation checks stored session state and expiry directly, then removes terminated sessions from indexes. Do not repair the audit chain by editing entries. |
| Audit-chain verification fails | Stop support access operations, preserve affected state and exported entries, and reconcile against a trusted checkpoint/archive. Resume only after restoring a verified snapshot; never truncate or rewrite the chain. |

### Session Revocation Events

```rust
// Emitted when a session is revoked
env.events().publish(
    (symbol_short!("impersonation"), symbol_short!("session_revoked")),
    (session_id, caller),
);
```

## Error Handling

### ImpersonationError

| Error Code | Description |
|------------|-------------|
| `SessionNotFound` | Session does not exist or has expired |
| `Unauthorized` | Caller lacks impersonation permission |
| `InvalidScope` | Requested scope is invalid |
| `DurationTooLong` | Duration exceeds maximum allowed |
| `SessionExpired` | Session has expired |
| `ActionNotPermitted` | Action not permitted in current scope |
| `DangerousMutationBlocked` | Dangerous mutation requires explicit permission |
| `SessionAlreadyActive` | Session already active (idempotency check) |
| `TargetNotImpersonatable` | Target user cannot be impersonated |
| `TooManyActiveSessions` | Maximum concurrent sessions exceeded |
| `DurationInvalid` | Duration must be greater than zero |
| `AuditFailure` | Immutable audit entry could not be appended |
| `SessionIdExhausted` | No further unique session IDs can be allocated |
| `TimestampOverflow` | The expiry timestamp cannot be represented |

## Integration with Existing Systems

### Authorization System

- Uses existing `Permission::ImpersonateUser` permission
- Integrates with `Role::Support` for authorization
- Uses `has_permission()` and Soroban `require_auth()` checks
- Consistent with existing role-based access control

### Audit Trail

- Uses the existing append-only, hash-chained audit ledger
- Existing user timeline and indexer events remain separate presentation/notification surfaces

### Event System

- Emits structured events using existing event patterns
- Topics follow existing naming conventions (`impersonation:*`)
- Data payloads use existing Soroban event patterns
- Compatible with existing event indexing infrastructure

## Best Practices

### For Maintainers

1. **Use the most restrictive scope possible**
   - Start with `ReadOnly` and only escalate if necessary
   - Use resource-level scoping to limit access to specific data
   - Avoid `FullAccess` unless absolutely required

2. **Keep sessions short**
   - Use the default 15-minute duration for most cases
   - Only extend to 1 hour for complex debugging scenarios
   - Revoke sessions immediately when debugging is complete

3. **Document the reason**
   - Always provide a clear reason for impersonation
   - Use specific reason codes that can be tracked
   - This improves audit trail quality

4. **Review session logs**
   - Check action logs after impersonation sessions
   - Verify that only intended actions were taken
   - Escalate any suspicious activity

### For Developers

1. **Always check permissions before actions**
   - Use `check_action_permission()` before any protected access or state change
   - Handle permission errors gracefully
   - Call `record_action()` and propagate its result before touching protected resources
   - Do not proceed after an audit failure or a denied action

2. **Validate session before use**
   - Call `validate_session()` to ensure session is still active
   - Handle session expiration gracefully
   - Provide clear error messages to users

3. **Resource scoping for precision**
   - Use resource scoping when debugging specific issues
   - Prevents accidental access to unrelated data
   - Improves security and audit quality

4. **Test impersonation flows**
   - Include tests for impersonation scenarios
   - Test scope enforcement and permission checks
   - Verify audit trail completeness

## Testing

### Unit Tests

The implementation includes comprehensive tests covering:

- **Session Creation**: Basic session creation with proper authorization
- **Unauthorized Access**: Prevention of unauthorized session creation
- **Duration Limits**: Enforcement of maximum session duration
- **Session Expiration**: Automatic expiration when time limit is reached
- **Scope Enforcement**: Read-only scope blocks mutations
- **Dangerous Mutation Blocking**: Prevention of dangerous operations
- **Session Revocation**: Manual session termination
- **Resource Scoping**: Resource-level access control
- **Active Session Detection**: Checking if a user is being impersonated
- **Concurrent Session Limits**: Enforcement of maximum concurrent sessions

### Running Tests

```bash
cargo test --package shared test_impersonation
```

### Test Scenarios

#### Allowed Actions
```rust
#[test]
fn test_read_action_permitted_in_readonly_scope() {
    // Read actions should be allowed in ReadOnly scope
}
```

#### Denied Actions
```rust
#[test]
fn test_mutation_blocked_in_readonly_scope() {
    // Mutations should be blocked in ReadOnly scope
}
```

#### Expired Sessions
```rust
#[test]
fn test_expired_session_rejected() {
    // Expired sessions should be rejected
}
```

#### Audited Sessions
```rust
#[test]
fn test_action_logging() {
    // All actions should be logged to audit trail
}
```

## Configuration

### Constants

```rust
// Maximum session duration in seconds (1 hour)
pub const MAX_SESSION_DURATION: u64 = 3600;

// Default session duration in seconds (15 minutes)
pub const DEFAULT_SESSION_DURATION: u64 = 900;

// Maximum concurrent sessions per maintainer
pub const MAX_CONCURRENT_SESSIONS: u32 = 5;
```

### Customization

To customize these values for your deployment:

1. Modify the constants in `shared/src/impersonation.rs`
2. Rebuild the shared crate
3. Update documentation to reflect new values
4. Test with new values to ensure proper operation

## Migration and Deployment

### Compatibility and Rollout

- `ImpersonationSession` and `SessionParams` storage/API shapes are unchanged.
- New session creation requires a non-empty, explicit resource scope; `ResourceType::All` is rejected. Update callers to provide scopes and authenticate before rollout.
- Previously stored sessions with empty or wildcard scopes are denied by the current action check and must be revoked or allowed to expire before recreating them with explicit scopes.
- `ErrorDomain::SupportAccess` is appended to the error taxonomy. Update client formatters to handle it; existing domain/code values are unchanged.
- Audit events reuse `AuditEventKind::PrivilegedAction`; the audit-ledger schema and existing event-kind codes do not change.

### Storage Migration

- Uses existing persistent storage patterns
- No session-storage schema migration is required

### Role Addition

The `Support` role must be added to the system:

```rust
// Grant Support role to authorized maintainers
grant_role(&env, &admin, &support_address, Role::Support)?;
```

### Permission Registration

The `ImpersonateUser` permission is automatically available through the existing permission system.

### Deployment Steps

1. Deploy updated shared crate with impersonation module
2. Grant `Support` role to authorized maintainers
3. Update monitoring to track impersonation events
4. Train maintainers on proper impersonation procedures
5. Review audit trails after initial deployment

### Rollback and Recovery

1. Stop creating support sessions and revoke active sessions while the tightened checks are deployed.
2. Verify and export the audit ledger, then compare its head with the latest trusted checkpoint.
3. Do not roll back to a version that accepts empty or wildcard scopes while any such session could remain active; that can restore broad access.
4. If a contract snapshot must be restored, restore session state and the audit ledger from the same verified snapshot. Reconcile against external checkpoints before resuming support access.

## Troubleshooting

### Session Creation Fails

**Problem**: `create_session()` returns `Unauthorized`

**Solutions**:
- Verify caller holds `Support` role
- Check that `Permission::ImpersonateUser` is properly configured
- Ensure target user is not an admin

### Actions Blocked During Session

**Problem**: `check_action_permission()` returns `ActionNotPermitted`

**Solutions**:
- Verify the action type matches the session scope
- Check resource scoping if using resource-level restrictions
- Consider escalating scope if action is legitimate

### Dangerous Mutation Blocked

**Problem**: `check_action_permission()` returns `DangerousMutationBlocked`

**Solutions**:
- Verify the action is truly necessary for debugging
- If required, recreate session with `allow_dangerous_mutations: true`
- Consider alternative debugging approaches

### Session Expires Unexpectedly

**Problem**: Session expires before expected time

**Solutions**:
- Check ledger timestamp vs expected expiration
- Verify session duration was set correctly
- Check for ledger time synchronization issues

### Too Many Active Sessions

**Problem**: `create_session()` returns `TooManyActiveSessions`

**Solutions**:
- Revoke unused or completed sessions
- Wait for existing sessions to expire
- Consider increasing `MAX_CONCURRENT_SESSIONS` if needed

## Monitoring and Alerting

### Key Events to Monitor

1. **Session Creation**: `impersonation.session_created`
   - Alert on unusual patterns (e.g., many sessions in short time)
   - Monitor for impersonation of sensitive users

2. **Session Revocation**: `impersonation.session_revoked`
   - Track revocation patterns
   - Alert on frequent revocations

3. **Action Recording**: `impersonation.action_recorded`
   - Monitor for dangerous actions during impersonation
   - Track action counts per session

4. **Session Expiration**: `impersonation.session_expired`
   - Monitor session duration patterns
   - Alert on sessions running to expiration

### Recommended Alerts

- **High session creation rate**: May indicate abuse or system issues
- **Dangerous actions during impersonation**: Requires immediate review
- **Sessions targeting privileged or service accounts**: Should never happen
- **Long-running sessions**: May indicate incomplete debugging

## API Reference

### Core Functions

#### `create_session`

Creates a new impersonation session.

```rust
pub fn create_session(
    env: &Env,
    impersonator: &Address,
    params: SessionParams,
) -> Result<SessionResult, ImpersonationError>
```

#### `validate_session`

Validates and returns an active session if it exists and is not expired.

```rust
pub fn validate_session(
    env: &Env,
    session_id: u64,
) -> Result<ImpersonationSession, ImpersonationError>
```

#### `revoke_session`

Revokes an active impersonation session.

```rust
pub fn revoke_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<(), ImpersonationError>
```

#### `check_action_permission`

Checks if an action is permitted within the session scope.

```rust
pub fn check_action_permission(
    env: &Env,
    session: &ImpersonationSession,
    action_type: ImpersonationAction,
    resource_type: ResourceType,
    resource_id: Option<u64>,
) -> Result<(), ImpersonationError>
```

#### `record_action`

Records an action taken during an impersonation session.

```rust
pub fn record_action(
    env: &Env,
    session_id: u64,
    action_type: ImpersonationAction,
    resource_type: ResourceType,
    resource_id: Option<u64>,
) -> Result<(), ImpersonationError>
```

### Query Functions

#### `is_being_impersonated`

Checks if a user is currently being impersonated.

```rust
pub fn is_being_impersonated(env: &Env, target_user: &Address) -> bool
```

#### `get_current_impersonation`

Gets the current impersonation session for a target user (if any).

```rust
pub fn get_current_impersonation(
    env: &Env,
    target_user: &Address,
) -> Option<ImpersonationSession>
```

#### `get_active_sessions_for_user`

Gets active impersonation sessions for a target user.

```rust
pub fn get_active_sessions_for_user(
    env: &Env,
    target_user: &Address,
) -> Vec<ImpersonationSession>
```

#### `get_active_sessions_for_impersonator`

Gets active impersonation sessions for an impersonator.

```rust
pub fn get_active_sessions_for_impersonator(
    env: &Env,
    impersonator: &Address,
) -> Vec<ImpersonationSession>
```

## Data Structures

### ImpersonationSession

Complete session record with full metadata:

```rust
pub struct ImpersonationSession {
    pub session_id: u64,
    pub impersonator: Address,
    pub target_user: Address,
    pub scope: ImpersonationScope,
    pub resource_scopes: Vec<ResourceScope>,
    pub created_at: u64,
    pub expires_at: u64,
    pub allow_dangerous_mutations: bool,
    pub reason: Symbol,
    pub state: SessionState,
    pub action_count: u32,
}
```

### SessionParams

Parameters for creating a new session:

```rust
pub struct SessionParams {
    pub target_user: Address,
    pub scope: ImpersonationScope,
    pub resource_scopes: Vec<ResourceScope>,
    pub duration_sec: u64,
    pub allow_dangerous_mutations: bool,
    pub reason: Symbol,
}
```

### ImpersonationScope

Permission scope for the session:

```rust
pub enum ImpersonationScope {
    ReadOnly,
    Diagnostic,
    SafeMutations,
    FullAccess,
}
```

### ResourceType

Types of resources that can be scoped:

```rust
pub enum ResourceType {
    Aid,
    Payment,
    Escrow,
    Treasury,
    Roles,
    Config,
    All,
}
```

### ImpersonationAction

Types of actions that can be taken:

```rust
pub enum ImpersonationAction {
    Read,
    Diagnostic,
    SafeMutation,
    DangerousMutation,
    ConfigChange,
    RoleManagement,
    TreasuryOperation,
}
```

## Security Considerations

### Privilege Escalation Prevention

- Privileged and service accounts cannot be impersonated
- Users with roles such as Upgrader, TreasuryManager, Pauser, ReferralManager, OracleSigner, ServiceActor, or Support cannot be impersonated
- Role hierarchy is respected during impersonation

### Data Protection

- Resource scoping limits access to specific data
- Read-only scope prevents any data modification
- Audit trail records all data access

### Action Accountability

- Every action is logged with full context
- Session metadata includes impersonator identity
- Action count tracking helps identify abuse patterns

### Time-Bounded Access

- Sessions automatically expire
- Maximum duration prevents long-term access
- Manual revocation available for immediate termination

## Future Enhancements

Potential future improvements:

1. **Session Templates**: Pre-configured session templates for common debugging scenarios
2. **Approval Workflow**: Require admin approval for high-scope sessions
3. **Session Renewal**: Allow session renewal with proper authorization
4. **Geographic Restrictions**: Limit impersonation based on geographic criteria
5. **Rate Limiting**: Add time-based rate limiting for session creation
6. **Multi-Factor Authentication**: Require additional auth for high-risk sessions

## Contributing

When contributing to the impersonation module:

1. Maintain backward compatibility with existing authorization system
2. Add tests for new features or scope types
3. Update this documentation for API changes
4. Follow existing code style and patterns
5. Ensure security considerations are maintained
6. Add audit events for any new operations

## License

This module is part of the Trellis Contracts project and follows the same license terms.
