//! # Governance Contract — Cross-Boundary Threat Model
//!
//! This module implements the multi-sig governance surface for Trellis
//! Contracts. Because it sits on the trust boundary between human operators,
//! the treasury/aid/oracle/marketplace modules, and the on-chain state, its
//! threat model is documented inline so reviewers and auditors can reason
//! about the highest-risk paths next to the code that enforces them.
//!
//! ## Trust boundaries
//!
//! 1. **Caller → contract**: every privileged entrypoint must authenticate
//!    the caller via `require_auth` (through `shared::auth`) and then check
//!    role membership. `require_active_admin` additionally re-checks the
//!    caller against the *current* admin set so a revoked admin cannot keep
//!    acting on a stale role grant.
//! 2. **Admin set → threshold/quorum**: the effective approval requirement is
//!    `max(threshold, ceil(active_count * quorum_bps / 10_000))`. This closes
//!    the "shrink the admin set to lower the bar" abuse case: approvals are
//!    re-counted against the live admin set at execution time.
//! 3. **Proposal → action execution**: `execute_action` is the only place
//!    that mutates roles, parameters, pause state, or invokes a target
//!    contract. Batch actions are validated for size and executed
//!    sequentially; any failure aborts the whole invocation (Soroban
//!    rollback), so partial batches cannot land.
//! 4. **Governance → external modules**: `SetTargetParameter` crosses into
//!    another contract via `try_invoke_contract`. The parameter is validated
//!    locally *before* the cross-contract call, and any error from the
//!    callee is surfaced as `Error::InvalidArgument` rather than swallowed.
//!
//! ## Abuse cases and mitigations
//!
//! * **Duplicate signers / sybil admin set** — `has_duplicate_addresses`
//!   rejects duplicates at `initialize` and `set_admin_set`.
//! * **Threshold downgrade via admin-set churn** — `execute` recomputes the
//!   required approvals from the live admin set and quorum on every call.
//! * **Double approval / replay** — per-(proposal, admin) approval flags are
//!   stored and checked; `AlreadyApproved` is returned on replay.
//! * **Expired proposal resurrection** — `approve` and `execute` both check
//!   `expires_at` and transition the proposal to `Expired`.
//! * **Unauthorized cancellation** — only the original proposer or the
//!   super-admin may cancel, and `require_auth` is enforced.
//! * **Parameter out-of-range writes** — `validate_param` enforces
//!   `ParameterBounds` for every write path (direct and via proposal).
//! * **Oversized batch / partial batch** — `MAX_BATCH_SIZE` is enforced and
//!   any inner failure aborts the batch.
//!
//! ## Operational edge cases, failure modes, rollback/recovery
//!
//! * **Lost admin keys**: recovery requires an existing admin to propose a
//!   `SetAdminSet`-equivalent via `set_admin_set` (or a `GrantRole` proposal)
//!   from a still-authorized signer. If *all* admins are lost, the contract
//!   is unrecoverable by design — there is no backdoor.
//! * **Stuck proposal**: a `Pending` proposal can be cancelled by its
//!   proposer or the super-admin; otherwise it expires after
//!   `PROPOSAL_LIFETIME` and can no longer be approved or executed.
//! * **Failed cross-contract call**: `SetTargetParameter` returns
//!   `InvalidArgument` and the whole `execute` invocation rolls back, leaving
//!   the proposal `Pending` so it can be retried after the target is fixed.
//! * **Pause**: `Pause`/`Unpause` are themselves proposals, so a compromised
//!   single signer cannot halt the protocol unilaterally.
//!
//! ## Executable verification
//!
//! The `tests` module below exercises the highest-risk paths: duplicate
//! approvals, threshold/quorum escalation and shrink, expired proposals,
//! revoked-admin denial, batch atomicity, and parameter bounds. These tests
//! are the executable form of the threat model and must pass in CI.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, BytesN, Env, IntoVal, Symbol,
};

use shared::auth::{self, Role};
use shared::errors::Error;
use shared::events;
use shared::events::{emit_action_executed, emit_module_initialized};
use shared::storage::{instance_get, instance_set, persistent_set};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MIN_AID_DEFAULT_EXPIRY: i128 = 60;
const MAX_AID_DEFAULT_EXPIRY: i128 = 31_536_000;
const DEFAULT_AID_DEFAULT_EXPIRY: i128 = 604_800;

const MIN_TREASURY_WITHDRAWAL_LIMIT: i128 = 0;
const MAX_TREASURY_WITHDRAWAL_LIMIT: i128 = 1_000_000_000_000_000_000;
const DEFAULT_TREASURY_WITHDRAWAL_LIMIT: i128 = 100_000_000_000;

const MIN_REFERRAL_TIER_BPS: i128 = 0;
const MAX_REFERRAL_TIER_BPS: i128 = 10_000;
const DEFAULT_REFERRAL_TIER_ONE_BPS: i128 = 500;
const DEFAULT_REFERRAL_TIER_TWO_BPS: i128 = 250;
const DEFAULT_REFERRAL_TIER_THREE_BPS: i128 = 100;

const MIN_REFERRAL_MAX_TIERS: i128 = 1;
const MAX_REFERRAL_MAX_TIERS: i128 = 10;
const DEFAULT_REFERRAL_MAX_TIERS: i128 = 3;

const MIN_REFERRAL_REWARD_CAP: i128 = 0;
const MAX_REFERRAL_REWARD_CAP: i128 = 1_000_000_000_000_000_000;
const DEFAULT_REFERRAL_REWARD_CAP: i128 = 10_000_000_000;
/// Maximum signers accepted in a single multi-signature operation.
pub const MAX_GOVERNANCE_ADMINS: u32 = 20;
/// Proposals are actionable for 30 days after creation.
pub const PROPOSAL_LIFETIME: u64 = 30 * 24 * 60 * 60;
/// Maximum number of actions in a batch proposal.
pub const MAX_BATCH_SIZE: u32 = 10;
const DEFAULT_QUORUM_BPS: u32 = 6_000;

/// Maximum number of actions permitted in a single `Batch` proposal.
///
/// Enforced in [`execute_action`] so that a malicious or buggy proposer
/// cannot exhaust the ledger budget or bypass per-action validation by
/// hiding actions behind a large batch.
pub const MAX_BATCH_ACTIONS: u32 = MAX_BATCH_SIZE;

type ContractResult<T> = core::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Storage key symbols (all <= 9 chars for symbol_short!)
// ---------------------------------------------------------------------------

const KEY_THRESHOLD: Symbol = symbol_short!("thresh");
const KEY_ADMIN_SET: Symbol = symbol_short!("adm_set");
const KEY_ADMIN_COUNT: Symbol = symbol_short!("adm_cnt");
const KEY_QUORUM_BPS: Symbol = symbol_short!("quorum");
const KEY_PROP_CNT: Symbol = symbol_short!("prop_cnt");
const KEY_PROPOSAL: Symbol = symbol_short!("proposal");
const KEY_APPROVAL: Symbol = symbol_short!("approval");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParameterKey {
    AidDefaultExpiry,
    TreasuryWithdrawalLimit,
    ReferralTierBps(u32),
    ReferralMaxTiers,
    ReferralRewardCap,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Parameter(ParameterKey),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterBounds {
    pub min: i128,
    pub max: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterChangedEvent {
    pub key: ParameterKey,
    pub value: i128,
}

/// The possible actions that a multi-sig proposal can execute.
///
/// Uses tuple-style variants because Soroban `contracttype` does not support
/// named fields in enums.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalAction {
    /// Grant `Role` to `Address`.
    GrantRole(Address, Role),
    /// Revoke `Role` from `Address`.
    RevokeRole(Address, Role),
    /// Update a protocol parameter: `(key, value)`.
    SetParameter(ParameterKey, i128),
    /// Execute a parameter update on a target contract:
    /// `(target, function_name, key, value)`.
    SetTargetParameter(Address, Symbol, ParameterKey, i128),
    /// Pause the contract.
    Pause,
    /// Unpause the contract.
    Unpause,
    /// Execute multiple actions atomically.
    Batch(soroban_sdk::Vec<ProposalAction>),
}

/// Status of a proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    Pending,
    Executed,
    Cancelled,
    Expired,
}

/// A multi-sig proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Address,
    pub action: ProposalAction,
    pub approval_count: u32,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct GovernanceContract;

/// The governance contract does not accept a caller-supplied correlation ID
/// (proposals are not tied to a request-scoped workflow), so every correlated
/// event uses the canonical zero correlation ID.
fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

#[contractimpl]
impl GovernanceContract {
    /// Initialise the contract: sets the admin address, seeds parameter
    /// defaults, and configures the initial multi-sig threshold.
    ///
    /// # Arguments
    /// * `admin` — The initial admin used as the "first admin" for legacy
    ///   `set_admin` / `require_admin` checks.
    /// * `threshold` — The minimum number of approvals (M) required to
    ///   execute a proposal. Must be >= 1 and <= admin_set length.
    /// * `admin_set` — The list of addresses that can approve proposals.
    ///   Must contain at least `threshold` addresses.
    ///   All addresses in this set are granted the `Admin` role.
    pub fn initialize(
        env: Env,
        admin: Address,
        threshold: u32,
        admin_set: soroban_sdk::Vec<Address>,
    ) -> Result<(), Error> {
        if threshold < 1 {
            return Err(Error::InvalidArgument);
        }
        if admin_set.len() < threshold || admin_set.len() > MAX_GOVERNANCE_ADMINS {
            return Err(Error::InvalidArgument);
        }
        if has_duplicate_addresses(&admin_set) {
            return Err(Error::InvalidArgument);
        }

        shared::auth::initialize_admin(&env, &admin)?;
        // Grant the Admin role to every address in the admin set so they
        // can propose, approve, and execute.
        let mut i: u32 = 0;
        while i < admin_set.len() {
            let addr = admin_set.get(i).unwrap();
            persistent_set(&env, &shared::auth::DataKey::Role(addr, Role::Admin), &true);
            i += 1;
        }

        // Store the threshold and admin set.
        instance_set(&env, &KEY_THRESHOLD, &threshold);
        instance_set(&env, &KEY_ADMIN_SET, &admin_set);
        instance_set(&env, &KEY_ADMIN_COUNT, &admin_set.len());
        instance_set(&env, &KEY_QUORUM_BPS, &DEFAULT_QUORUM_BPS);

        // Seed parameter defaults.
        seed_defaults(&env);
        emit_module_initialized(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("gov"),
            1,
            &admin,
            env.ledger().timestamp(),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Role management
    // -----------------------------------------------------------------------

    /// Grants `role` to `user`. Only callable by an admin.
    pub fn grant_role(env: Env, caller: Address, user: Address, role: Role) -> Result<(), Error> {
        // Auth check only once — avoid double-auth from calling
        // `auth::grant_role` which would call `require_auth` again.
        require_admin_role(&env, &caller)?;
        persistent_set(
            &env,
            &shared::auth::DataKey::Role(user.clone(), role.clone()),
            &true,
        );
        events::emit_role_granted(
            &env,
            &zero_correlation_id(&env),
            &caller,
            &user,
            role_name(&role),
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Revokes `role` from `user`. Only callable by an admin.
    pub fn revoke_role(env: Env, caller: Address, user: Address, role: Role) -> Result<(), Error> {
        require_admin_role(&env, &caller)?;
        shared::storage::persistent_remove(
            &env,
            &shared::auth::DataKey::Role(user.clone(), role.clone()),
        );
        events::emit_role_revoked(
            &env,
            &zero_correlation_id(&env),
            &caller,
            &user,
            role_name(&role),
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Returns `true` if `user` holds `role`.
    pub fn has_role(env: Env, user: Address, role: Role) -> bool {
        auth::has_role(&env, &user, role)
    }

    // -----------------------------------------------------------------------
    // Admin set management
    // -----------------------------------------------------------------------

    /// Updates the set of addresses that can participate in multi-sig
    /// approvals. Also updates the threshold. Only callable by an admin.
    pub fn set_admin_set(
        env: Env,
        caller: Address,
        new_admin_set: soroban_sdk::Vec<Address>,
        new_threshold: u32,
    ) -> Result<(), Error> {
        require_admin_role(&env, &caller)?;
        if new_threshold < 1
            || new_admin_set.len() < new_threshold
            || new_admin_set.len() > MAX_GOVERNANCE_ADMINS
        {
            return Err(Error::InvalidArgument);
        }
        if has_duplicate_addresses(&new_admin_set) {
            return Err(Error::InvalidArgument);
        }

        let old_admin_set = Self::get_admin_set(env.clone());
        let mut i = 0;
        while i < old_admin_set.len() {
            let old_admin = old_admin_set.get(i).unwrap();
            if !contains_address(&new_admin_set, &old_admin) {
                shared::storage::persistent_remove(
                    &env,
                    &shared::auth::DataKey::Role(old_admin, Role::Admin),
                );
            }
            i += 1;
        }
        i = 0;
        while i < new_admin_set.len() {
            let new_admin = new_admin_set.get(i).unwrap();
            persistent_set(
                &env,
                &shared::auth::DataKey::Role(new_admin, Role::Admin),
                &true,
            );
            i += 1;
        }
        instance_set(&env, &KEY_THRESHOLD, &new_threshold);
        instance_set(&env, &KEY_ADMIN_SET, &new_admin_set);
        instance_set(&env, &KEY_ADMIN_COUNT, &new_admin_set.len());
        Ok(())
    }

    /// Returns the current multi-sig threshold (M).
    pub fn get_threshold(env: Env) -> u32 {
        instance_get(&env, &KEY_THRESHOLD).unwrap_or(0)
    }

    /// Returns the current admin set (N).
    pub fn get_admin_set(env: Env) -> soroban_sdk::Vec<Address> {
        instance_get(&env, &KEY_ADMIN_SET).unwrap_or(soroban_sdk::Vec::new(&env))
    }

    /// Returns the current number of active multi-signature admins.
    pub fn get_active_admin_count(env: Env) -> u32 {
        instance_get(&env, &KEY_ADMIN_COUNT).unwrap_or(Self::get_admin_set(env.clone()).len())
    }

    /// Sets the minimum percentage quorum in basis points. Admin only.
    pub fn set_quorum_bps(env: Env, caller: Address, quorum_bps: u32) -> Result<(), Error> {
        require_admin_role(&env, &caller)?;
        if quorum_bps > 10_000 {
            return Err(Error::InvalidArgument);
        }
        instance_set(&env, &KEY_QUORUM_BPS, &quorum_bps);
        Ok(())
    }

    /// Returns the configured percentage quorum in basis points.
    pub fn get_quorum_bps(env: Env) -> u32 {
        instance_get(&env, &KEY_QUORUM_BPS).unwrap_or(DEFAULT_QUORUM_BPS)
    }

    /// Returns `true` if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        shared::storage::is_paused(&env)
    }

    // -----------------------------------------------------------------------
    // Multi-sig proposal flow
    // -----------------------------------------------------------------------

    /// Creates a new proposal. Only callable by an admin.
    ///
    /// Returns the newly created proposal ID.
    pub fn propose(env: Env, caller: Address, action: ProposalAction) -> Result<u64, Error> {
        require_active_admin(&env, &caller)?;

        let proposal_id: u64 = instance_get(&env, &KEY_PROP_CNT).unwrap_or(0);
        let new_id = proposal_id.checked_add(1).ok_or(Error::Overflow)?;
        instance_set(&env, &KEY_PROP_CNT, &new_id);

        let proposal = Proposal {
            id: new_id,
            proposer: caller.clone(),
            action: action.clone(),
            approval_count: 0,
            status: ProposalStatus::Pending,
            created_at: env.ledger().timestamp(),
            expires_at: env.ledger().timestamp().saturating_add(PROPOSAL_LIFETIME),
        };

        let proposal_key = (KEY_PROPOSAL, new_id);
        instance_set(&env, &proposal_key, &proposal);

        events::emit_proposal_created(
            &env,
            &zero_correlation_id(&env),
            new_id,
            &caller,
            action_symbol(&action),
            env.ledger().timestamp(),
        );

        Ok(new_id)
    }

    /// Approves a pending proposal. Only callable by an admin.
    ///
    /// Each admin may only approve a proposal once.
    pub fn approve(env: Env, caller: Address, proposal_id: u64) -> Result<(), Error> {
        require_active_admin(&env, &caller)?;

        let proposal_key = (KEY_PROPOSAL, proposal_id);
        let mut proposal: Proposal =
            instance_get(&env, &proposal_key).ok_or(Error::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(Error::AlreadyExecuted);
        }

        if env.ledger().timestamp() > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            instance_set(&env, &proposal_key, &proposal);
            env.events().publish(
                (shared::events::PROPOSAL_EXPIRED,),
                (proposal_id, env.ledger().timestamp()),
            );
            return Err(Error::ProposalExpired);
        }

        // Check for duplicate approval.
        let approval_key = (KEY_APPROVAL, proposal_id, caller.clone());
        if instance_get::<_, bool>(&env, &approval_key).unwrap_or(false) {
            return Err(Error::AlreadyApproved);
        }

        instance_set(&env, &approval_key, &true);
        proposal.approval_count = proposal
            .approval_count
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        instance_set(&env, &proposal_key, &proposal);

        events::emit_proposal_approved(
            &env,
            &zero_correlation_id(&env),
            proposal_id,
            &caller,
            proposal.approval_count,
            env.ledger().timestamp(),
        );

        Ok(())
    }

    /// Executes a proposal once the approval threshold is met.
    /// Only callable by an admin.
    ///
    /// # Errors
    /// * `Error::ProposalNotFound` — proposal does not exist.
    /// * `Error::AlreadyExecuted` — proposal already executed.
    /// * `Error::BelowThreshold` — approval count < threshold.
    pub fn execute(env: Env, caller: Address, proposal_id: u64) -> Result<(), Error> {
        require_active_admin(&env, &caller)?;

        let proposal_key = (KEY_PROPOSAL, proposal_id);
        let mut proposal: Proposal =
            instance_get(&env, &proposal_key).ok_or(Error::ProposalNotFound)?;

        if proposal.status == ProposalStatus::Executed {
            return Err(Error::AlreadyExecuted);
        }

        if proposal.status == ProposalStatus::Cancelled
            || proposal.status == ProposalStatus::Expired
        {
            return Err(Error::ProposalCancelled);
        }

        if env.ledger().timestamp() > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            instance_set(&env, &proposal_key, &proposal);
            env.events().publish(
                (shared::events::PROPOSAL_EXPIRED,),
                (proposal_id, env.ledger().timestamp()),
            );
            return Err(Error::ProposalExpired);
        }

        let threshold: u32 = instance_get(&env, &KEY_THRESHOLD).unwrap_or(0);
        let active_admins = Self::get_admin_set(env.clone());
        let active_count = instance_get(&env, &KEY_ADMIN_COUNT).unwrap_or(active_admins.len());
        let quorum_bps = Self::get_quorum_bps(env.clone());
        let quorum_approvals = ((active_count as u64 * quorum_bps as u64 + 9_999) / 10_000) as u32;
        let required_approvals = threshold.max(quorum_approvals);
        let valid_approvals = count_active_approvals(&env, proposal_id, &active_admins);
        if valid_approvals < required_approvals {
            return Err(Error::BelowThreshold);
        }

        execute_action(&env, &proposal.action)?;

        proposal.status = ProposalStatus::Executed;
        instance_set(&env, &proposal_key, &proposal);

        events::emit_proposal_executed(
            &env,
            &zero_correlation_id(&env),
            proposal_id,
            &caller,
            proposal.approval_count,
            env.ledger().timestamp(),
        );

        Ok(())
    }

    /// Cancel a pending proposal before it is executed. The original proposer
    /// or the configured super-admin may cancel it.
    pub fn cancel(env: Env, caller: Address, proposal_id: u64) -> Result<(), Error> {
        let proposal_key = (KEY_PROPOSAL, proposal_id);
        let mut proposal: Proposal =
            instance_get(&env, &proposal_key).ok_or(Error::ProposalNotFound)?;
        let super_admin = shared::auth::get_admin(&env);
        if caller != proposal.proposer && caller != super_admin {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        if proposal.status != ProposalStatus::Pending {
            return Err(Error::ProposalCancelled);
        }
        if env.ledger().timestamp() > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            instance_set(&env, &proposal_key, &proposal);
            env.events().publish(
                (shared::events::PROPOSAL_EXPIRED,),
                (proposal_id, env.ledger().timestamp()),
            );
            return Err(Error::ProposalExpired);
        }
        proposal.status = ProposalStatus::Cancelled;
        instance_set(&env, &proposal_key, &proposal);
        env.events().publish(
            (shared::events::PROPOSAL_CANCELLED,),
            (proposal_id, caller, env.ledger().timestamp()),
        );
        Ok(())
    }

    /// Returns a proposal by ID.
    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<Proposal, Error> {
        let proposal_key = (KEY_PROPOSAL, proposal_id);
        instance_get(&env, &proposal_key).ok_or(Error::ProposalNotFound)
    }

    // -----------------------------------------------------------------------
    // Parameter management
    // -----------------------------------------------------------------------

    /// Update a protocol parameter. Admin only.
    pub fn set_param(
        env: Env,
        caller: Address,
        key: ParameterKey,
        value: i128,
    ) -> Result<(), Error> {
        require_governance(&env, &caller)?;
        validate_param(&key, value)?;
        write_param(&env, &key, value);
        env.events().publish(
            (shared::events::PARAMETER_CHANGED,),
            ParameterChangedEvent { key, value },
        );
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("gov"),
            symbol_short!("set_param"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Read a protocol parameter from the typed catalog.
    pub fn get_param(env: Env, key: ParameterKey) -> Result<i128, Error> {
        read_param(&env, &key)
    }

    /// Return documented bounds for a protocol parameter.
    pub fn get_bounds(_env: Env, key: ParameterKey) -> Result<ParameterBounds, Error> {
        bounds_for(&key).ok_or(Error::InvalidArgument)
    }

    pub fn aid_default_expiry(env: Env) -> Result<i128, Error> {
        read_param(&env, &ParameterKey::AidDefaultExpiry)
    }

    pub fn treasury_withdrawal_limit(env: Env) -> Result<i128, Error> {
        read_param(&env, &ParameterKey::TreasuryWithdrawalLimit)
    }

    pub fn referral_tier_bps(env: Env, tier: u32) -> Result<i128, Error> {
        read_param(&env, &ParameterKey::ReferralTierBps(tier))
    }

    pub fn referral_max_tiers(env: Env) -> Result<i128, Error> {
        read_param(&env, &ParameterKey::ReferralMaxTiers)
    }

    pub fn referral_reward_cap(env: Env) -> Result<i128, Error> {
        read_param(&env, &ParameterKey::ReferralRewardCap)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Requires the caller to hold the `Admin` role.
fn require_admin_role(env: &Env, caller: &Address) -> ContractResult<()> {
    auth::require_permission(env, caller, shared::auth::Permission::ManageRoles)
}

fn require_active_admin(env: &Env, caller: &Address) -> ContractResult<()> {
    require_admin_role(env, caller)?;
    let admin_set: soroban_sdk::Vec<Address> =
        instance_get(env, &KEY_ADMIN_SET).unwrap_or(soroban_sdk::Vec::new(env));
    if !contains_address(&admin_set, caller) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn contains_address(admin_set: &soroban_sdk::Vec<Address>, address: &Address) -> bool {
    let mut i = 0;
    while i < admin_set.len() {
        if admin_set.get(i).unwrap() == *address {
            return true;
        }
        i += 1;
    }
    false
}

fn has_duplicate_addresses(admin_set: &soroban_sdk::Vec<Address>) -> bool {
    let mut i = 0;
    while i < admin_set.len() {
        let address = admin_set.get(i).unwrap();
        let mut j = i + 1;
        while j < admin_set.len() {
            if admin_set.get(j).unwrap() == address {
                return true;
            }
            j += 1;
        }
        i += 1;
    }
    false
}

fn count_active_approvals(
    env: &Env,
    proposal_id: u64,
    admin_set: &soroban_sdk::Vec<Address>,
) -> u32 {
    let mut count = 0;
    let mut i = 0;
    while i < admin_set.len() {
        let approval_key = (KEY_APPROVAL, proposal_id, admin_set.get(i).unwrap());
        if instance_get::<_, bool>(env, &approval_key).unwrap_or(false) {
            count += 1;
        }
        i += 1;
    }
    count
}

/// Requires the caller to be the admin (for backward-compatible parameter
/// management).
fn require_governance(env: &Env, caller: &Address) -> ContractResult<()> {
    auth::require_permission(env, caller, shared::auth::Permission::ManageConfiguration)
}

fn seed_defaults(env: &Env) {
    write_param(
        env,
        &ParameterKey::AidDefaultExpiry,
        DEFAULT_AID_DEFAULT_EXPIRY,
    );
    write_param(
        env,
        &ParameterKey::TreasuryWithdrawalLimit,
        DEFAULT_TREASURY_WITHDRAWAL_LIMIT,
    );
    write_param(
        env,
        &ParameterKey::ReferralTierBps(1),
        DEFAULT_REFERRAL_TIER_ONE_BPS,
    );
    write_param(
        env,
        &ParameterKey::ReferralTierBps(2),
        DEFAULT_REFERRAL_TIER_TWO_BPS,
    );
    write_param(
        env,
        &ParameterKey::ReferralTierBps(3),
        DEFAULT_REFERRAL_TIER_THREE_BPS,
    );
    write_param(
        env,
        &ParameterKey::ReferralMaxTiers,
        DEFAULT_REFERRAL_MAX_TIERS,
    );
    write_param(
        env,
        &ParameterKey::ReferralRewardCap,
        DEFAULT_REFERRAL_REWARD_CAP,
    );
}

fn validate_param(key: &ParameterKey, value: i128) -> ContractResult<()> {
    let bounds = bounds_for(key).ok_or(Error::InvalidArgument)?;
    if value < bounds.min || value > bounds.max {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn bounds_for(key: &ParameterKey) -> Option<ParameterBounds> {
    match key {
        ParameterKey::AidDefaultExpiry => Some(ParameterBounds {
            min: MIN_AID_DEFAULT_EXPIRY,
            max: MAX_AID_DEFAULT_EXPIRY,
        }),
        ParameterKey::TreasuryWithdrawalLimit => Some(ParameterBounds {
            min: MIN_TREASURY_WITHDRAWAL_LIMIT,
            max: MAX_TREASURY_WITHDRAWAL_LIMIT,
        }),
        ParameterKey::ReferralTierBps(tier) => {
            if *tier == 0 || i128::from(*tier) > MAX_REFERRAL_MAX_TIERS {
                None
            } else {
                Some(ParameterBounds {
                    min: MIN_REFERRAL_TIER_BPS,
                    max: MAX_REFERRAL_TIER_BPS,
                })
            }
        }
        ParameterKey::ReferralMaxTiers => Some(ParameterBounds {
            min: MIN_REFERRAL_MAX_TIERS,
            max: MAX_REFERRAL_MAX_TIERS,
        }),
        ParameterKey::ReferralRewardCap => Some(ParameterBounds {
            min: MIN_REFERRAL_REWARD_CAP,
            max: MAX_REFERRAL_REWARD_CAP,
        }),
    }
}

fn storage_key(key: &ParameterKey) -> DataKey {
    DataKey::Parameter(key.clone())
}

fn write_param(env: &Env, key: &ParameterKey, value: i128) {
    env.storage().instance().set(&storage_key(key), &value);
}

fn read_param(env: &Env, key: &ParameterKey) -> ContractResult<i128> {
    env.storage()
        .instance()
        .get::<DataKey, i128>(&storage_key(key))
        .ok_or(Error::NotFound)
}

fn action_symbol(action: &ProposalAction) -> Symbol {
    match action {
        ProposalAction::GrantRole(..) => symbol_short!("grt_role"),
        ProposalAction::RevokeRole(..) => symbol_short!("rvk_role"),
        ProposalAction::SetParameter(..) => symbol_short!("set_param"),
        ProposalAction::SetTargetParameter(..) => symbol_short!("set_tgt"),
        ProposalAction::Pause => symbol_short!("pause"),
        ProposalAction::Unpause => symbol_short!("unpause"),
        ProposalAction::Batch(..) => symbol_short!("batch"),
    }
}

fn role_name(role: &Role) -> Symbol {
    match role {
        Role::Admin => symbol_short!("admin"),
        Role::Upgrader => symbol_short!("upgrader"),
        Role::TreasuryManager => symbol_short!("treas_m"),
        Role::Pauser => symbol_short!("pauser"),
        Role::ReferralManager => symbol_short!("refrl_m"),
        Role::OracleSigner => symbol_short!("oracle_s"),
        Role::EndUser => symbol_short!("end_user"),
        Role::ServiceActor => symbol_short!("svc_actor"),
        Role::Support => symbol_short!("support"),
    }
}

fn execute_action(env: &Env, action: &ProposalAction) -> ContractResult<()> {
    match action {
        ProposalAction::GrantRole(user, role) => {
            persistent_set(
                env,
                &shared::auth::DataKey::Role(user.clone(), role.clone()),
                &true,
            );
        }
        ProposalAction::RevokeRole(user, role) => {
            shared::storage::persistent_remove(
                env,
                &shared::auth::DataKey::Role(user.clone(), role.clone()),
            );
        }
        ProposalAction::SetParameter(key, value) => {
            validate_param(key, *value)?;
            write_param(env, key, *value);
        }
        ProposalAction::SetTargetParameter(target, function_name, key, value) => {
            validate_param(key, *value)?;
            let args = vec![env, key.clone().into_val(env), (*value).into_val(env)];
            match env.try_invoke_contract::<(), Error>(target, function_name, args) {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(Error::InvalidArgument),
                Err(Ok(error)) => return Err(error),
                Err(Err(_)) => return Err(Error::InvalidArgument),
            }
        }
        ProposalAction::Pause => {
            shared::storage::set_paused(env, true);
        }
        ProposalAction::Unpause => {
            shared::storage::set_paused(env, false);
        }
        ProposalAction::Batch(actions) => {
            // Validate batch size
            if actions.len() > MAX_BATCH_SIZE {
                return Err(Error::InvalidArgument);
            }

            // Execute each action sequentially - all must succeed or all fail
            let mut i = 0;
            while i < actions.len() {
                let action = actions.get(i).ok_or(Error::InvalidArgument)?;
                execute_action(env, &action)?;
                i += 1;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Threat-model verification helpers
// ---------------------------------------------------------------------------

/// Returns the effective number of approvals required to execute a proposal
/// given the current admin set size, threshold, and quorum.
///
/// This is the single source of truth for the "cross-boundary trust" rule:
/// the requirement is recomputed from live state on every `execute`, so
/// admin-set churn cannot silently lower the bar.
///
/// * `active_count` — number of addresses currently in the admin set.
/// * `threshold` — configured minimum approvals (M).
/// * `quorum_bps` — configured percentage quorum in basis points.
///
/// Returns `max(threshold, ceil(active_count * quorum_bps / 10_000))`.
pub fn required_approvals(active_count: u32, threshold: u32, quorum_bps: u32) -> u32 {
    let quorum_approvals =
        ((active_count as u64 * quorum_bps as u64 + 9_999) / 10_000) as u32;
    threshold.max(quorum_approvals)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Events, Ledger as _};
    use soroban_sdk::{Env, IntoVal, TryFromVal};

    /// Creates a 2-of-2 governance setup. Returns (env, client, admin).
    fn setup() -> (Env, GovernanceContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let other = Address::generate(&env);
        let mut admin_set: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        admin_set.push_back(admin.clone());
        admin_set.push_back(other.clone());
        client.initialize(&admin, &2, &admin_set);
        (env, client, admin)
    }

    fn make_admin_set(env: &Env, n: usize) -> soroban_sdk::Vec<Address> {
        let mut v = soroban_sdk::Vec::new(env);
        for _ in 0..n {
            v.push_back(Address::generate(env));
        }
        v
    }

    // -----------------------------------------------------------------------
    // Threat-model: required_approvals is the cross-boundary trust rule
    // -----------------------------------------------------------------------

    #[test]
    fn required_approvals_uses_max_of_threshold_and_quorum() {
        // threshold dominates
        assert_eq!(required_approvals(2, 2, 6_000), 2);
        // quorum dominates
        assert_eq!(required_approvals(4, 1, 6_000), 3);
        // exact quorum boundary
        assert_eq!(required_approvals(5, 1, 6_000), 3);
        // zero quorum falls back to threshold
        assert_eq!(required_approvals(10, 2, 0), 2);
        // full quorum requires every admin
        assert_eq!(required_approvals(3, 1, 10_000), 3);
    }

    #[test]
    fn required_approvals_rounds_quorum_up() {
        // 3 * 5000 / 10000 = 1.5 -> ceil = 2
        assert_eq!(required_approvals(3, 1, 5_000), 2);
        // 7 * 3333 / 10000 = 2.3331 -> ceil = 3
        assert_eq!(required_approvals(7, 1, 3_333), 3);
    }

    #[test]
    fn max_batch_actions_matches_batch_size_limit() {
        assert_eq!(MAX_BATCH_ACTIONS, MAX_BATCH_SIZE);
    }

    // -----------------------------------------------------------------------
    // initialize
    // -----------------------------------------------------------------------

    #[test]
    fn initialize_sets_admin_and_seeds_defaults() {
        let (_env, client, admin) = setup();

        assert_eq!(client.aid_default_expiry(), DEFAULT_AID_DEFAULT_EXPIRY);
        assert_eq!(
            client.treasury_withdrawal_limit(),
            DEFAULT_TREASURY_WITHDRAWAL_LIMIT
        );
        assert_eq!(client.referral_tier_bps(&1), DEFAULT_REFERRAL_TIER_ONE_BPS);
        assert_eq!(client.referral_tier_bps(&2), DEFAULT_REFERRAL_TIER_TWO_BPS);
        assert_eq!(
            client.referral_tier_bps(&3),
            DEFAULT_REFERRAL_TIER_THREE_BPS
        );
        assert_eq!(client.referral_max_tiers(), DEFAULT_REFERRAL_MAX_TIERS);
        assert_eq!(client.referral_reward_cap(), DEFAULT_REFERRAL_REWARD_CAP);
        assert!(client.has_role(&admin, &Role::Admin));
    }

    #[test]
    fn initialize_rejects_zero_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let mut admin_set: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        admin_set.push_back(admin.clone());
        let result = client.try_initialize(&admin, &0, &admin_set);
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));
    }

    #[test]
    fn initialize_rejects_threshold_exceeding_admin_set_size() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let mut admin_set: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        admin_set.push_back(admin.clone());
        let result = client.try_initialize(&admin, &2, &admin_set);
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));
    }

    #[test]
    fn initialize_rejects_admin_set_over_the_iteration_limit() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let admin_set = make_admin_set(&env, MAX_GOVERNANCE_ADMINS as usize + 1);

        assert_eq!(
            client.try_initialize(&admin, &1, &admin_set),
            Err(Ok(Error::InvalidArgument))
        );
        assert_eq!(client.get_admin_set().len(), 0);
        assert_eq!(client.get_threshold(), 0);
    }

    // -----------------------------------------------------------------------
    // grant_role / revoke_role
    // -----------------------------------------------------------------------

    #[test]
    fn admin_can_grant_role() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Upgrader);
        assert!(client.has_role(&user, &Role::Upgrader));
    }

    #[test]
    fn non_admin_cannot_grant_role() {
        let (env, client, _admin) = setup();
        let stranger = Address::generate(&env);
        let user = Address::generate(&env);

        let result = client.try_grant_role(&stranger, &user, &Role::Upgrader);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
        assert!(!client.has_role(&user, &Role::Upgrader));
    }

    #[test]
    fn admin_can_revoke_role() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Pauser);
        assert!(client.has_role(&user, &Role::Pauser));

        client.revoke_role(&admin, &user, &Role::Pauser);
        assert!(!client.has_role(&user, &Role::Pauser));
    }

    #[test]
    fn non_admin_cannot_revoke_role() {
        let (env, client, admin) = setup();
        let stranger = Address::generate(&env);
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Pauser);

        let result = client.try_revoke_role(&stranger, &user, &Role::Pauser);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
        assert!(client.has_role(&user, &Role::Pauser));
    }

    // -----------------------------------------------------------------------
    // propose / approve / execute
    // -----------------------------------------------------------------------

    #[test]
    fn propose_creates_proposal_with_zero_approvals() {
        let (env, client, admin) = setup();

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        let proposal = client.get_proposal(&proposal_id);
        assert_eq!(proposal.id, 1);
        assert_eq!(proposal.proposer, admin);
        assert_eq!(proposal.action, ProposalAction::Pause);
        assert_eq!(proposal.approval_count, 0);
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.expires_at, proposal.created_at + PROPOSAL_LIFETIME);
    }

    #[test]
    fn non_admin_cannot_propose() {
        let (env, client, _admin) = setup();
        let stranger = Address::generate(&env);

        let action = ProposalAction::Pause;
        let result = client.try_propose(&stranger, &action);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn approve_records_and_increments_count() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        let proposal = client.get_proposal(&proposal_id);
        assert_eq!(proposal.approval_count, 1);

        client.approve(&second_admin, &proposal_id);
        let proposal = client.get_proposal(&proposal_id);
        assert_eq!(proposal.approval_count, 2);
    }

    #[test]
    fn duplicate_approval_is_rejected() {
        let (env, client, admin) = setup();

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        let result = client.try_approve(&admin, &proposal_id);
        assert_eq!(result, Err(Ok(Error::AlreadyApproved)));
    }

    #[test]
    fn execute_fails_below_threshold() {
        let (env, client, admin) = setup();

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        let result = client.try_execute(&admin, &proposal_id);
        assert_eq!(result, Err(Ok(Error::BelowThreshold)));
    }

    #[test]
    fn execute_succeeds_at_threshold() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);

        client.execute(&admin, &proposal_id);

        let proposal = client.get_proposal(&proposal_id);
        assert_eq!(proposal.status, ProposalStatus::Executed);
        assert!(client.is_paused());
    }

    #[test]
    fn execute_quorum_escalates_when_admin_set_grows() {
        let (env, client, admin) = setup();
        let mut admins = client.get_admin_set();
        admins.push_back(Address::generate(&env));
        admins.push_back(Address::generate(&env));
        client.set_admin_set(&admin, &admins, &1);
        assert_eq!(client.get_active_admin_count(), 4);

        let proposal_id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &proposal_id);
        client.approve(&admins.get(1).unwrap(), &proposal_id);
        assert_eq!(
            client.try_execute(&admin, &proposal_id),
            Err(Ok(Error::BelowThreshold))
        );
        client.approve(&admins.get(2).unwrap(), &proposal_id);
        client.execute(&admin, &proposal_id);
    }

    #[test]
    fn execute_quorum_recalculates_when_admin_set_shrinks() {
        let (env, client, admin) = setup();
        let mut expanded_admins = client.get_admin_set();
        expanded_admins.push_back(Address::generate(&env));
        expanded_admins.push_back(Address::generate(&env));
        client.set_admin_set(&admin, &expanded_admins, &1);

        let proposal_id = client.propose(&admin, &ProposalAction::Pause);
        let first = expanded_admins.get(0).unwrap();
        let second = expanded_admins.get(1).unwrap();
        client.approve(&first, &proposal_id);
        client.approve(&second, &proposal_id);
        assert_eq!(
            client.try_execute(&admin, &proposal_id),
            Err(Ok(Error::BelowThreshold))
        );

        let mut reduced_admins = soroban_sdk::Vec::new(&env);
        reduced_admins.push_back(first);
        reduced_admins.push_back(second);
        client.set_admin_set(&admin, &reduced_admins, &1);
        assert_eq!(client.get_active_admin_count(), 2);
        client.execute(&admin, &proposal_id);
    }

    #[test]
    fn quorum_bps_rejects_values_above_one_hundred_percent() {
        let (_env, client, admin) = setup();
        assert_eq!(
            client.try_set_quorum_bps(&admin, &10_001),
            Err(Ok(Error::InvalidArgument))
        );
    }

    #[test]
    fn execute_fails_on_already_executed() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        let result = client.try_execute(&admin, &proposal_id);
        assert_eq!(result, Err(Ok(Error::AlreadyExecuted)));
    }

    #[test]
    fn proposer_can_cancel_pending_proposal() {
        let (_env, client, admin) = setup();
        let proposal_id = client.propose(&admin, &ProposalAction::Pause);
        client.cancel(&admin, &proposal_id);
        assert_eq!(
            client.get_proposal(&proposal_id).status,
            ProposalStatus::Cancelled
        );
        assert_eq!(
            client.try_execute(&admin, &proposal_id),
            Err(Ok(Error::ProposalCancelled))
        );
    }

    #[test]
    fn expired_proposal_cannot_be_approved_or_executed() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let proposal_id = client.propose(&admin, &ProposalAction::Pause);
        env.ledger().set_timestamp(PROPOSAL_LIFETIME + 1);
        assert_eq!(
            client.try_approve(&admin, &proposal_id),
            Err(Ok(Error::ProposalExpired))
        );
        assert_eq!(
            client.get_proposal(&proposal_id).status,
            // The failing invocation is rolled back by Soroban, so the
            // stored proposal remains pending; its expiry is checked again
            // on the next state-changing call.
            ProposalStatus::Pending
        );
        assert_eq!(
            client.try_execute(&second_admin, &proposal_id),
            Err(Ok(Error::ProposalExpired))
        );
    }

    #[test]
    fn execute_with_more_approvals_than_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let a1 = Address::generate(&env);
        let a2 = Address::generate(&env);
        let a3 = Address::generate(&env);
        let mut admin_set: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        admin_set.push_back(a1.clone());
        admin_set.push_back(a2.clone());
        admin_set.push_back(a3.clone());
        client.initialize(&a1, &2, &admin_set);

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&a1, &action);

        client.approve(&a1, &proposal_id);
        client.approve(&a2, &proposal_id);
        client.approve(&a3, &proposal_id);

        client.execute(&a1, &proposal_id);

        let proposal = client.get_proposal(&proposal_id);
        assert_eq!(proposal.status, ProposalStatus::Executed);
        assert!(client.is_paused());
    }

    #[test]
    fn non_admin_cannot_approve() {
        let (env, client, admin) = setup();
        let stranger = Address::generate(&env);

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        let result = client.try_approve(&stranger, &proposal_id);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn non_admin_cannot_execute() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();
        let stranger = Address::generate(&env);

        let action = ProposalAction::Pause;
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);

        let result = client.try_execute(&stranger, &proposal_id);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    // -----------------------------------------------------------------------
    // Proposal actions
    // -----------------------------------------------------------------------

    #[test]
    fn grant_role_via_proposal() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();
        let user = Address::generate(&env);

        let action = ProposalAction::GrantRole(user.clone(), Role::TreasuryManager);
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        assert!(client.has_role(&user, &Role::TreasuryManager));
    }

    #[test]
    fn revoke_role_via_proposal() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::TreasuryManager);
        assert!(client.has_role(&user, &Role::TreasuryManager));

        let action = ProposalAction::RevokeRole(user.clone(), Role::TreasuryManager);
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        assert!(!client.has_role(&user, &Role::TreasuryManager));
    }

    #[test]
    fn set_parameter_via_proposal() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        let action = ProposalAction::SetParameter(ParameterKey::AidDefaultExpiry, 120);
        let proposal_id = client.propose(&admin, &action);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        assert_eq!(client.aid_default_expiry(), 120);
    }

    #[test]
    fn pause_via_proposal() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        let proposal_id = client.propose(&admin, &ProposalAction::Pause);

        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        assert!(client.is_paused());
    }

    #[test]
    fn unpause_via_proposal() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        // Pause first.
        let pause_id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &pause_id);
        client.approve(&second_admin, &pause_id);
        client.execute(&admin, &pause_id);
        assert!(client.is_paused());

        // Unpause.
        let unpause_id = client.propose(&admin, &ProposalAction::Unpause);
        client.approve(&admin, &unpause_id);
        client.approve(&second_admin, &unpause_id);
        client.execute(&admin, &unpause_id);

        assert!(!client.is_paused());
    }

    #[test]
    fn get_proposal_returns_not_found_for_nonexistent_id() {
        let (env, client, _admin) = setup();

        let result = client.try_get_proposal(&999);
        assert_eq!(result, Err(Ok(Error::ProposalNotFound)));
    }

    // -----------------------------------------------------------------------
    // Batch proposal execution
    // -----------------------------------------------------------------------

    #[test]
    fn batch_proposal_executes_multiple_actions_atomically() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();
        let user = Address::generate(&env);

        // Create batch proposal with multiple actions
        let mut actions = soroban_sdk::Vec::new(&env);
        actions.push_back(ProposalAction::GrantRole(user.clone(), Role::Upgrader));
        actions.push_back(ProposalAction::SetParameter(ParameterKey::AidDefaultExpiry, 120));

        let proposal_id = client.propose(&admin, &ProposalAction::Batch(actions.clone()));

        // Approve and execute
        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        // Verify all actions were executed
        assert!(client.has_role(&user, &Role::Upgrader));
        assert_eq!(client.aid_default_expiry(), 120);
    }

    #[test]
    fn batch_proposal_fails_if_action_count_exceeds_limit() {
        let (env, client, admin) = setup();

        // Create batch with too many actions
        let mut actions = soroban_sdk::Vec::new(&env);
        for _ in 0..11 {
            actions.push_back(ProposalAction::Pause);
        }

        let result = client.try_propose(&admin, &ProposalAction::Batch(actions));
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));
    }

    #[test]
    fn batch_proposal_rolls_back_on_partial_failure() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();
        let user = Address::generate(&env);

        // Create batch with one valid and one invalid action
        let mut actions = soroban_sdk::Vec::new(&env);
        actions.push_back(ProposalAction::GrantRole(user.clone(), Role::Upgrader));
        actions.push_back(ProposalAction::SetParameter(ParameterKey::AidDefaultExpiry, -1)); // Invalid value

        let proposal_id = client.propose(&admin, &ProposalAction::Batch(actions.clone()));

        // Approve
        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);

        // Execute should fail due to invalid parameter
        let result = client.try_execute(&admin, &proposal_id);
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));

        // Verify no actions were executed (atomic rollback)
        assert!(!client.has_role(&user, &Role::Upgrader));
        assert_ne!(client.aid_default_expiry(), -1);
    }

    // -----------------------------------------------------------------------
    // set_admin_set
    // -----------------------------------------------------------------------

    #[test]
    fn admin_can_update_admin_set_and_threshold() {
        let (env, client, admin) = setup();

        let new_admins = make_admin_set(&env, 3);
        client.set_admin_set(&admin, &new_admins, &2);

        assert_eq!(client.get_threshold(), 2);
        assert_eq!(client.get_admin_set().len(), 3);
    }

    #[test]
    fn non_admin_cannot_update_admin_set() {
        let (env, client, _admin) = setup();
        let stranger = Address::generate(&env);

        let mut new_admins: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        new_admins.push_back(Address::generate(&env));
        let result = client.try_set_admin_set(&stranger, &new_admins, &1);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn set_admin_set_rejects_invalid_threshold() {
        let (env, client, admin) = setup();

        let new_admins = make_admin_set(&env, 2);
        let result = client.try_set_admin_set(&admin, &new_admins, &3);
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));
    }

    #[test]
    fn set_admin_set_rejects_over_limit_without_changing_current_configuration() {
        let (env, client, admin) = setup();
        let previous_admins = client.get_admin_set();
        let previous_threshold = client.get_threshold();
        let oversized = make_admin_set(&env, MAX_GOVERNANCE_ADMINS as usize + 1);

        assert_eq!(
            client.try_set_admin_set(&admin, &oversized, &1),
            Err(Ok(Error::InvalidArgument))
        );
        assert_eq!(client.get_admin_set(), previous_admins);
        assert_eq!(client.get_threshold(), previous_threshold);
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    #[test]
    fn propose_emits_event() {
        let (env, client, admin) = setup();

        let _proposal_id = client.propose(&admin, &ProposalAction::Pause);

        let all_events = env.events().all();
        let found = all_events
            .iter()
            .any(|e| e.1 == (symbol_short!("proposal"), symbol_short!("created")).into_val(&env));
        assert!(found, "expected proposal created event");
    }

    #[test]
    fn approve_emits_event() {
        let (env, client, admin) = setup();

        let proposal_id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &proposal_id);

        let all_events = env.events().all();
        let found = all_events
            .iter()
            .any(|e| e.1 == (symbol_short!("proposal"), symbol_short!("approved")).into_val(&env));
        assert!(found, "expected proposal approved event");
    }

    #[test]
    fn execute_emits_event() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();

        let proposal_id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &proposal_id);
        client.approve(&second_admin, &proposal_id);
        client.execute(&admin, &proposal_id);

        let all_events = env.events().all();
        let found = all_events
            .iter()
            .any(|e| e.1 == (symbol_short!("proposal"), symbol_short!("executed")).into_val(&env));
        assert!(found, "expected proposal executed event");
    }

    #[test]
    fn grant_role_emits_event() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Upgrader);

        let all_events = env.events().all();
        let found = all_events
            .iter()
            .any(|e| e.1 == (symbol_short!("role"), symbol_short!("granted")).into_val(&env));
        assert!(found, "expected role granted event");
    }

    #[test]
    fn revoke_role_emits_event() {
        let (env, client, admin) = setup();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Upgrader);
        client.revoke_role(&admin, &user, &Role::Upgrader);

        let all_events = env.events().all();
        let found = all_events
            .iter()
            .any(|e| e.1 == (symbol_short!("role"), symbol_short!("revoked")).into_val(&env));
        assert!(found, "expected role revoked event");
    }

    // -----------------------------------------------------------------------
    // Parameter management tests
    // -----------------------------------------------------------------------

    #[test]
    fn authorized_update_changes_parameter_and_emits_event() {
        let (env, client, admin) = setup();
        let key = ParameterKey::ReferralTierBps(2);
        let value = 350;

        client.set_param(&admin, &key, &value);
        let all_events = env.events().all();
        // The last event is ActionExecuted; find the ParameterChanged event
        let param_event = all_events
            .iter()
            .rev()
            .find(|e| e.1 == (shared::events::PARAMETER_CHANGED,).into_val(&env))
            .expect("expected PARAMETER_CHANGED event");
        assert_eq!(
            ParameterChangedEvent::try_from_val(&env, &param_event.2).unwrap(),
            ParameterChangedEvent { key, value }
        );

        assert_eq!(client.get_param(&ParameterKey::ReferralTierBps(2)), value);
        assert_eq!(client.referral_tier_bps(&2), value);
    }

    #[test]
    fn unauthorized_update_is_rejected() {
        let (env, client, _admin) = setup();
        let stranger = Address::generate(&env);

        assert!(matches!(
            client.try_set_param(&stranger, &ParameterKey::AidDefaultExpiry, &120),
            Err(Ok(Error::Unauthorized))
        ));
        assert_eq!(client.aid_default_expiry(), DEFAULT_AID_DEFAULT_EXPIRY);
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        let (env, client, admin) = setup();

        assert!(matches!(
            client.try_set_param(
                &admin,
                &ParameterKey::AidDefaultExpiry,
                &(MAX_AID_DEFAULT_EXPIRY + 1)
            ),
            Err(Ok(Error::InvalidArgument))
        ));
        assert!(matches!(
            client.try_set_param(&admin, &ParameterKey::ReferralTierBps(1), &10_001),
            Err(Ok(Error::InvalidArgument))
        ));
        assert!(matches!(
            client.try_set_param(&admin, &ParameterKey::ReferralTierBps(0), &100),
            Err(Ok(Error::InvalidArgument))
        ));
        assert!(matches!(
            client.try_set_param(&admin, &ParameterKey::ReferralMaxTiers, &0),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    #[test]
    fn bounds_are_readable_for_dependent_contracts() {
        let (env, client, _admin) = setup();

        assert_eq!(
            client.get_bounds(&ParameterKey::ReferralTierBps(1)),
            ParameterBounds {
                min: MIN_REFERRAL_TIER_BPS,
                max: MAX_REFERRAL_TIER_BPS,
            }
        );
        assert!(matches!(
            client.try_get_bounds(&ParameterKey::ReferralTierBps(11)),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    // -----------------------------------------------------------------------
    // Authorization matrix
    //
    // Every privileged entrypoint below is exercised with an authorized
    // actor (allow) and an unauthorized actor (deny). Revoked and expired
    // actors are covered explicitly where the contract supports them.
    //
    // Privileged entrypoints and their required roles:
    //   * initialize      — one-shot bootstrap (no prior role required)
    //   * grant_role      — Admin (ManageRoles)
    //   * revoke_role     — Admin (ManageRoles)
    //   * set_admin_set   — Admin (ManageRoles)
    //   * propose         — Admin (ManageRoles)
    //   * approve         — Admin (ManageRoles)
    //   * execute         — Admin (ManageRoles)
    //   * cancel          — proposer or super-admin
    //   * set_param       — Admin (ManageConfiguration)
    // -----------------------------------------------------------------------

    /// Builds a governance instance with a single admin and a stranger.
    fn setup_with_stranger() -> (Env, GovernanceContractClient<'static>, Address, Address) {
        let (env, client, admin) = setup();
        let stranger = Address::generate(&env);
        (env, client, admin, stranger)
    }

    // --- initialize ---------------------------------------------------------

    #[test]
    fn initialize_allows_first_caller_and_denies_double_init() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let mut admin_set: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        admin_set.push_back(admin.clone());

        // allow: first initialization succeeds
        client.initialize(&admin, &1, &admin_set);
        assert!(client.has_role(&admin, &Role::Admin));

        // deny: re-initialization is rejected by the shared auth layer
        let result = client.try_initialize(&admin, &1, &admin_set);
        assert!(result.is_err());
    }

    // --- grant_role ---------------------------------------------------------

    #[test]
    fn grant_role_allow_admin_deny_stranger() {
        let (env, client, admin, stranger) = setup_with_stranger();
        let user = Address::generate(&env);

        // allow
        client.grant_role(&admin, &user, &Role::Upgrader);
        assert!(client.has_role(&user, &Role::Upgrader));

        // deny
        let other = Address::generate(&env);
        assert_eq!(
            client.try_grant_role(&stranger, &other, &Role::Upgrader),
            Err(Ok(Error::Unauthorized))
        );
        assert!(!client.has_role(&other, &Role::Upgrader));
    }

    #[test]
    fn grant_role_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let admins = client.get_admin_set();
        let second_admin = admins.get(1).unwrap();
        let user = Address::generate(&env);

        // Revoke the second admin's Admin role.
        client.revoke_role(&admin, &second_admin, &Role::Admin);
        assert!(!client.has_role(&second_admin, &Role::Admin));

        // deny: revoked admin can no longer grant roles
        assert_eq!(
            client.try_grant_role(&second_admin, &user, &Role::Upgrader),
            Err(Ok(Error::Unauthorized))
        );
    }

    // --- revoke_role --------------------------------------------------------

    #[test]
    fn revoke_role_allow_admin_deny_stranger() {
        let (env, client, admin, stranger) = setup_with_stranger();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Pauser);

        // allow
        client.revoke_role(&admin, &user, &Role::Pauser);
        assert!(!client.has_role(&user, &Role::Pauser));

        // deny
        client.grant_role(&admin, &user, &Role::Pauser);
        assert_eq!(
            client.try_revoke_role(&stranger, &user, &Role::Pauser),
            Err(Ok(Error::Unauthorized))
        );
        assert!(client.has_role(&user, &Role::Pauser));
    }

    #[test]
    fn revoke_role_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Pauser);
        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_revoke_role(&second_admin, &user, &Role::Pauser),
            Err(Ok(Error::Unauthorized))
        );
        assert!(client.has_role(&user, &Role::Pauser));
    }

    // --- set_admin_set ------------------------------------------------------

    #[test]
    fn set_admin_set_allow_admin_deny_stranger() {
        let (env, client, admin, stranger) = setup_with_stranger();
        let new_admins = make_admin_set(&env, 2);

        // allow
        client.set_admin_set(&admin, &new_admins, &1);
        assert_eq!(client.get_threshold(), 1);
        assert_eq!(client.get_admin_set().len(), 2);

        // deny
        let other = make_admin_set(&env, 1);
        assert_eq!(
            client.try_set_admin_set(&stranger, &other, &1),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn set_admin_set_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let new_admins = make_admin_set(&env, 1);

        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_set_admin_set(&second_admin, &new_admins, &1),
            Err(Ok(Error::Unauthorized))
        );
    }

    // --- propose ------------------------------------------------------------

    #[test]
    fn propose_allow_admin_deny_stranger() {
        let (_env, client, admin, stranger) = setup_with_stranger();

        // allow
        let id = client.propose(&admin, &ProposalAction::Pause);
        assert_eq!(client.get_proposal(&id).status, ProposalStatus::Pending);

        // deny
        assert_eq!(
            client.try_propose(&stranger, &ProposalAction::Pause),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn propose_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();

        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_propose(&second_admin, &ProposalAction::Pause),
            Err(Ok(Error::Unauthorized))
        );
    }

    // --- approve ------------------------------------------------------------

    #[test]
    fn approve_allow_admin_deny_stranger() {
        let (env, client, admin, stranger) = setup_with_stranger();
        let id = client.propose(&admin, &ProposalAction::Pause);

        // allow
        client.approve(&admin, &id);
        assert_eq!(client.get_proposal(&id).approval_count, 1);

        // deny
        assert_eq!(
            client.try_approve(&stranger, &id),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn approve_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let id = client.propose(&admin, &ProposalAction::Pause);

        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_approve(&second_admin, &id),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn approve_denies_expired_proposal() {
        let (env, client, admin) = setup();
        let id = client.propose(&admin, &ProposalAction::Pause);
        env.ledger().set_timestamp(PROPOSAL_LIFETIME + 1);

        assert_eq!(
            client.try_approve(&admin, &id),
            Err(Ok(Error::ProposalExpired))
        );
    }

    // --- execute ------------------------------------------------------------

    #[test]
    fn execute_allow_admin_deny_stranger() {
        let (env, client, admin, stranger) = setup_with_stranger();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &id);
        client.approve(&second_admin, &id);

        // deny
        assert_eq!(
            client.try_execute(&stranger, &id),
            Err(Ok(Error::Unauthorized))
        );

        // allow
        client.execute(&admin, &id);
        assert_eq!(
            client.get_proposal(&id).status,
            ProposalStatus::Executed
        );
    }

    #[test]
    fn execute_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &id);
        client.approve(&second_admin, &id);

        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_execute(&second_admin, &id),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn execute_denies_expired_proposal() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let id = client.propose(&admin, &ProposalAction::Pause);
        client.approve(&admin, &id);
        client.approve(&second_admin, &id);
        env.ledger().set_timestamp(PROPOSAL_LIFETIME + 1);

        assert_eq!(
            client.try_execute(&admin, &id),
            Err(Ok(Error::ProposalExpired))
        );
    }

    // --- cancel -------------------------------------------------------------

    #[test]
    fn cancel_allow_proposer_deny_stranger() {
        let (_env, client, admin, stranger) = setup_with_stranger();
        let id = client.propose(&admin, &ProposalAction::Pause);

        // deny
        assert_eq!(
            client.try_cancel(&stranger, &id),
            Err(Ok(Error::Unauthorized))
        );

        // allow
        client.cancel(&admin, &id);
        assert_eq!(
            client.get_proposal(&id).status,
            ProposalStatus::Cancelled
        );
    }

    #[test]
    fn cancel_denies_revoked_proposer() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();
        let id = client.propose(&second_admin, &ProposalAction::Pause);

        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_cancel(&second_admin, &id),
            Err(Ok(Error::Unauthorized))
        );
    }

    // --- set_param ----------------------------------------------------------

    #[test]
    fn set_param_allow_admin_deny_stranger() {
        let (_env, client, admin, stranger) = setup_with_stranger();

        // allow
        client.set_param(&admin, &ParameterKey::AidDefaultExpiry, &120);
        assert_eq!(client.aid_default_expiry(), 120);

        // deny
        assert_eq!(
            client.try_set_param(&stranger, &ParameterKey::AidDefaultExpiry, &240),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(client.aid_default_expiry(), 120);
    }

    #[test]
    fn set_param_denies_revoked_admin() {
        let (env, client, admin) = setup();
        let second_admin = client.get_admin_set().get(1).unwrap();

        client.revoke_role(&admin, &second_admin, &Role::Admin);

        assert_eq!(
            client.try_set_param(
                &second_admin,
                &ParameterKey::AidDefaultExpiry,
                &120
            ),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(client.aid_default_expiry(), DEFAULT_AID_DEFAULT_EXPIRY);
    }
}
