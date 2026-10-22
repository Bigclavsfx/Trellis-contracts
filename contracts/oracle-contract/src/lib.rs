#![no_std]
//! # Oracle Contract
//!
//! Off-chain data integration and verification bridge for Trellis.
//!
//! ## Overview
//!
//! The Oracle Contract acts as a bridge between off-chain verification systems and on-chain state.
//! It stores references to:
//! - **AI verification proofs**: Hash references to external verification
//! - **Metadata pointers**: URLs or identifiers for off-chain data
//! - **Signatures**: External signatures proving authenticity
//!
//! This contract does not execute the verification logic itself, but rather anchors
//! cryptographic proof that verification occurred.
//!
//! ## Example Flow
//!
//! 1. Off-chain system verifies user identity via AI or document review
//! 2. System generates a proof hash and calls the oracle contract
//! 3. On-chain applications query the oracle to confirm verification
//! 4. Applications can trust that a specific wallet has been verified
//!
//! ## Queries
//!
//! - Retrieve verification metadata for a wallet
//! - Check proof hashes and signatures
//!
//! For full API details, see the module items below.

mod errors;
mod events;
mod storage;
mod types;

use soroban_sdk::{
    contract, contractimpl, symbol_short, token, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use errors::OracleError;
use shared::events::emit_module_initialized;
use shared::{record_action_audit_event, ResourceLink, TimelineEventType};
use storage::{StakingConfig, UnbondingRequest};
use types::{FeedLatest, PriceSubmission};

const MAX_FUTURE_SKEW_SECS: u64 = 60;
const DEFAULT_MIN_PRICE_QUORUM: u32 = 2;

/// Correlation ID used for the contract-level events.
///
/// The oracle contract does not accept a caller-supplied correlation ID (the
/// contract entrypoints keep a stable signature), so the canonical zero ID is
/// used, matching the pattern used by the other contracts in this workspace.
fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

#[cfg(test)]
mod tests;

#[contract]
pub struct OracleContract;

#[contractimpl]
impl OracleContract {
    /// Initialize the oracle contract with an admin.
    pub fn initialize(env: Env, admin: Address) -> Result<(), OracleError> {
        shared::auth::initialize_admin(&env, &admin).map_err(|error| match error {
            shared::Error::AlreadyInitialized => OracleError::AlreadyInitialized,
            _ => OracleError::Unauthorized,
        })?;
        storage::set_min_price_quorum(&env, DEFAULT_MIN_PRICE_QUORUM);
        emit_module_initialized(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("oracle"),
            1,
            &admin,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Register a new authorized submitter (admin only).
    pub fn register_submitter(
        env: Env,
        caller: Address,
        submitter: Address,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        let was_active = storage::is_submitter_active(&env, &submitter);
        storage::register_submitter(&env, submitter.clone(), env.ledger().timestamp())?;
        record_action_audit_event(
            &env,
            &caller,
            TimelineEventType::RoleChanged,
            ResourceLink {
                kind: Bytes::from_slice(&env, b"oracle"),
                id: 0,
                revision: 0,
            },
            symbol_short!("oracle"),
            symbol_short!("signer"),
            symbol_short!("adm_grant"),
            Some(submitter.clone()),
            Some(symbol_short!("signer")),
            Some(if was_active { 1 } else { 0 }),
            Some(1),
        )
        .map_err(|_| OracleError::InternalError)?;
        events::emit_submitter_registered(&env, &submitter, env.ledger().timestamp());
        Ok(())
    }

    /// Register a new authorized submitter with an initial stake of protocol collateral (admin only).
    pub fn register_submitter_with_stake(
        env: Env,
        caller: Address,
        submitter: Address,
        stake_amount: i128,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        submitter.require_auth();

        let config = storage::get_staking_config(&env).ok_or(OracleError::StakingConfigNotSet)?;
        if stake_amount < config.min_stake {
            return Err(OracleError::InsufficientStake);
        }

        storage::register_submitter(&env, submitter.clone(), env.ledger().timestamp())?;
        record_action_audit_event(
            &env,
            &caller,
            TimelineEventType::RoleChanged,
            ResourceLink {
                kind: Bytes::from_slice(&env, b"oracle"),
                id: 0,
                revision: 0,
            },
            symbol_short!("oracle"),
            symbol_short!("signer"),
            symbol_short!("adm_grant"),
            Some(submitter.clone()),
            Some(symbol_short!("signer")),
            Some(0),
            Some(1),
        )
        .map_err(|_| OracleError::InternalError)?;
        events::emit_submitter_registered(&env, &submitter, env.ledger().timestamp());

        // Transfer collateral tokens from submitter to oracle contract
        token::Client::new(&env, &config.token).transfer(
            &submitter,
            &env.current_contract_address(),
            &stake_amount,
        );

        storage::set_submitter_stake(&env, &submitter, stake_amount);
        events::emit_submitter_staked(
            &env,
            &submitter,
            stake_amount,
            stake_amount,
            env.ledger().timestamp(),
        );

        Ok(())
    }

    /// Deactivate an authorized submitter (admin only).
    pub fn deactivate_submitter(
        env: Env,
        caller: Address,
        submitter: Address,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        let was_active = storage::is_submitter_active(&env, &submitter);
        storage::deactivate_submitter(&env, &submitter);
        record_action_audit_event(
            &env,
            &caller,
            TimelineEventType::RoleChanged,
            ResourceLink {
                kind: Bytes::from_slice(&env, b"oracle"),
                id: 0,
                revision: 0,
            },
            symbol_short!("oracle"),
            symbol_short!("signer"),
            symbol_short!("adm_rvok"),
            Some(submitter.clone()),
            Some(symbol_short!("signer")),
            Some(if was_active { 1 } else { 0 }),
            Some(0),
        )
        .map_err(|_| OracleError::InternalError)?;
        events::emit_submitter_deactivated(&env, &submitter, env.ledger().timestamp());
        Ok(())
    }

    /// Submit a price for a feed (authorized submitters only).
    ///
    /// Includes replay protection (nonce-based) and staleness validation.
    pub fn submit_price(
        env: Env,
        submitter: Address,
        feed_id: Symbol,
        price: i128,
        decimals: u32,
        timestamp: u64,
        nonce: u64,
    ) -> Result<u64, OracleError> {
        submitter.require_auth();

        // Validate price and decimals
        if price < 0 {
            return Err(OracleError::InvalidPrice);
        }
        if decimals > 18 {
            return Err(OracleError::InvalidDecimals);
        }

        // Check submitter is authorized
        if !storage::is_submitter_active(&env, &submitter) {
            return Err(OracleError::SubmitterNotAuthorized);
        }

        // Replay protection: check nonce
        let expected_nonce = storage::get_nonce(&env, &submitter, &feed_id);
        if nonce != expected_nonce + 1 {
            return Err(OracleError::DuplicateSubmission);
        }

        // Staleness check: ensure timestamp is neither stale nor too far ahead.
        let current_time = env.ledger().timestamp();
        let staleness_window = storage::get_staleness_window(&env);
        if timestamp > current_time.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(OracleError::SubmissionFromFuture);
        }
        let expires_at = timestamp
            .checked_add(staleness_window)
            .ok_or(OracleError::SubmissionStale)?;
        if current_time > expires_at {
            return Err(OracleError::SubmissionStale);
        }

        // Generate submission
        let submission_id = storage::next_submission_id(&env)?;
        let submission = PriceSubmission {
            id: submission_id,
            submitter: submitter.clone(),
            feed_id: feed_id.clone(),
            price,
            decimals,
            timestamp,
            nonce,
        };

        // Store submission
        storage::append_submission(&env, &feed_id, &submission);
        storage::set_feed_active_submission(&env, &feed_id, &submission);

        if let Some(latest) = aggregate_feed_latest(&env, &feed_id, current_time, staleness_window)
        {
            storage::set_feed_latest(&env, &feed_id, &latest);
        }

        // Update nonce
        storage::set_nonce(&env, &submitter, &feed_id, nonce);

        // Emit event
        events::emit_price_submitted(&env, &feed_id, price, &submitter, current_time);

        Ok(submission_id)
    }

    /// Get the latest price for a feed.
    pub fn get_latest_price(env: Env, feed_id: Symbol) -> Result<FeedLatest, OracleError> {
        if storage::get_feed_active_submissions(&env, &feed_id).len() == 0 {
            return Err(OracleError::FeedNotFound);
        }
        aggregate_feed_latest(
            &env,
            &feed_id,
            env.ledger().timestamp(),
            storage::get_staleness_window(&env),
        )
        .ok_or(OracleError::InsufficientQuorum)
    }

    /// Configure the global minimum number of active price submitters. Admin only.
    pub fn set_min_quorum(
        env: Env,
        caller: Address,
        min_quorum: u32,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        validate_quorum(&env, min_quorum)?;
        storage::set_min_price_quorum(&env, min_quorum);
        Ok(())
    }

    /// Set a per-feed quorum override. Admin only.
    pub fn set_feed_quorum(
        env: Env,
        caller: Address,
        feed_id: Symbol,
        quorum: u32,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        validate_quorum(&env, quorum)?;
        storage::set_feed_quorum(&env, &feed_id, quorum);
        Ok(())
    }

    /// Remove a feed-specific override so the global minimum applies again.
    pub fn clear_feed_quorum(
        env: Env,
        caller: Address,
        feed_id: Symbol,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        storage::remove_feed_quorum(&env, &feed_id);
        Ok(())
    }

    pub fn get_min_quorum(env: Env) -> u32 {
        storage::min_price_quorum(&env)
    }

    pub fn get_feed_quorum(env: Env, feed_id: Symbol) -> u32 {
        storage::feed_quorum(&env, &feed_id).unwrap_or(storage::min_price_quorum(&env))
    }

    /// Get submission history for a feed (latest N submissions).
    pub fn get_price_history(
        env: Env,
        feed_id: Symbol,
        limit: u32,
    ) -> Result<soroban_sdk::Vec<PriceSubmission>, OracleError> {
        let history = storage::get_feed_history(&env, &feed_id, limit);
        if history.len() == 0 {
            return Err(OracleError::FeedNotFound);
        }
        Ok(history)
    }

    /// Set the staleness window (admin only).
    pub fn set_staleness_window(
        env: Env,
        caller: Address,
        seconds: u64,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;

        storage::set_staleness_window(&env, seconds);
        events::emit_staleness_window_set(&env, seconds, env.ledger().timestamp());
        Ok(())
    }

    /// Get the current staleness window.
    pub fn get_staleness_window(env: Env) -> u64 {
        storage::get_staleness_window(&env)
    }

    /// Check if a submitter is active.
    pub fn is_submitter_active(env: Env, submitter: Address) -> bool {
        storage::is_submitter_active(&env, &submitter)
    }

    /// Check if a submitter is registered.
    pub fn is_submitter_registered(env: Env, submitter: Address) -> bool {
        storage::is_submitter_registered(&env, &submitter)
    }

    /// Get the admin address.
    pub fn get_admin(env: Env) -> Address {
        shared::auth::get_admin(&env)
    }

    /// Configure staking parameters (admin only).
    pub fn set_staking_config(
        env: Env,
        caller: Address,
        token: Address,
        min_stake: i128,
        unbonding_cooldown: u64,
    ) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        if min_stake <= 0 {
            return Err(OracleError::InvalidPenaltyAmount);
        }
        let config = StakingConfig {
            min_stake,
            token,
            unbonding_cooldown,
        };
        storage::set_staking_config(&env, &config);
        Ok(())
    }

    /// Get current staking configuration.
    pub fn get_staking_config(env: Env) -> Option<StakingConfig> {
        storage::get_staking_config(&env)
    }

    /// Configure the treasury contract address (admin only).
    pub fn set_treasury(env: Env, caller: Address, treasury: Address) -> Result<(), OracleError> {
        shared::auth::require_admin(&env, &caller).map_err(|_| OracleError::Unauthorized)?;
        storage::set_treasury(&env, &treasury);
        Ok(())
    }

    /// Get the configured treasury address.
    pub fn get_treasury(env: Env) -> Option<Address> {
        storage::get_treasury(&env)
    }

    /// Deposit protocol collateral stake for a registered submitter.
    pub fn stake(env: Env, submitter: Address, amount: i128) -> Result<(), OracleError> {
        submitter.require_auth();
        if amount <= 0 {
            return Err(OracleError::InsufficientStake);
        }
        if !storage::is_submitter_registered(&env, &submitter) {
            return Err(OracleError::SubmitterNotAuthorized);
        }
        let config = storage::get_staking_config(&env).ok_or(OracleError::StakingConfigNotSet)?;
        let current_stake = storage::get_submitter_stake(&env, &submitter);
        let new_stake = current_stake
            .checked_add(amount)
            .ok_or(OracleError::Overflow)?;

        // Transfer collateral tokens from submitter to oracle contract
        token::Client::new(&env, &config.token).transfer(
            &submitter,
            &env.current_contract_address(),
            &amount,
        );

        storage::set_submitter_stake(&env, &submitter, new_stake);
        events::emit_submitter_staked(
            &env,
            &submitter,
            amount,
            new_stake,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Get current staked amount for a submitter.
    pub fn get_stake(env: Env, submitter: Address) -> i128 {
        storage::get_submitter_stake(&env, &submitter)
    }

    /// Get pending unbonding request for a submitter.
    pub fn get_unbonding(env: Env, submitter: Address) -> Option<UnbondingRequest> {
        storage::get_unbonding_request(&env, &submitter)
    }

    /// Slash a submitter's collateral and direct the penalty collateral to the Treasury reserve.
    /// Executable by governance / admin.
    pub fn slash_submitter(
        env: Env,
        caller: Address,
        submitter: Address,
        penalty_amount: i128,
        reason: Symbol,
    ) -> Result<(), OracleError> {
        // Governance authority: the contract admin or any holder of the
        // admin role. `has_permission(ManageConfiguration)` resolves to the
        // admin role *or* the stored admin address.
        if !shared::auth::has_permission(
            &env,
            &caller,
            shared::auth::Permission::ManageConfiguration,
        ) {
            return Err(OracleError::Unauthorized);
        }
        caller.require_auth();

        if penalty_amount <= 0 {
            return Err(OracleError::InvalidPenaltyAmount);
        }

        let config = storage::get_staking_config(&env).ok_or(OracleError::StakingConfigNotSet)?;
        let treasury = storage::get_treasury(&env).ok_or(OracleError::TreasuryNotConfigured)?;

        let current_stake = storage::get_submitter_stake(&env, &submitter);
        let remaining_stake = if current_stake >= penalty_amount {
            let rem = current_stake - penalty_amount;
            storage::set_submitter_stake(&env, &submitter, rem);
            rem
        } else {
            // Check if there is an active unbonding request to slash from
            let shortfall = penalty_amount - current_stake;
            if let Some(mut unbonding) = storage::get_unbonding_request(&env, &submitter) {
                if unbonding.amount < shortfall {
                    return Err(OracleError::InvalidPenaltyAmount);
                }
                unbonding.amount -= shortfall;
                if unbonding.amount == 0 {
                    storage::remove_unbonding_request(&env, &submitter);
                } else {
                    storage::set_unbonding_request(&env, &submitter, &unbonding);
                }
                storage::set_submitter_stake(&env, &submitter, 0);
                0
            } else {
                return Err(OracleError::InvalidPenaltyAmount);
            }
        };

        // Transfer slashed collateral to TreasuryContract reserve
        token::Client::new(&env, &config.token).transfer(
            &env.current_contract_address(),
            &treasury,
            &penalty_amount,
        );

        let now = env.ledger().timestamp();
        events::emit_submitter_slashed(
            &env,
            &submitter,
            penalty_amount,
            remaining_stake,
            reason,
            now,
        );

        Ok(())
    }

    /// Initiate unstaking of all deposited collateral subject to unbonding cooldown window.
    pub fn unstake(env: Env, submitter: Address) -> Result<(), OracleError> {
        submitter.require_auth();

        if storage::get_unbonding_request(&env, &submitter).is_some() {
            return Err(OracleError::AlreadyUnbonding);
        }

        let current_stake = storage::get_submitter_stake(&env, &submitter);
        if current_stake <= 0 {
            return Err(OracleError::InsufficientStake);
        }

        let config = storage::get_staking_config(&env).ok_or(OracleError::StakingConfigNotSet)?;
        let now = env.ledger().timestamp();
        let unlock_time = now
            .checked_add(config.unbonding_cooldown)
            .ok_or(OracleError::Overflow)?;

        // Move stake into unbonding request
        storage::set_submitter_stake(&env, &submitter, 0);
        let unbonding = UnbondingRequest {
            amount: current_stake,
            unlock_time,
        };
        storage::set_unbonding_request(&env, &submitter, &unbonding);

        events::emit_unbonding_requested(&env, &submitter, current_stake, unlock_time, now);
        Ok(())
    }

    /// Withdraw unbonded collateral once the cooldown window has elapsed.
    pub fn withdraw_unbonded(env: Env, submitter: Address) -> Result<(), OracleError> {
        submitter.require_auth();

        let unbonding = storage::get_unbonding_request(&env, &submitter)
            .ok_or(OracleError::NoUnbondingRequest)?;

        let now = env.ledger().timestamp();
        if now < unbonding.unlock_time {
            return Err(OracleError::UnbondingCooldownActive);
        }

        let config = storage::get_staking_config(&env).ok_or(OracleError::StakingConfigNotSet)?;
        let amount = unbonding.amount;

        // Remove unbonding request
        storage::remove_unbonding_request(&env, &submitter);

        // Transfer tokens back to submitter
        token::Client::new(&env, &config.token).transfer(
            &env.current_contract_address(),
            &submitter,
            &amount,
        );

        events::emit_stake_withdrawn(&env, &submitter, amount, now);
        Ok(())
    }
}

fn aggregate_feed_latest(
    env: &Env,
    feed_id: &Symbol,
    current_time: u64,
    staleness_window: u64,
) -> Option<FeedLatest> {
    let active = storage::get_feed_active_submissions(env, feed_id);
    let mut prices = Vec::new(env);
    let mut decimals: Option<u32> = None;
    let mut newest_timestamp = 0_u64;

    for (_, submission) in active.iter() {
        if !storage::is_submitter_active(env, &submission.submitter) {
            continue;
        }
        let Some(expires_at) = submission.timestamp.checked_add(staleness_window) else {
            continue;
        };
        if submission.timestamp > current_time.saturating_add(MAX_FUTURE_SKEW_SECS)
            || current_time > expires_at
        {
            continue;
        }
        if let Some(expected_decimals) = decimals {
            if submission.decimals != expected_decimals {
                continue;
            }
        } else {
            decimals = Some(submission.decimals);
        }
        if submission.timestamp > newest_timestamp {
            newest_timestamp = submission.timestamp;
        }
        prices.push_back(submission.price);
    }

    let required_quorum = storage::feed_quorum(env, feed_id)
        .unwrap_or(storage::min_price_quorum(env));
    if prices.len() < required_quorum {
        return None;
    }

    sort_prices(&mut prices);
    let mid = prices.len() / 2;
    let price = if prices.len() % 2 == 1 {
        prices.get(mid).unwrap()
    } else {
        let low = prices.get(mid - 1).unwrap();
        let high = prices.get(mid).unwrap();
        low.checked_add(high)?.checked_div(2)?
    };

    Some(FeedLatest {
        feed_id: feed_id.clone(),
        price,
        decimals: decimals.unwrap_or(0),
        timestamp: newest_timestamp,
        submission_count: prices.len() as u64,
    })
}

fn validate_quorum(env: &Env, quorum: u32) -> Result<(), OracleError> {
    if quorum == 0 || quorum > storage::active_submitter_count(env) {
        return Err(OracleError::InvalidQuorum);
    }
    Ok(())
}

fn sort_prices(prices: &mut Vec<i128>) {
    let len = prices.len();
    let mut i = 1;
    while i < len {
        let mut j = i;
        while j > 0 {
            let left = prices.get(j - 1).unwrap();
            let right = prices.get(j).unwrap();
            if left <= right {
                break;
            }
            prices.set(j - 1, right);
            prices.set(j, left);
            j -= 1;
        }
        i += 1;
    }
}
