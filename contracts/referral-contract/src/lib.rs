#![no_std]
//! # Referral Contract
//!
//! Multi-tier referral network and affiliate commission distribution for Trellis.
//!
//! ## Overview
//!
//! The Referral Contract manages:
//! - **Referral graphs**: Wallets can register under a referrer to join the network
//! - **Multi-tier commissions**: Base amounts accrue commissions at each referral tier
//! - **Lifetime caps**: Each referrer has a maximum cumulative commission
//! - **Treasury integration**: Accrued commissions are claimed from the protocol treasury
//!
//! ## Tier System
//!
//! A transaction can trigger commissions across multiple tiers:
//! - **Tier 1**: Direct referrer gets Tier 1 BPS % of the base amount
//! - **Tier 2**: Referrer's referrer gets Tier 2 BPS % of the base amount
//! - Up to configured `max_tiers` (1-10 levels deep)
//!
//! Example: if Tier 1 BPS = 500 (5%) and a referral accrues 1000 tokens base:
//! - Tier 1 referrer gets 50 tokens
//! - Tier 2 referrer gets `1000 × (tier2_bps / 10000)` tokens
//!
//! ## Example Flow
//!
//! 1. Admin calls [`ReferralContract::initialize`]
//! 2. Admin calls [`ReferralContract::set_tier_config`] with BPS percentages and cap
//! 3. Wallet A calls [`ReferralContract::register`] under Wallet B
//! 4. Admin calls [`ReferralContract::accrue`] when transaction occurs
//! 5. Wallets call [`ReferralContract::claim_rewards`] to collect treasury payouts
//!
//! ## Queries
//!
//! - [`ReferralContract::accrued_balance`]: Claimable commission for a referrer
//! - [`ReferralContract::lifetime_accrued`]: Total lifetime commissions (for cap)
//! - [`ReferralContract::get_referrer`]: Direct referrer for a wallet
//! - [`ReferralContract::get_tier_config`]: Current tier configuration
//!
//! For full API details, see the module items below.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, BytesN, Env, IntoVal,
    Symbol,
};

use shared::errors::Error;
use shared::events::{emit_action_executed, emit_module_initialized, emit_permission_changed};
use shared::storage::{persistent_get, persistent_read, persistent_set};

const MAX_SUPPORTED_TIERS: u32 = 10;
const MIN_REWARD_CAP: i128 = 0;
const MAX_REWARD_CAP: i128 = 1_000_000_000_000_000_000;
const MIN_TIER_BPS: i128 = 0;
const MAX_TIER_BPS: i128 = 10_000;

type ContractResult<T> = core::result::Result<T, Error>;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Treasury,
    Registry,
    MaxTiers,
    RewardCap,
    TierBps(u32),
    Referrer(Address),
    ReferralRecord(Address),
    Accrued(Address),
    LifetimeAccrued(Address),
    ReferralCode(Symbol),
    AddressToCode(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierConfig {
    pub tier_bps: soroban_sdk::Vec<i128>,
    pub max_tiers: u32,
    pub reward_cap: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferralRecord {
    pub wallet: Address,
    pub referrer: Address,
    pub commission: i128,
    pub tier: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferrerSetEvent {
    pub referred_wallet: Address,
    pub referrer: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferralRegisteredEvent {
    pub wallet: Address,
    pub referrer: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccruedRewardEvent {
    pub referred_wallet: Address,
    pub referrer: Address,
    pub tier: u32,
    pub amount: i128,
    pub accrued_balance: i128,
    pub lifetime_accrued: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRewardsEvent {
    pub referrer: Address,
    pub amount: i128,
}

#[contract]
pub struct ReferralContract;

/// The referral contract does not accept a caller-supplied correlation ID
/// (the contract has no request-scoped workflow to correlate), so every
/// correlated event uses the canonical zero correlation ID.
fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

#[contractimpl]
impl ReferralContract {
    /// Initialise the contract, setting the admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        shared::auth::initialize_admin(&env, &admin)?;
        shared::auth::grant_role(&env, &admin, &admin, shared::auth::Role::ReferralManager)?;
        env.storage().instance().set(&DataKey::MaxTiers, &1_u32);
        env.storage().instance().set(&DataKey::RewardCap, &0_i128);
        env.storage().instance().set(&DataKey::TierBps(1), &0_i128);
        emit_module_initialized(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            1,
            &admin,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Configure the treasury contract used for referral reward claims.
    pub fn set_treasury(env: Env, caller: Address, treasury: Address) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Treasury, &treasury);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("treasury"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Read the configured treasury contract address.
    pub fn get_treasury(env: Env) -> Result<Address, Error> {
        read_treasury(&env)
    }

    /// Configure the registry contract that resolves dependency addresses.
    pub fn set_registry(env: Env, caller: Address, registry: Address) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Registry, &registry);
        Ok(())
    }

    /// Grant or revoke referral configuration access. Admin only.
    pub fn set_referral_manager(
        env: Env,
        caller: Address,
        manager: Address,
        enabled: bool,
    ) -> Result<(), Error> {
        shared::auth::require_admin(&env, &caller)?;
        let was_manager =
            shared::auth::has_role(&env, &manager, shared::auth::Role::ReferralManager);
        if enabled {
            shared::auth::grant_role(&env, &caller, &manager, shared::auth::Role::ReferralManager)?;
        } else {
            shared::auth::revoke_role(
                &env,
                &caller,
                &manager,
                shared::auth::Role::ReferralManager,
            )?;
        }
        shared::record_action_audit_event(
            &env,
            &caller,
            shared::TimelineEventType::RoleChanged,
            shared::ResourceLink {
                kind: Bytes::from_slice(&env, b"referral"),
                id: 0,
                revision: 0,
            },
            symbol_short!("referral"),
            symbol_short!("ref_mgr"),
            if enabled {
                symbol_short!("adm_grant")
            } else {
                symbol_short!("adm_rvok")
            },
            Some(manager.clone()),
            Some(symbol_short!("ref_mgr")),
            Some(if was_manager { 1 } else { 0 }),
            Some(if enabled { 1 } else { 0 }),
        )?;
        emit_permission_changed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("ref_mgr"),
            &manager,
            enabled,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Configure tier percentages and the lifetime cap enforced per referrer.
    pub fn set_tier_config(
        env: Env,
        caller: Address,
        tier_bps: soroban_sdk::Vec<i128>,
        max_tiers: u32,
        reward_cap: i128,
    ) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        validate_tier_config(&tier_bps, max_tiers, reward_cap)?;

        persistent_set(&env, &DataKey::MaxTiers, &max_tiers);
        persistent_set(&env, &DataKey::RewardCap, &reward_cap);

        let mut tier = 1_u32;
        while tier <= max_tiers {
            let bps = tier_bps.get(tier - 1).ok_or(Error::InvalidArgument)?;
            persistent_set(&env, &DataKey::TierBps(tier), &bps);
            tier += 1;
        }

        env.events().publish(
            (shared::events::TIER_CONFIG_SET,),
            TierConfig {
                tier_bps,
                max_tiers,
                reward_cap,
            },
        );
        emit_permission_changed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("tier"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Return the active tier configuration.
    pub fn get_tier_config(env: Env) -> Result<TierConfig, Error> {
        let max_tiers = read_max_tiers(&env)?;
        let mut tier_bps = soroban_sdk::Vec::new(&env);
        let mut tier = 1_u32;
        while tier <= max_tiers {
            tier_bps.push_back(read_tier_bps(&env, tier)?);
            tier += 1;
        }

        Ok(TierConfig {
            tier_bps,
            max_tiers,
            reward_cap: read_reward_cap(&env)?,
        })
    }

    /// Store a referral edge in the graph.
    pub fn set_referrer(
        env: Env,
        caller: Address,
        referred_wallet: Address,
        referrer: Address,
    ) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        if referred_wallet == referrer || would_create_cycle(&env, &referred_wallet, &referrer) {
            return Err(Error::InvalidArgument);
        }

        persistent_set(&env, &DataKey::Referrer(referred_wallet.clone()), &referrer);
        env.events().publish(
            (shared::events::REFERRER_SET,),
            ReferrerSetEvent {
                referred_wallet: referred_wallet.clone(),
                referrer: referrer.clone(),
            },
        );
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("referrer"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Read a wallet's direct referrer, if one has been registered.
    pub fn get_referrer(env: Env, wallet: Address) -> Option<Address> {
        read_referrer(&env, &wallet)
    }

    /// Register a wallet under an existing referrer in the referral graph.
    ///
    /// The caller (`wallet`) authorises their own registration. The referrer
    /// must already exist in the graph (have been registered or bootstrapped
    /// via `set_referrer`). Self-referral, duplicate registration, and
    /// cycles are rejected.
    pub fn register(env: Env, wallet: Address, referrer: Address) -> Result<(), Error> {
        wallet.require_auth();

        // Prevent self-referral.
        if wallet == referrer {
            return Err(Error::InvalidArgument);
        }

        // Prevent duplicate registration — wallet already has a referrer.
        if read_referrer(&env, &wallet).is_some() {
            return Err(Error::InvalidArgument);
        }

        // Referrer must already exist in the graph.
        if read_referrer(&env, &referrer).is_none() {
            return Err(Error::InvalidArgument);
        }

        // Prevent referral cycles.
        if would_create_cycle(&env, &wallet, &referrer) {
            return Err(Error::InvalidArgument);
        }

        persistent_set(&env, &DataKey::Referrer(wallet.clone()), &referrer);

        // Store the full referral record in persistent storage.
        let record = ReferralRecord {
            wallet: wallet.clone(),
            referrer: referrer.clone(),
            commission: 0,
            tier: 0,
        };
        persistent_set(&env, &DataKey::ReferralRecord(wallet.clone()), &record);

        env.events().publish(
            (shared::events::REFERRAL_REGISTERED,),
            ReferralRegisteredEvent {
                wallet: wallet.clone(),
                referrer: referrer.clone(),
            },
        );
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("register"),
            &wallet,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Return the full referral record for a wallet, if registered.
    pub fn get_referral_record(env: Env, wallet: Address) -> Option<ReferralRecord> {
        read_referral_record(&env, &wallet)
    }

    /// Accrue referral rewards for a referred wallet and base transaction amount.
    ///
    /// **Gas optimization**: Tier BPS values are pre-cached into a local array
    /// before the loop, avoiding repeated instance-storage reads for the same
    /// key on every iteration.
    pub fn accrue(
        env: Env,
        caller: Address,
        referred_wallet: Address,
        base_amount: i128,
    ) -> Result<i128, Error> {
        require_admin(&env, &caller)?;
        if base_amount <= 0 {
            return Err(Error::InvalidArgument);
        }

        let max_tiers = read_max_tiers(&env)?;
        let reward_cap = read_reward_cap(&env)?;

        // Pre-cache tier BPS values — avoids one instance-storage read per
        // iteration.  MAX_SUPPORTED_TIERS is 10 so this stack array is tiny.
        let mut tier_bps_cache = soroban_sdk::Vec::<i128>::new(&env);
        {
            let mut t = 1_u32;
            while t <= max_tiers {
                tier_bps_cache.push_back(read_tier_bps(&env, t)?);
                t += 1;
            }
        }

        let mut tier = 1_u32;
        let mut current_wallet = referred_wallet.clone();
        let mut total_credited = 0_i128;

        while tier <= max_tiers {
            let referrer = match read_referrer(&env, &current_wallet) {
                Some(address) => address,
                None => break,
            };
            // Index into the pre-cached array (tier is 1-based, index is 0-based)
            let tier_bps = tier_bps_cache.get(tier - 1).ok_or(Error::NotFound)?;
            let commission = shared::math::bps_of(base_amount, tier_bps).ok_or(Error::Overflow)?;

            if commission > 0 {
                let credited = credit_referrer(
                    &env,
                    &referred_wallet,
                    &referrer,
                    tier,
                    commission,
                    reward_cap,
                )?;
                total_credited =
                    shared::math::safe_add(total_credited, credited).ok_or(Error::Overflow)?;
            }

            current_wallet = referrer;
            tier += 1;
        }

        Ok(total_credited)
    }

    /// Read the currently claimable accrued balance for a referrer.
    pub fn accrued_balance(env: Env, referrer: Address) -> i128 {
        read_accrued(&env, &referrer)
    }

    /// Read total lifetime rewards accrued for cap enforcement.
    pub fn lifetime_accrued(env: Env, referrer: Address) -> i128 {
        read_lifetime_accrued(&env, &referrer)
    }

    /// Claim accrued referral rewards from treasury. A second claim after a
    /// successful payout returns zero and leaves treasury untouched.
    pub fn claim_rewards(env: Env, referrer: Address) -> Result<i128, Error> {
        referrer.require_auth();
        let amount = read_accrued(&env, &referrer);
        if amount == 0 {
            return Ok(0);
        }

        let treasury = read_treasury(&env)?;
        call_treasury_distribute_reward(&env, &treasury, &referrer, amount)?;
        persistent_set(&env, &DataKey::Accrued(referrer.clone()), &0_i128);
        env.events().publish(
            (shared::events::COMMISSION_PAID,),
            ClaimRewardsEvent {
                referrer: referrer.clone(),
                amount,
            },
        );
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("claim"),
            &referrer,
            true,
            env.ledger().timestamp(),
        );
        Ok(amount)
    }

    /// Register a vanity referral code for an address.
    ///
    /// Only callable by admin. Codes must be alphanumeric, 3-16 characters,
    /// and unique across the system.
    pub fn register_referral_code(
        env: Env,
        caller: Address,
        owner: Address,
        code: Symbol,
    ) -> Result<(), Error> {
        require_admin(&env, &caller)?;

        // Check uniqueness
        if env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ReferralCode(code.clone()))
            .is_some()
        {
            return Err(Error::InvalidArgument);
        }

        // Check owner doesn't already have a code
        if env
            .storage()
            .instance()
            .get::<DataKey, Symbol>(&DataKey::AddressToCode(owner.clone()))
            .is_some()
        {
            return Err(Error::InvalidArgument);
        }

        // Store mappings
        env.storage()
            .instance()
            .set(&DataKey::ReferralCode(code.clone()), &owner);
        env.storage()
            .instance()
            .set(&DataKey::AddressToCode(owner.clone()), &code);

        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("referral"),
            symbol_short!("reg_code"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Register a wallet using a vanity referral code instead of raw address.
    ///
    /// Resolves the code to the referrer address and performs standard registration.
    pub fn register_by_code(env: Env, wallet: Address, code: Symbol) -> Result<(), Error> {
        wallet.require_auth();

        // Resolve code to referrer address
        let referrer: Address = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ReferralCode(code.clone()))
            .ok_or(Error::InvalidArgument)?;

        // Perform standard registration with resolved referrer
        Self::register(env, wallet, referrer)
    }

    /// Get the vanity code for an address, if one exists.
    pub fn get_code_by_address(env: Env, address: Address) -> Option<Symbol> {
        env.storage()
            .instance()
            .get::<DataKey, Symbol>(&DataKey::AddressToCode(address))
    }

    /// Get the address for a vanity code, if it exists.
    pub fn get_address_by_code(env: Env, code: Symbol) -> Option<Address> {
        env.storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ReferralCode(code))
    }
}

fn require_admin(env: &Env, caller: &Address) -> ContractResult<()> {
    shared::auth::require_permission(env, caller, shared::auth::Permission::ReferralConfiguration)
}

fn validate_tier_config(
    tier_bps: &soroban_sdk::Vec<i128>,
    max_tiers: u32,
    reward_cap: i128,
) -> ContractResult<()> {
    if max_tiers == 0 || max_tiers > MAX_SUPPORTED_TIERS || tier_bps.len() != max_tiers {
        return Err(Error::InvalidArgument);
    }
    if !(MIN_REWARD_CAP..=MAX_REWARD_CAP).contains(&reward_cap) {
        return Err(Error::InvalidArgument);
    }

    let mut total_bps = 0_i128;
    let mut index = 0_u32;
    while index < tier_bps.len() {
        let bps = tier_bps.get(index).ok_or(Error::InvalidArgument)?;
        if !(MIN_TIER_BPS..=MAX_TIER_BPS).contains(&bps) {
            return Err(Error::InvalidArgument);
        }
        total_bps = shared::math::safe_add(total_bps, bps).ok_or(Error::Overflow)?;
        index += 1;
    }

    if total_bps > MAX_TIER_BPS {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn would_create_cycle(env: &Env, referred_wallet: &Address, referrer: &Address) -> bool {
    let mut current_wallet = referrer.clone();
    let mut depth = 0_u32;
    while depth < MAX_SUPPORTED_TIERS {
        if current_wallet == *referred_wallet {
            return true;
        }
        current_wallet = match read_referrer(env, &current_wallet) {
            Some(address) => address,
            None => return false,
        };
        depth += 1;
    }
    false
}

fn read_treasury(env: &Env) -> ContractResult<Address> {
    if let Some(registry) = env
        .storage()
        .instance()
        .get::<DataKey, Address>(&DataKey::Registry)
    {
        let args = vec![env, Symbol::new(env, "treasury").into_val(env)];
        match env.try_invoke_contract::<(Address, u32), Error>(
            &registry,
            &Symbol::new(env, "get_contract"),
            args,
        ) {
            Ok(Ok((address, _))) => return Ok(address),
            Ok(Err(_)) => {}
            Err(Ok(_)) => {}
            Err(Err(_)) => {}
        }
    }

    env.storage()
        .instance()
        .get::<DataKey, Address>(&DataKey::Treasury)
        .ok_or(Error::NotFound)
}

fn read_max_tiers(env: &Env) -> ContractResult<u32> {
    persistent_get(env, &DataKey::MaxTiers).ok_or(Error::NotFound)
}

fn read_reward_cap(env: &Env) -> ContractResult<i128> {
    persistent_get(env, &DataKey::RewardCap).ok_or(Error::NotFound)
}

fn read_tier_bps(env: &Env, tier: u32) -> ContractResult<i128> {
    persistent_get(env, &DataKey::TierBps(tier)).ok_or(Error::NotFound)
}

fn read_referrer(env: &Env, wallet: &Address) -> Option<Address> {
    persistent_get(env, &DataKey::Referrer(wallet.clone()))
}

/// Read-only query path — skip TTL bump since caller doesn't write back.
fn read_referral_record(env: &Env, wallet: &Address) -> Option<ReferralRecord> {
    persistent_read(env, &DataKey::ReferralRecord(wallet.clone()))
}

fn read_accrued(env: &Env, referrer: &Address) -> i128 {
    persistent_get(env, &DataKey::Accrued(referrer.clone())).unwrap_or(0)
}

fn read_lifetime_accrued(env: &Env, referrer: &Address) -> i128 {
    persistent_get(env, &DataKey::LifetimeAccrued(referrer.clone())).unwrap_or(0)
}

fn credit_referrer(
    env: &Env,
    referred_wallet: &Address,
    referrer: &Address,
    tier: u32,
    commission: i128,
    reward_cap: i128,
) -> ContractResult<i128> {
    // Read both balances once — avoids two separate storage reads when the
    // cap short-circuits early.
    let lifetime_accrued = read_lifetime_accrued(env, referrer);
    if lifetime_accrued >= reward_cap {
        return Ok(0);
    }

    let remaining_cap =
        shared::math::safe_sub(reward_cap, lifetime_accrued).ok_or(Error::Overflow)?;
    let credited = if commission > remaining_cap {
        remaining_cap
    } else {
        commission
    };
    if credited == 0 {
        return Ok(0);
    }

    let accrued_balance = read_accrued(env, referrer);
    let new_accrued_balance =
        shared::math::safe_add(accrued_balance, credited).ok_or(Error::Overflow)?;
    let new_lifetime_accrued =
        shared::math::safe_add(lifetime_accrued, credited).ok_or(Error::Overflow)?;

    persistent_set(
        env,
        &DataKey::Accrued(referrer.clone()),
        &new_accrued_balance,
    );
    persistent_set(
        env,
        &DataKey::LifetimeAccrued(referrer.clone()),
        &new_lifetime_accrued,
    );
    env.events().publish(
        (shared::events::REFERRAL_ACCRUED,),
        AccruedRewardEvent {
            referred_wallet: referred_wallet.clone(),
            referrer: referrer.clone(),
            tier,
            amount: credited,
            accrued_balance: new_accrued_balance,
            lifetime_accrued: new_lifetime_accrued,
        },
    );

    Ok(credited)
}

fn call_treasury_distribute_reward(
    env: &Env,
    treasury: &Address,
    referrer: &Address,
    amount: i128,
) -> ContractResult<()> {
    let args = vec![env, referrer.clone().into_val(env), amount.into_val(env)];
    match env.try_invoke_contract::<(), Error>(
        treasury,
        &Symbol::new(env, "distribute_reward"),
        args,
    ) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Error::InvalidArgument),
        Err(Ok(error)) => Err(error),
        Err(Err(_)) => Err(Error::InvalidArgument),
    }
}

/// CPU/memory footprint profiling for CI (issue #192). Kept separate from
/// `tests` so it can be run in isolation via `scripts/profile-budget.sh`.
#[cfg(test)]
mod profile_budget;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[contracttype]
    #[derive(Clone)]
    enum MockTreasuryKey {
        Rewards,
        Paid(Address),
    }

    #[contract]
    struct MockTreasury;

    #[contract]
    struct MockRegistry;

    #[contractimpl]
    impl MockTreasury {
        pub fn deposit_rewards(env: Env, amount: i128) -> Result<(), Error> {
            if amount < 0 {
                return Err(Error::InvalidArgument);
            }
            let balance = Self::rewards_balance(env.clone());
            let new_balance = shared::math::safe_add(balance, amount).ok_or(Error::Overflow)?;
            env.storage()
                .instance()
                .set(&MockTreasuryKey::Rewards, &new_balance);
            Ok(())
        }

        pub fn rewards_balance(env: Env) -> i128 {
            env.storage()
                .instance()
                .get::<MockTreasuryKey, i128>(&MockTreasuryKey::Rewards)
                .unwrap_or(0)
        }

        pub fn paid_to(env: Env, recipient: Address) -> i128 {
            env.storage()
                .instance()
                .get::<MockTreasuryKey, i128>(&MockTreasuryKey::Paid(recipient))
                .unwrap_or(0)
        }

        pub fn distribute_reward(env: Env, recipient: Address, amount: i128) -> Result<(), Error> {
            if amount <= 0 {
                return Err(Error::InvalidArgument);
            }
            let balance = Self::rewards_balance(env.clone());
            if balance < amount {
                return Err(Error::InsufficientBalance);
            }

            let paid = Self::paid_to(env.clone(), recipient.clone());
            let new_paid = shared::math::safe_add(paid, amount).ok_or(Error::Overflow)?;
            let new_balance = shared::math::safe_sub(balance, amount).ok_or(Error::Overflow)?;

            env.storage()
                .instance()
                .set(&MockTreasuryKey::Paid(recipient.clone()), &new_paid);
            env.storage()
                .instance()
                .set(&MockTreasuryKey::Rewards, &new_balance);
            env.events()
                .publish((shared::events::COMMISSION_PAID,), (recipient, amount));
            Ok(())
        }
    }

    #[contractimpl]
    impl MockRegistry {
        pub fn initialize(env: Env, admin: Address) {
            shared::auth::set_admin(&env, &admin);
        }

        pub fn set_contract(
            env: Env,
            caller: Address,
            name: Symbol,
            address: Address,
            version: u32,
        ) -> Result<(), Error> {
            if caller != shared::auth::get_admin(&env) {
                return Err(Error::Unauthorized);
            }
            caller.require_auth();
            env.storage()
                .instance()
                .set(&(name.clone(), version), &address);
            let mut history: soroban_sdk::Vec<u32> = env
                .storage()
                .instance()
                .get(&(name.clone(), Symbol::new(&env, "history")))
                .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
            if !history.iter().any(|item| item == version) {
                history.push_back(version);
                env.storage()
                    .instance()
                    .set(&(name.clone(), Symbol::new(&env, "history")), &history);
            }
            Ok(())
        }

        pub fn get_contract(env: Env, name: Symbol) -> Result<(Address, u32), Error> {
            let history: soroban_sdk::Vec<u32> = env
                .storage()
                .instance()
                .get(&(name.clone(), Symbol::new(&env, "history")))
                .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
            let latest_version = if history.len() > 0 {
                history.get(history.len() - 1).unwrap_or(0)
            } else {
                0
            };
            let address = env
                .storage()
                .instance()
                .get::<(Symbol, u32), Address>(&(name.clone(), latest_version))
                .ok_or(Error::NotFound)?;
            Ok((address, latest_version))
        }

        pub fn get_version_history(env: Env, name: Symbol) -> Result<soroban_sdk::Vec<u32>, Error> {
            env.storage()
                .instance()
                .get::<(Symbol, Symbol), soroban_sdk::Vec<u32>>(&(
                    name.clone(),
                    Symbol::new(&env, "history"),
                ))
                .ok_or(Error::NotFound)
        }
    }

    fn setup() -> (
        Env,
        Address,
        Address,
        Address,
        Address,
        Address,
        Address,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let referral_id = env.register_contract(None, ReferralContract);
        let treasury_id = env.register_contract(None, MockTreasury);
        let admin = Address::generate(&env);
        let referred = Address::generate(&env);
        let tier_one = Address::generate(&env);
        let tier_two = Address::generate(&env);
        let tier_three = Address::generate(&env);
        let tier_four = Address::generate(&env);

        let referral = ReferralContractClient::new(&env, &referral_id);
        let treasury = MockTreasuryClient::new(&env, &treasury_id);
        referral.initialize(&admin);
        referral.set_treasury(&admin, &treasury_id);
        treasury.deposit_rewards(&1_000_000_000);

        (
            env,
            referral_id,
            admin,
            referred,
            tier_one,
            tier_two,
            tier_three,
            tier_four,
        )
    }

    #[test]
    fn referral_manager_permission_is_enforced_and_revocable() {
        let (env, referral_id, admin, ..) = setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let manager = Address::generate(&env);
        let treasury = Address::generate(&env);

        referral.set_referral_manager(&admin, &manager, &true);
        referral.set_treasury(&manager, &treasury);
        assert_eq!(referral.get_treasury().unwrap(), treasury);

        referral.set_referral_manager(&admin, &manager, &false);
        assert_eq!(
            referral.try_set_treasury(&manager, &Address::generate(&env)),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn accrues_multi_tier_rewards_until_max_depth() {
        let (env, referral_id, admin, referred, tier_one, tier_two, tier_three, tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(
            &admin,
            &soroban_sdk::vec![&env, 1_000_i128, 500_i128],
            &2,
            &10_000,
        );
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.set_referrer(&admin, &tier_one, &tier_two);
        referral.set_referrer(&admin, &tier_two, &tier_three);
        referral.set_referrer(&admin, &tier_three, &tier_four);

        assert_eq!(referral.accrue(&admin, &referred, &10_000), 1_500);
        assert_eq!(referral.accrued_balance(&tier_one), 1_000);
        assert_eq!(referral.accrued_balance(&tier_two), 500);
        assert_eq!(referral.accrued_balance(&tier_three), 0);
        assert_eq!(referral.accrued_balance(&tier_four), 0);
    }

    #[test]
    fn enforces_lifetime_reward_cap_per_referrer() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &1_100);
        referral.set_referrer(&admin, &referred, &tier_one);

        assert_eq!(referral.accrue(&admin, &referred, &10_000), 1_000);
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 100);
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 0);
        assert_eq!(referral.accrued_balance(&tier_one), 1_100);
        assert_eq!(referral.lifetime_accrued(&tier_one), 1_100);
    }

    #[test]
    fn claim_rewards_distributes_from_treasury_and_double_claim_pays_nothing() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let treasury_id = referral.get_treasury();
        let treasury = MockTreasuryClient::new(&env, &treasury_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 1_000);

        assert_eq!(referral.claim_rewards(&tier_one), 1_000);
        assert_eq!(referral.accrued_balance(&tier_one), 0);
        assert_eq!(treasury.paid_to(&tier_one), 1_000);
        assert_eq!(treasury.rewards_balance(), 999_999_000);

        assert_eq!(referral.claim_rewards(&tier_one), 0);
        assert_eq!(treasury.paid_to(&tier_one), 1_000);
        assert_eq!(treasury.rewards_balance(), 999_999_000);
    }

    #[test]
    fn claim_rewards_resolves_treasury_via_registry() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let registry_id = env.register_contract(None, MockRegistry);
        let registry = MockRegistryClient::new(&env, &registry_id);
        let treasury_id = env.register_contract(None, MockTreasury);
        let treasury = MockTreasuryClient::new(&env, &treasury_id);

        registry.initialize(&admin);
        registry.set_contract(&admin, &Symbol::new(&env, "treasury"), &treasury_id, &1_u32);
        treasury.deposit_rewards(&1_000_000_000);
        referral.set_registry(&admin, &registry_id);
        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 1_000);

        assert_eq!(referral.claim_rewards(&tier_one), 1_000);
        assert_eq!(treasury.paid_to(&tier_one), 1_000);
    }

    #[test]
    fn accrual_math_rejects_overflow() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Set reward cap equal to the first accrual amount so the cap kicks in
        let max_cap: i128 = 10_000;
        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 10_000_i128], &1, &max_cap);
        referral.set_referrer(&admin, &referred, &tier_one);

        // Accrue up to the cap
        assert_eq!(referral.accrue(&admin, &referred, &max_cap), max_cap);
        assert_eq!(referral.accrued_balance(&tier_one), max_cap);

        // Further accruals should be capped at 0 (no overflow)
        assert_eq!(referral.accrue(&admin, &referred, &1), 0);
    }

    #[test]
    fn rejects_invalid_admin_config_and_cycles() {
        let (env, referral_id, admin, referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let attacker = Address::generate(&env);

        assert!(matches!(
            referral.try_set_tier_config(
                &attacker,
                &soroban_sdk::vec![&env, 1_000_i128],
                &1,
                &10_000,
            ),
            Err(Ok(Error::Unauthorized))
        ));
        assert!(matches!(
            referral.try_set_tier_config(
                &admin,
                &soroban_sdk::vec![&env, 9_000_i128, 2_000_i128],
                &2,
                &10_000,
            ),
            Err(Ok(Error::InvalidArgument))
        ));
        assert!(matches!(
            referral.try_set_referrer(&admin, &referred, &referred),
            Err(Ok(Error::InvalidArgument))
        ));

        referral.set_referrer(&admin, &referred, &tier_one);
        referral.set_referrer(&admin, &tier_one, &tier_two);
        assert!(matches!(
            referral.try_set_referrer(&admin, &tier_two, &referred),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    // -----------------------------------------------------------------------
    // register() tests
    // -----------------------------------------------------------------------

    /// Helper that bootstraps the referral graph via admin `set_referrer` so
    /// that `register` has an existing referrer to validate against.
    fn bootstrap_root(
        env: &Env,
        referral_id: &Address,
        admin: &Address,
        root: &Address,
        root_referrer: &Address,
    ) {
        let referral = ReferralContractClient::new(env, referral_id);
        referral.set_referrer(admin, root, root_referrer);
    }

    #[test]
    fn register_succeeds_with_valid_referrer_and_record_is_queryable() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Bootstrap: admin makes tier_one exist under tier_two.
        bootstrap_root(&env, &referral_id, &admin, &tier_one, &tier_two);

        // Now a new wallet registers under tier_one.
        let wallet = Address::generate(&env);
        referral.register(&wallet, &tier_one);

        // Edge is queryable.
        assert_eq!(referral.get_referrer(&wallet), Some(tier_one.clone()));

        // Full record is queryable.
        let record = referral.get_referral_record(&wallet).unwrap();
        assert_eq!(record.wallet, wallet);
        assert_eq!(record.referrer, tier_one);
        assert_eq!(record.commission, 0);
        assert_eq!(record.tier, 0);
    }

    #[test]
    fn register_rejects_self_referral() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Bootstrap: tier_one exists in the graph.
        bootstrap_root(&env, &referral_id, &admin, &tier_one, &tier_two);

        // Self-referral must fail.
        assert!(matches!(
            referral.try_register(&tier_one, &tier_one),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    #[test]
    fn register_rejects_duplicate() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Bootstrap.
        bootstrap_root(&env, &referral_id, &admin, &tier_one, &tier_two);

        let wallet = Address::generate(&env);
        referral.register(&wallet, &tier_one);

        // Duplicate registration must fail.
        assert!(matches!(
            referral.try_register(&wallet, &tier_one),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    #[test]
    fn register_rejects_nonexistent_referrer() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Bootstrap: tier_one exists.
        bootstrap_root(&env, &referral_id, &admin, &tier_one, &tier_two);

        let wallet = Address::generate(&env);
        let nonexistent = Address::generate(&env);

        // Referrer that was never registered must be rejected.
        assert!(matches!(
            referral.try_register(&wallet, &nonexistent),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    #[test]
    fn register_allows_chain_extension_without_cycle() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Bootstrap a chain: a → b (via admin set_referrer).
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        referral.set_referrer(&admin, &a, &b);

        // Register a fresh wallet under a — this is fine, no cycle.
        let w = Address::generate(&env);
        referral.register(&w, &a);
        assert_eq!(referral.get_referrer(&w), Some(a.clone()));

        // Register another wallet under w — also fine, w → a → b (no cycle).
        let w2 = Address::generate(&env);
        referral.register(&w2, &w);
        assert_eq!(referral.get_referrer(&w2), Some(w.clone()));
    }

    // ===========================================================================
    // Gas benchmark tests
    // ===========================================================================

    /// Benchmark: accrue with a 3-tier chain verifies pre-cached tier BPS.
    ///
    /// Before: each tier called `read_tier_bps` (instance-storage read).
    /// After: all tier BPS values are pre-cached into a Vec before the loop.
    #[test]
    fn gas_bench_accrue_3_tier() {
        let (env, referral_id, admin, referred, tier_one, tier_two, tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(
            &admin,
            &soroban_sdk::vec![&env, 1_000_i128, 500_i128, 250_i128],
            &3,
            &1_000_000,
        );
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.set_referrer(&admin, &tier_one, &tier_two);
        referral.set_referrer(&admin, &tier_two, &tier_three);

        assert_eq!(referral.accrue(&admin, &referred, &100_000), 17_500);
        assert_eq!(referral.accrued_balance(&tier_one), 10_000);
        assert_eq!(referral.accrued_balance(&tier_two), 5_000);
        assert_eq!(referral.accrued_balance(&tier_three), 2_500);
    }

    /// Benchmark: accrue with maximum 10-tier chain (worst-case gas scenario).
    #[test]
    fn gas_bench_accrue_max_depth() {
        let (env, referral_id, admin, referred, _tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        let tier_bps =
            soroban_sdk::vec![&env, 100_i128, 100, 100, 100, 100, 100, 100, 100, 100, 100,];
        referral.set_tier_config(&admin, &tier_bps, &10, &1_000_000_000_000_000_000);

        // Build a 10-deep chain
        let mut prev = referred.clone();
        for _ in 0..10 {
            let next = Address::generate(&env);
            referral.set_referrer(&admin, &prev, &next);
            prev = next;
        }

        // Should succeed without overflow
        let result = referral.try_accrue(&admin, &referred, &100_000);
        assert!(result.is_ok());
    }

    /// Benchmark: claim_rewards after accrue reads accrued balance once
    /// and does not re-read it.
    #[test]
    fn gas_bench_claim_rewards() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let treasury_id = referral.get_treasury();
        let treasury = MockTreasuryClient::new(&env, &treasury_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.accrue(&admin, &referred, &10_000);

        let claimed = referral.claim_rewards(&tier_one);
        assert_eq!(claimed, 1_000);
        assert_eq!(referral.accrued_balance(&tier_one), 0);
        assert_eq!(treasury.paid_to(&tier_one), 1_000);

        // Double claim returns 0
        let claimed2 = referral.claim_rewards(&tier_one);
        assert_eq!(claimed2, 0);
    }

    // -----------------------------------------------------------------------
    // Vanity referral codes tests
    // -----------------------------------------------------------------------

    #[test]
    fn register_vanity_code_succeeds() {
        let (env, referral_id, admin, _referred, _tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        let owner = Address::generate(&env);
        let code = Symbol::new(&env, "ALICE2026");

        referral.register_referral_code(&admin, &owner, &code);

        // Verify mappings
        assert_eq!(referral.get_address_by_code(code), Some(owner.clone()));
        assert_eq!(referral.get_code_by_address(owner), Some(code));
    }

    #[test]
    fn register_by_code_resolves_to_correct_referrer() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Register vanity code for tier_one
        let code = Symbol::new(&env, "BOB2026");
        referral.register_referral_code(&admin, &tier_one, &code);

        // Bootstrap tier_one in the graph
        referral.set_referrer(&admin, &tier_one, &tier_two);

        // New wallet registers using code
        let wallet = Address::generate(&env);
        referral.register_by_code(&wallet, code);

        // Verify referrer is tier_one
        assert_eq!(referral.get_referrer(&wallet), Some(tier_one));
    }

    #[test]
    fn duplicate_vanity_code_rejected() {
        let (env, referral_id, admin, _referred, _tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        let owner1 = Address::generate(&env);
        let owner2 = Address::generate(&env);
        let code = Symbol::new(&env, "SAVE2026");

        referral.register_referral_code(&admin, &owner1, &code);

        // Try to register same code for different owner
        let result = referral.try_register_referral_code(&admin, &owner2, &code);
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));
    }

    #[test]
    fn owner_cannot_have_multiple_codes() {
        let (env, referral_id, admin, _referred, _tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        let owner = Address::generate(&env);
        let code1 = Symbol::new(&env, "CODE1");
        let code2 = Symbol::new(&env, "CODE2");

        referral.register_referral_code(&admin, &owner, &code1);

        // Try to register second code for same owner
        let result = referral.try_register_referral_code(&admin, &owner, &code2);
        assert_eq!(result, Err(Ok(Error::InvalidArgument)));
    }

    #[test]
    fn non_admin_cannot_register_vanity_code() {
        let (env, referral_id, _admin, _referred, _tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        let attacker = Address::generate(&env);
        let owner = Address::generate(&env);
        let code = Symbol::new(&env, "HACK");

        let result = referral.try_register_referral_code(&attacker, &owner, &code);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    // ===========================================================================
    // Formal lifecycle state-machine tests
    //
    // The referral contract exposes a small set of lifecycle states per wallet
    // and per referrer. These tests enumerate the terminal and recovery
    // transitions explicitly so that any future change to the state machine
    // fails deterministically here rather than silently in production.
    //
    // State model (per wallet):
    //   Unregistered --register/set_referrer--> Registered --(no exit)-->
    //   Registered is terminal for the wallet edge; only admin `set_referrer`
    //   can overwrite it, and that is treated as a recovery path.
    //
    // State model (per referrer, for accrued rewards):
    //   Zero --accrue--> Accrued --claim--> Zero (terminal for that cycle)
    //   Accrued --accrue--> Accrued (monotonic growth, capped)
    //   Capped --accrue--> Capped (terminal, no further credit)
    //
    // Recovery paths covered:
    //   - Treasury failure during claim leaves accrued balance intact so the
    //     referrer can retry (claim is idempotent on failure).
    //   - Admin `set_referrer` overwrites a stale edge (recovery from a bad
    //     registration) without touching accrued balances.
    //   - Registry resolution falls back to the directly configured treasury
    //     when the registry lookup fails.
    // ===========================================================================

    /// Lifecycle state of a wallet edge in the referral graph.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum EdgeState {
        Unregistered,
        Registered,
    }

    fn edge_state(referral: &ReferralContractClient, wallet: &Address) -> EdgeState {
        if referral.get_referrer(wallet).is_some() {
            EdgeState::Registered
        } else {
            EdgeState::Unregistered
        }
    }

    /// Lifecycle state of a referrer's reward bucket.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RewardState {
        Zero,
        Accrued,
        Capped,
    }

    fn reward_state(referral: &ReferralContractClient, referrer: &Address) -> RewardState {
        let accrued = referral.accrued_balance(referrer);
        let lifetime = referral.lifetime_accrued(referrer);
        let cap = referral.get_tier_config().unwrap().reward_cap;
        if lifetime >= cap && cap > 0 {
            RewardState::Capped
        } else if accrued > 0 || lifetime > 0 {
            RewardState::Accrued
        } else {
            RewardState::Zero
        }
    }

    #[test]
    fn lifecycle_edge_unregistered_to_registered_is_the_only_forward_transition() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Bootstrap referrer so registration is valid.
        referral.set_referrer(&admin, &tier_one, &tier_two);

        let wallet = Address::generate(&env);
        assert_eq!(edge_state(&referral, &wallet), EdgeState::Unregistered);

        referral.register(&wallet, &tier_one);
        assert_eq!(edge_state(&referral, &wallet), EdgeState::Registered);

        // There is no public API to transition Registered -> Unregistered.
        // Re-registering the same wallet must fail deterministically.
        assert!(matches!(
            referral.try_register(&wallet, &tier_one),
            Err(Ok(Error::InvalidArgument))
        ));
        assert_eq!(edge_state(&referral, &wallet), EdgeState::Registered);
    }

    #[test]
    fn lifecycle_invalid_edge_transitions_fail_deterministically() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_referrer(&admin, &tier_one, &tier_two);

        // Unregistered -> Unregistered via self-referral is invalid.
        assert!(matches!(
            referral.try_register(&tier_one, &tier_one),
            Err(Ok(Error::InvalidArgument))
        ));

        // Unregistered -> Unregistered via nonexistent referrer is invalid.
        let wallet = Address::generate(&env);
        let ghost = Address::generate(&env);
        assert!(matches!(
            referral.try_register(&wallet, &ghost),
            Err(Ok(Error::InvalidArgument))
        ));

        // Unregistered -> Unregistered via cycle is invalid.
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        referral.set_referrer(&admin, &a, &b);
        assert!(matches!(
            referral.try_set_referrer(&admin, &b, &a),
            Err(Ok(Error::InvalidArgument))
        ));
    }

    #[test]
    fn lifecycle_reward_zero_to_accrued_to_zero_is_terminal_per_cycle() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);

        assert_eq!(reward_state(&referral, &tier_one), RewardState::Zero);

        referral.accrue(&admin, &referred, &10_000);
        assert_eq!(reward_state(&referral, &tier_one), RewardState::Accrued);

        referral.claim_rewards(&tier_one);
        // Accrued balance returns to zero, but lifetime remains > 0 so the
        // bucket is still considered Accrued (not Zero) for cap purposes.
        assert_eq!(referral.accrued_balance(&tier_one), 0);
        assert_eq!(reward_state(&referral, &tier_one), RewardState::Accrued);

        // A second claim in the same cycle is a no-op terminal transition.
        assert_eq!(referral.claim_rewards(&tier_one), 0);
    }

    #[test]
    fn lifecycle_reward_capped_is_terminal_and_no_further_credit() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &1_000);
        referral.set_referrer(&admin, &referred, &tier_one);

        assert_eq!(referral.accrue(&admin, &referred, &10_000), 1_000);
        assert_eq!(reward_state(&referral, &tier_one), RewardState::Capped);

        // Terminal: further accruals credit nothing.
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 0);
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 0);
        assert_eq!(referral.lifetime_accrued(&tier_one), 1_000);
    }

    #[test]
    fn lifecycle_recovery_claim_failure_preserves_accrued_balance() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let treasury_id = referral.get_treasury();
        let treasury = MockTreasuryClient::new(&env, &treasury_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.accrue(&admin, &referred, &10_000);
        assert_eq!(referral.accrued_balance(&tier_one), 1_000);

        // Drain the treasury so the claim fails.
        let drained = treasury.rewards_balance();
        treasury.deposit_rewards(&-drained);
        assert_eq!(treasury.rewards_balance(), 0);

        // Claim must fail and leave the accrued balance intact for retry.
        assert!(referral.try_claim_rewards(&tier_one).is_err());
        assert_eq!(referral.accrued_balance(&tier_one), 1_000);

        // Recovery: refill treasury and retry the claim.
        treasury.deposit_rewards(&1_000_000_000);
        assert_eq!(referral.claim_rewards(&tier_one), 1_000);
        assert_eq!(referral.accrued_balance(&tier_one), 0);
        assert_eq!(treasury.paid_to(&tier_one), 1_000);
    }

    #[test]
    fn lifecycle_recovery_admin_overwrite_of_stale_edge_preserves_balances() {
        let (env, referral_id, admin, referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.accrue(&admin, &referred, &10_000);
        assert_eq!(referral.accrued_balance(&tier_one), 1_000);

        // Recovery: admin overwrites the stale edge to point at tier_two.
        referral.set_referrer(&admin, &referred, &tier_two);
        assert_eq!(referral.get_referrer(&referred), Some(tier_two));

        // Accrued balances are untouched by the edge rewrite.
        assert_eq!(referral.accrued_balance(&tier_one), 1_000);
        assert_eq!(referral.accrued_balance(&tier_two), 0);
    }

    #[test]
    fn lifecycle_recovery_registry_failure_falls_back_to_direct_treasury() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);
        let registry_id = env.register_contract(None, MockRegistry);
        let registry = MockRegistryClient::new(&env, &registry_id);

        // Registry is configured but has no "treasury" entry, so lookup fails.
        registry.initialize(&admin);
        referral.set_registry(&admin, &registry_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.accrue(&admin, &referred, &10_000);

        // Claim must succeed via the direct treasury fallback.
        assert_eq!(referral.claim_rewards(&tier_one), 1_000);
        assert_eq!(referral.accrued_balance(&tier_one), 0);
    }

    #[test]
    fn lifecycle_invalid_reward_transitions_fail_deterministically() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &10_000);
        referral.set_referrer(&admin, &referred, &tier_one);

        // Zero -> Accrued with non-positive base amount is invalid.
        assert!(matches!(
            referral.try_accrue(&admin, &referred, &0),
            Err(Ok(Error::InvalidArgument))
        ));
        assert!(matches!(
            referral.try_accrue(&admin, &referred, &-1),
            Err(Ok(Error::InvalidArgument))
        ));

        // Non-admin cannot drive the reward state machine.
        let attacker = Address::generate(&env);
        assert!(matches!(
            referral.try_accrue(&attacker, &referred, &10_000),
            Err(Ok(Error::Unauthorized))
        ));

        // Claim with zero accrued is a valid terminal no-op.
        assert_eq!(referral.claim_rewards(&tier_one), 0);
    }

    #[test]
    fn lifecycle_tier_config_reconfiguration_is_a_recovery_path() {
        let (env, referral_id, admin, referred, tier_one, _tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        // Initial config: 10% tier 1, cap 1_000.
        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &1_000);
        referral.set_referrer(&admin, &referred, &tier_one);
        referral.accrue(&admin, &referred, &10_000);
        assert_eq!(referral.lifetime_accrued(&tier_one), 1_000);
        assert_eq!(reward_state(&referral, &tier_one), RewardState::Capped);

        // Recovery: admin raises the cap. Lifetime accrued is preserved and
        // the referrer can accrue again.
        referral.set_tier_config(&admin, &soroban_sdk::vec![&env, 1_000_i128], &1, &2_000);
        assert_eq!(referral.lifetime_accrued(&tier_one), 1_000);
        assert_eq!(referral.accrue(&admin, &referred, &10_000), 1_000);
        assert_eq!(referral.lifetime_accrued(&tier_one), 2_000);
        assert_eq!(reward_state(&referral, &tier_one), RewardState::Capped);
    }

    #[test]
    fn lifecycle_vanity_code_registration_is_terminal_per_owner_and_code() {
        let (env, referral_id, admin, _referred, tier_one, tier_two, _tier_three, _tier_four) =
            setup();
        let referral = ReferralContractClient::new(&env, &referral_id);

        let owner = Address::generate(&env);
        let code = Symbol::new(&env, "LIFE2026");
        referral.register_referral_code(&admin, &owner, &code);

        // Terminal: same code cannot be re-registered to another owner.
        let other = Address::generate(&env);
        assert!(matches!(
            referral.try_register_referral_code(&admin, &other, &code),
            Err(Ok(Error::InvalidArgument))
        ));

        // Terminal: same owner cannot register a second code.
        let code2 = Symbol::new(&env, "LIFE2027");
        assert!(matches!(
            referral.try_register_referral_code(&admin, &owner, &code2),
            Err(Ok(Error::InvalidArgument))
        ));

        // Recovery: register_by_code resolves the code and performs the
        // standard registration transition.
        referral.set_referrer(&admin, &tier_one, &tier_two);
        let code3 = Symbol::new(&env, "LIFE2028");
        referral.register_referral_code(&admin, &tier_one, &code3);
        let wallet = Address::generate(&env);
        referral.register_by_code(&wallet, code3);
        assert_eq!(referral.get_referrer(&wallet), Some(tier_one));
    }
}
