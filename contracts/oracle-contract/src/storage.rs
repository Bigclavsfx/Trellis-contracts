use crate::types::{FeedLatest, PriceSubmission, SubmitterInfo};
use shared::storage::{persistent_get, persistent_set};
use soroban_sdk::{contracttype, symbol_short, Address, Env, Map, Symbol, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakingConfig {
    pub min_stake: i128,
    pub token: Address,
    pub unbonding_cooldown: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnbondingRequest {
    pub amount: i128,
    pub unlock_time: u64,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    MinPriceQuorum,
    FeedQuorum(Symbol),
    SubmitterStake(Address),
    StakingConfig,
    UnbondingRequest(Address),
    Treasury,
}

// Storage key symbols (all <= 9 chars for symbol_short!)
const KEY_SUBMITTERS: Symbol = symbol_short!("submits");
const KEY_FEED_LATEST: Symbol = symbol_short!("feed_lat");
const KEY_FEED_ACTIVE: Symbol = symbol_short!("feed_act");
const KEY_FEED_HISTORY: Symbol = symbol_short!("feed_his");
const KEY_NEXT_SUBMISSION_ID: Symbol = symbol_short!("sub_id");
const KEY_NONCE: Symbol = symbol_short!("nonce");
const KEY_STALENESS_WINDOW: Symbol = symbol_short!("stale_wd");

/// Get or initialize the submitters map.
pub fn get_submitters(env: &Env) -> Map<Address, SubmitterInfo> {
    env.storage()
        .instance()
        .get(&KEY_SUBMITTERS)
        .unwrap_or_else(|| Map::new(env))
}

/// Set the submitters map.
pub fn set_submitters(env: &Env, submitters: &Map<Address, SubmitterInfo>) {
    env.storage().instance().set(&KEY_SUBMITTERS, submitters);
}

/// Check if a submitter is registered, active, and maintains required stake (if configured).
pub fn is_submitter_active(env: &Env, submitter: &Address) -> bool {
    let is_active = get_submitters(env)
        .get(submitter.clone())
        .map(|info| info.active)
        .unwrap_or(false);
    if !is_active {
        return false;
    }
    if let Some(config) = get_staking_config(env) {
        if config.min_stake > 0 {
            let stake = get_submitter_stake(env, submitter);
            if stake < config.min_stake {
                return false;
            }
        }
    }
    true
}

/// Check if a submitter is registered (active or inactive).
pub fn is_submitter_registered(env: &Env, submitter: &Address) -> bool {
    get_submitters(env).get(submitter.clone()).is_some()
}


/// Count currently active price submitters.
pub fn active_submitter_count(env: &Env) -> u32 {
    let mut count = 0;
    for (_, info) in get_submitters(env).iter() {
        if info.active {
            count += 1;
        }
    }
    count
}

pub fn min_price_quorum(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::MinPriceQuorum)
        .unwrap_or(2)
}

pub fn set_min_price_quorum(env: &Env, quorum: u32) {
    env.storage()
        .instance()
        .set(&DataKey::MinPriceQuorum, &quorum);
}

pub fn feed_quorum(env: &Env, feed_id: &Symbol) -> Option<u32> {
    env.storage()
        .instance()
        .get(&DataKey::FeedQuorum(feed_id.clone()))
}

pub fn set_feed_quorum(env: &Env, feed_id: &Symbol, quorum: u32) {
    env.storage()
        .instance()
        .set(&DataKey::FeedQuorum(feed_id.clone()), &quorum);
}

pub fn remove_feed_quorum(env: &Env, feed_id: &Symbol) {
    env.storage()
        .instance()
        .remove(&DataKey::FeedQuorum(feed_id.clone()));
}

/// Register a new submitter.
pub fn register_submitter(
    env: &Env,
    submitter: Address,
    registered_at: u64,
) -> Result<(), crate::errors::OracleError> {
    let mut submitters = get_submitters(env);
    if submitters.get(submitter.clone()).is_some() {
        return Err(crate::errors::OracleError::SubmitterAlreadyRegistered);
    }
    let info = SubmitterInfo {
        address: submitter.clone(),
        active: true,
        registered_at,
    };
    submitters.set(submitter, info);
    set_submitters(env, &submitters);
    Ok(())
}

/// Deactivate a submitter.
pub fn deactivate_submitter(env: &Env, submitter: &Address) {
    let mut submitters = get_submitters(env);
    if let Some(mut info) = submitters.get(submitter.clone()) {
        info.active = false;
        submitters.set(submitter.clone(), info);
        set_submitters(env, &submitters);
    }
}

/// Activate a submitter.
#[allow(dead_code)]
pub fn activate_submitter(env: &Env, submitter: &Address) {
    let mut submitters = get_submitters(env);
    if let Some(mut info) = submitters.get(submitter.clone()) {
        info.active = true;
        submitters.set(submitter.clone(), info);
        set_submitters(env, &submitters);
    }
}

/// Get the latest price for a feed.
#[allow(dead_code)]
pub fn get_feed_latest(env: &Env, feed_id: &Symbol) -> Option<FeedLatest> {
    let feeds: Map<Symbol, FeedLatest> = env
        .storage()
        .instance()
        .get(&KEY_FEED_LATEST)
        .unwrap_or_else(|| Map::new(env));
    feeds.get(feed_id.clone())
}

/// Set or update the latest price for a feed.
pub fn set_feed_latest(env: &Env, feed_id: &Symbol, latest: &FeedLatest) {
    let mut feeds: Map<Symbol, FeedLatest> = env
        .storage()
        .instance()
        .get(&KEY_FEED_LATEST)
        .unwrap_or_else(|| Map::new(env));
    feeds.set(feed_id.clone(), latest.clone());
    env.storage().instance().set(&KEY_FEED_LATEST, &feeds);
}

/// Get the latest active submission per submitter for a feed.
pub fn get_feed_active_submissions(env: &Env, feed_id: &Symbol) -> Map<Address, PriceSubmission> {
    let feeds: Map<Symbol, Map<Address, PriceSubmission>> = env
        .storage()
        .instance()
        .get(&KEY_FEED_ACTIVE)
        .unwrap_or_else(|| Map::new(env));
    feeds.get(feed_id.clone()).unwrap_or_else(|| Map::new(env))
}

/// Record the latest active submission for the submitting address.
pub fn set_feed_active_submission(env: &Env, feed_id: &Symbol, submission: &PriceSubmission) {
    let mut feeds: Map<Symbol, Map<Address, PriceSubmission>> = env
        .storage()
        .instance()
        .get(&KEY_FEED_ACTIVE)
        .unwrap_or_else(|| Map::new(env));
    let mut submitter_prices = feeds.get(feed_id.clone()).unwrap_or_else(|| Map::new(env));
    submitter_prices.set(submission.submitter.clone(), submission.clone());
    feeds.set(feed_id.clone(), submitter_prices);
    env.storage().instance().set(&KEY_FEED_ACTIVE, &feeds);
}

/// Get submission history for a feed (limited to most recent N submissions).
pub fn get_feed_history(env: &Env, feed_id: &Symbol, limit: u32) -> Vec<PriceSubmission> {
    let history: Map<Symbol, Vec<PriceSubmission>> =
        persistent_get(env, &KEY_FEED_HISTORY).unwrap_or_else(|| Map::new(env));

    if let Some(submissions) = history.get(feed_id.clone()) {
        let len = submissions.len() as u32;
        let start = if len > limit { (len - limit) as u32 } else { 0 };
        let mut result = Vec::new(env);
        let mut i = start;
        while i < submissions.len() {
            if let Some(sub) = submissions.get(i) {
                result.push_back(sub);
            }
            i += 1;
        }
        result
    } else {
        Vec::new(env)
    }
}

/// Append a submission to the history for a feed.
pub fn append_submission(env: &Env, feed_id: &Symbol, submission: &PriceSubmission) {
    let mut history: Map<Symbol, Vec<PriceSubmission>> =
        persistent_get(env, &KEY_FEED_HISTORY).unwrap_or_else(|| Map::new(env));

    let mut submissions = history
        .get(feed_id.clone())
        .unwrap_or_else(|| Vec::new(env));
    submissions.push_back(submission.clone());
    history.set(feed_id.clone(), submissions);
    persistent_set(env, &KEY_FEED_HISTORY, &history);
}

/// Get the next submission ID and increment the counter.
pub fn next_submission_id(env: &Env) -> Result<u64, crate::errors::OracleError> {
    let current: u64 = env
        .storage()
        .instance()
        .get(&KEY_NEXT_SUBMISSION_ID)
        .unwrap_or(0);
    let next = current
        .checked_add(1)
        .ok_or(crate::errors::OracleError::InternalError)?;
    env.storage().instance().set(&KEY_NEXT_SUBMISSION_ID, &next);
    Ok(next)
}

/// Get the nonce for a submitter and feed (for replay protection).
pub fn get_nonce(env: &Env, submitter: &Address, feed_id: &Symbol) -> u64 {
    let nonces: Map<(Address, Symbol), u64> = env
        .storage()
        .instance()
        .get(&KEY_NONCE)
        .unwrap_or_else(|| Map::new(env));
    nonces
        .get((submitter.clone(), feed_id.clone()))
        .unwrap_or(0)
}

/// Set the nonce for a submitter and feed.
pub fn set_nonce(env: &Env, submitter: &Address, feed_id: &Symbol, nonce: u64) {
    let mut nonces: Map<(Address, Symbol), u64> = env
        .storage()
        .instance()
        .get(&KEY_NONCE)
        .unwrap_or_else(|| Map::new(env));
    nonces.set((submitter.clone(), feed_id.clone()), nonce);
    env.storage().instance().set(&KEY_NONCE, &nonces);
}

/// Get the staleness window (in seconds) for feed submissions.
pub fn get_staleness_window(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&KEY_STALENESS_WINDOW)
        .unwrap_or(3600) // Default: 1 hour
}

/// Set the staleness window.
pub fn set_staleness_window(env: &Env, seconds: u64) {
    env.storage()
        .instance()
        .set(&KEY_STALENESS_WINDOW, &seconds);
}

/// Get the stake amount for a submitter under DataKey::SubmitterStake(Address).
pub fn get_submitter_stake(env: &Env, submitter: &Address) -> i128 {
    persistent_get(env, &DataKey::SubmitterStake(submitter.clone())).unwrap_or(0)
}

/// Set the stake amount for a submitter under DataKey::SubmitterStake(Address).
pub fn set_submitter_stake(env: &Env, submitter: &Address, amount: i128) {
    persistent_set(env, &DataKey::SubmitterStake(submitter.clone()), &amount);
}

/// Get the staking configuration.
pub fn get_staking_config(env: &Env) -> Option<StakingConfig> {
    env.storage().instance().get(&DataKey::StakingConfig)
}

/// Set the staking configuration.
pub fn set_staking_config(env: &Env, config: &StakingConfig) {
    env.storage().instance().set(&DataKey::StakingConfig, config);
}

/// Get the pending unbonding request for a submitter.
pub fn get_unbonding_request(env: &Env, submitter: &Address) -> Option<UnbondingRequest> {
    persistent_get(env, &DataKey::UnbondingRequest(submitter.clone()))
}

/// Set the pending unbonding request for a submitter.
pub fn set_unbonding_request(env: &Env, submitter: &Address, request: &UnbondingRequest) {
    persistent_set(
        env,
        &DataKey::UnbondingRequest(submitter.clone()),
        request,
    );
}

/// Remove the unbonding request for a submitter.
pub fn remove_unbonding_request(env: &Env, submitter: &Address) {
    shared::storage::persistent_remove(env, &DataKey::UnbondingRequest(submitter.clone()));
}

/// Get the treasury contract address.
pub fn get_treasury(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Treasury)
}

/// Set the treasury contract address.
pub fn set_treasury(env: &Env, treasury: &Address) {
    env.storage().instance().set(&DataKey::Treasury, treasury);
}

