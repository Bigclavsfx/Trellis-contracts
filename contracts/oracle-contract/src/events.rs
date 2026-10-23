use soroban_sdk::{symbol_short, Address, Env, Symbol};

/// Emit when a submitter is registered.
pub fn emit_submitter_registered(env: &Env, submitter: &Address, timestamp: u64) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("sub_reg")),
        (submitter.clone(), timestamp),
    );
}

/// Emit when a submitter is deactivated.
pub fn emit_submitter_deactivated(env: &Env, submitter: &Address, timestamp: u64) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("sub_del")),
        (submitter.clone(), timestamp),
    );
}

/// Emit when a price is submitted.
pub fn emit_price_submitted(
    env: &Env,
    feed_id: &Symbol,
    price: i128,
    submitter: &Address,
    timestamp: u64,
) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("price")),
        (feed_id.clone(), price, submitter.clone(), timestamp),
    );
}

/// Emit when a staleness window is updated.
pub fn emit_staleness_window_set(env: &Env, window_seconds: u64, timestamp: u64) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("stale")),
        (window_seconds, timestamp),
    );
}

/// Emit when a submitter stakes collateral.
pub fn emit_submitter_staked(
    env: &Env,
    submitter: &Address,
    amount: i128,
    total_stake: i128,
    timestamp: u64,
) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("staked")),
        (submitter.clone(), amount, total_stake, timestamp),
    );
}

/// Emit when a submitter is slashed.
pub fn emit_submitter_slashed(
    env: &Env,
    submitter: &Address,
    penalty_amount: i128,
    remaining_stake: i128,
    reason: Symbol,
    timestamp: u64,
) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("slashed")),
        (submitter.clone(), penalty_amount, remaining_stake, reason, timestamp),
    );
}

/// Emit when an unbonding request is initiated.
pub fn emit_unbonding_requested(
    env: &Env,
    submitter: &Address,
    amount: i128,
    unlock_time: u64,
    timestamp: u64,
) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("unbond")),
        (submitter.clone(), amount, unlock_time, timestamp),
    );
}

/// Emit when unbonded stake is withdrawn.
pub fn emit_stake_withdrawn(
    env: &Env,
    submitter: &Address,
    amount: i128,
    timestamp: u64,
) {
    env.events().publish(
        (symbol_short!("oracle"), symbol_short!("withdrawn")),
        (submitter.clone(), amount, timestamp),
    );
}
