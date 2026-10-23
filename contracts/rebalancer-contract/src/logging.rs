use soroban_sdk::{symbol_short, BytesN, Env};

use crate::Trade;
use shared::events::emit_action_executed;

/// The rebalancer does not accept a caller-supplied correlation ID (a rebalance
/// is not tied to a request-scoped workflow), so every correlated event uses
/// the canonical zero correlation ID.
fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

pub fn log_trade(env: &Env, _trade: &Trade, _actual_price: u128, _fee: u128) {
    emit_action_executed(
        env,
        &zero_correlation_id(env),
        symbol_short!("reb"),
        symbol_short!("trade"),
        &env.current_contract_address(),
        true,
        env.ledger().timestamp(),
    );
}
