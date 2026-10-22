#![no_std]

mod fee_calculator;
mod logging;
mod slippage_predictor;
pub mod strategy_executor;

pub use fee_calculator::calculate_total_fees;
pub use logging::log_trade;
use shared::events::emit_action_executed;
pub use slippage_predictor::predict_slippage;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Symbol,
    Vec, U256,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TradeCapacity {
    pub max_trade_amount: u128,
    pub max_slippage_bps: u32,
}

#[contracttype]
#[derive(Clone)]
enum StorageKey {
    Admin,
    Capacity(Symbol, Symbol),
}

#[contracterror]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebalancerError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InvalidCapacity = 4,
}

pub(crate) fn trade_capacity(env: &Env, pair: &(Symbol, Symbol)) -> Option<TradeCapacity> {
    env.storage()
        .instance()
        .get(&StorageKey::Capacity(pair.0.clone(), pair.1.clone()))
}

pub(crate) fn capacity_allows(
    env: &Env,
    pair: &(Symbol, Symbol),
    amount: u128,
    slippage_bps: u128,
) -> bool {
    trade_capacity(env, pair)
        .map(|capacity| {
            amount <= capacity.max_trade_amount
                && slippage_bps <= u128::from(capacity.max_slippage_bps)
        })
        .unwrap_or(false)
}
pub use strategy_executor::execute_strategy;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trade {
    pub asset_pair: (Symbol, Symbol),
    pub amount: u128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStrategy {
    MinimalCost,
    MinimalTime,
    Balanced,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TradeStatus {
    Success = 1,
    PartialFill = 2,
    Failed = 3,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TradeReceipt {
    pub asset_pair: (Symbol, Symbol),
    pub amount: u128,
    pub status: TradeStatus,
    pub fee: u128,
    pub error_code: Option<u32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReport {
    pub total_fees: u128,
    pub actual_slippage: U256,
    pub trades_executed: u32,
    pub trades_failed: u32,
    pub trade_statuses: Vec<TradeReceipt>,
}

impl ExecutionReport {
    pub fn trade_receipts(&self) -> &Vec<TradeReceipt> {
        &self.trade_statuses
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationResult {
    pub expected_fees: u128,
    pub expected_slippage: U256,
}

#[contract]
pub struct MultiAssetRebalancer;

/// The rebalancer contract does not accept a caller-supplied correlation ID
/// (a rebalance is not tied to a request-scoped workflow), so every correlated
/// event uses the canonical zero correlation ID.
fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

#[contractimpl]
impl MultiAssetRebalancer {
    /// Set the account that is allowed to configure pair-specific limits.
    pub fn initialize(env: Env, admin: Address) -> Result<(), RebalancerError> {
        if env.storage().instance().has(&StorageKey::Admin) {
            return Err(RebalancerError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&StorageKey::Admin, &admin);
        Ok(())
    }

    /// Configure the maximum amount and tolerated predicted slippage for a
    /// directed asset pair. Set limits from current pool depth and governance
    /// policy; unconfigured pairs are rejected by the executor.
    pub fn set_pair_capacity(
        env: Env,
        admin: Address,
        asset_in: Symbol,
        asset_out: Symbol,
        max_trade_amount: u128,
        max_slippage_bps: u32,
    ) -> Result<(), RebalancerError> {
        let configured_admin: Option<Address> = env.storage().instance().get(&StorageKey::Admin);
        let Some(configured_admin) = configured_admin else {
            return Err(RebalancerError::NotInitialized);
        };
        if admin != configured_admin {
            return Err(RebalancerError::Unauthorized);
        }
        admin.require_auth();
        if asset_in == asset_out || max_trade_amount == 0 || max_slippage_bps > 10_000 {
            return Err(RebalancerError::InvalidCapacity);
        }

        let capacity = TradeCapacity {
            max_trade_amount,
            max_slippage_bps,
        };
        env.storage()
            .instance()
            .set(&StorageKey::Capacity(asset_in, asset_out), &capacity);
        Ok(())
    }

    pub fn rebalance(
        env: Env,
        trades: Vec<Trade>,
        strategy: ExecutionStrategy,
        dry_run: bool,
    ) -> ExecutionReport {
        let report = if dry_run {
            let total_fees = calculate_total_fees(&trades);
            let mut total_slippage: u128 = 0;
            let mut trade_statuses = Vec::new(&env);

            for trade in trades.iter() {
                let slippage = predict_slippage(trade.asset_pair.clone(), trade.amount, &env);
                let slippage_val = slippage.to_u128().unwrap_or(0);
                total_slippage = total_slippage.saturating_add(slippage_val);

                let (status, fee, error_code) = if trade.amount == 0 {
                    (
                        TradeStatus::Failed,
                        0,
                        Some(strategy_executor::ERROR_ZERO_AMOUNT),
                    )
                } else if trade.asset_pair.0 == trade.asset_pair.1 {
                    (
                        TradeStatus::Failed,
                        0,
                        Some(strategy_executor::ERROR_IDENTICAL_ASSETS),
                    )
                } else if trade.amount > 10_000_000_000 {
                    (
                        TradeStatus::Failed,
                        0,
                        Some(strategy_executor::ERROR_EXCEEDS_CAPACITY),
                    )
                } else {
                    (
                        TradeStatus::Success,
                        fee_calculator::fee_for_amount(
                            trade.amount,
                            fee_calculator::DEFAULT_FEE_BPS,
                        )
                        .expect("the default fee rate is valid"),
                        None,
                    )
                };

                trade_statuses.push_back(TradeReceipt {
                    asset_pair: trade.asset_pair.clone(),
                    amount: trade.amount,
                    status,
                    fee,
                    error_code,
                });
            }

            let actual_slippage = U256::from_u128(&env, total_slippage);

            ExecutionReport {
                total_fees,
                actual_slippage,
                trades_executed: 0,
                trades_failed: 0,
                trade_statuses,
            }
        } else {
            execute_strategy(&env, &strategy, &trades)
        };

        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("reb"),
            symbol_short!("rebal"),
            &env.current_contract_address(),
            !dry_run,
            env.ledger().timestamp(),
        );

        report
    }
}

#[cfg(test)]
mod tests;

/// CPU/memory footprint profiling for CI (issue #192). Kept separate from
/// `tests` so it can be run in isolation via `scripts/profile-budget.sh`.
#[cfg(test)]
mod profile_budget;
