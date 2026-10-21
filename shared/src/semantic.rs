//! Semantic business-rule validation helpers.

use soroban_sdk::{contracttype, Address, Env};

use crate::errors::Error;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmountRule {
    pub min: i128,
    pub max: i128,
    pub allow_zero: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiryRule {
    pub min_delay_ledgers: u32,
    pub max_delay_ledgers: u32,
}

pub fn validate_amount(amount: i128, rule: &AmountRule) -> Result<(), Error> {
    if amount < 0 || (!rule.allow_zero && amount == 0) {
        return Err(Error::InvalidAmount);
    }
    if amount < rule.min || amount > rule.max {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

pub fn validate_distinct_parties(a: &Address, b: &Address) -> Result<(), Error> {
    if a == b {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

pub fn validate_future_expiry(
    env: &Env,
    expiry_ledger: u32,
    rule: &ExpiryRule,
) -> Result<(), Error> {
    let now = env.ledger().sequence();
    let min = now.saturating_add(rule.min_delay_ledgers);
    let max = now.saturating_add(rule.max_delay_ledgers);
    if expiry_ledger < min || expiry_ledger > max {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
