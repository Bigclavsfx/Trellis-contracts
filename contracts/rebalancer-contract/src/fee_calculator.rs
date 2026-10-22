use crate::Trade;
use soroban_sdk::Vec;

/// The default rebalancer fee is 0.1%, expressed in basis points.
pub const DEFAULT_FEE_BPS: u32 = 10;
const BPS_DENOMINATOR: u128 = 10_000;

/// Calculate a fee rounded up to the smallest token unit.
///
/// Splitting the multiplication into quotient and remainder avoids overflowing
/// `u128` for large trade amounts. Rates above 100% are rejected.
pub fn fee_for_amount(amount: u128, fee_bps: u32) -> Option<u128> {
    let bps = u128::from(fee_bps);
    if bps > BPS_DENOMINATOR {
        return None;
    }

    let whole = (amount / BPS_DENOMINATOR).checked_mul(bps)?;
    let remainder_product = (amount % BPS_DENOMINATOR).checked_mul(bps)?;
    let remainder_fee = remainder_product.checked_add(BPS_DENOMINATOR - 1)? / BPS_DENOMINATOR;
    whole.checked_add(remainder_fee)
}

pub fn calculate_total_fees(trades: &Vec<Trade>) -> u128 {
    let mut total_fees: u128 = 0;
    for trade in trades.iter() {
        let fee =
            fee_for_amount(trade.amount, DEFAULT_FEE_BPS).expect("the default fee rate is valid");
        total_fees = total_fees.saturating_add(fee);
    }
    total_fees
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_fractional_fees_up_without_losing_dust() {
        assert_eq!(fee_for_amount(1, 10), Some(1));
        assert_eq!(fee_for_amount(999, 10), Some(1));
        assert_eq!(fee_for_amount(1_000, 10), Some(1));
        assert_eq!(fee_for_amount(10_001, 10), Some(11));
    }

    #[test]
    fn supports_multiple_basis_point_rates_and_boundaries() {
        assert_eq!(fee_for_amount(10_001, 1), Some(2));
        assert_eq!(fee_for_amount(10_001, 100), Some(101));
        assert_eq!(fee_for_amount(u128::MAX, 0), Some(0));
        assert_eq!(fee_for_amount(u128::MAX, 10_000), Some(u128::MAX));
        assert_eq!(fee_for_amount(u128::MAX, 10), Some(u128::MAX / 1_000 + 1));
        assert_eq!(fee_for_amount(1, 10_001), None);
    }
}
