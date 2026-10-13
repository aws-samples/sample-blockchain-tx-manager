//! Live EIP-1559 fee estimation and replacement math.

use crate::error::{LambdaError, Result};
use alloy::eips::BlockNumberOrTag;
use alloy::providers::Provider;
use nonce_manager::FeeSpeed;

const REWARD_PERCENTILES: [f64; 3] = [25.0, 50.0, 75.0];
const FEE_HISTORY_BLOCKS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeQuote {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

fn ceil_mul(value: u128, numerator: u128, denominator: u128) -> u128 {
    value
        .saturating_mul(numerator)
        .saturating_add(denominator - 1)
        / denominator
}

fn tier(speed: FeeSpeed) -> (usize, u128, u128) {
    match speed {
        FeeSpeed::Slow => (0, 100, 100),
        FeeSpeed::Standard => (1, 125, 100),
        FeeSpeed::Fast => (2, 150, 100),
    }
}

fn median_nonzero(mut values: Vec<u128>) -> Option<u128> {
    values.retain(|v| *v > 0);
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

pub fn quote_from_history(
    speed: FeeSpeed,
    next_base_fee: u128,
    rewards: &[Vec<u128>],
    tip_floor: u128,
) -> Option<FeeQuote> {
    let (column, headroom_num, headroom_den) = tier(speed);
    let priority = median_nonzero(
        rewards
            .iter()
            .filter_map(|row| row.get(column).copied())
            .collect(),
    )?
    .max(tip_floor);
    let cap = ceil_mul(next_base_fee, headroom_num, headroom_den).saturating_add(priority);
    Some(FeeQuote {
        max_fee_per_gas: cap,
        max_priority_fee_per_gas: priority,
    })
}

pub fn replacement_quote(
    speed: FeeSpeed,
    previous_max_fee: u128,
    previous_priority: u128,
    live: FeeQuote,
) -> FeeQuote {
    let priority = ceil_mul(previous_priority, 1125, 1000).max(live.max_priority_fee_per_gas);
    // MetaMask's production-facing guidance uses ~30% max-fee headroom for a
    // replacement; this also clears Geth's 10% admission minimum comfortably.
    let cap = ceil_mul(previous_max_fee, 130, 100).max(
        live.max_fee_per_gas
            .saturating_sub(live.max_priority_fee_per_gas)
            .saturating_add(priority),
    );
    let _ = speed; // speed is represented in `live`; retain it in the API for clarity.
    FeeQuote {
        max_fee_per_gas: cap,
        max_priority_fee_per_gas: priority,
    }
}

pub async fn estimate_live_fees<P: Provider + ?Sized>(
    provider: &P,
    speed: FeeSpeed,
    tip_floor: u128,
) -> Result<FeeQuote> {
    let history_result = provider
        .get_fee_history(
            FEE_HISTORY_BLOCKS,
            BlockNumberOrTag::Latest,
            &REWARD_PERCENTILES,
        )
        .await;
    if let Ok(history) = &history_result
        && let (Some(next_base), Some(rewards)) =
            (history.next_block_base_fee(), history.reward.as_deref())
        && let Some(quote) = quote_from_history(speed, next_base, rewards, tip_floor)
    {
        return Ok(quote);
    }

    // Empty testnet blocks legitimately yield all-zero rewards. Alloy's estimator is a
    // second live provider-backed path; only fail before reservation when both paths fail.
    let fallback = provider
        .estimate_eip1559_fees()
        .await
        .map_err(|fallback_error| {
            let history_reason = history_result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "no usable non-zero reward samples".into());
            LambdaError::GasEstimationFailed(format!(
                "eth_feeHistory unavailable ({history_reason}); EIP-1559 fallback failed ({fallback_error})"
            ))
        })?;
    let priority = fallback.max_priority_fee_per_gas.max(tip_floor);
    Ok(FeeQuote {
        max_fee_per_gas: fallback.max_fee_per_gas.max(priority),
        max_priority_fee_per_gas: priority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewards() -> Vec<Vec<u128>> {
        vec![vec![1, 2, 4], vec![2, 3, 6], vec![3, 5, 9], vec![0, 0, 0]]
    }

    #[test]
    fn tiers_use_live_percentiles_and_expected_headroom() {
        let slow = quote_from_history(FeeSpeed::Slow, 100, &rewards(), 1).unwrap();
        let standard = quote_from_history(FeeSpeed::Standard, 100, &rewards(), 1).unwrap();
        let fast = quote_from_history(FeeSpeed::Fast, 100, &rewards(), 1).unwrap();
        assert_eq!(
            slow,
            FeeQuote {
                max_fee_per_gas: 102,
                max_priority_fee_per_gas: 2
            }
        );
        assert_eq!(
            standard,
            FeeQuote {
                max_fee_per_gas: 128,
                max_priority_fee_per_gas: 3
            }
        );
        assert_eq!(
            fast,
            FeeQuote {
                max_fee_per_gas: 156,
                max_priority_fee_per_gas: 6
            }
        );
    }

    #[test]
    fn tip_floor_applies_without_making_quote_inadmissible() {
        let quote = quote_from_history(FeeSpeed::Slow, 100, &rewards(), 10).unwrap();
        assert_eq!(quote.max_priority_fee_per_gas, 10);
        assert_eq!(quote.max_fee_per_gas, 110);
    }

    #[test]
    fn empty_rewards_fail_closed() {
        assert!(quote_from_history(FeeSpeed::Standard, 100, &[vec![0, 0, 0]], 1).is_none());
    }

    #[test]
    fn replacement_bumps_tip_12_5_and_cap_30_percent_with_ceiling_rounding() {
        let quote = replacement_quote(
            FeeSpeed::Standard,
            101,
            101,
            FeeQuote {
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 100,
            },
        );
        assert_eq!(quote.max_priority_fee_per_gas, 114);
        assert_eq!(quote.max_fee_per_gas, 132);
    }

    #[test]
    fn live_market_can_dominate_percentage_bump() {
        let quote = replacement_quote(
            FeeSpeed::Fast,
            100,
            10,
            FeeQuote {
                max_fee_per_gas: 300,
                max_priority_fee_per_gas: 50,
            },
        );
        assert_eq!(quote.max_priority_fee_per_gas, 50);
        assert_eq!(quote.max_fee_per_gas, 300);
    }
}
