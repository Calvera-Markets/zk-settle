//! Identifiers and the fixed-point [`Amount`] type.
//!
//! Everything here is deterministic by construction: amounts are integer base
//! units (quantums) with **no floating point anywhere**, and arithmetic is
//! checked (overflow and underflow are errors, never wraps or panics). This is
//! the same posture the sequencer takes on its record path — the settlement
//! state machine must replay to a bit-identical state on every node, which a
//! later validity proof re-derives (see `../docs/zk-validity-feasibility.md`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SettlementError;

/// A quantity in integer **base units** (quantums). The real-world scale is an
/// asset/instrument property (`base_scale` / `quote_scale` on
/// [`crate::instrument::Instrument`]); this type never carries a scale itself,
/// so it can only be combined with amounts of the same asset by construction of
/// the calling code.
///
/// Signed (`i128`) so it can also express position deltas and debits; balances
/// are kept non-negative by the state machine, not by the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(pub i128);

impl Amount {
    pub const ZERO: Amount = Amount(0);

    #[inline]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn is_negative(self) -> bool {
        self.0 < 0
    }

    /// Checked add; `Err(Overflow)` instead of wrapping or panicking.
    #[inline]
    pub fn checked_add(self, rhs: Amount) -> Result<Amount, SettlementError> {
        self.0
            .checked_add(rhs.0)
            .map(Amount)
            .ok_or(SettlementError::Overflow)
    }

    /// Checked sub; `Err(Overflow)` instead of wrapping or panicking. Does not
    /// enforce non-negativity — the caller (e.g. a balance debit) decides
    /// whether a negative result is allowed.
    #[inline]
    pub fn checked_sub(self, rhs: Amount) -> Result<Amount, SettlementError> {
        self.0
            .checked_sub(rhs.0)
            .map(Amount)
            .ok_or(SettlementError::Overflow)
    }

    /// Checked multiply, used for `price * size` style products.
    #[inline]
    pub fn checked_mul(self, rhs: Amount) -> Result<Amount, SettlementError> {
        self.0
            .checked_mul(rhs.0)
            .map(Amount)
            .ok_or(SettlementError::Overflow)
    }

    /// Canonical little-endian byte encoding for commitment hashing. Fixed
    /// width (16 bytes) so the leaf encoding is stable across builds/machines.
    #[inline]
    pub fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

/// A trading account — the unit that holds balances and positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccountId(pub Uuid);

/// A settleable asset (e.g. a specific token). Spot balances are keyed by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssetId(pub u32);

/// A market (orderbook), named by UUID to match the rest of the stack
/// (gateway/sequencer markets are UUIDs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MarketId(pub Uuid);

/// A tradable instrument. One market trades exactly one instrument; the
/// instrument's [`crate::instrument::SettlementKind`] selects the settlement
/// rule. Derivatives key their positions by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InstrumentId(pub u64);

/// An L1-owned identity that funds are escrowed against on the settlement
/// contract: 32-byte Solana pubkey bytes. Bound onto [`crate::account::Account`]
/// at first deposit — not derived from [`AccountId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct L1Address(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_add_sub_roundtrip() {
        let a = Amount(100);
        let b = Amount(40);
        assert_eq!(a.checked_add(b).unwrap(), Amount(140));
        assert_eq!(a.checked_sub(b).unwrap(), Amount(60));
        // sub may go negative; that's the caller's policy, not the type's.
        assert_eq!(b.checked_sub(a).unwrap(), Amount(-60));
    }

    #[test]
    fn add_overflow_is_error_not_panic() {
        let max = Amount(i128::MAX);
        assert_eq!(max.checked_add(Amount(1)), Err(SettlementError::Overflow));
    }

    #[test]
    fn sub_overflow_is_error_not_panic() {
        let min = Amount(i128::MIN);
        assert_eq!(min.checked_sub(Amount(1)), Err(SettlementError::Overflow));
    }

    #[test]
    fn mul_overflow_is_error_not_panic() {
        let big = Amount(i128::MAX);
        assert_eq!(big.checked_mul(Amount(2)), Err(SettlementError::Overflow));
        assert_eq!(Amount(7).checked_mul(Amount(6)).unwrap(), Amount(42));
    }

    #[test]
    fn le_bytes_is_fixed_width_and_stable() {
        assert_eq!(Amount(1).to_le_bytes().len(), 16);
        assert_eq!(Amount(0).to_le_bytes(), [0u8; 16]);
        // round-trips through i128
        let v = Amount(-123_456_789);
        assert_eq!(i128::from_le_bytes(v.to_le_bytes()), -123_456_789);
    }

    #[test]
    fn zero_helpers() {
        assert!(Amount::ZERO.is_zero());
        assert!(Amount(-1).is_negative());
        assert!(!Amount(1).is_negative());
    }
}
