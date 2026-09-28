//! Trading account: `balances` plus `positions`.
//!
//! Spot uses balances only. Derivatives add position entries. A new instrument
//! type should not add a third map on [`Account`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::SettlementError;
use crate::id::{Amount, AssetId, InstrumentId, L1Address};

/// A derivative position. Unused by spot (spot holdings are `balances`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub instrument: InstrumentId,
    /// Signed contracts; negative = short.
    pub signed_size: i128,
    pub entry_price: Amount,
    /// Snapshot of the cumulative funding index at last settlement, for lazy
    /// funding reconciliation. `None` until a funding-bearing instrument uses
    /// it.
    pub cached_funding_idx: Option<i128>,
}

/// A trading account: asset balances and (later) derivative positions.
///
/// Balances are kept **non-negative** by the mutators here — that invariant is
/// the account model's, not the [`Amount`] type's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    balances: BTreeMap<AssetId, Amount>,
    positions: BTreeMap<InstrumentId, Position>,
    /// Registered ed25519 trading key. `None` until the first deposit.
    /// Committed in the leaf so order signatures bind to the key on the account.
    trading_key: Option<crate::auth::Ed25519PubKey>,
    /// Cumulative base filled per order id. Lives in the account leaf so
    /// re-execution checks partial fills. Entries only increase; they stay after
    /// the balance drains so a filled order cannot be filled again. Fully-filled
    /// orders are not pruned.
    order_fills: BTreeMap<crate::commitment::Hash, Amount>,
    /// L1 owner (Solana pubkey) bound at first deposit. Ignored by [`Self::is_empty`]:
    /// an owner-only account is pruned and rebound on the next first deposit.
    l1_owner: Option<L1Address>,
}

impl Account {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current balance of `asset` (zero if untracked).
    pub fn balance(&self, asset: AssetId) -> Amount {
        self.balances.get(&asset).copied().unwrap_or(Amount::ZERO)
    }

    /// Credit `asset` by `amount` (`amount` must be positive). Checked.
    pub fn credit(&mut self, asset: AssetId, amount: Amount) -> Result<(), SettlementError> {
        if amount.is_negative() || amount.is_zero() {
            return Err(SettlementError::NonPositiveQuantity);
        }
        let next = self.balance(asset).checked_add(amount)?;
        self.set_balance(asset, next);
        Ok(())
    }

    /// Debit `asset` by `amount` (`amount` must be positive). Fails with
    /// `InsufficientBalance` rather than going negative. Checked.
    pub fn debit(
        &mut self,
        owner: crate::id::AccountId,
        asset: AssetId,
        amount: Amount,
    ) -> Result<(), SettlementError> {
        if amount.is_negative() || amount.is_zero() {
            return Err(SettlementError::NonPositiveQuantity);
        }
        let next = self.balance(asset).checked_sub(amount)?;
        if next.is_negative() {
            return Err(SettlementError::InsufficientBalance {
                account: owner,
                asset,
            });
        }
        self.set_balance(asset, next);
        Ok(())
    }

    /// Set a balance, pruning zero entries so the commitment encoding is
    /// canonical (no distinction between "absent" and "zero").
    fn set_balance(&mut self, asset: AssetId, value: Amount) {
        if value.is_zero() {
            self.balances.remove(&asset);
        } else {
            self.balances.insert(asset, value);
        }
    }

    /// Iterate balances in canonical (key-sorted) order — used for hashing.
    pub fn balances(&self) -> impl Iterator<Item = (&AssetId, &Amount)> {
        self.balances.iter()
    }

    /// Iterate positions in canonical (key-sorted) order.
    pub fn positions(&self) -> impl Iterator<Item = (&InstrumentId, &Position)> {
        self.positions.iter()
    }

    /// The account's registered trading key, if any.
    pub fn trading_key(&self) -> Option<crate::auth::Ed25519PubKey> {
        self.trading_key
    }

    /// Register the trading key. Idempotent to the same key; rejects an attempt
    /// to *change* an already-registered key (no rotation in v1).
    pub fn set_trading_key(
        &mut self,
        key: crate::auth::Ed25519PubKey,
    ) -> Result<(), SettlementError> {
        match self.trading_key {
            Some(existing) if existing != key => Err(SettlementError::KeyAlreadyRegistered),
            _ => {
                self.trading_key = Some(key);
                Ok(())
            }
        }
    }

    /// The L1 owner bound to this account, if any.
    pub fn l1_owner(&self) -> Option<L1Address> {
        self.l1_owner
    }

    /// Bind the L1 owner. First call wins; a later call must match or
    /// [`SettlementError::OwnerMismatch`].
    pub fn set_l1_owner(&mut self, owner: L1Address) -> Result<(), SettlementError> {
        match self.l1_owner {
            Some(existing) if existing != owner => Err(SettlementError::OwnerMismatch),
            Some(_) => Ok(()),
            None => {
                self.l1_owner = Some(owner);
                Ok(())
            }
        }
    }

    /// Cumulative base filled against `order_id` (zero if this account has never
    /// been filled on it).
    pub fn order_filled(&self, order_id: &crate::commitment::Hash) -> Amount {
        self.order_fills
            .get(order_id)
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// Add `base` to the cumulative fill of `order_id`. Checked (overflow errors).
    pub fn record_order_fill(
        &mut self,
        order_id: crate::commitment::Hash,
        base: Amount,
    ) -> Result<(), SettlementError> {
        let next = self.order_filled(&order_id).checked_add(base)?;
        self.order_fills.insert(order_id, next);
        Ok(())
    }

    /// Iterate order fills in canonical (id-sorted) order — for hashing.
    pub fn order_fills(&self) -> impl Iterator<Item = (&crate::commitment::Hash, &Amount)> {
        self.order_fills.iter()
    }

    /// An account is empty (⇒ hashes to the empty leaf, ⇒ absent from the tree)
    /// only when it holds nothing, has no registered key, **and** has no recorded
    /// order fills — so a registered or previously-trading account stays committed
    /// (keeping its key and its anti-replay fill records). The L1 owner is
    /// ignored: an owner-only account is empty and pruned.
    pub fn is_empty(&self) -> bool {
        self.balances.is_empty()
            && self.positions.is_empty()
            && self.trading_key.is_none()
            && self.order_fills.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{AccountId, InstrumentId};
    use uuid::Uuid;

    fn acct() -> AccountId {
        AccountId(Uuid::from_u128(1))
    }

    const USDC: AssetId = AssetId(0);

    #[test]
    fn owner_and_trading_key_setters() {
        let mut a = Account::new();
        let o = L1Address([7u8; 32]);
        a.set_l1_owner(o).unwrap();
        a.set_l1_owner(o).unwrap();
        assert_eq!(a.l1_owner(), Some(o));
        assert_eq!(
            a.set_l1_owner(L1Address([8u8; 32])).unwrap_err(),
            SettlementError::OwnerMismatch
        );
        let k = crate::auth::Ed25519PubKey([1u8; 32]);
        a.set_trading_key(k).unwrap();
        assert_eq!(a.trading_key(), Some(k));
        assert_eq!(
            a.set_trading_key(crate::auth::Ed25519PubKey([2u8; 32]))
                .unwrap_err(),
            SettlementError::KeyAlreadyRegistered
        );
    }

    #[test]
    fn canonical_encode_includes_position_funding_idx() {
        let mut a = Account::new();
        a.positions.insert(
            InstrumentId(7),
            Position {
                instrument: InstrumentId(7),
                signed_size: 3,
                entry_price: Amount(9),
                cached_funding_idx: Some(11),
            },
        );
        let with_idx = crate::commitment::canonical_encode(&a);
        a.positions
            .get_mut(&InstrumentId(7))
            .unwrap()
            .cached_funding_idx = None;
        let without_idx = crate::commitment::canonical_encode(&a);
        assert_ne!(with_idx, without_idx);
        assert!(with_idx.len() > without_idx.len());
    }

    #[test]
    fn credit_then_debit() {
        let mut a = Account::new();
        a.credit(USDC, Amount(100)).unwrap();
        assert_eq!(a.balance(USDC), Amount(100));
        a.debit(acct(), USDC, Amount(30)).unwrap();
        assert_eq!(a.balance(USDC), Amount(70));
    }

    #[test]
    fn debit_beyond_balance_rejects() {
        let mut a = Account::new();
        a.credit(USDC, Amount(10)).unwrap();
        let err = a.debit(acct(), USDC, Amount(11)).unwrap_err();
        assert_eq!(
            err,
            SettlementError::InsufficientBalance {
                account: acct(),
                asset: USDC
            }
        );
        // balance unchanged after a rejected debit
        assert_eq!(a.balance(USDC), Amount(10));
    }

    #[test]
    fn zero_balance_is_pruned() {
        let mut a = Account::new();
        a.credit(USDC, Amount(5)).unwrap();
        a.debit(acct(), USDC, Amount(5)).unwrap();
        assert_eq!(a.balance(USDC), Amount::ZERO);
        // pruned => canonical: account is empty again
        assert!(a.is_empty());
        assert_eq!(a.balances().count(), 0);
    }

    #[test]
    fn non_positive_credit_debit_rejected() {
        let mut a = Account::new();
        assert_eq!(
            a.credit(USDC, Amount::ZERO),
            Err(SettlementError::NonPositiveQuantity)
        );
        assert_eq!(
            a.debit(acct(), USDC, Amount(-1)),
            Err(SettlementError::NonPositiveQuantity)
        );
    }

    #[test]
    fn owner_alone_is_empty() {
        let mut a = Account::new();
        a.set_l1_owner(L1Address([1u8; 32])).unwrap();
        assert!(a.is_empty());
        a.set_l1_owner(L1Address([1u8; 32])).unwrap();
        assert_eq!(
            a.set_l1_owner(L1Address([2u8; 32])),
            Err(SettlementError::OwnerMismatch)
        );
    }
}
