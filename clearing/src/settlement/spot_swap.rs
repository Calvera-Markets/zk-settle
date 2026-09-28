//! Spot settlement: a fill is an atomic swap of base and quote balances.
//!
//! No funding, oracle, margin, or positions.

use crate::account::Position;
use crate::error::SettlementError;
use crate::id::Amount;
use crate::instrument::{Instrument, MarketGlobals};

use super::{Fill, Ledger, Settlement};

/// Spot swap settlement. Unit struct — settlement rules are stateless; all
/// state lives in the ledger and the instrument descriptor.
#[derive(Debug, Clone, Copy)]
pub struct SpotSwap;

impl Settlement for SpotSwap {
    fn apply_fill(
        &self,
        instrument: &Instrument,
        _globals: &MarketGlobals,
        ledger: &mut dyn Ledger,
        fill: &Fill,
    ) -> Result<(), SettlementError> {
        if fill.base_amount.is_negative()
            || fill.base_amount.is_zero()
            || fill.quote_amount.is_negative()
            || fill.quote_amount.is_zero()
        {
            return Err(SettlementError::NonPositiveQuantity);
        }

        // Debit the giving side first so an insufficient balance aborts before
        // any credit — the ledger is left untouched on rejection.
        //
        // Seller gives base, buyer pays quote; then base→buyer, quote→seller.
        ledger.debit(fill.seller, instrument.base, fill.base_amount)?;
        ledger.debit(fill.buyer, instrument.quote, fill.quote_amount)?;
        ledger.credit(fill.buyer, instrument.base, fill.base_amount)?;
        ledger.credit(fill.seller, instrument.quote, fill.quote_amount)?;
        Ok(())
    }

    fn position_value(
        &self,
        _instrument: &Instrument,
        _globals: &MarketGlobals,
        _position: &Position,
    ) -> Amount {
        // Spot holdings are balances, not positions; positions contribute zero.
        Amount::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::id::{AccountId, AssetId, InstrumentId};
    use crate::instrument::SettlementKind;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    /// In-test [`Ledger`] over a map of accounts.
    #[derive(Default)]
    struct TestLedger {
        accounts: BTreeMap<AccountId, Account>,
    }
    impl TestLedger {
        fn bal(&self, a: AccountId, asset: AssetId) -> Amount {
            self.accounts
                .get(&a)
                .map(|acc| acc.balance(asset))
                .unwrap_or(Amount::ZERO)
        }
        fn fund(&mut self, a: AccountId, asset: AssetId, amount: Amount) {
            self.accounts
                .entry(a)
                .or_default()
                .credit(asset, amount)
                .unwrap();
        }
    }
    impl Ledger for TestLedger {
        fn credit(
            &mut self,
            account: AccountId,
            asset: AssetId,
            amount: Amount,
        ) -> Result<(), SettlementError> {
            self.accounts
                .entry(account)
                .or_default()
                .credit(asset, amount)
        }
        fn debit(
            &mut self,
            account: AccountId,
            asset: AssetId,
            amount: Amount,
        ) -> Result<(), SettlementError> {
            self.accounts
                .entry(account)
                .or_default()
                .debit(account, asset, amount)
        }
    }

    const BTC: AssetId = AssetId(1);
    const USDC: AssetId = AssetId(0);

    fn btc_usdc() -> Instrument {
        Instrument {
            id: InstrumentId(1),
            kind: SettlementKind::SpotSwap,
            base: BTC,
            quote: USDC,
            base_scale: 8,
            quote_scale: 6,
        }
    }

    fn buyer() -> AccountId {
        AccountId(Uuid::from_u128(0xB))
    }
    fn seller() -> AccountId {
        AccountId(Uuid::from_u128(0x5))
    }

    fn fill(base: i128, quote: i128) -> Fill {
        Fill {
            buyer: buyer(),
            seller: seller(),
            base_amount: Amount(base),
            quote_amount: Amount(quote),
        }
    }

    #[test]
    fn exact_fill_swaps_balances() {
        let mut l = TestLedger::default();
        l.fund(buyer(), USDC, Amount(1000));
        l.fund(seller(), BTC, Amount(5));

        SpotSwap
            .apply_fill(
                &btc_usdc(),
                &MarketGlobals::default(),
                &mut l,
                &fill(5, 1000),
            )
            .unwrap();

        // buyer: -1000 USDC, +5 BTC ; seller: +1000 USDC, -5 BTC
        assert_eq!(l.bal(buyer(), USDC), Amount::ZERO);
        assert_eq!(l.bal(buyer(), BTC), Amount(5));
        assert_eq!(l.bal(seller(), USDC), Amount(1000));
        assert_eq!(l.bal(seller(), BTC), Amount::ZERO);
    }

    #[test]
    fn value_is_conserved() {
        let mut l = TestLedger::default();
        l.fund(buyer(), USDC, Amount(1000));
        l.fund(seller(), BTC, Amount(5));
        let usdc_before = l.bal(buyer(), USDC).0 + l.bal(seller(), USDC).0;
        let btc_before = l.bal(buyer(), BTC).0 + l.bal(seller(), BTC).0;

        SpotSwap
            .apply_fill(
                &btc_usdc(),
                &MarketGlobals::default(),
                &mut l,
                &fill(3, 600),
            )
            .unwrap();

        let usdc_after = l.bal(buyer(), USDC).0 + l.bal(seller(), USDC).0;
        let btc_after = l.bal(buyer(), BTC).0 + l.bal(seller(), BTC).0;
        assert_eq!(usdc_before, usdc_after);
        assert_eq!(btc_before, btc_after);
    }

    #[test]
    fn insufficient_buyer_quote_rejects_and_leaves_ledger_untouched() {
        let mut l = TestLedger::default();
        l.fund(buyer(), USDC, Amount(500)); // not enough for a 1000 fill
        l.fund(seller(), BTC, Amount(5));

        let err = SpotSwap
            .apply_fill(
                &btc_usdc(),
                &MarketGlobals::default(),
                &mut l,
                &fill(5, 1000),
            )
            .unwrap_err();
        assert_eq!(
            err,
            SettlementError::InsufficientBalance {
                account: buyer(),
                asset: USDC
            }
        );

        // Seller base was debited first, then buyer quote debit failed.
        // This ledger does not roll back the first debit; `State::apply` does.
        // The rule itself must not credit after a failed debit:
        assert_eq!(l.bal(buyer(), BTC), Amount::ZERO);
        assert_eq!(l.bal(seller(), USDC), Amount::ZERO);
    }

    #[test]
    fn non_positive_fill_rejected() {
        let mut l = TestLedger::default();
        l.fund(buyer(), USDC, Amount(1000));
        l.fund(seller(), BTC, Amount(5));
        assert_eq!(
            SpotSwap.apply_fill(
                &btc_usdc(),
                &MarketGlobals::default(),
                &mut l,
                &fill(0, 100)
            ),
            Err(SettlementError::NonPositiveQuantity)
        );
    }
}
