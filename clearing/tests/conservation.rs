//! Property test: spot settlement conserves value.
//!
//! A `Trade` must never create or destroy units of any asset — it only moves
//! them between accounts. We fund a buyer and seller with random amounts,
//! settle a random affordable fill, and assert the per-asset totals are
//! unchanged.

use clearing::id::{AccountId, Amount, AssetId, InstrumentId, L1Address, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{State, Tx};
use proptest::prelude::*;
use uuid::Uuid;

const USDC: AssetId = AssetId(0);
const BTC: AssetId = AssetId(1);

fn buyer() -> AccountId {
    AccountId(Uuid::from_u128(0xB))
}
fn seller() -> AccountId {
    AccountId(Uuid::from_u128(0x5))
}
fn market() -> MarketId {
    MarketId(Uuid::from_u128(0xA1))
}

fn fresh() -> State {
    let mut s = State::new();
    s.register_market(
        market(),
        Instrument {
            id: InstrumentId(1),
            kind: SettlementKind::SpotSwap,
            base: BTC,
            quote: USDC,
            base_scale: 8,
            quote_scale: 6,
        },
    );
    s
}

fn total(s: &State, asset: AssetId) -> i128 {
    s.accounts().map(|(_, a)| a.balance(asset).0).sum()
}

proptest! {
    #[test]
    fn trade_conserves_each_asset(
        buyer_usdc in 1i128..1_000_000,
        seller_btc in 1i128..1_000_000,
        // the fill must be affordable: base <= seller_btc, quote <= buyer_usdc
        base_num in 1i128..1_000_000,
        quote_num in 1i128..1_000_000,
    ) {
        let base = base_num.min(seller_btc);
        let quote = quote_num.min(buyer_usdc);

        let mut s = fresh();
        s.apply(&Tx::Deposit { account: buyer(), asset: USDC, amount: Amount(buyer_usdc), nonce: 0, owner: L1Address([1u8; 32]), trading_key: None }).unwrap();
        s.apply(&Tx::Deposit { account: seller(), asset: BTC, amount: Amount(seller_btc), nonce: 1, owner: L1Address([2u8; 32]), trading_key: None }).unwrap();

        let usdc_before = total(&s, USDC);
        let btc_before = total(&s, BTC);

        s.apply(&Tx::Trade {
            market: market(),
            fill: Fill { buyer: buyer(), seller: seller(), base_amount: Amount(base), quote_amount: Amount(quote) },
            auth: None,
        }).unwrap();

        prop_assert_eq!(total(&s, USDC), usdc_before);
        prop_assert_eq!(total(&s, BTC), btc_before);
    }
}
