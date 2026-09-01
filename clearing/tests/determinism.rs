//! Property test: the state machine is deterministic.
//!
//! Applying the same `Tx` sequence to two independently-constructed states must
//! yield identical states — no hidden nondeterminism (e.g. `HashMap` iteration
//! order, RNG, wall-clock). This is the invariant a later validity proof relies
//! on to re-derive the same state root. Transactions that reject are fine: they
//! reject identically and leave state unchanged on both sides.

use clearing::id::{AccountId, Amount, AssetId, InstrumentId, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{State, Tx};
use proptest::prelude::*;
use uuid::Uuid;

const USDC: AssetId = AssetId(0);
const BTC: AssetId = AssetId(1);

fn acct(i: u8) -> AccountId {
    AccountId(Uuid::from_u128(i as u128))
}
fn asset(is_btc: bool) -> AssetId {
    if is_btc { BTC } else { USDC }
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

fn tx_strategy() -> impl Strategy<Value = Tx> {
    prop_oneof![
        (0u8..4, any::<bool>(), 1i128..1000, 0u64..1000).prop_map(|(a, b, amt, nonce)| {
            Tx::Deposit {
                account: acct(a),
                asset: asset(b),
                amount: Amount(amt),
                nonce,
                trading_key: None,
            }
        }),
        (0u8..4, any::<bool>(), 1i128..1000).prop_map(|(a, b, amt)| Tx::Withdraw {
            account: acct(a),
            asset: asset(b),
            amount: Amount(amt),
        }),
        (0u8..4, 0u8..4, 1i128..1000, 1i128..1000).prop_map(|(b, s, base, quote)| Tx::Trade {
            market: market(),
            fill: Fill {
                buyer: acct(b),
                seller: acct(s),
                base_amount: Amount(base),
                quote_amount: Amount(quote),
            },
            auth: None,
        }),
    ]
}

proptest! {
    #[test]
    fn identical_input_yields_identical_state(ops in prop::collection::vec(tx_strategy(), 0..60)) {
        let mut a = fresh();
        let mut b = fresh();
        for tx in &ops {
            let _ = a.apply(tx);
        }
        for tx in &ops {
            let _ = b.apply(tx);
        }
        prop_assert_eq!(a, b);
    }
}
