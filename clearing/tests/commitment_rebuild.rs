//! Property test: the incrementally-maintained commitment always matches a
//! from-scratch rebuild.
//!
//! For an arbitrary transaction sequence, we maintain a `StateTree` by applying
//! each `StateDelta` as it happens, then assert its root equals a tree built
//! fresh from the final `State`. This is the load-bearing commitment invariant:
//! the incremental path (what a live node runs) and the canonical rebuild (what
//! a verifier / recovering node computes) must never diverge.

use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, L1Address, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{State, StateTree, Tx};
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
                owner: L1Address([a; 32]),
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
    fn incremental_root_matches_rebuild(ops in prop::collection::vec(tx_strategy(), 0..80)) {
        let mut state = fresh();
        let mut tree = StateTree::new(Sha256Hasher);

        for tx in &ops {
            // Only fold in the commitment delta for transactions that applied;
            // a rejected tx leaves both state and tree untouched.
            if let Ok(delta) = state.apply(tx) {
                tree.apply_delta(&state, &delta);
            }
        }

        let rebuilt = StateTree::from_state(Sha256Hasher, &state);
        prop_assert_eq!(tree.root(), rebuilt.root());
    }
}
