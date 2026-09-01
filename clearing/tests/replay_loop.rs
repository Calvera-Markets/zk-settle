//! End-to-end: drive the engine over a scripted multi-batch scenario and check
//! the whole story holds together — every batch proves, the per-batch roots
//! form an unbroken chain from empty, the final balances are exact, and the
//! final root is the canonical rebuild of the final state.

use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{Engine, ReplayProver, StateTree, SyntheticSource, Tx};
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

#[test]
fn scripted_scenario_clears_proves_and_chains() {
    let mut engine = Engine::new(Sha256Hasher, ReplayProver::new(Sha256Hasher));
    engine.register_market(
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

    let empty_root = StateTree::new(Sha256Hasher).root();

    // Three batches: fund, trade, withdraw.
    let mut source = SyntheticSource::new(vec![
        vec![
            Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                trading_key: None,
            },
            Tx::Deposit {
                account: seller(),
                asset: BTC,
                amount: Amount(5),
                nonce: 1,
                trading_key: None,
            },
        ],
        vec![Tx::Trade {
            market: market(),
            fill: Fill {
                buyer: buyer(),
                seller: seller(),
                base_amount: Amount(2),
                quote_amount: Amount(400),
            },
            auth: None,
        }],
        vec![Tx::Withdraw {
            account: buyer(),
            asset: USDC,
            amount: Amount(100),
        }],
    ]);

    // `run` returning Ok means every batch's witness verified.
    let outcomes = engine.run(&mut source).expect("all batches must prove");
    assert_eq!(outcomes.len(), 3);

    // Root chain: first batch starts from empty; each batch starts where the
    // previous ended; the last ends at the engine's current root.
    assert_eq!(outcomes[0].prev_root(), empty_root);
    for pair in outcomes.windows(2) {
        assert_eq!(pair[1].prev_root(), pair[0].new_root());
    }
    assert_eq!(outcomes.last().unwrap().new_root(), engine.root());

    // Each step actually moved the root (no batch here is a no-op).
    for o in &outcomes {
        assert_ne!(o.prev_root(), o.new_root());
    }

    // Exact final balances:
    //   fund:  buyer 1000 USDC ; seller 5 BTC
    //   trade: buyer -400 USDC +2 BTC ; seller +400 USDC -2 BTC
    //   wd:    buyer -100 USDC
    let s = engine.state();
    assert_eq!(s.balance(buyer(), USDC), Amount(500));
    assert_eq!(s.balance(buyer(), BTC), Amount(2));
    assert_eq!(s.balance(seller(), USDC), Amount(400));
    assert_eq!(s.balance(seller(), BTC), Amount(3));

    // Final committed root == canonical rebuild of the final state.
    let rebuilt = StateTree::from_state(Sha256Hasher, engine.state());
    assert_eq!(engine.root(), rebuilt.root());
}
