//! A runnable end-to-end demo of the clearing engine on spot.
//!
//!   cargo run -p clearing --example spot_demo
//!
//! Funds two accounts, settles a BTC/USDC trade, withdraws, and prints the
//! committed state-root chain plus each batch's proof status — the off-path
//! tailer's loop in miniature.

use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{Engine, Hash, ReplayProver, SyntheticSource, Tx};
use uuid::Uuid;

const USDC: AssetId = AssetId(0);
const BTC: AssetId = AssetId(1);

fn short(h: &Hash) -> String {
    h[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let buyer = AccountId(Uuid::from_u128(0xB));
    let seller = AccountId(Uuid::from_u128(0x5));
    let market = MarketId(Uuid::from_u128(0xA1));

    let mut engine = Engine::new(Sha256Hasher, ReplayProver::new(Sha256Hasher));
    engine.register_market(
        market,
        Instrument {
            id: InstrumentId(1),
            kind: SettlementKind::SpotSwap,
            base: BTC,
            quote: USDC,
            base_scale: 8,
            quote_scale: 6,
        },
    );

    let mut source = SyntheticSource::new(vec![
        vec![
            Tx::Deposit { account: buyer, asset: USDC, amount: Amount(1000), nonce: 0, trading_key: None },
            Tx::Deposit { account: seller, asset: BTC, amount: Amount(5), nonce: 1, trading_key: None },
        ],
        vec![Tx::Trade {
            market,
            fill: Fill { buyer, seller, base_amount: Amount(2), quote_amount: Amount(400) },
            auth: None,
        }],
        vec![Tx::Withdraw { account: buyer, asset: USDC, amount: Amount(100) }],
    ]);

    println!("empty root: {}…", short(&engine.root()));
    let outcomes = engine.run(&mut source).expect("all batches prove");

    for (i, o) in outcomes.iter().enumerate() {
        println!(
            "batch {i}: {}… -> {}…  ({} tx, {} leaf updates, proof OK)",
            short(&o.prev_root()),
            short(&o.new_root()),
            o.txs.len(),
            o.witness.updates.len(),
        );
    }

    let s = engine.state();
    println!(
        "final: buyer {} USDC / {} BTC ; seller {} USDC / {} BTC",
        s.balance(buyer, USDC).0,
        s.balance(buyer, BTC).0,
        s.balance(seller, USDC).0,
        s.balance(seller, BTC).0,
    );
    println!("committed root: {}…", short(&engine.root()));
}
