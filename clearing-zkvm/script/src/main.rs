//! Host: build a clearing batch witness, run it through the zkVM guest, and
//! (optionally) generate a proof.
//!
//!   cargo run --release                # execute only (runs the guest, no proof)
//!   cargo run --release -- --prove     # generate + verify a fast CORE proof
//!   cargo run --release -- --groth16   # generate + verify the ON-CHAIN Groth16
//!                                       # proof (the heavy gnark wrap; times it)
//!
//! `--execute` runs the `ExecutingProver` *inside* the zkVM and returns the
//! committed public outputs (prev_root, new_root, messages, operator_key,
//! batch_height); we check they match. The batch includes an **authenticated
//! trade** (maker + taker + matcher signatures), so the guest re-verifies three
//! ed25519 signatures — accelerated by SP1's curve25519 precompile. `--prove`
//! produces a real SP1 proof of that execution.

use clearing::auth::{Ed25519PubKey, Ed25519Signature, Order, Side, SignedOrder, TradeAuth};
use clearing::commitment::{encode_matcher_msg, encode_order, order_id};
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{ExecutingProver, OnChainMessage, Prover, State, StateTree, Tx, Witness};

#[cfg(not(feature = "poseidon2"))]
use clearing::commitment::hash_plain::Sha256Hasher as H;
#[cfg(feature = "poseidon2")]
use clearing::commitment::hash_poseidon2::Poseidon2Hasher as H;
use ed25519_dalek::{Signer, SigningKey};
use sp1_sdk::{
    Elf, ProvingKey as _, SP1Stdin,
    blocking::{ProveRequest as _, Prover as _, ProverClient},
    include_elf,
};
use uuid::Uuid;

const ELF: Elf = include_elf!("clearing-program");

fn keypair(seed: u8) -> (SigningKey, Ed25519PubKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = Ed25519PubKey(sk.verifying_key().to_bytes());
    (sk, pk)
}
fn sign(sk: &SigningKey, msg: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(sk.sign(msg).to_bytes())
}

/// Build an authenticated batch (fund + register keys, `n_trades` signed trades,
/// then a withdrawal) and capture its witness. Returns the witness plus the
/// trusted verifier config (operator key + batch height) the guest re-verifies.
/// Each trade is a distinct order pair (unique salt) filled once, so the batch
/// re-verifies `3 * n_trades` ed25519 signatures.
fn build_witness(n_trades: u64) -> (Witness, Option<Ed25519PubKey>, u64) {
    let market = MarketId(Uuid::from_u128(0xA1));
    let usdc = AssetId(0);
    let btc = AssetId(1);
    let buyer = AccountId(Uuid::from_u128(0xB));
    let seller = AccountId(Uuid::from_u128(0x5));

    let (buyer_sk, buyer_pk) = keypair(1);
    let (seller_sk, seller_pk) = keypair(2);
    let (op_sk, op_pk) = keypair(3);
    let batch_height = 0u64;

    let mut state = State::new();
    state.register_market(
        market,
        Instrument {
            id: InstrumentId(1),
            kind: SettlementKind::SpotSwap,
            base: btc,
            quote: usdc,
            base_scale: 8,
            quote_scale: 6,
        },
    );
    state.set_operator_key(op_pk);
    let mut tree = StateTree::new(H::default());

    // Fund generously enough to cover every trade + the closing withdrawal.
    let mut batch = vec![
        Tx::Deposit {
            account: buyer,
            asset: usdc,
            amount: Amount(400 * n_trades as i128 + 1000),
            nonce: 0,
            trading_key: Some(buyer_pk),
        },
        Tx::Deposit {
            account: seller,
            asset: btc,
            amount: Amount(2 * n_trades as i128 + 10),
            nonce: 1,
            trading_key: Some(seller_pk),
        },
    ];

    // One distinct, single-fill signed trade per iteration (unique salt).
    for i in 0..n_trades {
        let fill = Fill { buyer, seller, base_amount: Amount(2), quote_amount: Amount(400) };
        let buy = Order {
            account: buyer, market, side: Side::Buy,
            base_amount: Amount(2), limit_price: Amount(250), expiry: 1000, salt: i,
        };
        let sell = Order {
            account: seller, market, side: Side::Sell,
            base_amount: Amount(2), limit_price: Amount(180), expiry: 1000, salt: i,
        };
        let matcher_msg = encode_matcher_msg(market, &order_id(&buy), &order_id(&sell), &fill);
        let auth = TradeAuth {
            buy: SignedOrder { order: buy, sig: sign(&buyer_sk, &encode_order(&buy)) },
            sell: SignedOrder { order: sell, sig: sign(&seller_sk, &encode_order(&sell)) },
            matcher_sig: sign(&op_sk, &matcher_msg),
        };
        batch.push(Tx::Trade { market, fill, auth: Some(Box::new(auth)) });
    }

    batch.push(Tx::Withdraw { account: buyer, asset: usdc, amount: Amount(100) });

    let witness = Witness::capture(&mut state, &mut tree, &batch);
    (witness, Some(op_pk), batch_height)
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let do_groth16 = std::env::args().any(|a| a == "--groth16");
    let do_prove = do_groth16 || std::env::args().any(|a| a == "--prove");

    // Number of trades in the batch (default 1). Set TRADES=100 to measure how
    // cycles scale with trade count.
    let n_trades: u64 = std::env::var("TRADES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let (witness, operator_key, batch_height) = build_witness(n_trades);
    // The trades must have applied (authenticated swaps), so the batch is not a
    // no-op — a quick sanity check that auth passed at capture.
    assert!(!witness.updates.is_empty(), "authenticated batch produced no updates");

    // Native sanity check (same logic the guest runs, same trusted config).
    let native = match operator_key {
        Some(k) => ExecutingProver::with_auth(H::default(), k, batch_height),
        None => ExecutingProver::new(H::default()),
    };
    native.prove(&witness).expect("witness should be valid");

    let client = ProverClient::from_env();

    // Execute: run the guest in the zkVM, get the committed public outputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);
    stdin.write(&operator_key);
    stdin.write(&batch_height);
    let t_exec = std::time::Instant::now();
    let (mut public, report) = client.execute(ELF, stdin).run().expect("execute failed");
    let exec_time = t_exec.elapsed();
    let cycles = report.total_instruction_count();
    println!(
        "executed in zkVM: {cycles} cycles in {exec_time:.2?}  ({n_trades} trade(s), {} ed25519 sigs, {:.0} cycles/trade)",
        3 * n_trades,
        cycles as f64 / n_trades as f64,
    );

    let prev_root: [u8; 32] = public.read();
    let new_root: [u8; 32] = public.read();
    let messages: Vec<OnChainMessage> = public.read();
    let out_op_key: Option<Ed25519PubKey> = public.read();
    let out_height: u64 = public.read();
    assert_eq!(prev_root, witness.prev_root);
    assert_eq!(new_root, witness.new_root);
    assert_eq!(messages, witness.messages);
    assert_eq!(out_op_key, operator_key);
    assert_eq!(out_height, batch_height);
    println!(
        "public outputs match ✓  (prev_root, new_root, {} withdrawal message(s), operator_key, batch_height)",
        messages.len()
    );

    if do_prove {
        // Time each phase separately — setup (builds the proving key; the first
        // Groth16 run also fetches the gnark artifacts), proving, and verify.
        let t_setup = std::time::Instant::now();
        let pk = client.setup(ELF).expect("setup failed");
        let setup_time = t_setup.elapsed();

        let req = client.prove(&pk, {
            let mut s = SP1Stdin::new();
            s.write(&witness);
            s.write(&operator_key);
            s.write(&batch_height);
            s
        });
        // Core is fast; Groth16 is the on-chain artifact and the expensive one
        // (the gnark wrap). `.groth16()` is a consuming builder that returns the
        // request, so we chain it.
        let t_prove = std::time::Instant::now();
        let (proof, mode) = if do_groth16 {
            (req.groth16().run(), "Groth16 (on-chain)")
        } else {
            (req.run(), "core")
        };
        let proof = proof.expect("prove failed");
        let prove_time = t_prove.elapsed();

        let t_verify = std::time::Instant::now();
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("verify failed");
        let verify_time = t_verify.elapsed();

        println!("SP1 {mode} proof generated + verified ✓  ({} proof bytes)", proof.bytes().len());
        println!("  timing:");
        println!("    execute : {exec_time:.2?}");
        println!("    setup   : {setup_time:.2?}");
        println!("    prove   : {prove_time:.2?}");
        println!("    verify  : {verify_time:.2?}");
        println!("    total   : {:.2?}", exec_time + setup_time + prove_time + verify_time);
    }
}
