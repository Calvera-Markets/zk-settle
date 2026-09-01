//! End-to-end driver for the **custom-circuit** settlement path — the
//! counterpart to the zkVM host (`../clearing-zkvm/script/src/main.rs`). Both
//! build a realistic batch, prove the transition, and verify it; this one ends by
//! encoding the proof for an on-chain `alt_bn128` verifier.
//!
//!   cargo run --release --example e2e
//!
//! Native arkworks Groth16 (NOT SP1) — small and laptop-safe; there is no
//! dangerous proving flag here, unlike the zkVM's `--prove`.
//!
//! Flow (mirrors the zkVM host step for step):
//!   1. build a batch of spot swaps and the prev/new state roots  (witness)
//!   2. trusted setup, then PROVE the batch transition            (Groth16)
//!   3. VERIFY against only the public endpoint roots             (rollup property)
//!   4. cross-check each trade against the independent Rust spec  (differential)
//!   5. encode proof + VK + public inputs to the Solana wire form (alt_bn128)

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use clearing_circuits::reference::TradeScenario;
use clearing_circuits::tree::MerkleTree;
use clearing_circuits::{account_leaf3, solana, BatchTradeCircuit, TradeData, BATCH_SIZE, DEPTH};

/// One trade's scenario plus where the two accounts sit in the tree.
struct Trade {
    buyer_id: Fr,
    seller_id: Fr,
    bi: usize,
    si: usize,
    sc: TradeScenario,
}

fn main() {
    // A deterministic RNG: trusted setup + proving need randomness, but we want a
    // reproducible run. (`StdRng::seed_from_u64`, never the OS RNG, so the example
    // is identical every time.)
    let mut rng = StdRng::seed_from_u64(2024);

    // ---- 1. Build the batch + the prev/new roots (the "witness") -------------
    //
    // A buyer pays quote for base; the seller does the reverse. Distinct account
    // pairs at distinct indices so the trades are independent. This is exactly
    // what the zkVM host's `build_witness()` does, but producing circuit inputs
    // (roots + Merkle paths) instead of a `clearing::Witness`.
    let trades = vec![
        Trade {
            buyer_id: Fr::from(0x10u64),
            seller_id: Fr::from(0x11u64),
            bi: 1,
            si: 2,
            sc: TradeScenario {
                buyer_base: 10,
                buyer_quote: 1000,
                seller_base: 50,
                seller_quote: 0,
                base_amount: 2,
                quote_amount: 400,
            },
        },
        Trade {
            buyer_id: Fr::from(0x20u64),
            seller_id: Fr::from(0x21u64),
            bi: 10,
            si: 11,
            sc: TradeScenario {
                buyer_base: 5,
                buyer_quote: 500,
                seller_base: 30,
                seller_quote: 7,
                base_amount: 1,
                quote_amount: 100,
            },
        },
        Trade {
            buyer_id: Fr::from(0x30u64),
            seller_id: Fr::from(0x31u64),
            bi: 100,
            si: 101,
            sc: TradeScenario {
                buyer_base: 80,
                buyer_quote: 9000,
                seller_base: 200,
                seller_quote: 1,
                base_amount: 20,
                quote_amount: 3000,
            },
        },
        Trade {
            buyer_id: Fr::from(0x40u64),
            seller_id: Fr::from(0x41u64),
            bi: 250,
            si: 251,
            sc: TradeScenario {
                buyer_base: 1,
                buyer_quote: 1,
                seller_base: 1,
                seller_quote: 1,
                base_amount: 1,
                quote_amount: 1,
            },
        },
    ];
    assert_eq!(trades.len(), BATCH_SIZE);

    // Cross-check up front: every trade must be settleable, or the witness can't
    // produce consistent roots (step 4 re-checks this against the circuit).
    for t in &trades {
        assert!(t.sc.accepts(), "scenario must be valid to build a witness");
    }

    let (prev_root, new_root, trade_data) = build_witness(&trades);
    println!("1. built a batch of {BATCH_SIZE} spot swaps (tree depth {DEPTH})");
    println!("   prev_root = {prev_root}");
    println!("   new_root  = {new_root}");

    // ---- 2. Trusted setup, then prove ----------------------------------------
    // pk is the prover key, stays with us
    // vk is the verifier key, for the smart contract
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(BatchTradeCircuit::blank(), &mut rng).unwrap();
    println!("2. trusted setup done; proving the batch transition…");
    let circuit = BatchTradeCircuit::new(prev_root, new_root, trade_data);
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
    println!("   proof generated ✓");

    // ---- 3. Verify against only the public endpoint roots --------------------
    //
    // The rollup property: the on-chain verifier learns *only* (prev_root,
    // new_root) — never the individual trades — yet is convinced some valid
    // sequence of non-overdrawing swaps connects them.
    let public_inputs = [prev_root, new_root];
    assert!(Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap());
    // A tampered new_root must NOT verify.
    assert!(
        !Groth16::<Bn254>::verify(&vk, &[prev_root, new_root + Fr::from(1u64)], &proof).unwrap()
    );
    println!("3. verified against public (prev_root, new_root) ✓  (tampered root rejected ✓)");

    // ---- 4. Differential cross-check against the Rust spec -------------------
    for (i, t) in trades.iter().enumerate() {
        assert!(
            t.sc.accepts(),
            "trade {i} disagrees with the reference rule"
        );
    }
    println!("4. all {BATCH_SIZE} trades agree with the independent Rust spec ✓");

    // ---- 5. Encode for an on-chain alt_bn128 verifier ------------------------
    let proof_bytes = solana::proof_to_bytes(&proof);
    let vk_bytes = solana::vk_to_bytes(&vk);
    let input_bytes: Vec<[u8; 32]> = public_inputs
        .iter()
        .map(solana::public_input_to_bytes)
        .collect();
    println!("5. encoded for Solana / alt_bn128:");
    println!(
        "   proof          : {} bytes (A‖B‖C, big-endian uncompressed)",
        proof_bytes.len()
    );
    println!(
        "   verifying key  : {} bytes ({} IC points)",
        vk_bytes.len(),
        vk.gamma_abc_g1.len()
    );
    println!("   public inputs  : {} × 32 bytes", input_bytes.len());
    println!("   proof[..8]     = {:02x?}…", &proof_bytes[..8]);

    // Sanity: the encoded proof decodes back and still verifies (the encoding is
    // faithful and invertible — what we can check without a real on-chain run).
    let decoded = solana::proof_from_bytes(&proof_bytes);
    assert!(Groth16::<Bn254>::verify(&vk, &public_inputs, &decoded).unwrap());
    println!("   round-trips through the wire format and re-verifies ✓");

    println!("\ne2e flow complete ✓");
}

/// Build the prev/new roots and per-trade `TradeData` by threading every trade
/// (buyer then seller) through a running [`MerkleTree`], recording each party's
/// path *as of its turn*. This is the circuit equivalent of capturing a witness.
fn build_witness(trades: &[Trade]) -> (Fr, Fr, Vec<TradeData>) {
    // Distinct placeholder leaves everywhere; real leaves for the touched accounts.
    let mut leaves: Vec<Fr> = (0..(1u64 << DEPTH)).map(Fr::from).collect();
    for t in trades {
        leaves[t.bi] = account_leaf3(
            t.buyer_id,
            Fr::from(t.sc.buyer_base),
            Fr::from(t.sc.buyer_quote),
        );
        leaves[t.si] = account_leaf3(
            t.seller_id,
            Fr::from(t.sc.seller_base),
            Fr::from(t.sc.seller_quote),
        );
    }
    let mut tree = MerkleTree::new(leaves);
    let prev_root = tree.root();

    let mut data = Vec::with_capacity(trades.len());
    for t in trades {
        let buyer_path = tree.path(t.bi);
        let buyer_new = account_leaf3(
            t.buyer_id,
            Fr::from(t.sc.buyer_base) + Fr::from(t.sc.base_amount),
            Fr::from(t.sc.buyer_quote) - Fr::from(t.sc.quote_amount),
        );
        tree.update(t.bi, buyer_new);

        let seller_path = tree.path(t.si);
        let seller_new = account_leaf3(
            t.seller_id,
            Fr::from(t.sc.seller_base) - Fr::from(t.sc.base_amount),
            Fr::from(t.sc.seller_quote) + Fr::from(t.sc.quote_amount),
        );
        tree.update(t.si, seller_new);

        data.push(TradeData {
            buyer_id: t.buyer_id,
            seller_id: t.seller_id,
            base_amount: Fr::from(t.sc.base_amount),
            quote_amount: Fr::from(t.sc.quote_amount),
            buyer_base: Fr::from(t.sc.buyer_base),
            buyer_quote: Fr::from(t.sc.buyer_quote),
            seller_base: Fr::from(t.sc.seller_base),
            seller_quote: Fr::from(t.sc.seller_quote),
            buyer_path,
            seller_path,
        });
    }
    (prev_root, tree.root(), data)
}
