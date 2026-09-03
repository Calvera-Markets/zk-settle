//! Host: build a clearing batch witness, run it through the zkVM guest, and
//! (optionally) generate a proof.
//!
//!   cargo run --release                # execute only (runs the guest, no proof)
//!   cargo run --release -- --prove     # generate + verify a fast CORE proof
//!   cargo run --release -- --groth16   # generate + verify the ON-CHAIN Groth16
//!                                       # proof (the heavy gnark wrap; times it)
//!   cargo run --release -- --groth16 --dump-dir DIR
//!                                       # also write proof/pv/vk artifacts for
//!                                       # clearing-solana wrap tests (260-byte proof)
//!
//! `--execute` runs the `ExecutingProver` *inside* the zkVM and returns the
//! committed 144-byte public-values slice (`prev_root ‖ new_root ‖
//! withdrawals_root ‖ matcher_key ‖ batch_seq_le ‖ expiry_height_le`); we check
//! it matches. The batch includes an **authenticated trade** (maker + taker +
//! matcher signatures), so the guest re-verifies three ed25519 signatures —
//! accelerated by SP1's curve25519 precompile. `--prove` produces a real SP1
//! proof of that execution.

use clearing::auth::{Ed25519PubKey, Ed25519Signature, Order, Side, SignedOrder, TradeAuth};
use clearing::commitment::{
    encode_matcher_msg, encode_order, order_id, pack_public_values, withdrawals_root,
    PUBLIC_VALUES_LEN,
};
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, L1Address, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{ExecutingProver, OnChainMessage, Prover, State, StateTree, Tx, Witness};

#[cfg(not(feature = "poseidon2"))]
use clearing::commitment::hash_plain::Sha256Hasher as H;
#[cfg(feature = "poseidon2")]
use clearing::commitment::hash_poseidon2::Poseidon2Hasher as H;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest as _, Prover as _, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey as _, SP1Stdin,
};
use std::path::{Path, PathBuf};
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

fn expected_public_values(
    witness: &Witness,
    matcher_key: &Ed25519PubKey,
    batch_seq: u64,
    expiry_height: u64,
) -> [u8; PUBLIC_VALUES_LEN] {
    let entries: Vec<_> = witness
        .messages
        .iter()
        .map(
            |OnChainMessage::Withdraw {
                 owner,
                 asset,
                 amount,
             }| (*owner, *asset, *amount),
        )
        .collect();
    let w_root = withdrawals_root(&H::default(), batch_seq, &entries);
    pack_public_values(
        &witness.prev_root,
        &witness.new_root,
        &w_root,
        matcher_key,
        batch_seq,
        expiry_height,
    )
}

fn write_stdin(
    witness: &Witness,
    matcher_key: &Ed25519PubKey,
    batch_seq: u64,
    expiry_height: u64,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(witness);
    stdin.write(matcher_key);
    // Guest reads expiry_height then batch_seq; params follow the byte layout.
    stdin.write(&expiry_height);
    stdin.write(&batch_seq);
    stdin
}

/// Build an authenticated batch (fund + register keys, `n_trades` signed trades,
/// then a withdrawal) and capture its witness. Returns the witness plus the
/// trusted verifier config the guest re-verifies: matcher key, expiry height
/// (v1: 0), and batch_seq (0 for this single-batch demo). Each trade is a
/// distinct order pair (unique salt) filled once, so the batch re-verifies
/// `3 * n_trades` ed25519 signatures.
fn build_witness(n_trades: u64) -> (Witness, Ed25519PubKey, u64, u64) {
    let market = MarketId(Uuid::from_u128(0xA1));
    let usdc = AssetId(0);
    let btc = AssetId(1);
    let buyer = AccountId(Uuid::from_u128(0xB));
    let seller = AccountId(Uuid::from_u128(0x5));

    let (buyer_sk, buyer_pk) = keypair(1);
    let (seller_sk, seller_pk) = keypair(2);
    let (op_sk, op_pk) = keypair(3);
    let expiry_height = 0u64;
    // First batch in an empty contract: `withdrawal_roots.len() == 0`.
    let batch_seq = 0u64;

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
            owner: L1Address(buyer_pk.0),
            trading_key: Some(buyer_pk),
        },
        Tx::Deposit {
            account: seller,
            asset: btc,
            amount: Amount(2 * n_trades as i128 + 10),
            nonce: 1,
            owner: L1Address(seller_pk.0),
            trading_key: Some(seller_pk),
        },
    ];

    // One distinct, single-fill signed trade per iteration (unique salt).
    for i in 0..n_trades {
        let fill = Fill {
            buyer,
            seller,
            base_amount: Amount(2),
            quote_amount: Amount(400),
        };
        let buy = Order {
            account: buyer,
            market,
            side: Side::Buy,
            base_amount: Amount(2),
            limit_price: Amount(250),
            expiry: 1000,
            salt: i,
        };
        let sell = Order {
            account: seller,
            market,
            side: Side::Sell,
            base_amount: Amount(2),
            limit_price: Amount(180),
            expiry: 1000,
            salt: i,
        };
        let matcher_msg = encode_matcher_msg(market, &order_id(&buy), &order_id(&sell), &fill);
        let auth = TradeAuth {
            buy: SignedOrder {
                order: buy,
                sig: sign(&buyer_sk, &encode_order(&buy)),
            },
            sell: SignedOrder {
                order: sell,
                sig: sign(&seller_sk, &encode_order(&sell)),
            },
            matcher_sig: sign(&op_sk, &matcher_msg),
        };
        batch.push(Tx::Trade {
            market,
            fill,
            auth: Some(Box::new(auth)),
        });
    }

    batch.push(Tx::Withdraw {
        account: buyer,
        asset: usdc,
        amount: Amount(100),
    });

    let witness = Witness::capture(&mut state, &mut tree, &batch);
    (witness, op_pk, expiry_height, batch_seq)
}

fn arg_value(flag: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == flag {
            return args.next();
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn default_dump_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../clearing-solana/fixtures/sp1")
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn find_groth16_vk(prefix: &[u8; 4]) -> Option<(PathBuf, Vec<u8>)> {
    let mut candidates = Vec::new();
    if let Some(p) = std::env::var_os("SP1_GROTH16_VK") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let root = PathBuf::from(home).join(".sp1/circuits");
        if let Ok(walk) = std::fs::read_dir(&root) {
            fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
                let Ok(rd) = std::fs::read_dir(dir) else {
                    return;
                };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        collect(&p, out);
                    } else if p.file_name().is_some_and(|n| n == "groth16_vk.bin") {
                        out.push(p);
                    }
                }
            }
            collect(&root, &mut candidates);
        }
    }
    for path in candidates {
        if let Ok(bytes) = std::fs::read(&path) {
            let hash = sha256_bytes(&bytes);
            if hash[..4] == prefix[..] {
                return Some((path, bytes));
            }
        }
    }
    None
}

fn dump_wrap_artifacts(
    dir: &Path,
    proof_bytes: &[u8],
    public_values: &[u8],
    guest_vk_hash: &[u8; 32],
) {
    assert_eq!(
        proof_bytes.len(),
        260,
        "Groth16 wrap proof must be 260 bytes (4-byte gnark vk prefix + A||B||C); got {}",
        proof_bytes.len()
    );
    assert_eq!(public_values.len(), PUBLIC_VALUES_LEN);
    std::fs::create_dir_all(dir).expect("create dump dir");
    std::fs::write(dir.join("proof.bin"), proof_bytes).expect("write proof.bin");
    std::fs::write(dir.join("public_values.bin"), public_values).expect("write public_values.bin");
    std::fs::write(dir.join("guest_vk_hash.bin"), guest_vk_hash).expect("write guest_vk_hash.bin");

    let prefix: [u8; 4] = proof_bytes[..4].try_into().unwrap();
    let mut meta = String::new();
    meta.push_str(&format!("proof_len={}\n", proof_bytes.len()));
    meta.push_str(&format!("sp1-sdk=6.0.1 (lock may resolve newer)\n"));
    meta.push_str(&format!(
        "groth16_vk_hash_prefix={}\n",
        prefix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));

    match find_groth16_vk(&prefix) {
        Some((path, bytes)) => {
            let vk_hash = sha256_bytes(&bytes);
            std::fs::write(dir.join("groth16_vk.bin"), &bytes).expect("write groth16_vk.bin");
            meta.push_str(&format!("groth16_vk_path={}\n", path.display()));
            meta.push_str(&format!(
                "groth16_vk_sha256={}\n",
                vk_hash
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            meta.push_str("GROTH16_VK_match=prefix of SHA256(gnark_vk.bin) == proof[0..4]\n");
        }
        None => {
            meta.push_str("groth16_vk_path=NOT_FOUND set SP1_GROTH16_VK\n");
        }
    }
    std::fs::write(dir.join("meta.txt"), meta).expect("write meta.txt");
    println!("dumped wrap artifacts to {}", dir.display());
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let do_groth16 = std::env::args().any(|a| a == "--groth16");
    let do_prove = do_groth16 || std::env::args().any(|a| a == "--prove");
    let dump_dir = arg_value("--dump-dir").map(PathBuf::from).or_else(|| {
        if do_groth16 {
            Some(default_dump_dir())
        } else {
            None
        }
    });

    // Number of trades in the batch (default 1). Set TRADES=100 to measure how
    // cycles scale with trade count.
    let n_trades: u64 = std::env::var("TRADES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let (witness, matcher_key, expiry_height, batch_seq) = build_witness(n_trades);
    // The trades must have applied (authenticated swaps), so the batch is not a
    // no-op — a quick sanity check that auth passed at capture.
    assert!(
        !witness.updates.is_empty(),
        "authenticated batch produced no updates"
    );

    // Native sanity check (same logic the guest runs, same trusted config).
    ExecutingProver::with_auth(H::default(), matcher_key, expiry_height)
        .prove(&witness)
        .expect("witness should be valid");

    let expected = expected_public_values(&witness, &matcher_key, batch_seq, expiry_height);

    let client = ProverClient::from_env();

    // Execute: run the guest in the zkVM, get the committed public outputs.
    let stdin = write_stdin(&witness, &matcher_key, batch_seq, expiry_height);
    let t_exec = std::time::Instant::now();
    let (public, report) = client.execute(ELF, stdin).run().expect("execute failed");
    let exec_time = t_exec.elapsed();
    let cycles = report.total_instruction_count();
    println!(
        "executed in zkVM: {cycles} cycles in {exec_time:.2?}  ({n_trades} trade(s), {} ed25519 sigs, {:.0} cycles/trade)",
        3 * n_trades,
        cycles as f64 / n_trades as f64,
    );

    let pv = public.as_slice();
    assert_eq!(
        pv.len(),
        PUBLIC_VALUES_LEN,
        "public values must be 144 bytes"
    );
    assert_eq!(pv, expected.as_slice());
    assert_eq!(&pv[128..136], &batch_seq.to_le_bytes());
    assert_eq!(&pv[136..144], &expiry_height.to_le_bytes());
    println!(
        "public outputs match ✓  (144-byte slice: prev/new/withdrawals roots, matcher_key, batch_seq, expiry_height; {} withdrawal(s))",
        witness.messages.len()
    );

    if do_prove {
        // Time each phase separately — setup (builds the proving key; the first
        // Groth16 run also fetches the gnark artifacts), proving, and verify.
        let t_setup = std::time::Instant::now();
        let pk = client.setup(ELF).expect("setup failed");
        let setup_time = t_setup.elapsed();

        let req = client.prove(
            &pk,
            write_stdin(&witness, &matcher_key, batch_seq, expiry_height),
        );
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

        println!(
            "SP1 {mode} proof generated + verified ✓  ({} proof bytes)",
            proof.bytes().len()
        );
        println!("  timing:");
        println!("    execute : {exec_time:.2?}");
        println!("    setup   : {setup_time:.2?}");
        println!("    prove   : {prove_time:.2?}");
        println!("    verify  : {verify_time:.2?}");
        println!(
            "    total   : {:.2?}",
            exec_time + setup_time + prove_time + verify_time
        );

        if do_groth16 {
            if let Some(dir) = dump_dir.as_ref() {
                let guest_vk_hash = pk.verifying_key().bytes32_raw();
                dump_wrap_artifacts(dir, &proof.bytes(), pv, &guest_vk_hash);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// SP1 Groth16 public-input digest: SHA-256 of the committed bytes, then
    /// `out[0] &= 0x1F` so the result fits in BN254 Fr (253 bits). Copied from
    /// the on-chain verifier (`hashPublicValues` / `hash_public_inputs`).
    fn hash_public_inputs(public_values: &[u8]) -> [u8; 32] {
        let mut out: [u8; 32] = Sha256::digest(public_values).into();
        out[0] &= 0x1F;
        out
    }

    #[test]
    fn packed_public_values_are_144_bytes_and_seq_is_not_expiry() {
        let prev = [0x11u8; 32];
        let new = [0x22u8; 32];
        let w = [0x33u8; 32];
        let matcher = Ed25519PubKey([0x44u8; 32]);
        let batch_seq = 7u64;
        let expiry_height = 0u64;

        let pv = pack_public_values(&prev, &new, &w, &matcher, batch_seq, expiry_height);
        assert_eq!(pv.len(), 144);
        assert_eq!(&pv[0..32], &prev);
        assert_eq!(&pv[32..64], &new);
        assert_eq!(&pv[64..96], &w);
        assert_eq!(&pv[96..128], &matcher.0);
        assert_eq!(&pv[128..136], &batch_seq.to_le_bytes());
        assert_eq!(&pv[136..144], &expiry_height.to_le_bytes());
        // Distinct fields: a non-zero seq must not collide with expiry at 0.
        assert_ne!(&pv[128..136], &pv[136..144]);
    }

    #[test]
    fn hash_public_inputs_masks_bn254_top_bits() {
        let pv = pack_public_values(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &Ed25519PubKey([4u8; 32]),
            1,
            0,
        );
        let digest = hash_public_inputs(&pv);
        assert_eq!(
            digest[0] & 0xE0,
            0,
            "top 3 bits must be cleared for BN254 Fr"
        );

        let unmasked: [u8; 32] = Sha256::digest(pv).into();
        let mut expected = unmasked;
        expected[0] &= 0x1F;
        assert_eq!(digest, expected);
    }

    #[test]
    fn expected_public_values_from_demo_witness() {
        let (witness, matcher_key, expiry_height, batch_seq) = build_witness(1);
        assert!(!witness.messages.is_empty());
        let pv = expected_public_values(&witness, &matcher_key, batch_seq, expiry_height);
        assert_eq!(&pv[0..32], &witness.prev_root);
        assert_eq!(&pv[32..64], &witness.new_root);
        assert_eq!(&pv[96..128], &matcher_key.0);
        assert_eq!(&pv[128..136], &batch_seq.to_le_bytes());
        assert_eq!(&pv[136..144], &expiry_height.to_le_bytes());
        assert_eq!(batch_seq, 0);
        assert_eq!(expiry_height, 0);
    }

    #[test]
    fn withdrawals_root_in_public_values_is_keyed_by_batch_seq_not_expiry() {
        let (witness, matcher_key, _, _) = build_witness(1);
        let batch_seq = 7u64;
        let expiry_height = 99u64;
        assert_ne!(batch_seq, expiry_height);

        let entries: Vec<_> = witness
            .messages
            .iter()
            .map(
                |OnChainMessage::Withdraw {
                     owner,
                     asset,
                     amount,
                 }| (*owner, *asset, *amount),
            )
            .collect();
        let seq_root = withdrawals_root(&H::default(), batch_seq, &entries);
        let expiry_root = withdrawals_root(&H::default(), expiry_height, &entries);
        assert_ne!(seq_root, expiry_root);

        let pv = expected_public_values(&witness, &matcher_key, batch_seq, expiry_height);
        assert_eq!(&pv[64..96], &seq_root);
        assert_ne!(&pv[64..96], &expiry_root);
        assert_eq!(&pv[128..136], &batch_seq.to_le_bytes());
        assert_eq!(&pv[136..144], &expiry_height.to_le_bytes());
    }

    #[test]
    fn hash_public_inputs_matches_sp1_known_answer() {
        // Vector from sp1-primitives `test_hash_public_values`.
        let mut input = Vec::new();
        for _ in 0..8 {
            input.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
        }
        let digest = hash_public_inputs(&input);
        let expected = [
            0x1c, 0xe9, 0x87, 0xd0, 0xa7, 0xfc, 0xc2, 0x63, 0x6f, 0xe8, 0x7e, 0x69, 0x29, 0x5b,
            0xa1, 0x2b, 0x1c, 0xc4, 0x6c, 0x25, 0x6b, 0x36, 0x9a, 0xe7, 0x40, 0x1c, 0x51, 0xb8,
            0x05, 0xee, 0x91, 0xbd,
        ];
        assert_eq!(digest, expected);
    }
}
