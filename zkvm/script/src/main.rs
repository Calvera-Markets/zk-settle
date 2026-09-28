//! Host: one-trade batch at `CLEARING_TREE_DEPTH` (8 in this workspace), run in
//! the SP1 guest.
//!
//!   cargo run -p clearing-script --release --locked
//!   SP1_ALLOW_PROVE=1 ./target/release/clearing-host --prove
//!
//! `--groth16` wraps the SP1 recursion circuit (about 20 minutes, tens of GB).
//! Not a unit test. Needs `SP1_ALLOW_GROTH16=1` and an already-built binary.

use clearing::auth::{Ed25519PubKey, Ed25519Signature, Order, Side, SignedOrder, TradeAuth};
use clearing::commitment::{
    DEPTH, PUBLIC_VALUES_LEN, encode_matcher_msg, encode_order, order_id, pack_public_values,
    withdrawals_root,
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
    Elf, HashableKey, ProvingKey as _, SP1ProofWithPublicValues, SP1Stdin,
    blocking::{EnvProver, ProveRequest as _, Prover as _, ProverClient},
    include_elf,
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
/// (0), and batch_seq (0 for this single-batch demo). Each trade is a
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
        if root.is_dir() {
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

/// SP1 6 on-chain wrap bytes, TEE prefix stripped if present.
///
/// Observed layout (356 bytes): `SHA256(gnark_vk)[0..4]` ‖ exit(32) ‖ vk_root(32)
/// ‖ proof_nonce(32) ‖ A‖B‖C (256). Older docs assumed 260 (prefix + ABC only).
fn onchain_groth16_bytes(proof: &SP1ProofWithPublicValues) -> Vec<u8> {
    let mut bytes = proof.bytes();
    if let Some(tee) = &proof.tee_proof {
        assert!(
            bytes.starts_with(tee.as_slice()),
            "proof.bytes() should start with tee_proof"
        );
        bytes = bytes[tee.len()..].to_vec();
    }
    bytes
}

fn dump_wrap_artifacts(
    dir: &Path,
    proof: &SP1ProofWithPublicValues,
    public_values: &[u8],
    guest_vk_hash: &[u8; 32],
) {
    std::fs::create_dir_all(dir).expect("create dump dir");
    proof
        .save(dir.join("sp1_proof.bin"))
        .expect("write sp1_proof.bin");
    let raw = proof.bytes();
    std::fs::write(dir.join("proof.raw.bin"), &raw).expect("write proof.raw.bin");
    let proof_bytes = onchain_groth16_bytes(proof);
    assert!(
        proof_bytes.len() >= 4,
        "wrap proof too short: {} (raw {})",
        proof_bytes.len(),
        raw.len()
    );
    assert_eq!(public_values.len(), PUBLIC_VALUES_LEN);
    std::fs::write(dir.join("proof.bin"), &proof_bytes).expect("write proof.bin");
    std::fs::write(dir.join("public_values.bin"), public_values).expect("write public_values.bin");
    std::fs::write(dir.join("guest_vk_hash.bin"), guest_vk_hash).expect("write guest_vk_hash.bin");

    let prefix: [u8; 4] = proof_bytes[..4].try_into().unwrap();
    let mut meta = String::new();
    meta.push_str(&format!("proof_len={}\n", proof_bytes.len()));
    meta.push_str(&format!("proof_raw_len={}\n", raw.len()));
    meta.push_str(&format!("tree_depth={DEPTH}\n"));
    meta.push_str("layout=4_vk_prefix+32_exit+32_vk_root+32_nonce+256_ABC\n");
    if let Some(tee) = &proof.tee_proof {
        meta.push_str(&format!("tee_proof_len={}\n", tee.len()));
    }
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

fn execute_guest(client: &EnvProver, stdin: SP1Stdin) -> (Vec<u8>, u64) {
    let (public, report) = client.execute(ELF, stdin).run().expect("execute failed");
    (public.as_slice().to_vec(), report.total_instruction_count())
}

fn cap_threads() {
    if std::env::var_os("RAYON_NUM_THREADS").is_none() {
        std::env::set_var("RAYON_NUM_THREADS", "2");
    }
}

fn require_allow(flag: &str, env_name: &str) {
    if std::env::var(env_name).ok().as_deref() != Some("1") {
        eprintln!(
            "refusing {flag}: this path pins tens of GB of RAM (SP1 setup / gnark wrap).\n\
             Re-run with {env_name}=1 RAYON_NUM_THREADS=2, and prefer an already-built\n\
             binary (`./target/release/clearing-host`) so cargo does not rebuild sp1-sdk."
        );
        std::process::exit(2);
    }
}

fn main() {
    cap_threads();
    sp1_sdk::utils::setup_logger();
    let do_groth16 = std::env::args().any(|a| a == "--groth16");
    let do_prove = do_groth16 || std::env::args().any(|a| a == "--prove");
    if do_groth16 {
        require_allow("--groth16", "SP1_ALLOW_GROTH16");
    } else if do_prove {
        require_allow("--prove", "SP1_ALLOW_PROVE");
    }
    let dump_dir = arg_value("--dump-dir").map(PathBuf::from);

    // Number of trades in the batch (default 1). Set TRADES=100 to measure how
    // cycles scale with trade count.
    let n_trades: u64 = std::env::var("TRADES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    if n_trades > 4 && std::env::var("SP1_ALLOW_HEAVY").ok().as_deref() != Some("1") {
        eprintln!(
            "refusing TRADES={n_trades}: cap is 4 on a laptop. Set SP1_ALLOW_HEAVY=1 to override."
        );
        std::process::exit(2);
    }

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
    let (public, cycles) = execute_guest(&client, stdin);
    let exec_time = t_exec.elapsed();
    println!(
        "executed in zkVM: {cycles} cycles in {exec_time:.2?}  (tree depth {DEPTH}, {n_trades} trade(s), {} ed25519 sigs, {:.0} cycles/trade)",
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
                dump_wrap_artifacts(dir, &proof, pv, &guest_vk_hash);
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
    fn zkvm_compiles_shallow_tree() {
        assert_eq!(
            DEPTH, 8,
            "zkvm must compile clearing at CLEARING_TREE_DEPTH=8"
        );
    }

    #[test]
    fn execute_guest_matches_host_public_values() {
        // Debug SP1 execute takes minutes; this is the release test loop.
        if cfg!(debug_assertions) {
            return;
        }
        cap_threads();
        let (witness, matcher_key, expiry_height, batch_seq) = build_witness(1);
        let expected = expected_public_values(&witness, &matcher_key, batch_seq, expiry_height);
        let client = ProverClient::from_env();
        let stdin = write_stdin(&witness, &matcher_key, batch_seq, expiry_height);
        let (pv, cycles) = execute_guest(&client, stdin);
        eprintln!("execute_guest: {cycles} cycles at DEPTH={DEPTH}");
        assert_eq!(pv.as_slice(), expected.as_slice());
    }

    #[test]
    fn prove_guest_core_verifies() {
        if cfg!(debug_assertions) {
            return;
        }
        cap_threads();
        let (witness, matcher_key, expiry_height, batch_seq) = build_witness(1);
        let expected = expected_public_values(&witness, &matcher_key, batch_seq, expiry_height);
        let client = ProverClient::from_env();
        let pk = client.setup(ELF).expect("setup");
        let proof = client
            .prove(
                &pk,
                write_stdin(&witness, &matcher_key, batch_seq, expiry_height),
            )
            .run()
            .expect("core prove");
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("core verify");
        assert_eq!(proof.public_values.as_slice(), expected.as_slice());
        eprintln!("core prove+verify ok at DEPTH={DEPTH}");
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
