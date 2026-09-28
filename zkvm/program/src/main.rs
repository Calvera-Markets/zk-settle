//! SP1 guest: one clearing batch via [`clearing::ExecutingProver`].
//!
//! Reads a `Witness` and verifier config (`matcher_key`, `expiry_height`,
//! `batch_seq`). Re-executes the batch (signatures and over-fill included).
//! Commits 144 bytes:
//! `prev_root ‖ new_root ‖ withdrawals_root ‖ matcher_key ‖ batch_seq_le ‖
//! expiry_height_le`.
//!
//! `batch_seq` indexes the contract's withdrawal-root list. `expiry_height` is
//! a separate clock (currently 0). Invalid witnesses panic; no proof is
//! produced. ed25519 uses SP1's curve25519 precompile (patches in this
//! workspace `Cargo.toml`).

#![no_main]
sp1_zkvm::entrypoint!(main);

use clearing::auth::Ed25519PubKey;
use clearing::commitment::{pack_public_values, withdrawals_root};
use clearing::{ExecutingProver, OnChainMessage, Prover, Witness};

#[cfg(not(feature = "poseidon2"))]
use clearing::commitment::hash_plain::Sha256Hasher as H;
#[cfg(feature = "poseidon2")]
use clearing::commitment::hash_poseidon2::Poseidon2Hasher as H;

pub fn main() {
    let witness = sp1_zkvm::io::read::<Witness>();
    // Trusted matcher key. Signatures are checked against this, not the witness.
    let matcher_key = sp1_zkvm::io::read::<Ed25519PubKey>();
    // Expiry clock (0 until expiry is used). Distinct from `batch_seq`.
    let expiry_height = sp1_zkvm::io::read::<u64>();
    // Index of this batch in the contract's `withdrawal_roots` (first batch = 0).
    let batch_seq = sp1_zkvm::io::read::<u64>();

    ExecutingProver::with_auth(H::default(), matcher_key, expiry_height)
        .prove(&witness)
        .expect("invalid batch transition");

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
    let pv = pack_public_values(
        &witness.prev_root,
        &witness.new_root,
        &w_root,
        &matcher_key,
        batch_seq,
        expiry_height,
    );
    sp1_zkvm::io::commit_slice(&pv);
}
