//! The zkVM guest: proves one clearing batch transition.
//!
//! It reads a `Witness` plus the trusted verifier config (`matcher_key`,
//! `expiry_height`, `batch_seq`), runs the *executing* verifier — re-execute the
//! batch, bind execution + messages to the committed leaves, **and re-verify
//! every trade's maker/taker/matcher signatures and over-fill accounting** (the
//! keystone checks) — then commits one 144-byte public-values slice:
//! `prev_root ‖ new_root ‖ withdrawals_root ‖ matcher_key ‖ batch_seq_le ‖
//! expiry_height_le`. `batch_seq` (the contract's withdrawal-root index) is
//! distinct from `expiry_height` (the expiry clock; v1: 0). Production never
//! passes `None` for the matcher key. If the witness is invalid, `prove` panics
//! and no proof can be produced.
//!
//! This reuses `clearing::ExecutingProver` directly — the proven logic is exactly
//! the native, tested verifier, so there is no second implementation to drift.
//! The ed25519 signature checks inside `prove` are accelerated by SP1's
//! curve25519 precompile (see the root `Cargo.toml` patch).

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
    // Trusted matcher key — not optional. Production always re-verifies matcher
    // signatures against this key.
    let matcher_key = sp1_zkvm::io::read::<Ed25519PubKey>();
    // Expiry clock (v1: 0). Distinct from `batch_seq` below.
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
