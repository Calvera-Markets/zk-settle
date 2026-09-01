//! The zkVM guest: proves one clearing batch transition.
//!
//! It reads a `Witness` plus the trusted verifier config (`operator_key`,
//! `batch_height`), runs the *executing* verifier — re-execute the batch, bind
//! execution + messages to the committed leaves, **and re-verify every trade's
//! maker/taker/matcher signatures and over-fill accounting** (the keystone
//! checks) — then commits the public outputs the on-chain verifier acts on:
//! `prev_root`, `new_root`, the proven withdrawal `messages`, and the
//! `operator_key`/`batch_height` it enforced (so the contract can check those
//! against its own config/counter). If the witness is invalid, `prove` panics and
//! no proof can be produced.
//!
//! This reuses `clearing::ExecutingProver` directly — the proven logic is exactly
//! the native, tested verifier, so there is no second implementation to drift.
//! The ed25519 signature checks inside `prove` are accelerated by SP1's
//! curve25519 precompile (see the root `Cargo.toml` patch).

#![no_main]
sp1_zkvm::entrypoint!(main);

use clearing::auth::Ed25519PubKey;
use clearing::{ExecutingProver, Prover, Witness};

#[cfg(not(feature = "poseidon2"))]
use clearing::commitment::hash_plain::Sha256Hasher as H;
#[cfg(feature = "poseidon2")]
use clearing::commitment::hash_poseidon2::Poseidon2Hasher as H;

pub fn main() {
    let witness = sp1_zkvm::io::read::<Witness>();
    // Trusted verifier config (not part of the witness): the operator key the
    // matcher signatures must verify against, and the batch height for expiry.
    let operator_key = sp1_zkvm::io::read::<Option<Ed25519PubKey>>();
    let batch_height = sp1_zkvm::io::read::<u64>();

    let prover = match operator_key {
        Some(key) => ExecutingProver::with_auth(H::default(), key, batch_height),
        None => ExecutingProver::new(H::default()),
    };
    prover.prove(&witness).expect("invalid batch transition");

    sp1_zkvm::io::commit(&witness.prev_root);
    sp1_zkvm::io::commit(&witness.new_root);
    sp1_zkvm::io::commit(&witness.messages);
    // Commit the enforced config so the contract validates it against its own.
    sp1_zkvm::io::commit(&operator_key);
    sp1_zkvm::io::commit(&batch_height);
}
