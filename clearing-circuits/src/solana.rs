//! Slice 4b — the **Solana / `alt_bn128` wire format** for the Groth16 proof,
//! verifying key, and public inputs.
//!
//! A Solana program verifies a BN254 Groth16 proof through the `alt_bn128`
//! syscalls (the same curve and pairing as Ethereum's EIP-197 precompiles), as
//! exposed by verifiers like Light Protocol's `groth16-solana`. Those syscalls
//! consume points in **big-endian, uncompressed affine** form — *not* arkworks'
//! native little-endian compressed serialization. This module is the translation
//! layer: it encodes arkworks `Proof`/`VerifyingKey`/public-input values into that
//! byte layout (and decodes them back).
//!
//! ## Layout
//!
//! - **Field element** (`Fq` or `Fr`): 32 bytes, big-endian.
//! - **G1 point**: `x ‖ y`, 64 bytes.
//! - **G2 point**: `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0`, 128 bytes. The imaginary
//!   coordinate comes first — the EIP-197 convention the `alt_bn128` pairing
//!   uses (arkworks orders `Fq2` as `(c0, c1)`, so we swap on the wire).
//! - **Proof**: `A(G1) ‖ B(G2) ‖ C(G1)`, 256 bytes.
//! - **Verifying key**: `alpha_g1(G1) ‖ beta_g2(G2) ‖ gamma_g2(G2) ‖
//!   delta_g2(G2) ‖ ic[0..n+1](G1 each)`, where `ic == gamma_abc_g1` has
//!   `public_inputs + 1` entries.
//!
//! ## What is verified here, and what is not
//!
//! The round-trip test re-verifies a real proof *after* it has been encoded to
//! these bytes and decoded back through arkworks — proving the encoding is
//! **faithful and invertible** (a wrong endianness, padding, or `Fq2` order would
//! corrupt the point and fail either `G1Affine::new`'s on-curve check or the
//! pairing). What it does *not* prove is byte-for-byte equality with a *specific*
//! on-chain verifier's expected input: conventions like proof-`A` negation and
//! exact VK struct framing are verifier- and version-specific, and confirming
//! them needs a known-answer vector or an SVM test (the remaining gap; see
//! README slice 4).

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};

/// A field element as 32 big-endian bytes (works for both `Fq` and `Fr`).
fn fe_to_be<F: PrimeField>(x: &F) -> [u8; 32] {
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    // BN254 field elements are 254-bit ⇒ 32 bytes; left-pad defensively.
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

fn fq_from_be(b: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(b)
}

/// Encode a public input as 32 big-endian bytes (one `alt_bn128` scalar).
pub fn public_input_to_bytes(x: &Fr) -> [u8; 32] {
    fe_to_be(x)
}

/// Encode a G1 point: `x ‖ y`, big-endian, 64 bytes.
pub fn g1_to_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fe_to_be(&p.x));
    out[32..].copy_from_slice(&fe_to_be(&p.y));
    out
}

/// Decode a G1 point. Panics if the bytes are not a valid curve point.
pub fn g1_from_bytes(b: &[u8; 64]) -> G1Affine {
    G1Affine::new(fq_from_be(&b[..32]), fq_from_be(&b[32..]))
}

/// Encode a G2 point: `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0` (EIP-197 order), 128 bytes.
pub fn g2_to_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&fe_to_be(&p.x.c1));
    out[32..64].copy_from_slice(&fe_to_be(&p.x.c0));
    out[64..96].copy_from_slice(&fe_to_be(&p.y.c1));
    out[96..].copy_from_slice(&fe_to_be(&p.y.c0));
    out
}

/// Decode a G2 point. Panics if the bytes are not a valid curve point.
pub fn g2_from_bytes(b: &[u8; 128]) -> G2Affine {
    // c1 is first on the wire; arkworks `Fq2::new` takes (c0, c1).
    let x = Fq2::new(fq_from_be(&b[32..64]), fq_from_be(&b[..32]));
    let y = Fq2::new(fq_from_be(&b[96..]), fq_from_be(&b[64..96]));
    G2Affine::new(x, y)
}

/// Encode a Groth16 proof: `A ‖ B ‖ C`, 256 bytes.
pub fn proof_to_bytes(proof: &Proof<Bn254>) -> [u8; 256] {
    let mut out = [0u8; 256];
    out[..64].copy_from_slice(&g1_to_bytes(&proof.a));
    out[64..192].copy_from_slice(&g2_to_bytes(&proof.b));
    out[192..].copy_from_slice(&g1_to_bytes(&proof.c));
    out
}

/// Decode a Groth16 proof from its 256-byte wire form.
pub fn proof_from_bytes(b: &[u8; 256]) -> Proof<Bn254> {
    Proof {
        a: g1_from_bytes(b[..64].try_into().unwrap()),
        b: g2_from_bytes(b[64..192].try_into().unwrap()),
        c: g1_from_bytes(b[192..].try_into().unwrap()),
    }
}

/// Encode a verifying key in the layout above. The trailing `ic` block has one
/// G1 point per public input plus one (the constant term).
pub fn vk_to_bytes(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 128 * 3 + 64 * vk.gamma_abc_g1.len());
    out.extend_from_slice(&g1_to_bytes(&vk.alpha_g1));
    out.extend_from_slice(&g2_to_bytes(&vk.beta_g2));
    out.extend_from_slice(&g2_to_bytes(&vk.gamma_g2));
    out.extend_from_slice(&g2_to_bytes(&vk.delta_g2));
    for ic in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_bytes(ic));
    }
    out
}
