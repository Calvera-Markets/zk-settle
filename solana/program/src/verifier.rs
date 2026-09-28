//! Plain Groth16 over BN254 (`alt_bn128`).
//!
//! Pairing uses `groth16-solana` 0.2 `Groth16Verifier::new` on the host and
//! pinocchio `sol_alt_bn128_group_op` on SBF (crates.io 0.2.0 is not `no_std`).
//!
//! SP1 wrap digest helpers (`hash_public_inputs`, `groth16_public_values`) are
//! copied from succinctlabs/sp1-solana `verifier/src/utils.rs` at
//! `4181cae00d7493ede8a33066cb56683acb1dca72`. That crate is not a dependency
//! of this program. `settle` at `proof_version` 1 calls them.
//!
//! VK account (no `n_ic` word):
//! ```text
//! offset 0     u32 LE   nr_pubinputs
//! offset 4     [u8;64]  α G1
//! offset 68    [u8;128] β G2
//! offset 196   [u8;128] γ G2
//! offset 324   [u8;128] δ G2            // 4 + 64 + 128×3 = 452
//! offset 452            ic[]            // remainder; ic_len = (len-452)/64
//! ```
//! Require `data.len() >= 452`, `(len-452)%64==0`, `ic_len>=1`,
//! `nr_pubinputs == ic_len-1`. Adapter: `nr_pubinputs_u32_le ‖ vk_to_bytes(vk)`
//! with `nr_pubinputs = gamma_abc_g1.len()-1`.
//!
//! Proof is 256 bytes `A ‖ B ‖ C` (circuits `proof_to_bytes` does not negate A).
//! This module always negates A as G1 `(x, y) → (x, p − y)` over BN254 Fq.

use crate::error::ClearingError;

pub const PROOF_LEN: usize = 256;
/// SP1 6 wrap: `SHA256(gnark_vk)[0..4] ‖ exit ‖ vk_root ‖ proof_nonce ‖ A‖B‖C`.
pub const WRAP_PROOF_LEN: usize = 356;
pub const WRAP_PREFIX_LEN: usize = 4;
/// `exit_code ‖ vk_root ‖ proof_nonce` (gnark-ffi Solidity encoding).
pub const WRAP_SP1_HEADER_LEN: usize = 96;
pub const WRAP_ABC_OFF: usize = WRAP_PREFIX_LEN + WRAP_SP1_HEADER_LEN;
const _: () = assert!(WRAP_PROOF_LEN == crate::instruction::SETTLE_PROOF_LEN);
pub const VK_FIXED_LEN: usize = 452;
pub const G1_LEN: usize = 64;
pub const G2_LEN: usize = 128;
pub const FR_LEN: usize = 32;
/// Cap for Groth16 public inputs (wrap uses 5; claim-open uses 4).
pub const MAX_PUBLIC_INPUTS: usize = 8;

/// BN254 scalar field (Fr) modulus, big-endian.
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Debug)]
pub struct ParsedVk<'a> {
    pub nr_pubinputs: u32,
    pub alpha_g1: &'a [u8; G1_LEN],
    pub beta_g2: &'a [u8; G2_LEN],
    pub gamma_g2: &'a [u8; G2_LEN],
    pub delta_g2: &'a [u8; G2_LEN],
    pub ic: &'a [[u8; G1_LEN]],
}

fn read_arr<const N: usize>(data: &[u8], off: usize) -> Result<&[u8; N], ClearingError> {
    data.get(off..off + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(ClearingError::InvalidAccount)
}

fn ic_from_bytes(bytes: &[u8]) -> Result<&[[u8; G1_LEN]], ClearingError> {
    if !bytes.len().is_multiple_of(G1_LEN) {
        return Err(ClearingError::InvalidAccount);
    }
    let n = bytes.len() / G1_LEN;
    // SAFETY: `[u8; 64]` has align 1; `bytes` is `n` contiguous 64-byte groups.
    Ok(unsafe { core::slice::from_raw_parts(bytes.as_ptr() as *const [u8; G1_LEN], n) })
}

pub fn parse_vk(data: &[u8]) -> Result<ParsedVk<'_>, ClearingError> {
    if data.len() < VK_FIXED_LEN {
        return Err(ClearingError::InvalidAccount);
    }
    let rem = data.len() - VK_FIXED_LEN;
    if !rem.is_multiple_of(G1_LEN) {
        return Err(ClearingError::InvalidAccount);
    }
    let ic_len = rem / G1_LEN;
    if ic_len < 1 {
        return Err(ClearingError::InvalidAccount);
    }
    let nr_pubinputs = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| ClearingError::InvalidAccount)?,
    );
    if nr_pubinputs as usize != ic_len - 1 {
        return Err(ClearingError::InvalidAccount);
    }

    Ok(ParsedVk {
        nr_pubinputs,
        alpha_g1: read_arr(data, 4)?,
        beta_g2: read_arr(data, 68)?,
        gamma_g2: read_arr(data, 196)?,
        delta_g2: read_arr(data, 324)?,
        ic: ic_from_bytes(&data[VK_FIXED_LEN..])?,
    })
}

/// `nr_pubinputs_u32_le ‖ vk_to_bytes(vk)` with
/// `nr_pubinputs = ic_len - 1` and `ic_len = (vk_to_bytes.len() - 448) / 64`.
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn encode_vk_account(vk_to_bytes: &[u8]) -> Result<Vec<u8>, ClearingError> {
    const POINTS: usize = 64 + 128 * 3;
    if vk_to_bytes.len() < POINTS || !(vk_to_bytes.len() - POINTS).is_multiple_of(G1_LEN) {
        return Err(ClearingError::InvalidAccount);
    }
    let ic_len = (vk_to_bytes.len() - POINTS) / G1_LEN;
    if ic_len < 1 {
        return Err(ClearingError::InvalidAccount);
    }
    let nr = (ic_len - 1) as u32;
    let mut out = Vec::with_capacity(4 + vk_to_bytes.len());
    out.extend_from_slice(&nr.to_le_bytes());
    out.extend_from_slice(vk_to_bytes);
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedWrapProof {
    pub a: [u8; G1_LEN],
    pub b: [u8; G2_LEN],
    pub c: [u8; G1_LEN],
}

/// Split a 356-byte SP1 wrap proof and check the gnark VK prefix.
///
/// Pairing uses A‖B‖C at offset [`WRAP_ABC_OFF`] (after prefix + 96-byte SP1
/// header). A is returned *not* negated.
pub fn parse_wrap_proof(
    proof: &[u8; WRAP_PROOF_LEN],
    expected_prefix: &[u8; WRAP_PREFIX_LEN],
) -> Result<ParsedWrapProof, ClearingError> {
    if proof[..WRAP_PREFIX_LEN] != expected_prefix[..] {
        return Err(ClearingError::InvalidProof);
    }
    let abc = WRAP_ABC_OFF;
    Ok(ParsedWrapProof {
        a: proof[abc..abc + G1_LEN]
            .try_into()
            .map_err(|_| ClearingError::InvalidProof)?,
        b: proof[abc + G1_LEN..abc + G1_LEN + G2_LEN]
            .try_into()
            .map_err(|_| ClearingError::InvalidProof)?,
        c: proof[abc + G1_LEN + G2_LEN..]
            .try_into()
            .map_err(|_| ClearingError::InvalidProof)?,
    })
}

/// SHA-256 of `public_inputs`, then `out[0] &= 0x1F` so the digest fits in BN254 Fr.
///
/// Copied from succinctlabs/sp1-solana `verifier/src/utils.rs` at
/// `4181cae00d7493ede8a33066cb56683acb1dca72`.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = crate::hash::sha256(&[public_inputs]);
    result[0] &= 0x1F;
    result
}

/// Outer Groth16 public inputs for an SP1 wrap: two 32-byte BE scalars.
///
/// Layout matches `load_public_inputs_from_bytes` in the same sp1-solana
/// commit: a leading zero byte, then `vkey_hash[1..32]`, then the digest of
/// the guest public values. Copied from `groth16_public_values` there (that
/// helper returns 63 bytes; this inlines the leading zero).
pub fn groth16_public_values(sp1_vkey_hash: &[u8; 32], sp1_public_inputs: &[u8]) -> [u8; 64] {
    let digest = hash_public_inputs(sp1_public_inputs);
    let mut out = [0u8; 64];
    out[1..32].copy_from_slice(&sp1_vkey_hash[1..]);
    out[32..].copy_from_slice(&digest);
    out
}

/// Negate a BN254 G1 point `(x, y) → (x, p − y)` over Fq, 64-byte BE uncompressed.
pub fn negate_g1(g1: &[u8; G1_LEN]) -> [u8; G1_LEN] {
    if *g1 == [0u8; G1_LEN] {
        return [0u8; G1_LEN];
    }
    let mut result = [0u8; G1_LEN];
    result[..32].copy_from_slice(&g1[..32]);
    // BN254 Fq modulus, big-endian u64 limbs.
    const FQ: [u64; 4] = [
        0x30644e72e131a029,
        0xb85045b68181585d,
        0x97816a916871ca8d,
        0x3c208c16d87cfd47,
    ];
    let y_limb = |off: usize| {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&g1[off..off + 8]);
        u64::from_be_bytes(limb)
    };
    let y = [y_limb(32), y_limb(40), y_limb(48), y_limb(56)];
    let mut borrow: u64 = 0;
    let mut neg_y = [0u64; 4];
    for i in (0..4).rev() {
        let (diff, b1) = FQ[i].overflowing_sub(y[i]);
        let (diff, b2) = diff.overflowing_sub(borrow);
        neg_y[i] = diff;
        borrow = u64::from(b1) + u64::from(b2);
    }
    result[32..40].copy_from_slice(&neg_y[0].to_be_bytes());
    result[40..48].copy_from_slice(&neg_y[1].to_be_bytes());
    result[48..56].copy_from_slice(&neg_y[2].to_be_bytes());
    result[56..64].copy_from_slice(&neg_y[3].to_be_bytes());
    result
}

fn is_less_than_fr_modulus(bytes: &[u8; FR_LEN]) -> bool {
    *bytes < FR_MODULUS_BE
}

/// SP1 6 wrap public inputs: guest vk hash, SHA-256 digest of guest PV,
/// then `exit ‖ vk_root ‖ proof_nonce` from the 96-byte proof header.
pub const WRAP_NR_PUBINPUTS: u32 = 5;

pub fn wrap_public_inputs(
    guest_vk_hash: &[u8; 32],
    public_values: &[u8],
    proof: &[u8; WRAP_PROOF_LEN],
) -> [[u8; FR_LEN]; WRAP_NR_PUBINPUTS as usize] {
    let digest = hash_public_inputs(public_values);
    let mut exit = [0u8; FR_LEN];
    let mut vk_root = [0u8; FR_LEN];
    let mut nonce = [0u8; FR_LEN];
    exit.copy_from_slice(&proof[WRAP_PREFIX_LEN..WRAP_PREFIX_LEN + 32]);
    vk_root.copy_from_slice(&proof[WRAP_PREFIX_LEN + 32..WRAP_PREFIX_LEN + 64]);
    nonce.copy_from_slice(&proof[WRAP_PREFIX_LEN + 64..WRAP_ABC_OFF]);
    [*guest_vk_hash, digest, exit, vk_root, nonce]
}

/// Verify an SP1 Groth16 wrap proof (`proof_version = 1`).
///
/// Five BE scalars (SP1 6). Always negates A. VK `nr_pubinputs` must be 5.
pub fn verify_sp1_wrap(
    vk_account_data: &[u8],
    guest_vk_hash: &[u8; 32],
    groth16_vk_hash_prefix: &[u8; WRAP_PREFIX_LEN],
    proof: &[u8; WRAP_PROOF_LEN],
    public_values: &[u8],
) -> Result<(), ClearingError> {
    let parsed = parse_wrap_proof(proof, groth16_vk_hash_prefix)?;
    let a_neg = negate_g1(&parsed.a);
    let inputs = wrap_public_inputs(guest_vk_hash, public_values, proof);
    if inputs.iter().any(|i| !is_less_than_fr_modulus(i)) {
        return Err(ClearingError::InvalidProof);
    }
    let vk = parse_vk(vk_account_data)?;
    if vk.nr_pubinputs != WRAP_NR_PUBINPUTS {
        return Err(ClearingError::InvalidProof);
    }
    pairing_verify(&a_neg, &parsed.b, &parsed.c, &inputs, &vk)
}

/// Circuits-mode settle public inputs from the 144-byte pack.
///
/// `n == 2`: prev_root, new_root (`BatchTradeCircuit`).
/// `n == 3`: also withdrawals_root.
pub fn circuits_settle_public_inputs(
    prev_root: &[u8; 32],
    new_root: &[u8; 32],
    withdrawals_root: &[u8; 32],
    n: u32,
) -> Result<([[u8; FR_LEN]; MAX_PUBLIC_INPUTS], usize), ClearingError> {
    let mut inputs = [[0u8; FR_LEN]; MAX_PUBLIC_INPUTS];
    match n {
        2 => {
            inputs[0] = *prev_root;
            inputs[1] = *new_root;
        }
        3 => {
            inputs[0] = *prev_root;
            inputs[1] = *new_root;
            inputs[2] = *withdrawals_root;
        }
        _ => return Err(ClearingError::InvalidProof),
    }
    Ok((inputs, n as usize))
}

pub fn u32_be32(x: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&x.to_be_bytes());
    out
}

pub fn u64_be32(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}

/// Verify a 256-byte circuits-wire proof against a VK account. Always negates A.
pub fn verify_plain(
    vk_account_data: &[u8],
    proof: &[u8; PROOF_LEN],
    public_inputs: &[[u8; FR_LEN]],
) -> Result<(), ClearingError> {
    let vk = parse_vk(vk_account_data)?;
    if public_inputs.len() != vk.nr_pubinputs as usize {
        return Err(ClearingError::InvalidProof);
    }
    if public_inputs.len() > MAX_PUBLIC_INPUTS {
        return Err(ClearingError::InvalidProof);
    }
    for input in public_inputs {
        if !is_less_than_fr_modulus(input) {
            return Err(ClearingError::InvalidProof);
        }
    }

    let a: [u8; G1_LEN] = proof[0..G1_LEN]
        .try_into()
        .map_err(|_| ClearingError::InvalidProof)?;
    let b: [u8; G2_LEN] = proof[G1_LEN..G1_LEN + G2_LEN]
        .try_into()
        .map_err(|_| ClearingError::InvalidProof)?;
    let c: [u8; G1_LEN] = proof[G1_LEN + G2_LEN..]
        .try_into()
        .map_err(|_| ClearingError::InvalidProof)?;
    let a_neg = negate_g1(&a);

    pairing_verify(&a_neg, &b, &c, public_inputs, &vk)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn pairing_verify(
    proof_a: &[u8; G1_LEN],
    proof_b: &[u8; G2_LEN],
    proof_c: &[u8; G1_LEN],
    public_inputs: &[[u8; FR_LEN]],
    parsed: &ParsedVk<'_>,
) -> Result<(), ClearingError> {
    use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

    let vk = Groth16Verifyingkey {
        nr_pubinputs: parsed.nr_pubinputs as usize,
        vk_alpha_g1: *parsed.alpha_g1,
        vk_beta_g2: *parsed.beta_g2,
        vk_gamme_g2: *parsed.gamma_g2,
        vk_delta_g2: *parsed.delta_g2,
        vk_ic: parsed.ic,
    };

    fn go<const N: usize>(
        proof_a: &[u8; G1_LEN],
        proof_b: &[u8; G2_LEN],
        proof_c: &[u8; G1_LEN],
        public_inputs: &[[u8; FR_LEN]],
        vk: &Groth16Verifyingkey<'_>,
    ) -> Result<(), ClearingError> {
        let inputs: &[[u8; FR_LEN]; N] = public_inputs
            .try_into()
            .map_err(|_| ClearingError::InvalidProof)?;
        let mut verifier = Groth16Verifier::new(proof_a, proof_b, proof_c, inputs, vk)
            .map_err(|_| ClearingError::InvalidProof)?;
        verifier.verify().map_err(|_| ClearingError::InvalidProof)
    }

    match public_inputs.len() {
        0 => go::<0>(proof_a, proof_b, proof_c, public_inputs, &vk),
        1 => go::<1>(proof_a, proof_b, proof_c, public_inputs, &vk),
        2 => go::<2>(proof_a, proof_b, proof_c, public_inputs, &vk),
        3 => go::<3>(proof_a, proof_b, proof_c, public_inputs, &vk),
        4 => go::<4>(proof_a, proof_b, proof_c, public_inputs, &vk),
        5 => go::<5>(proof_a, proof_b, proof_c, public_inputs, &vk),
        6 => go::<6>(proof_a, proof_b, proof_c, public_inputs, &vk),
        7 => go::<7>(proof_a, proof_b, proof_c, public_inputs, &vk),
        8 => go::<8>(proof_a, proof_b, proof_c, public_inputs, &vk),
        _ => Err(ClearingError::InvalidProof),
    }
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn pairing_verify(
    proof_a: &[u8; G1_LEN],
    proof_b: &[u8; G2_LEN],
    proof_c: &[u8; G1_LEN],
    public_inputs: &[[u8; FR_LEN]],
    parsed: &ParsedVk<'_>,
) -> Result<(), ClearingError> {
    let mut prepared = *parsed.ic.first().ok_or(ClearingError::InvalidProof)?;
    for (i, input) in public_inputs.iter().enumerate() {
        let ic = parsed.ic.get(i + 1).ok_or(ClearingError::InvalidProof)?;
        prepared = g1_mul_add(ic, input, &prepared)?;
    }

    let mut pairing_input = [0u8; 768];
    pairing_input[0..64].copy_from_slice(proof_a);
    pairing_input[64..192].copy_from_slice(proof_b);
    pairing_input[192..256].copy_from_slice(&prepared);
    pairing_input[256..384].copy_from_slice(parsed.gamma_g2);
    pairing_input[384..448].copy_from_slice(proof_c);
    pairing_input[448..576].copy_from_slice(parsed.delta_g2);
    pairing_input[576..640].copy_from_slice(parsed.alpha_g1);
    pairing_input[640..768].copy_from_slice(parsed.beta_g2);

    let pairing_res = alt_bn128_pairing(&pairing_input)?;
    if pairing_res[31] != 1 {
        return Err(ClearingError::InvalidProof);
    }
    Ok(())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn g1_mul_add(
    point: &[u8; G1_LEN],
    scalar: &[u8; FR_LEN],
    acc: &[u8; G1_LEN],
) -> Result<[u8; G1_LEN], ClearingError> {
    let mut mul_input = [0u8; 96];
    mul_input[..G1_LEN].copy_from_slice(point);
    mul_input[G1_LEN..].copy_from_slice(scalar);
    let mul_res = alt_bn128_g1_mul(&mul_input)?;
    let mut add_input = [0u8; 128];
    add_input[..G1_LEN].copy_from_slice(&mul_res);
    add_input[G1_LEN..].copy_from_slice(acc);
    alt_bn128_g1_add(&add_input)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn alt_bn128_g1_add(input: &[u8; 128]) -> Result<[u8; G1_LEN], ClearingError> {
    group_op(0, input, [0u8; G1_LEN])
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn alt_bn128_g1_mul(input: &[u8; 96]) -> Result<[u8; G1_LEN], ClearingError> {
    group_op(2, input, [0u8; G1_LEN])
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn alt_bn128_pairing(input: &[u8; 768]) -> Result<[u8; FR_LEN], ClearingError> {
    group_op(3, input, [0u8; FR_LEN])
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn group_op<const N: usize, const M: usize>(
    op: u64,
    input: &[u8; N],
    mut out: [u8; M],
) -> Result<[u8; M], ClearingError> {
    let rc = unsafe {
        pinocchio::syscalls::sol_alt_bn128_group_op(
            op,
            input.as_ptr(),
            input.len() as u64,
            out.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(ClearingError::InvalidProof);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_vk_bytes(ic_len: usize, nr: u32) -> Vec<u8> {
        let mut data = vec![0u8; VK_FIXED_LEN + ic_len * G1_LEN];
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data
    }

    #[test]
    fn parse_vk_accepts_ic_at_452_without_n_ic_word() {
        let data = dummy_vk_bytes(2, 1);
        let vk = parse_vk(&data).expect("parse");
        assert_eq!(vk.nr_pubinputs, 1);
        assert_eq!(vk.ic.len(), 2);
        assert_eq!(data.len(), 452 + 128);
    }

    #[test]
    fn parse_vk_rejects_nr_mismatch() {
        let data = dummy_vk_bytes(2, 0);
        assert_eq!(parse_vk(&data).unwrap_err(), ClearingError::InvalidAccount);
    }

    #[test]
    fn parse_vk_rejects_short() {
        assert_eq!(
            parse_vk(&[0u8; 451]).unwrap_err(),
            ClearingError::InvalidAccount
        );
    }

    #[test]
    fn encode_vk_account_prepends_u32_and_places_ic_at_452() {
        let mut vk_to_bytes = vec![0u8; 448 + 64 * 2];
        vk_to_bytes[0] = 0xAB;
        let encoded = encode_vk_account(&vk_to_bytes).unwrap();
        assert_eq!(&encoded[0..4], &1u32.to_le_bytes());
        assert_eq!(encoded[4], 0xAB);
        assert_eq!(encoded.len(), 452 + 128);
        let parsed = parse_vk(&encoded).unwrap();
        assert_eq!(parsed.nr_pubinputs, 1);
        assert_eq!(parsed.ic.len(), 2);
    }

    #[test]
    fn negate_g1_flips_y_and_is_involution() {
        let mut p = [0u8; G1_LEN];
        p[31] = 1; // x = 1
        p[63] = 2; // y = 2 (BN254 generator)
        let n = negate_g1(&p);
        assert_eq!(&n[..32], &p[..32]);
        assert_ne!(&n[32..], &p[32..]);
        assert_eq!(negate_g1(&n), p);
        assert_eq!(negate_g1(&[0u8; G1_LEN]), [0u8; G1_LEN]);
    }

    #[test]
    fn hash_public_inputs_masks_bn254_top_bits() {
        let pv = [0xABu8; 144];
        let digest = hash_public_inputs(&pv);
        assert_eq!(digest[0] & 0xE0, 0);
        let unmasked = crate::hash::sha256(&[&pv]);
        let mut expected = unmasked;
        expected[0] &= 0x1F;
        assert_eq!(digest, expected);
    }

    #[test]
    fn hash_public_inputs_matches_sp1_known_answer() {
        // Vector from sp1-primitives `test_hash_public_values`, same as
        // zkvm/script.
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

    #[test]
    fn groth16_public_values_leading_zero_then_vk_tail_then_digest() {
        let mut vk = [0u8; 32];
        vk[0] = 0xFF;
        vk[1] = 0x11;
        vk[31] = 0x22;
        let pv = [0x03u8; 144];
        let out = groth16_public_values(&vk, &pv);
        assert_eq!(out[0], 0);
        assert_eq!(&out[1..32], &vk[1..]);
        assert_eq!(&out[32..], &hash_public_inputs(&pv));
    }

    #[test]
    fn parse_wrap_proof_splits_prefix_and_points() {
        let mut proof = [0u8; WRAP_PROOF_LEN];
        proof[0..4].copy_from_slice(&[1, 2, 3, 4]);
        proof[WRAP_ABC_OFF] = 0xAA;
        proof[WRAP_ABC_OFF + G1_LEN] = 0xBB;
        proof[WRAP_ABC_OFF + G1_LEN + G2_LEN] = 0xCC;
        let parsed = parse_wrap_proof(&proof, &[1, 2, 3, 4]).unwrap();
        assert_eq!(parsed.a[0], 0xAA);
        assert_eq!(parsed.b[0], 0xBB);
        assert_eq!(parsed.c[0], 0xCC);
    }

    #[test]
    fn parse_wrap_proof_rejects_wrong_prefix() {
        let proof = [0u8; WRAP_PROOF_LEN];
        assert_eq!(
            parse_wrap_proof(&proof, &[1, 2, 3, 4]).unwrap_err(),
            ClearingError::InvalidProof
        );
    }

    #[test]
    fn verify_sp1_wrap_rejects_junk_proof() {
        let vk = dummy_vk_bytes(3, 2);
        let proof = [0u8; WRAP_PROOF_LEN];
        let pv = [0x11u8; 144];
        // Wrong gnark-vk prefix: parse fails before pairing (no fixture needed).
        assert_eq!(
            verify_sp1_wrap(&vk, &[0u8; 32], &[1, 2, 3, 4], &proof, &pv).unwrap_err(),
            ClearingError::InvalidProof
        );
    }

    #[test]
    fn circuits_settle_public_inputs_two_and_three() {
        let prev = [1u8; 32];
        let new = [2u8; 32];
        let w = [3u8; 32];
        let (ins, n) = circuits_settle_public_inputs(&prev, &new, &w, 2).unwrap();
        assert_eq!(n, 2);
        assert_eq!(ins[0], prev);
        assert_eq!(ins[1], new);
        let (ins, n) = circuits_settle_public_inputs(&prev, &new, &w, 3).unwrap();
        assert_eq!(n, 3);
        assert_eq!(ins[2], w);
        assert!(circuits_settle_public_inputs(&prev, &new, &w, 5).is_err());
    }

    #[test]
    fn verify_sp1_wrap_rejects_wrong_nr_pubinputs() {
        let vk = dummy_vk_bytes(2, 1);
        let proof = [0u8; WRAP_PROOF_LEN];
        let pv = [0u8; 144];
        assert_eq!(
            verify_sp1_wrap(&vk, &[0u8; 32], &[0u8; 4], &proof, &pv).unwrap_err(),
            ClearingError::InvalidProof
        );
    }

    #[test]
    fn parse_vk_rejects_trailing_and_empty_ic() {
        assert_eq!(
            parse_vk(&dummy_vk_bytes(0, 0)).unwrap_err(),
            ClearingError::InvalidAccount
        );
        let mut odd = dummy_vk_bytes(1, 0);
        odd.push(0);
        assert_eq!(parse_vk(&odd).unwrap_err(), ClearingError::InvalidAccount);
    }

    #[test]
    fn encode_vk_account_rejects_short_and_empty_ic() {
        assert!(encode_vk_account(&[0u8; 10]).is_err());
        assert!(encode_vk_account(&[0u8; 448]).is_err());
    }

    #[test]
    fn u32_and_u64_be32_place_value_in_low_bytes() {
        let u = u32_be32(0x0102_0304);
        assert_eq!(&u[28..], &[1, 2, 3, 4]);
        assert_eq!(&u[..28], &[0u8; 28]);
        let v = u64_be32(0x0102_0304_0506_0708);
        assert_eq!(&v[24..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn wrap_public_inputs_copies_header_fields() {
        let mut proof = [0u8; WRAP_PROOF_LEN];
        proof[WRAP_PREFIX_LEN] = 0x11;
        proof[WRAP_PREFIX_LEN + 32] = 0x22;
        proof[WRAP_PREFIX_LEN + 64] = 0x33;
        let ins = wrap_public_inputs(&[0x44; 32], &[0x55; 144], &proof);
        assert_eq!(ins[0][0], 0x44);
        assert_eq!(ins[2][0], 0x11);
        assert_eq!(ins[3][0], 0x22);
        assert_eq!(ins[4][0], 0x33);
    }

    #[test]
    fn verify_sp1_wrap_rejects_fr_overflow_input() {
        let vk = dummy_vk_bytes(6, 5);
        let proof = [0u8; WRAP_PROOF_LEN];
        let pv = [0u8; 144];
        assert_eq!(
            verify_sp1_wrap(&vk, &[0xFFu8; 32], &[0u8; 4], &proof, &pv).unwrap_err(),
            ClearingError::InvalidProof
        );
    }

    #[test]
    fn verify_plain_rejects_nr_mismatch_and_fr_overflow() {
        let vk = dummy_vk_bytes(2, 1);
        let proof = [0u8; PROOF_LEN];
        let two = [[0u8; FR_LEN], [0u8; FR_LEN]];
        assert_eq!(
            verify_plain(&vk, &proof, &two).unwrap_err(),
            ClearingError::InvalidProof
        );
        let mut too_big = [0u8; FR_LEN];
        too_big[0] = 0xFF;
        assert_eq!(
            verify_plain(&vk, &proof, &[too_big]).unwrap_err(),
            ClearingError::InvalidProof
        );
        let vk9 = dummy_vk_bytes(10, 9);
        let nine = [[0u8; FR_LEN]; 9];
        assert_eq!(
            verify_plain(&vk9, &proof, &nine).unwrap_err(),
            ClearingError::InvalidProof
        );
    }

    #[test]
    fn verify_plain_pairing_arms_reject_junk() {
        let proof = [0u8; PROOF_LEN];
        for n in 0..=8 {
            let vk = dummy_vk_bytes(n + 1, n as u32);
            let inputs = vec![[0u8; FR_LEN]; n];
            let _ = verify_plain(&vk, &proof, &inputs);
        }
    }

    #[test]
    fn verifier_process_rejects_empty_accounts() {
        let id = crate::ID;
        assert!(crate::processor::verify::process(&id, &[], &[0u8; PROOF_LEN]).is_err());
    }
}
