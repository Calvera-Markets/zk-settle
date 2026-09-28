//! Convert SP1 gnark `groth16_vk.bin` into a groth16-solana VK account.
//! Copied from sp1-verifier `groth16/ark_converter.rs` (decompress only).

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use clearing_circuits::solana::vk_to_bytes;
use clearing_solana_program::verifier::encode_vk_account;

const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;
const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSITIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let reversed: [_; ARRAY_SIZE] = bytes
        .chunks_exact(CHUNK_SIZE)
        .flat_map(|chunk| chunk.iter().rev().copied())
        .enumerate()
        .fold([0u8; ARRAY_SIZE], |mut acc, (i, v)| {
            acc[i] = v;
            acc
        });
    reversed
}

fn gnark_flag_to_ark_flag(msb: u8) -> Option<u8> {
    let ark_flag = match msb & GNARK_MASK {
        GNARK_COMPRESSED_POSITIVE => ARK_COMPRESSED_POSITIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => return None,
    };
    Some(msb & !ARK_MASK | ark_flag)
}

fn gnark_compressed_x_to_ark_compressed_x(x: &[u8]) -> Option<Vec<u8>> {
    if x.len() != 32 && x.len() != 64 {
        return None;
    }
    let mut x_copy = x.to_vec();
    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;
    x_copy.reverse();
    Some(x_copy)
}

fn decompress_g1(g1_bytes: &[u8; 32]) -> Option<G1Affine> {
    let g1_bytes = gnark_compressed_x_to_ark_compressed_x(g1_bytes)?;
    let g1_bytes: [u8; 32] = g1_bytes.try_into().ok()?;
    let g1_bytes = convert_endianness::<32, 32>(&g1_bytes);
    G1Affine::deserialize_with_mode(
        convert_endianness::<32, 32>(&g1_bytes).as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .ok()
}

fn decompress_g2(g2_bytes: &[u8; 64]) -> Option<G2Affine> {
    let g2_bytes = gnark_compressed_x_to_ark_compressed_x(g2_bytes)?;
    let g2_bytes: [u8; 64] = g2_bytes.try_into().ok()?;
    let g2_bytes = convert_endianness::<64, 64>(&g2_bytes);
    G2Affine::deserialize_with_mode(
        convert_endianness::<64, 64>(&g2_bytes).as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .ok()
}

pub fn gnark_vk_to_account(buffer: &[u8]) -> Option<Vec<u8>> {
    if buffer.len() < 292 {
        return None;
    }
    let alpha_g1 = decompress_g1(buffer[..32].try_into().ok()?)?;
    let beta_g2 = decompress_g2(buffer[64..128].try_into().ok()?)?;
    let gamma_g2 = decompress_g2(buffer[128..192].try_into().ok()?)?;
    let delta_g2 = decompress_g2(buffer[224..288].try_into().ok()?)?;
    let num_k = u32::from_be_bytes(buffer[288..292].try_into().ok()?);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        if offset + 32 > buffer.len() {
            return None;
        }
        k.push(decompress_g1(buffer[offset..offset + 32].try_into().ok()?)?);
        offset += 32;
    }
    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: k,
    };
    encode_vk_account(&vk_to_bytes(&vk)).ok()
}
