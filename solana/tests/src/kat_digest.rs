//! Host known-answer: 144-byte guest public values → SP1 wrap digest.

use clearing_solana_program::instruction::pack_public_values;
use clearing_solana_program::verifier::{groth16_public_values, hash_public_inputs};

#[test]
fn packed_144_byte_public_values_digest_is_stable() {
    let pv = pack_public_values(&[0x11; 32], &[0x22; 32], &[0x33; 32], &[0x44; 32], 7, 0);
    assert_eq!(pv.len(), 144);
    assert_eq!(&pv[128..136], &7u64.to_le_bytes());
    assert_eq!(&pv[136..144], &0u64.to_le_bytes());

    let digest = hash_public_inputs(&pv);
    let expected = [
        0x0e, 0x8f, 0x2b, 0xd8, 0x86, 0x1a, 0xa7, 0x83, 0x1f, 0xdf, 0x54, 0xcf, 0xbc, 0x54, 0x9b,
        0x31, 0x63, 0xa4, 0x15, 0x02, 0xfb, 0x19, 0xce, 0x81, 0x3e, 0xb9, 0xc8, 0x26, 0x7c, 0x2e,
        0x0c, 0xfa,
    ];
    assert_eq!(digest, expected);
    assert_eq!(digest[0] & 0xE0, 0);
}

#[test]
fn groth16_public_values_are_two_be_scalars() {
    let pv = pack_public_values(&[0x11; 32], &[0x22; 32], &[0x33; 32], &[0x44; 32], 7, 0);
    let mut vk = [0u8; 32];
    vk[0] = 0xFF;
    vk[31] = 0xAB;
    let outer = groth16_public_values(&vk, &pv);
    assert_eq!(outer[0], 0);
    assert_eq!(&outer[1..32], &vk[1..]);
    assert_eq!(&outer[32..], &hash_public_inputs(&pv));
}
