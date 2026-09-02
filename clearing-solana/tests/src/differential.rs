//! Host differential: program withdrawal hashing matches `clearing::commitment`.

use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::commitment::{self, withdrawal_proof, withdrawals_root, Hasher};
use clearing::id::{Amount, AssetId, L1Address};
use clearing_solana_program::hash as prog;

#[test]
fn withdrawal_encoding_matches_clearing() {
    let owner = L1Address([9u8; 32]);
    let asset = AssetId(0);
    let amount = Amount(1_000);
    let batch_seq = 3u64;
    let index = 1u32;

    let native = commitment::encode_withdrawal(batch_seq, index, owner, asset, amount);
    let onchain =
        prog::encode_withdrawal(batch_seq, index, &owner.0, asset.0, &amount.to_le_bytes());
    assert_eq!(native.as_slice(), &onchain);

    let h = Sha256Hasher;
    let native_leaf = h.hash_leaf(&native);
    let onchain_leaf =
        prog::withdrawal_leaf(batch_seq, index, &owner.0, asset.0, &amount.to_le_bytes());
    assert_eq!(native_leaf, onchain_leaf);
}

#[test]
fn withdrawals_root_and_proof_match_clearing() {
    let h = Sha256Hasher;
    let owner = L1Address([0xABu8; 32]);
    let entries = [(owner, AssetId(0), Amount(42))];
    let root = withdrawals_root(&h, 0, &entries);
    let siblings = withdrawal_proof(&h, 0, &entries, 0);

    let amt = Amount(42).to_le_bytes();
    assert!(prog::verify_withdrawal(
        &root, 0, 0, &owner.0, 0, &amt, &siblings,
    ));
    assert_eq!(
        prog::withdrawal_leaf(0, 0, &owner.0, 0, &amt),
        h.hash_leaf(&commitment::encode_withdrawal(
            0,
            0,
            owner,
            AssetId(0),
            Amount(42)
        ))
    );
    assert!(!prog::verify_withdrawal(
        &root,
        0,
        0,
        &owner.0,
        0,
        &1i128.to_le_bytes(),
        &siblings,
    ));
}
