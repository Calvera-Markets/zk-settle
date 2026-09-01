use clearing::account::Account;
use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::commitment::{canonical_encode, default_hashes, root_from_path, Hasher, StateTree};
use clearing::id::{AccountId, Amount, AssetId, L1Address};
use clearing_solana_program::hash;
use uuid::Uuid;

fn acct(n: u128) -> AccountId {
    AccountId(Uuid::from_u128(n))
}

fn owner(n: u8) -> L1Address {
    L1Address([n; 32])
}

#[test]
fn hash_leaf_and_node_match_clearing_sha256() {
    let hasher = Sha256Hasher;
    assert_eq!(hash::hash_leaf(&[1, 2, 3]), hasher.hash_leaf(&[1, 2, 3]));
    assert_eq!(hash::hash_leaf(&[]), hasher.hash_leaf(&[]));
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    assert_eq!(hash::hash_node(&a, &b), hasher.hash_node(&a, &b));
}

#[test]
fn root_from_path_matches_clearing_sparse_tree() {
    let hasher = Sha256Hasher;
    let mut account = Account::new();
    account.credit(AssetId(0), Amount(1000)).unwrap();
    account.set_l1_owner(owner(7)).unwrap();

    let mut tree = StateTree::new(hasher);
    tree.update_account(acct(0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B), Some(&account));
    for i in 0..24u32 {
        let mut other = Account::new();
        other.credit(AssetId(0), Amount(1)).unwrap();
        other.set_l1_owner(owner(0xFF)).unwrap();
        let id = 0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0Bu128 ^ (1u128 << i);
        tree.update_account(acct(id), Some(&other));
    }

    let key = 0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0Bu128;
    let (mask, sibs) = tree.prove(acct(key));
    assert_eq!(sibs.len(), 24);

    let encoded = canonical_encode(&account);
    assert_eq!(encoded[0], 4);
    let leaf = hasher.hash_leaf(&encoded);
    assert_eq!(hash::hash_leaf(&encoded), leaf);

    let defaults = default_hashes(&hasher);
    let expected = root_from_path(&hasher, &defaults, key, leaf, mask, &sibs);
    let got = hash::root_from_path(key, leaf, mask, &sibs);
    assert_eq!(got, expected);
    assert_eq!(got, tree.root());
}
