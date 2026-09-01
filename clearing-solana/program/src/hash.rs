//! SHA-256 commitment hashing: leaf domain 0x00, node 0x01, DA domain 0x02.
//!
//! Sparse Merkle helpers match `clearing::commitment` (`hash_plain::Sha256Hasher`,
//! `root_from_path`, `default_hashes`). Empty-subtree defaults are folded
//! incrementally so the 129-hash table never sits on the SBF stack.

/// Tree depth = bits in an `AccountId` (UUID is 128-bit).
pub const DEPTH: u8 = 128;

pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    sha256(&[&[0x00], data])
}

pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[0x01], left, right])
}

/// Fold `leaf` up a sparse sibling path. `key` is `AccountId` as `u128`
/// (UUID big-endian, same as `Uuid::as_u128`). Omitted siblings (mask bit
/// clear) use the level default; a mask that claims more siblings than
/// provided fills from the default (wrong root, not a panic).
pub fn root_from_path(
    key: u128,
    leaf: [u8; 32],
    sibling_mask: u128,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut node = leaf;
    let mut index = key;
    let mut next = 0usize;
    let mut default = hash_leaf(&[]);
    for step in 0..DEPTH {
        let sib = if (sibling_mask >> step) & 1 == 1 {
            let s = siblings.get(next).copied().unwrap_or(default);
            next += 1;
            s
        } else {
            default
        };
        node = if index & 1 == 0 {
            hash_node(&node, &sib)
        } else {
            hash_node(&sib, &node)
        };
        index >>= 1;
        default = hash_node(&default, &default);
    }
    node
}

/// `SHA-256(0x02 ‖ u32_le(payload_len) ‖ payload)`. Clients/tests only;
/// the program does not recompute `da_hash` from a blob.
pub fn hash_da(payload: &[u8]) -> [u8; 32] {
    let len = (payload.len() as u32).to_le_bytes();
    sha256(&[&[0x02], &len, payload])
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut out = [0u8; 32];
        unsafe {
            pinocchio::syscalls::sol_sha256(
                parts.as_ptr() as *const u8,
                parts.len() as u64,
                out.as_mut_ptr(),
            );
        }
        out
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_node_domain_tags_differ() {
        let leaf = hash_leaf(&[1, 2, 3]);
        let node = hash_node(&[0u8; 32], &[0u8; 32]);
        assert_ne!(leaf, node);
        assert_ne!(leaf, [0u8; 32]);
    }

    #[test]
    fn root_from_path_key_zero_is_always_left() {
        let leaf = hash_leaf(&[4, 1, 2, 3]);
        let root = root_from_path(0, leaf, 0, &[]);
        let mut node = leaf;
        let mut default = hash_leaf(&[]);
        for _ in 0..DEPTH {
            node = hash_node(&node, &default);
            default = hash_node(&default, &default);
        }
        assert_eq!(root, node);
    }

    #[test]
    fn root_from_path_two_adjacent_leaves() {
        let left = hash_leaf(&[1]);
        let right = hash_leaf(&[2]);
        let parent = hash_node(&left, &right);
        let mask = 1u128;
        let from_left = root_from_path(0, left, mask, &[right]);
        let from_right = root_from_path(1, right, mask, &[left]);
        assert_eq!(from_left, from_right);

        let mut node = parent;
        let mut default = hash_leaf(&[]);
        default = hash_node(&default, &default);
        for _ in 1..DEPTH {
            node = hash_node(&node, &default);
            default = hash_node(&default, &default);
        }
        assert_eq!(from_left, node);
    }
}
