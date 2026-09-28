//! Default [`Hasher`]: SHA-256 with leaf/node domain separation.
//!
//! Leaf preimages are tagged `0x00`, internal nodes `0x01`. Another hasher
//! (see `poseidon2`) implements the same trait.

use sha2::{Digest, Sha256};

use super::{Hash, Hasher};

/// SHA-256 commitment hasher. Stateless unit struct.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash_leaf(&self, data: &[u8]) -> Hash {
        // Domain tag 0x00 distinguishes leaves from internal nodes, closing the
        // standard Merkle second-preimage gap.
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    fn hash_node(&self, left: &Hash, right: &Hash) -> Hash {
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}
