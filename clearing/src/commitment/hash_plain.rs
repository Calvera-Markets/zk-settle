//! The v0 default [`Hasher`]: SHA-256 with leaf/node domain separation.
//!
//! Plain and audited, chosen so the commitment is easy to reason about while
//! the rest of the layer matures. It is **not** SNARK-friendly — a `poseidon2`
//! implementation of the same [`Hasher`] trait swaps in later with zero
//! call-site changes (the whole point of the trait seam).

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
