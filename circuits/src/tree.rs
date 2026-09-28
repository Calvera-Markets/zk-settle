//! Dense BN254-Poseidon Merkle tree used to build circuit witnesses.
//!
//! Same role as `clearing::StateTree`, but over `Fr` leaves and
//! [`hash2`](crate::hash2), so roots and paths match `merkle_root_gadget`.
//! Every index is populated (`2^DEPTH` leaves). [`MerkleTree::updated`]
//! produces chained `prev → mid → new` roots for a two-account trade.

use crate::{hash2, DEPTH};
use ark_bn254::Fr;

/// A full (dense) Merkle tree over `Fr` using [`hash2`].
#[derive(Clone)]
pub struct MerkleTree {
    leaves: Vec<Fr>,
}

impl MerkleTree {
    /// Build a tree from exactly `2^DEPTH` leaves.
    pub fn new(leaves: Vec<Fr>) -> Self {
        assert_eq!(leaves.len(), 1 << DEPTH, "need exactly 2^DEPTH leaves");
        Self { leaves }
    }

    /// All tree levels, leaves first, root last.
    fn levels(&self) -> Vec<Vec<Fr>> {
        let mut levels = vec![self.leaves.clone()];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|c| hash2(c[0], c[1]))
                .collect();
            levels.push(next);
        }
        levels
    }

    /// The Merkle root.
    pub fn root(&self) -> Fr {
        *self.levels().last().unwrap().first().unwrap()
    }

    /// Sibling list (leaf→root) and direction bits (`true` = our node is the right
    /// child at that level), matching `merkle_root_gadget` / the circuits.
    pub fn path(&self, index: usize) -> (Vec<Fr>, Vec<bool>) {
        let levels = self.levels();
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut bits = Vec::with_capacity(DEPTH);
        let mut idx = index;
        for level in levels.iter().take(DEPTH) {
            siblings.push(level[idx ^ 1]);
            bits.push(idx & 1 == 1);
            idx >>= 1;
        }
        (siblings, bits)
    }

    /// Update tree with new leaf
    pub fn update(&mut self, index: usize, new_leaf: Fr) {
        self.leaves[index] = new_leaf;
    }
}
