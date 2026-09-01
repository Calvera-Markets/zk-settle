//! A Poseidon2 [`Hasher`] — the second hash implementation, behind the
//! `poseidon2` feature.
//!
//! This exists to demonstrate that the hash layer is a **linear seam**: the
//! whole stack is generic over `H: Hasher`, so swapping the hash is a new impl
//! and a type parameter — nothing structural changes. `Sha256Hasher` stays the
//! default; `Poseidon2Hasher` is opt-in (e.g. to compare zkVM proving cost).
//!
//! ## Honesty notes
//!
//! - This is a **self-contained, structurally-faithful Poseidon2** over the
//!   BabyBear field (width 16, x^7 S-box, 8 external + 13 internal rounds, the
//!   efficient M4-block external layer and sum+diagonal internal layer). The
//!   **round constants and internal diagonal are generated deterministically
//!   here, not taken from an audited reference** — so it is correct as a
//!   permutation-shaped, deterministic hash and gives a representative *cost*
//!   profile, but it is **not** a spec-compliant, audited Poseidon2. A
//!   production version uses the published constants (and ideally a precompile).
//! - SP1 exposes no user-facing Poseidon2 precompile (unlike sha2), so in the
//!   zkVM this runs as *software* — the point of the comparison.

use super::{Hash, Hasher};

/// BabyBear prime: 2^31 - 2^27 + 1.
const P: u64 = 0x7800_0001;
const WIDTH: usize = 16;
const RATE: usize = 8;
const EXTERNAL_ROUNDS: usize = 8; // RF, split 4 + 4
const INTERNAL_ROUNDS: usize = 13; // RP

#[inline]
fn add(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % P) as u32
}
#[inline]
fn mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P) as u32
}
/// S-box x^7.
#[inline]
fn sbox(x: u32) -> u32 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    let x6 = mul(x4, x2);
    mul(x6, x)
}

/// Deterministic round constant (see honesty note — not an audited constant).
#[inline]
fn rc(round: usize, i: usize) -> u32 {
    let v = (round as u64)
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add((i as u64).wrapping_mul(0x85EB_CA77))
        .wrapping_add(1);
    (v % P) as u32
}

/// Deterministic internal diagonal (small distinct nonzero values).
#[inline]
fn diag(i: usize) -> u32 {
    (i as u32) + 2
}

/// Poseidon2 efficient 4-element MDS (the documented M4).
#[inline]
fn m4(s: &mut [u32]) {
    let t0 = add(s[0], s[1]);
    let t1 = add(s[2], s[3]);
    let t2 = add(mul(2, s[1]), t1);
    let t3 = add(mul(2, s[3]), t0);
    let t4 = add(mul(4, t1), t3);
    let t5 = add(mul(4, t0), t2);
    let t6 = add(t3, t5);
    let t7 = add(t2, t4);
    s[0] = t6;
    s[1] = t5;
    s[2] = t7;
    s[3] = t4;
}

/// External linear layer: M4 on each block of 4, then add the per-position
/// block sums.
fn external_matmul(state: &mut [u32; WIDTH]) {
    for block in state.chunks_mut(4) {
        m4(block);
    }
    let mut sums = [0u32; 4];
    for (i, &x) in state.iter().enumerate() {
        sums[i % 4] = add(sums[i % 4], x);
    }
    for (i, x) in state.iter_mut().enumerate() {
        *x = add(*x, sums[i % 4]);
    }
}

/// Internal linear layer: new[i] = sum(state) + diag[i] * state[i].
fn internal_matmul(state: &mut [u32; WIDTH]) {
    let mut sum = 0u32;
    for &x in state.iter() {
        sum = add(sum, x);
    }
    for (i, x) in state.iter_mut().enumerate() {
        *x = add(mul(*x, diag(i)), sum);
    }
}

fn permute(state: &mut [u32; WIDTH]) {
    external_matmul(state);
    let mut round = 0;
    for _ in 0..EXTERNAL_ROUNDS / 2 {
        for (i, x) in state.iter_mut().enumerate() {
            *x = sbox(add(*x, rc(round, i)));
        }
        external_matmul(state);
        round += 1;
    }
    for _ in 0..INTERNAL_ROUNDS {
        state[0] = sbox(add(state[0], rc(round, 0)));
        internal_matmul(state);
        round += 1;
    }
    for _ in 0..EXTERNAL_ROUNDS / 2 {
        for (i, x) in state.iter_mut().enumerate() {
            *x = sbox(add(*x, rc(round, i)));
        }
        external_matmul(state);
        round += 1;
    }
}

/// Sponge hash of `data` with a domain tag, squeezing 8 field elements (32 B).
fn hash_bytes(domain: u8, data: &[u8]) -> Hash {
    // Pack into field elements: domain, length, then 4-byte little-endian chunks
    // reduced mod P.
    let mut elems = Vec::with_capacity(2 + data.len() / 4 + 1);
    elems.push(domain as u32);
    elems.push((data.len() as u64 % P) as u32);
    for chunk in data.chunks(4) {
        let mut b = [0u8; 4];
        b[..chunk.len()].copy_from_slice(chunk);
        elems.push(((u32::from_le_bytes(b) as u64) % P) as u32);
    }

    let mut state = [0u32; WIDTH];
    for chunk in elems.chunks(RATE) {
        for (i, &e) in chunk.iter().enumerate() {
            state[i] = add(state[i], e);
        }
        permute(&mut state);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Poseidon2 commitment hasher. Stateless unit struct (params are constants).
#[derive(Debug, Clone, Copy, Default)]
pub struct Poseidon2Hasher;

impl Hasher for Poseidon2Hasher {
    fn hash_leaf(&self, data: &[u8]) -> Hash {
        hash_bytes(0x00, data)
    }
    fn hash_node(&self, left: &Hash, right: &Hash) -> Hash {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        hash_bytes(0x01, &buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{AccountId, Amount, AssetId, InstrumentId, MarketId};
    use crate::instrument::{Instrument, SettlementKind};
    use crate::settlement::Fill;
    use crate::{ExecutingProver, Prover, State, StateTree, Tx, Witness};
    use uuid::Uuid;

    #[test]
    fn deterministic_and_input_sensitive() {
        let h = Poseidon2Hasher;
        assert_eq!(h.hash_leaf(b"abc"), h.hash_leaf(b"abc"));
        assert_ne!(h.hash_leaf(b"abc"), h.hash_leaf(b"abd"));
        // leaf vs node domain separation
        let z = [0u8; 32];
        assert_ne!(h.hash_leaf(&z), h.hash_node(&z, &z));
    }

    #[test]
    fn poseidon2_drives_the_whole_stack_like_sha2() {
        // The seam is linear: identical generic code, different `H`. A batch
        // captured + verified with Poseidon2Hasher works exactly as with sha2.
        let usdc = AssetId(0);
        let btc = AssetId(1);
        let buyer = AccountId(Uuid::from_u128(0xB));
        let seller = AccountId(Uuid::from_u128(0x5));
        let market = MarketId(Uuid::from_u128(0xA1));

        let mut s = State::new();
        s.register_market(
            market,
            Instrument {
                id: InstrumentId(1),
                kind: SettlementKind::SpotSwap,
                base: btc,
                quote: usdc,
                base_scale: 8,
                quote_scale: 6,
            },
        );
        let mut t = StateTree::new(Poseidon2Hasher);
        let batch = vec![
            Tx::Deposit { account: buyer, asset: usdc, amount: Amount(1000), nonce: 0, trading_key: None },
            Tx::Deposit { account: seller, asset: btc, amount: Amount(5), nonce: 1, trading_key: None },
            Tx::Trade {
                market,
                fill: Fill { buyer, seller, base_amount: Amount(2), quote_amount: Amount(400) },
                auth: None,
            },
            Tx::Withdraw { account: buyer, asset: usdc, amount: Amount(100) },
        ];
        let w = Witness::capture(&mut s, &mut t, &batch);
        // rebuild cross-check + executing verification, all under Poseidon2
        let rebuilt = StateTree::from_state(Poseidon2Hasher, &s);
        assert_eq!(w.new_root, rebuilt.root());
        ExecutingProver::new(Poseidon2Hasher).prove(&w).unwrap();
        assert_eq!(w.messages.len(), 1);
    }
}
