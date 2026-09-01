//! Trade-authorization primitives: user **trading keys**, **signed orders**, and
//! the canonical [`Order`] the matcher pairs into a fill.
//!
//! These are the data types and their encodings. Signature *verification* (the
//! ed25519 backend, and the SP1 precompile that accelerates it in the guest)
//! lands in a later phase — see `../docs/zkvm-trade-authentication-plan.md`. Here
//! we only fix the shapes and the byte layout that gets signed / committed, so
//! everything downstream (commitment leaf, order hash) is stable.
//!
//! Threat model recap: matching stays trusted (the backend decides *which* orders
//! pair). The proof enforces only that both users **and** the matcher authorized a
//! fill that respects each order's signed terms, and that no order is over-filled.

use serde::{Deserialize, Serialize};

use crate::id::{AccountId, Amount, MarketId};

/// An ed25519 public key (32-byte compressed point) — a user's registered trading
/// key, committed in their account leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PubKey(pub [u8; 32]);

/// An ed25519 signature, stored as its `R` (32) and `s` (32) halves. Split so it
/// derives serde (which stops at 32-byte arrays) without a big-array helper;
/// [`to_bytes`](Self::to_bytes) / [`from_bytes`](Self::from_bytes) give the wire
/// form the verifier consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Ed25519Signature {
    pub fn from_bytes(sig: [u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        Self { r, s }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }
}

/// Which side of the book an order is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Buy,
    Sell,
}

/// A user's signed authorization to trade, up to `base_amount` at `limit_price`.
///
/// The matcher may fill it partially and repeatedly (across async batches) as long
/// as cumulative fills stay within `base_amount` — tracked per `order_hash` in the
/// committed orders tree (a later phase). `salt` makes the hash unique so two
/// orders with identical terms are distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    pub account: AccountId,
    pub market: MarketId,
    pub side: Side,
    /// Maximum base this order authorizes to trade.
    pub base_amount: Amount,
    /// Buyer: max quote per base it will pay. Seller: min quote per base it will
    /// accept. The fill's implied price must respect both.
    pub limit_price: Amount,
    /// Dead once the committed `batch_height` exceeds this.
    pub expiry: u64,
    /// Client-chosen uniqueness nonce (distinguishes otherwise-identical orders).
    pub salt: u64,
}

/// An [`Order`] plus the signature over it by the account's trading key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrder {
    pub order: Order,
    pub sig: Ed25519Signature,
}

/// The full authorization attached to a matched trade: both parties' signed
/// orders plus the **matcher's** signature over the fill. The proof requires all
/// three (see `../docs/zkvm-trade-authentication-plan.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeAuth {
    pub buy: SignedOrder,
    pub sell: SignedOrder,
    /// Operator/matcher signature over the fill (binds "we produced this match").
    pub matcher_sig: Ed25519Signature,
}

/// Verify an ed25519 signature over `msg`. Uses `verify_strict` (rejects
/// small-order / malleable points). Returns `false` on any malformed key or
/// signature rather than erroring — the caller turns that into a rejection.
///
/// This is the one function the SP1 guest accelerates via the ed25519 precompile
/// (Phase 4); nothing else about the call sites changes.
pub fn verify(pubkey: &Ed25519PubKey, msg: &[u8], sig: &Ed25519Signature) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(&pubkey.0) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig.to_bytes());
    vk.verify_strict(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_round_trip() {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sig = Ed25519Signature::from_bytes(raw);
        assert_eq!(sig.to_bytes(), raw);
    }
}
