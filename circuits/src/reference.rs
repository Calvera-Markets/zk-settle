//! Integer reference for the spot-swap rule the circuits enforce.
//! Circuit satisfiability must match [`TradeScenario::accepts`].
//!
//! ## Correspondence to `clearing`
//!
//! The on-chain settlement rule lives in `clearing::settlement::SpotSwap`
//! (`../clearing/src/settlement/spot_swap.rs`): *seller gives base, buyer pays
//! quote; debit the giving side first so an unaffordable leg aborts before any
//! credit.* The validity statement that wraps it is `clearing::ExecutingProver`
//! (`../clearing/src/prover.rs`): reconstruct each touched account's prior leaf
//! from claimed contents, check it against the committed `prev_root`, re-execute
//! the batch, and confirm the result reproduces each committed `new_leaf`.
//!
//! `trade_step_gadget` is exactly that logic, specialised to a spot-swap trade
//! and expressed as BN254 constraints: reconstruct the buyer/seller leaf from
//! claimed balances → fold to the running root → apply the `SpotSwap` deltas →
//! fold the new leaves to the next root, with range checks standing in for "the
//! giving side can afford its leg / the receiving side does not overflow."
//!
//! ### Known, deliberate divergence
//!
//! `clearing::SpotSwap` additionally rejects a **non-positive** (zero/negative)
//! fill (`SettlementError::NonPositiveQuantity`). The trade circuit does **not**
//! constrain amounts to be non-zero — a zero-amount trade is a no-op that changes
//! no balance and no root, so it is harmless to *validity*; positivity is a
//! matching-layer concern enforced upstream, not a settlement-soundness one. This
//! reference therefore models the circuit's actual rule (zero amounts accepted);
//! see `nonzero_amounts_are_the_only_divergence_from_clearing` in the tests.
//!
//! ### Representation gap (the dual-implementation tax)
//!
//! The circuit commits state in a **dense BN254-Poseidon** Merkle tree; `clearing`
//! commits in a **sparse, UUID-keyed, depth-128 Sha256/Poseidon2-BabyBear** tree.
//! Making the two *bit-identical* (so one proof verifies the other's exact root)
//! means rebuilding `clearing`'s commitment in BN254-Poseidon — a larger
//! reconciliation than this slice. What we can and do verify here is that the
//! circuit enforces the *same settlement rule* as the Rust spec, exhaustively
//! fuzzed.

/// One trade's raw scenario: both parties' pre-trade balances and the traded
/// amounts, in integer (`u64`) units — the same units the circuit range-checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeScenario {
    pub buyer_base: u64,
    pub buyer_quote: u64,
    pub seller_base: u64,
    pub seller_quote: u64,
    pub base_amount: u64,
    pub quote_amount: u64,
}

impl TradeScenario {
    /// Does the settlement rule accept this trade?
    ///
    /// Mirrors `clearing::SpotSwap` (minus the upstream positivity check, see the
    /// module docs): the buyer must afford the quote it pays and the seller the
    /// base it gives, and neither receiving side may overflow `u64` (the circuit's
    /// `enforce_u64` on the *post-trade* balances).
    pub fn accepts(&self) -> bool {
        let buyer_can_pay = self.buyer_quote >= self.quote_amount;
        let seller_can_give = self.seller_base >= self.base_amount;
        let buyer_base_ok = self.buyer_base.checked_add(self.base_amount).is_some();
        let seller_quote_ok = self.seller_quote.checked_add(self.quote_amount).is_some();
        buyer_can_pay && seller_can_give && buyer_base_ok && seller_quote_ok
    }

    /// Post-trade balances `((buyer_base, buyer_quote), (seller_base, seller_quote))`.
    /// Only meaningful when [`accepts`](Self::accepts) — panics on under/overflow
    /// otherwise, which is the point: a rejected trade has no valid settlement.
    pub fn settle(&self) -> ((u64, u64), (u64, u64)) {
        let buyer = (
            self.buyer_base + self.base_amount,
            self.buyer_quote - self.quote_amount,
        );
        let seller = (
            self.seller_base - self.base_amount,
            self.seller_quote + self.quote_amount,
        );
        (buyer, seller)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_matches_accepts() {
        let ok = TradeScenario {
            buyer_base: 0,
            buyer_quote: 10,
            seller_base: 5,
            seller_quote: 0,
            base_amount: 2,
            quote_amount: 4,
        };
        assert!(ok.accepts());
        assert_eq!(ok.settle(), ((2, 6), (3, 4)));
        let bad = TradeScenario {
            quote_amount: 99,
            ..ok
        };
        assert!(!bad.accepts());
    }
}
