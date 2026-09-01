//! The prover / witness seam.
//!
//! A [`Witness`] captures everything needed to verify a state transition
//! `prev_root → new_root` over a batch of transactions **by Merkle paths alone**
//! — the per-leaf updates the batch produced, each with the sibling path valid
//! at the moment it was written (see [`crate::commitment::LeafUpdate`]). A
//! [`Prover`] turns that into a [`Proof`].
//!
//! v0 ships [`ReplayProver`], a **stub**: it re-derives `prev_root` and
//! `new_root` from the witnessed paths and accepts iff they chain correctly. It
//! deliberately does **not** prove the *execution* half — that each `new_leaf`
//! is the correct result of applying the transactions to the prior account
//! (that is deterministic and replayable, per
//! `../docs/zk-validity-feasibility.md` §6). A real backend implements the same
//! [`Prover`] trait, consuming the same [`Witness`], and additionally enforces
//! execution in-circuit. The seam — `Prover` + `Witness` + per-leaf paths — does
//! not change when that backend lands.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use uuid::Uuid;

use crate::account::Account;
use crate::auth::Ed25519PubKey;
use crate::commitment::{
    Hash, Hasher, LeafUpdate, StateTree, default_hashes, leaf_hash, root_from_path,
};
use crate::id::{AccountId, MarketId};
use crate::instrument::Instrument;
use crate::state::State;
use crate::tx::{OnChainMessage, Tx};

/// A self-contained statement of one batch transition — everything a verifier
/// (the [`ReplayProver`] Merkle check, the [`ExecutingProver`] re-execution, and
/// eventually a zkVM guest) needs to confirm `prev_root → new_root` is the
/// correct result of executing `txs`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Witness {
    pub prev_root: Hash,
    pub new_root: Hash,
    /// Per-leaf Merkle updates, in the order applied. Empty for a batch in which
    /// every transaction was rejected (then `prev_root == new_root`).
    pub updates: Vec<LeafUpdate>,
    /// The batch being proven.
    pub txs: Vec<Tx>,
    /// Prior contents of every account the batch could touch (`None` = it did
    /// not exist), captured *before* the batch — enough to re-execute in
    /// isolation.
    pub prev_accounts: Vec<(AccountId, Option<Account>)>,
    /// Market descriptors the batch's trades reference (to re-execute settlement).
    pub instruments: Vec<(MarketId, Instrument)>,
    /// On-chain messages the batch emits — the withdrawal payouts. These are the
    /// proven outputs the contract acts on (one per applied [`Tx::Withdraw`]).
    pub messages: Vec<OnChainMessage>,
}

impl Witness {
    /// Apply a batch to `(state, tree)` and capture the full self-contained
    /// witness for the resulting transition: the Merkle updates, the prior
    /// contents of touched accounts, the referenced instruments, and the emitted
    /// messages. Rejected transactions contribute nothing (state/tree untouched).
    pub fn capture<H: Hasher>(state: &mut State, tree: &mut StateTree<H>, txs: &[Tx]) -> Witness {
        let prev_root = tree.root();

        // Snapshot prior contents of every account the batch may touch, before
        // applying anything (so it is the batch's *prior* state, not mid-batch).
        let touched: BTreeSet<AccountId> = txs.iter().flat_map(|t| t.touched_accounts()).collect();
        let prev_accounts: Vec<(AccountId, Option<Account>)> = touched
            .iter()
            .map(|id| (*id, state.account(*id).cloned()))
            .collect();

        // Instruments referenced by the batch's trades.
        let mut seen_markets = BTreeSet::new();
        let mut instruments = Vec::new();
        for tx in txs {
            let Tx::Trade { market, .. } = tx else {
                continue;
            };
            if !seen_markets.insert(*market) {
                continue;
            }
            if let Some(inst) = state.instrument(*market) {
                instruments.push((*market, inst.clone()));
            }
        }

        let mut updates = Vec::new();
        let mut messages = Vec::new();
        for tx in txs {
            // Owner is read before apply: a full withdraw prunes the account
            // (`is_empty` ignores owner), so the post-apply account may be gone.
            let withdraw_owner = match tx {
                Tx::Withdraw { account, .. } => state.account(*account).and_then(|a| a.l1_owner()),
                _ => None,
            };
            if let Ok(delta) = state.apply(tx) {
                updates.extend(tree.apply_delta_proved(state, &delta));
                if let Tx::Withdraw { asset, amount, .. } = tx {
                    // Apply rejects ownerless withdraws; a successful debit
                    // therefore had a bound owner (read pre-apply, before prune).
                    debug_assert!(
                        withdraw_owner.is_some(),
                        "withdraw of an account with no owner cannot apply"
                    );
                    if let Some(owner) = withdraw_owner {
                        messages.push(OnChainMessage::Withdraw {
                            owner,
                            asset: *asset,
                            amount: *amount,
                        });
                    }
                }
            }
        }

        Witness {
            prev_root,
            new_root: tree.root(),
            updates,
            txs: txs.to_vec(),
            prev_accounts,
            instruments,
            messages,
        }
    }
}

/// Verify the Merkle half of a witness: the per-leaf updates chain
/// `prev_root → new_root`. Shared by both provers.
fn verify_chain<H: Hasher>(hasher: &H, witness: &Witness) -> Result<(), ProveError> {
    let defaults = default_hashes(hasher); // computed once; fills sparse-proof gaps
    let mut current = witness.prev_root;
    for (index, u) in witness.updates.iter().enumerate() {
        if root_from_path(
            hasher,
            &defaults,
            u.key,
            u.prev_leaf,
            u.sibling_mask,
            &u.siblings,
        ) != current
        {
            return Err(ProveError::ChainBroken { index });
        }
        current = root_from_path(
            hasher,
            &defaults,
            u.key,
            u.new_leaf,
            u.sibling_mask,
            &u.siblings,
        );
    }
    if current != witness.new_root {
        return Err(ProveError::NewRootMismatch);
    }
    Ok(())
}

/// A validity proof for a batch transition. Opaque marker in v0 (the stub's
/// "proof" is the successful path check); a real backend carries the SNARK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    _private: (),
}

/// Why a witness failed to verify.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProveError {
    /// An update's `prev_leaf` + path did not hash to the running root — the
    /// witness is inconsistent with the prior committed state.
    #[error("witness chain broken at update {index}")]
    ChainBroken { index: usize },

    /// The chained updates did not arrive at the claimed `new_root`.
    #[error("final root mismatch")]
    NewRootMismatch,

    /// A claimed prior account does not hash to the `prev_leaf` committed in
    /// `prev_root` — the witness lies about the starting state.
    #[error("prior state does not match the committed prev_leaf at key {key}")]
    PrevStateMismatch { key: u128 },

    /// Re-executing the batch produced a different leaf than the committed
    /// `new_leaf` — the claimed transition is not the rules' result.
    #[error("execution result does not match committed new_leaf at key {key}")]
    ExecutionMismatch { key: u128 },

    /// Re-executing the batch produced different on-chain messages than claimed.
    #[error("execution produced different on-chain messages than claimed")]
    MessageMismatch,
}

/// Produces a [`Proof`] for a [`Witness`].
pub trait Prover {
    fn prove(&self, witness: &Witness) -> Result<Proof, ProveError>;
}

/// The v0 stub prover: verifies the transition by re-deriving each intermediate
/// root from the witnessed leaf paths (it "replays" the leaf writes through
/// their Merkle paths). No SNARK, no execution check — see the module docs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplayProver<H: Hasher> {
    hasher: H,
}

impl<H: Hasher> ReplayProver<H> {
    pub fn new(hasher: H) -> Self {
        Self { hasher }
    }
}

impl<H: Hasher> Prover for ReplayProver<H> {
    fn prove(&self, witness: &Witness) -> Result<Proof, ProveError> {
        verify_chain(&self.hasher, witness)?;
        Ok(Proof { _private: () })
    }
}

/// The executing verifier — the **real correctness** of the keystone, in pure
/// Rust (and the exact body a zkVM guest runs).
///
/// On top of the Merkle chain check, it **re-executes the batch** from the
/// witnessed prior account contents and confirms the result *is* the committed
/// transition:
///
/// 1. the claimed `prev_accounts` hash to the `prev_leaf`s committed in
///    `prev_root` (the witness does not lie about the starting state);
/// 2. re-running `txs` over those accounts (via [`State::for_replay`]) yields
///    contents whose leaves equal the committed `new_leaf`s — binding execution
///    to the new root;
/// 3. re-execution emits exactly the claimed `messages` — binding the withdrawal
///    payouts to a real debit.
///
/// Together these close the gap [`ReplayProver`] leaves open: a Merkle-valid but
/// execution-invalid batch (wrong fills, or an unbacked withdrawal message) is
/// rejected. A real SNARK wraps this same logic so the contract can trust it
/// without re-executing.
///
/// **Trade authorization** rides along for free: because it re-executes each
/// trade via `State::apply`, it re-verifies the maker/taker/matcher signatures
/// and the over-fill accounting. The `operator_key` and `batch_height` it checks
/// against are **verifier configuration** carried here — not witness data — so a
/// witness cannot disable auth by lying about them (the operator key is the
/// exchange's own; the batch height is the contract's counter). Prior order fills
/// need no special handling: they live in the account leaves, already bound to
/// `prev_root` and re-verified by (1)–(2).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutingProver<H: Hasher> {
    hasher: H,
    /// Trusted matcher key checked against every trade's matcher signature.
    /// `None` reproduces a legacy/unauthenticated batch (auth skipped).
    operator_key: Option<Ed25519PubKey>,
    /// Trusted batch height for order-expiry checks (the verifier's counter).
    batch_height: u64,
}

impl<H: Hasher> ExecutingProver<H> {
    /// A prover with no operator key — reproduces unauthenticated batches (used by
    /// lower-level settlement/commitment tests).
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            operator_key: None,
            batch_height: 0,
        }
    }

    /// A prover configured with the trusted matcher key + batch height, so it
    /// re-verifies trade authorization exactly as the live state did.
    pub fn with_auth(hasher: H, operator_key: Ed25519PubKey, batch_height: u64) -> Self {
        Self {
            hasher,
            operator_key: Some(operator_key),
            batch_height,
        }
    }
}

impl<H: Hasher> Prover for ExecutingProver<H> {
    fn prove(&self, witness: &Witness) -> Result<Proof, ProveError> {
        // (1) Merkle: the updates chain prev_root -> new_root.
        verify_chain(&self.hasher, witness)?;

        // An account may be touched by several txs in one batch. Its prior state
        // is the *first* update's `prev_leaf`; its final state the *last*
        // update's `new_leaf`. (Intermediate values are already validated by the
        // Merkle chain above.)
        let mut first_prev: BTreeMap<u128, Hash> = BTreeMap::new();
        let mut last_new: BTreeMap<u128, Hash> = BTreeMap::new();
        for u in &witness.updates {
            first_prev.entry(u.key).or_insert(u.prev_leaf);
            last_new.insert(u.key, u.new_leaf);
        }

        // (2) Each touched account's claimed prior contents must hash to the
        //     committed `prev_leaf` — binding the witness to `prev_root`.
        let prev_by_key: BTreeMap<u128, &Option<Account>> = witness
            .prev_accounts
            .iter()
            .map(|(id, contents)| (id.0.as_u128(), contents))
            .collect();
        for (&key, &prev_leaf) in &first_prev {
            let claimed = prev_by_key.get(&key).copied().unwrap_or(&None);
            if leaf_hash(&self.hasher, claimed.as_ref()) != prev_leaf {
                return Err(ProveError::PrevStateMismatch { key });
            }
        }

        // (3) Re-execute the batch in isolation from the prior contents.
        let seed = witness
            .prev_accounts
            .iter()
            .filter_map(|(id, contents)| contents.clone().map(|a| (*id, a)));
        let mut replay = State::for_replay(
            seed,
            witness.instruments.iter().cloned(),
            self.operator_key,
            self.batch_height,
        );
        let mut produced = Vec::new();
        for tx in &witness.txs {
            let withdraw_owner = match tx {
                Tx::Withdraw { account, .. } => replay.account(*account).and_then(|a| a.l1_owner()),
                _ => None,
            };
            if replay.apply(tx).is_err() {
                continue;
            }
            if let Tx::Withdraw { asset, amount, .. } = tx {
                let Some(owner) = withdraw_owner else {
                    return Err(ProveError::MessageMismatch);
                };
                produced.push(OnChainMessage::Withdraw {
                    owner,
                    asset: *asset,
                    amount: *amount,
                });
            }
        }

        // (4) Re-executed final contents must reproduce each committed `new_leaf`.
        for (&key, &new_leaf) in &last_new {
            let id = AccountId(Uuid::from_u128(key));
            if leaf_hash(&self.hasher, replay.account(id)) != new_leaf {
                return Err(ProveError::ExecutionMismatch { key });
            }
        }

        // (5) Re-execution must emit exactly the claimed messages.
        if produced != witness.messages {
            return Err(ProveError::MessageMismatch);
        }

        Ok(Proof { _private: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::hash_plain::Sha256Hasher;
    use crate::id::{AccountId, Amount, AssetId, InstrumentId, L1Address, MarketId};
    use crate::instrument::{Instrument, SettlementKind};
    use crate::settlement::Fill;
    use uuid::Uuid;

    const USDC: AssetId = AssetId(0);
    const BTC: AssetId = AssetId(1);

    fn acct(i: u128) -> AccountId {
        AccountId(Uuid::from_u128(i))
    }
    fn owner(n: u8) -> L1Address {
        L1Address([n; 32])
    }
    fn market() -> MarketId {
        MarketId(Uuid::from_u128(0xA1))
    }

    fn fresh() -> (State, StateTree<Sha256Hasher>) {
        let mut s = State::new();
        s.register_market(
            market(),
            Instrument {
                id: InstrumentId(1),
                kind: SettlementKind::SpotSwap,
                base: BTC,
                quote: USDC,
                base_scale: 8,
                quote_scale: 6,
            },
        );
        (s, StateTree::new(Sha256Hasher))
    }

    fn sample_batch() -> Vec<Tx> {
        vec![
            Tx::Deposit {
                account: acct(0xB),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: owner(1),
                trading_key: None,
            },
            Tx::Deposit {
                account: acct(0x5),
                asset: BTC,
                amount: Amount(5),
                nonce: 1,
                owner: owner(2),
                trading_key: None,
            },
            Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: acct(0xB),
                    seller: acct(0x5),
                    base_amount: Amount(2),
                    quote_amount: Amount(400),
                },
                auth: None,
            },
        ]
    }

    #[test]
    fn valid_witness_verifies() {
        let (mut s, mut t) = fresh();
        let w = Witness::capture(&mut s, &mut t, &sample_batch());
        // sanity: the witness's new_root must match the tree it produced
        assert_eq!(w.new_root, t.root());
        ReplayProver::new(Sha256Hasher).prove(&w).unwrap();
    }

    #[test]
    fn all_rejected_batch_is_noop_witness() {
        let (mut s, mut t) = fresh();
        // Trade with empty accounts -> rejected; no updates, roots equal.
        let w = Witness::capture(
            &mut s,
            &mut t,
            &[Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: acct(1),
                    seller: acct(2),
                    base_amount: Amount(1),
                    quote_amount: Amount(1),
                },
                auth: None,
            }],
        );
        assert!(w.updates.is_empty());
        assert_eq!(w.prev_root, w.new_root);
        ReplayProver::new(Sha256Hasher).prove(&w).unwrap();
    }

    #[test]
    fn tampered_new_root_rejected() {
        let (mut s, mut t) = fresh();
        let mut w = Witness::capture(&mut s, &mut t, &sample_batch());
        w.new_root[0] ^= 0xFF;
        assert_eq!(
            ReplayProver::new(Sha256Hasher).prove(&w),
            Err(ProveError::NewRootMismatch)
        );
    }

    #[test]
    fn tampered_sibling_path_rejected() {
        let (mut s, mut t) = fresh();
        let mut w = Witness::capture(&mut s, &mut t, &sample_batch());
        // Corrupt the sparse-path encoding of the last update (flip a mask bit so
        // a level's sibling is reconstructed wrongly); the chain must not verify.
        let last = w.updates.last_mut().unwrap();
        last.sibling_mask ^= 1;
        assert!(ReplayProver::new(Sha256Hasher).prove(&w).is_err());
    }

    #[test]
    fn tampered_new_leaf_rejected() {
        let (mut s, mut t) = fresh();
        let mut w = Witness::capture(&mut s, &mut t, &sample_batch());
        // Forge a different post-state for the first updated leaf.
        w.updates[0].new_leaf[0] ^= 0xFF;
        assert!(ReplayProver::new(Sha256Hasher).prove(&w).is_err());
    }

    // --- ExecutingProver: binds execution, not just the Merkle bookkeeping ---

    fn deposit_then_withdraw_batch() -> Vec<Tx> {
        vec![
            Tx::Deposit {
                account: acct(0xB),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: owner(1),
                trading_key: None,
            },
            Tx::Withdraw {
                account: acct(0xB),
                asset: USDC,
                amount: Amount(400),
            },
        ]
    }

    #[test]
    fn witness_serde_round_trips() {
        // The witness is the zkVM guest's input — it must (de)serialize losslessly.
        let (mut s, mut t) = fresh();
        let w = Witness::capture(&mut s, &mut t, &deposit_then_withdraw_batch());
        let json = serde_json::to_string(&w).unwrap();
        let back: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
        // and the round-tripped witness still verifies
        ExecutingProver::new(Sha256Hasher).prove(&back).unwrap();
    }

    #[test]
    fn executing_prover_accepts_honest_batch() {
        // A batch with a real withdrawal: the executing prover re-runs it and
        // confirms the leaves and the emitted message.
        let (mut s, mut t) = fresh();
        let w = Witness::capture(&mut s, &mut t, &deposit_then_withdraw_batch());
        assert_eq!(w.messages.len(), 1);
        ExecutingProver::new(Sha256Hasher).prove(&w).unwrap();
        // also a multi-account trade batch
        let (mut s2, mut t2) = fresh();
        let w2 = Witness::capture(&mut s2, &mut t2, &sample_batch());
        ExecutingProver::new(Sha256Hasher).prove(&w2).unwrap();
    }

    #[test]
    fn executing_prover_rejects_forged_message() {
        // sample_batch has no withdrawals, so a Merkle-valid witness with NO
        // messages. ReplayProver accepts it; forging an unbacked withdrawal
        // message leaves the Merkle chain valid (ReplayProver still accepts) but
        // the executing prover re-executes and finds no such withdrawal.
        let (mut s, mut t) = fresh();
        let mut w = Witness::capture(&mut s, &mut t, &sample_batch());
        assert!(w.messages.is_empty());
        ReplayProver::new(Sha256Hasher).prove(&w).unwrap();

        w.messages.push(OnChainMessage::Withdraw {
            owner: owner(1),
            asset: USDC,
            amount: Amount(999),
        });
        // ReplayProver still accepts (Merkle untouched) — the gap.
        ReplayProver::new(Sha256Hasher).prove(&w).unwrap();
        // ExecutingProver rejects — the gap closed.
        assert_eq!(
            ExecutingProver::new(Sha256Hasher).prove(&w),
            Err(ProveError::MessageMismatch)
        );
    }

    #[test]
    fn executing_prover_rejects_tampered_prior_state() {
        // First batch establishes acct(0xB) with 1000 USDC; the second batch's
        // witness then carries a real prior balance. Tampering that claimed prior
        // state breaks the prev_leaf binding.
        let (mut s, mut t) = fresh();
        let _ = Witness::capture(
            &mut s,
            &mut t,
            &[Tx::Deposit {
                account: acct(0xB),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: owner(1),
                trading_key: None,
            }],
        );
        let mut w = Witness::capture(
            &mut s,
            &mut t,
            &[Tx::Withdraw {
                account: acct(0xB),
                asset: USDC,
                amount: Amount(400),
            }],
        );
        // Merkle chain is valid as captured.
        ReplayProver::new(Sha256Hasher).prove(&w).unwrap();

        // Lie about the prior balance (claim 500 instead of the real 1000).
        let mut forged = Account::new();
        forged.credit(USDC, Amount(500)).unwrap();
        w.prev_accounts = vec![(acct(0xB), Some(forged))];
        assert_eq!(
            ExecutingProver::new(Sha256Hasher).prove(&w),
            Err(ProveError::PrevStateMismatch {
                key: acct(0xB).0.as_u128()
            })
        );
    }

    /// The prover re-verifies trade authorization: it re-seeds the operator key /
    /// batch height / prior fills, so a batch whose committed transition includes
    /// a trade whose signatures don't verify is rejected.
    mod authz {
        use super::*;
        use crate::auth::{Ed25519PubKey, Ed25519Signature, Order, Side, SignedOrder, TradeAuth};
        use crate::commitment::{encode_matcher_msg, encode_order, order_id};
        use ed25519_dalek::{Signer, SigningKey};

        fn kp(seed: u8) -> (SigningKey, Ed25519PubKey) {
            let sk = SigningKey::from_bytes(&[seed; 32]);
            let pk = Ed25519PubKey(sk.verifying_key().to_bytes());
            (sk, pk)
        }
        fn sig(sk: &SigningKey, m: &[u8]) -> Ed25519Signature {
            Ed25519Signature::from_bytes(sk.sign(m).to_bytes())
        }

        /// A state (operator key set) + tree + a fully-signed authenticated batch
        /// (fund+register both accounts, then a valid trade).
        fn authed() -> (State, StateTree<Sha256Hasher>, Vec<Tx>) {
            let (buyer_sk, buyer_pk) = kp(1);
            let (seller_sk, seller_pk) = kp(2);
            let (op_sk, op_pk) = kp(3);
            let (mut s, t) = fresh();
            s.set_operator_key(op_pk);

            let buy = Order {
                account: acct(0xB),
                market: market(),
                side: Side::Buy,
                base_amount: Amount(5),
                limit_price: Amount(250),
                expiry: 100,
                salt: 1,
            };
            let sell = Order {
                account: acct(0x5),
                market: market(),
                side: Side::Sell,
                base_amount: Amount(5),
                limit_price: Amount(180),
                expiry: 100,
                salt: 2,
            };
            let f = Fill {
                buyer: acct(0xB),
                seller: acct(0x5),
                base_amount: Amount(2),
                quote_amount: Amount(400),
            };
            let m = encode_matcher_msg(market(), &order_id(&buy), &order_id(&sell), &f);
            let auth = TradeAuth {
                buy: SignedOrder {
                    order: buy,
                    sig: sig(&buyer_sk, &encode_order(&buy)),
                },
                sell: SignedOrder {
                    order: sell,
                    sig: sig(&seller_sk, &encode_order(&sell)),
                },
                matcher_sig: sig(&op_sk, &m),
            };
            let batch = vec![
                Tx::Deposit {
                    account: acct(0xB),
                    asset: USDC,
                    amount: Amount(1000),
                    nonce: 0,
                    owner: owner(1),
                    trading_key: Some(buyer_pk),
                },
                Tx::Deposit {
                    account: acct(0x5),
                    asset: BTC,
                    amount: Amount(5),
                    nonce: 1,
                    owner: owner(2),
                    trading_key: Some(seller_pk),
                },
                Tx::Trade {
                    market: market(),
                    fill: f,
                    auth: Some(Box::new(auth)),
                },
            ];
            (s, t, batch)
        }

        /// A prover configured with the same trusted matcher key + batch height
        /// the state used, so it re-verifies authorization.
        fn prover(s: &State) -> ExecutingProver<Sha256Hasher> {
            ExecutingProver::with_auth(Sha256Hasher, s.operator_key().unwrap(), s.batch_height())
        }

        #[test]
        fn authenticated_batch_proves_with_execution() {
            let (mut s, mut t, batch) = authed();
            let w = Witness::capture(&mut s, &mut t, &batch);
            // The trade applied (buyer received BTC).
            assert_eq!(s.balance(acct(0xB), BTC), Amount(2));
            prover(&s).prove(&w).unwrap();
        }

        #[test]
        fn tampered_matcher_sig_fails_execution() {
            let (mut s, mut t, batch) = authed();
            let prover = prover(&s);
            let mut w = Witness::capture(&mut s, &mut t, &batch);
            // Corrupt the matcher signature in the committed batch. The roots still
            // reflect the (authorized) trade, but replay now rejects it, so the
            // re-executed leaves diverge from the committed ones.
            for tx in w.txs.iter_mut() {
                if let Tx::Trade {
                    auth: Some(auth), ..
                } = tx
                {
                    auth.matcher_sig.r[0] ^= 0xFF;
                }
            }
            assert!(matches!(
                prover.prove(&w),
                Err(ProveError::ExecutionMismatch { .. })
            ));
        }
    }
}
