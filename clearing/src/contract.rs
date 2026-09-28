//! In-memory stand-in for the on-chain settlement program.
//!
//! [`MockSettlementContract`] holds escrow, the canonical root, and
//! proof-gated batches so tests can run without Solana.
//!
//! - [`MockSettlementContract::deposit`] credits an in-memory escrow pool.
//! - [`MockSettlementContract::commit`] queues a [`BatchProposal`];
//!   [`MockSettlementContract::verify_next`] runs the [`Prover`] and advances
//!   the root only on a valid proof.
//! - `verify_next` does not pay. It stores a withdrawals Merkle root; each
//!   user [`MockSettlementContract::claim`]s with an inclusion proof (one
//!   nullifier per leaf).
//! - [`MockSettlementContract::is_solvent`] checks
//!   `escrow == Σ L2 balances + unclaimed withdrawals` per asset.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use thiserror::Error;

use crate::account::Account;
use crate::commitment::{
    Hash, Hasher, canonical_encode, default_hashes, root_from_path, verify_withdrawal,
    withdrawals_root,
};
use crate::da::DaBlob;
use crate::id::{AccountId, Amount, AssetId, L1Address};
use crate::prover::{ProveError, Prover, Witness};
use crate::state::State;
use crate::tx::{OnChainMessage, Tx};

/// A batch handed to the contract for finalization: the witness to verify and
/// the `da` blob to publish (so account state stays reconstructable from public
/// data for the escape hatch).
///
/// The withdrawal messages the contract acts on live **inside the witness**
/// ([`Witness::messages`]) — so they are part of what the proof binds, not a
/// separately-supplied (and forgeable) field. A verifier that checks execution
/// ([`crate::prover::ExecutingProver`]) rejects a batch whose `witness.messages` don't match a
/// real debit, so the contract can release on them safely.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BatchProposal {
    pub witness: Witness,
    pub da: DaBlob,
}

impl BatchProposal {
    pub fn new(witness: Witness, da: DaBlob) -> Self {
        Self { witness, da }
    }
    pub fn prev_root(&self) -> Hash {
        self.witness.prev_root
    }
    pub fn new_root(&self) -> Hash {
        self.witness.new_root
    }
}

/// Why a settlement operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SettleError {
    /// A committed proposal must extend the current chain tip.
    #[error("proposal prev_root does not extend the chain tip")]
    ChainMismatch { expected: Hash, got: Hash },
    /// At verify time the front batch's `prev_root` must equal the canonical
    /// root (only fails if an earlier batch was dropped on an invalid proof).
    #[error("batch prev_root does not match the canonical root")]
    RootMismatch { expected: Hash, got: Hash },
    /// The batch proof did not verify; the root is not advanced.
    #[error("batch proof invalid: {0}")]
    InvalidProof(#[from] ProveError),
    /// `verify_next` was called with no pending batch.
    #[error("nothing to verify")]
    NothingToVerify,
    /// A deposit/release amount was not positive.
    #[error("non-positive amount")]
    NonPositiveAmount,
    /// A release exceeds the escrowed pool for an asset.
    #[error("insufficient escrow")]
    InsufficientEscrow,
    /// Escrow arithmetic overflowed.
    #[error("escrow amount overflow")]
    Overflow,
    /// A state-changing op was attempted after the escape hatch froze the chain.
    #[error("contract is frozen (escape hatch active)")]
    Frozen,
    /// An escape withdrawal was attempted while the chain is still live.
    #[error("escape hatch not active (contract not frozen)")]
    NotFrozen,
    /// The escape proof did not hash to the committed root — the claimed account
    /// state is not the proven state.
    #[error("invalid escape proof: claimed state not in the committed root")]
    BadEscapeProof,
    /// This account already escaped this asset (no double-withdraw).
    #[error("account already escaped this asset")]
    AlreadyEscaped,
    /// The proven balance for this asset is zero — nothing to withdraw.
    #[error("nothing to withdraw")]
    NothingToWithdraw,
    /// A claim referenced a batch sequence number that has not been finalized.
    #[error("unknown batch")]
    UnknownBatch,
    /// A claim's Merkle proof did not reproduce the committed withdrawals root.
    #[error("invalid claim proof: withdrawal not in the committed root")]
    BadClaimProof,
    /// This withdrawal was already claimed (nullifier present).
    #[error("withdrawal already claimed")]
    AlreadyClaimed,
    /// The escape caller is not the leaf's L1 owner (or the leaf has no owner).
    #[error("caller is not the proven leaf owner")]
    OwnerMismatch,
}

/// The mock settlement contract: escrow custody + proof-gated finalization.
#[derive(Debug, Clone)]
pub struct MockSettlementContract<V: Prover> {
    /// In-memory custody, as a **per-asset pool** (not per depositor): the total
    /// of each asset the contract holds. Entitlement is the proven L2 balance,
    /// not who deposited — trading redistributes claims, so withdrawals (normal
    /// or escape) are paid from this pool, never from the withdrawer's "own"
    /// deposit.
    escrow: BTreeMap<AssetId, Amount>,
    /// Canonical committed root; advanced only by a verified batch.
    root: Hash,
    /// Committed batches awaiting proof, in order.
    pending: VecDeque<BatchProposal>,
    /// Proof verifier ([`Prover`]).
    verifier: V,
    /// Monotonic source of deposit nonces. The contract is the sole issuer, so
    /// every deposit it originates is unique; the state machine then credits each
    /// nonce at most once.
    next_deposit_nonce: u64,
    /// Set by the escape hatch: once frozen, no further batches commit/verify and
    /// users withdraw directly against the frozen root.
    frozen: bool,
    /// `(account, asset)` pairs already escaped, so a frozen-state withdrawal can
    /// be claimed at most once per L2 account. Two accounts may share an L1 owner.
    escaped: BTreeSet<(AccountId, AssetId)>,
    /// DA blobs of finalized batches, in order — the public record from which
    /// anyone reconstructs account state to exit via the escape hatch.
    da_blobs: Vec<DaBlob>,
    /// Per finalized batch, the Merkle root over that batch's withdrawal
    /// messages (index = batch sequence). Users [`claim`](Self::claim) against
    /// it; settle does not pay recipients one by one.
    withdrawal_roots: Vec<Hash>,
    /// Leaf hashes of claimed withdrawals. A second claim of the same leaf
    /// is rejected. On Solana this is a PDA per nullifier.
    claimed: BTreeSet<Hash>,
    /// Authorized-but-unclaimed withdrawals per asset. Escrow still holds these
    /// (they're released only at claim time), so solvency is
    /// `escrow == Σ L2 balances + Σ pending_withdrawals`.
    pending_withdrawals: BTreeMap<AssetId, Amount>,
}

impl<V: Prover> MockSettlementContract<V> {
    /// Create a contract anchored at `genesis_root` (the empty-state root the
    /// engine also starts from), with empty escrow and no pending batches.
    pub fn new(verifier: V, genesis_root: Hash) -> Self {
        Self {
            escrow: BTreeMap::new(),
            root: genesis_root,
            pending: VecDeque::new(),
            verifier,
            next_deposit_nonce: 0,
            frozen: false,
            escaped: BTreeSet::new(),
            da_blobs: Vec::new(),
            withdrawal_roots: Vec::new(),
            claimed: BTreeSet::new(),
            pending_withdrawals: BTreeMap::new(),
        }
    }

    /// The published DA blobs of all finalized batches, in order. A user reads
    /// these (in reality, from the chain) and replays them via
    /// [`crate::da::reconstruct`] to rebuild account state for an escape exit.
    pub fn da_blobs(&self) -> &[DaBlob] {
        &self.da_blobs
    }

    /// The canonical (last-verified) state root.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Number of committed-but-unverified batches.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    // --- custody ---------------------------------------------------------

    /// Originate a deposit: escrow the funds (under `owner`) and return the
    /// contract-issued [`Tx::Deposit`] — with a unique nonce and that owner —
    /// that the engine must include to credit the L2 balance. The L2 credit is
    /// final only once the batch carrying this tx verifies; until then escrow
    /// leads the proven L2 state (the documented in-flight gap). `trading_key`
    /// on the issued tx is `None`.
    ///
    /// This is the deposit analogue of the proof-authorized withdrawal: the
    /// contract is the sole nonce issuer, so every credited deposit is backed by
    /// escrow it actually holds. (As with withdrawals, the v0 stub does not yet
    /// cryptographically bind the L2 credit to this escrow event — a real SNARK
    /// makes the contract's deposit queue a public input.)
    pub fn deposit(
        &mut self,
        account: AccountId,
        asset: AssetId,
        amount: Amount,
        owner: L1Address,
    ) -> Result<Tx, SettleError> {
        if self.frozen {
            return Err(SettleError::Frozen);
        }
        if amount.is_negative() || amount.is_zero() {
            return Err(SettleError::NonPositiveAmount);
        }
        let next = self
            .pool(asset)
            .checked_add(amount)
            .map_err(|_| SettleError::Overflow)?;
        self.set_pool(asset, next);

        let nonce = self.next_deposit_nonce;
        self.next_deposit_nonce += 1;
        Ok(Tx::Deposit {
            account,
            asset,
            amount,
            nonce,
            owner,
            // Deposit through this API does not register a trading key.
            trading_key: None,
        })
    }

    /// Pay `amount` of `asset` out of the pool. **Private on purpose:** a release
    /// is never a free, operator-callable action — it happens only inside
    /// [`Self::verify_next`] (driven by a withdrawal message in a *proven* batch)
    /// or [`Self::escape_withdraw`] (a proof against the frozen root). Paid from
    /// the asset pool, so a user is paid their proven entitlement regardless of
    /// who originally deposited it.
    fn release(&mut self, asset: AssetId, amount: Amount) -> Result<(), SettleError> {
        if amount.is_negative() || amount.is_zero() {
            return Err(SettleError::NonPositiveAmount);
        }
        let current = self.pool(asset);
        if amount > current {
            return Err(SettleError::InsufficientEscrow);
        }
        let next = current
            .checked_sub(amount)
            .map_err(|_| SettleError::Overflow)?;
        self.set_pool(asset, next);
        Ok(())
    }

    /// The escrow pool for `asset` (zero if none).
    fn pool(&self, asset: AssetId) -> Amount {
        self.escrow.get(&asset).copied().unwrap_or(Amount::ZERO)
    }

    /// Total escrow held in `asset` (the whole pool).
    pub fn total_escrow(&self, asset: AssetId) -> i128 {
        self.pool(asset).0
    }

    fn set_pool(&mut self, asset: AssetId, value: Amount) {
        if value.is_zero() {
            self.escrow.remove(&asset);
        } else {
            self.escrow.insert(asset, value);
        }
    }

    // --- batch lifecycle -------------------------------------------------

    /// The root the next committed batch must extend (last pending batch's
    /// `new_root`, or the canonical root if none are pending).
    fn tip(&self) -> Hash {
        self.pending
            .back()
            .map(BatchProposal::new_root)
            .unwrap_or(self.root)
    }

    /// Commit (queue) a batch. The proposal must extend the current tip; it is
    /// not finalized until [`Self::verify_next`] proves it. Rejected once the
    /// escape hatch has frozen the chain.
    pub fn commit(&mut self, proposal: BatchProposal) -> Result<(), SettleError> {
        if self.frozen {
            return Err(SettleError::Frozen);
        }
        let tip = self.tip();
        if proposal.prev_root() != tip {
            return Err(SettleError::ChainMismatch {
                expected: tip,
                got: proposal.prev_root(),
            });
        }
        self.pending.push_back(proposal);
        Ok(())
    }

    /// Verify the oldest pending batch and finalize it. On a valid proof the
    /// canonical root advances to the batch's `new_root`, the DA blob is
    /// published, and the batch's withdrawals are committed as **one Merkle root**
    /// (`withdrawal_roots`) — **not paid out here**. Users pull their funds later
    /// via [`Self::claim`]. Returns the new root; on an invalid proof nothing
    /// changes.
    ///
    /// Why not pay inline: a real (Solana) settlement transaction cannot push N
    /// per-recipient payouts (account/size/compute limits), so it commits an O(1)
    /// root and each user claims asynchronously. The withdrawal messages are the
    /// engine's proven outputs (bound by the proof — see [`OnChainMessage`]); we
    /// hash exactly those into the committed root, and record the pending totals
    /// so solvency accounts for authorized-but-unclaimed funds.
    pub fn verify_next<H: Hasher>(&mut self, hasher: &H) -> Result<Hash, SettleError> {
        if self.frozen {
            return Err(SettleError::Frozen);
        }
        let batch = self
            .pending
            .pop_front()
            .ok_or(SettleError::NothingToVerify)?;
        if batch.prev_root() != self.root {
            return Err(SettleError::RootMismatch {
                expected: self.root,
                got: batch.prev_root(),
            });
        }
        // Proof gate.
        self.verifier.prove(&batch.witness)?;

        // Finalize: advance the root and commit this batch's withdrawals as one
        // root (the batch's sequence number is its index in `withdrawal_roots`).
        let batch_seq = self.withdrawal_roots.len() as u64;
        let entries: Vec<(L1Address, AssetId, Amount)> = batch
            .witness
            .messages
            .iter()
            .map(
                |OnChainMessage::Withdraw {
                     owner,
                     asset,
                     amount,
                 }| (*owner, *asset, *amount),
            )
            .collect();
        let w_root = withdrawals_root(hasher, batch_seq, &entries);

        self.root = batch.new_root();
        self.withdrawal_roots.push(w_root);
        // Track authorized-but-unclaimed totals (escrow still holds them).
        for (_, asset, amount) in &entries {
            let acc = self
                .pending_withdrawals
                .entry(*asset)
                .or_insert(Amount::ZERO);
            *acc = acc
                .checked_add(*amount)
                .map_err(|_| SettleError::Overflow)?;
        }
        self.da_blobs.push(batch.da);
        Ok(self.root)
    }

    // --- async withdrawal claims -----------------------------------------

    /// The committed withdrawals root for a finalized batch (by sequence number).
    pub fn withdrawals_root(&self, batch_seq: usize) -> Option<Hash> {
        self.withdrawal_roots.get(batch_seq).copied()
    }

    /// **Pull** a proven withdrawal: a user claims their payout from a finalized
    /// batch by supplying its `(batch_seq, index)`, the withdrawal fields, and the
    /// Merkle `siblings` proving inclusion in that batch's committed withdrawals
    /// root. Pays `amount` of `asset` to `owner` — **once**, gated by the
    /// nullifier (the leaf hash). This is the async, one-tx-per-user counterpart
    /// to a settle-time payout: the batch committed all withdrawals as a single
    /// root; each user claims their slice independently.
    #[allow(clippy::too_many_arguments)]
    pub fn claim<H: Hasher>(
        &mut self,
        hasher: &H,
        batch_seq: usize,
        index: u32,
        owner: L1Address,
        asset: AssetId,
        amount: Amount,
        siblings: &[Hash],
    ) -> Result<(), SettleError> {
        let root = self
            .withdrawal_roots
            .get(batch_seq)
            .copied()
            .ok_or(SettleError::UnknownBatch)?;

        // Inclusion: the claimed withdrawal must be in the committed root. This is
        // also the leaf's nullifier (unique via batch_seq + index).
        if !verify_withdrawal(
            hasher,
            root,
            batch_seq as u64,
            index,
            owner,
            asset,
            amount,
            siblings,
        ) {
            return Err(SettleError::BadClaimProof);
        }
        let nullifier = crate::commitment::withdrawal_leaf(
            hasher,
            batch_seq as u64,
            index,
            owner,
            asset,
            amount,
        );
        if self.claimed.contains(&nullifier) {
            return Err(SettleError::AlreadyClaimed);
        }

        // Pay out and mark claimed; drop the pending total.
        self.release(asset, amount)?;
        self.claimed.insert(nullifier);
        if let Some(acc) = self.pending_withdrawals.get_mut(&asset) {
            *acc = acc.checked_sub(amount).map_err(|_| SettleError::Overflow)?;
            if acc.is_zero() {
                self.pending_withdrawals.remove(&asset);
            }
        }
        Ok(())
    }

    /// Total authorized-but-unclaimed withdrawals of `asset`.
    pub fn pending_withdrawals(&self, asset: AssetId) -> Amount {
        self.pending_withdrawals
            .get(&asset)
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    // --- escape hatch (emergency self-withdrawal) ------------------------

    /// Freeze the chain — the escape hatch. After this, no batch commits or
    /// verifies; users withdraw directly via [`Self::escape_withdraw`]. (In the
    /// full system this is triggered by a missed priority-tx deadline, S4; here
    /// it is an explicit call.)
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Emergency self-withdrawal: a user pulls their funds **directly from the
    /// contract**, with no operator, by proving their account state against the
    /// frozen root.
    ///
    /// The caller supplies their claimed account contents (`proven`), the Merkle
    /// `siblings` for their leaf, and `signer_owner` (the Solana signer analogue).
    /// After the root check, the leaf owner must equal `signer_owner`
    /// ([`SettleError::OwnerMismatch`] if missing or different). Pays the proven
    /// balance of `asset` from the pool, once per `(account, asset)`.
    #[allow(clippy::too_many_arguments)]
    pub fn escape_withdraw<H: Hasher>(
        &mut self,
        hasher: &H,
        account: AccountId,
        proven: &Account,
        sibling_mask: u128,
        siblings: &[Hash],
        asset: AssetId,
        signer_owner: L1Address,
    ) -> Result<Amount, SettleError> {
        if !self.frozen {
            return Err(SettleError::NotFrozen);
        }
        // Bind the claim to the committed state: the claimed contents must hash,
        // along the supplied (sparse) path, back to the frozen root.
        let leaf = hasher.hash_leaf(&canonical_encode(proven));
        let defaults = default_hashes(hasher);
        if root_from_path(
            hasher,
            &defaults,
            account.0.as_u128(),
            leaf,
            sibling_mask,
            siblings,
        ) != self.root
        {
            return Err(SettleError::BadEscapeProof);
        }
        if proven.l1_owner() != Some(signer_owner) {
            return Err(SettleError::OwnerMismatch);
        }
        if self.escaped.contains(&(account, asset)) {
            return Err(SettleError::AlreadyEscaped);
        }
        let amount = proven.balance(asset);
        if amount.is_zero() {
            return Err(SettleError::NothingToWithdraw);
        }
        self.release(asset, amount)?;
        self.escaped.insert((account, asset));
        Ok(amount)
    }

    // --- invariant -------------------------------------------------------

    /// For every asset in `assets`:
    /// `escrow == Σ L2 balances + unclaimed withdrawals`.
    /// Escaped `(account, asset)` pairs are omitted from the L2 sum (escape
    /// pays escrow without mutating the off-chain state). Assert only at
    /// settled points; a committed-but-unverified batch is the exception.
    pub fn is_solvent(&self, state: &State, assets: &[AssetId]) -> bool {
        assets.iter().all(|&asset| {
            let l2: i128 = state
                .accounts()
                .map(|(id, a)| {
                    if self.escaped.contains(&(*id, asset)) {
                        0
                    } else {
                        a.balance(asset).0
                    }
                })
                .sum();
            self.total_escrow(asset) == l2 + self.pending_withdrawals(asset).0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::commitment::StateTree;
    use crate::commitment::hash_plain::Sha256Hasher;
    use crate::id::{AccountId, InstrumentId, L1Address, MarketId};
    use crate::instrument::{Instrument, SettlementKind};
    use crate::settlement::Fill;
    use crate::{Engine, ExecutingProver, ReplayProver, Tx};
    use uuid::Uuid;

    const USDC: AssetId = AssetId(0);
    const BTC: AssetId = AssetId(1);

    fn buyer() -> AccountId {
        AccountId(Uuid::from_u128(0xB))
    }
    fn seller() -> AccountId {
        AccountId(Uuid::from_u128(0x5))
    }
    fn buyer_owner() -> L1Address {
        L1Address([1u8; 32])
    }
    fn seller_owner() -> L1Address {
        L1Address([2u8; 32])
    }
    fn market() -> MarketId {
        MarketId(Uuid::from_u128(0xA1))
    }
    fn genesis() -> Hash {
        StateTree::new(Sha256Hasher).root()
    }
    fn engine() -> Engine<Sha256Hasher, ReplayProver<Sha256Hasher>> {
        let mut e = Engine::new(Sha256Hasher, ReplayProver::new(Sha256Hasher));
        e.register_market(
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
        e
    }
    // The contract verifies with the *executing* prover — the security boundary
    // must check execution, not just the Merkle bookkeeping.
    fn contract() -> MockSettlementContract<ExecutingProver<Sha256Hasher>> {
        MockSettlementContract::new(ExecutingProver::new(Sha256Hasher), genesis())
    }

    #[test]
    fn commit_then_verify_advances_root() {
        let mut e = engine();
        let outcome = e
            .step(vec![Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: buyer_owner(),
                trading_key: None,
            }])
            .unwrap();

        let mut c = contract();
        assert_eq!(c.root(), genesis());
        assert_eq!(outcome.prev_root(), genesis());

        c.commit(outcome.proposal()).unwrap();
        assert_eq!(c.pending_len(), 1);

        let new_root = c.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(new_root, outcome.new_root());
        assert_eq!(c.root(), e.root());
        assert_eq!(c.pending_len(), 0);
    }

    #[test]
    fn tampered_proof_does_not_advance_root() {
        let mut e = engine();
        let outcome = e
            .step(vec![Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: buyer_owner(),
                trading_key: None,
            }])
            .unwrap();

        let mut tampered = outcome.witness.clone();
        tampered.new_root[0] ^= 0xFF;

        let mut c = contract();
        c.commit(BatchProposal::new(tampered, DaBlob::default()))
            .unwrap();
        let err = c.verify_next(&Sha256Hasher).unwrap_err();
        assert!(matches!(err, SettleError::InvalidProof(_)));
        assert_eq!(c.root(), genesis(), "root must not advance on a bad proof");
    }

    #[test]
    fn batches_finalize_in_chain_order() {
        let mut e = engine();
        let o1 = e
            .step(vec![
                Tx::Deposit {
                    account: buyer(),
                    asset: USDC,
                    amount: Amount(1000),
                    nonce: 0,
                    owner: buyer_owner(),
                    trading_key: None,
                },
                Tx::Deposit {
                    account: seller(),
                    asset: BTC,
                    amount: Amount(5),
                    nonce: 1,
                    owner: seller_owner(),
                    trading_key: None,
                },
            ])
            .unwrap();
        let o2 = e
            .step(vec![Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: buyer(),
                    seller: seller(),
                    base_amount: Amount(2),
                    quote_amount: Amount(400),
                },
                auth: None,
            }])
            .unwrap();

        let mut c = contract();
        c.commit(o1.proposal()).unwrap();
        c.commit(o2.proposal()).unwrap();
        assert_eq!(c.verify_next(&Sha256Hasher).unwrap(), o1.new_root());
        assert_eq!(c.verify_next(&Sha256Hasher).unwrap(), o2.new_root());
        assert_eq!(c.root(), e.root());
    }

    #[test]
    fn commit_out_of_chain_rejected() {
        let mut e = engine();
        let o1 = e
            .step(vec![Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: buyer_owner(),
                trading_key: None,
            }])
            .unwrap();
        let o2 = e
            .step(vec![Tx::Withdraw {
                account: buyer(),
                asset: USDC,
                amount: Amount(100),
            }])
            .unwrap();

        let mut c = contract();
        // Committing o2 first skips o1 — its prev_root != tip (genesis).
        let err = c.commit(o2.proposal()).unwrap_err();
        assert!(matches!(err, SettleError::ChainMismatch { .. }));
        // o1 commits fine.
        c.commit(o1.proposal()).unwrap();
    }

    #[test]
    fn withdrawal_committed_on_verify_then_released_on_claim() {
        use crate::commitment::withdrawal_proof;
        let mut e = engine();
        let mut c = contract();

        // Deposit (batch 0): the contract escrows and issues the deposit tx.
        let dep = c
            .deposit(buyer(), USDC, Amount(1000), buyer_owner())
            .unwrap();
        let o1 = e.step(vec![dep]).unwrap();
        c.commit(o1.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(c.total_escrow(USDC), 1000);
        assert!(c.is_solvent(e.state(), &[USDC, BTC]));

        // Withdraw 400 (batch 1): verifying commits the withdrawals root but does
        // NOT release — the payout is pending, escrow still holds it.
        let o2 = e
            .step(vec![Tx::Withdraw {
                account: buyer(),
                asset: USDC,
                amount: Amount(400),
            }])
            .unwrap();
        assert_eq!(o2.messages.len(), 1);
        c.commit(o2.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(c.total_escrow(USDC), 1000); // not released
        assert_eq!(c.pending_withdrawals(USDC), Amount(400));
        assert!(c.is_solvent(e.state(), &[USDC, BTC])); // 1000 == 600 L2 + 400 pending

        // The user claims asynchronously against batch 1's withdrawals root.
        let owner = buyer_owner();
        let entries = [(owner, USDC, Amount(400))];
        let siblings = withdrawal_proof(&Sha256Hasher, 1, &entries, 0);
        c.claim(&Sha256Hasher, 1, 0, owner, USDC, Amount(400), &siblings)
            .unwrap();
        assert_eq!(c.total_escrow(USDC), 600); // now released
        assert_eq!(c.pending_withdrawals(USDC), Amount::ZERO);
        assert_eq!(e.state().balance(buyer(), USDC), Amount(600));
        assert!(c.is_solvent(e.state(), &[USDC, BTC]));

        // Replaying the same claim is rejected by the nullifier.
        assert_eq!(
            c.claim(&Sha256Hasher, 1, 0, owner, USDC, Amount(400), &siblings),
            Err(SettleError::AlreadyClaimed)
        );
    }

    #[test]
    fn claim_rejects_bad_proof_and_unknown_batch() {
        use crate::commitment::withdrawal_proof;
        let mut e = engine();
        let mut c = contract();

        let dep = c
            .deposit(buyer(), USDC, Amount(1000), buyer_owner())
            .unwrap();
        let o1 = e.step(vec![dep]).unwrap();
        c.commit(o1.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        let o2 = e
            .step(vec![Tx::Withdraw {
                account: buyer(),
                asset: USDC,
                amount: Amount(400),
            }])
            .unwrap();
        c.commit(o2.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();

        let owner = buyer_owner();
        let entries = [(owner, USDC, Amount(400))];
        let siblings = withdrawal_proof(&Sha256Hasher, 1, &entries, 0);

        // Wrong amount → the leaf differs → not in the committed root.
        assert_eq!(
            c.claim(&Sha256Hasher, 1, 0, owner, USDC, Amount(999), &siblings),
            Err(SettleError::BadClaimProof)
        );
        // A batch that was never finalized.
        assert_eq!(
            c.claim(&Sha256Hasher, 9, 0, owner, USDC, Amount(400), &siblings),
            Err(SettleError::UnknownBatch)
        );
        // Nothing released by the failed claims.
        assert_eq!(c.total_escrow(USDC), 1000);
    }

    #[test]
    fn over_withdrawal_emits_no_message_and_releases_nothing() {
        let mut e = engine();
        let mut c = contract();

        let dep = c
            .deposit(buyer(), USDC, Amount(1000), buyer_owner())
            .unwrap();
        let o1 = e.step(vec![dep]).unwrap();
        c.commit(o1.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();

        // Try to withdraw more than the L2 balance: the state machine rejects it,
        // so the batch emits no message and the proven transition is a no-op —
        // the contract releases nothing and stays solvent. The spoof (drain
        // escrow without a real debit) is simply not expressible.
        let spoof = e
            .step(vec![Tx::Withdraw {
                account: buyer(),
                asset: USDC,
                amount: Amount(5000),
            }])
            .unwrap();
        assert!(spoof.messages.is_empty());
        assert_eq!(spoof.prev_root(), spoof.new_root());
        c.commit(spoof.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(c.total_escrow(USDC), 1000);
        assert!(c.is_solvent(e.state(), &[USDC, BTC]));
    }

    #[test]
    fn contract_rejects_forged_withdrawal_message() {
        // The other angle on the spoof: not a rejected tx, but a *malicious
        // operator* who hand-forges a withdrawal message onto an otherwise-honest
        // batch. The funds exist in escrow (1000), so only the proof stands
        // between the operator and a stolen 999. Because the contract verifies
        // with the executing prover, re-execution finds no such withdrawal and
        // the batch is rejected — at the contract.
        let mut e = engine();
        let mut c = contract();
        let dep = c
            .deposit(buyer(), USDC, Amount(1000), buyer_owner())
            .unwrap();
        let o1 = e.step(vec![dep]).unwrap();
        c.commit(o1.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(c.total_escrow(USDC), 1000);

        // An honest (no-withdrawal) batch, then forge a withdrawal into its
        // witness. The Merkle chain stays valid, so a Merkle-only verifier would
        // accept it.
        let mut o2 = e
            .step(vec![Tx::Deposit {
                account: seller(),
                asset: USDC,
                amount: Amount(1),
                nonce: 99,
                owner: seller_owner(),
                trading_key: None,
            }])
            .unwrap();
        o2.witness.messages.push(OnChainMessage::Withdraw {
            owner: buyer_owner(),
            asset: USDC,
            amount: Amount(999),
        });

        c.commit(o2.proposal()).unwrap();
        assert!(matches!(
            c.verify_next(&Sha256Hasher),
            Err(SettleError::InvalidProof(_))
        ));
        // Nothing released; the forged withdrawal never finalized.
        assert_eq!(c.total_escrow(USDC), 1000);
    }

    #[test]
    fn escape_hatch_self_withdraw_and_rejects_forgery() {
        let mut e = engine();
        let mut c = contract();

        // Fund + trade: buyer ends with 600 USDC / 2 BTC, seller 400 USDC / 3 BTC.
        let d1 = c
            .deposit(buyer(), USDC, Amount(1000), buyer_owner())
            .unwrap();
        let d2 = c.deposit(seller(), BTC, Amount(5), seller_owner()).unwrap();
        let o1 = e.step(vec![d1, d2]).unwrap();
        c.commit(o1.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        let o2 = e
            .step(vec![Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: buyer(),
                    seller: seller(),
                    base_amount: Amount(2),
                    quote_amount: Amount(400),
                },
                auth: None,
            }])
            .unwrap();
        c.commit(o2.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(e.state().balance(seller(), USDC), Amount(400));

        // Operator goes dark → escape hatch. No more batches finalize.
        c.freeze();
        assert!(c.is_frozen());
        assert_eq!(c.verify_next(&Sha256Hasher), Err(SettleError::Frozen));

        // A user reconstructs account state from the contract's published DA
        // blobs alone — NOT from engine.state() — and builds the Merkle tree.
        // This is the real escape path: no operator, only on-chain data.
        let accounts = crate::da::reconstruct(c.da_blobs());
        let tree = StateTree::from_accounts(Sha256Hasher, accounts.iter());
        assert_eq!(
            tree.root(),
            c.root(),
            "DA blobs reconstruct the committed root"
        );

        // Theft: DA-reconstructed leaf for account B, caller A, valid path.
        // Merkle succeeds; owner check rejects. Escrow unchanged.
        let seller_acct = accounts.get(&seller()).cloned().unwrap();
        let (mask, sibs) = tree.prove(seller());
        let escrow_before = c.total_escrow(USDC);
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                seller(),
                &seller_acct,
                mask,
                &sibs,
                USDC,
                buyer_owner(),
            ),
            Err(SettleError::OwnerMismatch)
        );
        assert_eq!(c.total_escrow(USDC), escrow_before);

        // Seller self-withdraws their 400 USDC — note they never *deposited* USDC
        // (it came from the trade): it's paid from the asset pool.
        let got = c
            .escape_withdraw(
                &Sha256Hasher,
                seller(),
                &seller_acct,
                mask,
                &sibs,
                USDC,
                seller_owner(),
            )
            .unwrap();
        assert_eq!(got, Amount(400));
        assert_eq!(c.total_escrow(USDC), 600);

        // Double-escape of the same asset is rejected.
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                seller(),
                &seller_acct,
                mask,
                &sibs,
                USDC,
                seller_owner(),
            ),
            Err(SettleError::AlreadyEscaped)
        );

        // UNLAWFUL withdrawal: forge a higher balance (claim 5000 USDC). The
        // forged contents don't hash to the committed root → rejected AT THE
        // CONTRACT, period.
        let mut forged = Account::new();
        forged.credit(USDC, Amount(5000)).unwrap();
        let (bmask, bsibs) = tree.prove(buyer());
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                buyer(),
                &forged,
                bmask,
                &bsibs,
                USDC,
                buyer_owner(),
            ),
            Err(SettleError::BadEscapeProof)
        );

        // The buyer can still withdraw their *real* proven 600 (also from DA).
        let buyer_acct = accounts.get(&buyer()).cloned().unwrap();
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                buyer(),
                &buyer_acct,
                bmask,
                &bsibs,
                USDC,
                buyer_owner(),
            )
            .unwrap(),
            Amount(600)
        );
        assert_eq!(c.total_escrow(USDC), 0); // pool fully and exactly drained
    }

    #[test]
    fn two_accounts_same_owner_can_both_escape() {
        let other = AccountId(Uuid::from_u128(0xC));
        let mut e = engine();
        let mut c = contract();

        let d1 = c
            .deposit(buyer(), USDC, Amount(100), buyer_owner())
            .unwrap();
        let d2 = c.deposit(other, USDC, Amount(50), buyer_owner()).unwrap();
        let o1 = e.step(vec![d1, d2]).unwrap();
        c.commit(o1.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        c.freeze();

        let accounts = crate::da::reconstruct(c.da_blobs());
        let tree = StateTree::from_accounts(Sha256Hasher, accounts.iter());
        let buyer_acct = accounts.get(&buyer()).cloned().unwrap();
        let other_acct = accounts.get(&other).cloned().unwrap();
        let (bmask, bsibs) = tree.prove(buyer());
        let (omask, osibs) = tree.prove(other);

        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                buyer(),
                &buyer_acct,
                bmask,
                &bsibs,
                USDC,
                buyer_owner(),
            )
            .unwrap(),
            Amount(100)
        );
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                other,
                &other_acct,
                omask,
                &osibs,
                USDC,
                buyer_owner(),
            )
            .unwrap(),
            Amount(50)
        );
        assert_eq!(c.total_escrow(USDC), 0);
    }

    #[test]
    fn frozen_rejects_deposit_and_commit() {
        let mut e = engine();
        let mut c = contract();
        c.freeze();
        assert_eq!(
            c.deposit(buyer(), USDC, Amount(1), buyer_owner()),
            Err(SettleError::Frozen)
        );
        let outcome = e
            .step(vec![Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1),
                nonce: 0,
                owner: buyer_owner(),
                trading_key: None,
            }])
            .unwrap();
        assert_eq!(c.commit(outcome.proposal()), Err(SettleError::Frozen));
    }

    #[test]
    fn deposit_rejects_non_positive() {
        let mut c = contract();
        assert_eq!(
            c.deposit(buyer(), USDC, Amount(0), buyer_owner()),
            Err(SettleError::NonPositiveAmount)
        );
        assert_eq!(
            c.deposit(buyer(), USDC, Amount(-1), buyer_owner()),
            Err(SettleError::NonPositiveAmount)
        );
    }

    #[test]
    fn verify_nothing_pending_and_withdrawals_root_lookup() {
        let mut c = contract();
        assert_eq!(
            c.verify_next(&Sha256Hasher),
            Err(SettleError::NothingToVerify)
        );
        assert!(c.withdrawals_root(0).is_none());
        let mut e = engine();
        let dep = c.deposit(buyer(), USDC, Amount(10), buyer_owner()).unwrap();
        let o = e.step(vec![dep]).unwrap();
        c.commit(o.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        assert!(c.withdrawals_root(0).is_some());
        assert!(c.withdrawals_root(1).is_none());
    }

    #[test]
    fn escape_rejects_unfrozen_and_zero_balance() {
        let mut e = engine();
        let mut c = contract();
        let dep = c.deposit(buyer(), USDC, Amount(10), buyer_owner()).unwrap();
        let o = e.step(vec![dep]).unwrap();
        c.commit(o.proposal()).unwrap();
        c.verify_next(&Sha256Hasher).unwrap();
        let accounts = crate::da::reconstruct(c.da_blobs());
        let tree = StateTree::from_accounts(Sha256Hasher, accounts.iter());
        let buyer_acct = accounts.get(&buyer()).cloned().unwrap();
        let (mask, sibs) = tree.prove(buyer());
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                buyer(),
                &buyer_acct,
                mask,
                &sibs,
                USDC,
                buyer_owner(),
            ),
            Err(SettleError::NotFrozen)
        );
        c.freeze();
        assert_eq!(
            c.escape_withdraw(
                &Sha256Hasher,
                buyer(),
                &buyer_acct,
                mask,
                &sibs,
                BTC,
                buyer_owner(),
            ),
            Err(SettleError::NothingToWithdraw)
        );
    }
}
