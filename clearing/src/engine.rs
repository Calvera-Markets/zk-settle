//! The replay-loop driver — the v0 end-to-end deliverable.
//!
//! [`Engine`] owns the clearing [`State`], its [`StateTree`] commitment, and a
//! [`Prover`]. It pulls batches from a [`TxSource`], applies each one
//! (capturing a [`Witness`]), proves the transition, and emits a
//! [`BatchOutcome`] per batch. This is the core loop the off-path tailer runs;
//! swapping the synthetic source for a committed-log adapter and the
//! [`crate::prover::ReplayProver`] stub for a real backend leaves this loop
//! unchanged.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::commitment::{Hash, Hasher, StateTree};
use crate::contract::BatchProposal;
use crate::da::DaBlob;
use crate::id::{AccountId, MarketId};
use crate::instrument::Instrument;
use crate::prover::{Proof, ProveError, Prover, Witness};
use crate::source::TxSource;
use crate::state::State;
use crate::tx::{OnChainMessage, Tx};

/// The result of clearing one batch: the transactions, the [`Witness`] for the
/// transition, its [`Proof`], and the L1 [`OnChainMessage`]s (withdrawals) the
/// batch emitted. The `prev_root → new_root` pair lives on the witness;
/// [`BatchOutcome::prev_root`] / [`BatchOutcome::new_root`] expose it.
#[derive(Debug, Clone)]
pub struct BatchOutcome {
    pub txs: Vec<Tx>,
    pub witness: Witness,
    pub proof: Proof,
    pub messages: Vec<OnChainMessage>,
    /// The data-availability blob: the changed accounts' new contents, posted so
    /// state can be reconstructed from public data (escape hatch).
    pub da: DaBlob,
}

impl BatchOutcome {
    pub fn prev_root(&self) -> Hash {
        self.witness.prev_root
    }
    pub fn new_root(&self) -> Hash {
        self.witness.new_root
    }
    /// Package this outcome as a [`BatchProposal`] for the settlement contract
    /// (the witness to verify — which carries the proven withdrawal messages —
    /// plus the DA blob to publish).
    pub fn proposal(&self) -> BatchProposal {
        BatchProposal::new(self.witness.clone(), self.da.clone())
    }
}

/// The clearing engine: state + commitment + prover, driven by a [`TxSource`].
pub struct Engine<H: Hasher, P: Prover> {
    state: State,
    tree: StateTree<H>,
    prover: P,
}

impl<H: Hasher, P: Prover> Engine<H, P> {
    pub fn new(hasher: H, prover: P) -> Self {
        Self {
            state: State::new(),
            tree: StateTree::new(hasher),
            prover,
        }
    }

    /// Register the instrument a market trades (v0 admin path; do this before
    /// clearing trades on that market).
    pub fn register_market(&mut self, market: MarketId, instrument: Instrument) {
        self.state.register_market(market, instrument);
    }

    /// Register the operator/matcher key on the live state, so `step`'s capture
    /// enforces trade authorization. Must match the key the `prover` (and the
    /// contract's verifier) is configured with, or capture and re-verification
    /// disagree. (v0 admin path.)
    pub fn set_operator_key(&mut self, key: crate::auth::Ed25519PubKey) {
        self.state.set_operator_key(key);
    }

    /// The current committed state root.
    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    /// Read-only view of the clearing state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Clear one batch: apply it (capturing the witness) and prove the
    /// transition. A rejected transaction inside the batch simply contributes
    /// nothing (it left state untouched); a *proof* failure is returned as an
    /// error — it signals an inconsistent witness, which should never happen for
    /// an honestly-applied batch.
    pub fn step(&mut self, batch: Vec<Tx>) -> Result<BatchOutcome, ProveError> {
        let witness = Witness::capture(&mut self.state, &mut self.tree, &batch);
        let messages = witness.messages.clone();
        let proof = self.prover.prove(&witness)?;

        // The DA blob = the changed accounts' new contents. The witness already
        // names every changed leaf (by key); snapshot each one's current state.
        let mut seen = BTreeSet::new();
        let mut accounts = Vec::new();
        for u in &witness.updates {
            if seen.insert(u.key) {
                let id = AccountId(Uuid::from_u128(u.key));
                accounts.push((id, self.state.account(id).cloned()));
            }
        }
        accounts.sort_by_key(|(id, _)| *id);
        let da = DaBlob { accounts };

        Ok(BatchOutcome {
            txs: batch,
            witness,
            proof,
            messages,
            da,
        })
    }

    /// Drain a source, clearing and proving every batch in order. Returns the
    /// outcomes; stops at the first proof failure.
    pub fn run<S: TxSource>(&mut self, source: &mut S) -> Result<Vec<BatchOutcome>, ProveError> {
        let mut outcomes = Vec::new();
        while let Some(batch) = source.next_batch() {
            outcomes.push(self.step(batch)?);
        }
        Ok(outcomes)
    }
}
