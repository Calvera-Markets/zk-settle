//! `clearing` — the deterministic account/state layer of the validity-exchange
//! protocol (account-keeping, settlement, and — later — netting/margin: the
//! post-trade "clearing" half of an exchange).
//!
//! This crate maintains a **unified account state** (`balances` + `positions`)
//! and applies settlement deterministically behind a per-instrument dispatch
//! seam, so the *instrument type doesn't matter*: anything tradable in an
//! orderbook settles through the same machine. It is designed as an **off-path
//! consumer** of the sequencer's committed log — matching/ordering happen
//! upstream; this layer only moves balances and (later) positions, then commits
//! the result.
//!
//! See the design docs:
//! - `../docs/zk-validity-feasibility.md` — why settlement is off-path; why the
//!   guarantee is over ordering, not execution.
//! - `../docs/unified-instrument-model.md` — the Option A model (descriptor +
//!   dispatched settlement) and the §7 extensibility contract this code
//!   implements.
//! - `../docs/settlement-crate-v0-plan.md` — the phased plan; this is Phase 0–5
//!   (account model + settlement seam + state machine + commitment +
//!   prover/witness seam + the `TxSource` + engine replay loop).
//!
//! ## The seam (Option A)
//!
//! [`account::Account`] is `balances + positions` and never grows a third field
//! per instrument. [`instrument::SettlementKind`] tags each instrument;
//! [`settlement::handler`] dispatches to a [`settlement::Settlement`] impl.
//! Adding an instrument type is a new `SettlementKind` arm + a new `Settlement`
//! impl — no change to the account model, the dispatch site, or (later) the
//! commitment. v0 ships exactly one impl: [`settlement::spot_swap::SpotSwap`].
//!
//! ## Determinism
//!
//! Integer fixed-point amounts only (no floating point), ordered containers for
//! anything that feeds the commitment, checked arithmetic everywhere. This is
//! what lets a later validity proof re-derive the exact same state root.

pub mod account;
pub mod auth;
pub mod commitment;
pub mod contract;
pub mod da;
pub mod engine;
pub mod error;
pub mod id;
pub mod instrument;
pub mod prover;
pub mod settlement;
pub mod source;
pub mod state;
pub mod tx;

pub use auth::{Ed25519PubKey, Ed25519Signature, Order, SignedOrder, Side};
pub use commitment::{Hash, StateTree};
pub use da::DaBlob;
pub use contract::{BatchProposal, MockSettlementContract, SettleError};
pub use engine::{BatchOutcome, Engine};
pub use id::L1Address;
pub use prover::{ExecutingProver, Proof, Prover, ReplayProver, Witness};
pub use source::{SyntheticSource, TxSource};
pub use state::{State, StateDelta};
pub use tx::{OnChainMessage, Tx};
