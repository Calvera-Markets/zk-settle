//! The clearing transaction vocabulary — the input the state machine applies.
//!
//! These are the *settlement-relevant* events, decoupled from the matching
//! engine: account funding ([`Tx::Deposit`] / [`Tx::Withdraw`]) and a matched
//! trade ([`Tx::Trade`], carrying a [`Fill`] the book already produced). A later
//! adapter turns the sequencer's committed log + book fills into this stream
//! (the off-path tailer of `../docs/zk-validity-feasibility.md` §5); v0 feeds it
//! synthetically.

use crate::auth::{Ed25519PubKey, TradeAuth};
use crate::id::{AccountId, Amount, AssetId, L1Address, MarketId};
use crate::settlement::Fill;

/// An L1-bound effect a *verified* batch instructs the settlement contract to
/// perform. Currently only withdrawals: a [`Tx::Withdraw`] that successfully
/// debits an L2 balance emits one of these, and the contract releases the
/// matching escrow when the batch's proof verifies.
///
/// In a real validity rollup these are **public outputs of the SNARK**, so they
/// are cryptographically bound to the proven state transition and cannot be
/// forged. The v0 stub does not yet bind them (the `ReplayProver` proves only
/// the Merkle transition — see `prover.rs`), so the contract *trusts* the
/// engine-produced messages on a verified batch. Closing that gap is the real
/// prover's job; the message vocabulary and the release path are already in
/// their final shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OnChainMessage {
    /// Release `amount` of `asset` from escrow to `owner` on the L1 contract.
    Withdraw {
        owner: L1Address,
        asset: AssetId,
        amount: Amount,
    },
}

/// A single clearing transaction. Applied atomically by
/// [`crate::state::State::apply`]: it either fully applies or leaves state
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Tx {
    /// Credit an account with externally-deposited funds. Originated by the
    /// settlement contract, which escrows the funds and assigns `nonce`; the
    /// state machine credits each `nonce` **at most once** (replay protection),
    /// so a deposit can never be double-credited. (A real system also commits
    /// the processed-nonce set; v0 keeps it as state metadata — see
    /// `state.rs`.)
    Deposit {
        account: AccountId,
        asset: AssetId,
        amount: Amount,
        nonce: u64,
        /// The account's trading key, registered on the deposit that *creates*
        /// the account (folded into the first deposit — see
        /// `../docs/zkvm-trade-authentication-plan.md`). `None` on subsequent
        /// deposits; a `Some` that disagrees with an already-registered key is
        /// rejected (`KeyAlreadyRegistered`).
        trading_key: Option<Ed25519PubKey>,
    },
    /// Debit an account to withdraw funds out of the system.
    Withdraw {
        account: AccountId,
        asset: AssetId,
        amount: Amount,
    },
    /// Settle a matched trade in `market` between the fill's buyer and seller.
    ///
    /// `auth` carries the two signed orders + the matcher signature that
    /// authorize the fill (see [`crate::auth::TradeAuth`]). Boxed to keep the
    /// `Tx` enum small. It is **optional only for lower-level tests**: whenever an
    /// operator key is registered in the state (always, in production), a trade
    /// with `auth: None` — or with signatures that don't verify — is rejected.
    Trade {
        market: MarketId,
        fill: Fill,
        auth: Option<Box<TradeAuth>>,
    },
}

impl Tx {
    /// The accounts this transaction can mutate. The state machine snapshots
    /// exactly these before applying, so a rejected transaction rolls back
    /// without cloning unrelated state. For v0's transaction types the touched
    /// set is fully determined by the transaction itself.
    pub(crate) fn touched_accounts(&self) -> Vec<AccountId> {
        match self {
            Tx::Deposit { account, .. } | Tx::Withdraw { account, .. } => vec![*account],
            Tx::Trade { fill, .. } => {
                if fill.buyer == fill.seller {
                    vec![fill.buyer]
                } else {
                    vec![fill.buyer, fill.seller]
                }
            }
        }
    }
}
