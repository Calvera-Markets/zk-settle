//! The public error boundary for the settlement layer.

use thiserror::Error;

use crate::id::{AccountId, AssetId, MarketId};

/// Errors returned when applying settlement. These are *rejections* of a
/// transaction, not faults — the state machine stays consistent and the caller
/// learns precisely why a transaction did not apply.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SettlementError {
    /// Checked arithmetic over/underflowed. A guard against silent wraps on the
    /// replayable path; should not occur with well-scaled amounts.
    #[error("amount arithmetic overflow")]
    Overflow,

    /// A debit would drive a balance negative.
    #[error("account {account:?} has insufficient balance of asset {asset:?}")]
    InsufficientBalance { account: AccountId, asset: AssetId },

    /// A transaction referenced a market with no registered instrument.
    #[error("unknown market {0:?}")]
    UnknownMarket(MarketId),

    /// A negative or zero quantity where a positive one is required
    /// (deposit/withdraw amount, fill price/size).
    #[error("non-positive quantity where positive required")]
    NonPositiveQuantity,

    /// A deposit with this nonce was already credited (replay protection).
    #[error("duplicate deposit nonce {0}")]
    DuplicateDeposit(u64),

    /// An attempt to register a *different* trading key on an account that
    /// already has one (no rotation in v1).
    #[error("account already has a different trading key registered")]
    KeyAlreadyRegistered,

    /// A deposit's L1 owner does not match the owner already bound to the account.
    #[error("L1 owner does not match the account's bound owner")]
    OwnerMismatch,

    /// A trade referenced an account with no registered trading key, so its
    /// order could not be authorized.
    #[error("account {account:?} has no registered trading key")]
    MissingTradingKey { account: AccountId },

    /// A trade's orders/fill were structurally inconsistent (market, side, or
    /// party mismatch between the fill and the signed orders).
    #[error("trade orders are inconsistent with the fill")]
    OrderMismatch,

    /// A user order's signature did not verify against the account's key.
    #[error("invalid order signature")]
    InvalidOrderSignature,

    /// The matcher signature did not verify against the operator key (or no
    /// operator key is registered).
    #[error("invalid matcher signature")]
    InvalidMatcherSignature,

    /// An order was past its expiry at the current batch height.
    #[error("order expired")]
    OrderExpired,

    /// The fill's price violated an order's limit price.
    #[error("fill violates an order's limit price")]
    PriceViolation,

    /// Filling this trade would exceed an order's authorized `base_amount`
    /// (cumulatively, across fills).
    #[error("order over-filled beyond its authorized amount")]
    OrderOverfilled,
}
