//! Per-instrument settlement: [`Settlement`], [`Ledger`], and [`handler`].
//!
//! Matching produces a [`Fill`]. Settlement only moves the resulting
//! quantities. A new product is a [`Settlement`] impl plus a
//! [`crate::instrument::SettlementKind`] arm in [`handler`].

pub mod spot_swap;

use crate::account::Position;
use crate::error::SettlementError;
use crate::id::{AccountId, Amount, AssetId};
use crate::instrument::{Instrument, MarketGlobals, SettlementKind};

/// A matched trade handed to settlement by the matching layer. Settlement does
/// not match or price — it only moves the resulting quantities. The matcher
/// supplies the exact base and quote amounts exchanged, so settlement carries
/// no price/size/scale assumptions and no rounding (that lives in matching).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Fill {
    /// Receives `base_amount`, pays `quote_amount`.
    pub buyer: AccountId,
    /// Gives `base_amount`, receives `quote_amount`.
    pub seller: AccountId,
    /// Base asset moved buyer-ward (positive).
    pub base_amount: Amount,
    /// Quote asset moved seller-ward (positive).
    pub quote_amount: Amount,
}

/// Mutable multi-account view settlement writes through. Two-sided fills
/// (and later funding/liquidation) go through this instead of borrowing
/// [`crate::state::State`] accounts directly.
pub trait Ledger {
    /// Credit `amount` (positive) of `asset` to `account`.
    fn credit(
        &mut self,
        account: AccountId,
        asset: AssetId,
        amount: Amount,
    ) -> Result<(), SettlementError>;

    /// Debit `amount` (positive) of `asset` from `account`; fails rather than
    /// going negative.
    fn debit(
        &mut self,
        account: AccountId,
        asset: AssetId,
        amount: Amount,
    ) -> Result<(), SettlementError>;
}

/// Per-instrument settlement rule. [`handler`] dispatches on
/// [`SettlementKind`]; matching never sees this.
///
/// `apply_fill` moves balances/positions for a trade. `position_value` is a
/// position's contribution to account value (zero for spot). Funding ticks and
/// expiry are state-level txs on [`MarketGlobals`], not methods here.
pub trait Settlement {
    /// Apply a matched `fill` to the ledger under the given instrument/globals.
    fn apply_fill(
        &self,
        instrument: &Instrument,
        globals: &MarketGlobals,
        ledger: &mut dyn Ledger,
        fill: &Fill,
    ) -> Result<(), SettlementError>;

    /// Position contribution to account value. Spot has no positions (zero);
    /// derivatives mark to market here.
    fn position_value(
        &self,
        instrument: &Instrument,
        globals: &MarketGlobals,
        position: &Position,
    ) -> Amount;
}

/// Map a [`SettlementKind`] to its handler. A new instrument type adds one
/// arm and one impl module.
pub fn handler(kind: SettlementKind) -> &'static dyn Settlement {
    static SPOT_SWAP: spot_swap::SpotSwap = spot_swap::SpotSwap;
    match kind {
        SettlementKind::SpotSwap => &SPOT_SWAP,
    }
}
