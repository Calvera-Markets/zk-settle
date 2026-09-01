//! The settlement seam: the [`Settlement`] trait every instrument type
//! implements, the [`Ledger`] it acts through, and the fixed dispatch site
//! ([`handler`]).
//!
//! This module is the open/closed boundary of the Option A design
//! (`../docs/unified-instrument-model.md` §7). The trait, the [`Ledger`]
//! interface, and the [`handler`] dispatch are **closed** — adding an
//! instrument type never edits them. A new type is a new [`Settlement`] impl
//! (in a sibling module) plus a [`crate::instrument::SettlementKind`] arm in
//! [`handler`].

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

/// A mutable, multi-account view settlement acts through. Decoupling settlement
/// from the concrete state container (a) avoids double-mutable-borrow gymnastics
/// when a fill touches two accounts, and (b) keeps the door open for settlement
/// that touches many accounts at once (funding, liquidation) without changing
/// the [`Settlement`] signatures. The [`crate::state::State`] machine implements
/// this in Phase 2.
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

/// The per-instrument settlement rule. Dispatched by [`handler`] on the
/// instrument's [`SettlementKind`]; the matching layer never sees it.
///
/// v0 declares the two methods spot needs and a margin engine will need:
/// `apply_fill` (mutate balances/positions for a trade) and `position_value`
/// (a position's contribution to account value). Scheduled market-global events
/// (funding ticks, expiry) are modeled separately as state-level transactions
/// that mutate [`MarketGlobals`], with per-position lazy reconciliation — so no
/// broad-sweep trait method is needed here.
pub trait Settlement {
    /// Apply a matched `fill` to the ledger under the given instrument/globals.
    fn apply_fill(
        &self,
        instrument: &Instrument,
        globals: &MarketGlobals,
        ledger: &mut dyn Ledger,
        fill: &Fill,
    ) -> Result<(), SettlementError>;

    /// A position's contribution to account value, for the (later) margin
    /// check. Spot has no positions, so this is zero; derivatives mark to
    /// market here.
    fn position_value(
        &self,
        instrument: &Instrument,
        globals: &MarketGlobals,
        position: &Position,
    ) -> Amount;
}

/// The fixed dispatch site: map a [`SettlementKind`] to its handler. Adding an
/// instrument type adds exactly one arm here and one impl module — the linear
/// extension point (`../docs/unified-instrument-model.md` §7.2).
pub fn handler(kind: SettlementKind) -> &'static dyn Settlement {
    static SPOT_SWAP: spot_swap::SpotSwap = spot_swap::SpotSwap;
    match kind {
        SettlementKind::SpotSwap => &SPOT_SWAP,
    }
}
