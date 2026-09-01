//! The instrument descriptor and the [`SettlementKind`] discriminator.
//!
//! This is the **open** half of the Option A seam
//! (`../docs/unified-instrument-model.md` §7.2): adding an instrument type is a
//! new [`SettlementKind`] variant plus a [`crate::settlement::Settlement`] impl
//! plus (optionally) new [`MarketGlobals`] fields — and nothing in the closed
//! core changes.

use serde::{Deserialize, Serialize};

use crate::id::{AssetId, InstrumentId};

/// Selects the settlement rule for an instrument. The settlement engine
/// dispatches on this; the matching layer never sees it.
///
/// v0 ships exactly one variant. New product families (perpetual, dated
/// future, option) are added here as additional variants — the dispatch *site*
/// is fixed, only the arms grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementKind {
    /// Spot: a fill is an atomic swap of base and quote balances. No funding,
    /// no oracle, no margin.
    SpotSwap,
}

/// Static description of a tradable instrument. One market trades exactly one
/// instrument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instrument {
    pub id: InstrumentId,
    pub kind: SettlementKind,
    /// The asset being traded (e.g. BTC).
    pub base: AssetId,
    /// The asset it is priced/settled in (e.g. USDC).
    pub quote: AssetId,
    /// Decimal scale (base-units exponent) of base/quote. Carried for
    /// completeness and future rounding logic; spot v0 settles in raw base
    /// units and does not rescale.
    pub base_scale: u8,
    pub quote_scale: u8,
}

/// Per-market, time-varying global state read by settlement. Empty for spot;
/// funding indices, mark/index prices, expiry, and open interest live here for
/// derivatives — hoisted out of the account leaf so a spot path never touches
/// funding logic (`../docs/unified-instrument-model.md` §5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketGlobals {
    // intentionally empty in v0
}
