//! Instrument type and settlement dispatch.
//!
//! Matching sees `{market, side, price, qty}`. What a fill does to balances
//! is chosen here via [`SettlementKind`]. A new product is a new variant plus
//! a [`crate::settlement::Settlement`] impl; account state and the commitment
//! stay unchanged.

use serde::{Deserialize, Serialize};

use crate::id::{AssetId, InstrumentId};

/// Settlement rule for an instrument. The engine dispatches on this; matching
/// never sees it.
///
/// v0 has [`SettlementKind::SpotSwap`] only. Perps, dated futures, and options
/// are extra variants on the same enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementKind {
    /// Atomic swap of base and quote balances. No funding, oracle, or margin.
    SpotSwap,
}

/// Static description of a tradable instrument. One market trades exactly one
/// instrument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instrument {
    pub id: InstrumentId,
    pub kind: SettlementKind,
    /// Asset being traded (e.g. BTC).
    pub base: AssetId,
    /// Asset it is priced and settled in (e.g. USDC).
    pub quote: AssetId,
    /// Decimal scale of base/quote. Spot v0 settles in raw units and does not
    /// rescale; the fields are here for later rounding.
    pub base_scale: u8,
    pub quote_scale: u8,
}

/// Per-market, time-varying state settlement can read. Empty for spot.
/// Funding, mark/index, expiry, and open interest go here for derivatives so
/// a spot path never touches them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketGlobals {
    // empty in v0
}
