# clearing

Deterministic account and state layer for post-trade clearing. It keeps a unified account (`balances` + `positions`), applies settlement behind a per-instrument dispatch, and commits the result to a Merkleized state root that a validity proof can re-derive.

Matching and ordering happen upstream in the sequencer and book. This crate only moves balances and positions.

## Matching vs settlement

Matching is instrument-agnostic; settlement is instrument-specific. An order is `{market, side, price, qty}` regardless of underlying. What differs per instrument (spot = balance swap; perp = funding + margin; future = expiry) lives here, behind the `Settlement` trait.

## Adding an instrument type

1. Add a variant to `instrument::SettlementKind`.
2. Add an arm to `settlement::handler` returning the new handler.
3. Implement `settlement::Settlement` for it in a new module under `src/settlement/`.
4. Optionally add time-varying globals to `instrument::MarketGlobals`.

If a new type forces an edit to `account.rs`, `state.rs`, the commitment, or the dispatch site itself, the seam is wrong.

## Status

Fixed-point `Amount` and ids, the `Account` model, the `Settlement` seam with `SpotSwap`, transactional `State` (`Tx` apply with rollback), Merkle `StateTree` (`Hasher` seam + sha2, incremental `apply_delta` with a from-scratch rebuild check), the prover/witness seam (`Witness`, `Prover`, and `ReplayProver`, which verifies a transition by Merkle paths alone), and the `TxSource` + `Engine` replay loop.

```
cargo run -p clearing --example spot_demo
```
