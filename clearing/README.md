todo:  3. Target the actual new bottleneck — shrink the witness (the 128-deep sibling paths are the heavy part of the 2.7M). That's where further cycle wins now live.


# clearing

The deterministic **account / state layer** of the validity-exchange protocol —
the post-trade ("clearing") half orderlib was missing. It maintains a unified account state
(`balances` + `positions`), applies settlement behind a per-instrument dispatch
seam, and (in later phases) commits the result to a Merkleized state root that a
validity proof can re-derive.

It is an **off-path consumer** of the committed log: matching and ordering
happen upstream in the sequencer + book; this layer only moves balances and
positions. See `../docs/zk-validity-feasibility.md` for *why* settlement is
off-path (and why best execution is an ordering property, not an execution one),
and `../docs/unified-instrument-model.md` for the unified-instrument model.

## Matching vs settlement

The load-bearing boundary: **matching is instrument-agnostic; settlement is
instrument-specific.** An order is `{market, side, price, qty}` regardless of
underlying; what differs per instrument (spot = balance swap; perp = funding +
margin; future = expiry) lives entirely here, behind the `Settlement` trait.

## Adding an instrument type (the linear-extension checklist)

Per `../docs/unified-instrument-model.md` §7, adding a type is additive and
never refactors the core:

1. Add a variant to `instrument::SettlementKind`.
2. Add an arm to `settlement::handler` returning the new handler.
3. Implement `settlement::Settlement` for it in a new module under
   `src/settlement/`.
4. (Optional) add any time-varying globals to `instrument::MarketGlobals`.

If a new type forces an edit to `account.rs`, `state.rs`, the commitment, or the
dispatch site itself, the seam is wrong — fix it before the second type ships.

## Status

Phase 0–5 of `../docs/settlement-crate-v0-plan.md`: fixed-point `Amount` + ids,
the `Account` model, the `Settlement` seam + `SpotSwap` beachhead impl, the
transactional `State` machine (`Tx` apply with rollback), the Merkleized
`StateTree` commitment (`Hasher` seam + sha2, incremental `apply_delta` with a
from-scratch rebuild cross-check), the prover/witness seam (`Witness`, `Prover`,
and the `ReplayProver` stub that verifies a transition by Merkle paths alone),
and the `TxSource` + `Engine` replay loop. Run the demo:

```
cargo run -p clearing --example spot_demo
```

Phase 6 (hardening + the extensibility-proof test) is the remaining v0 step.
