# circuits

Hand-written Groth16 circuits over BN254 (the curve Solana verifies with `alt_bn128`). Own workspace, not in the root `clearing` members.

Native arkworks, no zkVM. The test suite is tens of seconds on a laptop.

The settlement *rule* matches `clearing::settlement::SpotSwap`. The commitment does not: this crate uses a dense Poseidon-over-BN254 tree and BabyJubJub app-keys; `clearing` uses a sparse SHA-256 tree and ed25519.

```
cargo test --release
cargo run --release --example e2e
```

`examples/e2e.rs` builds a batch of spot swaps, runs setup / prove / verify against the endpoint roots, cross-checks each trade against the integer spec in `reference.rs`, and encodes the proof for `alt_bn128`.

## Circuits

- `MerkleInclusionCircuit` — leaf + path = public `root`
- `WithdrawTransitionCircuit` — one account, range-checked withdraw, `prev_root` → `new_root`
- `TradeTransitionCircuit` — two-account spot swap (chained Merkle update)
- `BatchTradeCircuit` — `BATCH_SIZE` swaps, public inputs `prev_root` and `new_root` only
- `ClaimOpenCircuit` — `Poseidon(owner, asset, amount)` is in `root` (Solana `proof_version = 2` claim)
- `CommitRootsCircuit` — public `prev_root`, `new_root`, `withdrawals_root` with `prev == new`
- `AuthedTradeCircuit` — swap plus three in-circuit BabyJubJub signatures (buyer, seller, matcher)

Hash is Poseidon over BN254 `Fr` (arkworks native + gadget, same config). EdDSA is in `eddsa.rs`. Wire encoding is in `solana.rs`.

## Notes

Poseidon round constants and MDS come from arkworks' Grain LFSR, not the circomlib/EIP set. Interop with an on-chain Poseidon needs those standard parameters pinned.

`DEPTH` is 8 here. A production tree is deeper or uses dense indices.

The EdDSA scheme is a custom Poseidon-challenge construction; it is tested, not audited.
