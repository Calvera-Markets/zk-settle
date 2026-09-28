# zk-settlement

Clearing for a validity exchange: the post-trade slice. Matching and the order book live elsewhere.

An off-chain engine keeps balances, applies spot settlement, and commits a Merkle root. A Solana program holds Token-2022 vaults against that root. Users deposit on-chain; the matcher posts a Groth16 proof of a batch; users claim withdrawals from a per-batch tree. If the matcher stalls, freeze plus an inclusion proof against the last committed root lets a user escape.

This repo is the clearing slice only. There is no matcher or order book here. v0 settlement is spot.

## Layout

Four Cargo workspaces. The root workspace only builds the native spec:

```
members = ["clearing"]
exclude = ["clearing-zkvm", "clearing-circuits", "clearing-solana"]
```

| Path | Role |
| --- | --- |
| `clearing/` | Account state, spot settlement, SHA-256 sparse Merkle tree, `ExecutingProver`, mock L1 |
| `clearing-zkvm/` | SP1 guest: same `ExecutingProver`, 144-byte public values |
| `clearing-circuits/` | Laptop Groth16/BN254 (Poseidon tree, BabyJubJub auth) |
| `clearing-solana/` | Pinocchio program: custody, settle, claim, freeze/escape |

`cargo build --workspace` at the repo root only builds `clearing`.

## Native spec (`clearing`)

Integer amounts, checked arithmetic. Accounts are `balances + positions` behind a `Settlement` trait. Spot is implemented; a new instrument is a new `SettlementKind` arm plus a `Settlement` impl.

The SHA-256 tree is keyed by account UUID. Depth is compile-time `CLEARING_TREE_DEPTH` (default **128**). The zkVM workspace pins **8** so execute / CORE prove stay small.

Trades are ed25519-authenticated (maker, taker, matcher). `ExecutingProver` re-applies the batch and binds execution plus withdrawal messages to the leaves.

Guest public values (144 bytes):

```
prev_root (32) || new_root (32) || withdrawals_root (32)
|| matcher_key (32) || batch_seq_le (8) || expiry_height_le (8)
```

```sh
cargo test -p clearing
cargo run -p clearing --example spot_demo
```

## SP1 guest (`clearing-zkvm`)

Same prover as native Rust, compiled for SP1. Invalid witnesses panic. SHA-256 and ed25519 use SP1 precompiles.

From `clearing-zkvm/` (tree depth 8):

```sh
cargo run -p clearing-script --release --locked                 # execute, no proof
SP1_ALLOW_PROVE=1 ./target/release/clearing-host --prove       # CORE
```

`--groth16` wraps the whole SP1 recursion circuit (~20 min, tens of GB). It is not a unit test. Dump with `SP1_ALLOW_GROTH16=1` and `--dump-dir`. A recorded wrap lives in `clearing-solana/fixtures/sp1/` (`kat_sp1`).

## Circuits (`clearing-circuits`)

Hand-written Groth16 over BN254. Poseidon-over-BN254 tree and BabyJubJub EdDSA — same settlement *rules* as `clearing`, different leaf encoding. Laptop-safe (tens of seconds).

```sh
cd clearing-circuits
cargo test --release
cargo run --release --example e2e
```

## Solana program (`clearing-solana`)

Pinocchio 0.10. Program id: `AyALYha1o9u43sYybKhfgja7ZtSVXkqUzzVijgkYCm1`.

Token-2022 only, 82-byte mint layout, no extensions, no mint freeze authority. `admin` and `matcher_key` are different keys.

`proof_version` is set at initialize / `rotate_vk` and stays for that deployment:

| Version | Settle | Claim / escape |
| ---: | --- | --- |
| 1 | SP1 Groth16 wrap (356-byte proof) | SHA-256 Merkle path vs `withdrawals_root` / `root` |
| 2 | Circuits Groth16 (first 256 bytes) | Groth16 `ClaimOpenCircuit` (Poseidon leaf inside the proof) |

Version 2 uses a separate `open_vk_account` for claim/escape (`rotate_open_vk`). Solana never hashes Poseidon.

### Instructions

| Disc | Name |
| ---: | --- |
| 0 | `initialize` |
| 1 | `register_mint` |
| 2 | `deposit` |
| 3 | `settle` |
| 4 | `claim` |
| 5 | `freeze` |
| 6 | `escape_withdraw` |
| 7 | `set_admin` |
| 8 | `rotate_vk` |
| 9 | `verify_plain` |
| 10 | `rotate_open_vk` |

Test SBF is built with `--features mock-proof` (`proof_version = 0` skips pairing). Production must not enable that. Wrap settle is covered by `kat_sp1`. Circuits claim/settle through the vault is `circuits_e2e_settle_then_claim`.

```sh
cargo test --manifest-path clearing-solana/Cargo.toml
```

Do not `cargo test -p clearing-solana-program` from the repo root.

## Status

Shipped: spot clearing, SHA-256 tree, SP1 guest + wrap fixture, circuits Groth16, Solana custody with both proof modes, freeze/escape, solvency tests.

Not in this repo: perps/futures, matcher, order book.
