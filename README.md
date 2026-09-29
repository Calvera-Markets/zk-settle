# ZeroSettle

[![CI](https://github.com/Calvera-Markets/zk-settlement/actions/workflows/ci.yml/badge.svg)](https://github.com/Calvera-Markets/zk-settlement/actions/workflows/ci.yml)
![coverage](badges/coverage.svg)

Scalable Solana on-chain settlement for off-chain order matching, using zero-knowledge proofs. Spot only for now, with plans for marginated trading. Spot clearing, SHA-256 tree, SP1 guest and wrap fixture, circuits Groth16, Solana custody with both proof modes, freeze/escape, solvency tests.

The settlement engine stays off-chain: it keeps balances, runs spot settlement, and commits a Merkle root. The Solana program holds Token-2022 vaults against that root. Users deposit on-chain. The matcher posts a Groth16 proof of a batch. Users claim withdrawals from a per-batch tree. If the matcher stalls, freeze plus an inclusion proof against the last committed root lets a user escape.

## Layout

Four Cargo workspaces. The root workspace is the native spec only:

```
members = ["clearing"]
exclude = ["zkvm", "circuits", "solana"]
```

| Path | Role |
| --- | --- |
| `clearing/` | Account state, spot settlement, SHA-256 sparse Merkle tree, `ExecutingProver`, mock L1 |
| `zkvm/` | SP1 guest: same `ExecutingProver`, 144-byte public values |
| `circuits/` | Laptop Groth16/BN254 (Poseidon tree, BabyJubJub auth) |
| `solana/` | Pinocchio program: custody, settle, claim, freeze/escape |

`just build` and `just test` therefore only touch `clearing`.

```sh
just test              # clearing
just test-circuits     # circuits, --release
just test-solana       # needs cargo-build-sbf
just coverage-all      # all four workspaces, writes badges/coverage.svg
```

## Native spec (`clearing`)

Integer amounts and checked arithmetic. Accounts are `balances + positions` behind a `Settlement` trait. Spot is implemented. A new instrument is a new `SettlementKind` arm plus a `Settlement` impl.

The SHA-256 tree is keyed by account UUID. Depth is compile-time `CLEARING_TREE_DEPTH` (default 128 in `clearing` and the Solana program). The zkVM workspace and the circuits crate default to 8 so execute, CORE prove, and Groth16 stay small.

Trades are authorized with ed25519 (maker, taker, and matcher over the fill). `ExecutingProver` re-applies the batch and binds execution plus withdrawal messages to the committed leaves.

Guest public values (144 bytes):

```
prev_root (32) || new_root (32) || withdrawals_root (32)
|| matcher_key (32) || batch_seq_le (8) || expiry_height_le (8)
```

```sh
just test
cargo run -p clearing --example spot_demo
```

## SP1 guest (`zkvm`)

The guest is that same prover, compiled for SP1. Invalid witnesses panic; no proof can be produced. SHA-256 and ed25519 use SP1 precompiles.

From `zkvm/` (tree depth 8):

```sh
cargo run -p clearing-script --release --locked                 # execute, no proof
SP1_ALLOW_PROVE=1 ./target/release/clearing-host --prove       # CORE
```

`--groth16` wraps the whole SP1 recursion circuit (about 20 minutes and tens of GB). That path is a fixture dump. Dump with `SP1_ALLOW_GROTH16=1` and `--dump-dir`. A recorded wrap is in `solana/fixtures/sp1/` (`kat_sp1`).

## Circuits (`circuits`)

Hand-written Groth16 over BN254, the curve Solana verifies with `alt_bn128`. The tree is Poseidon-over-BN254 and auth is BabyJubJub EdDSA. Settlement rules match `clearing`; leaf encoding does not. The suite is tens of seconds on a laptop.

```sh
just test-circuits
cargo run --manifest-path circuits/Cargo.toml --release --example e2e
```

## Solana program (`solana`)

Pinocchio 0.10. Program id: `AyALYha1o9u43sYybKhfgja7ZtSVXkqUzzVijgkYCm1`.

Custody is Token-2022 only. Mints and token accounts must be the 82-byte base layout: no extensions, and a freeze authority on the mint is rejected so an issuer cannot freeze the vault. `admin` and `matcher_key` are different keys.

`proof_version` is set at initialize / `rotate_vk` and stays for that deployment:

| Version | Settle | Claim / escape |
| ---: | --- | --- |
| 1 | SP1 Groth16 wrap (356-byte proof) | SHA-256 Merkle path vs `withdrawals_root` / `root` |
| 2 | Circuits Groth16 (first 256 bytes) | Groth16 `ClaimOpenCircuit` (Poseidon leaf inside the proof) |

Version 2 uses a separate `open_vk_account` for claim and escape (`rotate_open_vk`). Poseidon is never hashed on-chain.

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

The test SBF build uses `--features mock-proof` (`proof_version = 0` skips pairing). Leave that feature off for production deploys. Wrap settle is `kat_sp1`. Circuits settle then claim through the vault is `circuits_e2e_settle_then_claim`.

```sh
just test-solana
```

`cargo test -p clearing-solana-program` from the repo root fails; that package is not in the host workspace.
