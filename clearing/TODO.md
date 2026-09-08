# clearing — TODO

Tracks the v0 build against `../docs/settlement-crate-v0-plan.md`. (Crate named
`clearing` — the post-trade half of an exchange: account-keeping, settlement,
and later netting/margin.)

## Done

- **Phase 0 — scaffold.** Crate + workspace wiring; `id.rs` (fixed-point
  `Amount`, checked arithmetic, ids); `error.rs`.
- **Phase 1 — account model + settlement seam.** `account.rs`
  (`Account { balances, positions }`, `Position`); `instrument.rs`
  (`Instrument`, `SettlementKind`, `MarketGlobals`); `settlement/` (the
  `Settlement` trait, `Ledger`, `Fill`, the `handler` dispatch site); `SpotSwap`
  impl.
- **Phase 2 — state machine.** `tx.rs` (`Tx`: Deposit/Withdraw/Trade);
  `state.rs` (`State` implements `Ledger`; `apply` dispatches via `handler`;
  **transactional** via touched-account snapshot/rollback; `StateDelta` of
  changed accounts for the commitment). Property tests: value conservation
  (`tests/conservation.rs`), determinism (`tests/determinism.rs`).
- **Phase 3 — commitment.** `commitment/` — `Hasher` trait + `Sha256Hasher`
  (leaf/node domain separation); `canonical_encode` (versioned, fixed-width LE,
  sorted); sparse Merkle `StateTree` (depth 128 over the account UUID, default
  hashes for empty subtrees); `root()`; incremental `apply_delta`; `from_state`
  rebuild. Cross-check: `tests/commitment_rebuild.rs` (incremental root ==
  rebuild over arbitrary tx sequences).

- **Phase 4 — prover/witness seam.** `prover.rs` — `Witness` (prev/new root +
  ordered `LeafUpdate`s with sibling paths) built by `Witness::capture`; `Prover`
  trait + `Proof`; `ReplayProver` stub that verifies the transition **by paths
  alone** (chained single-leaf Merkle proofs, correct under shared paths).
  Execution-binding (new leaves = txs applied to prior state) is left to the real
  backend — see module docs. Tests: accept valid + reject tampered
  root/sibling/leaf; `tests/prover_roundtrip.rs` (any batch verifies and its
  root matches a rebuild).

- **Phase 5 — source + replay loop.** `source.rs` (`TxSource` trait +
  `SyntheticSource`); `engine.rs` (`Engine` owns state + commitment + prover;
  `step`/`run` clear and prove batches, emitting `BatchOutcome`s carrying
  `prev_root`/`new_root`/witness/proof). End-to-end: `tests/replay_loop.rs`
  (root chain + exact balances + rebuild) and a runnable `examples/spot_demo.rs`
  that prints the root chain.

## Settlement track (`../docs/settlement-l1-plan.md`)

- **S1 — mock settlement contract (done).** `contract.rs` —
  `MockSettlementContract`: escrow custody, canonical root, `commit`
  (chain-checked) + `verify_next` (advances root **only on a valid proof** via
  the `Prover` seam), and `is_solvent` (escrow == Σ L2 balances).
- **S3 — withdrawal binding (done).** Withdrawals are proof-authorized:
  `OnChainMessage::Withdraw` is emitted by the engine **only for a
  successfully-applied `Tx::Withdraw`** (routed to `AccountId::l1_owner`), rides
  the `BatchProposal`, and `verify_next` releases escrow for it **after the proof
  verifies** (pre-validated so a batch fully finalizes or not at all). `release`
  is now private — there is no operator-callable drain. Tests:
  `withdrawal_releases_escrow_on_verify`, `over_withdrawal_emits_no_message...`,
  and `tests/settlement_e2e.rs::fail_spoof_withdraw`. *Honesty note:* the stub
  proof does not yet cryptographically bind the messages (it proves only the
  Merkle transition); the contract trusts engine-emitted messages on a verified
  batch — a real SNARK binds them as public outputs. See `tx.rs` / `prover.rs`.

- **S2 — deposit binding (done).** `Tx::Deposit` carries a `nonce`;
  `contract.deposit(account, asset, amount)` escrows under the account's L1 owner
  and **issues** the nonce'd deposit tx for the engine to include; the L2 credit
  is final only once the batch verifies. `State` dedups deposit nonces
  (`applied_deposits`), so a deposit is never double-credited
  (`duplicate_deposit_nonce_rejected`). `settlement_e2e` now sources deposits
  from the contract. *Honesty note:* like withdrawals, the stub doesn't yet bind
  the L2 credit to the escrow event cryptographically — the contract being the
  sole nonce issuer keeps them paired in the honest pipeline; a real SNARK makes
  the deposit queue a public input.

- **Escrow is a per-asset pool, not per-depositor (fix).** Withdrawals (normal
  and escape) are paid from the asset pool against *proven entitlement*, not from
  the withdrawer's own deposit — otherwise a user whose balance came via trading
  couldn't be paid. `total_escrow(asset)` is the pool.
- **S5 — escape hatch (done, the "withdraw yourself" path).** `freeze()` halts
  commit/verify; `escape_withdraw(hasher, account, proven, siblings, asset)` lets
  a user pull funds **directly from the contract** by proving their account
  against the frozen root (`root_from_path` + `canonical_encode`). An unlawful
  claim (forged/inflated balance) fails at the contract with `BadEscapeProof`;
  double-escape → `AlreadyEscaped`. `StateTree::prove` produces the inclusion
  path. Test: `escape_hatch_self_withdraw_and_rejects_forgery`.

- **Data availability (done).** `da::DaBlob` (changed accounts' new contents per
  batch); the engine emits it, `BatchProposal` carries it, `verify_next`
  publishes it (`contract.da_blobs()`). `da::reconstruct` + `StateTree::from_accounts`
  rebuild account state from blobs alone. The escape-hatch test now reconstructs
  from the contract's published DA (not `engine.state()`) and asserts the
  reconstructed root matches before withdrawing. v0 posts full account contents;
  a real system compresses to minimal deltas + Ethereum blobs.

- **zkVM step 1 — executing verifier (done).** `Witness` is now self-contained
  (`prev_accounts`, `txs`, `instruments`, `messages`); `State::for_replay`
  re-executes a batch in isolation; `commitment::leaf_hash` is the shared
  account→leaf. `ExecutingProver` re-executes and binds execution + messages to
  the committed leaves — a forged/unbacked withdrawal message that `ReplayProver`
  accepts is now rejected. This is the future zkVM **guest body** in pure Rust.
  (Real SP1/RISC0 proof = steps 2–4 of `../docs/zkvm-prover-plan.md`, toolchain
  permitting.) Tests in `prover.rs`.
- **Contract releases bound to proven messages (done).** Withdrawal messages now
  live **inside the witness** (`Witness::messages`), not a separate forgeable
  `BatchProposal` field; `verify_next` releases from `batch.witness.messages`. The
  contract verifies with `ExecutingProver`, so a malicious operator who forges a
  withdrawal message onto an honest batch is rejected **at the contract** —
  `contract_rejects_forged_withdrawal_message`. The message-trust gap is now
  closed natively (the SNARK later makes the same check succinctly verifiable
  on-chain). `settlement_e2e` runs against `ExecutingProver`.

- **zkVM step 2 prep — `Witness` is serde-(de)serializable (done).** Added
  `Serialize`/`Deserialize` to `Witness` + `LeafUpdate`/`Tx`/`Fill`/
  `OnChainMessage`/`DaBlob`/`BatchProposal`, with a round-trip test
  (`witness_serde_round_trips`). An SP1 guest reads its `Witness` input via serde,
  so this is the prerequisite for the guest.

## Next

- **zkVM steps 2–4 (toolchain-gated).** Concrete guest + host + Solana Groth16
  verifier reference is in `../docs/zkvm-prover-plan.md` ("Steps 2–4
  implementation guide"). The guest body is `ExecutingProver` (done); what
  remains is the SP1 wrapper + Solana program, which need the `sp1` toolchain
  (not available in this env) and must be checked against the installed SP1
  version. Target a **Groth16** wrapped proof (Solana-verifiable via alt_bn128).
- **Phase 6 — hardening + extensibility proof.** Determinism across process
  restarts; `tests/extensibility.rs` adds a stub `SettlementKind` without
  editing core; document the checklist.
- **S4 — priority txs + inclusion deadline.** Forced-inclusion queue on the
  contract; missed deadline auto-triggers `freeze()` (the real escape-hatch
  trigger, vs the explicit `freeze()` today).
- **Normal per-user claim.** Today `verify_next` still releases all withdrawal
  messages in one loop (fine for the mock, won't scale on-chain). Real design:
  verify records claimable; each user calls a per-user `claim()` (same Merkle
  check as `escape_withdraw`, against the live root). Unifies with the escape
  hatch.
- **S6 — solvency property test + full end-to-end (done).**
  `tests/solvency.rs` proptests random deposit/trade/withdraw/claim/freeze/escape
  sequences against `is_solvent` at every settled point. `tests/settlement_e2e.rs`
  `operator_dark_e2e_reconstructs_from_da` is the scripted operator-dark exit
  (DA reconstruct, both users escape, pending-claim term still counted).
  S4 (deadline auto-freeze) is not this.

## Deferred (final)

The real on-chain contract (EVM, real verifier, calldata/blobs), the real SNARK
prover backend, Poseidon2, perp/future/option settlement, funding/oracle/margin,
and the live committed-log adapter (the `TxSource` seam stands in).
