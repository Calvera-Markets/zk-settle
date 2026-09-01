# clearing-circuits

The **custom-circuit** path (the "Lighter-style" approach): hand-written
arithmetic constraints proven with **Groth16 over BN254** (the curve a Solana
program can verify via `alt_bn128`). Its own workspace, excluded from orderlib.

Chosen deliberately over the zkVM after the debate in
`../docs/problem-and-strategy-debate.md`. This is the higher-effort, higher-risk
route — built in small, auditable slices.

Native arkworks Groth16 (not SP1), so this is **laptop-safe**: there is no
dangerous proving flag, and the whole test suite runs in ~50s (Poseidon is heavy,
but it is all native — no `--prove`).

## Run the end-to-end example

```
cargo run --release --example e2e
```

`examples/e2e.rs` is the runnable top-level driver — the counterpart to the zkVM
host (`../clearing-zkvm/script/src/main.rs`). It builds a batch of spot swaps and
the prev/new roots (the witness), runs trusted-setup → **prove** → **verify**
(exposing only the endpoint roots — the rollup property), cross-checks each trade
against the independent Rust spec, and encodes the proof/VK/inputs into the
Solana `alt_bn128` wire format. The same steps the tests exercise, in one
readable flow.

The math and process behind each step — the field, Poseidon, the Merkle
commitment, the range checks, the chained multi-leaf update, Groth16, and the
on-chain encoding — is written up in `../docs/circuit-e2e-math.md`.

## Status

- **Slice 1 — Merkle inclusion (done).** `MerkleInclusionCircuit` proves "folding
  a `leaf` up its Merkle path with the given siblings yields the public `root`."
  Real `circuit_specific_setup` → `prove` → `verify`, plus a constraint-system
  test that a tampered witness is unsatisfiable. The foundation of any
  state-validity proof (an account is in the committed root).
- **Slice 3a — withdrawal transition (done).** `WithdrawTransitionCircuit` proves
  a single-account, **range-checked** balance change: account `id` held `balance`
  in `prev_root`; withdrawing `withdraw <= balance` leaves `balance - withdraw`;
  `new_root` updates only that leaf. Introduces the soundness-critical primitive
  — `enforce_u64` (a range check is how a field circuit proves "no underflow").
  Tests: real prove/verify; `overdraw_is_unsatisfiable` (the range check rejects
  an underflow even when the roots are otherwise consistent).
- **Slice 3b — trade transition (done).** `TradeTransitionCircuit` proves a
  two-account **spot swap**: buyer pays `quote_amount`, receives `base_amount`;
  seller does the reverse. Both accounts live in the *same* tree, so the Merkle
  update is **multi-leaf** — handled as a **chained update** (buyer
  `prev_root → mid_root`, then seller `mid_root → new_root`, the seller's path
  supplied as-of-`mid_root`), exactly the chaining the zkVM witness uses. Leaf
  now binds two balances: `hash(hash(id, base), quote)`. Conservation is automatic
  (the same amounts move both ways); the only soundness gates are two range checks
  — buyer can afford the quote, seller can afford the base. Tests: real
  prove/verify with an in-test dense Merkle tree (`TestTree`) producing real
  prev/mid/new roots; `trade_seller_overdraw_is_unsatisfiable` (seller can't
  afford the base even with otherwise-consistent roots).
- **Slice 3c — batch (done).** `BatchTradeCircuit` folds `BATCH_SIZE` spot swaps
  into one proof, exposing **only the endpoint roots** (`prev_root`, `new_root`) —
  the rollup property. It threads a running root from `prev_root` through every
  trade via the shared `trade_step_gadget` (the single authoritative encoding of a
  swap, also used by `TradeTransitionCircuit`) and proves the final root equals
  `new_root`. The per-trade ids/amounts/balances/paths are all witness. Tests:
  real prove/verify over a 4-trade chain built through `TestTree`;
  `batch_with_one_overdraw_is_unsatisfiable` (a single mid-batch underflow voids
  the whole proof). A real rollup pads the tail with no-op trades to keep one
  fixed circuit shape; here `BATCH_SIZE` is small and concrete.

- **Slice 2 — real Poseidon (done).** The placeholder MiMC-style `hash2` is
  replaced by a real **Poseidon sponge over BN254 `Fr`** (width t=3 = rate 2 +
  capacity 1, x⁵ S-box, 8 full + 57 partial rounds) via arkworks'
  `ark-crypto-primitives`, which ships *matched* native + R1CS-gadget Poseidon —
  so `hash2` and `hash2_gadget` agree by construction (the
  `native_and_gadget_poseidon_agree` test locks this). The circuit *shape* is
  unchanged; every slice 1/3a/3b/3c circuit now proves over Poseidon. (BN254-field
  Poseidon, *not* the BabyBear `Poseidon2Hasher` in `clearing` — different regime;
  see `../docs/zkvm-vs-circuits-and-hashing.md`.) Note: Poseidon is far heavier on
  constraints than the placeholder, so the test suite now runs in ~30s (still
  native, no `--prove`).

- **Slice 4 — match the spec + Solana wire format (done).** Two parts:
  - **4a — differential spec (`reference.rs`).** A plain-integer `TradeScenario`
    re-implements the spot-swap settlement rule — independently of the circuit —
    and `circuit_matches_reference_over_random_trades` asserts the circuit's
    satisfiability equals the reference's accept/reject over a biased random
    sweep (zeros, affordable/unaffordable, near-`u64::MAX` overflow). The module
    documents how `trade_step_gadget` corresponds to `clearing::ExecutingProver`'s
    execution-binding logic (reconstruct prior leaf → check vs root → apply
    `SpotSwap` → fold to next root), and the one deliberate divergence (zero-amount
    no-ops: rejected by `clearing` at matching, harmless to circuit validity —
    `nonzero_amounts_are_the_only_divergence_from_clearing`).
  - **4b — Solana / `alt_bn128` wire format (`solana.rs`).** Encodes the Groth16
    proof, VK, and public inputs into the **big-endian, uncompressed affine** byte
    layout the `alt_bn128` syscalls / `groth16-solana` consume (G2 in EIP-197
    imaginary-first order). `proof_round_trips_through_solana_wire_format_and_reverifies`
    encodes a real proof to bytes, decodes it, and re-verifies — proving the
    encoding is faithful and invertible; `g1_g2_codecs_are_invertible` checks
    point identity directly.

- **Slice 5a — BabyJubJub EdDSA signatures (done).** `eddsa.rs` adds a
  Schnorr/EdDSA-Poseidon signature over **BabyJubJub** (`ark_ed_on_bn254`, a
  twisted-Edwards curve whose base field *is* BN254's scalar field), with native
  `sign`/`verify` and an in-circuit `verify_gadget` (`s·B == R + e·A`, challenge
  `e = Poseidon(R, A, msg)`). This is what makes *authenticated* trades provable
  on a laptop: **~6,800 constraints per signature** (measured), versus *millions*
  for native ed25519 in-circuit. Trade-off: users sign with a registered
  BabyJubJub app-key, not their L1 wallet key. Tests: native sign/verify,
  `gadget_matches_native`, `gadget_rejects_forgery` (wrong message / tampered
  `s`), and a constraint-count report. **Unaudited custom construction** — see the
  module's honesty notes (cofactor/subgroup handling, `s < l` malleability,
  pinned params all need review).

- **Slice 5b — authenticated trade circuit (done).** `AuthedTradeCircuit` verifies
  **three BabyJubJub EdDSA signatures in-circuit** per trade — buyer's order,
  seller's order, and the **matcher's** over the fill — via `eddsa::verify_gadget`.
  The account leaf now commits each party's trading key (`account_leaf_auth`), and
  the signature is checked against the *same* `EdwardsVar` whose coordinates the
  leaf hashes — so a valid signature is provably from the account that owns the
  funds. On top: the affordability range checks and the chained Merkle update over
  the auth leaves. Public inputs: `prev_root`, `new_root`, `matcher_pk`. Tests:
  real prove/verify (`authed_trade_proves_and_verifies`) and
  `authed_trade_forged_signature_is_unsatisfiable` (wrong key → circuit rejects).
  This closes the authorization gap in the laptop-provable path.
  *Deferred (mechanical follow-ons):* the limit-price check (needs a wider range
  gadget for the price·size product), order expiry, over-fill accounting (needs
  fill-state in the leaf), and batching `AuthedTradeCircuit` like `BatchTradeCircuit`.

## Roadmap

- **Remaining reconciliation (not yet built).**
  - **Bit-identical commitment.** The circuit commits state in a dense
    BN254-Poseidon tree; `clearing` uses a sparse, UUID-keyed, depth-128
    Sha256/Poseidon2-BabyBear tree. A single proof verifying `clearing`'s *exact*
    root needs `clearing`'s commitment rebuilt in BN254-Poseidon — a larger
    reconciliation than slice 4. 4a verifies the *settlement rule* matches, not
    the commitment encoding.
  - **On-chain known-answer.** 4b proves the wire encoding round-trips through
    arkworks; verifier-specific conventions (proof-`A` negation, exact VK struct
    framing) still need a known-answer vector or an SVM test against a real
    `groth16-solana` program.

## Honesty notes

- The hash is a real **Poseidon** over BN254 `Fr` (slice 2), but its round
  constants/MDS are **arkworks-generated** (Grain LFSR), *not* the canonical
  circomlib/EIP set. A production build that must interoperate with an existing
  on-chain Poseidon has to pin those exact standard parameters; the circuit shape
  is unaffected.
- Custom circuits are **soundness-critical**: an under-constrained circuit is a
  silent fund-draining bug. Slices stay small and testable; we differential-fuzz
  the circuit against an independent Rust spec (slice 4a), but a production
  version still needs a specialist audit and fuzzing against `clearing` over a
  *shared* commitment encoding (the dual-implementation tax — see Roadmap).
- Depth is a small constant here (illustrative); production is deeper or uses
  dense account indices.
