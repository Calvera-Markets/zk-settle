//! The custom-circuit path: **Groth16 over BN254** state-validity circuits.
//!
//! This is the "Lighter-style" approach: instead of proving the execution of a
//! program in a zkVM, we hand-write the computation as **arithmetic
//! constraints**. Built in slices (see `README.md`): Merkle inclusion (1),
//! Poseidon hash (2), a range-checked withdrawal transition (3a), a two-account
//! spot-swap transition (3b), and a batch of swaps under one proof (3c). The
//! foundation throughout: an account leaf folds up its Merkle path to the
//! committed `root`, and balance changes are range-checked so no side can overdraw.
//!
//! ## Honesty notes
//! - The hash (`hash2`) is a real **Poseidon** sponge over BN254 `Fr` (slice 2),
//!   via arkworks' matched native + R1CS gadget. Its round constants/MDS are
//!   arkworks-generated (Grain LFSR), *not* the canonical circomlib/EIP set, so a
//!   production build that must interoperate with an existing on-chain hash has to
//!   pin those exact standard parameters. The circuit *shape* is unaffected.
//! - Depth here is a small constant for the slice; the production tree is deeper
//!   (or uses dense account indices). The structure is what matters.
//! - This is the high-risk path (`docs/problem-and-strategy-debate.md`): an
//!   under-constrained circuit is a soundness hole. This slice is intentionally
//!   tiny and testable so the constraint logic is auditable as it grows.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::EdwardsProjective;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::sync::OnceLock;

pub mod eddsa;
pub mod reference;
pub mod solana;
pub mod tree;

/// Merkle depth for this slice (illustrative; production is deeper).
pub const DEPTH: usize = 8;

/// Poseidon parameters for BN254 `Fr`: width **t = 3** (rate 2 + capacity 1),
/// **x⁵ S-box**, **8 full + 57 partial rounds** — the standard BN254 Poseidon
/// shape. Built once and cached.
///
/// The round constants + MDS matrix are generated deterministically by arkworks'
/// Grain-LFSR procedure (`find_poseidon_ark_and_mds`). That gives a *real*
/// Poseidon permutation (not the MiMC placeholder of slice 1), but the constants
/// are arkworks' own, not the canonical circomlib/EIP set — so for on-chain
/// interop a production build must pin the exact standard parameters (see README).
pub(crate) fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        const FULL_ROUNDS: usize = 8;
        const PARTIAL_ROUNDS: usize = 57;
        const ALPHA: u64 = 5;
        const RATE: usize = 2;
        const CAPACITY: usize = 1;
        // 254 = bit-size of the BN254 scalar field modulus.
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            254,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

/// Native 2-to-1 Poseidon compression — must match [`hash2_gadget`] exactly
/// (same config drives both, so they agree by construction).
pub fn hash2(left: Fr, right: Fr) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&left);
    sponge.absorb(&right);
    sponge.squeeze_field_elements(1)[0]
}

/// In-circuit 2-to-1 Poseidon compression — the constraint version of [`hash2`].
fn hash2_gadget(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let cs = left.cs().or(right.cs());
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(left)?;
    sponge.absorb(right)?;
    Ok(sponge.squeeze_field_elements(1)?.swap_remove(0))
}

/// Native multi-input Poseidon (sponge): absorb all inputs, squeeze one element.
/// Used for the EdDSA challenge hash (see [`eddsa`]).
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements(1)[0]
}

/// In-circuit version of [`poseidon_hash`]. `cs` anchors the sponge (the inputs
/// may be constants with no constraint system of their own).
pub(crate) fn poseidon_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    for x in inputs {
        sponge.absorb(x)?;
    }
    Ok(sponge.squeeze_field_elements(1)?.swap_remove(0))
}

/// Native account leaf: bind the account id to its (single-asset) balance.
pub fn account_leaf(id: Fr, balance: Fr) -> Fr {
    hash2(id, balance)
}

/// Native account leaf for the trade model: id + base + quote balances, chained
/// `hash2(hash2(id, base), quote)`.
pub fn account_leaf3(id: Fr, base: Fr, quote: Fr) -> Fr {
    hash2(hash2(id, base), quote)
}

/// In-circuit version of [`account_leaf3`].
fn leaf3_gadget(
    id: &FpVar<Fr>,
    base: &FpVar<Fr>,
    quote: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = hash2_gadget(id, base)?;
    hash2_gadget(&inner, quote)
}

/// Native **authenticated** account leaf: id + balances + the account's committed
/// BabyJubJub trading pubkey (its two coordinates). Committing the key is what
/// lets the trade circuit verify a signature *against the key the state records*
/// (slice 5b), binding authorization to the committed account.
pub fn account_leaf_auth(id: Fr, base: Fr, quote: Fr, pk: &crate::eddsa::PublicKey) -> Fr {
    poseidon_hash(&[id, base, quote, pk.0.x, pk.0.y])
}

/// In-circuit version of [`account_leaf_auth`]. The `pk` coordinates come from the
/// *same* `EdwardsVar` the signature is verified against, so the key in the leaf
/// and the key that signed are provably identical.
fn leaf_auth_gadget(
    cs: ConstraintSystemRef<Fr>,
    id: &FpVar<Fr>,
    base: &FpVar<Fr>,
    quote: &FpVar<Fr>,
    pk: &EdwardsVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_gadget(
        cs,
        &[
            id.clone(),
            base.clone(),
            quote.clone(),
            pk.x.clone(),
            pk.y.clone(),
        ],
    )
}

/// Fold `leaf` up a Merkle path (siblings + direction bits) to its root.
/// `bits[i] == true` ⇒ our node is the right child at level `i`.
fn merkle_root_gadget(
    leaf: FpVar<Fr>,
    siblings: &[FpVar<Fr>],
    bits: &[Boolean<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut cur = leaf;
    for (sib, is_right) in siblings.iter().zip(bits.iter()) {
        let left = FpVar::conditionally_select(is_right, sib, &cur)?;
        let right = FpVar::conditionally_select(is_right, &cur, sib)?;
        cur = hash2_gadget(&left, &right)?;
    }
    Ok(cur)
}

/// Allocated Merkle path: sibling field-vars + direction bits.
type AllocatedPath = (Vec<FpVar<Fr>>, Vec<Boolean<Fr>>);

/// Allocate a Merkle path (siblings + direction bits) as witnesses.
fn alloc_path(
    cs: ConstraintSystemRef<Fr>,
    siblings: &[Option<Fr>],
    path_bits: &[Option<bool>],
) -> Result<AllocatedPath, SynthesisError> {
    let mut sibs = Vec::with_capacity(DEPTH);
    let mut bits = Vec::with_capacity(DEPTH);
    for i in 0..DEPTH {
        sibs.push(FpVar::new_witness(cs.clone(), || {
            siblings[i].ok_or(SynthesisError::AssignmentMissing)
        })?);
        bits.push(Boolean::new_witness(cs.clone(), || {
            path_bits[i].ok_or(SynthesisError::AssignmentMissing)
        })?);
    }
    Ok((sibs, bits))
}

/// Enforce `0 <= x < 2^64` by checking its field bit-decomposition has no bits
/// set above position 64. This is the soundness-critical primitive: it's how a
/// circuit proves "no underflow" / non-negativity (a prime field has no native
/// notion of "negative", so a balance check is really a range check).
fn enforce_u64(x: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits = x.to_bits_le()?;
    for b in bits.iter().skip(64) {
        b.enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}

/// Proves: folding `leaf` up the Merkle path defined by (`siblings`,
/// `path_bits`) reproduces the public `root`. `path_bits[i] == true` means our
/// node is the **right** child at level `i` (so the sibling is on the left).
///
/// Fields are `Option` so the same struct serves Groth16 *setup* (all `None`,
/// only the shape matters) and *proving* (filled). Vec lengths must equal
/// [`DEPTH`] in both.
#[derive(Clone)]
pub struct MerkleInclusionCircuit {
    pub root: Option<Fr>,
    pub leaf: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
}

impl MerkleInclusionCircuit {
    /// A blank instance for setup (correct shape, no values).
    pub fn blank() -> Self {
        Self {
            root: None,
            leaf: None,
            siblings: vec![None; DEPTH],
            path_bits: vec![None; DEPTH],
        }
    }

    /// A fully-assigned instance for proving.
    pub fn new(root: Fr, leaf: Fr, siblings: Vec<Fr>, path_bits: Vec<bool>) -> Self {
        assert_eq!(siblings.len(), DEPTH);
        assert_eq!(path_bits.len(), DEPTH);
        Self {
            root: Some(root),
            leaf: Some(leaf),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for MerkleInclusionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public input: the committed root.
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Private witness: the leaf and its Merkle path.
        let leaf = FpVar::new_witness(cs.clone(), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let (sibs, bits) = alloc_path(cs, &self.siblings, &self.path_bits)?;

        let computed = merkle_root_gadget(leaf, &sibs, &bits)?;
        computed.enforce_equal(&root)?;
        Ok(())
    }
}

/// Slice 3 — a single-account, range-checked **withdrawal transition**.
///
/// Proves: account `id` held `balance` in `prev_root`; withdrawing `withdraw`
/// (which must be `<= balance` — the range check) leaves `balance - withdraw`;
/// and `new_root` is `prev_root` with *only* that account's leaf updated (the
/// siblings are unchanged, so no other account moved). This is the core
/// settlement-transition pattern `ExecutingProver` checks, reduced to one
/// account / one op. Multi-account trades and full batches are the next slices.
///
/// Public inputs (in order): `prev_root`, `new_root`, `id`, `withdraw`.
#[derive(Clone)]
pub struct WithdrawTransitionCircuit {
    pub prev_root: Option<Fr>,
    pub new_root: Option<Fr>,
    pub id: Option<Fr>,
    pub withdraw: Option<Fr>,
    pub balance: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
}

impl WithdrawTransitionCircuit {
    pub fn blank() -> Self {
        Self {
            prev_root: None,
            new_root: None,
            id: None,
            withdraw: None,
            balance: None,
            siblings: vec![None; DEPTH],
            path_bits: vec![None; DEPTH],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prev_root: Fr,
        new_root: Fr,
        id: Fr,
        withdraw: Fr,
        balance: Fr,
        siblings: Vec<Fr>,
        path_bits: Vec<bool>,
    ) -> Self {
        assert_eq!(siblings.len(), DEPTH);
        assert_eq!(path_bits.len(), DEPTH);
        Self {
            prev_root: Some(prev_root),
            new_root: Some(new_root),
            id: Some(id),
            withdraw: Some(withdraw),
            balance: Some(balance),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prev_root = FpVar::new_input(cs.clone(), || {
            self.prev_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let new_root = FpVar::new_input(cs.clone(), || {
            self.new_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let id = FpVar::new_input(cs.clone(), || {
            self.id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let withdraw = FpVar::new_input(cs.clone(), || {
            self.withdraw.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let balance = FpVar::new_witness(cs.clone(), || {
            self.balance.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let (sibs, bits) = alloc_path(cs, &self.siblings, &self.path_bits)?;

        // Inputs are bounded (so field arithmetic models integer arithmetic).
        enforce_u64(&balance)?;
        enforce_u64(&withdraw)?;

        // The prior leaf for this account must be in prev_root.
        let prev_leaf = hash2_gadget(&id, &balance)?;
        let computed_prev = merkle_root_gadget(prev_leaf, &sibs, &bits)?;
        computed_prev.enforce_equal(&prev_root)?;

        // new = balance - withdraw, and it must be a valid u64 — which is exactly
        // "withdraw <= balance" (no underflow). This is the soundness-critical
        // check: drop it and a circuit would happily prove a negative balance.
        let new_balance = &balance - &withdraw;
        enforce_u64(&new_balance)?;

        // The updated leaf (same path) must be in new_root.
        let new_leaf = hash2_gadget(&id, &new_balance)?;
        let computed_new = merkle_root_gadget(new_leaf, &sibs, &bits)?;
        computed_new.enforce_equal(&new_root)?;
        Ok(())
    }
}

/// One spot-swap's worth of already-allocated circuit variables: the two parties'
/// ids, the traded amounts, both parties' prior balances, and their Merkle paths
/// (buyer's vs the *current* root, seller's vs the post-buyer *mid* root).
struct TradeVars {
    buyer_id: FpVar<Fr>,
    seller_id: FpVar<Fr>,
    base_amount: FpVar<Fr>,
    quote_amount: FpVar<Fr>,
    buyer_base: FpVar<Fr>,
    buyer_quote: FpVar<Fr>,
    seller_base: FpVar<Fr>,
    seller_quote: FpVar<Fr>,
    b_sibs: Vec<FpVar<Fr>>,
    b_bits: Vec<Boolean<Fr>>,
    s_sibs: Vec<FpVar<Fr>>,
    s_bits: Vec<Boolean<Fr>>,
}

/// Apply one spot swap to `cur_root` and return the resulting root.
///
/// Buyer gives `quote_amount`, receives `base_amount`; seller does the reverse.
/// The two accounts live in the *same* tree, so this is a **multi-leaf update**:
/// updating the buyer's leaf changes some of the seller's siblings. We handle it
/// with a **chained update** — buyer first (`cur_root → mid_root`), then seller
/// (`mid_root → next_root`) — exactly the chaining the zkVM witness uses. The
/// seller's path is supplied **as of `mid_root`** (i.e. after the buyer update).
///
/// Conservation is automatic (the same amounts are moved both ways); the only
/// soundness gates are the two range checks: the buyer can afford the quote and
/// the seller can afford the base. Account leaf binds id + both balances:
/// `hash(hash(id, base), quote)`.
///
/// Shared by the single-trade circuit and the batch circuit, so there is one
/// authoritative encoding of the transition (the spec to match in slice 4).
fn trade_step_gadget(cur_root: &FpVar<Fr>, t: &TradeVars) -> Result<FpVar<Fr>, SynthesisError> {
    // Inputs bounded so field arithmetic models integer arithmetic.
    enforce_u64(&t.buyer_base)?;
    enforce_u64(&t.buyer_quote)?;
    enforce_u64(&t.seller_base)?;
    enforce_u64(&t.seller_quote)?;
    enforce_u64(&t.base_amount)?;
    enforce_u64(&t.quote_amount)?;

    // 1. Buyer's prior leaf is in the current root.
    let buyer_old = leaf3_gadget(&t.buyer_id, &t.buyer_base, &t.buyer_quote)?;
    merkle_root_gadget(buyer_old, &t.b_sibs, &t.b_bits)?.enforce_equal(cur_root)?;

    // 2. Buyer update: +base, -quote (must afford the quote). -> mid_root.
    let buyer_base_new = &t.buyer_base + &t.base_amount;
    let buyer_quote_new = &t.buyer_quote - &t.quote_amount;
    enforce_u64(&buyer_base_new)?;
    enforce_u64(&buyer_quote_new)?;
    let buyer_new = leaf3_gadget(&t.buyer_id, &buyer_base_new, &buyer_quote_new)?;
    let mid_root = merkle_root_gadget(buyer_new, &t.b_sibs, &t.b_bits)?;

    // 3. Seller's prior leaf is in mid_root (path is as-of-mid).
    let seller_old = leaf3_gadget(&t.seller_id, &t.seller_base, &t.seller_quote)?;
    merkle_root_gadget(seller_old, &t.s_sibs, &t.s_bits)?.enforce_equal(&mid_root)?;

    // 4. Seller update: -base (must afford it), +quote. -> next_root.
    let seller_base_new = &t.seller_base - &t.base_amount;
    let seller_quote_new = &t.seller_quote + &t.quote_amount;
    enforce_u64(&seller_base_new)?;
    enforce_u64(&seller_quote_new)?;
    let seller_new = leaf3_gadget(&t.seller_id, &seller_base_new, &seller_quote_new)?;
    merkle_root_gadget(seller_new, &t.s_sibs, &t.s_bits)
}

/// Slice 3b — a two-account **spot-swap (trade) transition**.
///
/// Proves a single trade takes `prev_root` to `new_root` (see [`trade_step_gadget`]
/// for the transition itself). Here the parties' ids and the amounts are **public
/// inputs** (the on-chain verifier learns who traded what); the balances and paths
/// stay witness.
///
/// Public inputs (in order): `prev_root`, `new_root`, `buyer_id`, `seller_id`,
/// `base_amount`, `quote_amount`.
#[derive(Clone)]
pub struct TradeTransitionCircuit {
    pub prev_root: Option<Fr>,
    pub new_root: Option<Fr>,
    pub buyer_id: Option<Fr>,
    pub seller_id: Option<Fr>,
    pub base_amount: Option<Fr>,
    pub quote_amount: Option<Fr>,
    pub buyer_base: Option<Fr>,
    pub buyer_quote: Option<Fr>,
    pub seller_base: Option<Fr>,
    pub seller_quote: Option<Fr>,
    pub buyer_siblings: Vec<Option<Fr>>,
    pub buyer_bits: Vec<Option<bool>>,
    pub seller_siblings: Vec<Option<Fr>>,
    pub seller_bits: Vec<Option<bool>>,
}

impl TradeTransitionCircuit {
    pub fn blank() -> Self {
        Self {
            prev_root: None,
            new_root: None,
            buyer_id: None,
            seller_id: None,
            base_amount: None,
            quote_amount: None,
            buyer_base: None,
            buyer_quote: None,
            seller_base: None,
            seller_quote: None,
            buyer_siblings: vec![None; DEPTH],
            buyer_bits: vec![None; DEPTH],
            seller_siblings: vec![None; DEPTH],
            seller_bits: vec![None; DEPTH],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prev_root: Fr,
        new_root: Fr,
        buyer_id: Fr,
        seller_id: Fr,
        base_amount: Fr,
        quote_amount: Fr,
        buyer_base: Fr,
        buyer_quote: Fr,
        seller_base: Fr,
        seller_quote: Fr,
        buyer_path: (Vec<Fr>, Vec<bool>),
        seller_path: (Vec<Fr>, Vec<bool>),
    ) -> Self {
        Self {
            prev_root: Some(prev_root),
            new_root: Some(new_root),
            buyer_id: Some(buyer_id),
            seller_id: Some(seller_id),
            base_amount: Some(base_amount),
            quote_amount: Some(quote_amount),
            buyer_base: Some(buyer_base),
            buyer_quote: Some(buyer_quote),
            seller_base: Some(seller_base),
            seller_quote: Some(seller_quote),
            buyer_siblings: buyer_path.0.into_iter().map(Some).collect(),
            buyer_bits: buyer_path.1.into_iter().map(Some).collect(),
            seller_siblings: seller_path.0.into_iter().map(Some).collect(),
            seller_bits: seller_path.1.into_iter().map(Some).collect(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for TradeTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let inp = |v: Option<Fr>| {
            FpVar::new_input(cs.clone(), move || {
                v.ok_or(SynthesisError::AssignmentMissing)
            })
        };
        let wit = |v: Option<Fr>| {
            FpVar::new_witness(cs.clone(), move || {
                v.ok_or(SynthesisError::AssignmentMissing)
            })
        };

        let prev_root = inp(self.prev_root)?;
        let new_root = inp(self.new_root)?;
        let buyer_id = inp(self.buyer_id)?;
        let seller_id = inp(self.seller_id)?;
        let base_amount = inp(self.base_amount)?;
        let quote_amount = inp(self.quote_amount)?;

        let buyer_base = wit(self.buyer_base)?;
        let buyer_quote = wit(self.buyer_quote)?;
        let seller_base = wit(self.seller_base)?;
        let seller_quote = wit(self.seller_quote)?;

        let (b_sibs, b_bits) = alloc_path(cs.clone(), &self.buyer_siblings, &self.buyer_bits)?;
        let (s_sibs, s_bits) = alloc_path(cs.clone(), &self.seller_siblings, &self.seller_bits)?;

        let vars = TradeVars {
            buyer_id,
            seller_id,
            base_amount,
            quote_amount,
            buyer_base,
            buyer_quote,
            seller_base,
            seller_quote,
            b_sibs,
            b_bits,
            s_sibs,
            s_bits,
        };
        // One trade: prev_root -> new_root.
        trade_step_gadget(&prev_root, &vars)?.enforce_equal(&new_root)?;
        Ok(())
    }
}

/// The fixed number of trades a single batch proof covers. A real rollup pads the
/// tail with no-op trades to keep one fixed circuit shape; here we keep it small
/// and concrete.
pub const BATCH_SIZE: usize = 4;

/// Concrete inputs for one trade in a batch (ergonomic test/host construction).
#[derive(Clone)]
pub struct TradeData {
    pub buyer_id: Fr,
    pub seller_id: Fr,
    pub base_amount: Fr,
    pub quote_amount: Fr,
    pub buyer_base: Fr,
    pub buyer_quote: Fr,
    pub seller_base: Fr,
    pub seller_quote: Fr,
    /// Buyer's path vs the root *entering* this trade.
    pub buyer_path: (Vec<Fr>, Vec<bool>),
    /// Seller's path vs the *mid* root (after this trade's buyer update).
    pub seller_path: (Vec<Fr>, Vec<bool>),
}

/// One batch slot, as `Option`s so a blank (setup-only) instance has the right
/// shape without any values.
// TODO: buyer and seller naming convention here is problematic, it should be
// maker and taker
#[derive(Clone)]
struct TradeWitness {
    buyer_id: Option<Fr>,
    seller_id: Option<Fr>,
    base_amount: Option<Fr>,
    quote_amount: Option<Fr>,
    buyer_base: Option<Fr>,
    buyer_quote: Option<Fr>,
    seller_base: Option<Fr>,
    seller_quote: Option<Fr>,
    // Merkle authentication path for the buyer
    buyer_siblings: Vec<Option<Fr>>,
    buyer_bits: Vec<Option<bool>>,
    // Merkle authentication path for the seller
    seller_siblings: Vec<Option<Fr>>,
    seller_bits: Vec<Option<bool>>,
}

impl TradeWitness {
    fn blank() -> Self {
        Self {
            buyer_id: None,
            seller_id: None,
            base_amount: None,
            quote_amount: None,
            buyer_base: None,
            buyer_quote: None,
            seller_base: None,
            seller_quote: None,
            buyer_siblings: vec![None; DEPTH],
            buyer_bits: vec![None; DEPTH],
            seller_siblings: vec![None; DEPTH],
            seller_bits: vec![None; DEPTH],
        }
    }

    fn from_data(d: TradeData) -> Self {
        Self {
            buyer_id: Some(d.buyer_id),
            seller_id: Some(d.seller_id),
            base_amount: Some(d.base_amount),
            quote_amount: Some(d.quote_amount),
            buyer_base: Some(d.buyer_base),
            buyer_quote: Some(d.buyer_quote),
            seller_base: Some(d.seller_base),
            seller_quote: Some(d.seller_quote),
            buyer_siblings: d.buyer_path.0.into_iter().map(Some).collect(),
            buyer_bits: d.buyer_path.1.into_iter().map(Some).collect(),
            seller_siblings: d.seller_path.0.into_iter().map(Some).collect(),
            seller_bits: d.seller_path.1.into_iter().map(Some).collect(),
        }
    }

    /// Allocate this slot's variables — **all as witness** (in a batch the
    /// individual trades are private; only the endpoint roots are public).
    fn alloc(&self, cs: ConstraintSystemRef<Fr>) -> Result<TradeVars, SynthesisError> {
        let wit = |v: Option<Fr>| {
            FpVar::new_witness(cs.clone(), move || {
                v.ok_or(SynthesisError::AssignmentMissing)
            })
        };
        let (b_sibs, b_bits) = alloc_path(cs.clone(), &self.buyer_siblings, &self.buyer_bits)?;
        let (s_sibs, s_bits) = alloc_path(cs.clone(), &self.seller_siblings, &self.seller_bits)?;
        Ok(TradeVars {
            buyer_id: wit(self.buyer_id)?,
            seller_id: wit(self.seller_id)?,
            base_amount: wit(self.base_amount)?,
            quote_amount: wit(self.quote_amount)?,
            buyer_base: wit(self.buyer_base)?,
            buyer_quote: wit(self.buyer_quote)?,
            seller_base: wit(self.seller_base)?,
            seller_quote: wit(self.seller_quote)?,
            b_sibs,
            b_bits,
            s_sibs,
            s_bits,
        })
    }
}

/// Slice 3c — a **batch** of `BATCH_SIZE` spot swaps folded into one proof.
///
/// This is the rollup property: only the two **endpoint roots** are public. The
/// circuit starts at `prev_root`, applies each trade in order via the shared
/// [`trade_step_gadget`] (threading the running root through every intermediate
/// state), and proves the final root equals `new_root`. A single succinct proof
/// thus attests that *some* valid sequence of `BATCH_SIZE` non-overdrawing trades
/// took the committed state from `prev_root` to `new_root`.
///
/// Public inputs (in order): `prev_root`, `new_root`.
#[derive(Clone)]
pub struct BatchTradeCircuit {
    prev_root: Option<Fr>,
    new_root: Option<Fr>,
    trades: Vec<TradeWitness>,
}

impl BatchTradeCircuit {
    pub fn blank() -> Self {
        Self {
            prev_root: None,
            new_root: None,
            trades: vec![TradeWitness::blank(); BATCH_SIZE],
        }
    }

    /// `trades` must have exactly `BATCH_SIZE` entries.
    pub fn new(prev_root: Fr, new_root: Fr, trades: Vec<TradeData>) -> Self {
        assert_eq!(
            trades.len(),
            BATCH_SIZE,
            "batch must be exactly BATCH_SIZE trades"
        );
        Self {
            prev_root: Some(prev_root),
            new_root: Some(new_root),
            trades: trades.into_iter().map(TradeWitness::from_data).collect(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for BatchTradeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prev_root = FpVar::new_input(cs.clone(), || {
            self.prev_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let new_root = FpVar::new_input(cs.clone(), || {
            self.new_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Thread the running root through every trade.
        let mut cur_root = prev_root;
        for trade in &self.trades {
            let vars = trade.alloc(cs.clone())?;
            cur_root = trade_step_gadget(&cur_root, &vars)?;
        }
        cur_root.enforce_equal(&new_root)?;
        Ok(())
    }
}

// ===== Slice 5b — authenticated trade (signatures verified in-circuit) =========

/// One party's inputs to an authenticated trade: its account contents, committed
/// BabyJubJub trading key, the signed order terms, its signature, and the Merkle
/// path. `side` and `account` are fixed by role (buyer/seller), so they're
/// implied, not stored.
#[derive(Clone)]
pub struct AuthedParty {
    pub id: Fr,
    pub base: Fr,
    pub quote: Fr,
    pub pk: crate::eddsa::PublicKey,
    pub order_base: Fr,
    pub order_limit: Fr,
    pub order_salt: Fr,
    pub sig: crate::eddsa::Signature,
    /// Merkle path: siblings (leaf→root) + direction bits, length `DEPTH`.
    pub path: (Vec<Fr>, Vec<bool>),
}

/// Full inputs for one authenticated spot swap.
#[derive(Clone)]
pub struct AuthedTrade {
    pub prev_root: Fr,
    pub new_root: Fr,
    pub market: Fr,
    /// The operator/matcher key — verifier configuration (a public input).
    pub matcher_pk: crate::eddsa::PublicKey,
    pub buyer: AuthedParty,
    pub seller: AuthedParty,
    pub fill_base: Fr,
    pub fill_quote: Fr,
    pub matcher_sig: crate::eddsa::Signature,
}

/// A party's allocated circuit variables.
struct AllocParty {
    id: FpVar<Fr>,
    base: FpVar<Fr>,
    quote: FpVar<Fr>,
    pk: EdwardsVar,
    order_base: FpVar<Fr>,
    order_limit: FpVar<Fr>,
    order_salt: FpVar<Fr>,
    sig_r: EdwardsVar,
    sig_s: FpVar<Fr>,
    sibs: Vec<FpVar<Fr>>,
    bits: Vec<Boolean<Fr>>,
}

fn alloc_party(
    cs: ConstraintSystemRef<Fr>,
    p: Option<&AuthedParty>,
) -> Result<AllocParty, SynthesisError> {
    let f = |v: Option<Fr>| {
        FpVar::new_witness(cs.clone(), move || {
            v.ok_or(SynthesisError::AssignmentMissing)
        })
    };
    let pt = |v: Option<EdwardsProjective>| {
        EdwardsVar::new_witness(cs.clone(), move || {
            v.ok_or(SynthesisError::AssignmentMissing)
        })
    };
    Ok(AllocParty {
        id: f(p.map(|p| p.id))?,
        base: f(p.map(|p| p.base))?,
        quote: f(p.map(|p| p.quote))?,
        pk: pt(p.map(|p| EdwardsProjective::from(p.pk.0)))?,
        order_base: f(p.map(|p| p.order_base))?,
        order_limit: f(p.map(|p| p.order_limit))?,
        order_salt: f(p.map(|p| p.order_salt))?,
        sig_r: pt(p.map(|p| EdwardsProjective::from(p.sig.r)))?,
        sig_s: f(p.map(|p| crate::eddsa::jub_to_f(p.sig.s)))?,
        sibs: (0..DEPTH)
            .map(|i| f(p.map(|p| p.path.0[i])))
            .collect::<Result<Vec<_>, _>>()?,
        bits: (0..DEPTH)
            .map(|i| {
                Boolean::new_witness(cs.clone(), || {
                    p.map(|p| p.path.1[i])
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Slice 5b — a fully **authenticated** single spot-swap transition.
///
/// On top of the settlement arithmetic + Merkle update, this verifies **three
/// BabyJubJub EdDSA signatures in-circuit**: the buyer's over their order, the
/// seller's over theirs, and the **matcher's** over the fill. Each user's key is
/// the one committed in their account leaf (`account_leaf_auth`), so a valid
/// signature is provably from the account that owns the funds — closing the
/// authorization gap (`../docs/zkvm-trade-authentication-plan.md`) in the
/// laptop-provable custom-circuit path.
///
/// Public inputs (in order): `prev_root`, `new_root`, `matcher_pk` (2 coords).
///
/// Scope of this slice: signatures + pubkey-in-leaf binding + affordability +
/// the chained Merkle update. Deferred (noted): the limit-price check (needs a
/// wider range gadget for the price·size product), order expiry, over-fill
/// accounting (needs fill-state committed in the leaf), and batching — all
/// mechanical follow-ons on top of this.
#[derive(Clone)]
pub struct AuthedTradeCircuit {
    input: Option<AuthedTrade>,
}

impl AuthedTradeCircuit {
    pub fn blank() -> Self {
        Self { input: None }
    }
    pub fn new(trade: AuthedTrade) -> Self {
        Self { input: Some(trade) }
    }
}

impl ConstraintSynthesizer<Fr> for AuthedTradeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let input = self.input;
        let miss = SynthesisError::AssignmentMissing;

        // Public: the endpoint roots and the (trusted) matcher key.
        let prev_root = FpVar::new_input(cs.clone(), || {
            input.as_ref().map(|t| t.prev_root).ok_or(miss)
        })?;
        let new_root = FpVar::new_input(cs.clone(), || {
            input.as_ref().map(|t| t.new_root).ok_or(miss)
        })?;
        let matcher_pk = EdwardsVar::new_input(cs.clone(), || {
            input
                .as_ref()
                .map(|t| EdwardsProjective::from(t.matcher_pk.0))
                .ok_or(miss)
        })?;

        // Witness: market, fill, matcher signature, both parties.
        let market =
            FpVar::new_witness(cs.clone(), || input.as_ref().map(|t| t.market).ok_or(miss))?;
        let fill_base = FpVar::new_witness(cs.clone(), || {
            input.as_ref().map(|t| t.fill_base).ok_or(miss)
        })?;
        let fill_quote = FpVar::new_witness(cs.clone(), || {
            input.as_ref().map(|t| t.fill_quote).ok_or(miss)
        })?;
        let matcher_r = EdwardsVar::new_witness(cs.clone(), || {
            input
                .as_ref()
                .map(|t| EdwardsProjective::from(t.matcher_sig.r))
                .ok_or(miss)
        })?;
        let matcher_s = FpVar::new_witness(cs.clone(), || {
            input
                .as_ref()
                .map(|t| crate::eddsa::jub_to_f(t.matcher_sig.s))
                .ok_or(miss)
        })?;
        let buyer = alloc_party(cs.clone(), input.as_ref().map(|t| &t.buyer))?;
        let seller = alloc_party(cs.clone(), input.as_ref().map(|t| &t.seller))?;

        // --- authorization: three signatures ---
        // Buyer/seller sign their order; side is fixed by role (0 = Buy, 1 = Sell).
        let buy_msg = vec![
            buyer.id.clone(),
            market.clone(),
            FpVar::constant(Fr::from(0u64)),
            buyer.order_base.clone(),
            buyer.order_limit.clone(),
            buyer.order_salt.clone(),
        ];
        crate::eddsa::verify_gadget(cs.clone(), &buyer.pk, &buyer.sig_r, &buyer.sig_s, &buy_msg)?;
        let sell_msg = vec![
            seller.id.clone(),
            market.clone(),
            FpVar::constant(Fr::from(1u64)),
            seller.order_base.clone(),
            seller.order_limit.clone(),
            seller.order_salt.clone(),
        ];
        crate::eddsa::verify_gadget(
            cs.clone(),
            &seller.pk,
            &seller.sig_r,
            &seller.sig_s,
            &sell_msg,
        )?;

        // Matcher signs the pairing: (buy commitment, sell commitment, fill).
        let buy_commit = poseidon_hash_gadget(cs.clone(), &buy_msg)?;
        let sell_commit = poseidon_hash_gadget(cs.clone(), &sell_msg)?;
        let matcher_msg = vec![
            buy_commit,
            sell_commit,
            fill_base.clone(),
            fill_quote.clone(),
        ];
        crate::eddsa::verify_gadget(
            cs.clone(),
            &matcher_pk,
            &matcher_r,
            &matcher_s,
            &matcher_msg,
        )?;

        // --- settlement: affordability + chained Merkle update over auth leaves ---
        enforce_u64(&buyer.base)?;
        enforce_u64(&buyer.quote)?;
        enforce_u64(&seller.base)?;
        enforce_u64(&seller.quote)?;
        enforce_u64(&fill_base)?;
        enforce_u64(&fill_quote)?;

        // Buyer's prior leaf (binding its committed key) is in prev_root.
        let buyer_old =
            leaf_auth_gadget(cs.clone(), &buyer.id, &buyer.base, &buyer.quote, &buyer.pk)?;
        merkle_root_gadget(buyer_old, &buyer.sibs, &buyer.bits)?.enforce_equal(&prev_root)?;
        // Buyer: +base, -quote (must afford the quote). -> mid_root.
        let b_base_new = &buyer.base + &fill_base;
        let b_quote_new = &buyer.quote - &fill_quote;
        enforce_u64(&b_base_new)?;
        enforce_u64(&b_quote_new)?;
        let buyer_new =
            leaf_auth_gadget(cs.clone(), &buyer.id, &b_base_new, &b_quote_new, &buyer.pk)?;
        let mid_root = merkle_root_gadget(buyer_new, &buyer.sibs, &buyer.bits)?;

        // Seller's prior leaf is in mid_root; apply -base (afford), +quote.
        let seller_old = leaf_auth_gadget(
            cs.clone(),
            &seller.id,
            &seller.base,
            &seller.quote,
            &seller.pk,
        )?;
        merkle_root_gadget(seller_old, &seller.sibs, &seller.bits)?.enforce_equal(&mid_root)?;
        let s_base_new = &seller.base - &fill_base;
        let s_quote_new = &seller.quote + &fill_quote;
        enforce_u64(&s_base_new)?;
        enforce_u64(&s_quote_new)?;
        let seller_new = leaf_auth_gadget(
            cs.clone(),
            &seller.id,
            &s_base_new,
            &s_quote_new,
            &seller.pk,
        )?;
        merkle_root_gadget(seller_new, &seller.sibs, &seller.bits)?.enforce_equal(&new_root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// The native and in-circuit Poseidon must agree bit-for-bit — every circuit's
    /// soundness depends on the gadget computing the same root the prover commits.
    #[test]
    fn native_and_gadget_poseidon_agree() {
        let (a, b) = (Fr::from(123u64), Fr::from(456u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        let av = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
        let bv = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();
        let out = hash2_gadget(&av, &bv).unwrap();
        assert_eq!(out.value().unwrap(), hash2(a, b));
        assert!(cs.is_satisfied().unwrap());
    }

    /// A native Merkle path: siblings (leaf→root) plus direction bits.
    type NativePath = (Vec<Fr>, Vec<bool>);

    /// Fold a leaf up a path natively (the statement the circuit proves).
    fn compute_root(leaf: Fr, siblings: &[Fr], bits: &[bool]) -> Fr {
        let mut cur = leaf;
        for i in 0..siblings.len() {
            let (l, r) = if bits[i] {
                (siblings[i], cur)
            } else {
                (cur, siblings[i])
            };
            cur = hash2(l, r);
        }
        cur
    }

    use crate::tree::MerkleTree;

    #[test]
    fn groth16_merkle_inclusion_proves_and_verifies() {
        let mut rng = StdRng::seed_from_u64(0);

        // A random leaf + path, with the matching root computed natively.
        let leaf = Fr::rand(&mut rng);
        let siblings: Vec<Fr> = (0..DEPTH).map(|_| Fr::rand(&mut rng)).collect();
        let bits: Vec<bool> = (0..DEPTH).map(|i| i % 2 == 0).collect();
        let root = compute_root(leaf, &siblings, &bits);

        // Trusted setup (circuit-specific), then prove, then verify — all real.
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(MerkleInclusionCircuit::blank(), &mut rng)
                .unwrap();

        let circuit = MerkleInclusionCircuit::new(root, leaf, siblings, bits);
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Public input is just the root.
        assert!(Groth16::<Bn254>::verify(&vk, &[root], &proof).unwrap());

        // A different claimed root must NOT verify against this proof.
        assert!(!Groth16::<Bn254>::verify(&vk, &[root + Fr::from(1u64)], &proof).unwrap());
    }

    #[test]
    fn wrong_witness_does_not_satisfy_the_constraints() {
        use ark_relations::r1cs::ConstraintSystem;

        let mut rng = StdRng::seed_from_u64(0);
        let leaf = Fr::rand(&mut rng);
        let siblings: Vec<Fr> = (0..DEPTH).map(|_| Fr::rand(&mut rng)).collect();
        let bits: Vec<bool> = (0..DEPTH).map(|_| true).collect();
        let root = compute_root(leaf, &siblings, &bits);

        // A tampered leaf claiming the original root: the constraint system is
        // unsatisfiable, so no valid proof exists. (The prover would panic on an
        // unsatisfiable witness, so we check satisfiability directly.)
        let bad = MerkleInclusionCircuit::new(root, leaf + Fr::from(1u64), siblings, bits);
        let cs = ConstraintSystem::<Fr>::new_ref();
        bad.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn withdraw_transition_proves_and_verifies() {
        let mut rng = StdRng::seed_from_u64(1);
        let id = Fr::from(0xBu64);
        let (balance, w) = (1000u64, 100u64);
        let (bf, wf) = (Fr::from(balance), Fr::from(w));

        let siblings: Vec<Fr> = (0..DEPTH).map(|_| Fr::rand(&mut rng)).collect();
        let bits: Vec<bool> = (0..DEPTH).map(|i| i % 3 == 0).collect();
        let prev_root = compute_root(account_leaf(id, bf), &siblings, &bits);
        let new_root = compute_root(account_leaf(id, Fr::from(balance - w)), &siblings, &bits);

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(WithdrawTransitionCircuit::blank(), &mut rng)
                .unwrap();

        let circuit =
            WithdrawTransitionCircuit::new(prev_root, new_root, id, wf, bf, siblings, bits);
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        assert!(Groth16::<Bn254>::verify(&vk, &[prev_root, new_root, id, wf], &proof).unwrap());
        // A different claimed new_root must not verify.
        let bad_new = new_root + Fr::from(1u64);
        assert!(!Groth16::<Bn254>::verify(&vk, &[prev_root, bad_new, id, wf], &proof).unwrap());
    }

    #[test]
    fn overdraw_is_unsatisfiable() {
        use ark_relations::r1cs::ConstraintSystem;

        let mut rng = StdRng::seed_from_u64(2);
        let id = Fr::from(0xBu64);
        let (balance, w) = (100u64, 1000u64); // withdraw more than the balance
        let (bf, wf) = (Fr::from(balance), Fr::from(w));

        let siblings: Vec<Fr> = (0..DEPTH).map(|_| Fr::rand(&mut rng)).collect();
        let bits: Vec<bool> = (0..DEPTH).map(|_| false).collect();
        let prev_root = compute_root(account_leaf(id, bf), &siblings, &bits);
        // balance - w wraps in the field (a huge element); build the "new_root"
        // consistent with that wrapped value so ONLY the range check can fail.
        let wrapped = bf - wf;
        let new_root = compute_root(account_leaf(id, wrapped), &siblings, &bits);

        let circuit =
            WithdrawTransitionCircuit::new(prev_root, new_root, id, wf, bf, siblings, bits);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // The enforce_u64(new_balance) range check rejects the underflow.
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Build the prev/mid/new roots + both paths for a spot swap, given starting
    /// balances and the traded amounts. Returns everything the circuit needs.
    #[allow(clippy::too_many_arguments)]
    fn build_trade(
        buyer_id: Fr,
        seller_id: Fr,
        bi: usize,
        si: usize,
        bb: u64,
        bq: u64,
        sb: u64,
        sq: u64,
        base_amt: u64,
        quote_amt: u64,
    ) -> (Fr, Fr, NativePath, NativePath) {
        // Distinct placeholder leaves everywhere, real leaves for the two accounts.
        let mut leaves: Vec<Fr> = (0..(1u64 << DEPTH)).map(Fr::from).collect();
        leaves[bi] = account_leaf3(buyer_id, Fr::from(bb), Fr::from(bq));
        leaves[si] = account_leaf3(seller_id, Fr::from(sb), Fr::from(sq));
        let prev = MerkleTree::new(leaves);
        let prev_root = prev.root();
        let buyer_path = prev.path(bi);

        // Buyer: +base, -quote. Field subtraction (wraps if unaffordable — the
        // circuit's range check is what catches that, not this helper).
        let buyer_new = account_leaf3(
            buyer_id,
            Fr::from(bb) + Fr::from(base_amt),
            Fr::from(bq) - Fr::from(quote_amt),
        );
        let mut mid = prev.clone();
        mid.update(bi, buyer_new);
        let seller_path = mid.path(si);

        // Seller: -base, +quote.
        let seller_new = account_leaf3(
            seller_id,
            Fr::from(sb) - Fr::from(base_amt),
            Fr::from(sq) + Fr::from(quote_amt),
        );
        let mut new_root = mid.clone();
        new_root.update(si, seller_new);
        let new_root = new_root.root();

        (prev_root, new_root, buyer_path, seller_path)
    }

    #[test]
    fn trade_transition_proves_and_verifies() {
        let mut rng = StdRng::seed_from_u64(3);
        let buyer_id = Fr::from(0xB0u64);
        let seller_id = Fr::from(0x5Eu64);
        let (bi, si) = (5usize, 200usize);
        // Buyer pays 400 quote for 2 base; seller does the reverse.
        let (bb, bq, sb, sq) = (10u64, 1000u64, 50u64, 0u64);
        let (base_amt, quote_amt) = (2u64, 400u64);

        let (prev_root, new_root, buyer_path, seller_path) = build_trade(
            buyer_id, seller_id, bi, si, bb, bq, sb, sq, base_amt, quote_amt,
        );

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(TradeTransitionCircuit::blank(), &mut rng)
                .unwrap();

        let circuit = TradeTransitionCircuit::new(
            prev_root,
            new_root,
            buyer_id,
            seller_id,
            Fr::from(base_amt),
            Fr::from(quote_amt),
            Fr::from(bb),
            Fr::from(bq),
            Fr::from(sb),
            Fr::from(sq),
            buyer_path,
            seller_path,
        );
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let public = [
            prev_root,
            new_root,
            buyer_id,
            seller_id,
            Fr::from(base_amt),
            Fr::from(quote_amt),
        ];
        assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());

        // Tampering the claimed new_root breaks verification.
        let mut bad = public;
        bad[1] += Fr::from(1u64);
        assert!(!Groth16::<Bn254>::verify(&vk, &bad, &proof).unwrap());
    }

    #[test]
    fn trade_seller_overdraw_is_unsatisfiable() {
        use ark_relations::r1cs::ConstraintSystem;

        let buyer_id = Fr::from(0xB0u64);
        let seller_id = Fr::from(0x5Eu64);
        let (bi, si) = (5usize, 200usize);
        // Seller holds only 1 base but the trade moves 2 — seller can't afford it.
        let (bb, bq, sb, sq) = (10u64, 1000u64, 1u64, 0u64);
        let (base_amt, quote_amt) = (2u64, 400u64);

        // Roots are built consistently with the wrapped (underflowed) seller base,
        // so ONLY the seller's range check can fail.
        let (prev_root, new_root, buyer_path, seller_path) = build_trade(
            buyer_id, seller_id, bi, si, bb, bq, sb, sq, base_amt, quote_amt,
        );

        let circuit = TradeTransitionCircuit::new(
            prev_root,
            new_root,
            buyer_id,
            seller_id,
            Fr::from(base_amt),
            Fr::from(quote_amt),
            Fr::from(bb),
            Fr::from(bq),
            Fr::from(sb),
            Fr::from(sq),
            buyer_path,
            seller_path,
        );
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// One trade's worth of inputs for batch construction. Distinct account pairs
    /// at distinct indices keep per-trade balances independent.
    struct Spec {
        buyer_id: Fr,
        seller_id: Fr,
        bi: usize,
        si: usize,
        bb: u64,
        bq: u64,
        sb: u64,
        sq: u64,
        base_amt: u64,
        quote_amt: u64,
    }

    /// Build a batch end-to-end: place every account in the initial tree, capture
    /// `prev_root`, then apply each trade (buyer then seller) through the running
    /// tree — recording each trade's paths as-of-its-turn — and capture `new_root`.
    /// Uses field arithmetic, so an unaffordable trade simply wraps (consistent
    /// roots; the circuit's range check is what rejects it).
    fn build_batch(specs: &[Spec]) -> (Fr, Fr, Vec<TradeData>) {
        let mut leaves: Vec<Fr> = (0..(1u64 << DEPTH)).map(Fr::from).collect();
        for s in specs {
            leaves[s.bi] = account_leaf3(s.buyer_id, Fr::from(s.bb), Fr::from(s.bq));
            leaves[s.si] = account_leaf3(s.seller_id, Fr::from(s.sb), Fr::from(s.sq));
        }
        let mut tree = MerkleTree::new(leaves);
        let prev_root = tree.root();

        let mut trades = Vec::with_capacity(specs.len());
        for s in specs {
            let buyer_path = tree.path(s.bi);
            let buyer_new = account_leaf3(
                s.buyer_id,
                Fr::from(s.bb) + Fr::from(s.base_amt),
                Fr::from(s.bq) - Fr::from(s.quote_amt),
            );
            tree.update(s.bi, buyer_new);

            let seller_path = tree.path(s.si);
            let seller_new = account_leaf3(
                s.seller_id,
                Fr::from(s.sb) - Fr::from(s.base_amt),
                Fr::from(s.sq) + Fr::from(s.quote_amt),
            );
            tree.update(s.si, seller_new);

            trades.push(TradeData {
                buyer_id: s.buyer_id,
                seller_id: s.seller_id,
                base_amount: Fr::from(s.base_amt),
                quote_amount: Fr::from(s.quote_amt),
                buyer_base: Fr::from(s.bb),
                buyer_quote: Fr::from(s.bq),
                seller_base: Fr::from(s.sb),
                seller_quote: Fr::from(s.sq),
                buyer_path,
                seller_path,
            });
        }
        (prev_root, tree.root(), trades)
    }

    fn sample_specs() -> Vec<Spec> {
        let specs = vec![
            Spec {
                buyer_id: Fr::from(0x10u64),
                seller_id: Fr::from(0x11u64),
                bi: 1,
                si: 2,
                bb: 10,
                bq: 1000,
                sb: 50,
                sq: 0,
                base_amt: 2,
                quote_amt: 400,
            },
            Spec {
                buyer_id: Fr::from(0x20u64),
                seller_id: Fr::from(0x21u64),
                bi: 10,
                si: 11,
                bb: 5,
                bq: 500,
                sb: 30,
                sq: 7,
                base_amt: 1,
                quote_amt: 100,
            },
            Spec {
                buyer_id: Fr::from(0x30u64),
                seller_id: Fr::from(0x31u64),
                bi: 100,
                si: 101,
                bb: 80,
                bq: 9000,
                sb: 200,
                sq: 1,
                base_amt: 20,
                quote_amt: 3000,
            },
            Spec {
                buyer_id: Fr::from(0x40u64),
                seller_id: Fr::from(0x41u64),
                bi: 250,
                si: 251,
                bb: 1,
                bq: 1,
                sb: 1,
                sq: 1,
                base_amt: 1,
                quote_amt: 1,
            },
        ];
        assert_eq!(specs.len(), BATCH_SIZE);
        specs
    }

    #[test]
    fn batch_of_trades_proves_and_verifies() {
        let mut rng = StdRng::seed_from_u64(4);
        let (prev_root, new_root, trades) = build_batch(&sample_specs());

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(BatchTradeCircuit::blank(), &mut rng).unwrap();
        let circuit = BatchTradeCircuit::new(prev_root, new_root, trades);
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Only the endpoint roots are public — the rollup property.
        assert!(Groth16::<Bn254>::verify(&vk, &[prev_root, new_root], &proof).unwrap());
        assert!(
            !Groth16::<Bn254>::verify(&vk, &[prev_root, new_root + Fr::from(1u64)], &proof)
                .unwrap()
        );
    }

    #[test]
    fn report_trade_constraints() {
        use ark_relations::r1cs::ConstraintSystem;

        // One trade transition (Merkle folds at DEPTH=8 + range checks), no sigs.
        let (prev, new, bpath, spath) = build_trade(
            Fr::from(0xB0u64),
            Fr::from(0x5Eu64),
            5,
            200,
            10,
            1000,
            50,
            0,
            2,
            400,
        );
        let cs = ConstraintSystem::<Fr>::new_ref();
        TradeTransitionCircuit::new(
            prev,
            new,
            Fr::from(0xB0u64),
            Fr::from(0x5Eu64),
            Fr::from(2u64),
            Fr::from(400u64),
            Fr::from(10u64),
            Fr::from(1000u64),
            Fr::from(50u64),
            Fr::from(0u64),
            bpath,
            spath,
        )
        .generate_constraints(cs.clone())
        .unwrap();
        println!(
            "TradeTransition (DEPTH={DEPTH}): {} constraints/trade",
            cs.num_constraints()
        );

        // A full BATCH_SIZE batch.
        let (pr, nr, trades) = build_batch(&sample_specs());
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        BatchTradeCircuit::new(pr, nr, trades)
            .generate_constraints(cs2.clone())
            .unwrap();
        println!(
            "BatchTradeCircuit ({BATCH_SIZE} trades): {} constraints ({} /trade)",
            cs2.num_constraints(),
            cs2.num_constraints() / BATCH_SIZE,
        );
    }

    #[test]
    fn batch_with_one_overdraw_is_unsatisfiable() {
        use ark_relations::r1cs::ConstraintSystem;

        // The 3rd trade's seller holds only 5 base but the trade moves 20.
        let mut specs = sample_specs();
        specs[2].sb = 5;
        let (prev_root, new_root, trades) = build_batch(&specs);

        let circuit = BatchTradeCircuit::new(prev_root, new_root, trades);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // One trade in the middle of the batch underflows -> whole batch invalid.
        assert!(!cs.is_satisfied().unwrap());
    }

    // ----- Slice 4a: differential test against the Rust reference spec -----

    /// Mix of values that exercises both soundness gates from both sides: zeros,
    /// small/medium amounts (affordable and not), and near-`u64::MAX` balances
    /// (so the receiving side's add overflows).
    fn pick(rng: &mut StdRng) -> u64 {
        use ark_std::rand::Rng;
        match rng.gen_range(0..5) {
            0 => 0,
            1 => rng.gen_range(1..1_000),
            2 => rng.gen_range(1..1_000_000),
            3 => u64::MAX - rng.gen_range(0..1_000),
            // `r#gen`: `gen` is a reserved keyword in edition 2024 (this crate is
            // 2021, but the raw identifier keeps rust-analyzer from flagging it).
            _ => rng.r#gen::<u64>(),
        }
    }

    /// For many random trades, the circuit's satisfiability must equal the
    /// reference rule's accept/reject. Uses `is_satisfied()` (no Groth16
    /// setup/prove) so it stays fast and laptop-safe across many iterations.
    #[test]
    fn circuit_matches_reference_over_random_trades() {
        use crate::reference::TradeScenario;

        let mut rng = StdRng::seed_from_u64(7);
        let buyer_id = Fr::from(0xB0u64);
        let seller_id = Fr::from(0x5Eu64);

        // Each iteration builds a Poseidon tree + evaluates a Poseidon-heavy
        // constraint system (no proving). 64 with the biased `pick` covers the
        // accept/reject boundary while keeping the suite quick.
        for _ in 0..64 {
            let (bb, bq, sb, sq) = (
                pick(&mut rng),
                pick(&mut rng),
                pick(&mut rng),
                pick(&mut rng),
            );
            let (base_amt, quote_amt) = (pick(&mut rng), pick(&mut rng));
            let sc = TradeScenario {
                buyer_base: bb,
                buyer_quote: bq,
                seller_base: sb,
                seller_quote: sq,
                base_amount: base_amt,
                quote_amount: quote_amt,
            };

            // Roots are built with field arithmetic (wraps consistently when a
            // side can't afford its leg), so the ONLY thing that can make the
            // circuit unsatisfiable is the range checks — exactly the rule the
            // reference encodes.
            let (prev_root, new_root, buyer_path, seller_path) = build_trade(
                buyer_id, seller_id, 5, 200, bb, bq, sb, sq, base_amt, quote_amt,
            );
            let circuit = TradeTransitionCircuit::new(
                prev_root,
                new_root,
                buyer_id,
                seller_id,
                Fr::from(base_amt),
                Fr::from(quote_amt),
                Fr::from(bb),
                Fr::from(bq),
                Fr::from(sb),
                Fr::from(sq),
                buyer_path,
                seller_path,
            );
            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert_eq!(
                cs.is_satisfied().unwrap(),
                sc.accepts(),
                "circuit/reference disagree on {sc:?}"
            );
        }
    }

    /// Documents the one deliberate gap between this circuit and
    /// `clearing::SpotSwap`: a zero-amount trade is a no-op the circuit accepts
    /// but `clearing` rejects (`NonPositiveQuantity`, enforced at matching).
    #[test]
    fn nonzero_amounts_are_the_only_divergence_from_clearing() {
        use crate::reference::TradeScenario;

        let zero_trade = TradeScenario {
            buyer_base: 10,
            buyer_quote: 10,
            seller_base: 10,
            seller_quote: 10,
            base_amount: 0,
            quote_amount: 0,
        };
        // The reference models the *circuit's* rule, which accepts the no-op...
        assert!(zero_trade.accepts());

        // ...and the circuit is indeed satisfiable for it (a no-op transition:
        // prev_root == new_root).
        let buyer_id = Fr::from(0xB0u64);
        let seller_id = Fr::from(0x5Eu64);
        let (prev_root, new_root, buyer_path, seller_path) =
            build_trade(buyer_id, seller_id, 5, 200, 10, 10, 10, 10, 0, 0);
        assert_eq!(
            prev_root, new_root,
            "a zero-amount trade must not move the root"
        );
        let circuit = TradeTransitionCircuit::new(
            prev_root,
            new_root,
            buyer_id,
            seller_id,
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(10u64),
            Fr::from(10u64),
            Fr::from(10u64),
            Fr::from(10u64),
            buyer_path,
            seller_path,
        );
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        // clearing::SpotSwap would reject this with NonPositiveQuantity — the gap
        // is intentional (positivity is a matching concern; see reference.rs).
    }

    // ----- Slice 4b: Solana / alt_bn128 wire format -----

    /// A real proof encoded to the big-endian uncompressed Solana wire form and
    /// decoded back must still verify — proving the encoding is faithful and
    /// invertible (the part we can check without an on-chain verifier).
    #[test]
    fn proof_round_trips_through_solana_wire_format_and_reverifies() {
        let mut rng = StdRng::seed_from_u64(11);

        // Merkle inclusion is the cheapest circuit to set up + prove.
        let leaf = Fr::rand(&mut rng);
        let siblings: Vec<Fr> = (0..DEPTH).map(|_| Fr::rand(&mut rng)).collect();
        let bits: Vec<bool> = (0..DEPTH).map(|i| i % 2 == 0).collect();
        let root = compute_root(leaf, &siblings, &bits);

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(MerkleInclusionCircuit::blank(), &mut rng)
                .unwrap();
        let proof = Groth16::<Bn254>::prove(
            &pk,
            MerkleInclusionCircuit::new(root, leaf, siblings, bits),
            &mut rng,
        )
        .unwrap();
        assert!(Groth16::<Bn254>::verify(&vk, &[root], &proof).unwrap());

        // Encode -> bytes -> decode, then re-verify the decoded proof.
        let bytes = solana::proof_to_bytes(&proof);
        assert_eq!(bytes.len(), 256);
        let parsed = solana::proof_from_bytes(&bytes);
        assert!(
            Groth16::<Bn254>::verify(&vk, &[root], &parsed).unwrap(),
            "decoded proof must still verify"
        );

        // Public input is one 32-byte big-endian scalar; VK has one IC point per
        // public input plus the constant term.
        assert_eq!(solana::public_input_to_bytes(&root).len(), 32);
        assert_eq!(vk.gamma_abc_g1.len(), 2, "1 public input + constant term");
        let vk_bytes = solana::vk_to_bytes(&vk);
        assert_eq!(vk_bytes.len(), 64 + 128 * 3 + 64 * vk.gamma_abc_g1.len());
    }

    /// The G1/G2 codecs are exact inverses (point identity, not just re-verify).
    #[test]
    fn g1_g2_codecs_are_invertible() {
        use ark_ec::AffineRepr;
        let mut rng = StdRng::seed_from_u64(12);
        let g1 = (ark_bn254::G1Affine::generator() * Fr::rand(&mut rng)).into();
        let g2 = (ark_bn254::G2Affine::generator() * Fr::rand(&mut rng)).into();
        assert_eq!(solana::g1_from_bytes(&solana::g1_to_bytes(&g1)), g1);
        assert_eq!(solana::g2_from_bytes(&solana::g2_to_bytes(&g2)), g2);
    }

    // ----- Slice 5b: authenticated trade (in-circuit signature verification) --

    /// Build a valid authenticated trade + its tree over auth leaves.
    fn sample_authed_trade() -> (AuthedTrade, Vec<Fr>) {
        use crate::eddsa::SecretKey;
        let buyer_sk = SecretKey::from_seed(1);
        let seller_sk = SecretKey::from_seed(2);
        let matcher_sk = SecretKey::from_seed(3);
        let (buyer_pk, seller_pk, matcher_pk) =
            (buyer_sk.public(), seller_sk.public(), matcher_sk.public());

        let buyer_id = Fr::from(0xB0u64);
        let seller_id = Fr::from(0x5Eu64);
        let market = Fr::from(0xA1u64);
        let (bi, si) = (5usize, 200usize);
        let (bb, bq, sb, sq) = (10u64, 1000u64, 50u64, 0u64);
        let (fb, fq) = (2u64, 400u64);
        // order terms (base cap, limit price, salt) — not all enforced yet.
        let (ob, ol, osalt) = (5u64, 250u64, 1u64);
        let (sob, sol, ssalt) = (5u64, 180u64, 2u64);

        let buy_msg = [
            buyer_id,
            market,
            Fr::from(0u64),
            Fr::from(ob),
            Fr::from(ol),
            Fr::from(osalt),
        ];
        let sell_msg = [
            seller_id,
            market,
            Fr::from(1u64),
            Fr::from(sob),
            Fr::from(sol),
            Fr::from(ssalt),
        ];
        let buy_sig = buyer_sk.sign(&buy_msg);
        let sell_sig = seller_sk.sign(&sell_msg);
        let matcher_sig = matcher_sk.sign(&[
            crate::poseidon_hash(&buy_msg),
            crate::poseidon_hash(&sell_msg),
            Fr::from(fb),
            Fr::from(fq),
        ]);

        // Tree over authenticated leaves (id + balances + committed pubkey).
        let mut leaves: Vec<Fr> = (0..(1u64 << DEPTH)).map(Fr::from).collect();
        leaves[bi] = account_leaf_auth(buyer_id, Fr::from(bb), Fr::from(bq), &buyer_pk);
        leaves[si] = account_leaf_auth(seller_id, Fr::from(sb), Fr::from(sq), &seller_pk);
        let prev = MerkleTree::new(leaves);
        let prev_root = prev.root();
        let buyer_path = prev.path(bi);
        let buyer_new =
            account_leaf_auth(buyer_id, Fr::from(bb + fb), Fr::from(bq - fq), &buyer_pk);
        let mut mid = prev.clone();
        mid.update(bi, buyer_new);
        let seller_path = mid.path(si);
        let seller_new =
            account_leaf_auth(seller_id, Fr::from(sb - fb), Fr::from(sq + fq), &seller_pk);
        let mut new_root = mid.clone();
        new_root.update(si, seller_new);
        let new_root = new_root.root();

        let trade = AuthedTrade {
            prev_root,
            new_root,
            market,
            matcher_pk,
            buyer: AuthedParty {
                id: buyer_id,
                base: Fr::from(bb),
                quote: Fr::from(bq),
                pk: buyer_pk,
                order_base: Fr::from(ob),
                order_limit: Fr::from(ol),
                order_salt: Fr::from(osalt),
                sig: buy_sig,
                path: buyer_path,
            },
            seller: AuthedParty {
                id: seller_id,
                base: Fr::from(sb),
                quote: Fr::from(sq),
                pk: seller_pk,
                order_base: Fr::from(sob),
                order_limit: Fr::from(sol),
                order_salt: Fr::from(ssalt),
                sig: sell_sig,
                path: seller_path,
            },
            fill_base: Fr::from(fb),
            fill_quote: Fr::from(fq),
            matcher_sig,
        };
        let public = vec![prev_root, new_root, matcher_pk.0.x, matcher_pk.0.y];
        (trade, public)
    }

    #[test]
    fn authed_trade_proves_and_verifies() {
        let mut rng = StdRng::seed_from_u64(20);
        let (trade, public) = sample_authed_trade();

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(AuthedTradeCircuit::blank(), &mut rng)
                .unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, AuthedTradeCircuit::new(trade), &mut rng).unwrap();
        assert!(Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
    }

    #[test]
    fn authed_trade_forged_signature_is_unsatisfiable() {
        use crate::eddsa::SecretKey;
        use ark_relations::r1cs::ConstraintSystem;

        let (mut trade, _) = sample_authed_trade();
        // The buyer's order is now "signed" by the wrong key. The committed leaf
        // still holds the buyer's real key, so the signature check fails.
        let buy_msg = [
            trade.buyer.id,
            trade.market,
            Fr::from(0u64),
            trade.buyer.order_base,
            trade.buyer.order_limit,
            trade.buyer.order_salt,
        ];
        trade.buyer.sig = SecretKey::from_seed(99).sign(&buy_msg);

        let cs = ConstraintSystem::<Fr>::new_ref();
        AuthedTradeCircuit::new(trade)
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
