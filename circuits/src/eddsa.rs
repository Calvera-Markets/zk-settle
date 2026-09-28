//! BabyJubJub EdDSA-Poseidon signatures, native and in-circuit.
//!
//! Ed25519 inside a BN254 circuit is foreign-field arithmetic (millions of
//! constraints). BabyJubJub (`ark_ed_on_bn254`) uses BN254's scalar field, so
//! a check is thousands of constraints. Users sign with a registered
//! BabyJubJub app-key, not their L1 wallet key.
//!
//! Scheme (a Schnorr / EdDSA-style construction with a Poseidon challenge):
//! - key: `sk ∈ Fr(BabyJubJub)`, `A = sk·B` where `B` is the curve generator.
//! - sign(m): nonce `k = H(sk, m)`, `R = k·B`, challenge `e = H(R, A, m)`,
//!   `s = k + e·sk (mod l)`. Signature is `(R, s)`.
//! - verify: recompute `e`, check `s·B == R + e·A`.
//!
//! Native and in-circuit verification compute the **same** equation over the same
//! points and the same challenge bits, so they agree by construction (locked by
//! `gadget_matches_native`).
//!
//! Custom construction: Poseidon params are arkworks-generated; the challenge
//! is the low [`CHALLENGE_BITS`] of the Poseidon output. Tested, not audited.
//! Cofactor/subgroup handling and `s < l` (malleability) need review for
//! production.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::{EdwardsAffine, Fr as JubScalar};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use ark_bn254::Fr as F;

/// Bits of the Poseidon output used as the challenge scalar. Kept below
/// `log2(l)` (the BabyJubJub subgroup order ≈ 2^251) so the challenge is always a
/// valid scalar `< l` and native/circuit multiplication agree without a modular
/// reduction. 250 bits is ample Fiat-Shamir security.
pub const CHALLENGE_BITS: usize = 250;

/// A BabyJubJub secret key (a scalar).
#[derive(Clone, Copy)]
pub struct SecretKey(pub JubScalar);

/// A BabyJubJub public key (a curve point `A = sk·B`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub EdwardsAffine);

/// A signature `(R, s)`: a curve point and a scalar.
#[derive(Clone, Copy)]
pub struct Signature {
    pub r: EdwardsAffine,
    pub s: JubScalar,
}

/// The curve generator `B`.
fn base() -> EdwardsAffine {
    EdwardsAffine::generator()
}

/// Reinterpret a BabyJubJub scalar as a base-field (`F`) element. Sound because
/// `l < q`, so the scalar's integer value fits in `F` with no reduction.
pub fn jub_to_f(s: JubScalar) -> F {
    F::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le())
}

/// The challenge scalar `e`: the low [`CHALLENGE_BITS`] of `Poseidon(R, A, m)`,
/// as a BabyJubJub scalar. Matches the circuit's `e_bits[..CHALLENGE_BITS]`.
fn challenge(r: &EdwardsAffine, pk: &EdwardsAffine, msg: &[F]) -> JubScalar {
    let mut inputs = vec![r.x, r.y, pk.x, pk.y];
    inputs.extend_from_slice(msg);
    let e_fq = crate::poseidon_hash(&inputs);
    let mut bits = e_fq.into_bigint().to_bits_le();
    bits.truncate(CHALLENGE_BITS);
    JubScalar::from_bigint(<JubScalar as PrimeField>::BigInt::from_bits_le(&bits))
        .expect("CHALLENGE_BITS < log2(l), so the value is a valid scalar")
}

impl SecretKey {
    /// Deterministic key from a seed (pseudo-random scalar via Poseidon).
    pub fn from_seed(seed: u64) -> Self {
        let h = crate::poseidon_hash(&[F::from(seed)]);
        SecretKey(JubScalar::from_le_bytes_mod_order(
            &h.into_bigint().to_bytes_le(),
        ))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey((base().into_group() * self.0).into_affine())
    }

    /// Sign `msg`. Deterministic nonce `k = H(sk, msg)` (no RNG).
    pub fn sign(&self, msg: &[F]) -> Signature {
        let mut nonce_inputs = vec![jub_to_f(self.0)];
        nonce_inputs.extend_from_slice(msg);
        let k_fq = crate::poseidon_hash(&nonce_inputs);
        let k = JubScalar::from_le_bytes_mod_order(&k_fq.into_bigint().to_bytes_le());

        let r = (base().into_group() * k).into_affine();
        let pk = self.public().0;
        let e = challenge(&r, &pk, msg);
        let s = k + e * self.0;
        Signature { r, s }
    }
}

/// Native verification: `s·B == R + e·A`.
pub fn verify(pk: &PublicKey, msg: &[F], sig: &Signature) -> bool {
    let e = challenge(&sig.r, &pk.0, msg);
    let lhs = base().into_group() * sig.s;
    let rhs = sig.r.into_group() + pk.0.into_group() * e;
    lhs == rhs
}

/// In-circuit verification — the constraint version of [`verify`]. Enforces
/// `s·B == R + e·A` with `e = Poseidon(R, A, msg)`; unsatisfiable for a bad
/// signature. `s` is supplied as a field element (its scalar value `< l`).
pub fn verify_gadget(
    cs: ConstraintSystemRef<F>,
    pk: &EdwardsVar,
    r: &EdwardsVar,
    s: &FpVar<F>,
    msg: &[FpVar<F>],
) -> Result<(), SynthesisError> {
    // Challenge e = Poseidon(R.x, R.y, A.x, A.y, msg...).
    let mut inputs = vec![r.x.clone(), r.y.clone(), pk.x.clone(), pk.y.clone()];
    inputs.extend_from_slice(msg);
    let e = crate::poseidon_hash_gadget(cs.clone(), &inputs)?;

    let e_bits = e.to_bits_le()?;
    let s_bits = s.to_bits_le()?;
    let base_var = EdwardsVar::new_constant(cs.clone(), base().into_group())?;

    // lhs = s·B ; rhs = R + e·A  (e uses the low CHALLENGE_BITS, matching native).
    let lhs = base_var.scalar_mul_le(s_bits.iter())?;
    let e_pk = pk.scalar_mul_le(e_bits[..CHALLENGE_BITS].iter())?;
    let rhs = r + &e_pk;
    lhs.enforce_equal(&rhs)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn msg() -> Vec<F> {
        vec![F::from(42u64), F::from(7u64), F::from(0xBEEFu64)]
    }

    #[test]
    fn native_sign_verify() {
        let sk = SecretKey::from_seed(1);
        let pk = sk.public();
        let m = msg();
        let sig = sk.sign(&m);

        assert!(verify(&pk, &m, &sig));
        // Wrong message rejected.
        assert!(!verify(
            &pk,
            &[F::from(43u64), F::from(7u64), F::from(0xBEEFu64)],
            &sig
        ));
        // Wrong key rejected.
        assert!(!verify(&SecretKey::from_seed(2).public(), &m, &sig));
    }

    /// Allocate a (pk, R, s, msg) set as witnesses and run the verify gadget.
    fn run_gadget(pk: &PublicKey, r_pt: &EdwardsAffine, s: JubScalar, m: &[F]) -> bool {
        let cs = ConstraintSystem::<F>::new_ref();
        let pk_var = EdwardsVar::new_witness(cs.clone(), || Ok(pk.0.into_group())).unwrap();
        let r_var = EdwardsVar::new_witness(cs.clone(), || Ok(r_pt.into_group())).unwrap();
        let s_var = FpVar::new_witness(cs.clone(), || Ok(jub_to_f(s))).unwrap();
        let msg_vars: Vec<_> = m
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();
        verify_gadget(cs.clone(), &pk_var, &r_var, &s_var, &msg_vars).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn gadget_matches_native() {
        let sk = SecretKey::from_seed(1);
        let pk = sk.public();
        let m = msg();
        let sig = sk.sign(&m);

        assert!(verify(&pk, &m, &sig));
        assert!(
            run_gadget(&pk, &sig.r, sig.s, &m),
            "valid signature must satisfy the circuit"
        );
    }

    #[test]
    fn gadget_rejects_forgery() {
        let sk = SecretKey::from_seed(1);
        let pk = sk.public();
        let m = msg();
        let sig = sk.sign(&m);

        // A signature is valid for `m` but checked against a different message.
        let other = [F::from(999u64), F::from(7u64), F::from(0xBEEFu64)];
        assert!(!run_gadget(&pk, &sig.r, sig.s, &other));

        // Tampered `s` is rejected too.
        let bad = Signature {
            r: sig.r,
            s: sig.s + JubScalar::from(1u64),
        };
        assert!(!verify(&pk, &m, &bad));
        assert!(!run_gadget(&pk, &bad.r, bad.s, &m));
    }

    #[test]
    fn report_constraint_count() {
        let sk = SecretKey::from_seed(3);
        let pk = sk.public();
        let m = msg();
        let sig = sk.sign(&m);

        let cs = ConstraintSystem::<F>::new_ref();
        let pk_var = EdwardsVar::new_witness(cs.clone(), || Ok(pk.0.into_group())).unwrap();
        let r_var = EdwardsVar::new_witness(cs.clone(), || Ok(sig.r.into_group())).unwrap();
        let s_var = FpVar::new_witness(cs.clone(), || Ok(jub_to_f(sig.s))).unwrap();
        let msg_vars: Vec<_> = m
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();
        verify_gadget(cs.clone(), &pk_var, &r_var, &s_var, &msg_vars).unwrap();
        assert!(cs.is_satisfied().unwrap());
        // Surfaced so the per-signature cost is visible (run with --nocapture).
        println!(
            "EdDSA verify: {} constraints per signature",
            cs.num_constraints()
        );
    }
}
