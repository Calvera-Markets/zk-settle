//! Known-answer test: a real `clearing-circuits` Groth16 proof, encoded with
//! `vk_to_bytes` / `proof_to_bytes`, verified on-chain via alt_bn128.

use std::path::PathBuf;
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use clearing_circuits::tree::MerkleTree;
use clearing_circuits::{solana, MerkleInclusionCircuit, DEPTH};
use clearing_solana_program::{
    error::ClearingError,
    instruction::VERIFY_PLAIN,
    verifier::{self, encode_vk_account, PROOF_LEN},
    ID as PROGRAM_ID,
};
use mollusk_svm::{result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const FIXTURE_SEED: u64 = 11;

struct Kat {
    vk_account: Vec<u8>,
    proof: [u8; PROOF_LEN],
    public_inputs: Vec<[u8; 32]>,
}

fn prove_merkle_inclusion() -> Kat {
    let mut rng = StdRng::seed_from_u64(FIXTURE_SEED);
    let leaf = Fr::from(7u64);
    let mut leaves: Vec<Fr> = (0..(1u64 << DEPTH)).map(Fr::from).collect();
    leaves[0] = leaf;
    let tree = MerkleTree::new(leaves);
    let root = tree.root();
    let (siblings, bits) = tree.path(0);

    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(MerkleInclusionCircuit::blank(), &mut rng)
            .expect("setup");
    let proof = Groth16::<Bn254>::prove(
        &pk,
        MerkleInclusionCircuit::new(root, leaf, siblings, bits),
        &mut rng,
    )
    .expect("prove");
    assert!(
        Groth16::<Bn254>::verify(&vk, &[root], &proof).unwrap(),
        "native arkworks verify"
    );

    let vk_bytes = solana::vk_to_bytes(&vk);
    assert_eq!(vk.gamma_abc_g1.len(), 2);
    let vk_account = encode_vk_account(&vk_bytes).expect("encode vk");
    assert_eq!(vk_account.len(), 452 + 64 * 2);
    assert_eq!(&vk_account[0..4], &1u32.to_le_bytes());

    Kat {
        vk_account,
        proof: solana::proof_to_bytes(&proof),
        public_inputs: vec![solana::public_input_to_bytes(&root)],
    }
}

fn kat() -> &'static Kat {
    static KAT: OnceLock<Kat> = OnceLock::new();
    KAT.get_or_init(prove_merkle_inclusion)
}

fn write_fixtures(kat: &Kat) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).expect("fixtures dir");
    std::fs::write(dir.join("circuits_vk.bin"), &kat.vk_account).expect("vk fixture");
    std::fs::write(dir.join("circuits_proof.bin"), kat.proof).expect("proof fixture");
    let mut inputs = Vec::new();
    for pi in &kat.public_inputs {
        inputs.extend_from_slice(pi);
    }
    std::fs::write(dir.join("circuits_inputs.bin"), inputs).expect("inputs fixture");
}

fn setup_mollusk() -> Mollusk {
    std::env::set_var("SBF_OUT_DIR", env!("SBF_OUT_DIR"));
    Mollusk::new(&PROGRAM_ID, "clearing_solana_program")
}

fn pack_verify_plain(proof: &[u8; PROOF_LEN], public_inputs: &[[u8; 32]]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + PROOF_LEN + public_inputs.len() * 32);
    data.push(VERIFY_PLAIN);
    data.extend_from_slice(proof);
    for pi in public_inputs {
        data.extend_from_slice(pi);
    }
    data
}

fn verify_ix(vk: Pubkey, proof: &[u8; PROOF_LEN], public_inputs: &[[u8; 32]]) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new_readonly(vk, false)],
        data: pack_verify_plain(proof, public_inputs),
    }
}

fn vk_account(data: Vec<u8>) -> Account {
    Account {
        lamports: 1_000_000_000,
        data,
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

#[test]
fn host_verifies_circuits_merkle_proof() {
    let kat = kat();
    write_fixtures(kat);
    verifier::verify_plain(&kat.vk_account, &kat.proof, &kat.public_inputs)
        .expect("host groth16-solana verify");
}

#[test]
fn host_rejects_tampered_a() {
    let kat = kat();
    let mut proof = kat.proof;
    proof[0] ^= 1;
    assert_eq!(
        verifier::verify_plain(&kat.vk_account, &proof, &kat.public_inputs),
        Err(ClearingError::InvalidProof)
    );
}

#[test]
fn host_rejects_tampered_public_input() {
    let kat = kat();
    let mut inputs = kat.public_inputs.clone();
    inputs[0][31] ^= 1;
    assert_eq!(
        verifier::verify_plain(&kat.vk_account, &kat.proof, &inputs),
        Err(ClearingError::InvalidProof)
    );
}

#[test]
fn mollusk_verifies_circuits_merkle_proof() {
    let kat = kat();
    let mollusk = setup_mollusk();
    let vk = Pubkey::new_from_array([0xA1u8; 32]);
    mollusk.process_and_validate_instruction(
        &verify_ix(vk, &kat.proof, &kat.public_inputs),
        &[(vk, vk_account(kat.vk_account.clone()))],
        &[Check::success()],
    );
}

#[test]
fn mollusk_rejects_tampered_a() {
    let kat = kat();
    let mut proof = kat.proof;
    proof[0] ^= 1;
    let mollusk = setup_mollusk();
    let vk = Pubkey::new_from_array([0xA1u8; 32]);
    mollusk.process_and_validate_instruction(
        &verify_ix(vk, &proof, &kat.public_inputs),
        &[(vk, vk_account(kat.vk_account.clone()))],
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidProof as u32,
        ))],
    );
}

#[test]
fn mollusk_rejects_tampered_public_input() {
    let kat = kat();
    let mut inputs = kat.public_inputs.clone();
    inputs[0][31] ^= 1;
    let mollusk = setup_mollusk();
    let vk = Pubkey::new_from_array([0xA1u8; 32]);
    mollusk.process_and_validate_instruction(
        &verify_ix(vk, &kat.proof, &inputs),
        &[(vk, vk_account(kat.vk_account.clone()))],
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidProof as u32,
        ))],
    );
}

#[test]
fn mollusk_rejects_vk_nr_pubinputs_mismatch() {
    let kat = kat();
    let mut vk_bytes = kat.vk_account.clone();
    vk_bytes[0..4].copy_from_slice(&0u32.to_le_bytes());
    let mollusk = setup_mollusk();
    let vk = Pubkey::new_from_array([0xA1u8; 32]);
    mollusk.process_and_validate_instruction(
        &verify_ix(vk, &kat.proof, &kat.public_inputs),
        &[(vk, vk_account(vk_bytes))],
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidAccount as u32,
        ))],
    );
}
