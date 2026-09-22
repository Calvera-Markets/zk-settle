//! Circuits-mode (`proof_version = 2`) Groth16: ClaimOpenCircuit via verify_plain.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use clearing_circuits::tree::MerkleTree;
use clearing_circuits::{solana, ClaimOpenCircuit, DEPTH};
use clearing_solana_program::{
    error::ClearingError,
    instruction::VERIFY_PLAIN,
    verifier::{encode_vk_account, PROOF_LEN},
    ID as PROGRAM_ID,
};
use mollusk_svm::{result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

fn prove_claim_open() -> (Vec<u8>, [u8; PROOF_LEN], Vec<[u8; 32]>) {
    let mut rng = StdRng::seed_from_u64(21);
    let owner = Fr::from(1u64);
    let asset = Fr::from(0u64);
    let amount = Fr::from(100u64);
    let leaf = clearing_circuits::claim_open_leaf(owner, asset, amount);
    let mut leaves: Vec<Fr> = (0..(1u64 << DEPTH)).map(Fr::from).collect();
    leaves[0] = leaf;
    let tree = MerkleTree::new(leaves);
    let root = tree.root();
    let (siblings, bits) = tree.path(0);
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(ClaimOpenCircuit::blank(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(
        &pk,
        ClaimOpenCircuit::new(root, owner, asset, amount, siblings, bits),
        &mut rng,
    )
    .unwrap();
    let vk_bytes = solana::vk_to_bytes(&vk);
    let vk_account = encode_vk_account(&vk_bytes).unwrap();
    let public_inputs = vec![
        solana::public_input_to_bytes(&root),
        solana::public_input_to_bytes(&owner),
        solana::public_input_to_bytes(&asset),
        solana::public_input_to_bytes(&amount),
    ];
    (vk_account, solana::proof_to_bytes(&proof), public_inputs)
}

fn packed_inputs(public_inputs: &[[u8; 32]]) -> Vec<u8> {
    let mut inputs = Vec::with_capacity(public_inputs.len() * 32);
    for pi in public_inputs {
        inputs.extend_from_slice(pi);
    }
    inputs
}

fn mollusk() -> Mollusk {
    std::env::set_var("SBF_OUT_DIR", env!("SBF_OUT_DIR"));
    Mollusk::new(&PROGRAM_ID, "clearing_solana_program")
}

#[test]
fn circuits_claim_open_verifies_on_chain() {
    let (vk_account, proof, inputs) = prove_claim_open();
    let vk_pubkey = Pubkey::new_from_array([7u8; 32]);
    let mut data = proof.to_vec();
    data.extend_from_slice(&packed_inputs(&inputs));
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new_readonly(vk_pubkey, false)],
        data: {
            let mut d = vec![VERIFY_PLAIN];
            d.extend_from_slice(&data);
            d
        },
    };
    let vk_acc = Account {
        lamports: 1_000_000_000,
        data: vk_account,
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    };
    mollusk().process_and_validate_instruction(
        &ix,
        &[(vk_pubkey, vk_acc.clone())],
        &[Check::success()],
    );

    let mut bad = proof;
    bad[0] ^= 1;
    let mut data = bad.to_vec();
    data.extend_from_slice(&packed_inputs(&inputs));
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new_readonly(vk_pubkey, false)],
        data: {
            let mut d = vec![VERIFY_PLAIN];
            d.extend_from_slice(&data);
            d
        },
    };
    mollusk().process_and_validate_instruction(
        &ix,
        &[(
            vk_pubkey,
            Account {
                lamports: 1_000_000_000,
                data: vk_acc.data,
                owner: PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )],
        &[Check::err(solana_program_error::ProgramError::Custom(
            ClearingError::InvalidProof as u32,
        ))],
    );
}
