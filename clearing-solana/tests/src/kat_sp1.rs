//! SP1 wrap known-answer. Skips unless `fixtures/sp1/proof.bin` is present
//! (356-byte on-chain wrap). Do not generate that file in this test.

use std::fs;
use std::path::PathBuf;

use clearing_solana_program::{
    error::ClearingError,
    instruction::{pack_public_values, InitializeArgs, SettleArgs, SETTLE_PROOF_LEN},
    pda,
    state::{BatchRecord, Config},
    verifier::WRAP_PROOF_LEN,
    ID as PROGRAM_ID,
};
use litesvm::LiteSVM;
use solana_account::Account as SolAccount;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

struct WrapFixture {
    proof: [u8; WRAP_PROOF_LEN],
    public_values: [u8; 144],
    guest_vk_hash: [u8; 32],
    vk_account: Vec<u8>,
    prefix: [u8; 4],
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/sp1")
}

fn load_wrap_fixture() -> Option<WrapFixture> {
    let dir = fixtures_dir();
    let proof_vec = fs::read(dir.join("proof.bin")).ok()?;
    if proof_vec.len() != WRAP_PROOF_LEN {
        eprintln!(
            "skip kat_sp1: proof.bin is {} bytes, want {WRAP_PROOF_LEN}",
            proof_vec.len()
        );
        return None;
    }
    let mut proof = [0u8; WRAP_PROOF_LEN];
    proof.copy_from_slice(&proof_vec);

    let pv_vec = fs::read(dir.join("public_values.bin")).ok()?;
    if pv_vec.len() != 144 {
        return None;
    }
    let mut public_values = [0u8; 144];
    public_values.copy_from_slice(&pv_vec);

    let hash_vec = fs::read(dir.join("guest_vk_hash.bin")).ok()?;
    if hash_vec.len() != 32 {
        return None;
    }
    let mut guest_vk_hash = [0u8; 32];
    guest_vk_hash.copy_from_slice(&hash_vec);

    let vk_account = fs::read(dir.join("vk_account.bin"))
        .ok()
        .or_else(|| fs::read(dir.join("groth16_vk.bin")).ok())?;
    if vk_account.len() < 452 + 64 * 3 {
        eprintln!(
            "skip kat_sp1: vk account too short ({} bytes); need groth16-solana layout",
            vk_account.len()
        );
        return None;
    }

    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&proof[0..4]);
    Some(WrapFixture {
        proof,
        public_values,
        guest_vk_hash,
        vk_account,
        prefix,
    })
}

fn program_elf() -> Vec<u8> {
    std::fs::read(format!(
        "{}/clearing_solana_program.so",
        env!("SBF_OUT_DIR")
    ))
    .expect("sbf program")
}

fn setup_svm() -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program(PROGRAM_ID, &program_elf()).unwrap();
    svm
}

fn send_ok(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> u64 {
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).unwrap().compute_units_consumed
}

fn send_err(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> u32 {
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    match svm.send_transaction(tx).unwrap_err().err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => code,
        other => panic!("unexpected error: {other:?}"),
    }
}

fn settle_ix(
    admin: Pubkey,
    vk: Pubkey,
    proof: [u8; SETTLE_PROOF_LEN],
    public_values: [u8; 144],
) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let pv = clearing_solana_program::instruction::PublicValues::unpack(&public_values);
    let (batch, _) = pda::find_batch(&PROGRAM_ID, &pv.batch_seq.to_le_bytes());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk, false),
            AccountMeta::new(batch, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: SettleArgs {
            proof,
            public_values,
            da_hash: [0xDDu8; 32],
        }
        .pack()
        .to_vec(),
    }
}

fn boot_wrap(fix: &WrapFixture) -> (LiteSVM, Keypair, Pubkey, Pubkey) {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let vk = Pubkey::new_from_array([0xEEu8; 32]);
    let lamports = svm
        .minimum_balance_for_rent_exemption(fix.vk_account.len())
        .max(1);
    svm.set_account(
        vk,
        SolAccount {
            lamports,
            data: fix.vk_account.clone(),
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let pv = clearing_solana_program::instruction::PublicValues::unpack(&fix.public_values);
    let args = InitializeArgs {
        genesis_root: pv.prev_root,
        admin: *payer.pubkey().as_array(),
        matcher_key: pv.matcher_key,
        freeze_authority: [0x44u8; 32],
        guest_vk_hash: fix.guest_vk_hash,
        groth16_vk_hash_prefix: fix.prefix,
        proof_version: 1,
    };
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: args.pack().to_vec(),
    };
    send_ok(&mut svm, &payer, ix);
    (svm, payer, config, vk)
}

#[test]
fn kat_sp1_wrap_known_answer() {
    let Some(fix) = load_wrap_fixture() else {
        eprintln!("skip kat_sp1: fixtures/sp1/proof.bin (356) + pv + vk not present");
        return;
    };
    let (mut svm, payer, config, vk) = boot_wrap(&fix);
    let cu = send_ok(
        &mut svm,
        &payer,
        settle_ix(payer.pubkey(), vk, fix.proof, fix.public_values),
    );
    assert!(
        cu <= 400_000,
        "wrap settle {cu} CU exceeds 400k (redesign if > 600k)"
    );

    let pv = clearing_solana_program::instruction::PublicValues::unpack(&fix.public_values);
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.root, pv.new_root);
    assert_eq!(cfg.batch_seq, pv.batch_seq + 1);
    assert_eq!(cfg.expiry_height, 0);

    let (batch, _) = pda::find_batch(&PROGRAM_ID, &pv.batch_seq.to_le_bytes());
    let rec = BatchRecord::unpack(&svm.get_account(&batch).unwrap().data).unwrap();
    assert_eq!(rec.withdrawals_root, pv.withdrawals_root);
    assert_eq!(rec.da_hash, [0xDDu8; 32]);
}

#[test]
fn kat_sp1_rejects_tampered_a_pv_and_prefix() {
    let Some(fix) = load_wrap_fixture() else {
        eprintln!("skip kat_sp1 tamper: no fixtures");
        return;
    };

    let (mut svm, payer, config, vk) = boot_wrap(&fix);
    let mut tampered_a = fix.proof;
    tampered_a[clearing_solana_program::verifier::WRAP_ABC_OFF] ^= 1;
    assert_eq!(
        send_err(
            &mut svm,
            &payer,
            settle_ix(payer.pubkey(), vk, tampered_a, fix.public_values)
        ),
        ClearingError::InvalidProof as u32
    );
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    let pv = clearing_solana_program::instruction::PublicValues::unpack(&fix.public_values);
    assert_eq!(cfg.root, pv.prev_root);
    assert_eq!(cfg.batch_seq, 0);

    let (mut svm, payer, _config, vk) = boot_wrap(&fix);
    let orig = clearing_solana_program::instruction::PublicValues::unpack(&fix.public_values);
    let mut withdrawals = orig.withdrawals_root;
    withdrawals[0] ^= 1;
    let bad_packed = pack_public_values(
        &orig.prev_root,
        &orig.new_root,
        &withdrawals,
        &orig.matcher_key,
        orig.batch_seq,
        orig.expiry_height,
    );
    assert_eq!(
        send_err(
            &mut svm,
            &payer,
            settle_ix(payer.pubkey(), vk, fix.proof, bad_packed)
        ),
        ClearingError::InvalidProof as u32
    );

    let (mut svm, payer, _config, vk) = boot_wrap(&fix);
    let mut bad_prefix = fix.proof;
    bad_prefix[0] ^= 1;
    assert_eq!(
        send_err(
            &mut svm,
            &payer,
            settle_ix(payer.pubkey(), vk, bad_prefix, fix.public_values)
        ),
        ClearingError::InvalidProof as u32
    );
}
