use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::create_account_with_minimum_balance_signed;

use crate::{
    error::ClearingError,
    instruction::SettleArgs,
    pda::{self, BATCH_SEED},
    state::{BatchRecord, Config},
};

pub fn process(program_id: &Address, accounts: &[AccountView], args: &SettleArgs) -> ProgramResult {
    let [admin, config, vk_account, batch, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !admin.is_writable() || !config.is_writable() || !batch.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }
    if system_program.address() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_config, _) = pda::find_config(program_id);
    if config.address() != &expected_config {
        return Err(ClearingError::InvalidPda.into());
    }

    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    if cfg.frozen != 0 {
        return Err(ClearingError::Frozen.into());
    }
    if admin.address().as_array() != &cfg.admin {
        return Err(ClearingError::Unauthorized.into());
    }
    if vk_account.address().as_array() != &cfg.vk_account {
        return Err(ClearingError::InvalidAccount.into());
    }

    let seq = cfg.batch_seq;
    let seq_le = seq.to_le_bytes();
    let (expected_batch, batch_bump) = pda::find_batch(program_id, &seq_le);
    if batch.address() != &expected_batch {
        return Err(ClearingError::InvalidPda.into());
    }
    if !batch.owned_by(&pinocchio_system::ID) || !batch.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }

    {
        let vk_data = vk_account.try_borrow()?;
        verify_or_skip_proof(&cfg, &vk_data, args)?;
    }

    let pv = args.public_values();
    if pv.prev_root != cfg.root
        || pv.matcher_key != cfg.matcher_key
        || pv.batch_seq != cfg.batch_seq
        || pv.expiry_height != cfg.expiry_height
    {
        return Err(ClearingError::InvalidProof.into());
    }

    let batch_bump_seed = [batch_bump];
    let batch_seeds = [
        Seed::from(BATCH_SEED),
        Seed::from(seq_le.as_ref()),
        Seed::from(batch_bump_seed.as_ref()),
    ];
    let batch_signer = Signer::from(&batch_seeds);
    create_account_with_minimum_balance_signed(
        batch,
        BatchRecord::LEN,
        program_id,
        admin,
        None,
        &[batch_signer],
    )?;

    let rec = BatchRecord {
        disc: BatchRecord::DISC,
        bump: batch_bump,
        _pad: [0; 7],
        seq,
        new_root: pv.new_root,
        withdrawals_root: pv.withdrawals_root,
        da_hash: args.da_hash,
    };
    {
        let mut data = batch.try_borrow_mut()?;
        rec.pack(&mut data)?;
    }

    cfg.root = pv.new_root;
    cfg.batch_seq = seq.checked_add(1).ok_or(ClearingError::Overflow)?;
    // v1: expiry_height stays pinned at 0; do not advance it.
    let mut data = config.try_borrow_mut()?;
    cfg.pack(&mut data)
}

/// Proof-version dispatch.
///
/// * `mock-proof` + `proof_version == 0`: skip pairing (host / test SBF).
///   Production `bpf-entrypoint` builds do not enable `mock-proof`.
/// * Without skip: `proof_version != 1` → `InvalidProof`.
/// * `proof_version == 1`: SP1 wrap pairing.
fn verify_or_skip_proof(
    cfg: &Config,
    vk_account_data: &[u8],
    args: &SettleArgs,
) -> Result<(), ClearingError> {
    if skip_pairing(cfg.proof_version) {
        return Ok(());
    }
    if cfg.proof_version != 1 {
        return Err(ClearingError::InvalidProof);
    }
    crate::verifier::verify_sp1_wrap(
        vk_account_data,
        &cfg.guest_vk_hash,
        &cfg.groth16_vk_hash_prefix,
        &args.proof,
        &args.public_values,
    )
}

fn skip_pairing(proof_version: u8) -> bool {
    #[cfg(feature = "mock-proof")]
    {
        proof_version == 0
    }
    #[cfg(not(feature = "mock-proof"))]
    {
        let _ = proof_version;
        false
    }
}
