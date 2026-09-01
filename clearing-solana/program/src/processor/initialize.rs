use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::create_account_with_minimum_balance_signed;

use crate::{
    error::ClearingError,
    instruction::InitializeArgs,
    pda::{self, CONFIG_SEED},
    state::Config,
};

pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    args: &InitializeArgs,
) -> ProgramResult {
    let [payer, config, vk_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() || !payer.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !config.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }
    if system_program.address() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_config, bump) = pda::find_config(program_id);
    if config.address() != &expected_config {
        return Err(ClearingError::InvalidPda.into());
    }
    if !config.owned_by(&pinocchio_system::ID) || !config.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }

    let (_vault_authority, vault_authority_bump) = pda::find_vault_authority(program_id);

    let bump_seed = [bump];
    let seeds = [Seed::from(CONFIG_SEED), Seed::from(bump_seed.as_ref())];
    let signer = Signer::from(&seeds);

    create_account_with_minimum_balance_signed(
        config,
        Config::LEN,
        program_id,
        payer,
        None,
        &[signer],
    )?;

    let cfg = Config {
        disc: Config::DISC,
        bump,
        vault_authority_bump,
        frozen: 0,
        proof_version: args.proof_version,
        groth16_vk_hash_prefix: args.groth16_vk_hash_prefix,
        _pad: [],
        root: args.genesis_root,
        admin: args.admin,
        matcher_key: args.matcher_key,
        freeze_authority: args.freeze_authority,
        vk_account: vk_account.address().to_bytes(),
        guest_vk_hash: args.guest_vk_hash,
        batch_seq: 0,
        expiry_height: 0,
        next_deposit_nonce: 0,
        next_asset_id: 0,
        _pad2: [0; 4],
    };

    let mut data = config.try_borrow_mut()?;
    cfg.pack(&mut data)
}
