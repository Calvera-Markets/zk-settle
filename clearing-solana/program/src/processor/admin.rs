use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::{
    error::ClearingError,
    instruction::{RotateVkArgs, SetAdminArgs},
    pda,
    state::Config,
};

pub fn set_admin(
    program_id: &Address,
    accounts: &[AccountView],
    args: &SetAdminArgs,
) -> ProgramResult {
    let [admin, config, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !config.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }
    let (expected, _) = pda::find_config(program_id);
    if config.address() != &expected {
        return Err(ClearingError::InvalidPda.into());
    }
    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    if admin.address().as_array() != &cfg.admin {
        return Err(ClearingError::Unauthorized.into());
    }
    cfg.admin = args.new_admin;
    cfg.pack(&mut config.try_borrow_mut()?)
}

pub fn rotate_vk(
    program_id: &Address,
    accounts: &[AccountView],
    args: &RotateVkArgs,
) -> ProgramResult {
    let [admin, config, vk_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !config.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }
    let (expected, _) = pda::find_config(program_id);
    if config.address() != &expected {
        return Err(ClearingError::InvalidPda.into());
    }
    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    if admin.address().as_array() != &cfg.admin {
        return Err(ClearingError::Unauthorized.into());
    }
    cfg.vk_account = vk_account.address().to_bytes();
    cfg.guest_vk_hash = args.guest_vk_hash;
    cfg.groth16_vk_hash_prefix = args.groth16_vk_hash_prefix;
    cfg.proof_version = args.proof_version;
    cfg.pack(&mut config.try_borrow_mut()?)
}

pub fn rotate_open_vk(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin, config, open_vk_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !config.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }
    let (expected, _) = pda::find_config(program_id);
    if config.address() != &expected {
        return Err(ClearingError::InvalidPda.into());
    }
    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    if admin.address().as_array() != &cfg.admin {
        return Err(ClearingError::Unauthorized.into());
    }
    cfg.open_vk_account = open_vk_account.address().to_bytes();
    cfg.pack(&mut config.try_borrow_mut()?)
}
