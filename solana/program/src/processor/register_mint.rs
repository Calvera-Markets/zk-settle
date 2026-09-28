use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    error::ProgramError,
};
use pinocchio_system::create_account_with_minimum_balance_signed;
use pinocchio_token_2022::{
    ID as TOKEN_2022, instructions::InitializeAccount3, state::TokenAccount,
};

use crate::{
    error::ClearingError,
    instruction::RegisterMintArgs,
    pda::{self, MINT_SEED, VAULT_SEED},
    state::{Config, MintMeta},
    token::{self, MAX_REGISTERED_MINTS},
};

pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    args: &RegisterMintArgs,
) -> ProgramResult {
    let [
        admin,
        config,
        mint,
        mint_meta,
        vault,
        token_program,
        system_program,
        ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !admin.is_writable()
        || !config.is_writable()
        || !mint_meta.is_writable()
        || !vault.is_writable()
    {
        return Err(ClearingError::InvalidAccount.into());
    }
    if system_program.address() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    token::require_token_2022_program(token_program)?;

    let (expected_config, _) = pda::find_config(program_id);
    if config.address() != &expected_config {
        return Err(ClearingError::InvalidPda.into());
    }

    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    if admin.address().as_array() != &cfg.admin {
        return Err(ClearingError::Unauthorized.into());
    }
    if cfg.next_asset_id >= MAX_REGISTERED_MINTS {
        return Err(ClearingError::Overflow.into());
    }

    let mint_decimals = token::require_plain_token_2022_mint(mint)?;
    if mint_decimals != args.decimals {
        return Err(ClearingError::InvalidAccount.into());
    }

    let mint_key = mint.address().to_bytes();
    let (expected_meta, meta_bump) = pda::find_mint_meta(program_id, &mint_key);
    if mint_meta.address() != &expected_meta {
        return Err(ClearingError::InvalidPda.into());
    }
    let (expected_vault, vault_bump) = pda::find_vault(program_id, &mint_key);
    if vault.address() != &expected_vault {
        return Err(ClearingError::InvalidPda.into());
    }

    let vault_authority = token::vault_authority(program_id, cfg.vault_authority_bump)?;

    if !mint_meta.owned_by(&pinocchio_system::ID) || !mint_meta.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }
    if !vault.owned_by(&pinocchio_system::ID) || !vault.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }

    let asset_id = cfg.next_asset_id;
    cfg.next_asset_id = asset_id.checked_add(1).ok_or(ClearingError::Overflow)?;

    let meta_bump_seed = [meta_bump];
    let meta_seeds = [
        Seed::from(MINT_SEED),
        Seed::from(mint_key.as_ref()),
        Seed::from(meta_bump_seed.as_ref()),
    ];
    let meta_signer = Signer::from(&meta_seeds);
    create_account_with_minimum_balance_signed(
        mint_meta,
        MintMeta::LEN,
        program_id,
        admin,
        None,
        &[meta_signer],
    )?;

    let meta = MintMeta {
        disc: MintMeta::DISC,
        bump: meta_bump,
        decimals: args.decimals,
        _pad: [0; 2],
        asset_id,
        mint: mint_key,
        vault: expected_vault.to_bytes(),
    };
    {
        let mut data = mint_meta.try_borrow_mut()?;
        meta.pack(&mut data)?;
    }

    let vault_bump_seed = [vault_bump];
    let vault_seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(mint_key.as_ref()),
        Seed::from(vault_bump_seed.as_ref()),
    ];
    let vault_signer = Signer::from(&vault_seeds);
    create_account_with_minimum_balance_signed(
        vault,
        TokenAccount::BASE_LEN,
        &TOKEN_2022,
        admin,
        None,
        &[vault_signer],
    )?;

    InitializeAccount3 {
        account: vault,
        mint,
        owner: &vault_authority,
        token_program: token_program.address(),
    }
    .invoke()?;

    let mut data = config.try_borrow_mut()?;
    cfg.pack(&mut data)
}
