use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::create_account_with_minimum_balance_signed;
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    error::ClearingError,
    hash,
    instruction::ClaimArgs,
    pda::{self, CLAIM_SEED, VAULT_AUTHORITY_SEED},
    state::{BatchRecord, Config, MintMeta, Nullifier},
    token,
};

pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    args: &ClaimArgs,
    sibling_bytes: &[u8],
) -> ProgramResult {
    let [claimant, claimant_ata, vault, mint, mint_meta, config, batch, nullifier, token_program, system_program, vault_authority, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !claimant.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !claimant_ata.is_writable() || !vault.is_writable() || !nullifier.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }
    if system_program.address() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if args.amount == 0 {
        return Err(ClearingError::NonPositiveQuantity.into());
    }

    token::require_token_2022_program(token_program)?;
    let mint_decimals = token::require_plain_token_2022_mint(mint)?;

    let (expected_config, _) = pda::find_config(program_id);
    if config.address() != &expected_config {
        return Err(ClearingError::InvalidPda.into());
    }
    let cfg = Config::unpack(&config.try_borrow()?)?;

    let mint_key = mint.address().to_bytes();
    let (expected_meta, _) = pda::find_mint_meta(program_id, &mint_key);
    if mint_meta.address() != &expected_meta {
        return Err(ClearingError::InvalidPda.into());
    }
    let (expected_vault, _) = pda::find_vault(program_id, &mint_key);
    if vault.address() != &expected_vault {
        return Err(ClearingError::InvalidPda.into());
    }
    let meta = MintMeta::unpack(&mint_meta.try_borrow()?)?;
    if meta.mint != mint_key || meta.asset_id != args.asset_id || mint_decimals != meta.decimals {
        return Err(ClearingError::InvalidAccount.into());
    }

    let seq_le = args.batch_seq.to_le_bytes();
    let (expected_batch, _) = pda::find_batch(program_id, &seq_le);
    if batch.address() != &expected_batch {
        return Err(ClearingError::InvalidPda.into());
    }
    let rec = BatchRecord::unpack(&batch.try_borrow()?)?;
    if rec.seq != args.batch_seq {
        return Err(ClearingError::InvalidAccount.into());
    }

    if sibling_bytes.len() != args.n_siblings as usize * 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut siblings = [[0u8; 32]; 16];
    if args.n_siblings as usize > 16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    for i in 0..args.n_siblings as usize {
        siblings[i].copy_from_slice(&sibling_bytes[i * 32..i * 32 + 32]);
    }

    let owner = claimant.address().to_bytes();
    let mut amt_i128 = [0u8; 16];
    amt_i128[..8].copy_from_slice(&args.amount.to_le_bytes());
    if !hash::verify_withdrawal(
        &rec.withdrawals_root,
        args.batch_seq,
        args.index,
        &owner,
        args.asset_id,
        &amt_i128,
        &siblings[..args.n_siblings as usize],
    ) {
        return Err(ClearingError::InvalidProof.into());
    }

    let leaf = hash::withdrawal_leaf(
        args.batch_seq,
        args.index,
        &owner,
        args.asset_id,
        &amt_i128,
    );
    let (expected_nullifier, nullifier_bump) = pda::find_claim_nullifier(program_id, &leaf);
    if nullifier.address() != &expected_nullifier {
        return Err(ClearingError::InvalidPda.into());
    }
    if !nullifier.owned_by(&pinocchio_system::ID) || !nullifier.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }

    let expected_authority = token::vault_authority(program_id, cfg.vault_authority_bump)?;
    if vault_authority.address() != &expected_authority {
        return Err(ClearingError::InvalidPda.into());
    }
    token::require_vault(vault, mint.address(), &expected_authority)?;
    token::require_user_ata(claimant_ata, mint.address(), claimant.address())?;

    let nb = [nullifier_bump];
    let nseeds = [
        Seed::from(CLAIM_SEED),
        Seed::from(leaf.as_ref()),
        Seed::from(nb.as_ref()),
    ];
    let nsigner = Signer::from(&nseeds);
    create_account_with_minimum_balance_signed(
        nullifier,
        Nullifier::LEN,
        program_id,
        claimant,
        None,
        &[nsigner],
    )?;
    {
        let rec = Nullifier {
            disc: Nullifier::DISC,
            bump: nullifier_bump,
            _pad: [0; 7],
        };
        let mut data = nullifier.try_borrow_mut()?;
        rec.pack(&mut data)?;
    }

    let va_bump = [cfg.vault_authority_bump];
    let va_seeds = [
        Seed::from(VAULT_AUTHORITY_SEED),
        Seed::from(va_bump.as_ref()),
    ];
    let va_signer = Signer::from(&va_seeds);
    TransferChecked {
        from: vault,
        mint,
        to: claimant_ata,
        authority: vault_authority,
        amount: args.amount,
        decimals: meta.decimals,
        token_program: token_program.address(),
    }
    .invoke_signed(&[va_signer])?;

    Ok(())
}
