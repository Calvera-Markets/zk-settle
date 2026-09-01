use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::create_account_with_minimum_balance_signed;
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    error::ClearingError,
    instruction::DepositArgs,
    pda::{self, ACCT_SEED, DEPOSIT_SEED},
    state::{AccountOwner, Config, DepositReceipt, MintMeta},
    token,
};

pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    args: &DepositArgs,
) -> ProgramResult {
    let [owner, owner_ata, vault, mint, mint_meta, config, account_owner, receipt, token_program, system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !owner.is_writable()
        || !owner_ata.is_writable()
        || !vault.is_writable()
        || !config.is_writable()
        || !receipt.is_writable()
    {
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

    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    if cfg.frozen != 0 {
        return Err(ClearingError::Frozen.into());
    }

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
    if meta.mint != mint_key || &meta.vault != expected_vault.as_array() {
        return Err(ClearingError::InvalidAccount.into());
    }
    if mint_decimals != meta.decimals {
        return Err(ClearingError::InvalidAccount.into());
    }

    let vault_authority = token::vault_authority(program_id, cfg.vault_authority_bump)?;
    token::require_vault(vault, mint.address(), &vault_authority)?;
    token::require_user_ata(owner_ata, mint.address(), owner.address())?;

    let (expected_acct, acct_bump) = pda::find_account_owner(program_id, &args.account_id);
    if account_owner.address() != &expected_acct {
        return Err(ClearingError::InvalidPda.into());
    }

    let nonce = cfg.next_deposit_nonce;
    let nonce_le = nonce.to_le_bytes();
    let (expected_receipt, receipt_bump) = pda::find_deposit_receipt(program_id, &nonce_le);
    if receipt.address() != &expected_receipt {
        return Err(ClearingError::InvalidPda.into());
    }
    if !receipt.owned_by(&pinocchio_system::ID) || !receipt.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }

    // Existence is program-owned + nonempty (not a disc check). Unpack then
    // verifies the AccountOwner disc; a wrong disc is InvalidAccount.
    // Gate trading_key on existed — not trading_key_set. A first deposit with
    // tag 0x00 leaves the flag 0; a later 0x01 must still fail.
    let existed = account_owner.owned_by(program_id) && !account_owner.is_data_empty();
    let mut trading_key = [0u8; 32];
    let mut trading_key_set = 0u8;

    if existed {
        let stored = AccountOwner::unpack(&account_owner.try_borrow()?)
            .map_err(|_| ProgramError::from(ClearingError::InvalidAccount))?;
        if &stored.owner != owner.address().as_array() {
            return Err(ClearingError::OwnerMismatch.into());
        }
        if args.trading_key.is_some() {
            return Err(ClearingError::KeyAlreadyRegistered.into());
        }
    } else {
        // First signer binds AccountOwner forever. Predictable account_ids can
        // be squatted; the operator should assign high-entropy ids.
        if !account_owner.is_writable() {
            return Err(ClearingError::InvalidAccount.into());
        }
        if !account_owner.owned_by(&pinocchio_system::ID) || !account_owner.is_data_empty() {
            return Err(ClearingError::InvalidAccount.into());
        }
        if let Some(key) = args.trading_key {
            trading_key = key;
            trading_key_set = 1;
        }
        let acct_bump_seed = [acct_bump];
        let acct_seeds = [
            Seed::from(ACCT_SEED),
            Seed::from(args.account_id.as_ref()),
            Seed::from(acct_bump_seed.as_ref()),
        ];
        let acct_signer = Signer::from(&acct_seeds);
        create_account_with_minimum_balance_signed(
            account_owner,
            AccountOwner::LEN,
            program_id,
            owner,
            None,
            &[acct_signer],
        )?;
        let acc = AccountOwner {
            disc: AccountOwner::DISC,
            bump: acct_bump,
            trading_key_set,
            _pad: [0; 6],
            owner: owner.address().to_bytes(),
        };
        let mut data = account_owner.try_borrow_mut()?;
        acc.pack(&mut data)?;
    }

    TransferChecked {
        from: owner_ata,
        mint,
        to: vault,
        authority: owner,
        amount: args.amount,
        decimals: meta.decimals,
        token_program: token_program.address(),
    }
    .invoke()?;

    cfg.next_deposit_nonce = nonce.checked_add(1).ok_or(ClearingError::Overflow)?;

    let receipt_bump_seed = [receipt_bump];
    let receipt_seeds = [
        Seed::from(DEPOSIT_SEED),
        Seed::from(nonce_le.as_ref()),
        Seed::from(receipt_bump_seed.as_ref()),
    ];
    let receipt_signer = Signer::from(&receipt_seeds);
    create_account_with_minimum_balance_signed(
        receipt,
        DepositReceipt::LEN,
        program_id,
        owner,
        None,
        &[receipt_signer],
    )?;

    let rec = DepositReceipt {
        disc: DepositReceipt::DISC,
        bump: receipt_bump,
        _pad: [0; 7],
        nonce,
        account_id: args.account_id,
        asset_id: meta.asset_id,
        _pad2: [0; 4],
        amount: args.amount,
        owner: owner.address().to_bytes(),
        trading_key,
    };
    {
        let mut data = receipt.try_borrow_mut()?;
        rec.pack(&mut data)?;
    }

    let mut data = config.try_borrow_mut()?;
    cfg.pack(&mut data)
}
