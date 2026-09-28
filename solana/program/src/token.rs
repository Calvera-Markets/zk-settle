//! Token-2022 mint and token-account checks shared by custody instructions.

use pinocchio::{AccountView, Address, error::ProgramError};
use pinocchio_token_2022::{
    ID as TOKEN_2022,
    state::{Mint, TokenAccount},
};

use crate::{error::ClearingError, pda};

/// Maximum registered mints (`config.next_asset_id`).
pub const MAX_REGISTERED_MINTS: u32 = 16;

pub fn require_token_2022_program(token_program: &AccountView) -> Result<(), ProgramError> {
    if token_program.address() != &TOKEN_2022 {
        return Err(ClearingError::UnsupportedMint.into());
    }
    Ok(())
}

/// Mint owner is Token-2022 and account data is exactly the 82-byte base mint
/// (TLV length 0 / no extensions). Freeze authority is also rejected so an
/// issuer cannot freeze the vault. Returns on-mint decimals.
pub fn require_plain_token_2022_mint(mint: &AccountView) -> Result<u8, ProgramError> {
    if !mint.owned_by(&TOKEN_2022) {
        return Err(ClearingError::UnsupportedMint.into());
    }
    if mint.data_len() != Mint::BASE_LEN {
        return Err(ClearingError::UnsupportedMint.into());
    }
    let mint_state = Mint::from_account_view(mint)?;
    if !mint_state.is_initialized() {
        return Err(ClearingError::InvalidAccount.into());
    }
    if mint_state.has_freeze_authority() {
        return Err(ClearingError::UnsupportedMint.into());
    }
    Ok(mint_state.decimals())
}

pub fn vault_authority(program_id: &Address, bump: u8) -> Result<Address, ProgramError> {
    let bump = [bump];
    Address::create_program_address(&[pda::VAULT_AUTHORITY_SEED, &bump], program_id)
        .map_err(|_| ClearingError::InvalidPda.into())
}

pub fn require_vault(
    vault: &AccountView,
    mint: &Address,
    authority: &Address,
) -> Result<(), ProgramError> {
    let token = TokenAccount::from_account_view(vault)
        .map_err(|_| ProgramError::from(ClearingError::InvalidAccount))?;
    if token.mint() != mint || token.owner() != authority {
        return Err(ClearingError::InvalidAccount.into());
    }
    Ok(())
}

pub fn require_user_ata(
    ata: &AccountView,
    mint: &Address,
    owner: &Address,
) -> Result<(), ProgramError> {
    let token = TokenAccount::from_account_view(ata)
        .map_err(|_| ProgramError::from(ClearingError::InvalidAccount))?;
    if token.mint() != mint || token.owner() != owner {
        return Err(ClearingError::InvalidAccount.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_base_len_is_82() {
        assert_eq!(Mint::BASE_LEN, 82);
    }

    #[test]
    fn token_account_base_len_is_165() {
        assert_eq!(TokenAccount::BASE_LEN, 165);
    }
}
