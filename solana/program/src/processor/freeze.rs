use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::{error::ClearingError, pda, state::Config};

/// `freeze` (disc = 5). Signer is `config.admin` or `config.freeze_authority`.
/// Sets `config.frozen = 1`. Idempotent.
pub fn process(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [signer, config, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !config.is_writable() {
        return Err(ClearingError::InvalidAccount.into());
    }

    let (expected_config, _) = pda::find_config(program_id);
    if config.address() != &expected_config {
        return Err(ClearingError::InvalidPda.into());
    }

    let mut cfg = Config::unpack(&config.try_borrow()?)?;
    let key = signer.address().as_array();
    if key != &cfg.admin && key != &cfg.freeze_authority {
        return Err(ClearingError::Unauthorized.into());
    }

    cfg.frozen = 1;
    let mut data = config.try_borrow_mut()?;
    cfg.pack(&mut data)
}
