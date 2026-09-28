use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::verifier::{self, FR_LEN, MAX_PUBLIC_INPUTS, PROOF_LEN};

/// `verify_plain` (disc = 9). No funds, no root — pairing only.
pub fn process(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vk_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() < PROOF_LEN || !(data.len() - PROOF_LEN).is_multiple_of(FR_LEN) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let n = (data.len() - PROOF_LEN) / FR_LEN;
    if n > MAX_PUBLIC_INPUTS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let proof: [u8; PROOF_LEN] = data[..PROOF_LEN]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut inputs = [[0u8; FR_LEN]; MAX_PUBLIC_INPUTS];
    for (i, slot) in inputs.iter_mut().take(n).enumerate() {
        let off = PROOF_LEN + i * FR_LEN;
        slot.copy_from_slice(&data[off..off + FR_LEN]);
    }

    let vk_data = vk_account.try_borrow()?;
    verifier::verify_plain(&vk_data, &proof, &inputs[..n])?;
    Ok(())
}
