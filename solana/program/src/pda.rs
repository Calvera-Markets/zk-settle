use pinocchio::Address;

pub const CONFIG_SEED: &[u8] = b"config";
pub const VAULT_AUTHORITY_SEED: &[u8] = b"vault-authority";
pub const VAULT_SEED: &[u8] = b"vault";
pub const MINT_SEED: &[u8] = b"mint";
pub const ACCT_SEED: &[u8] = b"acct";
pub const DEPOSIT_SEED: &[u8] = b"deposit";
pub const BATCH_SEED: &[u8] = b"batch";
pub const CLAIM_SEED: &[u8] = b"claim";
pub const ESCAPE_SEED: &[u8] = b"escape";

pub fn find_config(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[CONFIG_SEED], program_id)
}

pub fn find_vault_authority(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[VAULT_AUTHORITY_SEED], program_id)
}

pub fn find_vault(program_id: &Address, mint: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[VAULT_SEED, mint], program_id)
}

pub fn find_mint_meta(program_id: &Address, mint: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[MINT_SEED, mint], program_id)
}

pub fn find_account_owner(program_id: &Address, account_id: &[u8; 16]) -> (Address, u8) {
    Address::find_program_address(&[ACCT_SEED, account_id], program_id)
}

pub fn find_deposit_receipt(program_id: &Address, nonce_le: &[u8; 8]) -> (Address, u8) {
    Address::find_program_address(&[DEPOSIT_SEED, nonce_le], program_id)
}

pub fn find_batch(program_id: &Address, seq_le: &[u8; 8]) -> (Address, u8) {
    Address::find_program_address(&[BATCH_SEED, seq_le], program_id)
}

pub fn find_claim_nullifier(program_id: &Address, nullifier: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[CLAIM_SEED, nullifier], program_id)
}

pub fn find_escape_nullifier(
    program_id: &Address,
    owner: &[u8; 32],
    mint: &[u8; 32],
) -> (Address, u8) {
    Address::find_program_address(&[ESCAPE_SEED, owner, mint], program_id)
}
