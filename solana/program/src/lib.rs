//! Pinocchio settlement program: Token-2022 vaults and a Groth16-gated root.
//!
//! `proof_version` 1 verifies an SP1 wrap and opens claims/escapes with SHA-256
//! paths. Version 2 verifies circuits Groth16 and opens with `ClaimOpenCircuit`.

#![cfg_attr(any(target_os = "solana", target_arch = "bpf"), no_std)]

pub mod error;
pub mod hash;
pub mod instruction;
pub mod pda;
pub mod processor;
pub mod state;
pub mod token;
pub mod verifier;

pub use pinocchio::{AccountView as AccountInfo, Address as Pubkey, ProgramResult};

pinocchio::address::declare_id!("AyALYha1o9u43sYybKhfgja7ZtSVXkqUzzVijgkYCm1");

pub fn dispatch(
    program_id: &pinocchio::Address,
    accounts: &[pinocchio::AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    use pinocchio::error::ProgramError;

    let (disc, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *disc {
        instruction::INITIALIZE => {
            let args = instruction::InitializeArgs::unpack(rest)?;
            processor::initialize::process(program_id, accounts, &args)
        }
        instruction::REGISTER_MINT => {
            let args = instruction::RegisterMintArgs::unpack(rest)?;
            processor::register_mint::process(program_id, accounts, &args)
        }
        instruction::DEPOSIT => {
            let args = instruction::DepositArgs::unpack(rest)?;
            processor::deposit::process(program_id, accounts, &args)
        }
        instruction::SETTLE => {
            let args = instruction::SettleArgs::unpack(rest)?;
            processor::settle::process(program_id, accounts, &args)
        }
        instruction::CLAIM => {
            let (args, siblings) = instruction::ClaimArgs::unpack(rest)?;
            processor::claim::process(program_id, accounts, &args, siblings)
        }
        instruction::FREEZE => {
            if !rest.is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            processor::freeze::process(program_id, accounts)
        }
        instruction::ESCAPE_WITHDRAW => {
            let args = instruction::EscapeWithdrawArgs::unpack(rest)?;
            processor::escape::process(program_id, accounts, &args)
        }
        instruction::SET_ADMIN => {
            let args = instruction::SetAdminArgs::unpack(rest)?;
            processor::admin::set_admin(program_id, accounts, &args)
        }
        instruction::ROTATE_VK => {
            let args = instruction::RotateVkArgs::unpack(rest)?;
            processor::admin::rotate_vk(program_id, accounts, &args)
        }
        instruction::VERIFY_PLAIN => processor::verify::process(program_id, accounts, rest),
        instruction::ROTATE_OPEN_VK => {
            if !rest.is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            processor::admin::rotate_open_vk(program_id, accounts)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(feature = "bpf-entrypoint")]
mod entrypoint {
    use pinocchio::{
        AccountView, Address, ProgramResult, default_allocator, nostd_panic_handler,
        program_entrypoint,
    };

    program_entrypoint!(process_instruction);
    default_allocator!();
    nostd_panic_handler!();

    pub fn process_instruction(
        program_id: &Address,
        accounts: &[AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        crate::dispatch(program_id, accounts, instruction_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{
        ClaimArgs, DA_HASH_LEN, DepositArgs, EscapeWithdrawArgs, InitializeArgs, RegisterMintArgs,
        RotateVkArgs, SETTLE_PROOF_LEN, SetAdminArgs, SettleArgs, pack_freeze, pack_public_values,
        pack_rotate_open_vk,
    };

    #[test]
    fn dispatch_rejects_empty_unknown_and_trailing_bytes() {
        let id = ID;
        assert!(dispatch(&id, &[], &[]).is_err());
        assert!(dispatch(&id, &[], &[255]).is_err());
        assert!(dispatch(&id, &[], &[instruction::FREEZE, 1]).is_err());
        assert!(dispatch(&id, &[], &[instruction::ROTATE_OPEN_VK, 1]).is_err());
        assert!(dispatch(&id, &[], &pack_freeze()).is_err());
        assert!(dispatch(&id, &[], &pack_rotate_open_vk()).is_err());
    }

    #[test]
    fn dispatch_enters_each_processor_with_empty_accounts() {
        let id = ID;
        let init = InitializeArgs {
            genesis_root: [0u8; 32],
            admin: [0u8; 32],
            matcher_key: [0u8; 32],
            freeze_authority: [0u8; 32],
            guest_vk_hash: [0u8; 32],
            groth16_vk_hash_prefix: [0; 4],
            proof_version: 1,
        };
        assert!(dispatch(&id, &[], &init.pack()).is_err());
        assert!(dispatch(&id, &[], &RegisterMintArgs { decimals: 6 }.pack()).is_err());
        let dep = DepositArgs {
            account_id: [0u8; 16],
            amount: 1,
            trading_key: None,
        };
        assert!(dispatch(&id, &[], dep.pack().as_slice()).is_err());
        let settle = SettleArgs {
            proof: [0u8; SETTLE_PROOF_LEN],
            public_values: pack_public_values(&[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32], 0, 0),
            da_hash: [0u8; DA_HASH_LEN],
        };
        assert!(dispatch(&id, &[], &settle.pack()).is_err());
        assert!(
            dispatch(
                &id,
                &[],
                &ClaimArgs {
                    batch_seq: 0,
                    index: 0,
                    asset_id: 0,
                    amount: 0,
                    n_siblings: 0,
                }
                .pack_header()
            )
            .is_err()
        );
        assert!(
            dispatch(
                &id,
                &[],
                &EscapeWithdrawArgs {
                    account_id: [0u8; 16],
                    asset_id: 0,
                }
                .pack()
            )
            .is_err()
        );
        assert!(
            dispatch(
                &id,
                &[],
                &SetAdminArgs {
                    new_admin: [0u8; 32],
                }
                .pack()
            )
            .is_err()
        );
        assert!(
            dispatch(
                &id,
                &[],
                &RotateVkArgs {
                    guest_vk_hash: [0u8; 32],
                    groth16_vk_hash_prefix: [0; 4],
                    proof_version: 1,
                }
                .pack()
            )
            .is_err()
        );
        assert!(dispatch(&id, &[], &[instruction::VERIFY_PLAIN]).is_err());
    }
}
