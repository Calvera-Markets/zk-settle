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
        instruction::VERIFY_PLAIN => verifier::process(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(feature = "bpf-entrypoint")]
mod entrypoint {
    use pinocchio::{
        default_allocator, nostd_panic_handler, program_entrypoint, AccountView, Address,
        ProgramResult,
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
