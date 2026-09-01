use pinocchio::error::ProgramError;

pub const INITIALIZE: u8 = 0;
pub const REGISTER_MINT: u8 = 1;
pub const DEPOSIT: u8 = 2;
pub const SETTLE: u8 = 3;
pub const CLAIM: u8 = 4;
pub const FREEZE: u8 = 5;
pub const ESCAPE_WITHDRAW: u8 = 6;
pub const SET_ADMIN: u8 = 7;
pub const ROTATE_VK: u8 = 8;
/// KAT-only plain Groth16 verify (no funds, no root). Settle will reuse `verifier`.
pub const VERIFY_PLAIN: u8 = 9;

/// `initialize` (disc = 0) instruction data after the discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializeArgs {
    pub genesis_root: [u8; 32],
    pub admin: [u8; 32],
    pub matcher_key: [u8; 32],
    pub freeze_authority: [u8; 32],
    pub guest_vk_hash: [u8; 32],
    pub groth16_vk_hash_prefix: [u8; 4],
    pub proof_version: u8,
}

impl InitializeArgs {
    pub const LEN: usize = 32 * 5 + 4 + 1;

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut genesis_root = [0u8; 32];
        genesis_root.copy_from_slice(&data[0..32]);
        let mut admin = [0u8; 32];
        admin.copy_from_slice(&data[32..64]);
        let mut matcher_key = [0u8; 32];
        matcher_key.copy_from_slice(&data[64..96]);
        let mut freeze_authority = [0u8; 32];
        freeze_authority.copy_from_slice(&data[96..128]);
        let mut guest_vk_hash = [0u8; 32];
        guest_vk_hash.copy_from_slice(&data[128..160]);
        let mut groth16_vk_hash_prefix = [0u8; 4];
        groth16_vk_hash_prefix.copy_from_slice(&data[160..164]);
        Ok(Self {
            genesis_root,
            admin,
            matcher_key,
            freeze_authority,
            guest_vk_hash,
            groth16_vk_hash_prefix,
            proof_version: data[164],
        })
    }

    pub fn pack(&self) -> [u8; 1 + Self::LEN] {
        let mut out = [0u8; 1 + Self::LEN];
        out[0] = INITIALIZE;
        out[1..33].copy_from_slice(&self.genesis_root);
        out[33..65].copy_from_slice(&self.admin);
        out[65..97].copy_from_slice(&self.matcher_key);
        out[97..129].copy_from_slice(&self.freeze_authority);
        out[129..161].copy_from_slice(&self.guest_vk_hash);
        out[161..165].copy_from_slice(&self.groth16_vk_hash_prefix);
        out[165] = self.proof_version;
        out
    }
}

/// `register_mint` (disc = 1) instruction data after the discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterMintArgs {
    pub decimals: u8,
}

impl RegisterMintArgs {
    pub const LEN: usize = 1;

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(Self { decimals: data[0] })
    }

    pub fn pack(&self) -> [u8; 1 + Self::LEN] {
        [REGISTER_MINT, self.decimals]
    }
}

/// `deposit` (disc = 2) instruction data after the discriminator.
///
/// `trading_key` tag: `0x00` none; `0x01 ‖ [u8;32]` first deposit only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositArgs {
    pub account_id: [u8; 16],
    pub amount: u64,
    pub trading_key: Option<[u8; 32]>,
}

impl DepositArgs {
    pub const LEN_NONE: usize = 16 + 8 + 1;
    pub const LEN_KEY: usize = 16 + 8 + 1 + 32;

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN_NONE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut account_id = [0u8; 16];
        account_id.copy_from_slice(&data[0..16]);
        let mut amount_bytes = [0u8; 8];
        amount_bytes.copy_from_slice(&data[16..24]);
        let amount = u64::from_le_bytes(amount_bytes);
        let trading_key = match data[24] {
            0x00 => {
                if data.len() != Self::LEN_NONE {
                    return Err(ProgramError::InvalidInstructionData);
                }
                None
            }
            0x01 => {
                if data.len() != Self::LEN_KEY {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[25..57]);
                Some(key)
            }
            _ => return Err(ProgramError::InvalidInstructionData),
        };
        Ok(Self {
            account_id,
            amount,
            trading_key,
        })
    }

    pub fn pack(&self) -> DepositIxBytes {
        match self.trading_key {
            None => {
                let mut out = [0u8; 1 + Self::LEN_NONE];
                out[0] = DEPOSIT;
                out[1..17].copy_from_slice(&self.account_id);
                out[17..25].copy_from_slice(&self.amount.to_le_bytes());
                out[25] = 0x00;
                DepositIxBytes::None(out)
            }
            Some(key) => {
                let mut out = [0u8; 1 + Self::LEN_KEY];
                out[0] = DEPOSIT;
                out[1..17].copy_from_slice(&self.account_id);
                out[17..25].copy_from_slice(&self.amount.to_le_bytes());
                out[25] = 0x01;
                out[26..58].copy_from_slice(&key);
                DepositIxBytes::Key(out)
            }
        }
    }
}

/// Packed `deposit` ix bytes (variable length, no `alloc` on SBF).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositIxBytes {
    None([u8; 1 + DepositArgs::LEN_NONE]),
    Key([u8; 1 + DepositArgs::LEN_KEY]),
}

impl DepositIxBytes {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::None(bytes) => bytes,
            Self::Key(bytes) => bytes,
        }
    }
}
