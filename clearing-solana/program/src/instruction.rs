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

/// SP1 wrap proof length (`SHA256(gnark_vk)[..4] ‖ A ‖ B ‖ C`). v1 mock-proof may be zeros.
pub const SETTLE_PROOF_LEN: usize = 260;
pub const PUBLIC_VALUES_LEN: usize = 144;
pub const DA_HASH_LEN: usize = 32;

/// Packed guest public values (144 bytes, little-endian u64s).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicValues {
    pub prev_root: [u8; 32],
    pub new_root: [u8; 32],
    pub withdrawals_root: [u8; 32],
    pub matcher_key: [u8; 32],
    pub batch_seq: u64,
    pub expiry_height: u64,
}

impl PublicValues {
    pub const LEN: usize = PUBLIC_VALUES_LEN;

    pub fn unpack(data: &[u8; Self::LEN]) -> Self {
        let mut prev_root = [0u8; 32];
        prev_root.copy_from_slice(&data[0..32]);
        let mut new_root = [0u8; 32];
        new_root.copy_from_slice(&data[32..64]);
        let mut withdrawals_root = [0u8; 32];
        withdrawals_root.copy_from_slice(&data[64..96]);
        let mut matcher_key = [0u8; 32];
        matcher_key.copy_from_slice(&data[96..128]);
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&data[128..136]);
        let mut expiry_bytes = [0u8; 8];
        expiry_bytes.copy_from_slice(&data[136..144]);
        Self {
            prev_root,
            new_root,
            withdrawals_root,
            matcher_key,
            batch_seq: u64::from_le_bytes(seq_bytes),
            expiry_height: u64::from_le_bytes(expiry_bytes),
        }
    }

    pub fn pack(&self) -> [u8; Self::LEN] {
        pack_public_values(
            &self.prev_root,
            &self.new_root,
            &self.withdrawals_root,
            &self.matcher_key,
            self.batch_seq,
            self.expiry_height,
        )
    }
}

pub fn pack_public_values(
    prev_root: &[u8; 32],
    new_root: &[u8; 32],
    withdrawals_root: &[u8; 32],
    matcher_key: &[u8; 32],
    batch_seq: u64,
    expiry_height: u64,
) -> [u8; PUBLIC_VALUES_LEN] {
    let mut pv = [0u8; PUBLIC_VALUES_LEN];
    pv[0..32].copy_from_slice(prev_root);
    pv[32..64].copy_from_slice(new_root);
    pv[64..96].copy_from_slice(withdrawals_root);
    pv[96..128].copy_from_slice(matcher_key);
    pv[128..136].copy_from_slice(&batch_seq.to_le_bytes());
    pv[136..144].copy_from_slice(&expiry_height.to_le_bytes());
    pv
}

/// `settle` (disc = 3) instruction data after the discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettleArgs {
    pub proof: [u8; SETTLE_PROOF_LEN],
    pub public_values: [u8; PUBLIC_VALUES_LEN],
    pub da_hash: [u8; DA_HASH_LEN],
}

impl SettleArgs {
    pub const LEN: usize = SETTLE_PROOF_LEN + PUBLIC_VALUES_LEN + DA_HASH_LEN;

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut proof = [0u8; SETTLE_PROOF_LEN];
        proof.copy_from_slice(&data[0..SETTLE_PROOF_LEN]);
        let mut public_values = [0u8; PUBLIC_VALUES_LEN];
        public_values
            .copy_from_slice(&data[SETTLE_PROOF_LEN..SETTLE_PROOF_LEN + PUBLIC_VALUES_LEN]);
        let mut da_hash = [0u8; DA_HASH_LEN];
        da_hash.copy_from_slice(&data[SETTLE_PROOF_LEN + PUBLIC_VALUES_LEN..]);
        Ok(Self {
            proof,
            public_values,
            da_hash,
        })
    }

    pub fn pack(&self) -> [u8; 1 + Self::LEN] {
        let mut out = [0u8; 1 + Self::LEN];
        out[0] = SETTLE;
        out[1..1 + SETTLE_PROOF_LEN].copy_from_slice(&self.proof);
        out[1 + SETTLE_PROOF_LEN..1 + SETTLE_PROOF_LEN + PUBLIC_VALUES_LEN]
            .copy_from_slice(&self.public_values);
        out[1 + SETTLE_PROOF_LEN + PUBLIC_VALUES_LEN..].copy_from_slice(&self.da_hash);
        out
    }

    pub fn public_values(&self) -> PublicValues {
        PublicValues::unpack(&self.public_values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_values_roundtrip_offsets() {
        let packed = pack_public_values(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 7, 0);
        assert_eq!(packed.len(), 144);
        let pv = PublicValues::unpack(&packed);
        assert_eq!(pv.prev_root, [1u8; 32]);
        assert_eq!(pv.new_root, [2u8; 32]);
        assert_eq!(pv.withdrawals_root, [3u8; 32]);
        assert_eq!(pv.matcher_key, [4u8; 32]);
        assert_eq!(pv.batch_seq, 7);
        assert_eq!(pv.expiry_height, 0);
        assert_eq!(pv.pack(), packed);
    }

    #[test]
    fn settle_args_pack_unpack() {
        let args = SettleArgs {
            proof: [0xABu8; SETTLE_PROOF_LEN],
            public_values: pack_public_values(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 0, 0),
            da_hash: [0xCDu8; 32],
        };
        let packed = args.pack();
        assert_eq!(packed[0], SETTLE);
        assert_eq!(packed.len(), 1 + SettleArgs::LEN);
        let unpacked = SettleArgs::unpack(&packed[1..]).unwrap();
        assert_eq!(unpacked, args);
    }
}

pub fn pack_freeze() -> [u8; 1] {
    [FREEZE]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EscapeWithdrawArgs {
    pub account_id: [u8; 16],
    pub asset_id: u32,
}

impl EscapeWithdrawArgs {
    pub const LEN: usize = 16 + 4;

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut account_id = [0u8; 16];
        account_id.copy_from_slice(&data[0..16]);
        let mut asset_bytes = [0u8; 4];
        asset_bytes.copy_from_slice(&data[16..20]);
        Ok(Self {
            account_id,
            asset_id: u32::from_le_bytes(asset_bytes),
        })
    }

    pub fn pack(&self) -> [u8; 1 + Self::LEN] {
        let mut out = [0u8; 1 + Self::LEN];
        out[0] = ESCAPE_WITHDRAW;
        out[1..17].copy_from_slice(&self.account_id);
        out[17..21].copy_from_slice(&self.asset_id.to_le_bytes());
        out
    }
}

/// `claim` (disc = 4). Variable length: header + n_siblings × 32.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimArgs {
    pub batch_seq: u64,
    pub index: u32,
    pub asset_id: u32,
    pub amount: u64,
    pub n_siblings: u8,
}

impl ClaimArgs {
    pub const HEADER_LEN: usize = 8 + 4 + 4 + 8 + 1;

    pub fn unpack(data: &[u8]) -> Result<(Self, &[u8]), ProgramError> {
        if data.len() < Self::HEADER_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let n_siblings = data[24];
        let sib_len = n_siblings as usize * 32;
        if data.len() != Self::HEADER_LEN + sib_len {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&data[0..8]);
        let mut idx = [0u8; 4];
        idx.copy_from_slice(&data[8..12]);
        let mut asset = [0u8; 4];
        asset.copy_from_slice(&data[12..16]);
        let mut amt = [0u8; 8];
        amt.copy_from_slice(&data[16..24]);
        Ok((
            Self {
                batch_seq: u64::from_le_bytes(seq),
                index: u32::from_le_bytes(idx),
                asset_id: u32::from_le_bytes(asset),
                amount: u64::from_le_bytes(amt),
                n_siblings,
            },
            &data[Self::HEADER_LEN..],
        ))
    }

    pub fn pack_header(&self) -> [u8; 1 + Self::HEADER_LEN] {
        let mut out = [0u8; 1 + Self::HEADER_LEN];
        out[0] = CLAIM;
        out[1..9].copy_from_slice(&self.batch_seq.to_le_bytes());
        out[9..13].copy_from_slice(&self.index.to_le_bytes());
        out[13..17].copy_from_slice(&self.asset_id.to_le_bytes());
        out[17..25].copy_from_slice(&self.amount.to_le_bytes());
        out[25] = self.n_siblings;
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetAdminArgs {
    pub new_admin: [u8; 32],
}

impl SetAdminArgs {
    pub const LEN: usize = 32;
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut new_admin = [0u8; 32];
        new_admin.copy_from_slice(data);
        Ok(Self { new_admin })
    }
    pub fn pack(&self) -> [u8; 1 + Self::LEN] {
        let mut out = [0u8; 33];
        out[0] = SET_ADMIN;
        out[1..].copy_from_slice(&self.new_admin);
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotateVkArgs {
    pub guest_vk_hash: [u8; 32],
    pub groth16_vk_hash_prefix: [u8; 4],
    pub proof_version: u8,
}

impl RotateVkArgs {
    pub const LEN: usize = 32 + 4 + 1;
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut guest_vk_hash = [0u8; 32];
        guest_vk_hash.copy_from_slice(&data[0..32]);
        let mut groth16_vk_hash_prefix = [0u8; 4];
        groth16_vk_hash_prefix.copy_from_slice(&data[32..36]);
        Ok(Self {
            guest_vk_hash,
            groth16_vk_hash_prefix,
            proof_version: data[36],
        })
    }

    pub fn pack(&self) -> [u8; 1 + Self::LEN] {
        let mut out = [0u8; 1 + Self::LEN];
        out[0] = ROTATE_VK;
        out[1..33].copy_from_slice(&self.guest_vk_hash);
        out[33..37].copy_from_slice(&self.groth16_vk_hash_prefix);
        out[37] = self.proof_version;
        out
    }
}
