use pinocchio::error::ProgramError;

/// SHA256(b"account:Config")[..8]
const fn disc(bytes: [u8; 8]) -> [u8; 8] {
    bytes
}

fn pack_bytes<T>(value: &T, dst: &mut [u8], len: usize) -> Result<(), ProgramError> {
    if dst.len() < len {
        return Err(ProgramError::InvalidAccountData);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(value as *const T as *const u8, dst.as_mut_ptr(), len);
    }
    Ok(())
}

fn unpack_bytes<T>(data: &[u8], len: usize) -> Result<T, ProgramError> {
    if data.len() < len {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), value.as_mut_ptr() as *mut u8, len);
        Ok(value.assume_init())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub disc: [u8; 8],
    pub bump: u8,
    pub vault_authority_bump: u8,
    pub frozen: u8,
    pub proof_version: u8,
    pub groth16_vk_hash_prefix: [u8; 4],
    pub _pad: [u8; 0],
    pub root: [u8; 32],
    pub admin: [u8; 32],
    pub matcher_key: [u8; 32],
    pub freeze_authority: [u8; 32],
    pub vk_account: [u8; 32],
    pub guest_vk_hash: [u8; 32],
    pub batch_seq: u64,
    pub expiry_height: u64,
    pub next_deposit_nonce: u64,
    pub next_asset_id: u32,
    pub _pad2: [u8; 4],
}

impl Config {
    pub const DISC: [u8; 8] = disc([155, 12, 170, 224, 30, 250, 204, 130]);
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        pack_bytes(self, dst, Self::LEN)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let cfg: Self = unpack_bytes(data, Self::LEN)?;
        if cfg.disc != Self::DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(cfg)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MintMeta {
    pub disc: [u8; 8],
    pub bump: u8,
    pub decimals: u8,
    pub _pad: [u8; 2],
    pub asset_id: u32,
    pub mint: [u8; 32],
    pub vault: [u8; 32],
}

impl MintMeta {
    pub const DISC: [u8; 8] = disc([63, 207, 120, 142, 111, 38, 43, 247]);
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        pack_bytes(self, dst, Self::LEN)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let meta: Self = unpack_bytes(data, Self::LEN)?;
        if meta.disc != Self::DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(meta)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountOwner {
    pub disc: [u8; 8],
    pub bump: u8,
    pub trading_key_set: u8,
    pub _pad: [u8; 6],
    pub owner: [u8; 32],
}

impl AccountOwner {
    pub const DISC: [u8; 8] = disc([35, 41, 58, 124, 127, 110, 111, 152]);
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        pack_bytes(self, dst, Self::LEN)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let acc: Self = unpack_bytes(data, Self::LEN)?;
        if acc.disc != Self::DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(acc)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositReceipt {
    pub disc: [u8; 8],
    pub bump: u8,
    pub _pad: [u8; 7],
    pub nonce: u64,
    pub account_id: [u8; 16],
    pub asset_id: u32,
    pub _pad2: [u8; 4],
    pub amount: u64,
    pub owner: [u8; 32],
    pub trading_key: [u8; 32],
}

impl DepositReceipt {
    pub const DISC: [u8; 8] = disc([64, 175, 24, 183, 138, 109, 70, 78]);
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        pack_bytes(self, dst, Self::LEN)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let rec: Self = unpack_bytes(data, Self::LEN)?;
        if rec.disc != Self::DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(rec)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchRecord {
    pub disc: [u8; 8],
    pub bump: u8,
    pub _pad: [u8; 7],
    pub seq: u64,
    pub new_root: [u8; 32],
    pub withdrawals_root: [u8; 32],
    pub da_hash: [u8; 32],
}

impl BatchRecord {
    pub const DISC: [u8; 8] = disc([237, 157, 151, 81, 127, 59, 13, 242]);
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        pack_bytes(self, dst, Self::LEN)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let rec: Self = unpack_bytes(data, Self::LEN)?;
        if rec.disc != Self::DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(rec)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nullifier {
    pub disc: [u8; 8],
    pub bump: u8,
    pub _pad: [u8; 7],
}

impl Nullifier {
    pub const DISC: [u8; 8] = disc([18, 56, 142, 165, 181, 158, 187, 133]);
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        pack_bytes(self, dst, Self::LEN)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let n: Self = unpack_bytes(data, Self::LEN)?;
        if n.disc != Self::DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_layout_is_240_and_8_aligned() {
        assert_eq!(Config::LEN, 240);
        assert_eq!(core::mem::align_of::<Config>(), 8);
    }
}
