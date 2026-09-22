use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::create_account_with_minimum_balance_signed;
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    error::ClearingError,
    hash,
    instruction::EscapeWithdrawArgs,
    pda::{self, ESCAPE_SEED, VAULT_AUTHORITY_SEED},
    state::{Config, MintMeta, Nullifier},
    token,
};

/// Max user-owned proof buffer (reject larger).
pub const MAX_PROOF_BUFFER: usize = 10_240;
const MAX_BALANCES: u32 = 16;
const MAX_FILLS: u32 = 32;
const LEAF_VERSION: u8 = 4;

/// `escape_withdraw` (disc = 6). Requires `config.frozen`. Signer must equal
/// the proven v4 leaf `l1_owner`. Proof lives in a user-owned buffer account.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    args: &EscapeWithdrawArgs,
) -> ProgramResult {
    // vault_authority is unallocated (no stored PDA); it must still be passed
    // so TransferChecked can CPI-sign with vault-authority seeds.
    let [owner, owner_ata, vault, mint, mint_meta, config, proof_buffer, escape_nullifier, token_program, system_program, vault_authority, ..] =
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
        || !escape_nullifier.is_writable()
    {
        return Err(ClearingError::InvalidAccount.into());
    }
    if system_program.address() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    token::require_token_2022_program(token_program)?;
    let mint_decimals = token::require_plain_token_2022_mint(mint)?;

    let (expected_config, _) = pda::find_config(program_id);
    if config.address() != &expected_config {
        return Err(ClearingError::InvalidPda.into());
    }

    let cfg = Config::unpack(&config.try_borrow()?)?;
    if cfg.frozen == 0 {
        return Err(ClearingError::InvalidAccount.into());
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
    if mint_decimals != meta.decimals || meta.asset_id != args.asset_id {
        return Err(ClearingError::InvalidAccount.into());
    }

    let expected_authority = token::vault_authority(program_id, cfg.vault_authority_bump)?;
    if vault_authority.address() != &expected_authority {
        return Err(ClearingError::InvalidPda.into());
    }
    token::require_vault(vault, mint.address(), &expected_authority)?;
    token::require_user_ata(owner_ata, mint.address(), owner.address())?;

    let proof_data = proof_buffer.try_borrow()?;
    let (l1_owner, amount) = if cfg.proof_version == crate::instruction::PROOF_VERSION_CIRCUITS {
        let vk_account = accounts.get(11).ok_or(ProgramError::NotEnoughAccountKeys)?;
        if vk_account.address().as_array() != &cfg.vk_account {
            return Err(ClearingError::InvalidAccount.into());
        }
        // `[amount_u64_le][256-byte groth16]`
        if proof_data.len() != 8 + crate::verifier::PROOF_LEN {
            return Err(ClearingError::InvalidProofBuffer.into());
        }
        let mut amt_le = [0u8; 8];
        amt_le.copy_from_slice(&proof_data[0..8]);
        let amount = u64::from_le_bytes(amt_le);
        if amount == 0 {
            return Err(ClearingError::NonPositiveQuantity.into());
        }
        let proof: [u8; crate::verifier::PROOF_LEN] = proof_data[8..]
            .try_into()
            .map_err(|_| ClearingError::InvalidProofBuffer)?;
        let owner_bytes = owner.address().to_bytes();
        let inputs = [
            cfg.root,
            owner_bytes,
            crate::verifier::u32_be32(args.asset_id),
            crate::verifier::u64_be32(amount),
        ];
        let vk_data = vk_account.try_borrow()?;
        crate::verifier::verify_plain(&vk_data, &proof, &inputs)?;
        (owner_bytes, amount)
    } else {
        let (sibling_mask, siblings, leaf_bytes) = parse_proof_buffer(&proof_data)?;

        let leaf = hash::hash_leaf(leaf_bytes);
        let key = u128::from_be_bytes(args.account_id);
        let root = hash::root_from_path(key, leaf, sibling_mask, siblings);
        if root != cfg.root {
            return Err(ClearingError::InvalidProof.into());
        }

        let decoded = decode_v4_leaf(leaf_bytes, args.asset_id)?;
        let l1_owner = decoded.owner.ok_or(ClearingError::OwnerMismatch)?;
        if &l1_owner != owner.address().as_array() {
            return Err(ClearingError::OwnerMismatch.into());
        }
        if decoded.amount <= 0 {
            return Err(ClearingError::NonPositiveQuantity.into());
        }
        if decoded.amount > u64::MAX as i128 {
            return Err(ClearingError::Overflow.into());
        }
        (l1_owner, decoded.amount as u64)
    };

    // Nullifier seeds use the leaf owner (equal to signer after the check).
    let (expected_nullifier, nullifier_bump) =
        pda::find_escape_nullifier(program_id, &l1_owner, &mint_key);
    if escape_nullifier.address() != &expected_nullifier {
        return Err(ClearingError::InvalidPda.into());
    }
    if !escape_nullifier.owned_by(&pinocchio_system::ID) || !escape_nullifier.is_data_empty() {
        return Err(ClearingError::AlreadyInitialized.into());
    }

    let nullifier_bump_seed = [nullifier_bump];
    let nullifier_seeds = [
        Seed::from(ESCAPE_SEED),
        Seed::from(l1_owner.as_ref()),
        Seed::from(mint_key.as_ref()),
        Seed::from(nullifier_bump_seed.as_ref()),
    ];
    let nullifier_signer = Signer::from(&nullifier_seeds);
    create_account_with_minimum_balance_signed(
        escape_nullifier,
        Nullifier::LEN,
        program_id,
        owner,
        None,
        &[nullifier_signer],
    )?;
    {
        let rec = Nullifier {
            disc: Nullifier::DISC,
            bump: nullifier_bump,
            _pad: [0; 7],
        };
        let mut data = escape_nullifier.try_borrow_mut()?;
        rec.pack(&mut data)?;
    }

    let va_bump = [cfg.vault_authority_bump];
    let va_seeds = [
        Seed::from(VAULT_AUTHORITY_SEED),
        Seed::from(va_bump.as_ref()),
    ];
    let va_signer = Signer::from(&va_seeds);
    TransferChecked {
        from: vault,
        mint,
        to: owner_ata,
        authority: vault_authority,
        amount,
        decimals: meta.decimals,
        token_program: token_program.address(),
    }
    .invoke_signed(&[va_signer])?;

    Ok(())
}

type ProofParts<'a> = (u128, &'a [[u8; 32]], &'a [u8]);

fn parse_proof_buffer(data: &[u8]) -> Result<ProofParts<'_>, ProgramError> {
    if data.len() > MAX_PROOF_BUFFER || data.len() < 17 {
        return Err(ClearingError::InvalidProofBuffer.into());
    }
    let mut mask_bytes = [0u8; 16];
    mask_bytes.copy_from_slice(&data[0..16]);
    let sibling_mask = u128::from_le_bytes(mask_bytes);
    let n = data[16] as usize;
    if n > 128 {
        return Err(ClearingError::InvalidProofBuffer.into());
    }
    let sib_end = 17usize
        .checked_add(n.saturating_mul(32))
        .ok_or(ClearingError::InvalidProofBuffer)?;
    if sib_end > data.len() {
        return Err(ClearingError::InvalidProofBuffer.into());
    }
    let sib_bytes = &data[17..sib_end];
    // SAFETY: `[u8; 32]` has alignment 1; `sib_bytes.len() == n * 32`.
    let siblings = unsafe { core::slice::from_raw_parts(sib_bytes.as_ptr() as *const [u8; 32], n) };
    Ok((sibling_mask, siblings, &data[sib_end..]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedLeaf {
    owner: Option<[u8; 32]>,
    amount: i128,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ClearingError::InvalidProofBuffer)?;
        if end > self.data.len() {
            return Err(ClearingError::InvalidProofBuffer.into());
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }

    fn u32_le(&mut self) -> Result<u32, ProgramError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn i128_le(&mut self) -> Result<i128, ProgramError> {
        let mut b = [0u8; 16];
        b.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(b))
    }

    fn finish(self) -> Result<(), ProgramError> {
        if self.pos != self.data.len() {
            Err(ClearingError::InvalidProofBuffer.into())
        } else {
            Ok(())
        }
    }
}

/// Bounded v4 leaf walk. Hash is over the raw remainder; this only extracts
/// `l1_owner` and `balance(asset)`. Trailing bytes reject.
fn decode_v4_leaf(data: &[u8], asset_id: u32) -> Result<DecodedLeaf, ProgramError> {
    let mut c = Cursor::new(data);
    if c.u8()? != LEAF_VERSION {
        return Err(ClearingError::InvalidProofBuffer.into());
    }

    let n_balances = c.u32_le()?;
    if n_balances > MAX_BALANCES {
        return Err(ClearingError::InvalidProofBuffer.into());
    }
    let mut amount = 0i128;
    for _ in 0..n_balances {
        let mut asset_b = [0u8; 4];
        asset_b.copy_from_slice(c.take(4)?);
        let asset = u32::from_le_bytes(asset_b);
        let amt = c.i128_le()?;
        if asset == asset_id {
            amount = amt;
        }
    }

    let n_positions = c.u32_le()?;
    if n_positions != 0 {
        return Err(ClearingError::InvalidProofBuffer.into());
    }

    match c.u8()? {
        0 => {}
        1 => {
            let _ = c.take(32)?;
        }
        _ => return Err(ClearingError::InvalidProofBuffer.into()),
    }

    let n_fills = c.u32_le()?;
    if n_fills > MAX_FILLS {
        return Err(ClearingError::InvalidProofBuffer.into());
    }
    for _ in 0..n_fills {
        let _ = c.take(32)?;
        let _ = c.i128_le()?;
    }

    let owner = match c.u8()? {
        0 => None,
        1 => {
            let mut o = [0u8; 32];
            o.copy_from_slice(c.take(32)?);
            Some(o)
        }
        _ => return Err(ClearingError::InvalidProofBuffer.into()),
    };
    c.finish()?;
    Ok(DecodedLeaf { owner, amount })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::error::ProgramError;

    fn custom(err: ClearingError) -> ProgramError {
        err.into()
    }

    fn v4_leaf(owner: Option<[u8; 32]>, balances: &[(u32, i128)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(LEAF_VERSION);
        out.extend_from_slice(&(balances.len() as u32).to_le_bytes());
        for (asset, amt) in balances {
            out.extend_from_slice(&asset.to_le_bytes());
            out.extend_from_slice(&amt.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.push(0);
        out.extend_from_slice(&0u32.to_le_bytes());
        match owner {
            Some(o) => {
                out.push(1);
                out.extend_from_slice(&o);
            }
            None => out.push(0),
        }
        out
    }

    #[test]
    fn decode_extracts_owner_and_balance() {
        let owner = [7u8; 32];
        let leaf = v4_leaf(Some(owner), &[(0, 1000), (1, 5)]);
        let d = decode_v4_leaf(&leaf, 0).unwrap();
        assert_eq!(d.owner, Some(owner));
        assert_eq!(d.amount, 1000);
        let d1 = decode_v4_leaf(&leaf, 1).unwrap();
        assert_eq!(d1.amount, 5);
        let d2 = decode_v4_leaf(&leaf, 99).unwrap();
        assert_eq!(d2.amount, 0);
    }

    #[test]
    fn decode_missing_owner_is_none() {
        let leaf = v4_leaf(None, &[(0, 1)]);
        let d = decode_v4_leaf(&leaf, 0).unwrap();
        assert!(d.owner.is_none());
    }

    #[test]
    fn decode_rejects_trailing_and_bad_version() {
        let mut leaf = v4_leaf(Some([1u8; 32]), &[(0, 1)]);
        leaf.push(0);
        assert_eq!(
            decode_v4_leaf(&leaf, 0).unwrap_err(),
            custom(ClearingError::InvalidProofBuffer)
        );
        let mut bad = v4_leaf(Some([1u8; 32]), &[(0, 1)]);
        bad[0] = 3;
        assert_eq!(
            decode_v4_leaf(&bad, 0).unwrap_err(),
            custom(ClearingError::InvalidProofBuffer)
        );
    }

    #[test]
    fn parse_buffer_rejects_n_siblings_over_128() {
        let mut data = vec![0u8; 17];
        data[16] = 129;
        assert_eq!(
            parse_proof_buffer(&data).unwrap_err(),
            custom(ClearingError::InvalidProofBuffer)
        );
    }

    #[test]
    fn parse_buffer_splits_mask_siblings_leaf() {
        let mut data = vec![0u8; 17 + 32 + 4];
        data[0] = 1;
        data[16] = 1;
        data[17..49].copy_from_slice(&[0xABu8; 32]);
        data[49..].copy_from_slice(&[1, 2, 3, 4]);
        let (mask, sibs, leaf) = parse_proof_buffer(&data).unwrap();
        assert_eq!(mask, 1);
        assert_eq!(sibs.len(), 1);
        assert_eq!(sibs[0], [0xABu8; 32]);
        assert_eq!(leaf, &[1, 2, 3, 4]);
    }
}
