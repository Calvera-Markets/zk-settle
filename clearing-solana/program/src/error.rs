use pinocchio::error::ProgramError;

/// Custom program errors. Codes 13–17 match the design mapping.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClearingError {
    Overflow = 0,
    InsufficientBalance = 1,
    UnknownMarket = 2,
    NonPositiveQuantity = 3,
    DuplicateDeposit = 4,
    Frozen = 5,
    InvalidProof = 6,
    AlreadyInitialized = 7,
    InvalidPda = 8,
    InvalidAccount = 9,
    OwnerMismatch = 13,
    UnsupportedMint = 14,
    Unauthorized = 15,
    KeyAlreadyRegistered = 16,
    InvalidProofBuffer = 17,
}

impl From<ClearingError> for ProgramError {
    fn from(e: ClearingError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
