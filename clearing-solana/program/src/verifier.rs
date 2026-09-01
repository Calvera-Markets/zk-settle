//! Groth16 verification: v1 plain circuits KAT + v1.1 SP1 wrap framing.
//! Stub this PR; pairing lands with the KAT / wrap work.

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
use groth16_solana as _;
