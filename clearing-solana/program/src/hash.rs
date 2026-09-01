//! SHA-256 commitment hashing: leaf domain 0x00, node 0x01, DA domain 0x02.

pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    sha256(&[&[0x00], data])
}

pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[0x01], left, right])
}

/// `SHA-256(0x02 ‖ u32_le(payload_len) ‖ payload)`. Clients/tests only;
/// the program does not recompute `da_hash` from a blob.
pub fn hash_da(payload: &[u8]) -> [u8; 32] {
    let len = (payload.len() as u32).to_le_bytes();
    sha256(&[&[0x02], &len, payload])
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut out = [0u8; 32];
        unsafe {
            pinocchio::syscalls::sol_sha256(
                parts.as_ptr() as *const u8,
                parts.len() as u64,
                out.as_mut_ptr(),
            );
        }
        out
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_node_domain_tags_differ() {
        let leaf = hash_leaf(&[1, 2, 3]);
        let node = hash_node(&[0u8; 32], &[0u8; 32]);
        assert_ne!(leaf, node);
        assert_ne!(leaf, [0u8; 32]);
    }
}
