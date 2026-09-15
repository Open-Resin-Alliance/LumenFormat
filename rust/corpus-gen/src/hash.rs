//! SHA-256, the layer tree (spec 4.11) and hex rendering.

use sha2::{Digest, Sha256};

/// The digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// The digest of `data`, lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

/// The hash of one layer: domain-separated so a leaf can never be mistaken for an
/// interior node.
pub fn leaf_hash(layer_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(layer_bytes);
    hasher.finalize().into()
}

/// The root over `leaves`, pairing nodes and promoting the odd one.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "no leaves");
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => {
                    let mut hasher = Sha256::new();
                    hasher.update([0x01]);
                    hasher.update(left);
                    hasher.update(right);
                    next.push(hasher.finalize().into());
                }
                [odd] => next.push(*odd),
                _ => unreachable!("chunks of two"),
            }
        }
        level = next;
    }
    level[0]
}

/// Lowercase hex, the spelling every published digest in the corpus uses.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0F)] as char);
    }
    out
}
