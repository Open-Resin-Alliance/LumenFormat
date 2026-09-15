//! The checksum, the variable-length integer and the Merkle fold, read from the
//! specification rather than borrowed from the generator.
//!
//! Nothing here may be shared with `lumen-corpus-gen`, or the corpus stops
//! being evidence about the specification. The CRC comes from a third-party
//! crate, which the two readings are free to share; the self-test is what makes
//! that safe, since a wrong CRC would otherwise show up only as a corpus-wide
//! checksum failure.

use sha2::{Digest, Sha256};

/// CRC-32C of `"123456789"` - the published check value for the Castagnoli
/// polynomial. Both scripts verify this before trusting their own arithmetic.
pub const CRC32C_CHECK_VALUE: u32 = 0xE306_9283;

/// Run the CRC-32C self-test both scripts gate on.
pub fn crc32c_self_test() -> bool {
    crc32c::crc32c(b"123456789") == CRC32C_CHECK_VALUE
}

/// A variable-length integer that runs off the end of its buffer, or one that
/// does not terminate in eleven bytes. The message is the reader's own wording
/// for the failure, and reaches the report as a failed check's detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarintError(pub &'static str);

impl VarintError {
    const PAST_END: VarintError = VarintError("varint runs past the end of its buffer");
    const TOO_LONG: VarintError = VarintError("varint longer than 10 bytes");
}

/// One LEB128 value.
///
/// The value is exact in 128 bits: the reader accepts up to eleven bytes, so a
/// stored length can be wider than the buffer that holds it, and the Python
/// compares such a length against a file size without wrapping. Returning
/// `u64` here would silently turn "larger than any file" into a small number.
pub fn read_varint(buf: &[u8], pos: usize) -> Result<(u128, usize), VarintError> {
    let mut shift = 0u32;
    let mut val = 0u128;
    let mut pos = pos;
    let start = pos;
    loop {
        let byte = *buf.get(pos).ok_or(VarintError::PAST_END)?;
        pos += 1;
        val |= u128::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((val, pos));
        }
        if pos - start > 10 {
            return Err(VarintError::TOO_LONG);
        }
    }
}

/// The root of a Merkle tree over `leaves`, folded in pairs.
///
/// `None` for an empty list, which the Python answers with an `IndexError`: a
/// file that declares no leaves cannot have a root to compare against.
pub fn merkle_root(leaves: &[Vec<u8>]) -> Option<[u8; 32]> {
    let mut level: Vec<Vec<u8>> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(fold(left, right)),
                [last] => next.push(last.clone()),
                _ => unreachable!("chunks(2) yields one or two elements"),
            }
        }
        level = next;
    }
    level.first().map(|root| {
        let mut out = [0u8; 32];
        out.copy_from_slice(root);
        out
    })
}

fn fold(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}
