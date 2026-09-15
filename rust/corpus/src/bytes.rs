//! Byte-level helpers, with the exact semantics of the Python the reader was
//! ported from.
//!
//! Two of them matter more than they look. [`at`] is Python's slice, which
//! clamps instead of failing: the corpus reader relies on that when a chunk
//! descriptor's length runs past the file, and a port that panicked there
//! would be a different reader. The little-endian readers are
//! `struct.unpack_from`, which returns `None` where the Python raises - the
//! callers turn that into "this file is not a container" rather than a panic.

/// Python's `raw[off : off + len]`: clamped at both ends, never panics.
pub fn at(raw: &[u8], off: u128, len: u128) -> &[u8] {
    let end = raw.len() as u128;
    let start = off.min(end);
    let stop = off.saturating_add(len).min(end);
    &raw[start as usize..stop.max(start) as usize]
}

/// `struct.unpack_from` of `N` little-endian bytes: `None` when they do not fit.
pub fn le<const N: usize>(raw: &[u8], off: usize) -> Option<[u8; N]> {
    let bytes = raw.get(off..off.checked_add(N)?)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Some(out)
}

pub fn u32_at(raw: &[u8], off: usize) -> Option<u32> {
    le::<4>(raw, off).map(u32::from_le_bytes)
}

pub fn u64_at(raw: &[u8], off: usize) -> Option<u64> {
    le::<8>(raw, off).map(u64::from_le_bytes)
}

/// `struct.unpack_from(">I", ...)`, for the one big-endian structure in the
/// specification: the PNG header.
pub fn be_u32_at(raw: &[u8], off: usize) -> Option<u32> {
    le::<4>(raw, off).map(u32::from_be_bytes)
}

/// `bytes.hex()`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
}

/// `bytes.fromhex()`, accepting the same forms: no prefix, an even number of
/// hexadecimal digits, surrounding whitespace ignored. `None` where the Python
/// raises `ValueError`.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
