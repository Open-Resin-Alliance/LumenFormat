//! The two tables a LUMEN container is described by: its chunk directory
//! (§4.1) and its block table (§4.6).
//!
//! Both are read by the reader and by the crypto checks - the directory's flags
//! are what says whether a payload is sealed - so the shapes live here rather
//! than inside either.

/// One chunk-directory record, in the order the directory lists it.
pub struct Entry {
    /// The type tag, four bytes, NUL-padded where it is shorter.
    pub ctype: [u8; 4],
    pub offset: u64,
    /// Uncompressed payload length.
    pub usz: u64,
    /// Stored payload length; 0 when the payload is not compressed.
    pub csz: u64,
    pub flags: u32,
}

impl Entry {
    /// The stored payload length: `csz` when the payload is compressed, and
    /// the uncompressed length otherwise - what the directory actually
    /// allocated. Zero means the record is unused.
    pub fn size(&self) -> u64 {
        if self.csz != 0 {
            self.csz
        } else {
            self.usz
        }
    }
}

/// One LAYR block-table record (§4.6).
pub struct Block {
    pub frame_offset: u64,
    pub frame_size: u64,
    pub uncompressed_size: u64,
}

/// §4.1: the file header's `ENCRYPTED` flag - an AUTH chunk is present and the
/// content is sealed.
pub const ENCRYPTED_FLAG: u32 = 0x08;

/// §9.1: the chunk descriptor's `ENCRYPTED` flag - this chunk's payload is
/// sealed.
pub const SEALED_FLAG: u32 = 0x10;

/// §9.3: `nonce[12]` followed by `tag[16]`.
pub const AEAD_OVERHEAD: usize = 28;

/// §4.3: the chunk types whose payload is zstd-compressed.
pub const COMPRESSED_TYPES: [&[u8; 4]; 5] = [b"META", b"PROF", b"SECT", b"LROV", b"VOXL"];

/// The type tag with its NUL padding removed, for a report line.
pub fn type_name(ctype: &[u8; 4]) -> String {
    let len = ctype.iter().position(|&b| b == 0).unwrap_or(ctype.len());
    String::from_utf8_lossy(&ctype[..len]).into_owned()
}
