//! The table a LUMEN container is described by: its chunk directory (§4.1).
//!
//! The directory is read by the reader and by the crypto checks - its flags are
//! what say whether a payload is sealed, and its order is what the `LAYR` and
//! `LROV` chunk indices in `LTBL` count - so the shape lives here rather than
//! inside either.

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

/// A live chunk as the directory lists it: its record, and its **directory
/// index** - the position among all `chunk_count` records, which is what
/// `LTBL`'s `first_layr` and `first_lrov` count and what a sealed `LAYR`
/// frame's AAD binds (§4.8, §9.3).
#[derive(Clone, Copy)]
pub struct Chunk<'a> {
    pub index: usize,
    pub entry: &'a Entry,
}

/// §4.1: the file header's `ENCRYPTED` flag - an AUTH chunk is present and the
/// content is sealed.
pub const ENCRYPTED_FLAG: u32 = 0x08;

/// §9.1: the chunk descriptor's `ENCRYPTED` flag - this chunk's payload is
/// sealed.
pub const SEALED_FLAG: u32 = 0x10;

/// §9.3: `nonce[12]` followed by `tag[16]`.
pub const AEAD_OVERHEAD: usize = 28;

/// §4.10: the plaintext `layr_version` field a `LAYR` chunk's frame follows.
///
/// The frame is the sealed unit when the file is encrypted, so this many bytes
/// of the container stay in the clear - and a reader slicing a frame off a
/// container starts here.
pub const LAYR_HEADER_SIZE: u64 = 4;

/// §4.3: the chunk types whose payload is zstd-compressed.
pub const COMPRESSED_TYPES: [&[u8; 4]; 4] = [b"META", b"PROF", b"LROV", b"VOXL"];

/// The type tag with its NUL padding removed, for a report line.
pub fn type_name(ctype: &[u8; 4]) -> String {
    let len = ctype.iter().position(|&b| b == 0).unwrap_or(ctype.len());
    String::from_utf8_lossy(&ctype[..len]).into_owned()
}
