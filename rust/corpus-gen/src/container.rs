//! Container assembly (spec 3): the file header, the entries, the chunk directory
//! and the trailer.

use std::collections::HashMap;

use crate::hash;
use crate::ZSTD_SMALL_LEVEL;

/// The bytes every file starts with.
pub const MAGIC: &[u8; 4] = b"LUMN";
/// The bytes every file ends with.
pub const TRAILER_MAGIC: &[u8; 4] = b"LEND";
/// The fixed header length.
pub const HEADER_SIZE: usize = 32;
/// One chunk directory entry.
pub const DESCRIPTOR_SIZE: usize = 32;
/// Payloads are aligned to this many bytes (spec 3.2 recommends 8).
pub const CHUNK_ALIGN: usize = 8;
/// One LTBL entry.
pub const LTBL_ENTRY_SIZE: usize = 20;
/// One LAYR block table entry.
pub const BLOCK_TABLE_ENTRY_SIZE: usize = 24;

pub const FLAG_MULTI_SECTOR: u32 = 0x02;
pub const FLAG_ENCRYPTED: u32 = 0x08;
pub const FLAG_CHUNK_ENCRYPTED: u32 = 0x10;

/// One chunk, before the file is assembled around it.
#[derive(Clone)]
pub struct Chunk {
    pub ctype: [u8; 4],
    pub payload: Vec<u8>,
    pub compressed: bool,
    pub flags: u32,
    /// A PREV may be sealed even when the file itself is encrypted (spec 4.7, 9.1).
    pub seal: bool,
    /// A framed, encrypted unit; `size_uncompressed` is the plaintext it yields
    /// after decrypt and decompress, while the stored length includes the AEAD
    /// framing (spec 3.2, 9.3).
    pub sealed: Option<Vec<u8>>,
    pub sealed_plaintext_len: usize,
}

impl Chunk {
    pub fn new(ctype: &[u8; 4], payload: Vec<u8>) -> Self {
        Chunk {
            ctype: *ctype,
            payload,
            compressed: false,
            flags: 0,
            seal: false,
            sealed: None,
            sealed_plaintext_len: 0,
        }
    }

    /// Store the payload zstd-compressed at the small-payload level.
    pub fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Ask for this chunk to be sealed in an encrypted file.
    pub fn sealable(mut self) -> Self {
        self.seal = true;
        self
    }

    /// Replace the payload with a sealed unit that yields `plaintext_len` bytes.
    pub fn seal_with(mut self, sealed: Vec<u8>, plaintext_len: usize, flags: u32) -> Self {
        self.sealed = Some(sealed);
        self.sealed_plaintext_len = plaintext_len;
        self.flags = flags;
        self
    }

    /// The chunk's name without its NUL padding.
    pub fn name(&self) -> &'static str {
        match &self.ctype {
            b"HDR\0" => "HDR",
            b"META" => "META",
            b"SECT" => "SECT",
            b"PROF" => "PROF",
            b"LROV" => "LROV",
            b"PREV" => "PREV",
            b"VOXL" => "VOXL",
            b"EXTD" => "EXTD",
            b"LTBL" => "LTBL",
            b"LHAS" => "LHAS",
            b"LAYR" => "LAYR",
            b"ZDIC" => "ZDIC",
            b"AUTH" => "AUTH",
            _ => "????",
        }
    }
}

/// One chunk directory entry, as written.
pub struct Entry {
    pub ctype: [u8; 4],
    pub offset: usize,
    pub size_uncompressed: usize,
    pub size_compressed: usize,
    pub flags: u32,
}

/// Where everything landed, for the manifest and for the invalid vectors that
/// rewrite a field in place.
pub struct Layout {
    offsets: HashMap<[u8; 4], usize>,
    pub dir_offset: usize,
    pub trailer_offset: usize,
    pub entries: Vec<Entry>,
}

impl Layout {
    /// The offset of a chunk's payload; the last chunk of a type wins, as in the
    /// producer this ports.
    pub fn offset(&self, ctype: &[u8; 4]) -> usize {
        self.offsets[ctype]
    }
}

/// Assemble `chunks`, in file order, into a complete file.
///
/// HDR must be first, which places its payload at offset 32. The gaps that
/// alignment leaves are free because the directory carries explicit offsets.
pub fn build_file(chunks: &[Chunk], header_flags: u32) -> (Vec<u8>, Layout) {
    let mut compressor = zstd::bulk::Compressor::new(ZSTD_SMALL_LEVEL).expect("zstd compressor");
    let mut body = Vec::new();
    let mut pos = HEADER_SIZE;
    let mut offsets = HashMap::new();
    let mut entries = Vec::new();
    let mut total_uncompressed = 0;

    for chunk in chunks {
        let pad = (CHUNK_ALIGN - pos % CHUNK_ALIGN) % CHUNK_ALIGN;
        body.resize(body.len() + pad, 0);
        pos += pad;

        let compressed;
        let (stored, size_uncompressed, size_compressed): (&[u8], usize, usize) =
            if let Some(sealed) = &chunk.sealed {
                (sealed, chunk.sealed_plaintext_len, sealed.len())
            } else if chunk.compressed {
                compressed = compressor
                    .compress(&chunk.payload)
                    .expect("small payload compression");
                (&compressed, chunk.payload.len(), compressed.len())
            } else {
                (&chunk.payload, chunk.payload.len(), 0)
            };

        offsets.insert(chunk.ctype, pos);
        entries.push(Entry {
            ctype: chunk.ctype,
            offset: pos,
            size_uncompressed,
            size_compressed,
            flags: chunk.flags,
        });
        body.extend_from_slice(stored);
        pos += stored.len();
        total_uncompressed += size_uncompressed;
    }

    let dir_offset = pos;
    let mut directory = Vec::with_capacity(entries.len() * DESCRIPTOR_SIZE);
    for entry in &entries {
        directory.extend_from_slice(&entry.ctype);
        directory.extend_from_slice(&(entry.offset as u64).to_le_bytes());
        directory.extend_from_slice(&(entry.size_uncompressed as u64).to_le_bytes());
        directory.extend_from_slice(&(entry.size_compressed as u64).to_le_bytes());
        directory.extend_from_slice(&entry.flags.to_le_bytes());
    }
    pos += directory.len();

    let mut file = Vec::with_capacity(pos + 8);
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&1u32.to_le_bytes());
    file.extend_from_slice(&(dir_offset as u64).to_le_bytes());
    file.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    file.extend_from_slice(&header_flags.to_le_bytes());
    file.extend_from_slice(&(total_uncompressed as u64).to_le_bytes());
    assert_eq!(file.len(), HEADER_SIZE, "header layout");
    file.extend_from_slice(&body);
    file.extend_from_slice(&directory);

    let crc = crc32c::crc32c(&file);
    file.extend_from_slice(TRAILER_MAGIC);
    file.extend_from_slice(&crc.to_le_bytes());

    let trailer_offset = file.len() - 8;
    (
        file,
        Layout {
            offsets,
            dir_offset,
            trailer_offset,
            entries,
        },
    )
}

/// The LAYR block table exactly as written to the file (spec 4.10).
///
/// Read back rather than recomputed: an encrypted vector's frames are sealed, so
/// their frame_size includes the AEAD overhead, and the manifest must describe the
/// bytes that are actually there.
pub fn stored_block_table(raw: &[u8], layout: &Layout) -> Vec<serde_json::Value> {
    let off = layout.offset(b"LAYR");
    let block_count = read_u32(raw, off + 4);
    let entry_size = read_u32(raw, off + 8) as usize;
    (0..block_count)
        .map(|k| {
            let base = off + 12 + k as usize * entry_size;
            crate::obj![
                "frame_offset" => read_u64(raw, base),
                "frame_size" => read_u64(raw, base + 8),
                "uncompressed_size" => read_u64(raw, base + 16),
            ]
        })
        .collect()
}

/// The trailer CRC-32C over everything before it.
pub fn trailer_crc(raw: &[u8], layout: &Layout) -> u32 {
    read_u32(raw, layout.trailer_offset + 4)
}

/// Recompute the trailer CRC-32C after a mutation.
pub fn repack(raw: &[u8], layout: &Layout) -> Vec<u8> {
    let mut out = raw.to_vec();
    let crc = crc32c::crc32c(&out[..layout.trailer_offset]);
    out[layout.trailer_offset + 4..layout.trailer_offset + 8].copy_from_slice(&crc.to_le_bytes());
    out
}

/// Read a little-endian `u32` out of a file image.
pub fn read_u32(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().expect("four bytes"))
}

/// Read a little-endian `u64` out of a file image.
pub fn read_u64(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().expect("eight bytes"))
}

/// Write a little-endian `u32` into a file image.
pub fn write_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian `u64` into a file image.
pub fn write_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// The SHA-256 of a whole file, as the manifest records it.
pub fn file_sha256(raw: &[u8]) -> String {
    hash::sha256_hex(raw)
}
