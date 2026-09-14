//! Reading a chunk payload off disk: stored bytes, decryption, decompression.
//!
//! This is the one place that knows which chunk types carry a zstd frame and how
//! a sealed payload is framed, so the validator and the reader cannot disagree
//! about either.

use crate::check::Check;
use crate::chunks;
use crate::container::{ChunkDescriptor, ChunkType};
use crate::crypto::{self, Cipher, SessionKey};
use crate::error::{Error, Result};

/// The stored bytes of a chunk, sealed or not.
pub(crate) fn stored<'a>(buf: &'a [u8], d: &ChunkDescriptor) -> Result<&'a [u8]> {
    let start = d.offset as usize;
    let end = start
        .checked_add(d.stored_len() as usize)
        .ok_or_else(|| Error::new(Check::DirChunkExtent, "chunk extent overflows"))?;
    buf.get(start..end).ok_or_else(|| {
        Error::new(
            Check::DirChunkExtent,
            format!(
                "chunk {} at {start}..{end} lies outside the {} byte file",
                d.chunk_type,
                buf.len()
            ),
        )
    })
}

/// The plaintext bytes of a chunk, or `None` when it is sealed and no key is
/// available.
///
/// `LAYR` is the exception the specification carves out (section 3.2): its
/// descriptor carries the sealed bit because its block frames are sealed
/// individually, but the header and block table stay plaintext, so the
/// chunk-level bytes are returned as stored.
pub(crate) fn plaintext(
    d: &ChunkDescriptor,
    stored: &[u8],
    cipher: Option<Cipher>,
    key: Option<&SessionKey>,
) -> Result<Option<Vec<u8>>> {
    if d.chunk_type == ChunkType::LAYR || !d.is_encrypted() {
        return Ok(Some(stored.to_vec()));
    }
    match (cipher, key) {
        (Some(cipher), Some(key)) => Ok(Some(crypto::open(cipher, key, d.chunk_type, 0, stored)?)),
        _ => Ok(None),
    }
}

/// The decrypted, decompressed payload of a chunk, or `None` when it cannot be
/// read.
///
/// Whether a payload carries a zstd frame is a property of the chunk type
/// (section 6.3) - except for `EXTD`, whose compression is per-extension. For
/// `EXTD` the descriptor answers instead: section 3.2 defines
/// `size_compressed` as zero for a raw payload, so a non-zero value on an
/// unsealed extension means a zstd frame. A sealed extension's payload is left
/// alone, because its framing hides whether a frame is inside and no implemented
/// extension exists to say.
pub(crate) fn payload(
    d: &ChunkDescriptor,
    stored: &[u8],
    cipher: Option<Cipher>,
    key: Option<&SessionKey>,
) -> Result<Option<Vec<u8>>> {
    let Some(plain) = plaintext(d, stored, cipher, key)? else {
        return Ok(None);
    };
    let compressed = d.chunk_type.is_compressed()
        || (d.chunk_type == ChunkType::EXTD && !d.is_encrypted() && d.size_compressed != 0);
    if !compressed {
        return Ok(Some(plain));
    }
    Ok(Some(chunks::decompress(&plain, d.size_uncompressed, None)?))
}

/// The unsealed bytes of `LAYR` block `k`, or `None` when it is sealed and no key
/// is available.
pub(crate) fn block_frame(
    layr: &chunks::layr::Layr,
    stored: &[u8],
    desc: &ChunkDescriptor,
    k: usize,
    cipher: Option<Cipher>,
    key: Option<&SessionKey>,
) -> Result<Option<Vec<u8>>> {
    let frame = layr.frame(stored, k)?;
    if !desc.is_encrypted() {
        return Ok(Some(frame.to_vec()));
    }
    match (cipher, key) {
        (Some(cipher), Some(key)) => Ok(Some(crypto::open(
            cipher,
            key,
            ChunkType::LAYR,
            k as u32,
            frame,
        )?)),
        _ => Ok(None),
    }
}
