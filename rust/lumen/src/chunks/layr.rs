//! The `LAYR` chunk: all layer masks as independent zstd block frames
//! ([`spec/06-layer-data.md`] section 4.10).
//!
//! The chunk is stored uncompressed at the container level: its payload is a
//! plaintext header and block table followed by the block region, and that whole
//! region is what the chunk descriptor's sizes describe. A sealed file seals each
//! block frame separately, so a reader still reaches single blocks without
//! streaming the ciphertext.

use crate::check::Check;
use crate::error::{Error, Result};
use crate::io::Reader;

/// The `LAYR` header: `layr_version`, `block_count`, `block_table_entry_size`.
pub const LAYR_HEADER_LEN: usize = 12;
/// Bytes per block table entry in v1.
pub const BLOCK_TABLE_ENTRY_SIZE_V1: u32 = 24;

/// One entry of the block table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockEntry {
    /// Offset of the frame from the start of the block region.
    pub frame_offset: u64,
    /// Stored size of the frame, including AEAD framing when sealed.
    pub frame_size: u64,
    /// Exact size of the block's decompressed output.
    pub uncompressed_size: u64,
}

/// The `LAYR` header and block table, plus where the block region starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layr {
    /// Layout version. `1` for this specification.
    pub layr_version: u32,
    /// Bytes per block table entry; readers stride by this.
    pub block_table_entry_size: u32,
    /// One entry per block, in block order.
    pub blocks: Vec<BlockEntry>,
    /// Offset of the block region from the start of the chunk payload.
    pub block_region_offset: usize,
}

impl Layr {
    /// Parse the header and block table.
    pub fn parse(payload: &[u8]) -> Result<Layr> {
        let (layr_version, block_count, block_table_entry_size) = parse_header(payload)?;
        if block_count == 0 {
            return Err(Error::new(
                Check::LayrBlockCount,
                "the LAYR chunk holds no blocks",
            ));
        }
        if block_table_entry_size < BLOCK_TABLE_ENTRY_SIZE_V1 {
            return Err(Error::new(
                Check::LayrBlockTableEntrySize,
                format!(
                    "block_table_entry_size {block_table_entry_size} is below the \
                     {BLOCK_TABLE_ENTRY_SIZE_V1} byte v1 layout"
                ),
            ));
        }
        let table_len = (block_count as usize)
            .checked_mul(block_table_entry_size as usize)
            .ok_or_else(|| {
                Error::new(
                    Check::LayrBlockTableEntrySize,
                    "the block table length overflows",
                )
            })?;
        let block_region_offset = LAYR_HEADER_LEN.checked_add(table_len).ok_or_else(|| {
            Error::new(
                Check::LayrBlockTableEntrySize,
                "the block region offset overflows",
            )
        })?;
        if block_region_offset > payload.len() {
            return Err(Error::new(
                Check::LayrBlockTableEntrySize,
                format!(
                    "{block_count} entries of {block_table_entry_size} bytes need \
                     {block_region_offset} bytes, but the payload is {} bytes",
                    payload.len()
                ),
            ));
        }
        let mut r = Reader::checked(
            &payload[LAYR_HEADER_LEN..block_region_offset],
            Check::LayrBlockTableEntrySize,
        );
        let mut blocks = Vec::with_capacity(block_count as usize);
        for _ in 0..block_count {
            blocks.push(BlockEntry {
                frame_offset: r.u64()?,
                frame_size: r.u64()?,
                uncompressed_size: r.u64()?,
            });
            // Future versions may append fields; stride past them.
            r.skip(block_table_entry_size as usize - BLOCK_TABLE_ENTRY_SIZE_V1 as usize)?;
        }
        Ok(Layr {
            layr_version,
            block_table_entry_size,
            blocks,
            block_region_offset,
        })
    }

    /// The number of blocks.
    pub fn block_count(&self) -> u32 {
        self.blocks.len() as u32
    }

    /// The stored bytes of block `index`.
    pub fn frame<'a>(&self, payload: &'a [u8], index: usize) -> Result<&'a [u8]> {
        let block = self.blocks.get(index).ok_or_else(|| {
            Error::new(
                Check::LayrBlockRegionBounds,
                format!(
                    "block {index} is outside the {} blocks of this chunk",
                    self.block_count()
                ),
            )
        })?;
        let start = self.block_region_offset + block.frame_offset as usize;
        let end = start
            .checked_add(block.frame_size as usize)
            .ok_or_else(|| Error::new(Check::LayrBlockRegionBounds, "block frame end overflows"))?;
        if end > payload.len() {
            return Err(Error::new(
                Check::LayrBlockRegionBounds,
                format!(
                    "block {index} ends at {end}, past the {} byte payload",
                    payload.len()
                ),
            ));
        }
        Ok(&payload[start..end])
    }

    /// The byte after the last frame.
    pub fn block_region_end(&self) -> u64 {
        self.blocks
            .last()
            .map(|b| b.frame_offset + b.frame_size)
            .unwrap_or(0)
    }

    /// Serialize the header and block table, leaving the caller to append frames.
    pub fn header_to_bytes(blocks: &[BlockEntry]) -> Vec<u8> {
        let mut w = crate::io::Writer::with_capacity(
            LAYR_HEADER_LEN + blocks.len() * BLOCK_TABLE_ENTRY_SIZE_V1 as usize,
        );
        w.u32(1);
        w.u32(blocks.len() as u32);
        w.u32(BLOCK_TABLE_ENTRY_SIZE_V1);
        for block in blocks {
            w.u64(block.frame_offset);
            w.u64(block.frame_size);
            w.u64(block.uncompressed_size);
        }
        w.into_vec()
    }
}

/// Parse just the header of a `LAYR` payload, without the block table.
///
/// Structural validation has to run before the table is trusted, because
/// `block_count` is what decides whether the table can be read at all.
pub fn parse_header(payload: &[u8]) -> Result<(u32, u32, u32)> {
    let mut r = Reader::checked(payload, Check::LayrVersion);
    let layr_version = r.u32()?;
    if layr_version != 1 {
        return Err(Error::new(
            Check::LayrVersion,
            format!("unsupported layr_version {layr_version}"),
        ));
    }
    let block_count = r.u32()?;
    let entry_size = r.u32()?;
    Ok((layr_version, block_count, entry_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::Writer;

    /// A 12-byte header, a block table and a block region of 5 + 7 bytes.
    fn framed_chunk(entry_size: u32) -> Vec<u8> {
        let mut w = Writer::with_capacity(12 + 2 * entry_size as usize + 12);
        w.u32(1);
        w.u32(2);
        w.u32(entry_size);
        for (offset, size, uncompressed) in [(0u64, 5u64, 100u64), (5, 7, 50)] {
            w.u64(offset);
            w.u64(size);
            w.u64(uncompressed);
            for _ in 0..(entry_size - BLOCK_TABLE_ENTRY_SIZE_V1) {
                w.u8(0xAA); // an unknown trailing field
            }
        }
        w.bytes(b"aaaaa"); // block 0
        w.bytes(b"bbbbbbb"); // block 1
        w.into_vec()
    }

    #[test]
    fn layr_parses_a_header_and_slices_frames() {
        let payload = framed_chunk(BLOCK_TABLE_ENTRY_SIZE_V1);
        let layr = Layr::parse(&payload).unwrap();
        assert_eq!(layr.layr_version, 1);
        assert_eq!(layr.block_count(), 2);
        assert_eq!(layr.block_region_offset, 12 + 2 * 24);
        assert_eq!(
            layr.blocks[0],
            BlockEntry {
                frame_offset: 0,
                frame_size: 5,
                uncompressed_size: 100,
            }
        );
        assert_eq!(layr.blocks[1].uncompressed_size, 50);
        assert_eq!(layr.frame(&payload, 0).unwrap(), b"aaaaa");
        assert_eq!(layr.frame(&payload, 1).unwrap(), b"bbbbbbb");
        assert_eq!(layr.block_region_end(), 12);
        assert_eq!(
            layr.frame(&payload, 2).unwrap_err().check(),
            Check::LayrBlockRegionBounds
        );
    }

    #[test]
    fn layr_skips_unknown_table_fields() {
        let payload = framed_chunk(32);
        let layr = Layr::parse(&payload).unwrap();
        assert_eq!(layr.block_table_entry_size, 32);
        assert_eq!(layr.block_region_offset, 12 + 2 * 32);
        assert_eq!(layr.frame(&payload, 1).unwrap(), b"bbbbbbb");
    }

    #[test]
    fn layr_rejects_bad_version_count_and_table() {
        assert_eq!(
            Layr::parse(&framed_chunk(BLOCK_TABLE_ENTRY_SIZE_V1)[..4])
                .unwrap_err()
                .check(),
            Check::LayrVersion
        );

        let mut bad = framed_chunk(BLOCK_TABLE_ENTRY_SIZE_V1);
        bad[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Layr::parse(&bad).unwrap_err().check(), Check::LayrVersion);

        let mut empty = framed_chunk(BLOCK_TABLE_ENTRY_SIZE_V1);
        empty[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Layr::parse(&empty).unwrap_err().check(),
            Check::LayrBlockCount
        );

        let mut small = framed_chunk(BLOCK_TABLE_ENTRY_SIZE_V1);
        small[8..12].copy_from_slice(&23u32.to_le_bytes());
        assert_eq!(
            Layr::parse(&small).unwrap_err().check(),
            Check::LayrBlockTableEntrySize
        );

        // A table that runs past the payload is rejected before reading it.
        let mut short = framed_chunk(BLOCK_TABLE_ENTRY_SIZE_V1);
        short.truncate(12 + 24);
        assert_eq!(
            Layr::parse(&short).unwrap_err().check(),
            Check::LayrBlockTableEntrySize
        );
    }
}
