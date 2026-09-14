//! The `LTBL` chunk: layer index to block and byte range
//! ([`spec/06-layer-data.md`] section 4.8).

use crate::check::Check;
use crate::error::{Error, Result};
use crate::io::{Reader, Writer};

/// The `LTBL` chunk header: `table_version`, `layer_count`, `entry_size`.
pub const LTBL_HEADER_LEN: usize = 12;
/// Bytes per entry in a v1 table.
pub const LTBL_ENTRY_SIZE_V1: u32 = 20;

/// One layer's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayerEntry {
    /// Byte offset from the start of block `block_index`'s decompressed output.
    pub data_offset: u64,
    /// Index into the `LAYR` block table.
    pub block_index: u32,
    /// Byte size of this layer's data within its block.
    pub data_size: u32,
    /// Sectors active on this layer; `0` marks the empty layer.
    pub sector_count: u32,
}

impl LayerEntry {
    /// Whether this layer is stored as the empty-layer form.
    pub fn is_empty(&self) -> bool {
        self.sector_count == 0
    }
}

/// The `LTBL` chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerTable {
    /// Layout version. `1` for this specification.
    pub table_version: u32,
    /// Bytes per entry; readers stride by this and skip unknown trailing fields.
    pub entry_size: u32,
    /// One entry per layer, in layer order.
    pub entries: Vec<LayerEntry>,
}

impl LayerTable {
    /// Parse the chunk payload.
    pub fn parse(payload: &[u8]) -> Result<LayerTable> {
        let mut r = Reader::checked(payload, Check::LtblEntrySize);
        let table_version = r.u32()?;
        if table_version != 1 {
            return Err(Error::new(
                Check::LtblVersion,
                format!("unsupported table_version {table_version}"),
            ));
        }
        let layer_count = r.u32()?;
        let entry_size = r.u32()?;
        if entry_size < LTBL_ENTRY_SIZE_V1 {
            return Err(Error::new(
                Check::LtblEntrySize,
                format!("entry_size {entry_size} is below the {LTBL_ENTRY_SIZE_V1} byte v1 layout"),
            ));
        }
        let table_len = (layer_count as usize)
            .checked_mul(entry_size as usize)
            .ok_or_else(|| Error::new(Check::LtblEntrySize, "the layer table length overflows"))?;
        if table_len > r.remaining() {
            return Err(Error::new(
                Check::LtblEntrySize,
                format!(
                    "{layer_count} entries of {entry_size} bytes need {table_len} bytes, {} remain",
                    r.remaining()
                ),
            ));
        }
        let mut entries = Vec::with_capacity(layer_count as usize);
        for _ in 0..layer_count {
            entries.push(LayerEntry {
                data_offset: r.u64()?,
                block_index: r.u32()?,
                data_size: r.u32()?,
                sector_count: r.u32()?,
            });
            // Future versions may append fields; stride past them.
            r.skip(entry_size as usize - LTBL_ENTRY_SIZE_V1 as usize)?;
        }
        Ok(LayerTable {
            table_version,
            entry_size,
            entries,
        })
    }

    /// Serialize the chunk payload at `entry_size` 20.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            LTBL_HEADER_LEN + self.entries.len() * LTBL_ENTRY_SIZE_V1 as usize,
        );
        w.u32(self.table_version);
        w.u32(self.entries.len() as u32);
        w.u32(LTBL_ENTRY_SIZE_V1);
        for entry in &self.entries {
            w.u64(entry.data_offset);
            w.u32(entry.block_index);
            w.u32(entry.data_size);
            w.u32(entry.sector_count);
        }
        w.into_vec()
    }

    /// The number of layers the table describes.
    pub fn layer_count(&self) -> u32 {
        self.entries.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries of 24 bytes: the v1 20-byte layout plus four unknown bytes.
    fn strided_table() -> Vec<u8> {
        let mut w = Writer::with_capacity(LTBL_HEADER_LEN + 2 * 24);
        w.u32(1);
        w.u32(2);
        w.u32(24);
        for (offset, block, size, sectors) in [(100u64, 0u32, 5u32, 1u32), (105, 1, 0, 0)] {
            w.u64(offset);
            w.u32(block);
            w.u32(size);
            w.u32(sectors);
            w.u32(0xDEAD_BEEF); // an unknown trailing field
        }
        w.into_vec()
    }

    #[test]
    fn ltbl_strides_by_entry_size_skipping_unknown_fields() {
        let table = LayerTable::parse(&strided_table()).unwrap();
        assert_eq!(table.table_version, 1);
        assert_eq!(table.entry_size, 24);
        assert_eq!(table.layer_count(), 2);
        assert_eq!(
            table.entries[0],
            LayerEntry {
                data_offset: 100,
                block_index: 0,
                data_size: 5,
                sector_count: 1,
            }
        );
        assert!(table.entries[1].is_empty());
        assert_eq!(table.entries[1].data_offset, 105);

        // Serializing writes the canonical v1 entry size and drops the unknown field.
        let bytes = table.to_bytes();
        assert_eq!(bytes.len(), LTBL_HEADER_LEN + 2 * 20);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 20);
        assert_eq!(LayerTable::parse(&bytes).unwrap().entries, table.entries);
    }

    #[test]
    fn ltbl_rejects_short_entries_and_bad_frames() {
        let mut w = Writer::new();
        w.u32(1);
        w.u32(1);
        w.u32(19);
        w.u64(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u8(0); // 19-byte entry
        assert_eq!(
            LayerTable::parse(&w.into_vec()).unwrap_err().check(),
            Check::LtblEntrySize
        );

        // entry_size is fine but the declared entries do not fit.
        let mut w = Writer::new();
        w.u32(1);
        w.u32(5);
        w.u32(20);
        w.u64(0);
        assert_eq!(
            LayerTable::parse(&w.into_vec()).unwrap_err().check(),
            Check::LtblEntrySize
        );

        let mut w = Writer::new();
        w.u32(2);
        w.u32(0);
        w.u32(20);
        assert_eq!(
            LayerTable::parse(&w.into_vec()).unwrap_err().check(),
            Check::LtblVersion
        );
    }
}
