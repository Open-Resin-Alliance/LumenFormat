//! The multi-sector per-layer framing ([`spec/06-layer-data.md`] section 4.10).
//!
//! In a `MULTI_SECTOR` file a layer's data begins with a varint sector count,
//! then one `(sector_id, size)` pair and a tag-plus-mask blob per sector. The
//! blob's size is what lets a reader skip a sector it does not care about.

use crate::check::Check;
use crate::error::{Error, Result};
use crate::io::{Reader, Writer};

/// One sector's contribution to one layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectorLayer {
    /// Sector identifier, `0` for the implicit primary sector.
    pub sector_id: u32,
    /// The sector's mask data: the one-byte encoding tag, then the REE stream.
    pub mask: Vec<u8>,
}

/// Decode the sector framing of one layer.
///
/// `expected_count` is the `LTBL` entry's `sector_count`, which the in-band
/// varint must equal. An empty layer is stored as zero bytes, so a `data` slice
/// that is empty decodes to no sectors regardless of `expected_count`.
pub fn decode(data: &[u8], expected_count: u32) -> Result<Vec<SectorLayer>> {
    if data.is_empty() {
        if expected_count != 0 {
            return Err(Error::new(
                Check::LtblSectorCountMatch,
                format!("layer stores no bytes but LTBL declares {expected_count} sector(s)"),
            ));
        }
        return Ok(Vec::new());
    }

    let mut reader = Reader::checked(data, Check::SectorTags);
    let count = reader.varint()?;
    // The equality check is also the allocation guard: `expected_count` comes
    // from a `u32` LTBL field, so a hostile in-band count is refused here,
    // before anything is sized from it.
    if count != u64::from(expected_count) {
        return Err(Error::new(
            Check::LtblSectorCountMatch,
            format!("layer framing declares {count} sector(s), LTBL declares {expected_count}"),
        ));
    }

    // The equality check above is also the section 5.2-style allocation guard:
    // `expected_count` comes from a `u32` LTBL field, so a hostile in-band count
    // is refused before anything is sized from it. A sector still needs two
    // varints (id and size), so the remaining bytes cap what can follow.
    let mut sectors: Vec<SectorLayer> =
        Vec::with_capacity((count as usize).min(reader.remaining() / 2 + 1));
    for _ in 0..count {
        let id = reader.varint()?;
        let id = u32::try_from(id).map_err(|_| {
            Error::new(
                Check::SectorTags,
                format!("sector id {id} does not fit a u32"),
            )
        })?;
        if sectors.iter().any(|sector| sector.sector_id == id) {
            return Err(Error::new(
                Check::SectorTags,
                format!("sector {id} appears more than once on the same layer"),
            ));
        }
        let size = reader.varint()?;
        let size = usize::try_from(size).map_err(|_| {
            Error::new(
                Check::SectorTags,
                format!("sector {id} declares {size} bytes, too many to address"),
            )
        })?;
        let mask = reader.bytes(size)?.to_vec();
        sectors.push(SectorLayer {
            sector_id: id,
            mask,
        });
    }
    Ok(sectors)
}

/// Encode the sector framing of one layer, including the sector count varint.
pub fn encode(sectors: &[SectorLayer]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.varint(sectors.len() as u64);
    for sector in sectors {
        writer.varint(u64::from(sector.sector_id));
        writer.varint(sector.mask.len() as u64);
        writer.bytes(&sector.mask);
    }
    writer.into_vec()
}

/// Split a mask blob into its tag and stream.
pub fn split_tag(mask: &[u8]) -> Result<(u8, &[u8])> {
    match mask.split_first() {
        Some((&tag, stream)) => Ok((tag, stream)),
        None => Err(Error::new(
            Check::ReeTag,
            "sector mask is empty: a non-empty sector carries an encoding tag",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Layer 0 of `test-vectors/valid/multi-sector.lumen`: the implicit primary
    /// sector 0 plus sector 1.
    const TWO_SECTORS: &str = "02000400ff02640106000003c80164";
    /// Layer 1 of that file: one active sector inside a multi-sector file.
    const ONE_SECTOR: &str = "01000400ff0240";

    fn bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    #[test]
    fn corpus_layer_with_two_sectors() {
        let sectors = decode(&bytes(TWO_SECTORS), 2).unwrap();
        assert_eq!(
            sectors,
            vec![
                SectorLayer {
                    sector_id: 0,
                    mask: bytes("00ff0264"),
                },
                SectorLayer {
                    sector_id: 1,
                    mask: bytes("000003c80164"),
                },
            ]
        );
        // The framing is reproduced byte for byte, count varint included.
        assert_eq!(encode(&sectors), bytes(TWO_SECTORS));
        // Each mask is a tag plus a decodable stream: sector 0 is white for 100
        // pixels and sector 1 black for 200 then white for 100.
        let (tag, _) = split_tag(&sectors[0].mask).unwrap();
        assert_eq!(tag, crate::ree::TAG_BINARY);
        let zero = crate::ree::decode(&sectors[0].mask, 3072, true).unwrap();
        assert_eq!(zero.pixels[99], 255);
        assert_eq!(zero.pixels[100], 0);
        let one = crate::ree::decode(&sectors[1].mask, 3072, true).unwrap();
        assert_eq!(one.pixels[199], 0);
        assert_eq!(one.pixels[200], 255);
        assert_eq!(one.pixels[300], 0);
    }

    #[test]
    fn corpus_layer_with_one_sector_in_a_multi_sector_file() {
        let sectors = decode(&bytes(ONE_SECTOR), 1).unwrap();
        assert_eq!(sectors.len(), 1);
        assert_eq!(sectors[0].sector_id, 0);
        assert_eq!(sectors[0].mask, bytes("00ff0240"));
        assert_eq!(encode(&sectors), bytes(ONE_SECTOR));
        let layer = crate::ree::decode(&sectors[0].mask, 3072, true).unwrap();
        assert_eq!(layer.pixels[63], 255);
        assert_eq!(layer.pixels[64], 0);
    }

    #[test]
    fn an_empty_layer_is_an_empty_vector() {
        assert_eq!(decode(&[], 0).unwrap(), Vec::new());
        assert_eq!(
            decode(&[], 3).unwrap_err().check(),
            Check::LtblSectorCountMatch
        );
    }

    #[test]
    fn the_in_band_count_must_equal_the_ltbl_entry() {
        let sectors = vec![SectorLayer {
            sector_id: 0,
            mask: bytes("00ff0264"),
        }];
        let data = encode(&sectors);
        assert_eq!(decode(&data, 1).unwrap(), sectors);
        assert_eq!(
            decode(&data, 2).unwrap_err().check(),
            Check::LtblSectorCountMatch
        );
        // A hostile count is refused before any allocation is attempted.
        let mut hostile = crate::varint::to_vec(1_000_000_000);
        hostile.push(0x00);
        assert_eq!(
            decode(&hostile, 1).unwrap_err().check(),
            Check::LtblSectorCountMatch
        );
    }

    #[test]
    fn a_repeated_sector_id_is_rejected() {
        let mut data = crate::varint::to_vec(2);
        for _ in 0..2 {
            data.extend_from_slice(&crate::varint::to_vec(0));
            data.extend_from_slice(&crate::varint::to_vec(4));
            data.extend_from_slice(&bytes("00ff0264"));
        }
        assert_eq!(decode(&data, 2).unwrap_err().check(), Check::SectorTags);
    }

    #[test]
    fn a_truncated_sector_is_rejected() {
        // Two sectors declared, but the first mask claims four bytes of which
        // only one is present.
        let mut data = crate::varint::to_vec(2);
        data.extend_from_slice(&crate::varint::to_vec(0));
        data.extend_from_slice(&crate::varint::to_vec(4));
        data.push(0x00);
        assert_eq!(decode(&data, 2).unwrap_err().check(), Check::SectorTags);
    }

    #[test]
    fn framing_round_trips() {
        let sectors = vec![
            SectorLayer {
                sector_id: 0,
                mask: bytes("00ff0264"),
            },
            SectorLayer {
                sector_id: 3,
                mask: bytes("000003c80164"),
            },
        ];
        let data = encode(&sectors);
        assert_eq!(data[0], 2, "the count varint leads the framing");
        assert_eq!(decode(&data, 2).unwrap(), sectors);
        assert_eq!(encode(&[]), vec![0x00]);
    }

    #[test]
    fn split_tag_needs_a_tag() {
        assert_eq!(split_tag(&[]).unwrap_err().check(), Check::ReeTag);
        let mask = bytes("00ff0264");
        assert_eq!(split_tag(&mask).unwrap(), (0x00, &mask[1..]));
        let (tag, stream) = split_tag(&[0x01]).unwrap();
        assert_eq!(tag, 0x01);
        assert!(stream.is_empty());
    }
}
