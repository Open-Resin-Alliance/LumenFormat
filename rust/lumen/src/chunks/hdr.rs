//! The `HDR` chunk: display dimensions, layer count and encoder identity
//! ([`spec/03-chunks.md`] section 4.1).

use crate::check::Check;
use crate::error::{Error, Result};
use crate::io::{Reader, Writer};

/// Bytes of `HDR` other than `encoder_name`: 4 before it and 48 after.
pub const HDR_FIXED_LEN: usize = 52;
/// Longest permitted `encoder_name`.
pub const ENCODER_NAME_MAX: usize = 256;

/// The `HDR` chunk body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hdr {
    /// Layout version. `1` for this specification.
    pub hdr_version: u32,
    /// UTF-8 encoder identity, e.g. `DragonFruit 1.0`.
    pub encoder_name: String,
    /// Creation timestamp in Unix seconds.
    pub created_unix_sec: u64,
    /// Logical display width: the layer mask grid.
    pub display_width_px: u32,
    /// Logical display height.
    pub display_height_px: u32,
    /// Physical panel width, an integer multiple of the display width.
    pub physical_width_px: u32,
    /// Physical panel height, an integer multiple of the display height.
    pub physical_height_px: u32,
    /// Build plate X dimension in micrometers.
    pub build_width_um: u32,
    /// Build plate Y dimension in micrometers.
    pub build_depth_um: u32,
    /// Build plate Z dimension in micrometers.
    pub build_height_um: u32,
    /// Default layer thickness in micrometers.
    pub layer_height_um: u32,
    /// Total layer count, which `LTBL.layer_count` must equal.
    pub total_layers: u32,
}

impl Hdr {
    /// Parse the chunk payload.
    pub fn parse(payload: &[u8]) -> Result<Hdr> {
        let mut r = Reader::checked(payload, Check::HdrFrame);
        let hdr_version = r.u32()?;
        if hdr_version != 1 {
            return Err(Error::new(
                Check::HdrVersion,
                format!("unsupported hdr_version {hdr_version}"),
            ));
        }
        let encoder_name_len = r.u32()?;
        if encoder_name_len as usize > ENCODER_NAME_MAX {
            return Err(Error::new(
                Check::HdrFrame,
                format!(
                    "encoder_name_len {encoder_name_len} exceeds the {ENCODER_NAME_MAX} byte limit"
                ),
            ));
        }
        let encoder_name = r.utf8(encoder_name_len as usize)?.to_owned();
        let created_unix_sec = r.u64()?;
        let display_width_px = r.u32()?;
        let display_height_px = r.u32()?;
        let physical_width_px = r.u32()?;
        let physical_height_px = r.u32()?;
        let build_width_um = r.u32()?;
        let build_depth_um = r.u32()?;
        let build_height_um = r.u32()?;
        let layer_height_um = r.u32()?;
        let total_layers = r.u32()?;
        Ok(Hdr {
            hdr_version,
            encoder_name,
            created_unix_sec,
            display_width_px,
            display_height_px,
            physical_width_px,
            physical_height_px,
            build_width_um,
            build_depth_um,
            build_height_um,
            layer_height_um,
            total_layers,
        })
    }

    /// Serialize the chunk payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(HDR_FIXED_LEN + self.encoder_name.len());
        w.u32(self.hdr_version);
        w.u32(self.encoder_name.len() as u32);
        w.bytes(self.encoder_name.as_bytes());
        w.u64(self.created_unix_sec);
        w.u32(self.display_width_px);
        w.u32(self.display_height_px);
        w.u32(self.physical_width_px);
        w.u32(self.physical_height_px);
        w.u32(self.build_width_um);
        w.u32(self.build_depth_um);
        w.u32(self.build_height_um);
        w.u32(self.layer_height_um);
        w.u32(self.total_layers);
        w.into_vec()
    }

    /// Pixels in one layer mask: `display_width_px * display_height_px`.
    pub fn total_pixels(&self) -> u32 {
        self.display_width_px.saturating_mul(self.display_height_px)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> Hdr {
        Hdr {
            hdr_version: 1,
            encoder_name: name.to_owned(),
            created_unix_sec: 1_710_000_000,
            display_width_px: 64,
            display_height_px: 48,
            physical_width_px: 128,
            physical_height_px: 96,
            build_width_um: 218_000,
            build_depth_um: 123_000,
            build_height_um: 250_000,
            layer_height_um: 50,
            total_layers: 4,
        }
    }

    #[test]
    fn hdr_round_trips_with_a_multibyte_name() {
        let hdr = sample("DragonFruit 1.0 \u{2713}");
        let bytes = hdr.to_bytes();
        // `encoder_name_len` counts bytes, not characters: the check mark is three.
        assert_eq!(bytes.len(), HDR_FIXED_LEN + hdr.encoder_name.len());
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize,
            hdr.encoder_name.len()
        );
        let parsed = Hdr::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn hdr_rejects_a_length_measured_in_characters() {
        let hdr = sample("DragonFruit \u{2713}");
        let mut bytes = hdr.to_bytes();
        // A writer that confused characters for bytes declares too few bytes,
        // so the name no longer decodes as UTF-8.
        let chars = hdr.encoder_name.chars().count() as u32;
        bytes[4..8].copy_from_slice(&chars.to_le_bytes());
        let err = Hdr::parse(&bytes).unwrap_err();
        assert_eq!(err.check(), Check::HdrFrame);
    }

    #[test]
    fn hdr_rejects_an_oversized_or_truncated_frame() {
        let mut bytes = sample("DragonFruit 1.0").to_bytes();
        bytes[4..8].copy_from_slice(&(ENCODER_NAME_MAX as u32 + 1).to_le_bytes());
        assert_eq!(Hdr::parse(&bytes).unwrap_err().check(), Check::HdrFrame);

        let bytes = sample("DragonFruit 1.0").to_bytes();
        assert_eq!(
            Hdr::parse(&bytes[..bytes.len() - 1]).unwrap_err().check(),
            Check::HdrFrame
        );
        assert_eq!(
            Hdr::parse(&bytes[..4]).unwrap_err().check(),
            Check::HdrFrame
        );
    }

    #[test]
    fn hdr_rejects_unknown_versions_but_tolerates_trailing_bytes() {
        let mut bytes = sample("X").to_bytes();
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Hdr::parse(&bytes).unwrap_err().check(), Check::HdrVersion);

        let mut bytes = sample("X").to_bytes();
        bytes.push(0);
        assert_eq!(Hdr::parse(&bytes).unwrap(), sample("X"));
    }
}
