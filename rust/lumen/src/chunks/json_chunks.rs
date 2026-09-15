//! The JSON chunks: `META`, `PROF`, `SECT` and `LROV`
//! ([`spec/03-chunks.md`], [`spec/05-print-control.md`]).

use crate::check::Check;
use crate::error::{Error, Result};
use crate::json::{Lrov, Meta, Profile, Sect};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Deserialize a JSON chunk payload.
///
/// Every JSON chunk reports the same check on a shape failure: the corpus has
/// no per-chunk JSON variant, and a caller that cares about a specific group
/// validates the parsed value afterwards.
fn from_json<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    serde_json::from_slice(payload).map_err(|e| {
        Error::new(
            Check::MetaJson,
            format!("the JSON payload is not a valid object: {e}"),
        )
    })
}

/// Serialize a JSON chunk payload.
fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| {
        Error::new(
            Check::MetaJson,
            format!("the JSON payload could not be serialized: {e}"),
        )
    })
}

/// Parse a `META` payload.
pub fn parse_meta(payload: &[u8]) -> Result<Meta> {
    from_json(payload)
}

/// Serialize a `META` payload.
pub fn meta_to_bytes(meta: &Meta) -> Result<Vec<u8>> {
    to_json(meta)
}

/// Parse a `PROF` payload.
pub fn parse_profile(payload: &[u8]) -> Result<Profile> {
    from_json(payload)
}

/// Serialize a `PROF` payload.
pub fn profile_to_bytes(profile: &Profile) -> Result<Vec<u8>> {
    to_json(profile)
}

/// Parse a `SECT` payload.
pub fn parse_sect(payload: &[u8]) -> Result<Sect> {
    from_json(payload)
}

/// Serialize a `SECT` payload.
pub fn sect_to_bytes(sect: &Sect) -> Result<Vec<u8>> {
    to_json(sect)
}

/// Parse an `LROV` payload.
pub fn parse_lrov(payload: &[u8]) -> Result<Lrov> {
    from_json(payload)
}

/// Serialize an `LROV` payload.
pub fn lrov_to_bytes(lrov: &Lrov) -> Result<Vec<u8>> {
    to_json(lrov)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_round_trips_and_preserves_unknown_keys() {
        let payload = br#"{
            "meta_version": 1,
            "normal_exposure_ms": 2500,
            "bottom_exposure_ms": 30000,
            "layer_height_um": 50,
            "vendor_extension": {"a": 1}
        }"#;
        let meta = parse_meta(payload).unwrap();
        assert_eq!(meta.meta_version, Some(1));
        assert_eq!(meta.timing.normal_exposure_ms, Some(2500));
        // An unknown key is preserved rather than rejected or dropped.
        assert_eq!(
            meta.timing.extra.get("vendor_extension"),
            Some(&serde_json::json!({"a": 1}))
        );

        let bytes = meta_to_bytes(&meta).unwrap();
        assert_eq!(parse_meta(&bytes).unwrap(), meta);
    }

    #[test]
    fn every_json_chunk_reports_meta_json_on_bad_input() {
        assert_eq!(
            parse_meta(b"not json").unwrap_err().check(),
            Check::MetaJson
        );
        assert_eq!(parse_profile(b"[").unwrap_err().check(), Check::MetaJson);
        assert_eq!(parse_sect(b"").unwrap_err().check(), Check::MetaJson);
        assert_eq!(parse_lrov(b"{}x").unwrap_err().check(), Check::MetaJson);
    }

    #[test]
    fn sect_and_lrov_round_trip() {
        let sect = parse_sect(br#"{"sector_id": 2, "material_index": 1}"#).unwrap();
        assert_eq!(sect.sector_id, 2);
        assert_eq!(parse_sect(&sect_to_bytes(&sect).unwrap()).unwrap(), sect);

        let lrov = parse_lrov(
            br#"{"overrides": [{"layer": 3, "normal_exposure_ms": 2000},
                               {"layer_range": [5, 9], "sector_id": 1}]}"#,
        )
        .unwrap();
        assert_eq!(lrov.overrides.len(), 2);
        assert_eq!(lrov.overrides[0].layer, Some(3));
        assert_eq!(lrov.overrides[1].layer_range, Some([5, 9]));
        assert_eq!(parse_lrov(&lrov_to_bytes(&lrov).unwrap()).unwrap(), lrov);
    }
}
