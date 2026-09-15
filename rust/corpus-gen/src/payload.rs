//! Chunk payload builders: the bytes of HDR, META, PROF, LROV, LTBL, LHAS,
//! ZDIC, LAYR, VOXL and EXTD before any of it is compressed or sealed.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::container::{Chunk, LAYR_VERSION, LTBL_ENTRY_SIZE};
use crate::hash;
use crate::json;
use crate::obj;
use crate::CREATED_UNIX_SEC;

/// One entry of the layer table (spec 4.9): one `(layer, sector)`'s slice.
#[derive(Clone, Copy)]
pub struct LayerEntry {
    /// The layer this entry belongs to.
    pub layer: u32,
    /// The sector the slice belongs to; 0 is primary.
    pub sector_id: u32,
    /// The slice's length; 0 for a sector the layer carries no data for.
    pub data_size: u32,
    /// The directory index of the `(layer, sector)`'s `LROV` chunk, or 0 when it
    /// has no overrides.
    pub first_lrov: u32,
    /// The directory index of the `LAYR` chunk whose frame holds the slice.
    pub first_layr: u32,
    /// Further entries for this layer after this one; non-zero only on a layer's
    /// first entry.
    pub additional_sector_count: u32,
    /// The slice's offset inside `first_layr`'s decompressed frame.
    pub data_offset: u64,
}

/// The file header's fields (spec 3.1).
///
/// The build volume is part of the corpus' fixed test rig, so it lives in the
/// default rather than at every call site.
pub struct Header<'a> {
    pub encoder_name: &'a str,
    pub display_w: u32,
    pub display_h: u32,
    pub build_w_um: u32,
    pub build_d_um: u32,
    pub build_h_um: u32,
    pub layer_height_um: u32,
    pub total_layers: u32,
}

impl Default for Header<'_> {
    fn default() -> Self {
        Header {
            encoder_name: "",
            display_w: 0,
            display_h: 0,
            build_w_um: 218_000,
            build_d_um: 123_000,
            build_h_um: 250_000,
            layer_height_um: 0,
            total_layers: 0,
        }
    }
}

/// The file header (spec 3.1).
pub fn hdr(header: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.encoder_name.len() as u32).to_le_bytes());
    out.extend_from_slice(header.encoder_name.as_bytes());
    out.extend_from_slice(&CREATED_UNIX_SEC.to_le_bytes());
    for value in [
        header.display_w,
        header.display_h,
        header.display_w,
        header.display_h,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in [
        header.build_w_um,
        header.build_d_um,
        header.build_h_um,
        header.layer_height_um,
        header.total_layers,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// META's object, with `overrides` applied on top of the corpus' settings
/// (spec 4.2).
///
/// The object rather than its bytes, because the manifest resolves its timing
/// pipeline from the same values the payload carries.
pub fn meta_value(overrides: &[(&str, Value)]) -> Value {
    json::merge(
        obj![
            "meta_version" => 1,
            "normal_exposure_ms" => 2500,
            "bottom_exposure_ms" => 30000,
            "bottom_layer_count" => 2,
            "transition_layer_count" => 1,
            "layer_height_um" => 50,
            "lift_slow_distance_um" => 5000,
            "lift_slow_speed_um_min" => 65000,
            "retract_fast_distance_um" => 5000,
            "retract_fast_speed_um_min" => 150000,
        ],
        overrides,
    )
}

/// One `META.sectors` entry (spec 4.2): a non-zero sector's identity and the
/// timing it resolves with, both inherited per field from META.
pub fn sector_value(sector_id: u32, name: &str, exposure_ms: u32) -> Value {
    obj![
        "sector_id" => sector_id,
        "name" => name,
        "material_index" => 0,
        "normal_exposure_ms" => exposure_ms,
    ]
}

/// LTBL (spec 4.9): the header, then one 28-byte entry per `(layer, sector)`, the
/// entries of a layer adjacent and that layer's first entry naming sector 0.
pub fn ltbl(entries: &[LayerEntry], layer_count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + entries.len() * LTBL_ENTRY_SIZE);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&layer_count.to_le_bytes());
    out.extend_from_slice(&(LTBL_ENTRY_SIZE as u32).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.data_size.to_le_bytes());
        out.extend_from_slice(&entry.first_lrov.to_le_bytes());
        out.extend_from_slice(&entry.first_layr.to_le_bytes());
        out.extend_from_slice(&entry.additional_sector_count.to_le_bytes());
        out.extend_from_slice(&entry.data_offset.to_le_bytes());
        out.extend_from_slice(&entry.sector_id.to_le_bytes());
    }
    out
}

/// LHAS (spec 4.11): the root, then every leaf.
pub fn lhas(leaves: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(38 + leaves.len() * 32);
    out.push(0x01);
    out.push(32);
    out.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
    out.extend_from_slice(&hash::merkle_root(leaves));
    for leaf in leaves {
        out.extend_from_slice(leaf);
    }
    out
}

/// ZDIC (spec 4.8).
pub fn zdic(dict_bytes: &[u8], dict_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + dict_bytes.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&dict_id.to_le_bytes());
    out.extend_from_slice(&(dict_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(dict_bytes);
    out
}

/// LAYR (spec 4.10): the version field, then the chunk's single zstd frame.
///
/// One chunk carries one frame - the concatenation of a sector's layer data for
/// one group of layers - so the container is the version field and the frame and
/// nothing else.
pub fn layr(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&LAYR_VERSION.to_le_bytes());
    out.extend_from_slice(frame);
    out
}

/// Settings overrides for [`prof`], by META's field names.
#[derive(Default)]
pub struct ProfSettings {
    pub normal_exposure_ms: Option<i64>,
    pub layer_height_um: Option<i64>,
    pub cure_curve: Option<Value>,
}

impl ProfSettings {
    fn entries(&self) -> Vec<(&'static str, Value)> {
        let mut out = Vec::new();
        if let Some(value) = self.normal_exposure_ms {
            out.push(("normal_exposure_ms", Value::from(value)));
        }
        if let Some(value) = self.layer_height_um {
            out.push(("layer_height_um", Value::from(value)));
        }
        if let Some(value) = &self.cure_curve {
            out.push(("cure_curve", value.clone()));
        }
        out
    }
}

/// Top-level overrides for [`prof`].
#[derive(Default)]
pub struct ProfOverrides {
    pub profile_type: Option<&'static str>,
    pub profile_name: Option<&'static str>,
    pub profile_uuid: Option<&'static str>,
    pub materials: Option<Value>,
}

impl ProfOverrides {
    fn entries(&self) -> Vec<(&'static str, Value)> {
        let mut out = Vec::new();
        if let Some(value) = self.profile_type {
            out.push(("profile_type", Value::from(value)));
        }
        if let Some(value) = self.profile_name {
            out.push(("profile_name", Value::from(value)));
        }
        if let Some(value) = self.profile_uuid {
            out.push(("profile_uuid", Value::from(value)));
        }
        if let Some(value) = &self.materials {
            out.push(("materials", value.clone()));
        }
        out
    }
}

/// PROF (spec 4.3): a reusable print profile, with META's field names under
/// `settings`.
pub fn prof(settings_extra: ProfSettings, overrides: ProfOverrides) -> Vec<u8> {
    let settings = json::merge(
        obj![
            "normal_exposure_ms" => 2500,
            "bottom_exposure_ms" => 32000,
            "bottom_layer_count" => 5,
            "transition_layer_count" => 8,
            "layer_height_um" => 50,
            "lift_slow_distance_um" => 5000,
            "lift_slow_speed_um_min" => 65000,
            "lift_fast_distance_um" => 3000,
            "lift_fast_speed_um_min" => 200000,
            "retract_fast_distance_um" => 4000,
            "retract_fast_speed_um_min" => 150000,
            "retract_slow_distance_um" => 2000,
            "retract_slow_speed_um_min" => 180000,
            "bottom_lift_slow_distance_um" => 6000,
            "bottom_lift_slow_speed_um_min" => 50000,
            "bottom_retract_fast_distance_um" => 6000,
            "bottom_retract_fast_speed_um_min" => 100000,
            "wait_time_before_cure_ms" => 1000,
            "wait_time_after_cure_ms" => 0,
            "wait_time_after_lift_ms" => 500,
            "light_pwm" => 255,
            "chamber_temperature_c" => 30.0,
            "vat_temperature_c" => 28.0,
            "cure_curve" => obj!["dp_um" => 120, "ec_mj_cm2" => 7.5, "e0_mj_cm2" => 3.0],
        ],
        &settings_extra.entries(),
    );

    let profile = json::merge(
        obj![
            "profile_name" => "LumenFormat test profile",
            "profile_version" => "1.0.0",
            "profile_type" => "combined",
            "profile_uuid" => "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "settings" => settings,
            "materials" => vec![obj![
                "name" => "ABS-Like Grey",
                "brand" => "DragonFruit",
                "family" => "abs-like",
                "density_g_ml" => 1.1,
                "color_rgba" => vec![128, 128, 128, 255],
                "bottle_price" => 29.99,
                "bottle_capacity_ml" => 1000,
            ]],
            "scale_compensation_pct" => obj!["x" => 0.5, "y" => 0.5, "z" => 0.0],
            "extra" => json::obj(Vec::new()),
        ],
        &overrides.entries(),
    );
    json::dumps(&profile)
}

/// LROV (spec 4.6): one `(layer, sector)`'s timing deltas, as the JSON object the
/// chunk carries.
///
/// The point the chunk belongs to is not in the payload: the entry that names
/// this chunk is what places it, so an override set can never disagree with the
/// layer table about who it applies to.
pub fn lrov(fields: &[(&str, Value)]) -> Vec<u8> {
    json::dumps(&json::obj(fields.to_vec()))
}

/// VOXL (spec 4.12): a minimal V1 scene document.
///
/// A V1 document starts with `{`, which is how a reader recognizes the generation
/// without knowing anything else about VOXL.
pub fn voxl() -> Vec<u8> {
    json::dumps(&obj![
        "magic" => "VOXL",
        "version" => 1,
        "meta" => obj!["generator" => "LumenFormat test vectors", "printer" => "Test printer"],
        "scene" => obj!["name" => "embedded-scene", "units" => "mm"],
        "models" => Vec::<Value>::new(),
        "supports" => Vec::<Value>::new(),
    ])
}

/// An EXTD chunk (spec 4.13) and the descriptor flags that carry its vendor id and
/// critical bit.
#[derive(Clone, Copy)]
pub struct Extd<'a> {
    pub ext_type: &'a [u8],
    pub ext_data: &'a [u8],
    pub ext_version: u32,
    pub vendor_id: u32,
    pub critical: bool,
    pub flags_extra: u32,
}

impl Default for Extd<'_> {
    fn default() -> Self {
        Extd {
            ext_type: &[],
            ext_data: &[],
            ext_version: 1,
            vendor_id: 0,
            critical: false,
            flags_extra: 0,
        }
    }
}

/// The EXTD frame is `ext_version || ext_type || ext_data`. The descriptor's flags
/// carry the vendor id in bits 8-23 and the critical bit at 24; `flags_extra` is for
/// the invalid vectors that set a reserved bit on purpose.
pub fn extd(spec: Extd) -> (Vec<u8>, u32) {
    let flags = ((spec.vendor_id & 0xFFFF) << 8)
        | if spec.critical { 0x0100_0000 } else { 0 }
        | spec.flags_extra;
    let mut payload = Vec::with_capacity(4 + spec.ext_type.len() + spec.ext_data.len());
    payload.extend_from_slice(&spec.ext_version.to_le_bytes());
    payload.extend_from_slice(spec.ext_type);
    payload.extend_from_slice(spec.ext_data);
    (payload, flags)
}

/// SHA-256 of each PROF/LROV/PREV/VOXL/EXTD plaintext payload, as the manifest
/// records it: a digest for the singletons, a list for the repeatable ones.
///
/// `LROV` repeats - one chunk per `(layer, sector)` with overrides - so it is a
/// list, in file order.
pub fn payload_hashes(chunks: &[Chunk]) -> Value {
    let mut single: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut lists: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for chunk in chunks {
        let digest = hash::sha256_hex(&chunk.payload);
        match chunk.name() {
            "PREV" | "EXTD" | "LROV" => lists.entry(chunk.name()).or_default().push(digest),
            "PROF" | "VOXL" => {
                single.insert(chunk.name(), digest);
            }
            _ => {}
        }
    }

    let mut entries: Vec<(&str, Value)> = Vec::new();
    entries.extend(
        single
            .into_iter()
            .map(|(key, value)| (key, Value::from(value))),
    );
    entries.extend(
        lists
            .into_iter()
            .map(|(key, values)| (key, Value::from(values))),
    );
    json::obj(entries)
}
