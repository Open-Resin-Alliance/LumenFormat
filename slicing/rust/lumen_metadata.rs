//! The slice job's metadata as LUMEN's `HEAD` and `META`.
//!
//! `SliceJobV3` carries geometry, resolution and anti-aliasing settings but no
//! timing and no printer identity: exposures, motion, waits and temperatures live in
//! the opaque `metadata_json` string the app layer builds (see
//! `src/features/slicing/rasterLayerZipExport.ts`), with plugin-local settings merged
//! in by the export orchestrator. This module reads that JSON and fills LUMEN's HEAD
//! (section 2) and META (section 5), which is the same job the CTB plugin's
//! `ctb_metadata.rs` does for its container.
//!
//! A value is looked up in the containment chain DragonFruit already writes:
//! `lumen.*` first, so the LUMEN settings profile (`materialSettings/`, registered by
//! `pluginDefinition.ts`) owns every field it defines, then the CTB-shaped `ctb.*` /
//! `export.ctb.*` keys, which a profile that was written for ChiTuBox carries and which
//! keep such a profile slicing LUMEN correctly without new settings, then the base
//! `material` node of the manifest.
//!
//! Units: LUMEN stores integer micrometres and whole milliseconds, and nothing below
//! one micrometre or one millisecond is expressible, so every value is rounded to the
//! nearest unit here rather than truncated, and the last two rows of Appendix B's
//! conversion table are the live ones: `liftDistanceMm`/`liftDistance2Mm` are already
//! the two segments LUMEN wants.

use std::time::{SystemTime, UNIX_EPOCH};

use lumen::chunks::head::Head;
use lumen::json::{AntiAliasing, Material, Meta, Printer, Slicer, Timing};
use serde_json::Value;

use crate::engine::SlicerV3Error;
use crate::types::SliceJobV3;

use super::lumen_types::{DEFAULT_LAYERS_PER_CHUNK, DEFAULT_ZSTD_LEVEL, ENCODER_NAME};

/// LUMEN's `META` requires these ten fields to be present (section 11.2), so every
/// one of them is written even when the job has nothing to say about it.
pub const HEAD_VERSION: u32 = 1;
/// `META.meta_version`: the schema version of the payload.
pub const META_VERSION: u32 = 1;

/// Everything the encoder needs from the job besides the masks themselves.
pub struct LumenMetadata {
    pub head: Head,
    pub meta: Meta,
    pub layers_per_chunk: u32,
    pub zstd_level: i32,
}

/// Containers a settings value may live in, most specific first.
///
/// `lumen` and its `timing` child are where the LUMEN settings profile puts the
/// motion, wait, PWM and temperature values it owns; the `ctb` and `export.ctb`
/// entries keep a profile written for ChiTuBox working; `material` is the manifest's
/// own node, which holds the base exposures and the first lift segment.
const CONTAINERS: [&str; 9] = [
    "lumen",
    "lumen.timing",
    "export.lumen",
    "export.lumen.timing",
    "ctb",
    "ctb.timing",
    "export.ctb",
    "export.ctb.timing",
    "material",
];

/// The job's `metadata_json`, read as a tree.
struct Values {
    root: Value,
}

impl Values {
    fn new(json: &str) -> Self {
        Self {
            root: serde_json::from_str(json).unwrap_or(Value::Null),
        }
    }

    /// Resolve a dotted path, e.g. `printer.buildVolumeMm.height`.
    fn at(&self, path: &str) -> Option<&Value> {
        let mut current = &self.root;
        for part in path.split('.') {
            current = current.get(part)?;
        }
        Some(current)
    }

    /// A number carried under `key`, from the first container that has one.
    fn number(&self, key: &str) -> Option<f64> {
        CONTAINERS
            .iter()
            .find_map(|container| self.at(container)?.get(key)?.as_f64())
    }

    /// A dotted path read as a number.
    fn number_at(&self, path: &str) -> Option<f64> {
        self.at(path)?.as_f64()
    }

    /// A dotted path read as a string.
    fn text_at(&self, path: &str) -> Option<String> {
        self.at(path)?.as_str().map(str::to_string)
    }

    /// A dotted path read as an unsigned integer, tolerating a float spelling.
    fn unsigned_at(&self, path: &str) -> Option<u32> {
        let value = self.at(path)?;
        value
            .as_u64()
            .or_else(|| value.as_f64().map(|number| number as u64))
            .and_then(|number| u32::try_from(number).ok())
    }
}

/// Round to the nearest whole unit, never below zero and never overflowing.
///
/// LUMEN has no sub-unit precision (section 2), so this is the only rounding the
/// conversion is allowed to do: a 2.0005 mm lift is 2001 um, not 2000.
fn whole(value: f64) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    let rounded = value.round();
    if rounded >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        rounded as u32
    }
}

/// Millimetres to micrometres.
fn um_from_mm(millimetres: f64) -> u32 {
    whole(millimetres * 1000.0)
}

/// Seconds to whole milliseconds.
fn ms_from_sec(seconds: f64) -> u32 {
    whole(seconds * 1000.0)
}

/// A percentage to LUMEN's `0`-`255` PWM scale.
fn pwm_from_percent(percent: f64) -> u32 {
    if !percent.is_finite() || percent <= 0.0 {
        return 0;
    }
    ((percent * 2.55).round() as i64).clamp(0, 255) as u32
}

/// `HEAD` and `META` for this job.
pub fn build(job: &SliceJobV3) -> Result<LumenMetadata, SlicerV3Error> {
    // The engine hands the encoder runs at the source raster resolution, one run
    // list per layer covering the whole frame. LUMEN stores masks on the display
    // grid and a reader applies no flip or unpack (section 2), so the two grids must
    // be the same thing: they are whenever the job is not packed, and a packed job
    // would need a HEAD whose display grid is not the run stream's.
    if job.x_packing_mode != "none" {
        return Err(SlicerV3Error::UnsupportedOutput(format!(
            "the LUMEN encoder stores masks on the display grid, so it cannot write a job packed as {}",
            job.x_packing_mode
        )));
    }

    let values = Values::new(&job.metadata_json);
    let width = job.source_width_px;
    let height = job.source_height_px;
    let total_layers = job.total_layers;

    let layer_height_um = {
        let from_job = um_from_mm(f64::from(job.layer_height_mm));
        if from_job > 0 {
            from_job
        } else {
            um_from_mm(values.number("layerHeightMm").unwrap_or(0.0))
        }
    };

    let created_unix_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);

    // Build volume: the plate comes from the job, the Z height only from the
    // printer node. Without it, the tallest thing the job can represent is the stack
    // it was asked to slice.
    let build_width_um = um_from_mm(f64::from(job.build_width_mm));
    let build_depth_um = um_from_mm(f64::from(job.build_depth_mm));
    let stacked_height_um = (layer_height_um as u64 * total_layers as u64).min(u64::from(u32::MAX)) as u32;
    let build_height_um = values
        .number_at("printer.buildVolumeMm.height")
        .map(um_from_mm)
        .filter(|height| *height > 0)
        .unwrap_or(stacked_height_um);

    let head = Head {
        head_version: HEAD_VERSION,
        encoder_name: ENCODER_NAME.to_string(),
        created_unix_sec,
        display_width_px: width,
        display_height_px: height,
        physical_width_px: width,
        physical_height_px: height,
        build_width_um,
        build_depth_um,
        build_height_um,
        layer_height_um,
        total_layers,
    };

    let mut timing = Timing {
        layer_height_um: Some(layer_height_um),
        normal_exposure_ms: Some(ms_from_sec(values.number("normalExposureSec").unwrap_or(0.0))),
        bottom_exposure_ms: Some(ms_from_sec(values.number("bottomExposureSec").unwrap_or(0.0))),
        bottom_layer_count: Some(values.number("bottomLayerCount").unwrap_or(0.0) as u32),
        transition_layer_count: Some(values.number("transitionLayerCount").unwrap_or(0.0) as u32),
        ..Timing::default()
    };

    // Motion. LUMEN keeps the peel and the remainder as two segments per direction
    // (Appendix B), and DragonFruit's settings already carry both, so these map one
    // to one. A second segment of zero is the specification's way of saying the
    // motion is single-stage, which is exactly what the simple settings mode means.
    timing.lift_slow_distance_um = Some(um_from_mm(values.number("liftDistanceMm").unwrap_or(0.0)));
    timing.lift_slow_speed_um_min = Some(um_from_mm(values.number("liftSpeedMmMin").unwrap_or(0.0)));
    timing.lift_fast_distance_um = Some(um_from_mm(values.number("liftDistance2Mm").unwrap_or(0.0)));
    timing.lift_fast_speed_um_min = Some(um_from_mm(values.number("liftSpeed2MmMin").unwrap_or(0.0)));

    let lift_distance_mm = values.number("liftDistanceMm").unwrap_or(0.0);
    let retract_distance_mm = values
        .number("retractDistanceMm")
        .filter(|value| *value > 0.0)
        .unwrap_or(lift_distance_mm);
    timing.retract_fast_distance_um = Some(um_from_mm(retract_distance_mm));
    timing.retract_fast_speed_um_min = Some(um_from_mm(values.number("retractSpeedMmMin").unwrap_or(0.0)));
    timing.retract_slow_distance_um = Some(um_from_mm(values.number("retractDistance2Mm").unwrap_or(0.0)));
    timing.retract_slow_speed_um_min = Some(um_from_mm(values.number("retractSpeed2MmMin").unwrap_or(0.0)));

    timing.bottom_lift_slow_distance_um = Some(um_from_mm(values.number("bottomLiftDistanceMm").unwrap_or(0.0)));
    timing.bottom_lift_slow_speed_um_min = Some(um_from_mm(values.number("bottomLiftSpeedMmMin").unwrap_or(0.0)));
    timing.bottom_lift_fast_distance_um = Some(um_from_mm(values.number("bottomLiftDistance2Mm").unwrap_or(0.0)));
    timing.bottom_lift_fast_speed_um_min = Some(um_from_mm(values.number("bottomLiftSpeed2MmMin").unwrap_or(0.0)));
    timing.bottom_retract_fast_distance_um = Some(um_from_mm(values.number("bottomRetractDistanceMm").unwrap_or(0.0)));
    timing.bottom_retract_fast_speed_um_min = Some(um_from_mm(values.number("bottomRetractSpeedMmMin").unwrap_or(0.0)));
    // Appendix B's closing note: ChiTuBox's second retract height is the same
    // quantity as LUMEN's slow retract distance, bottom or not.
    timing.bottom_retract_slow_distance_um = Some(um_from_mm(values.number("bottomRetractHeight2Mm").unwrap_or(0.0)));
    timing.bottom_retract_slow_speed_um_min = Some(um_from_mm(values.number("bottomRetractSpeed2MmMin").unwrap_or(0.0)));

    // Waits. LUMEN has no light-off field: ChiTuBox's light-off delay is the pause
    // after the cure, which is `wait_time_after_cure_ms` (Appendix B).
    timing.wait_time_before_cure_ms = Some(ms_from_sec(values.number("waitTimeBeforeCureSec").unwrap_or(0.0)));
    timing.wait_time_after_cure_ms = Some(ms_from_sec(
        values
            .number("waitTimeAfterCureSec")
            .or_else(|| values.number("lightOffDelaySec"))
            .unwrap_or(0.0),
    ));
    timing.wait_time_after_lift_ms = Some(ms_from_sec(values.number("waitTimeAfterLiftSec").unwrap_or(0.0)));
    timing.bottom_wait_time_before_cure_ms = Some(ms_from_sec(values.number("bottomWaitTimeBeforeCureSec").unwrap_or(0.0)));
    timing.bottom_wait_time_after_cure_ms = Some(ms_from_sec(
        values
            .number("bottomWaitTimeAfterCureSec")
            .or_else(|| values.number("bottomLightOffDelaySec"))
            .unwrap_or(0.0),
    ));
    timing.bottom_wait_time_after_lift_ms = Some(ms_from_sec(values.number("bottomWaitTimeAfterLiftSec").unwrap_or(0.0)));

    let light_pwm = pwm_from_percent(values.number("projectorPwmPercent").unwrap_or(0.0));
    if light_pwm > 0 {
        timing.light_pwm = Some(light_pwm);
    }
    let bottom_light_pwm = pwm_from_percent(values.number("bottomProjectorPwmPercent").unwrap_or(0.0));
    if bottom_light_pwm > 0 {
        timing.bottom_light_pwm = Some(bottom_light_pwm);
    }

    // Temperatures. These have no ChiTuBox counterpart to convert or rename, so they
    // are read as plain numbers and written as they come: Celsius, in a fractional
    // unit, not one of the integer micrometre or millisecond scales above. Only a key
    // the job actually carries produces a field, so a job without one leaves META
    // without a temperature and the printer keeps its own default (unheated).
    // `cure_curve` is deliberately never set: it is an object, not a settings field.
    timing.chamber_temperature_c = values.number("chamberTemperatureC");
    timing.vat_temperature_c = values.number("vatTemperatureC");

    // The printer node, as the manifest writes it. Pixel pitch is not carried, so it
    // is derived from the plate and the panel, which is the same derivation the
    // engine's own `xy_pixel_pitch_mm` helper makes.
    let pixel_size_um = if width > 0 && build_width_um > 0 {
        Some((build_width_um as u64 / width as u64).min(u64::from(u32::MAX)) as u32)
    } else {
        None
    };
    let bit_depth = values
        .unsigned_at("printer.bitDepth.bits")
        .or_else(|| values.unsigned_at("printer.bitDepth"));
    let printer = Printer {
        name: values.text_at("printer.name"),
        display_width_px: Some(width),
        display_height_px: Some(height),
        pixel_size_um,
        build_width_um: Some(build_width_um),
        build_depth_um: Some(build_depth_um),
        build_height_um: Some(build_height_um),
        bit_depth,
        ..Printer::default()
    };

    // The material library, when the job names a material. An entry's name must be
    // non-empty, so an unnamed material is left out rather than written blank; the
    // app-level material id has no schema field of its own and rides in `extra`,
    // which section 10.2 preserves.
    let materials = values
        .text_at("material.name")
        .filter(|name| !name.trim().is_empty())
        .map(|name| {
            let mut extra = serde_json::Map::new();
            if let Some(id) = values.text_at("material.id") {
                extra.insert("id".to_string(), Value::String(id));
            }
            vec![Material {
                name,
                brand: None,
                family: None,
                density_g_ml: None,
                color_rgba: None,
                bottle_price: None,
                bottle_capacity_ml: None,
                extra,
            }]
        });

    let anti_aliasing = AntiAliasing {
        enabled: Some(!job.anti_aliasing_level.eq_ignore_ascii_case("off")),
        level: aa_level(&job.anti_aliasing_level),
        mode: Some(job.anti_aliasing_mode.to_ascii_lowercase()).filter(|mode| !mode.is_empty()),
        minimum_alpha_percent: Some(f64::from(job.minimum_aa_alpha_percent)),
        blur_brush_radius_px: Some(job.blur_brush_radius_px),
        blur_brush_kernel: Some(job.blur_brush_kernel.clone()).filter(|kernel| !kernel.is_empty()),
        blur_brush_sigma_x: Some(job.blur_brush_sigma_x),
        blur_brush_sigma_y: Some(job.blur_brush_sigma_y),
        z_blend_look_back: Some(job.z_blend_look_back),
        dither_enabled: Some(job.dither_enabled),
        ..AntiAliasing::default()
    };

    let meta = Meta {
        meta_version: Some(META_VERSION),
        timing,
        materials,
        printer: Some(printer),
        anti_aliasing: Some(anti_aliasing),
        slicer: Some(Slicer {
            name: Some("DragonFruit".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            url: Some("https://dragonfruit-slicer.com".to_string()),
            ..Slicer::default()
        }),
        ..Meta::default()
    };

    Ok(LumenMetadata {
        head,
        meta,
        layers_per_chunk: values
            .number("layersPerChunk")
            .map(whole)
            .filter(|chunk| *chunk > 0)
            .unwrap_or(DEFAULT_LAYERS_PER_CHUNK),
        zstd_level: values
            .number("zstdLevel")
            .map(|level| (level.round() as i64).clamp(1, 22) as i32)
            .unwrap_or(DEFAULT_ZSTD_LEVEL),
    })
}

/// The factor in an AA level spelled `Off`, `2x`, `4x`, or as a bare number.
fn aa_level(level: &str) -> Option<u32> {
    let digits: String = level.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<u32>().ok().filter(|factor| *factor > 1)
}
