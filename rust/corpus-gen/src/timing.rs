//! Section 8's per-layer settings pipeline, and the sample of points the
//! manifest pins for it.
//!
//! The generator already writes each vector's META, `SECT` and `LROV` payloads;
//! this module reads those same payloads the way a conforming reader must and
//! resolves the timing of a `(layer, sector)` pair ([`spec/11-layer-timing.md`]
//! section 8). `manifest.json` then records the result for the points
//! [`Pipeline::manifest`] selects, so a third-party implementation has numbers to
//! agree with and not just bytes to re-derive.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::json;

/// Light PWM when META carries none (spec 4.2).
const DEFAULT_LIGHT_PWM: u32 = 255;

/// One value a reader resolves per layer: the two names its normal and its
/// bottom form go by in the META, `SECT` and `LROV` namespace, what an absent
/// field means, and whether the transition range blends the pair.
struct Field {
    /// The key the manifest publishes the value under.
    key: &'static str,
    /// The name of the normal form.
    normal: &'static str,
    /// The name of the bottom form.
    bottom: &'static str,
    /// What the field resolves to when neither form is present.
    default: u32,
    /// Whether the transition range interpolates between the two forms. The one
    /// field that does not switches at the first non-bottom layer (spec 8).
    interpolates: bool,
}

/// The values one layer resolves to, in the order the manifest lists them.
///
/// `layer_height_um` is not among them: it is never blended and never has a
/// bottom form, so [`Pipeline::resolve`] takes it straight from META or the
/// sector definition.
const FIELDS: [Field; 13] = [
    Field {
        key: "exposure_ms",
        normal: "normal_exposure_ms",
        bottom: "bottom_exposure_ms",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "lift_slow_distance_um",
        normal: "lift_slow_distance_um",
        bottom: "bottom_lift_slow_distance_um",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "lift_slow_speed_um_min",
        normal: "lift_slow_speed_um_min",
        bottom: "bottom_lift_slow_speed_um_min",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "lift_fast_distance_um",
        normal: "lift_fast_distance_um",
        bottom: "bottom_lift_fast_distance_um",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "lift_fast_speed_um_min",
        normal: "lift_fast_speed_um_min",
        bottom: "bottom_lift_fast_speed_um_min",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "retract_fast_distance_um",
        normal: "retract_fast_distance_um",
        bottom: "bottom_retract_fast_distance_um",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "retract_fast_speed_um_min",
        normal: "retract_fast_speed_um_min",
        bottom: "bottom_retract_fast_speed_um_min",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "retract_slow_distance_um",
        normal: "retract_slow_distance_um",
        bottom: "bottom_retract_slow_distance_um",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "retract_slow_speed_um_min",
        normal: "retract_slow_speed_um_min",
        bottom: "bottom_retract_slow_speed_um_min",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "wait_time_before_cure_ms",
        normal: "wait_time_before_cure_ms",
        bottom: "bottom_wait_time_before_cure_ms",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "wait_time_after_cure_ms",
        normal: "wait_time_after_cure_ms",
        bottom: "bottom_wait_time_after_cure_ms",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "wait_time_after_lift_ms",
        normal: "wait_time_after_lift_ms",
        bottom: "bottom_wait_time_after_lift_ms",
        default: 0,
        interpolates: true,
    },
    Field {
        key: "light_pwm",
        normal: "light_pwm",
        bottom: "bottom_light_pwm",
        default: DEFAULT_LIGHT_PWM,
        interpolates: false,
    },
];

/// The timing one `(layer, sector)` pair resolves to.
struct Resolved {
    /// Layer thickness, from META or the sector definition.
    layer_height_um: u32,
    /// One value per entry of [`FIELDS`], in the same order.
    values: [u32; FIELDS.len()],
}

/// The pipeline's inputs: a file's META object, its `SECT` definitions, its
/// `LROV` entries in file order, and the header's layer count.
pub struct Pipeline<'a> {
    /// META, whose values are the base for every field (spec 8 step 1).
    meta: &'a Map<String, Value>,
    /// Each `SECT` definition, with the `sector_id` it speaks for.
    sectors: Vec<(u32, &'a Map<String, Value>)>,
    /// The `LROV` entries, in file order (spec 8 step 3).
    overrides: &'a [Value],
    /// The header's `total_layers`, which bounds every point.
    total: u32,
}

impl<'a> Pipeline<'a> {
    /// Read a file's timing inputs.
    pub fn new(
        meta: &'a Value,
        sectors: &'a [Value],
        overrides: &'a [Value],
        total_layers: u32,
    ) -> Self {
        let meta = meta.as_object().expect("META is a JSON object");
        let sectors = sectors
            .iter()
            .map(|definition| {
                let definition = definition
                    .as_object()
                    .expect("a SECT definition is a JSON object");
                (
                    int(definition, "sector_id").expect("a SECT definition names its sector"),
                    definition,
                )
            })
            .collect();
        Pipeline {
            meta,
            sectors,
            overrides,
            total: total_layers,
        }
    }

    /// The `resolved_timing` array: every sampled point as the sixteen-key
    /// object the manifest publishes, sorted by `(layer, sector)`.
    pub fn manifest(&self) -> Value {
        Value::Array(
            self.points()
                .into_iter()
                .map(|(layer, sector)| self.point(layer, sector))
                .collect(),
        )
    }

    /// One point as the manifest's object.
    fn point(&self, layer: u32, sector: u32) -> Value {
        let resolved = self.resolve(layer, sector);
        let mut entries: Vec<(&str, Value)> = vec![
            ("layer", Value::from(layer)),
            ("sector", Value::from(sector)),
            ("layer_height_um", Value::from(resolved.layer_height_um)),
        ];
        entries.extend(
            FIELDS
                .iter()
                .zip(resolved.values)
                .map(|(field, value)| (field.key, Value::from(value))),
        );
        json::obj(entries)
    }

    /// The timing of one `(layer, sector)` pair (spec 8 steps 1-5).
    fn resolve(&self, layer: u32, sector: u32) -> Resolved {
        let sect = self.definition(sector);
        let stage = self.stage(layer, sect);
        let mut resolved = Resolved {
            layer_height_um: self.merged(sect, "layer_height_um").unwrap_or(0),
            values: FIELDS.map(|field| self.value(field, sect, stage)),
        };

        // Every matching entry folds onto the resolved values in file order, so
        // the last entry to carry a field wins it while a later entry that omits
        // a field keeps what an earlier one set.
        for entry in self.overrides {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            if !matches_entry(entry, layer, sector) {
                continue;
            }
            if let Some(value) = int(entry, "layer_height_um") {
                resolved.layer_height_um = value;
            }
            for (value, field) in resolved.values.iter_mut().zip(FIELDS) {
                // An entry names a field in its normal or its bottom form; when
                // it carries both, the normal one wins, because the override
                // replaces the layer's single resolved value.
                if let Some(overridden) =
                    int(entry, field.normal).or_else(|| int(entry, field.bottom))
                {
                    *value = overridden;
                }
            }
        }
        resolved
    }

    /// One field at `stage`: the base value META and the sector definition
    /// give, blended when the layer is in the transition range (spec 8 steps
    /// 1-4).
    fn value(&self, field: Field, sect: Option<&Map<String, Value>>, stage: Stage) -> u32 {
        let normal = self.merged(sect, field.normal).unwrap_or(field.default);
        // A `bottom_*` field that is absent equals its normal counterpart, which
        // is what makes that field's interpolation a no-op.
        let bottom = self.merged(sect, field.bottom).unwrap_or(normal);
        match stage {
            Stage::Bottom => bottom,
            Stage::Normal => normal,
            Stage::Transition { k, n } if field.interpolates => blend(normal, bottom, k, n),
            // PWM is categorical, so the transition range takes the normal value
            // rather than an interpolated one.
            Stage::Transition { .. } => normal,
        }
    }

    /// The value for `name`: the sector definition's when it carries one, META's
    /// otherwise (spec 8 step 1).
    fn merged(&self, sect: Option<&Map<String, Value>>, name: &str) -> Option<u32> {
        sect.and_then(|timing| int(timing, name))
            .or_else(|| int(self.meta, name))
    }

    /// The `SECT` definition that speaks for `sector`, when the file carries
    /// one.
    ///
    /// Sector 0 is the implicit primary sector and a `SECT` definition names
    /// `sector_id >= 1` (spec 4.5), so only a non-zero sector can have one, and
    /// a definition speaks for the sector it names.
    fn definition(&self, sector: u32) -> Option<&'a Map<String, Value>> {
        self.sectors
            .iter()
            .find(|(id, _)| *id == sector)
            .map(|(_, timing)| *timing)
    }

    /// The layer counts `sector` resolves with: the definition's when it carries
    /// them, META's otherwise, per field (spec 4.5, 8).
    ///
    /// A file that carries neither count has no bottom or transition range,
    /// which is what zero of each means. `u64` keeps the range's end,
    /// `bottom + transition`, from wrapping on counts a malformed META or `SECT`
    /// could carry.
    fn counts(&self, sect: Option<&Map<String, Value>>) -> (u64, u64) {
        (
            u64::from(self.merged(sect, "bottom_layer_count").unwrap_or(0)),
            u64::from(self.merged(sect, "transition_layer_count").unwrap_or(0)),
        )
    }

    /// Which range `layer` falls in for `sector` (spec 8 step 2).
    fn stage(&self, layer: u32, sect: Option<&Map<String, Value>>) -> Stage {
        let (bottom, transition) = self.counts(sect);
        let index = u64::from(layer);
        if index < bottom {
            Stage::Bottom
        } else if index < bottom + transition {
            Stage::Transition {
                k: index - bottom + 1,
                n: transition + 1,
            }
        } else {
            Stage::Normal
        }
    }

    /// The `(layer, sector)` pairs the manifest pins, sorted and deduplicated.
    ///
    /// Every sector is sampled on the layers its own pipeline branches at,
    /// because a sector resolves the two counts per field for itself: a `SECT`
    /// definition that carries `bottom_layer_count` or
    /// `transition_layer_count` is blended over its own ranges, so the layers
    /// META's counts would put it at are not the ones it branches at (spec 4.5,
    /// 8). A reader MUST NOT resolve the ranges once from META and apply them to
    /// every sector.
    ///
    /// The sectors are sector 0, every `sector_id` a `SECT` definition carries
    /// and every `sector_id` an `LROV` entry names. A sector's layers are the
    /// two ends of its bottom range, its first transition step, its first
    /// fully-normal layer and the last layer, each clamped into the file's
    /// range, plus every layer an `LROV` entry that can match that sector - one
    /// whose `sector_id` is absent or is the sector's - names, both ends of a
    /// `layer_range`, and, for each of those, its neighbours. The pairs are the
    /// union over the sectors of the sector's layers against the sector itself.
    fn points(&self) -> Vec<(u32, u32)> {
        if self.total == 0 {
            return Vec::new();
        }
        let last = i64::from(self.total - 1);
        let clamp = |layer: i64| layer.clamp(0, last) as u32;

        let mut sectors: BTreeSet<u32> = BTreeSet::from([0]);
        sectors.extend(self.sectors.iter().map(|(id, _)| *id));
        for entry in self.overrides {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            if let Some(sector) = int(entry, "sector_id") {
                sectors.insert(sector);
            }
        }

        let mut points: BTreeSet<(u32, u32)> = BTreeSet::new();
        for sector in sectors {
            let sect = self.definition(sector);
            let (bottom, transition) = self.counts(sect);
            let mut layers: BTreeSet<u32> = BTreeSet::new();
            for layer in [
                0,
                1,
                bottom as i64 - 1,
                bottom as i64,
                (bottom + transition) as i64,
                last,
            ] {
                layers.insert(clamp(layer));
            }

            for entry in self.overrides {
                let Some(entry) = entry.as_object() else {
                    continue;
                };
                // An entry that names a sector other than this one cannot match
                // it, and so names no layer of it (spec 4.6).
                if int(entry, "sector_id").is_some_and(|target| target != sector) {
                    continue;
                }
                for layer in named_layers(entry) {
                    // An entry naming a layer the file does not have names no
                    // point of it.
                    if layer >= self.total {
                        continue;
                    }
                    layers.insert(layer);
                    if layer > 0 {
                        layers.insert(layer - 1);
                    }
                    if layer < self.total - 1 {
                        layers.insert(layer + 1);
                    }
                }
            }

            points.extend(layers.into_iter().map(|layer| (layer, sector)));
        }

        points.into_iter().collect()
    }
}

/// Which range a layer falls in (spec 8 step 2).
#[derive(Clone, Copy)]
enum Stage {
    /// Below `bottom_layer_count`: bottom-prefixed values verbatim.
    Bottom,
    /// Inside the transition range: the `k`th of `n` blend steps.
    Transition { k: u64, n: u64 },
    /// At or beyond `bottom_layer_count + transition_layer_count`.
    Normal,
}

/// The specification's exact integer blend (spec 8), with `n` the number of
/// steps, rounding half away from zero - half up, the two ends never being
/// negative:
///
/// ```text
/// value = round((bottom * (n - k) + normal * k) / n)
/// ```
///
/// `u128` keeps both the product and the doubled tie from overflowing on any
/// pair of counts a malformed META could carry, and the value is a convex
/// combination of the two ends, so it always fits the `u32` it came from.
fn blend(normal: u32, bottom: u32, k: u64, n: u64) -> u32 {
    let numerator = u128::from(bottom) * u128::from(n - k) + u128::from(normal) * u128::from(k);
    ((2 * numerator + u128::from(n)) / (2 * u128::from(n))) as u32
}

/// Whether an `LROV` entry targets `(layer, sector)`: its `layer` equals the
/// point's or its inclusive `layer_range` contains it, and its `sector_id` is
/// absent or the point's (spec 4.6).
fn matches_entry(entry: &Map<String, Value>, layer: u32, sector: u32) -> bool {
    if int(entry, "sector_id").is_some_and(|target| target != sector) {
        return false;
    }
    if int(entry, "layer") == Some(layer) {
        return true;
    }
    let Some(range) = entry.get("layer_range").and_then(Value::as_array) else {
        return false;
    };
    let (Some(start), Some(end)) = (
        range.first().and_then(Value::as_u64),
        range.get(1).and_then(Value::as_u64),
    ) else {
        return false;
    };
    start <= u64::from(layer) && u64::from(layer) <= end
}

/// The layers an `LROV` entry names: its `layer`, or both ends of its inclusive
/// `layer_range`.
fn named_layers(entry: &Map<String, Value>) -> Vec<u32> {
    if let Some(layer) = int(entry, "layer") {
        return vec![layer];
    }
    entry
        .get("layer_range")
        .and_then(Value::as_array)
        .map(|range| {
            range
                .iter()
                .filter_map(Value::as_u64)
                .map(|layer| layer as u32)
                .collect()
        })
        .unwrap_or_default()
}

/// An integer field of a JSON object, when it carries one.
///
/// A duration with a fractional part is not a duration this format can express
/// (spec 4.2), so it reads as absent here rather than being truncated.
fn int(object: &Map<String, Value>, name: &str) -> Option<u32> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .map(|value| value as u32)
}
