//! §8: the per-layer settings pipeline, as this reader resolves it.
//!
//! The manifest records, for a sample of `(layer, sector)` points, the numbers a
//! conforming reader must resolve for them, so a third-party implementation has
//! something to agree with. This module is the validator's own reading of that
//! pipeline - written from §8, §4.2 and §4.5 rather than shared with the
//! generator - so agreement between the two is evidence about the specification
//! rather than one implementation restated.
//!
//! Nothing here reads a file. [`TimingInputs`] carries the `META` object and the
//! `(layer, sector)` override sets the reader decrypted and parsed, and
//! [`resolve`] turns them plus a point into the values §8 defines for it.
//! [`sampled_points`] is the other half of the same reading: which points the
//! manifest is expected to record, recomputed from the file's own numbers.
//!
//! The pipeline's inputs moved when the layout did. A sector's base timing is a
//! `META.sectors` entry rather than a `SECT` chunk, field by field over META's
//! base (§4.2); an override set is placed by the entries that name it - what
//! `LTBL.first_lrov` says - rather than by a layer or a layer range in the payload
//! that a reader has to match against, and one chunk may serve every pair whose
//! delta is the same (§4.5). One place, one answer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// Everything §8 resolves a point from - and, for [`sampled_points`], everything
/// the sample of points is bounded by: the chunks the reader parsed, standing in
/// for the file they came from.
pub struct TimingInputs {
    /// `HEAD`'s layer count (§4.1), which bounds every sampled layer.
    pub total_layers: u32,
    /// `META`, the base for every field and the home of the sector definitions
    /// (§4.2).
    pub meta: Value,
    /// Each `(layer, sector)`'s override set, keyed by the point it belongs to.
    /// A point with no overrides has no entry; there is no empty delta, because
    /// `LTBL.first_lrov` is `0` exactly then (§4.7).
    pub overrides: BTreeMap<(u32, u32), Value>,
}

/// One field of a resolved point: where META keeps its normal and bottom values,
/// whether §8 blends it across the transition range, and what META's absence
/// resolves to.
struct Field {
    /// The key the manifest records the resolved value under.
    key: &'static str,
    /// META's key for the field's normal value.
    normal: &'static str,
    /// META's key for the field's bottom value. The layer height has no bottom
    /// variant, so it names its own key: §8 takes it from META or the sector
    /// definition and the bottom range leaves it alone.
    bottom: &'static str,
    /// Whether §8 interpolates the field across the transition range. `light_pwm`
    /// is the one field that does not: it holds the bottom value below
    /// `bottom_layer_count` and switches to the normal value at the first
    /// non-bottom layer.
    blends: bool,
    /// What META's absence resolves to (§4.2 rule 4): `0` for a distance, speed
    /// or duration - a segment or a pause that is not performed - and `255` for
    /// PWM. Never the implementation's usual default.
    absent: i64,
}

/// §8's fields, in the order a resolved point lists them.
const FIELDS: [Field; 14] = [
    Field {
        key: "layer_height_um",
        normal: "layer_height_um",
        bottom: "layer_height_um",
        blends: false,
        absent: 0,
    },
    Field {
        key: "exposure_ms",
        normal: "normal_exposure_ms",
        bottom: "bottom_exposure_ms",
        blends: true,
        absent: 0,
    },
    Field {
        key: "light_pwm",
        normal: "light_pwm",
        bottom: "bottom_light_pwm",
        blends: false,
        absent: 255,
    },
    Field {
        key: "lift_slow_distance_um",
        normal: "lift_slow_distance_um",
        bottom: "bottom_lift_slow_distance_um",
        blends: true,
        absent: 0,
    },
    Field {
        key: "lift_slow_speed_um_min",
        normal: "lift_slow_speed_um_min",
        bottom: "bottom_lift_slow_speed_um_min",
        blends: true,
        absent: 0,
    },
    Field {
        key: "lift_fast_distance_um",
        normal: "lift_fast_distance_um",
        bottom: "bottom_lift_fast_distance_um",
        blends: true,
        absent: 0,
    },
    Field {
        key: "lift_fast_speed_um_min",
        normal: "lift_fast_speed_um_min",
        bottom: "bottom_lift_fast_speed_um_min",
        blends: true,
        absent: 0,
    },
    Field {
        key: "retract_fast_distance_um",
        normal: "retract_fast_distance_um",
        bottom: "bottom_retract_fast_distance_um",
        blends: true,
        absent: 0,
    },
    Field {
        key: "retract_fast_speed_um_min",
        normal: "retract_fast_speed_um_min",
        bottom: "bottom_retract_fast_speed_um_min",
        blends: true,
        absent: 0,
    },
    Field {
        key: "retract_slow_distance_um",
        normal: "retract_slow_distance_um",
        bottom: "bottom_retract_slow_distance_um",
        blends: true,
        absent: 0,
    },
    Field {
        key: "retract_slow_speed_um_min",
        normal: "retract_slow_speed_um_min",
        bottom: "bottom_retract_slow_speed_um_min",
        blends: true,
        absent: 0,
    },
    Field {
        key: "wait_time_before_cure_ms",
        normal: "wait_time_before_cure_ms",
        bottom: "bottom_wait_time_before_cure_ms",
        blends: true,
        absent: 0,
    },
    Field {
        key: "wait_time_after_cure_ms",
        normal: "wait_time_after_cure_ms",
        bottom: "bottom_wait_time_after_cure_ms",
        blends: true,
        absent: 0,
    },
    Field {
        key: "wait_time_after_lift_ms",
        normal: "wait_time_after_lift_ms",
        bottom: "bottom_wait_time_after_lift_ms",
        blends: true,
        absent: 0,
    },
];

/// The values §8 resolves for one `(layer, sector)` point.
pub struct Resolved {
    values: [i64; FIELDS.len()],
}

impl Resolved {
    /// Every field key a resolved point carries, in the order `resolve` fills
    /// them. The point's own `layer` and `sector` are its coordinates rather
    /// than resolved values, and are not among them.
    pub fn keys() -> [&'static str; FIELDS.len()] {
        std::array::from_fn(|index| FIELDS[index].key)
    }

    /// One field's value, by the key the manifest records it under. `None` for a
    /// key §8 does not resolve.
    pub fn get(&self, key: &str) -> Option<i64> {
        FIELDS
            .iter()
            .position(|field| field.key == key)
            .map(|index| self.values[index])
    }
}

/// Resolve one `(layer, sector)` point, as §8 defines it.
///
/// `layer` and `sector` are the point's coordinates; everything else comes from
/// `inputs`, so two readers given the same chunks resolve the same numbers.
pub fn resolve(inputs: &TimingInputs, layer: u32, sector: u32) -> Resolved {
    // 1. META, with the point's sector definition folded over it: a
    // `META.sectors` entry replaces META's value for every field it carries.
    // Sector 0 has no entry by construction - it is primary and carried
    // implicitly (§4.2) - so a single-sector file never folds anything.
    let definition = sector_definition(&inputs.meta, sector);
    let base = |key: &str| -> Option<i64> {
        definition
            .and_then(|sector| integer(sector.get(key)))
            .or_else(|| integer(inputs.meta.get(key)))
    };

    // §8 takes the layer counts from the base and never blends them: the point's
    // sector resolves them from its own definition when it carries them and from
    // META otherwise, field by field, and then uses them verbatim.
    let (bottom_layers, transition) = layer_counts(definition, &inputs.meta);

    let mut resolved = Resolved {
        values: std::array::from_fn(|index| {
            let field = &FIELDS[index];
            // 2 and 3. A bottom value that is absent equals its normal
            // counterpart, and a field absent everywhere resolves to the
            // default rather than to whatever the implementation usually does.
            let normal = base(field.normal).unwrap_or(field.absent);
            let bottom = base(field.bottom).unwrap_or(normal);
            if layer < bottom_layers {
                // 4. Layers below `bottom_layer_count` use the bottom-prefixed
                // values verbatim.
                bottom
            } else if field.blends && layer < bottom_layers.saturating_add(transition) {
                // 4. Inside the transition range the bottom and normal values
                // blend, in exact integer arithmetic rounding half away from
                // zero. `step` runs 1 ..= transition, so the last transition
                // layer is `k = transition + 1` and collapses to `normal`.
                let steps = i128::from(transition) + 1;
                let step = i128::from(layer - bottom_layers) + 1;
                round_half_away_from_zero(
                    i128::from(bottom) * (steps - step) + i128::from(normal) * step,
                    steps,
                ) as i64
            } else {
                normal
            }
        }),
    };

    // 5. LROV. The point's own override set is the one its table record points
    // at, so there is nothing to match and nothing to fold: every field the set
    // carries replaces the value the point holds for it, and nothing it carries
    // is blended.
    if let Some(entry) = inputs.overrides.get(&(layer, sector)) {
        for (index, field) in FIELDS.iter().enumerate() {
            // Within one set a field's normal-form key wins over its own
            // bottom-form key; a field the set does not carry is left alone.
            if let Some(value) =
                integer(entry.get(field.normal)).or_else(|| integer(entry.get(field.bottom)))
            {
                resolved.values[index] = value;
            }
        }
    }

    resolved
}

/// The points the manifest's sample must cover, recomputed from the file.
///
/// Each sector `s` the file names - sector 0, every `sector_id` a `META.sectors`
/// entry carries, and every sector an override set belongs to - supplies its own
/// layers: `{0, 1, bottom_s - 1, bottom_s, bottom_s + transition_s, total - 1}`,
/// each clamped into the file's range, plus the layer of every `(layer, s)` that
/// has an override set, and each of those layers' neighbours that is in range.
/// The sample is the union of `layers_s × {s}` over the sectors, deduplicated.
///
/// The layers are resolved per sector rather than once for the file, because
/// §8's counts are the ones the layer's sector resolves with: `bottom_s` and
/// `transition_s` are the counts its own `META.sectors` entry carries when it
/// carries them and META's otherwise, per field (§4.2). Two sectors can be in
/// different stages on the same layer, so a sample that resolved the ranges once
/// from META would pin the wrong layers for a sector whose definition moves
/// them - and would miss them entirely.
///
/// That covers every branch of §8: bottom, the first transition step, the first
/// fully normal layer, the last layer, every override boundary and its
/// neighbours, and every sector with a definition or an override.
pub fn sampled_points(inputs: &TimingInputs) -> BTreeSet<(u32, u32)> {
    let highest = inputs.total_layers.saturating_sub(1);
    let clamp = |layer: i64| layer.clamp(0, i64::from(highest)) as u32;
    let in_range = |layer: i64| (0..=i64::from(highest)).contains(&layer);

    // The sectors the sample names, before their layers are worked out.
    let mut sectors: BTreeSet<u32> = BTreeSet::from([0]);
    for sector in sector_definitions(&inputs.meta) {
        sectors.extend(sector_id(sector.get("sector_id")));
    }
    sectors.extend(inputs.overrides.keys().map(|(_, sector)| *sector));

    let mut points: BTreeSet<(u32, u32)> = BTreeSet::new();
    for sector in sectors {
        // The definition this sector resolves with - the same one [`resolve`]
        // folds over META for a point in it.
        let definition = sector_definition(&inputs.meta, sector);
        let (bottom, transition) = layer_counts(definition, &inputs.meta);
        let (bottom, transition) = (i64::from(bottom), i64::from(transition));

        let mut layers: BTreeSet<u32> = [0, 1, bottom - 1, bottom, bottom + transition]
            .into_iter()
            .map(clamp)
            .collect();
        layers.insert(highest);
        for (layer, _) in inputs
            .overrides
            .keys()
            .filter(|(_, override_sector)| *override_sector == sector)
        {
            let layer = i64::from(*layer);
            // The neighbours of an override boundary, when the file has them:
            // the sample never names a layer index the file does not.
            layers.extend(
                [layer - 1, layer, layer + 1]
                    .into_iter()
                    .filter(|l| in_range(*l))
                    .map(clamp),
            );
        }

        points.extend(layers.into_iter().map(|layer| (layer, sector)));
    }
    points
}

/// `META.sectors`' entries, in the order META carries them. A `sectors` field
/// that is not an array carries no definitions.
fn sector_definitions(meta: &Value) -> impl Iterator<Item = &Value> {
    meta.get("sectors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// The definition a sector resolves with: the entry META carries for it, or
/// `None` for a sector META does not define - which is sector 0 always, and any
/// other sector that simply takes META's values.
fn sector_definition(meta: &Value, sector: u32) -> Option<&Value> {
    sector_definitions(meta)
        .find(|definition| integer(definition.get("sector_id")) == Some(i64::from(sector)))
}

/// A `sector_id` as the id it names. A value that is not a whole number, or is
/// negative, names no sector at all.
fn sector_id(value: Option<&Value>) -> Option<u32> {
    u32::try_from(integer(value)?).ok()
}

/// The bottom and transition layer counts §8 resolves one sector with: the
/// sector's own definition when it carries them, META's otherwise, per field
/// (§4.2). Neither count is blended, so these are used verbatim.
fn layer_counts(definition: Option<&Value>, meta: &Value) -> (u32, u32) {
    let count_for = |key: &str| {
        count(
            definition
                .and_then(|sector| integer(sector.get(key)))
                .or_else(|| integer(meta.get(key))),
        )
    };
    (
        count_for("bottom_layer_count"),
        count_for("transition_layer_count"),
    )
}

/// A layer count as the number of layers it names. A value that is not a whole
/// number, or is negative, names none.
fn count(value: Option<i64>) -> u32 {
    value
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0)
}

/// A JSON number as the whole number §8 works in. Every field the pipeline
/// resolves is an integer (§4.2), so a value that is not one is not carried and
/// the absent rules apply to it instead.
///
/// Integral floating-point syntax is read as the number it spells rather than
/// rejected: a reader MAY reject `2500.0` (§4.2), but this one is comparing the
/// numbers, not their spelling.
fn integer(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    let number = value.as_f64()?;
    (number.fract() == 0.0 && number >= i64::MIN as f64 && number <= i64::MAX as f64)
        .then_some(number as i64)
}

/// §8's rounding: exact integer division whose remainder rounds half away from
/// zero, so a remainder of exactly half a unit rounds up in magnitude.
fn round_half_away_from_zero(numerator: i128, denominator: i128) -> i128 {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder.abs() * 2 >= denominator {
        quotient + numerator.signum()
    } else {
        quotient
    }
}
