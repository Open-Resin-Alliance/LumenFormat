//! §8: the per-layer settings pipeline, as this reader resolves it.
//!
//! The manifest records, for a sample of `(layer, sector)` points, the numbers a
//! conforming reader must resolve for them, so a third-party implementation has
//! something to agree with. This module is the validator's own reading of that
//! pipeline - written from §8, §4.2 and §4.6 rather than shared with the
//! generator - so agreement between the two is evidence about the specification
//! rather than one implementation restated.
//!
//! Nothing here reads a file. [`TimingInputs`] carries the `META`, `SECT` and
//! `LROV` objects the reader decrypted and parsed, and [`resolve`] turns them
//! plus a point into the values §8 defines for it. [`sampled_points`] is the
//! other half of the same reading: which points the manifest is expected to
//! record, recomputed from the file's own numbers.

use std::collections::BTreeSet;

use serde_json::Value;

/// Everything §8 resolves a point from - and, for [`sampled_points`], everything
/// the sample of points is bounded by: the chunks the reader parsed, standing in
/// for the file they came from.
pub struct TimingInputs {
    /// `HDR`'s layer count (§4.1), which bounds every sampled layer.
    pub total_layers: u32,
    /// `META`, the base for every field (§4.2).
    pub meta: Value,
    /// Every `SECT` definition, in file order (§4.5).
    pub sects: Vec<Value>,
    /// The `LROV` body, when the file carries one (§4.6). A file carries at most
    /// one, and readers use the first.
    pub lrov: Option<Value>,
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
    // 1. META, with the point's sector definition folded over it: a `SECT` entry
    // replaces META's value for every field it carries. Sector 0 has no
    // definition by construction (§4.5 reserves it), so a single-sector file
    // never folds anything.
    let definition = inputs
        .sects
        .iter()
        .find(|sect| integer(sect.get("sector_id")) == Some(i64::from(sector)));
    let base = |key: &str| -> Option<i64> {
        definition
            .and_then(|sect| integer(sect.get(key)))
            .or_else(|| integer(inputs.meta.get(key)))
    };

    // §8 takes the layer counts from the base and never blends them: a file that
    // carries `bottom_layer_count` and `transition_layer_count` in META uses
    // those, verbatim.
    let bottom_layers = count(base("bottom_layer_count"));
    let transition = count(base("transition_layer_count"));

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

    // 5. LROV. Matching entries fold over the resolved values in file order, and
    // every field a matching entry carries replaces the value the point holds
    // for it: an entry is a sparse set of overrides, not a replacement for the
    // entries before it. Nothing an entry carries is blended.
    for entry in overrides(inputs).filter(|entry| targets(entry, layer, sector)) {
        for (index, field) in FIELDS.iter().enumerate() {
            // Within one entry a field's normal-form key wins over its own
            // bottom-form key; a field the entry does not carry is left alone.
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
/// The layers are `{0, 1, bottom - 1, bottom, bottom + transition, total - 1}`,
/// each clamped into the file's range, plus every layer an `LROV` entry names -
/// its `layer`, or both ends of its inclusive `layer_range` - and each of those
/// neighbours that is in range. The sectors are `{0}` plus every `sector_id` a
/// `SECT` defines or an `LROV` entry names. The sample is their product,
/// deduplicated by construction.
///
/// That covers every branch of §8: bottom, the first transition step, the first
/// fully normal layer, the last layer, every override boundary and its
/// neighbours, and every sector with a definition or an override.
///
/// `bottom_layer_count` and `transition_layer_count` are META's here, which is
/// where §8 takes them from; [`resolve`] reads them from META with the point's
/// sector definition folded over it (§4.5), and no vector in the corpus defines
/// a layer count per sector.
pub fn sampled_points(inputs: &TimingInputs) -> BTreeSet<(u32, u32)> {
    let highest = inputs.total_layers.saturating_sub(1);
    let clamp = |layer: i64| layer.clamp(0, i64::from(highest)) as u32;
    let in_range = |layer: i64| (0..=i64::from(highest)).contains(&layer);

    let bottom = i64::from(meta_count(&inputs.meta, "bottom_layer_count"));
    let transition = i64::from(meta_count(&inputs.meta, "transition_layer_count"));

    let mut layers: BTreeSet<u32> = [0, 1, bottom - 1, bottom, bottom + transition]
        .into_iter()
        .map(clamp)
        .collect();
    layers.insert(highest);
    let mut sectors: BTreeSet<u32> = BTreeSet::from([0]);
    for sect in &inputs.sects {
        sectors.extend(sector_id(sect.get("sector_id")));
    }

    for entry in overrides(inputs) {
        for layer in named_layers(entry) {
            let layer = i64::from(clamp(layer));
            // The neighbours of an override boundary, when the file has them:
            // the sample never names a layer index the file does not.
            layers.extend(
                [layer - 1, layer, layer + 1]
                    .into_iter()
                    .filter(|l| in_range(*l))
                    .map(clamp),
            );
        }
        sectors.extend(sector_id(entry.get("sector_id")));
    }

    layers
        .iter()
        .flat_map(|layer| sectors.iter().map(move |sector| (*layer, *sector)))
        .collect()
}

/// The layers an `LROV` entry names: its `layer`, or both ends of its inclusive
/// `layer_range`. An entry that carries neither names none.
fn named_layers(entry: &Value) -> Vec<i64> {
    if let Some(layer) = integer(entry.get("layer")) {
        return vec![layer];
    }
    let Some(range) = entry.get("layer_range").and_then(Value::as_array) else {
        return Vec::new();
    };
    match (
        range.first().and_then(|end| integer(Some(end))),
        range.get(1).and_then(|end| integer(Some(end))),
    ) {
        (Some(start), Some(end)) => vec![start, end],
        _ => Vec::new(),
    }
}

/// A `sector_id` as the id it names. A value that is not a whole number, or is
/// negative, names no sector at all.
fn sector_id(value: Option<&Value>) -> Option<u32> {
    u32::try_from(integer(value)?).ok()
}

/// A layer count META carries, as the number of layers it names.
fn meta_count(meta: &Value, key: &str) -> u32 {
    count(integer(meta.get(key)))
}

/// The `LROV` body's override entries, in the order the file carries them.
fn overrides(inputs: &TimingInputs) -> impl Iterator<Item = &Value> {
    inputs
        .lrov
        .as_ref()
        .and_then(|body| body.get("overrides"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// Whether an `LROV` entry targets a point (§4.6): its `layer` or its inclusive
/// `layer_range`, and - when it carries one - its `sector_id`.
fn targets(entry: &Value, layer: u32, sector: u32) -> bool {
    let layer = i64::from(layer);
    let named = integer(entry.get("layer")) == Some(layer);
    let within_range = entry
        .get("layer_range")
        .and_then(Value::as_array)
        .is_some_and(|range| match (range.first(), range.get(1)) {
            (Some(start), Some(end)) => match (integer(Some(start)), integer(Some(end))) {
                (Some(start), Some(end)) => start <= layer && layer <= end,
                _ => false,
            },
            _ => false,
        });
    let sector_matches = match entry.get("sector_id") {
        None => true,
        Some(id) => integer(Some(id)) == Some(i64::from(sector)),
    };
    (named || within_range) && sector_matches
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
