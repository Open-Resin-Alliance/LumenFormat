//! The per-layer settings pipeline ([`spec/11-layer-timing.md`] section 8).
//!
//! Base values come from `META`, a `SECT` chunk overrides them per sector, the
//! bottom and transition ranges blend bottom-prefixed values into normal ones,
//! and the last matching `LROV` entry wins per `(layer, sector)` pair.

use crate::check::Check;
use crate::error::{Error, Result};
use crate::json::{CureCurve, Lrov, LrovEntry, Meta, Sect, Timing, REQUIRED_META_FIELDS};

/// Light PWM when META carries none (`spec/03-chunks.md` section 4.2).
const DEFAULT_LIGHT_PWM: u32 = 255;

/// The concrete timing of one `(layer, sector)` pair.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// Layer thickness in micrometres.
    pub layer_height_um: u32,
    /// Exposure time for this layer, in seconds.
    pub exposure_sec: f64,
    /// Lift, slow segment distance.
    pub lift_slow_distance_um: u32,
    /// Lift, slow segment speed.
    pub lift_slow_speed_um_min: u32,
    /// Lift, fast segment distance.
    pub lift_fast_distance_um: u32,
    /// Lift, fast segment speed.
    pub lift_fast_speed_um_min: u32,
    /// Retract, fast segment distance.
    pub retract_fast_distance_um: u32,
    /// Retract, fast segment speed.
    pub retract_fast_speed_um_min: u32,
    /// Retract, slow segment distance.
    pub retract_slow_distance_um: u32,
    /// Retract, slow segment speed.
    pub retract_slow_speed_um_min: u32,
    /// Pause before curing, in seconds.
    pub wait_time_before_cure_sec: f64,
    /// Pause after curing, in seconds.
    pub wait_time_after_cure_sec: f64,
    /// Pause after the lift, in seconds.
    pub wait_time_after_lift_sec: f64,
    /// Light PWM for this layer.
    pub light_pwm: u32,
    /// Chamber target temperature, if any.
    pub chamber_temperature_c: Option<f64>,
    /// Vat target temperature, if any.
    pub vat_temperature_c: Option<f64>,
    /// The resin working curve, if any.
    pub cure_curve: Option<CureCurve>,
    /// Whether this layer is in the bottom range.
    pub is_bottom: bool,
    /// Whether this layer is in the interpolated transition range.
    pub is_transition: bool,
}

/// [`field_pair`] for a field named in both its normal and its `bottom_` form.
macro_rules! pair {
    ($meta:expr, $sector:expr, $normal:ident, $bottom:ident, $default:expr) => {
        field_pair($meta, $sector, |t| t.$normal, |t| t.$bottom, $default)
    };
}

/// Resolve one layer's timing.
///
/// `sector` is the `SECT` definition for `sector_id`, when one exists; sector 0
/// has no definition by construction.
pub fn resolve(
    meta: &Meta,
    sector: Option<&Sect>,
    lrov: Option<&Lrov>,
    layer: u32,
    sector_id: u32,
) -> Result<Resolved> {
    // The pipeline needs a concrete value for every required META field except
    // the schema version, which `validate` owns and a resolved layer never
    // depends on. Presence can only be read from the parsed `Option`s here.
    let missing: Vec<&str> = REQUIRED_META_FIELDS
        .iter()
        .copied()
        .filter(|name| *name != "meta_version")
        .filter(|name| !meta_carries(meta, name))
        .collect();
    if !missing.is_empty() {
        return Err(Error::new(
            Check::MetaRequiredFields,
            format!("META is missing {}", missing.join(", ")),
        ));
    }

    let timing = &meta.timing;
    // A `SECT` definition describes a non-zero sector, so it only speaks for
    // one; sector 0 has none by construction.
    let sect = match sector_id {
        0 => None,
        _ => sector.map(|definition| &definition.timing),
    };

    // Base values: META, with every field the sector definition carries
    // replacing the META value for that sector.
    let layer_height_um = merged(timing, sect, |t| t.layer_height_um).unwrap_or_default();
    let bottom_layer_count = merged(timing, sect, |t| t.bottom_layer_count).unwrap_or_default();
    let transition_layer_count =
        merged(timing, sect, |t| t.transition_layer_count).unwrap_or_default();
    let light_pwm = merged(timing, sect, |t| t.light_pwm).unwrap_or(DEFAULT_LIGHT_PWM);
    let bottom_light_pwm = merged(timing, sect, |t| t.bottom_light_pwm).unwrap_or(light_pwm);

    // The values the bottom and transition ranges blend, each as a (normal,
    // bottom) pair. An absent optional field resolves to `0`/`0.0`, which the
    // spec renders as a segment that is not performed, or no pause at all.
    let exposure = pair!(timing, sect, normal_exposure_sec, bottom_exposure_sec, 0.0);
    let lift_slow_distance = pair!(
        timing,
        sect,
        lift_slow_distance_um,
        bottom_lift_slow_distance_um,
        0
    );
    let lift_slow_speed = pair!(
        timing,
        sect,
        lift_slow_speed_um_min,
        bottom_lift_slow_speed_um_min,
        0
    );
    let lift_fast_distance = pair!(
        timing,
        sect,
        lift_fast_distance_um,
        bottom_lift_fast_distance_um,
        0
    );
    let lift_fast_speed = pair!(
        timing,
        sect,
        lift_fast_speed_um_min,
        bottom_lift_fast_speed_um_min,
        0
    );
    let retract_fast_distance = pair!(
        timing,
        sect,
        retract_fast_distance_um,
        bottom_retract_fast_distance_um,
        0
    );
    let retract_fast_speed = pair!(
        timing,
        sect,
        retract_fast_speed_um_min,
        bottom_retract_fast_speed_um_min,
        0
    );
    let retract_slow_distance = pair!(
        timing,
        sect,
        retract_slow_distance_um,
        bottom_retract_slow_distance_um,
        0
    );
    let retract_slow_speed = pair!(
        timing,
        sect,
        retract_slow_speed_um_min,
        bottom_retract_slow_speed_um_min,
        0
    );
    let wait_before_cure = pair!(
        timing,
        sect,
        wait_time_before_cure_sec,
        bottom_wait_time_before_cure_sec,
        0.0
    );
    let wait_after_cure = pair!(
        timing,
        sect,
        wait_time_after_cure_sec,
        bottom_wait_time_after_cure_sec,
        0.0
    );
    let wait_after_lift = pair!(
        timing,
        sect,
        wait_time_after_lift_sec,
        bottom_wait_time_after_lift_sec,
        0.0
    );

    // `u64` keeps `bottom + transition` from wrapping on a malformed META.
    let bottom = u64::from(bottom_layer_count);
    let transition = u64::from(transition_layer_count);
    let index = u64::from(layer);
    let stage = if index < bottom {
        Stage::Bottom
    } else if index < bottom + transition {
        // One step into the range is the first blend step, and the first
        // fully-normal layer, `bottom + transition`, is `t = 1`.
        Stage::Transition((index - bottom + 1) as f64 / (transition + 1) as f64)
    } else {
        Stage::Normal
    };

    let mut resolved = Resolved {
        layer_height_um,
        exposure_sec: blend_f64(exposure, stage),
        lift_slow_distance_um: blend_u32(lift_slow_distance, stage),
        lift_slow_speed_um_min: blend_u32(lift_slow_speed, stage),
        lift_fast_distance_um: blend_u32(lift_fast_distance, stage),
        lift_fast_speed_um_min: blend_u32(lift_fast_speed, stage),
        retract_fast_distance_um: blend_u32(retract_fast_distance, stage),
        retract_fast_speed_um_min: blend_u32(retract_fast_speed, stage),
        retract_slow_distance_um: blend_u32(retract_slow_distance, stage),
        retract_slow_speed_um_min: blend_u32(retract_slow_speed, stage),
        wait_time_before_cure_sec: blend_f64(wait_before_cure, stage),
        wait_time_after_cure_sec: blend_f64(wait_after_cure, stage),
        wait_time_after_lift_sec: blend_f64(wait_after_lift, stage),
        // PWM is categorical: it switches at the first non-bottom layer instead
        // of interpolating.
        light_pwm: match stage {
            Stage::Bottom => bottom_light_pwm,
            _ => light_pwm,
        },
        chamber_temperature_c: merged(timing, sect, |t| t.chamber_temperature_c),
        vat_temperature_c: merged(timing, sect, |t| t.vat_temperature_c),
        cure_curve: merged(timing, sect, |t| t.cure_curve),
        is_bottom: matches!(stage, Stage::Bottom),
        is_transition: matches!(stage, Stage::Transition(_)),
    };

    // Every matching entry folds onto the values in file order, so the last one
    // wins per field while fields it leaves out keep what earlier entries set.
    if let Some(lrov) = lrov {
        for entry in &lrov.overrides {
            if matches_entry(entry, layer, sector_id) {
                fold_entry(&mut resolved, &entry.timing);
            }
        }
    }

    Ok(resolved)
}

/// Which range a layer falls in.
#[derive(Clone, Copy)]
enum Stage {
    /// Below `bottom_layer_count`: bottom-prefixed values, verbatim.
    Bottom,
    /// At or beyond `bottom_layer_count + transition_layer_count`: normal values.
    Normal,
    /// Inside the transition range, with its blend factor `t`.
    Transition(f64),
}

/// One field's two forms, with an absent bottom form already folded onto the
/// normal one, which is what makes its interpolation a no-op.
#[derive(Clone, Copy)]
struct Blend<T> {
    /// The normal-layer value.
    normal: T,
    /// The bottom-layer value.
    bottom: T,
}

impl<T: Copy> Blend<T> {
    /// Pair `normal` with `bottom`, defaulting an absent `normal` to `default`
    /// and an absent `bottom` to the resolved normal value.
    fn new(normal: Option<T>, bottom: Option<T>, default: T) -> Self {
        let normal = normal.unwrap_or(default);
        Blend {
            normal,
            bottom: bottom.unwrap_or(normal),
        }
    }
}

/// A META field with the sector override applied.
///
/// `sector` is the definition's timing namespace, or `None` for sector 0.
fn merged<T: Copy>(
    meta: &Timing,
    sector: Option<&Timing>,
    get: impl Fn(&Timing) -> Option<T>,
) -> Option<T> {
    sector.and_then(&get).or_else(|| get(meta))
}

/// One field's `(normal, bottom)` pair, each with the sector override applied.
fn field_pair<T: Copy>(
    meta: &Timing,
    sector: Option<&Timing>,
    normal: impl Fn(&Timing) -> Option<T>,
    bottom: impl Fn(&Timing) -> Option<T>,
    default: T,
) -> Blend<T> {
    Blend::new(
        merged(meta, sector, normal),
        merged(meta, sector, bottom),
        default,
    )
}

/// Whether META carries a value for `name`, one of the fields the pipeline
/// needs ([`REQUIRED_META_FIELDS`] without `meta_version`).
///
/// [`resolve`] only receives the parsed struct, so unlike `validate`, which
/// reads the raw JSON object, it has nothing but the `Option`s to go on.
fn meta_carries(meta: &Meta, name: &str) -> bool {
    let timing = &meta.timing;
    match name {
        "normal_exposure_sec" => timing.normal_exposure_sec.is_some(),
        "bottom_exposure_sec" => timing.bottom_exposure_sec.is_some(),
        "bottom_layer_count" => timing.bottom_layer_count.is_some(),
        "transition_layer_count" => timing.transition_layer_count.is_some(),
        "layer_height_um" => timing.layer_height_um.is_some(),
        "lift_slow_distance_um" => timing.lift_slow_distance_um.is_some(),
        "lift_slow_speed_um_min" => timing.lift_slow_speed_um_min.is_some(),
        "retract_fast_distance_um" => timing.retract_fast_distance_um.is_some(),
        "retract_fast_speed_um_min" => timing.retract_fast_speed_um_min.is_some(),
        _ => false,
    }
}

/// An integer field at `stage`: verbatim at either end, rounded in between.
fn blend_u32(field: Blend<u32>, stage: Stage) -> u32 {
    match stage {
        Stage::Bottom => field.bottom,
        Stage::Normal => field.normal,
        Stage::Transition(t) => {
            let bottom = f64::from(field.bottom);
            let normal = f64::from(field.normal);
            let value = bottom + t * (normal - bottom);
            // `round` breaks ties away from zero, as the spec asks, and the
            // value lies between two `u32`s, so the cast cannot saturate.
            value.round() as u32
        }
    }
}

/// A floating-point field at `stage`: verbatim at either end, blended between.
fn blend_f64(field: Blend<f64>, stage: Stage) -> f64 {
    match stage {
        Stage::Bottom => field.bottom,
        Stage::Normal => field.normal,
        Stage::Transition(t) => field.bottom + t * (field.normal - field.bottom),
    }
}

/// Whether an `LROV` entry targets `(layer, sector_id)`.
///
/// An entry matches by single layer or by inclusive range, and one without a
/// `sector_id` targets every sector.
fn matches_entry(entry: &LrovEntry, layer: u32, sector_id: u32) -> bool {
    if entry.sector_id.is_some_and(|target| target != sector_id) {
        return false;
    }
    let by_layer = entry.layer == Some(layer);
    let by_range = entry
        .layer_range
        .is_some_and(|[start, end]| start <= layer && layer <= end);
    by_layer || by_range
}

/// Fold one matching `LROV` entry onto the values resolved for its layer.
///
/// An entry replaces only the fields it carries, so a later entry that leaves a
/// field out never clears an earlier entry's value for it. When an entry names
/// a field in both its normal and its `bottom_` form, the normal one wins: an
/// `LROV` entry overrides the layer's single resolved value.
fn fold_entry(resolved: &mut Resolved, over: &Timing) {
    if let Some(value) = over.layer_height_um {
        resolved.layer_height_um = value;
    }
    if let Some(value) = over.normal_exposure_sec.or(over.bottom_exposure_sec) {
        resolved.exposure_sec = value;
    }
    if let Some(value) = over
        .lift_slow_distance_um
        .or(over.bottom_lift_slow_distance_um)
    {
        resolved.lift_slow_distance_um = value;
    }
    if let Some(value) = over
        .lift_slow_speed_um_min
        .or(over.bottom_lift_slow_speed_um_min)
    {
        resolved.lift_slow_speed_um_min = value;
    }
    if let Some(value) = over
        .lift_fast_distance_um
        .or(over.bottom_lift_fast_distance_um)
    {
        resolved.lift_fast_distance_um = value;
    }
    if let Some(value) = over
        .lift_fast_speed_um_min
        .or(over.bottom_lift_fast_speed_um_min)
    {
        resolved.lift_fast_speed_um_min = value;
    }
    if let Some(value) = over
        .retract_fast_distance_um
        .or(over.bottom_retract_fast_distance_um)
    {
        resolved.retract_fast_distance_um = value;
    }
    if let Some(value) = over
        .retract_fast_speed_um_min
        .or(over.bottom_retract_fast_speed_um_min)
    {
        resolved.retract_fast_speed_um_min = value;
    }
    if let Some(value) = over
        .retract_slow_distance_um
        .or(over.bottom_retract_slow_distance_um)
    {
        resolved.retract_slow_distance_um = value;
    }
    if let Some(value) = over
        .retract_slow_speed_um_min
        .or(over.bottom_retract_slow_speed_um_min)
    {
        resolved.retract_slow_speed_um_min = value;
    }
    if let Some(value) = over
        .wait_time_before_cure_sec
        .or(over.bottom_wait_time_before_cure_sec)
    {
        resolved.wait_time_before_cure_sec = value;
    }
    if let Some(value) = over
        .wait_time_after_cure_sec
        .or(over.bottom_wait_time_after_cure_sec)
    {
        resolved.wait_time_after_cure_sec = value;
    }
    if let Some(value) = over
        .wait_time_after_lift_sec
        .or(over.bottom_wait_time_after_lift_sec)
    {
        resolved.wait_time_after_lift_sec = value;
    }
    if let Some(value) = over.light_pwm.or(over.bottom_light_pwm) {
        resolved.light_pwm = value;
    }
    if let Some(value) = over.chamber_temperature_c {
        resolved.chamber_temperature_c = Some(value);
    }
    if let Some(value) = over.vat_temperature_c {
        resolved.vat_temperature_c = Some(value);
    }
    if let Some(value) = over.cure_curve {
        resolved.cure_curve = Some(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// META with every required field, the optional four-segment motion, and the
    /// bottom counts the acceptance case names.
    fn meta() -> Meta {
        Meta {
            meta_version: Some(1),
            timing: Timing {
                layer_height_um: Some(50),
                normal_exposure_sec: Some(2.5),
                bottom_exposure_sec: Some(30.0),
                bottom_layer_count: Some(4),
                transition_layer_count: Some(8),
                lift_slow_distance_um: Some(5000),
                lift_slow_speed_um_min: Some(65000),
                lift_fast_distance_um: Some(3000),
                lift_fast_speed_um_min: Some(180000),
                retract_fast_distance_um: Some(5000),
                retract_fast_speed_um_min: Some(150000),
                retract_slow_distance_um: Some(3000),
                retract_slow_speed_um_min: Some(180000),
                wait_time_before_cure_sec: Some(1.0),
                wait_time_after_cure_sec: Some(0.0),
                wait_time_after_lift_sec: Some(0.5),
                light_pwm: Some(255),
                ..Timing::default()
            },
            ..Meta::default()
        }
    }

    /// Sector 0's resolution, which is what most cases look at.
    fn at(meta: &Meta, layer: u32) -> Resolved {
        resolve(meta, None, None, layer, 0).unwrap()
    }

    #[test]
    fn exposure_blends_bottom_transition_and_normal() {
        let meta = meta();

        assert_eq!(at(&meta, 0).exposure_sec, 30.0);
        assert_eq!(at(&meta, 3).exposure_sec, 30.0);
        assert!((at(&meta, 4).exposure_sec - (30.0 + (1.0 / 9.0) * (2.5 - 30.0))).abs() < 1e-9);
        assert!((at(&meta, 11).exposure_sec - (30.0 + (8.0 / 9.0) * (2.5 - 30.0))).abs() < 1e-9);
        assert_eq!(at(&meta, 12).exposure_sec, 2.5);

        assert_eq!(
            (at(&meta, 0).is_bottom, at(&meta, 0).is_transition),
            (true, false)
        );
        assert_eq!(
            (at(&meta, 3).is_bottom, at(&meta, 3).is_transition),
            (true, false)
        );
        assert_eq!(
            (at(&meta, 4).is_bottom, at(&meta, 4).is_transition),
            (false, true)
        );
        assert_eq!(
            (at(&meta, 11).is_bottom, at(&meta, 11).is_transition),
            (false, true)
        );
        assert_eq!(
            (at(&meta, 12).is_bottom, at(&meta, 12).is_transition),
            (false, false)
        );
        assert_eq!(
            (at(&meta, 400).is_bottom, at(&meta, 400).is_transition),
            (false, false)
        );
    }

    #[test]
    fn wait_times_interpolate_between_their_two_forms() {
        let mut meta = meta();
        meta.timing.bottom_wait_time_before_cure_sec = Some(10.0);

        assert_eq!(at(&meta, 0).wait_time_before_cure_sec, 10.0);
        assert!(
            (at(&meta, 4).wait_time_before_cure_sec - (10.0 + (1.0 / 9.0) * (1.0 - 10.0))).abs()
                < 1e-9
        );
        assert_eq!(at(&meta, 12).wait_time_before_cure_sec, 1.0);
        // A wait with no bottom form holds its normal value throughout.
        assert_eq!(at(&meta, 0).wait_time_after_lift_sec, 0.5);
        assert_eq!(at(&meta, 5).wait_time_after_lift_sec, 0.5);
    }

    #[test]
    fn absent_bottom_form_inherits_its_normal_value() {
        let meta = meta();
        // No `bottom_lift_fast_distance_um` in META, so a bottom layer lifts the
        // same as a normal one.
        assert_eq!(at(&meta, 0).lift_fast_distance_um, 3000);
        assert_eq!(at(&meta, 6).lift_fast_distance_um, 3000);
        assert_eq!(at(&meta, 40).lift_fast_distance_um, 3000);

        // An optional segment that is absent altogether is not performed.
        let mut without = meta.clone();
        without.timing.lift_fast_distance_um = None;
        assert_eq!(at(&without, 40).lift_fast_distance_um, 0);
    }

    #[test]
    fn integer_motion_interpolates_and_rounds_away_from_zero() {
        let mut meta = meta();
        meta.timing.bottom_lift_slow_distance_um = Some(6000);

        assert_eq!(at(&meta, 0).lift_slow_distance_um, 6000);
        // 6000 + (1/9)(5000 - 6000) = 5888.88.. -> 5889
        assert_eq!(at(&meta, 4).lift_slow_distance_um, 5889);
        assert_eq!(at(&meta, 12).lift_slow_distance_um, 5000);

        // With a one-layer transition the factor is exactly 1/2, which makes
        // 5001 + 0.5 * (5000 - 5001) = 5000.5 a tie to break.
        let mut half = meta.clone();
        half.timing.bottom_layer_count = Some(1);
        half.timing.transition_layer_count = Some(1);
        half.timing.lift_slow_distance_um = Some(5000);
        half.timing.bottom_lift_slow_distance_um = Some(5001);
        assert_eq!(at(&half, 1).lift_slow_distance_um, 5001);
    }

    #[test]
    fn light_pwm_switches_at_the_bottom_boundary_without_interpolating() {
        let mut meta = meta();
        meta.timing.bottom_light_pwm = Some(200);

        assert_eq!(at(&meta, 3).light_pwm, 200);
        // The first non-bottom layer, even a transition one, takes the normal
        // value: the boundary is `bottom_layer_count`, not the end of blending.
        assert_eq!(at(&meta, 4).light_pwm, 255);

        // An absent bottom PWM falls back to the normal one.
        let mut no_bottom_pwm = meta.clone();
        no_bottom_pwm.timing.bottom_light_pwm = None;
        no_bottom_pwm.timing.light_pwm = Some(180);
        assert_eq!(at(&no_bottom_pwm, 0).light_pwm, 180);
        assert_eq!(at(&no_bottom_pwm, 4).light_pwm, 180);

        // An absent normal PWM is the spec's default of 255.
        let mut no_pwm = meta.clone();
        no_pwm.timing.light_pwm = None;
        no_pwm.timing.bottom_light_pwm = None;
        assert_eq!(at(&no_pwm, 0).light_pwm, 255);
        assert_eq!(at(&no_pwm, 40).light_pwm, 255);
    }

    #[test]
    fn sect_overrides_its_own_sector_only() {
        let meta = meta();
        let sector = Sect {
            sector_id: 1,
            timing: Timing {
                normal_exposure_sec: Some(3.0),
                bottom_exposure_sec: Some(35.0),
                ..Timing::default()
            },
            ..Sect::default()
        };

        // Sector 0 keeps META even when a definition is offered.
        assert_eq!(
            resolve(&meta, Some(&sector), None, 0, 0)
                .unwrap()
                .exposure_sec,
            30.0
        );
        assert_eq!(
            resolve(&meta, Some(&sector), None, 12, 0)
                .unwrap()
                .exposure_sec,
            2.5
        );

        // Sector 1 blends the sector's own pair.
        assert_eq!(
            resolve(&meta, Some(&sector), None, 0, 1)
                .unwrap()
                .exposure_sec,
            35.0
        );
        assert_eq!(
            resolve(&meta, Some(&sector), None, 12, 1)
                .unwrap()
                .exposure_sec,
            3.0
        );

        // A field the definition leaves out still comes from META...
        assert_eq!(
            resolve(&meta, Some(&sector), None, 12, 1)
                .unwrap()
                .lift_slow_distance_um,
            5000
        );
        // ...for a sector with no definition at all, as well.
        assert_eq!(resolve(&meta, None, None, 12, 1).unwrap().exposure_sec, 2.5);

        // The definition's own layer counts move the ranges for its sector.
        let sector = Sect {
            sector_id: 1,
            timing: Timing {
                bottom_layer_count: Some(6),
                transition_layer_count: Some(0),
                ..Timing::default()
            },
            ..Sect::default()
        };
        assert!(resolve(&meta, Some(&sector), None, 5, 1).unwrap().is_bottom);
        assert!(
            resolve(&meta, Some(&sector), None, 5, 0)
                .unwrap()
                .is_transition
        );
    }

    #[test]
    fn temperatures_and_cure_curve_come_from_meta_or_sect_unblended() {
        let mut meta = meta();
        meta.timing.chamber_temperature_c = Some(30.0);
        meta.timing.cure_curve = Some(CureCurve {
            dp_um: 120.0,
            ec_mj_cm2: 7.5,
            e0_mj_cm2: 3.0,
        });

        let resolved = at(&meta, 0);
        assert_eq!(resolved.chamber_temperature_c, Some(30.0));
        assert_eq!(resolved.vat_temperature_c, None);
        assert_eq!(
            resolved.cure_curve,
            Some(CureCurve {
                dp_um: 120.0,
                ec_mj_cm2: 7.5,
                e0_mj_cm2: 3.0,
            })
        );

        let sector = Sect {
            sector_id: 1,
            timing: Timing {
                chamber_temperature_c: Some(40.0),
                ..Timing::default()
            },
            ..Sect::default()
        };
        let for_sector_1 = resolve(&meta, Some(&sector), None, 0, 1).unwrap();
        assert_eq!(for_sector_1.chamber_temperature_c, Some(40.0));
        assert_eq!(for_sector_1.vat_temperature_c, None);
        assert_eq!(for_sector_1.cure_curve.unwrap().dp_um, 120.0);
        assert_eq!(at(&meta, 0).chamber_temperature_c, Some(30.0));
    }

    #[test]
    fn lrov_folds_matching_entries_in_order() {
        let meta = meta();
        let lrov = Lrov {
            overrides: vec![
                LrovEntry {
                    layer: Some(12),
                    timing: Timing {
                        normal_exposure_sec: Some(9.0),
                        lift_slow_distance_um: Some(7000),
                        ..Timing::default()
                    },
                    ..LrovEntry::default()
                },
                LrovEntry {
                    layer_range: Some([10, 15]),
                    timing: Timing {
                        normal_exposure_sec: Some(4.0),
                        ..Timing::default()
                    },
                    ..LrovEntry::default()
                },
            ],
        };

        let resolved = resolve(&meta, None, Some(&lrov), 12, 0).unwrap();
        // The later entry wins for the field both entries carry...
        assert_eq!(resolved.exposure_sec, 4.0);
        // ...while the field only the earlier one carries still stands.
        assert_eq!(resolved.lift_slow_distance_um, 7000);

        // Layers no entry matches keep the blended defaults.
        assert_eq!(
            resolve(&meta, None, Some(&lrov), 16, 0)
                .unwrap()
                .exposure_sec,
            2.5
        );
        assert_eq!(
            resolve(&meta, None, Some(&lrov), 11, 0)
                .unwrap()
                .exposure_sec,
            4.0
        );
    }

    #[test]
    fn lrov_sector_scope_limits_an_entry() {
        let meta = meta();
        let lrov = Lrov {
            overrides: vec![LrovEntry {
                layer: Some(12),
                sector_id: Some(1),
                timing: Timing {
                    normal_exposure_sec: Some(8.0),
                    ..Timing::default()
                },
                ..LrovEntry::default()
            }],
        };

        assert_eq!(
            resolve(&meta, None, Some(&lrov), 12, 0)
                .unwrap()
                .exposure_sec,
            2.5
        );
        assert_eq!(
            resolve(&meta, None, Some(&lrov), 12, 1)
                .unwrap()
                .exposure_sec,
            8.0
        );

        // An entry without a sector applies to every sector.
        let every_sector = Lrov {
            overrides: vec![LrovEntry {
                layer: Some(12),
                timing: Timing {
                    normal_exposure_sec: Some(6.0),
                    ..Timing::default()
                },
                ..LrovEntry::default()
            }],
        };
        assert_eq!(
            resolve(&meta, None, Some(&every_sector), 12, 0)
                .unwrap()
                .exposure_sec,
            6.0
        );
        assert_eq!(
            resolve(&meta, None, Some(&every_sector), 12, 1)
                .unwrap()
                .exposure_sec,
            6.0
        );
    }

    #[test]
    fn lrov_overrides_pwm_and_optional_motion() {
        let meta = meta();
        let lrov = Lrov {
            overrides: vec![LrovEntry {
                layer_range: Some([0, 2]),
                timing: Timing {
                    light_pwm: Some(120),
                    bottom_light_pwm: Some(130),
                    lift_fast_distance_um: Some(2500),
                    chamber_temperature_c: Some(35.0),
                    ..Timing::default()
                },
                ..LrovEntry::default()
            }],
        };

        let resolved = resolve(&meta, None, Some(&lrov), 1, 0).unwrap();
        assert_eq!(resolved.light_pwm, 120);
        assert_eq!(resolved.lift_fast_distance_um, 2500);
        assert_eq!(resolved.chamber_temperature_c, Some(35.0));
        assert_eq!(
            resolve(&meta, None, Some(&lrov), 3, 0).unwrap().light_pwm,
            255
        );
    }

    #[test]
    fn missing_required_meta_field_is_reported() {
        let mut meta = meta();
        meta.timing.bottom_exposure_sec = None;
        meta.timing.lift_slow_speed_um_min = None;

        let err = resolve(&meta, None, None, 0, 0).unwrap_err();
        assert_eq!(err.check(), Check::MetaRequiredFields);
        let detail = err.detail();
        assert!(detail.contains("bottom_exposure_sec"), "{detail}");
        assert!(detail.contains("lift_slow_speed_um_min"), "{detail}");
        assert!(!detail.contains("normal_exposure_sec"), "{detail}");

        // The schema version is `validate`'s business, not the pipeline's.
        let mut no_version = meta.clone();
        no_version.meta_version = None;
        no_version.timing.bottom_exposure_sec = Some(30.0);
        no_version.timing.lift_slow_speed_um_min = Some(65000);
        assert!(resolve(&no_version, None, None, 0, 0).is_ok());
    }
}
