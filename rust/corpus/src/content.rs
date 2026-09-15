//! The content predicates the `META`, `PROF`, `LROV` and `PREV` checks are
//! built from (§4.2, §4.3, §4.6, §4.7, §11.2).
//!
//! Each one answers a question the specification asks of a decoded chunk, so
//! they are kept apart from the reader that walks the container: the checks
//! read as the rules they enforce, and the JSON type rules ("a number, but not
//! a bool") are stated once.

use serde_json::Value;

use crate::bytes::be_u32_at;

pub const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];

/// A JSON number, as opposed to a bool (which is an int in the Python).
pub fn is_number(v: &Value) -> bool {
    v.as_f64().is_some() && !v.is_boolean()
}

/// A JSON integer, as opposed to a number with a fractional part.
pub fn is_int(v: &Value) -> bool {
    !v.is_boolean() && (v.as_i64().is_some() || v.as_u64().is_some())
}

/// Python truthiness, for the predicates that test a field rather than a type.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64().map_or_else(
            || {
                n.as_u64()
                    .map_or_else(|| n.as_f64().is_some_and(|f| f != 0.0), |u| u != 0)
            },
            |i| i != 0,
        ),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `==` over the JSON scalars LUMEN stores in identity fields: numbers
/// compare by value, so an integer and the same float are one value.
pub fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (number_of(a), number_of(b)) {
        (Some(x), Some(y)) => x == y,
        (None, None) => match (a, b) {
            (Value::String(x), Value::String(y)) => x == y,
            (Value::Null, Value::Null) => true,
            (Value::Bool(x), Value::Bool(y)) => x == y,
            _ => false,
        },
        _ => false,
    }
}

/// Python's `>=` on a JSON value: a bool counts as the number it is, and
/// anything that is not a number is not above the bound.
pub fn number_at_least(value: &Value, bound: f64) -> bool {
    number_of(value).is_some_and(|number| number >= bound)
}

fn number_of(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ if v.is_number() => v.as_f64(),
        _ => None,
    }
}

/// §4.2: every duration is a JSON integer.
///
/// The `*_ms` fields count whole milliseconds; META's estimated print time is
/// the one duration in whole seconds, since an estimate spanning hours has no
/// millisecond precision to report. Either way a value with a fractional part
/// is a type violation rather than a precision problem, which is why a loose
/// reader rejects it too (§11.5). Whether a chunk carries any timing field at
/// all is the chunk's own business: a non-object is left to the shape checks.
pub fn time_fields_integer(obj: &Value) -> bool {
    let Some(fields) = obj.as_object() else {
        return true;
    };
    fields.iter().all(|(name, value)| {
        let is_duration = name.ends_with("_ms") || name == "estimated_print_time_sec";
        !is_duration || is_int(value)
    })
}

/// §11.2: absent, or a non-empty array of objects each with a non-empty name.
pub fn materials_shape_ok(mats: Option<&Value>) -> bool {
    match mats {
        None => true,
        Some(Value::Array(items)) => {
            !items.is_empty()
                && items.iter().all(|m| {
                    m.as_object()
                        .and_then(|o| o.get("name"))
                        .is_some_and(truthy)
                })
        }
        Some(_) => false,
    }
}

/// §4.2: absent, or an array of objects each carrying a `sector_id` that is an
/// integer `>= 1` - sector 0 is primary and is carried implicitly - with no two
/// entries naming the same sector.
///
/// The ids compare by value, as the old `SECT` ids did: `1` and `1.0` name one
/// sector, and two entries that name it are a defect rather than a duplicate
/// definition.
pub fn sectors_shape_ok(sectors: Option<&Value>) -> bool {
    let Some(sectors) = sectors else {
        return true;
    };
    let Value::Array(items) = sectors else {
        return false;
    };
    let ids: Vec<&Value> = items
        .iter()
        .map(|sector| {
            sector
                .as_object()
                .and_then(|fields| fields.get("sector_id"))
        })
        .collect::<Option<Vec<_>>>()
        .into_iter()
        .flatten()
        .collect();
    // Every entry carries an id, of the shape §4.2 gives it.
    if ids.len() != items.len() || !ids.iter().all(|id| is_int(id) && number_at_least(id, 1.0)) {
        return false;
    }
    (0..ids.len()).all(|i| (i + 1..ids.len()).all(|j| !scalar_eq(ids[i], ids[j])))
}

/// §4.2: every duration a sector definition carries is a JSON integer, so that
/// `meta.time_integer` covers META's whole namespace - the durations `SECT` used
/// to hold are META's now. A `sectors` field that is not an array has no
/// durations to judge; its shape is a separate rule.
pub fn sectors_time_integer(sectors: Option<&Value>) -> bool {
    match sectors {
        Some(Value::Array(items)) => items.iter().all(time_fields_integer),
        _ => true,
    }
}

/// §11.2: a sector definition's `material_index`, when it carries one, indexes
/// the materials array - which must therefore exist.
pub fn sector_material_index_ok(sectors: Option<&Value>, materials: Option<&Value>) -> bool {
    let Some(Value::Array(items)) = sectors else {
        return true;
    };
    items.iter().all(|sector| {
        let Some(index) = sector
            .as_object()
            .and_then(|fields| fields.get("material_index"))
        else {
            return true;
        };
        materials
            .and_then(container_len)
            .is_some_and(|length| index_in_range(index, length))
    })
}

/// Python's `len()`, for the containers that have one. A materials field that
/// is not one of them cannot be indexed into at all.
fn container_len(value: &Value) -> Option<usize> {
    match value {
        Value::Array(items) => Some(items.len()),
        Value::String(text) => Some(text.chars().count()),
        Value::Object(fields) => Some(fields.len()),
        _ => None,
    }
}

/// Python's `0 <= index < length`: a bool counts as the number it is, and
/// anything else that is not a number is not an index.
fn index_in_range(index: &Value, length: usize) -> bool {
    let number = match index {
        Value::Bool(true) => 1.0,
        Value::Bool(false) => 0.0,
        _ => match index.as_f64() {
            Some(number) => number,
            None => return false,
        },
    };
    number >= 0.0 && number < length as f64
}

/// A JSON number above zero, as opposed to a bool (which is an int in the
/// Python).
pub fn is_positive_number(value: &Value) -> bool {
    is_number(value) && value.as_f64().is_some_and(|n| n > 0.0)
}

/// §4.2 / §11.2: a working curve, where one is carried, is usable - a
/// penetration depth and a critical exposure above zero, and a base energy that
/// is not negative. META and PROF carry the same object under the same rule.
pub fn cure_curve_ok(curve: Option<&Value>) -> bool {
    curve.is_none_or(|curve| {
        curve.get("dp_um").is_some_and(is_positive_number)
            && curve.get("ec_mj_cm2").is_some_and(is_positive_number)
            && curve
                .get("e0_mj_cm2")
                .is_some_and(|e0| is_number(e0) && number_at_least(e0, 0.0))
    })
}

/// §4.2 / §11.2: a temperature target META carries is inside the range a printer
/// can be asked for. `null` is the printer's own default - unheated - rather
/// than a temperature, so it is not range-checked.
pub fn temperature_range_ok(meta: &Value) -> bool {
    ["chamber_temperature_c", "vat_temperature_c"]
        .iter()
        .all(|key| match meta.get(key) {
            None | Some(Value::Null) => true,
            Some(value) => {
                is_number(value) && value.as_f64().is_some_and(|t| (0.0..=120.0).contains(&t))
            }
        })
}

/// §4.7 / §11.2 (strict): PNG signature followed by a well-formed IHDR.
///
/// Only the leading IHDR is inspected: the signature must be present, its
/// declared length must be at least the 13 bytes of the fixed IHDR layout, and
/// its width and height must both be non-zero.
pub fn png_header_ok(blob: &[u8]) -> bool {
    if blob.len() < 24 || !blob.starts_with(&PNG_SIGNATURE) {
        return false;
    }
    let Some(ihdr_len) = be_u32_at(blob, 8) else {
        return false;
    };
    if ihdr_len < 13 || &blob[12..16] != b"IHDR" {
        return false;
    }
    let width = be_u32_at(blob, 16).unwrap_or(0);
    let height = be_u32_at(blob, 20).unwrap_or(0);
    width > 0 && height > 0
}

/// A UUID in the 8-4-4-4-12 form §11.2 asks for.
pub fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            *b == b'-'
        } else {
            b.is_ascii_hexdigit()
        }
    })
}
