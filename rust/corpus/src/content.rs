//! The content predicates the `META`, `SECT`, `PROF` and `LROV` checks are
//! built from (§4.2, §4.3, §4.7, §11.2).
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

/// §11.2: `layer`, and both `layer_range` bounds, in `[0, total_layers - 1]`.
pub fn lrov_indices_ok(entry: &Value, total_layers: u32) -> bool {
    let Some(fields) = entry.as_object() else {
        return false;
    };
    let highest = f64::from(total_layers) - 1.0;
    let in_range =
        |v: &Value| is_number(v) && v.as_f64().is_some_and(|n| (0.0..=highest).contains(&n));
    if let Some(layer) = fields.get("layer") {
        return in_range(layer);
    }
    fields.get("layer_range").is_some_and(|rng| {
        rng.as_array()
            .is_some_and(|bounds| bounds.len() == 2 && bounds.iter().all(in_range))
    })
}

/// §11.2: `layer_range` is inclusive and `end >= start`.
pub fn lrov_range_ordered(entry: &Value) -> bool {
    let Some(rng) = entry.as_object().and_then(|o| o.get("layer_range")) else {
        return true;
    };
    rng.as_array()
        .filter(|bounds| bounds.len() == 2)
        .and_then(|bounds| Some(number_of(&bounds[0])? <= number_of(&bounds[1])?))
        .unwrap_or(false)
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
