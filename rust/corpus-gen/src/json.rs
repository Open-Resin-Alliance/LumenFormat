//! JSON payloads, in the shape the specification's corpus stores them.
//!
//! Every JSON payload in a `.lumen` file is compressed into it, so its text is part
//! of the file's bytes: the corpus was published as `json.dumps(obj, indent=2,
//! sort_keys=True)`, and this module reproduces that text exactly. Two-space
//! indent, sorted keys, `": "` separators, empty containers as `{}` and `[]`, no
//! trailing newline, integers and floats kept distinct (`50` is not `50.0`).

use serde_json::{Map, Value};

/// An object with its keys sorted, like Python's `sort_keys=True`.
///
/// Sorting here rather than relying on the map implementation keeps the output
/// order a property of this function, so it stays correct whichever map
/// `serde_json` was built with.
pub fn obj(entries: Vec<(&str, Value)>) -> Value {
    let mut entries = entries;
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

/// Overlay `entries` onto an object, the way Python's `dict.update` does.
pub fn merge(base: Value, entries: &[(&str, Value)]) -> Value {
    let Value::Object(mut map) = base else {
        panic!("merge expects an object");
    };
    for (key, value) in entries {
        map.insert((*key).to_owned(), value.clone());
    }
    Value::Object(map)
}

/// The bytes of one payload: pretty-printed, UTF-8, no trailing newline.
pub fn dumps(value: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value).expect("corpus payloads are always serializable")
}

/// An object literal, with the keys sorted by [`obj`].
#[macro_export]
macro_rules! obj {
    ($($key:expr => $value:expr),* $(,)?) => {
        $crate::json::obj(vec![$(($key, ::serde_json::Value::from($value))),*])
    };
}
