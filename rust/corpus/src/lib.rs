//! The specification's own reader.
//!
//! Validates a `.lumen` file against LUMEN v1.0 without using the reference
//! crate. That is the whole point of this package existing separately: the
//! corpus is evidence about the *specification* only if a second, independent
//! reading of the text - this one - agrees with the bytes the generator wrote.
//!
//! It shares no code with `lumen-corpus-gen`, and depends on neither it nor
//! `lumen-format`. Sharing third-party crates (`zstd`, `sha2`, `aes-gcm`, ...) is
//! expected; sharing our own code would make the two readings one reading.
//!
//! # How the reader is put together
//!
//! * [`reader`] walks a container and runs every check the specification
//!   defines, in the specification's order.
//! * [`container`] is the chunk directory it walks, and the directory indices
//!   the layer table's chunk references count against.
//! * [`ree`] decodes the three run-length encodings and says which rule a
//!   stream breaks.
//! * [`crypto`] opens the AUTH chunk and the sealed units it describes.
//! * [`content`] is the JSON shape rules the content chunks are held to.
//! * [`decompress`] is zstd, with the oracle's semantics rather than the
//!   obvious ones.
//! * [`timing`] is §8's pipeline: the values a conforming reader must resolve
//!   for a `(layer, sector)` point, which the manifest records for a sample of
//!   them.
//! * [`manifest`] compares a file against the corpus' recorded golden values,
//!   which is a different claim from "it conforms".
//! * [`primitives`] and [`bytes`] are the arithmetic and the byte reads those
//!   are built on.

pub mod bytes;
pub mod container;
pub mod content;
pub mod crypto;
pub mod decompress;
pub mod manifest;
pub mod primitives;
pub mod reader;
pub mod ree;
pub mod timing;

pub use crypto::CryptoBlock;
pub use manifest::{check_manifest, Comparison, Invalid, Manifest, Valid};
pub use primitives::crc32c_self_test;
pub use reader::{validate, validate_bytes, Checks, Payload};

/// The line terminator the report uses.
///
/// The report is diffed line by line against the Python validator's own output,
/// and Python's `print` writes CRLF when its stdout is redirected on Windows.
/// Matching it is what makes a plain `diff` of the two files empty rather than
/// every line differing by an invisible byte; on every other platform both
/// readings write LF.
#[cfg(windows)]
pub const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
pub const LINE_ENDING: &str = "\n";

/// Print one report line, terminated the way the corpus' own validator
/// terminates its lines.
#[macro_export]
macro_rules! reportln {
    () => {
        print!("{}", $crate::LINE_ENDING)
    };
    ($($arg:tt)*) => {
        print!("{}{}", format_args!($($arg)*), $crate::LINE_ENDING)
    };
}
