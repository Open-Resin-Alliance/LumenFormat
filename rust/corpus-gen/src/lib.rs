//! The LUMEN conformance corpus generator.
//!
//! A second, independent reading of the specification: it shares no code with the
//! validator in `lumen-corpus` and does not use the reference crate, so agreement
//! between the files written here and the files that validator accepts is evidence
//! about the specification rather than one implementation checking itself.
//!
//! Every byte it writes is derived from the rules in `spec/`, down to the framing
//! and the compression, so the published corpus can be regenerated and audited.

pub mod container;
pub mod crypto;
pub mod deflate;
pub mod hash;
pub mod json;
pub mod payload;
pub mod png;
pub mod ree;
pub mod timing;
pub mod vector;
pub mod vectors;

/// The revision of the specification the vectors are written against.
///
/// `status.json` names the working-tree revision; this is the value it carries, and
/// it is what the manifest's `generator` block reports. A new revision means new
/// vectors, so the value moves with the corpus and not with the toolchain.
pub const FORMAT_REVISION: &str = "1.0";

/// The zstd level used for the `LAYR` frames (spec 4.9).
pub const ZSTD_LAYER_LEVEL: i32 = 6;

/// The zstd level used for the small metadata payloads (spec 3.2).
pub const ZSTD_SMALL_LEVEL: i32 = 3;

/// Construction timestamp the corpus pins, 2025-09-04T16:53:20Z.
pub const CREATED_UNIX_SEC: u64 = 1_757_000_000;
