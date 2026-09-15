//! Constants shared by the LUMEN plugin's modules.

/// How many layers one `LAYR` chunk groups.
///
/// The specification's compression strategy (section 6.2) compresses a group of
/// layers into one frame so the compressor can match across them; 64 is the
/// reference writer's default. A profile may override it through
/// `lumen.layersPerChunk`.
pub const DEFAULT_LAYERS_PER_CHUNK: u32 = 64;

/// zstd level for `LAYR` frames.
///
/// Section 9 suggests 3 for interactive work and 6 for a final export, and a real
/// 16K model says the same thing with numbers. On a 3 688-layer print, 122.8 MB of
/// REE to compress: level 3 costs 0.60 s and 8.7% more file size than level 19,
/// level 6 costs 1.08 s and 2.8% more, and level 19 costs 15.45 s. The last of those
/// is the difference between a slice that takes longer than CTB's and one that does
/// not, for two percent of the file, so 6 is the default and a profile can ask for
/// 19 through `lumen.zstdLevel` when file size is the only thing that matters.
pub const DEFAULT_ZSTD_LEVEL: i32 = 6;

/// `HEAD.encoder_name`, which the specification leaves to the writer.
pub const ENCODER_NAME: &str = "DragonFruit";
