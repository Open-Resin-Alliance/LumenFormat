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
/// Section 9 suggests 3-6 for a panel frame and calls 6 the final-export setting.
/// Encoding happens once per print and decoding does not depend on the level, so a
/// profile that would rather have smaller files can raise it through
/// `lumen.zstdLevel`; 19 measurably takes about a third off anti-aliased layers.
pub const DEFAULT_ZSTD_LEVEL: i32 = 6;

/// `HEAD.encoder_name`, which the specification leaves to the writer.
pub const ENCODER_NAME: &str = "DragonFruit";
