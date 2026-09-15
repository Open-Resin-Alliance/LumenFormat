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
/// Section 9 suggests 3-6 for a panel frame, which predates the measurements. On a real
/// 800-layer 16K print, re-encoded through this writer, level 3 leaves 12.5% on the
/// table against level 19, level 6 leaves 5.1% and level 12 leaves 4.0%; level 22 buys
/// nothing further. The planes made the level matter less than it did - 13% before
/// them, 5.1% after - but what remains is free to a reader, since decompression does
/// not depend on the level, and costs one-off time at encode: 0.8 s against 0.1 s for
/// that print. A profile can still lower it through `lumen.zstdLevel`.
pub const DEFAULT_ZSTD_LEVEL: i32 = 19;

/// `HEAD.encoder_name`, which the specification leaves to the writer.
pub const ENCODER_NAME: &str = "DragonFruit";
