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
/// Section 6.3 suggests 3 for interactive work and 6 for a final export, and the
/// measurements agree that the level is a time-for-size knob whose worth depends on
/// the print. On a 3 688-layer 16K print, 122.8 MB of REE to compress: level 3 costs
/// 0.60 s and 8.7% more file size than level 19, level 6 costs 1.08 s and 2.8% more,
/// and level 19 costs 15.45 s.
///
/// An anti-aliased print has more to gain, because its greyscale planes carry
/// structure that only the higher levels find, and it gains more still now that a
/// dictionary is written only when it pays. Measured on an 800-layer 12K print whose
/// 75.9 MB of streams are anti-aliased, against the same print written at level 6:
///
/// | level | file | encoding |
/// |-------|------|----------|
/// | 3 | +10% | — |
/// | 6 | baseline | 0.56 s |
/// | 9 | −3% | 0.77 s |
/// | 12 | −6% | 1.74 s |
/// | 19 | −17% | 9.01 s |
///
/// So 6 is the default for a slice that has to stay quick - level 19 is the difference
/// between a slice that takes longer than CTB's and one that does not - and a profile
/// can ask for 19 through `lumen.zstdLevel` when file size is the only thing that
/// matters. The gain is large enough on a layer-heavy print that the settings page
/// spells the trade out rather than hiding it behind "compression".
pub const DEFAULT_ZSTD_LEVEL: i32 = 6;

/// `HEAD.encoder_name`, which the specification leaves to the writer.
pub const ENCODER_NAME: &str = "DragonFruit";
