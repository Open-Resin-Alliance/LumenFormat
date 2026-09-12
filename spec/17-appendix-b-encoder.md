# Reference encoder integration

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix B: Reference Encoder Integration

This appendix is informative. It describes how a reference encoder for a slicer
using the plugin pattern below is expected to integrate; it is not a description of
shipped code, and a conforming implementation is free to structure itself
differently.

Such an encoder would follow the plugin pattern (`FormatEncoder` +
`RleStreamEncoder` traits defined in
`rust/dragonfruit-slicing-engine/src/encoders/mod.rs`):

```
plugins/lumen/
  pluginDefinition.ts
  pluginManifest.ts
  slicing/
    lumenFormatDefinition.ts      - SlicingFormatDefinition (layerDataKind: 'raw-mask')
    rust/
      encoder_impl.rs             - FormatEncoder + RleStreamEncoder impl
      lumen_layout.rs             - Chunk assembly, REE encoding, block framing, zstd compression
      lumen_metadata.rs           - JSON builders for META, SECT, LROV
      lumen_crypto.rs             - AUTH chunk, AEAD encrypt/decrypt, key wrapping
      lumen_types.rs              - Consts, LumenPreparedLayer, etc.
```

Key integration points:
- `output_format()` returns `".lumen"`.
- `requires_raw_mask_layers()` returns `true`, `requires_png_layers()` returns `false`.
- `create_rle_stream_encoder()` receives `Vec<RleRun>` per layer and converts each
  layer to a REE stream.
- `finalize_to_bytes()` splits the accumulated layer streams into blocks, trains the
  zstd dictionary into a `ZDIC` chunk, compresses each block independently, and
  assembles the complete chunk layout (`ZDIC`, `LTBL`, `LAYR`, `VOXL`, directory,
  trailer).
- `parallel_encode_fn()` enables parallel RLE→REE conversion via rayon; block
  compression is likewise independent per block.

### B.1 Mapping to the existing formats

LUMEN stores motion as two segments per direction, while ChiTuBox and the formats
derived from it store the *total* lift and only the second segment:

| LUMEN | ChiTuBox / GOO v5 |
|-------|-------------------|
| `lift_distance_mm` + `lift_distance2_mm` | `LiftHeight` (the total) |
| `retract_distance_mm` | `RetractHeight` (the first segment) |
| `retract_distance2_mm` | `RetractHeight2` (the second segment) |
| `bottom_retract_distance2_mm` | `BottomRetractHeight2` |

A converter that copies `lift_distance_mm` straight into `LiftHeight` lifts only a
fraction of the intended travel, because ours is the first segment where theirs is
the sum. Note also that the slicer's CTB timing struct carries a
`bottom_retract_height2_mm` field: it is the same quantity as
`bottom_retract_distance2_mm`, under the other format's name.
