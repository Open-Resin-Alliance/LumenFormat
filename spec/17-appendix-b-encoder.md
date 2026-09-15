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
| `lift_slow_distance_um` + `lift_fast_distance_um` | `LiftHeight` (the total) |
| `retract_fast_distance_um` | `RetractHeight` (the first segment) |
| `retract_slow_distance_um` | `RetractHeight2` (the second segment) |
| `bottom_retract_slow_distance_um` | `BottomRetractHeight2` |
| `wait_time_after_cure_ms` | `LightOffDelay` |

A converter that copies `lift_slow_distance_um` straight into `LiftHeight` lifts only a
fraction of the intended travel, because ours is the first segment where theirs is
the sum. The last row is the reverse case: ChiTuBox's `LightOffDelay` is a pause after the
exposure, which is exactly what `wait_time_after_cure_ms` is, so the two are one wait under
two names. Lumen keeps the wait and drops the older field, whose meaning is not consistent
between firmwares - some apply it before the lift, some treat it as a per-layer total.

Two rows carry a unit to convert. ChiTuBox stores lift heights as millimetre floats, so
multiply by 1000 writing Lumen and divide by 1000 reading ChiTuBox; it stores timings as
second floats, so the same factor converts `wait_time_after_cure_ms` and `LightOffDelay`.
Both directions lose what the integer cannot hold: a ChiTuBox value of 5.0005 mm has no
exact micrometer form, and a `LightOffDelay` of 2.0005 s has no exact millisecond form.
Round to the nearest unit in both directions. Neither format carries a sub-micrometer
length or a sub-millisecond duration, so a converted value may sit less than one unit from
its source and a round trip does not always return the original float.

Note also that the slicer's CTB timing struct carries a
`bottom_retract_height2_mm` field: it is the same quantity as
`bottom_retract_slow_distance_um`, under the other format's name.
