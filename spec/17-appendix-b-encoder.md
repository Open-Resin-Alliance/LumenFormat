# Reference encoder integration

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix B: Reference Encoder Integration

The LUMEN encoder follows the existing plugin pattern (`FormatEncoder` +
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
