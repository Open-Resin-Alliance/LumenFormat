# Reference implementation

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix B: The Reference Implementation

This appendix is informative. It describes the implementation that exists - the
reference crate and the slicer adapter DragonFruit compiles into its engine - rather than
a shape an implementation might take. Nothing here is normative: sections 3 to 9 define
the format, and a conforming implementation is free to structure itself differently.

### B.1 What the two pieces own

The format has one implementation and two consumers (the **DragonFruit** slicer writes
it, **Odyssey** firmware prints it), and every divergence between implementations is a
compatibility bug that only shows up on a printer. So the container is implemented once,
and each consumer is an adapter over it:

| Piece | Owns |
|-------|------|
| [`rust/lumen`](../rust/lumen) - package `lumen-format`, library `lumen` | The container of sections 3 to 9: header, chunk directory and trailer; one codec per chunk type; REE; zstd framing and the trained dictionary; layer hashes; `AUTH` and its AEAD units; the checks of section 11. |
| [`slicing/`](../slicing) in this repository - the `plugins/lumen` submodule of DragonFruit, compiled into its slicing engine | The mapping from the slicer's own model into `HEAD`, `META` and `LROV`; the streaming sink that feeds layer runs to the crate; the export capture as a `PREV` chunk; the file-type declaration the shell thumbnail providers read. |

The crate is a consumer of this specification, not a substitute for it: where the two
disagree the specification wins, and [`test-vectors/`](../test-vectors) settles the
argument.

### B.2 The crate

```
rust/lumen/src/
  container.rs   file header, chunk directory, trailer
  chunkio.rs     chunk framing, compression and sealing as they are written
  chunks/        one codec per chunk type: head, json_chunks, ltbl, layr, zdic,
                 lhas, preview, voxl, extd
  json.rs        the typed META, PROF and LROV models
  ree.rs         run-end encoding: binary, grayscale, split and attached
  timing.rs      the per-layer settings pipeline of section 8
  crypto.rs      AUTH, the AEAD units, Argon2id and X25519 key wrapping
  validate.rs    the checks of section 11, named as the corpus names them
  check.rs       check names and levels
  reader.rs      LumenFile: random access to one layer
  writer.rs      Encoder: produces a conforming file
```

`LumenFile::layer(i)` decompresses the one `LAYR` chunk that holds layer *i* and nothing
else, which is what lets a firmware reader stream a long print through a bounded buffer.
`Encoder` trains the dictionary, frames each layer group on worker threads and assembles
the directory and trailer; identical input and settings produce identical bytes
(§5.7), which is what makes re-slicing a scene reproduce its `LHAS` hashes. Sealed output
is the documented exception (§9.4): it draws its keys and nonces from the OS CSPRNG.

### B.3 The DragonFruit adapter

```
plugins/lumen/
  pluginDefinition.ts          the plugin's declaration: format, settings, scene payload
  outputFileTypes.json         extension, media type, UTI, and where the preview lives
  materialSettings/            the LUMEN settings profile
  slicing/lumenFormatDefinition.ts
  slicing/rust/
    encoder_impl.rs            FormatEncoder + RleStreamEncoder
    lumen_metadata.rs          job settings -> HEAD and META, and LROV overrides
    lumen_preview.rs           the export capture -> a PREV chunk
    lumen_types.rs             the defaults in B.4
```

The integration, as the engine's traits are actually implemented:

- `output_format()` returns `".lumen"`, and `requires_png_layers()` is false: the encoder
  takes the engine's RLE streaming path (`create_rle_stream_encoder`), so the rasterizer
  hands over run lists and no full-frame buffer is ever materialized. On a 16K frame that
  is the difference between microseconds and a tenth of a second per layer.
- `consume_rle_layer` encodes one layer's runs into its REE stream; `parallel_encode_fn`
  moves that conversion into the engine's workers, because layers are independent;
  `finalize_to_bytes` hands the accumulated layers to `writer::Encoder`.
  `encode_container_from_rendered_layers` produces the same file for callers that already
  hold raster masks instead of runs.
- `read_layer_preview_png` opens an artifact the way a printer would - container only, no
  key, no dictionary of its own - and renders one stored 8-bit mask, which is what the
  app's layer scrubbing shows.
- `lumen_metadata::build` fills `HEAD` (§4.1) and `META` (§4.2) from the job. A value is
  looked up in the chain the app already writes: `lumen.*` first, so the LUMEN settings
  profile owns every field it defines; then the CTB-shaped `ctb.*` / `export.ctb.*` keys a
  ChiTuBox-derived profile carries, which keeps such a profile slicing LUMEN without new
  settings; then the manifest's `material` node. LUMEN stores integer micrometers and
  whole milliseconds (§2), so every value is converted and rounded to the nearest unit
  rather than truncated, and the pairing the app's own settings already carry -
  `liftDistanceMm` and `liftDistance2Mm` as the two segments of the peel, a second retract
  height as the slow retract, a light-off delay as the pause after the cure - maps field
  for field onto §8's model.
- `lumen_preview::export_preview_png` fits the exporter's 1600×960 capture into the
  role-1 box of §4.6 (400×300) and the encoder writes it as one `PREV` chunk, which is
  what gives a `.lumen` file a thumbnail in a file manager.
- The embedded scene is declared, not coded: `pluginDefinition.ts` names the setting that
  asks for a payload and the metadata path it lands on, and the host bakes it. The
  encoder's `embedded_scene` refuses a job whose flag asks for a scene it did not receive
  (§4.11), so a profile that promised a re-editable file never produces one that is not.

### B.4 The defaults, and where they come from

| Setting | Default | Why |
|---------|---------|-----|
| `layers_per_chunk` (`lumen.layersPerChunk`) | 64 | §6.2's grouping: enough layers for cross-layer matching to pay for itself, few enough that a reader's working set stays bounded. |
| `zstd_level` (`lumen.zstdLevel`) | 6 | §6.3 recommends level 3 for interactive work and level 6 for a final export. On a measured 3,688-layer 16K print - 122.8 MB of REE to compress - level 3 costs 0.60 s and 8.7% more file size than level 19, level 6 costs 1.08 s and 2.8% more, and level 19 costs 15.45 s. An anti-aliased print has more to gain: on an 800-layer 12K print whose 75.9 MB of streams are anti-aliased, against the same print at level 6, level 9 is 3% smaller and 0.2 s slower, level 12 is 6% smaller and 1.2 s slower, and level 19 is 17% smaller and 9.0 s slower. Level 6 is the default so a slice does not take longer than the format it replaces, and a profile can ask for 19 (or 9, or 12) when file size is what matters. |
| dictionary (`Encoder::set_dictionary`, no setting) | on, and conditional in effect | §6.2's step 5: the writer samples the print, trains a dictionary and writes it only when a probe of the print says it earns its own bytes back, so "on" means "considered" rather than "written". An anti-aliased print's planes are high-entropy enough that a dictionary loses to no dictionary, and the writer omits the chunk there. The adapter always asks for it; the decision is the crate's, which is what keeps two DragonFruit versions writing the same file. |
| encoding tag (`lumen.tagProbe`; `Encoder::set_tag_probe`, on by default) | on - the smaller candidate, by compressed frame | §5.7 leaves the tag to the encoder, so the writer chooses it per layer group, at the end, with the `ZDIC` dictionary the frames will actually use: it encodes the group's layers both ways - with the tag `EncodeMode::Auto` picks, and with tag `0x03` - compresses both frames exactly as the file frames them and keeps the smaller. A stream's raw length does not predict that: on a near-static binary print the attached form of a slice with no AA pixels is *smaller* uncompressed than the binary stream and 23% larger after zstd, so an encoder that chose by raw length would choose the larger file. The adapter pushes its runs under `EncodeMode::Auto`, so the choice stays the crate's. |
| layer hashes (`Encoder::set_layer_hashes`, no setting) | on | §4.10's integrity tree is optional and the writer emits it: 32 bytes per layer, the thing that makes a partial file verifiable, and a printer that does not want it skips the chunk. |
| `encoder_name` (constant) | `DragonFruit` | §4.1 leaves the field to the writer. |

### B.5 What is deliberately not here

The plugin contains no container code: no chunk assembly, no framing, no cryptography.
Those would be a second implementation of sections 3 to 9, and the point of one reference
crate is that there is one - REE canonicalization, dictionary IDs and the per-chunk AAD
that binds a sealed frame to its chunk and directory index are exactly the details two
implementations disagree about.

Also out of scope here, and stated as such by the specification: `VOXL` parsing (the
crate carries the embedded scene as opaque bytes and checks only its magic, §4.11),
extension payload semantics (`EXTD` framing and flags are the specification's, the
payload is the extension's, §4.12), and signing - the format has authenticated
encryption, not a signature.

### B.6 Conformance

[`test-vectors/`](../test-vectors) and the crate's `validate` are what the plugin is
written against, at two levels: `Loose` for printing, where structurally valid files are
accepted and unknown chunks and fields are skipped, and `Strict` for verification, where
every check in §11 runs and the first failure is reported in the specification's own
order. The crate's tests read the corpus, and DragonFruit's plugin registration generator
refuses a plugin whose declared crate does not resolve, so the encoder in B.3 stays an
adapter over the reference implementation rather than drifting into a parallel one.
