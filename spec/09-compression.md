# Compression strategy

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 6. Compression Strategy

Compression is the single most important factor in a modern print file format.
A 12K printer generates 74.6 million pixels per layer; across 2,000 layers that
is 149 GB of raw data. Without aggressive compression, files are unmanageably
large for storage, network transfer, and embedded-printer memory.

LUMEN's compression strategy has two layers. First, the REE encoding ([§5](08-layer-encoding.md#5-layer-mask-encoding))
reduces the per-layer information content well below that of raw pixels.
Second, zstd compresses the layer data stream in blocks with a shared
trained dictionary, exploiting the fact that adjacent layers in a
3D print are nearly identical - only the edges change. No existing resin print
format does cross-layer compression; this alone is expected to yield a step
change in compressed file sizes.

### 6.1 Why zstd

| Property | zlib/deflate | zstd |
|----------|-------------|------|
| Compression ratio | baseline | Consistently better at equivalent speed |
| Decompression speed | Baseline | Significantly faster (see zstd benchmarks) |
| Compression speed | Baseline | Significantly faster at default levels |
| Dictionary support | raw deflate only | First-class training API |
| Streaming API | Yes | Yes |

Benchmark data is published by the zstd project (RFC 8878). The key design
decision is that zstd's combination of higher ratio, faster decompression, and
first-class dictionary training makes it the right choice for cross-layer
compression of REE data.

### 6.2 Dictionary Compression for LAYR

1. Encode all layers to REE streams, in layer order.
2. Split the layer sequence into contiguous blocks ([§4.10](06-layer-data.md#410-layr---layer-data-chunk)). Recommended: 32–64
   layers per block.
3. Sample the first `min(256, total_layers)` layers for a training set.
4. Train a zstd dictionary with `ZDICT_trainFromBuffer()`.
5. Store the dictionary in a `ZDIC` chunk ([§4.9](06-layer-data.md#49-zdic---zstd-dictionary-chunk)).
6. Compress each block independently with `ZSTD_compress_usingDict()`.

The dictionary captures statistical patterns in REE data. Because adjacent layers
are highly similar (only the edges change between adjacent layers), a dictionary
trained on the first 256 layers should generalize to the entire print. If dictionary
training fails (degenerate geometry, very small prints), omit the `ZDIC` chunk and
compress each block with standard zstd, without a dictionary.

**Why blocks instead of one frame.** A single frame compresses marginally better,
but a zstd frame cannot be decompressed partially. That would make `LTBL` random
access, per-layer `LHAS` verification, resume-after-power-loss, and parallel block
decode all impossible, and would force a full-copy decompression buffer of hundreds
of megabytes on embedded readers. Block frames make each of those operations real.
The cost is one frame header per block and a small ratio loss, largely recovered by
the shared dictionary.

### 6.3 Per-Chunk Compression Policy

The compressed/uncompressed choice in the table below is **normative**: it tells a
reader whether a chunk payload carries a zstd frame. The levels are recommendations.

| Chunk | Compression | Rationale |
|-------|------------|-----------|
| HDR | None | Tiny (~50 bytes); read before decompressor init. |
| AUTH | None | Tiny (~few hundred bytes); read before decompressor init. |
| META | zstd level 3 | Small payload; speed matters. |
| SECT | zstd level 3 | Small payload. |
| LROV | zstd level 3 | Small payload. |
| PREV | None | PNG is already compressed. |
| LTBL | None | Needed for random access; 20 bytes/layer is acceptable. |
| ZDIC | None | Raw dictionary bytes; read before any LAYR block decompression. |
| LAYR | zstd level 3–6 per block, shared dictionary | Bulk of file; level 3 for interactive, level 6 for final export. |
| VOXL | zstd level 3 | VOXL V2 already uses zlib internally; zstd recompression yields additional reduction. |
| LHAS | None | Needed for integrity checks before decompressor init. |
| EXTD | Per-extension | Extension defines its own recommendation. |
