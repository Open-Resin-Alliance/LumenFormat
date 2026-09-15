# Compression strategy

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 6. Compression Strategy

Compression is the single most important factor in a modern print file format.
A 12K printer generates 74.6 million pixels per layer; across 2,000 layers that
is 149 GB of raw data. Without aggressive compression, files are unmanageably
large for storage, network transfer, and embedded-printer memory.

LUMEN's compression strategy has two layers. First, the REE encoding ([§5](08-layer-encoding.md#5-layer-mask-encoding))
reduces the per-layer information content well below that of raw pixels.
Second, zstd compresses each sector's layer data in frames with a shared
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

1. Encode every `(layer, sector)` slice to an REE stream, in layer order within each sector.
2. Group each sector's layers into contiguous runs, and make one frame - one `LAYR` chunk -
   per run ([§4.10](06-layer-data.md#410-layr---layer-data-chunk)). Recommended: 32–64
   layers per frame.
3. Sample the first `min(256, total_layers)` layers for a training set.
4. Train a zstd dictionary with `ZDICT_trainFromBuffer()`.
5. Store the dictionary in a `ZDIC` chunk ([§4.9](06-layer-data.md#49-zdic---zstd-dictionary-chunk)).
6. Compress each frame independently with `ZSTD_compress_usingDict()`.

The dictionary captures statistical patterns in REE data. Because adjacent layers
are highly similar (only the edges change between adjacent layers), a dictionary
trained on the first 256 layers should generalize to the entire print. If dictionary
training fails (degenerate geometry, very small prints), omit the `ZDIC` chunk and
compress each frame with standard zstd, without a dictionary.

Because a sector's frames may be compressed independently, one dictionary trained once for
the print serves them all: every frame in the file agrees with `ZDIC.dict_id`, whatever
sector or layer group it carries.

**Why frames instead of one frame per sector.** One frame over all of a sector's layers
would compress marginally better, but a zstd frame cannot be decompressed partially. That
would make `LTBL` random access, per-layer `LHAS` verification, resume-after-power-loss, and
parallel frame decode all impossible, and would force a full-copy decompression buffer of
hundreds of megabytes on embedded readers. One frame per `(sector, layer group)` makes each
of those operations real. The cost is one frame header per group and a small ratio loss,
largely recovered by the shared dictionary.

**Sector boundaries are frame boundaries.** A frame carries one sector's data and never two,
so a reader that prints a single sector decodes only that sector's chunks, and each sector's
frames can be sized, laid out and compressed without reference to the others. Two sectors of
one file need not share layer-group boundaries: they are encoded independently, and a layer
group is per sector, not a file-wide partition.

### 6.3 Per-Chunk Compression Policy

The compressed/uncompressed choice in the table below is **normative**: it tells a
reader whether a chunk payload carries a zstd frame. The levels are recommendations.

| Chunk | Compression | Rationale |
|-------|------------|-----------|
| HDR | None | Tiny (~50 bytes); read before decompressor init. |
| AUTH | None | Tiny (~few hundred bytes); read before decompressor init. |
| META | zstd level 3 | Small payload; speed matters. |
| PROF | zstd level 3 | Reusable profile; small payload. |
| LROV | zstd level 3 | Small payload; one chunk per overridden `(layer, sector)`. |
| PREV | None | PNG is already compressed. |
| LTBL | None | Needed for random access; 28 bytes per `(layer, sector)` entry is acceptable. |
| ZDIC | None | Raw dictionary bytes; read before any LAYR frame decompression. |
| LAYR | zstd level 3–6 per frame, shared dictionary | Bulk of file; level 3 for interactive, level 6 for final export. |
| VOXL | zstd level 3 | VOXL V2 already uses zlib internally; zstd recompression yields additional reduction. |
| LHAS | None | Needed for integrity checks before decompressor init. |
| EXTD | Per-extension | Extension defines its own recommendation. |
