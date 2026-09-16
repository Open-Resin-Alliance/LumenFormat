# Example file layouts

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix A: Example File Layouts

The reference implementation ships the files this appendix describes, and one command
writes them, so every number below can be regenerated rather than taken on trust:

```sh
cargo run --example make_test_file -- /tmp/lumen
```

| File | What it is |
|------|------------|
| `sample.lumen` | Twelve layers over one sector that between them use every layer encoding, with a trained dictionary, a profile, a preview, an embedded scene and an extension |
| `sample-no-lhas.lumen` | The same print without the optional integrity tree |
| `sample-encrypted.lumen` | The same print sealed with a password |
| `sample-multi-sector.lumen` | Ten layers over two resins, with per-layer settings over both |

### A.1 An illustrative layout

Single-sector, 100 layers, 1920×1080, no encryption (illustrative estimates):

```
Offset    Size    Content
------    ----    -------
0         32      File header: LUMN, v1, dir_offset=<end>, chunk_count=8, flags=0x00
32        ~60     HEAD (uncompressed): encoder="DragonFruit 1.0", 1920×1080, layer_height_um=50, 100 layers
~92       ~350    META (zstd-compressed, ~1.2 KB uncompressed): full JSON metadata
~442      ~800    PROF (zstd-compressed, ~2.5 KB uncompressed): reusable print profile for Odyssey import
~1,242    ~5,200  PREV (uncompressed PNG): 400×300 preview
~6,442    ~16K    ZDIC (uncompressed): zstd dictionary trained on the layer data
~22,442   2,800   LTBL (uncompressed): 100 entries × 28 bytes
~24,442   ~850K   LAYR (uncompressed container; 2 block frames of 50 layers, ~1.6 MB uncompressed each)
--        ~45K    VOXL (zstd-compressed, ~80 KB uncompressed): embedded scene for round-trip editing
--        256     Chunk Directory: 8 × 32 bytes
--        8       Trailer: "LEND" + CRC-32C
```

Total: approximately 920 KB for this example (the optional `LROV` chunk is omitted
because there are no overrides). Actual sizes depend on geometry
complexity, AA settings, and zstd compression level. The VOXL embedding adds a
small overhead relative to the layer data and buys full re-editability.

### A.2 The single-sector example

Twelve layers of a 64×48 display, one sector, `bottom_layer_count` 2 and
`transition_layer_count` 3, in three `LAYR` chunks of four layers each. The encoder
picks the smallest of the three encodings for each layer, which is why the masks
below carry the tags they do:

| Layer | Mask | Tag | Stored |
|-------|------|-----|--------|
| 0 | nothing at all: the empty-layer form | - | 0 bytes |
| 1 | solid | binary REE (`0x00`) | 7 bytes |
| 2 | solid with a rectangular hole | binary REE (`0x00`) | 40 bytes |
| 3 | a horizontal ramp: 64 distinct values down each row | split REE (`0x02`) | 6,061 bytes |
| 4 | a disc with a one-pixel anti-aliased rim | split REE (`0x02`) | 574 bytes |
| 5 | a checkerboard, the worst case for run-end encoding | binary REE (`0x00`) | 3,033 bytes |
| 6-11 | bars that grow with the layer, so no two layers are alike | binary REE (`0x00`) | 102 bytes each |

The file is 12 chunks and 3,400 bytes: `HEAD`, `META`, `PROF`, `ZDIC` (a 650-byte
dictionary, id 165639893), `PREV`, `VOXL`, `LTBL`, `LHAS`, three `LAYR`, `EXTD`.
Layer 3 is the largest slice by far - sixty times the growing bars - which is what an
anti-aliased ramp costs and what section 6 exists to compress.

The timing pipeline resolves it as:

| Layers | Exposure | Stage |
|--------|----------|-------|
| 0-1 | 30,000 ms | bottom, verbatim |
| 2 | 23,125 ms | transition, `k = 1` of 4 |
| 3 | 16,250 ms | transition, `k = 2` of 4 |
| 4 | 9,375 ms | transition, `k = 3` of 4 |
| 5-11 | 2,500 ms | normal |

§A.3 below gives the same print a second resin.

### A.3 Two resins with per-layer settings

`sample-multi-sector.lumen` is the shape a slicer produces when two resins print at
once and an operator adjusts individual layers. Ten layers, two sectors: sector 0 is
the model, a rectangle that widens as the print rises, and sector 1 a support column
in a second vat. The two masks are disjoint at every layer, which is what the
partition invariant asks ([§7.3](13-sectors.md#73-sector-mask-invariant)): a pixel
belongs to exactly one sector.

**The two resins** are a library in META and an entry in its `sectors` array
([§4.2](05-meta.md#42-meta---metadata-chunk)):

```jsonc
"materials": [
  { "name": "Model Resin",   "color_rgba": [200, 200, 205, 255] },
  { "name": "Support Resin", "color_rgba": [ 20, 200, 120, 255] }
],
"sectors": [
  {
    "sector_id": 1,
    "name": "Support Resin",
    "material_index": 1,
    "color_rgba": [20, 200, 120, 255],
    // This resin's own base, and its own burn-in range: five layers, where META
    // burns in for two. Every field it does not name it inherits from META,
    // including the transition count of 3.
    "normal_exposure_ms": 3000,
    "bottom_exposure_ms": 26000,
    "bottom_layer_count": 5
  }
]
```

**The per-layer settings** are five `LROV` chunks, one per `(layer, sector)` the
operator touched. Each is a sparse delta: it replaces the fields it names and leaves
the rest of the resolved value standing.

| Chunk | Applies to | Delta | Why a slicer would write it |
|-------|-----------|-------|-----------------------------|
| 2 | layer 3, sector 0 | `normal_exposure_ms` 4000, `lift_slow_distance_um` 7000 | that layer has the largest cross-section in the print, so it peels harder |
| 3 | layers 6, 7 and 8, sector 0 | `normal_exposure_ms` 2000 | the taper towards the top, the same on all three |
| 4 | layer 9, sector 1 | `normal_exposure_ms` 5000 | the support tips need more cure than the rest of their sector |

Chunk 3 is a *range* of three layers, written once: an `LROV` chunk is placed by the
layer table entries that name it, and any number of them may name one
([§4.5](08-print-control.md#45-lrov---layer-override-chunk)). The three entries are
the range - no field in the payload says where it starts or ends - so a slicer that
adjusts 500 layers with one delta writes one chunk and points 500 entries at it. A
slicer that gives every pair a chunk of its own is equally conforming, which is what
[`lrov-per-pair`](../test-vectors/README.md) pins.

**The file** is 11 chunks and 2,344 bytes: `HEAD`, `META`, three `LROV`, `LTBL`,
`LHAS`, and four `LAYR` chunks - one per `(sector, layer group)`, two sectors over
two groups of five layers. There is no `ZDIC`: ten small layers are not enough
sample data to train a dictionary on, and a writer that cannot train one omits it.

**The layer table** is the index a printer reads. Every layer carries sector 0's
entry even when sector 0 holds nothing on that layer, which is what the last row
shows: the model has finished, the supports have not.

| Layer | Sector | `first_layr` | `first_lrov` | `data_offset` | `data_size` |
|-------|--------|--------------|--------------|---------------|-------------|
| 0 | 0 | 7 | 0 | 0 | 56 |
| 0 | 1 | 8 | 0 | 0 | 72 |
| 1 | 0 | 7 | 0 | 56 | 56 |
| 1 | 1 | 8 | 0 | 72 | 72 |
| 2 | 0 | 7 | 0 | 112 | 56 |
| 2 | 1 | 8 | 0 | 144 | 72 |
| 3 | 0 | 7 | **2** | 168 | 56 |
| 3 | 1 | 8 | 0 | 216 | 72 |
| 4 | 0 | 7 | 0 | 224 | 56 |
| 4 | 1 | 8 | 0 | 288 | 72 |
| 5 | 0 | 9 | 0 | 0 | 56 |
| 5 | 1 | 10 | 0 | 0 | 72 |
| 6 | 0 | 9 | **3** | 56 | 56 |
| 6 | 1 | 10 | 0 | 72 | 72 |
| 7 | 0 | 9 | **3** | 112 | 56 |
| 7 | 1 | 10 | 0 | 144 | 72 |
| 8 | 0 | 9 | **3** | 168 | 56 |
| 8 | 1 | 10 | 0 | 216 | 72 |
| 9 | 0 | 10 | 0 | 0 | **0** |
| 9 | 1 | 10 | **4** | 288 | 24 |

Three things to read out of it. The `LAYR` chunk changes at layer 5, because the
group of five layers ends there - chunks 7 and 8 hold layers 0 to 4 for sectors 0
and 1, chunks 9 and 10 hold layers 5 to 9 - and that is what makes the chunk index
and the offset together enough to find one layer's bytes. Layers 6, 7 and 8 name the
same `first_lrov`, which is the range written once: one chunk, three entries, and
nothing else in the file says those three layers share a delta. And layer 9's
sector-0 entry is real but empty: `data_size` 0 means the sector has no bytes on that
layer, while the entry itself is what keeps sector 0's place in the order.

**What a reader resolves** for every `(layer, sector)` - META, then the sector's own
entry, then the bottom and transition blend over the counts *that sector* carries or
inherits, then the delta its entry names ([§8](14-layer-timing.md#8-per-layer-settings-model)):

| Layer | Sector 0 | Sector 1 | Overridden |
|-------|----------|----------|------------|
| 0 | 30,000 ms | 26,000 ms | - |
| 1 | 30,000 ms | 26,000 ms | - |
| 2 | 23,125 ms | 26,000 ms | - |
| 3 | **4,000 ms** | 26,000 ms | sector 0, chunk 2 |
| 4 | 9,375 ms | 26,000 ms | - |
| 5 | 2,500 ms | 20,250 ms | - |
| 6 | **2,000 ms** | 14,500 ms | sector 0, chunk 3 |
| 7 | **2,000 ms** | 8,750 ms | sector 0, chunk 4 |
| 8 | **2,000 ms** | 3,000 ms | sector 0, chunk 5 |
| 9 | 2,500 ms | **5,000 ms** | sector 1, chunk 6 |

The two sectors are in different stages on the same layer, which is the point of the
counts living in the sector's own entry: sector 0 burns in for two layers and blends
over layers 2 to 4, sector 1 burns in for five and blends over layers 5 to 7, so
layer 4 is fully normal at 2,500 ms for the model and still a bottom layer at
26,000 ms for the support resin.

A reader that prints one sector per layer cannot print this file faithfully: sector 1
carries pixels on every layer, so the single-material degradation of
[§7.2](13-sectors.md#72-sector-0-convention-and-single-material-degradation) has to
report the print as incomplete rather than complete. The reference crate answers
`is_single_material_complete() == false` for it, which is §7.2's rule expressed as an
API.
