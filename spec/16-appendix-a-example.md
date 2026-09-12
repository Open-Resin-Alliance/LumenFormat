# Example file layout

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix A: Example File Layout

Single-sector, 100 layers, 1920×1080, no encryption (illustrative estimates):

```
Offset    Size    Content
------    ----    -------
0         32      File header: LUMN, v1, dir_offset=<end>, chunk_count=8, flags=0x00
32        ~60     HDR (uncompressed): encoder="DragonFruit 1.0", 1920×1080, layer_height=0.05, 100 layers
~92       ~350    META (zstd-compressed, ~1.2 KB uncompressed): full JSON metadata
~442      ~800    PROF (zstd-compressed, ~2.5 KB uncompressed): reusable print profile for Odyssey import
~1,242    ~5,200  PREV (uncompressed PNG): 400×300 preview
~6,442    ~16K    ZDIC (uncompressed): zstd dictionary trained on the layer data
~22,442   2,000   LTBL (uncompressed): 100 entries × 20 bytes
~24,442   ~850K   LAYR (uncompressed container; 2 block frames of 50 layers, ~1.6 MB uncompressed each)
--        ~45K    VOXL (zstd-compressed, ~80 KB uncompressed): embedded scene for round-trip editing
--        256     Chunk Directory: 8 × 32 bytes
--        8       Trailer: "LEND" + CRC-32C
```

Total: approximately 920 KB for this example (the optional `LROV` chunk is omitted
because there are no overrides). Actual sizes depend on geometry
complexity, AA settings, and zstd compression level. The VOXL embedding adds a
small overhead relative to the layer data and buys full re-editability.
