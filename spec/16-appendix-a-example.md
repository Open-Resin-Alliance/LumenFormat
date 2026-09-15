# Example file layout

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix A: Example File Layout

Single-sector, 100 layers, 1920×1080, no encryption (illustrative estimates):

```
Offset    Size    Content
------    ----    -------
0         32      File header: LUMN, v1, dir_offset=<end>, chunk_count=9, flags=0x00
32        ~60     HEAD (uncompressed): encoder="DragonFruit 1.0", 1920×1080, layer_height_um=50, 100 layers
~92       ~350    META (zstd-compressed, ~1.2 KB uncompressed): full JSON metadata, no `sectors` entry - one sector
~442      ~800    PROF (zstd-compressed, ~2.5 KB uncompressed): reusable print profile for Odyssey import
~1,242    ~5,200  PREV (uncompressed PNG): 400×300 preview
~6,442    ~16K    ZDIC (uncompressed): zstd dictionary trained on the layer data
~22,442   2,800   LTBL (uncompressed): 100 entries × 28 bytes, one per (layer, sector 0)
~25,242   ~425K   LAYR (uncompressed container; sector 0, layers 0-49, one zstd frame)
~460K     ~425K   LAYR (uncompressed container; sector 0, layers 50-99, one zstd frame)
--        ~45K    VOXL (zstd-compressed, ~80 KB uncompressed): embedded scene for round-trip editing
--        288     Chunk Directory: 9 × 32 bytes
--        8       Trailer: "LEND" + CRC-32C
```

Total: approximately 920 KB for this example (the optional `LROV` and `ZDIC`-less cases aside,
this file carries no overrides, so no `LROV` chunk is present, and one sector means every
`LTBL` entry is sector 0's with `additional_sector_count == 0`). Actual sizes depend on
geometry complexity, AA settings, and zstd compression level. The VOXL embedding adds a
small overhead relative to the layer data and buys full re-editability.
