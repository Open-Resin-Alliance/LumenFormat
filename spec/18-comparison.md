# Comparison with existing formats

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 12. Comparison with Existing Formats

| Feature | CTB v5 | GOO | AFZ (Anycubic) | NanoDLP | **LUMEN v1** |
|---------|--------|-----|----------------|---------|-------------|
| Container | Flat binary, fixed header | Flat binary, 195 KB header | ZIP archive | ZIP archive | Chunk directory (extensible) |
| Endianness | LE | BE | LE | LE | LE |
| Metadata | Fixed-offset binary | Fixed-offset binary | JSON files in ZIP | JSON files in ZIP | JSON in typed chunks |
| Human-readable params | No | No | Yes (unzip) | Yes | Yes (`strings` + decompress) |
| Layer encoding | Variable-length RLE, XOR-obfuscated | 0x55-magic RLE, checksum | PW0 RLE (4-bit quant) | PNG (deflate) | REE + zstd with dictionary |
| Compression | RLE only | RLE only | Deflate per-entry | Deflate per PNG | zstd cross-layer with dictionary |
| Cross-layer compression | No | No | No | No | Yes (shared-dictionary frames, one per sector per layer group) |
| Encryption | AES-256-CBC (optional, v5enc) | No | No | No | Optional AEAD (AES-256-GCM / ChaCha20-Poly1305) |
| Encryption purpose | Vendor file binding (enforced by the printer) | - | - | - | User security (opt-in) |
| Per-layer overrides | No (bottom/normal/transition) | No | No | No | Yes (LROV, arbitrary overrides of one `(layer, sector)`) |
| Embedded print profile | No | No | No | No | Yes (PROF chunk - importable by Odyssey firmware) |
| Embedded source scene | No | No | No | No | Yes (VOXL chunk - round-trip re-editable) |
| Multi-material | No | No | No | No | Yes (per-sector layer chunks, and per-sector timing and material in META) |
| Extensibility | No (must reverse-engineer) | No | No | No | Yes (EXTD chunks, vendor IDs) |
| Max resolution | ~16K (32-bit offsets) | Fixed header limit | Unlimited (ZIP64) | Unlimited | Unlimited (64-bit offsets) |
| Preview images | 2× RGB15 RLE (fixed size) | 2× PNG in header (fixed size) | 3× PNG in ZIP | 1× PNG in ZIP | 1+N PNG in PREV chunks (flexible) |
| AA support | Grayscale RLE | Grayscale RLE | 4-bit PW0 | Full 8-bit PNG | Full 8-bit REE + split encoding + zstd |
| Temperature control | No | No | No | No | Yes (chamber + vat, Celsius) |
| Resin cure curve | No | No | No | No | Yes (Dp, Ec, E0 - experimental, for physics-based exposure) |
| Per-layer integrity | No | No (per-layer checksum) | ZIP CRC32 per entry | ZIP CRC32 per entry | SHA-256 Merkle tree (LHAS chunk) + CRC-32C trailer |
| Validation | CRC32 (encrypted only) | One's-complement per layer | ZIP CRC32 per entry | ZIP CRC32 per entry | CRC-32C trailer + structural + semantic + Merkle root |

The columns for formats other than LUMEN are drawn from public community
reverse-engineering and may be inaccurate or out of date. They are here to place
LUMEN's design decisions in context, not to specify those formats.
