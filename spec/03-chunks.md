# Chunk types

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 4. Chunk Types

A LUMEN file is composed of typed chunks. The table below summarizes every
chunk defined by this specification. Developers can scan this to understand
the file's capabilities at a glance; detailed binary layouts follow.

| Tag | Name | Required | Reader support | Encrypted | Purpose |
|-----|------|----------|----------------|-----------|---------|
| `HEAD` | Header | Yes | Required | No | Display dimensions, layer count, encoder identity |
| `META` | Metadata | Yes | Required | Yes | Print parameters as JSON (exposure, lift, motion) |
| `PROF` | Print Profile | No | Optional | Yes | Named, versioned, reusable profile for Odyssey import |
| `AUTH` | Authentication | No | Required when the file is encrypted | No | Encryption metadata, key wrapping, machine binding |
| `LROV` | Layer Override | No | **Required** - refuse a file you cannot honor ([§4.5](08-print-control.md#45-lrov---layer-override-chunk)) | Yes | Timing overrides for one `(layer, sector)` pair |
| `PREV` | Preview Image | No | Optional | Optional | PNG preview images, multiple roles supported |
| `LTBL` | Layer Table | Yes | Required | No | Per-`(layer, sector)` chunk index and slice offsets, for random access |
| `ZDIC` | Zstd Dictionary | No | Required when present | Yes | Trained dictionary shared by every LAYR frame |
| `LAYR` | Layer Data | Yes | Required | Yes | One sector's layer masks for a group of layers, as one zstd frame |
| `LHAS` | Layer Hashes | No | Optional | No | SHA-256 Merkle tree for integrity verification |
| `VOXL` | Embedded Scene | No | Optional (opaque) | Yes | Complete VOXL scene file for round-trip re-editing |
| `EXTD` | Extension | No | Per-extension: refuse a `critical` one you do not implement | Per-extension | Vendor-specific or future standard extensions |

The **Required** column is about presence in a file: what an encoder must write. **Reader
support** is the separate obligation on the other side, and the two do not line up - a
chunk may be optional to write and still mandatory to honor. An entry that says *Required*
means a reader that cannot meet it MUST refuse the file rather than print an approximation
of it. The chunks that carry the print itself - `HEAD`, `META`, `LTBL`, `LAYR` - are joined
there by `LROV`, because a printer that ignores overrides prints those layers at the wrong
exposure, and nothing in the file says so afterwards.
