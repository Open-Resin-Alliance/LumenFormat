# Scene and extension chunks

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

### 4.12 VOXL - Embedded Scene Chunk

**Type tag:** `VOXL` (`0x56 0x4F 0x58 0x4C`). Optional.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Embeds the complete DragonFruit VOXL scene file that produced this print. This
makes the `.lumen` file a **self-contained, re-editable project** - the user
never loses the source. Any compatible slicer can extract the VOXL, restore the
full scene (models, supports, modifiers, hollowing state), and continue editing
as if the file had never been closed.

**Payload:** The raw bytes of a VOXL file (see `DragonFruit/docs/dev/voxl-format-spec.md`).
V2 binary chunk format is the current target; V1 JSON is also valid. The VOXL carries its
own internal version field for format detection.

**Workflow:**

1. **Save:** DragonFruit slices a scene → writes `.lumen` with the VOXL chunk
   embedded alongside the print data. One file contains everything.
2. **Re-open:** DragonFruit opens a `.lumen` file → detects the `VOXL` chunk →
   extracts and parses the VOXL → restores the full editable scene (models,
   supports, modifiers, hollowing snapshots).
3. **Round-trip:** Edit → re-slice → overwrite `.lumen` with updated VOXL and
   new print layers. The file IS the project.
4. **Sharing:** Send one `.lumen` file. The recipient can print it (printer) or
   edit it (slicer). No separate `.voxl` sidecar.

**Design notes:**
- The VOXL chunk is optional. A `.lumen` file without it is still a valid
  printable file - it just cannot be re-edited (the source scene is missing).
- Only one `VOXL` chunk should be present. If multiple are present, readers
  should use the first one.
- The VOXL payload is zstd-compressed for storage efficiency. VOXL V2 already
  uses zlib internally; recompressing the whole file with zstd is expected to
  yield additional size reduction.
- Encrypted alongside other sensitive chunks when `AUTH` is present - scene
  geometry may be proprietary.

**Relationship to other chunks:**
- `HDR.display_width_px` etc. should match the VOXL scene's intended printer.
- `META.materials` / `PROF.materials` should match the resin(s) used in the VOXL scene.
- A reader can validate consistency between the VOXL scene metadata and the
  LUMEN print parameters (strict mode).

### 4.13 EXTD - Extension Chunk

**Type tag:** `EXTD` (`0x45 0x58 0x54 0x44`). Optional, multiple allowed.

**Flags:** zstd-compressed (unless the extension specifies otherwise).

Vendor or future-standard extension data.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `ext_version` | Extension format version. |
| 4 | 4 | `[u8; 4]` | `ext_type` | Four-char ASCII type code. |
| 8 | N | - | `ext_data` | Extension-specific payload. |

**Chunk flags:**

| Bit | Name | Description |
|-----|------|-------------|
| 0–7 | - | Reserved for standard chunk flags (bit 4 = `ENCRYPTED`, see [§3.2](02-file-structure.md#32-chunk-descriptor)). |
| 8–23 | `vendor_id` | Vendor identifier (registered with ORA). `0x0000` = ORA standard extension. |
| 24 | `critical` | If set, a reader that does not recognize this extension must refuse to print. |
| 25–31 | - | Reserved. Must be 0. |

Readers skip unknown EXTD chunks (or refuse if `critical` is set).

**Reserved ORA-standard extension types (`vendor_id = 0`):**

| `ext_type` | Name | Purpose |
|------------|------|---------|
| `SIGN` | Signature | Cryptographic signature for file authenticity. |
| `VLYR` | Variable Layers | Per-layer height values. Reserved for a future core mechanism; not usable in v1 ([§5.7](08-layer-encoding.md#57-resin-working-curve-experimental)). |
| `CMLT` | Compression ML | Training metadata for the `ZDIC` dictionary (corpus size, training parameters). |
| `CMAP` | Color Map | Per-sector color channel mapping for multi-color printing. |
