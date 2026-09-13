# Print control chunks

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

### 4.5 SECT - Sector Definition Chunk

**Type tag:** `SECT` (`0x53 0x45 0x43 0x54`). Optional, multiple allowed.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Required only when `MULTI_SECTOR` flag is set. Defines a material/exposure sector.

```jsonc
{
  "sector_id": 1,
  "name": "Support Material",
  "material_index": 1,
  "color_rgba": [0, 255, 0, 128],

  // Any timing field from META can be overridden per-sector:
  "normal_exposure_sec": 3.0,
  "bottom_exposure_sec": 35.0
  // ... (all META timing fields are valid here)
}
```

- `sector_id` 0 is reserved for the implicit primary/default sector. SECT chunks must use `sector_id >= 1`.
- All `sector_id` values must be unique within the file.
- `material_index` indexes `META.materials` (or `PROF.materials`, when the profile
  supplies the library) and defaults to `0` when absent. When present, the referenced
  array MUST exist, be non-empty, and contain the index.
- `color_rgba` is a display hint that overrides the referenced material's colour for
  this sector; it does not affect exposure.
- If a timing field is absent, the sector inherits from META defaults.
- A single-material printer can ignore all `SECT` chunks and decode only sector 0;
  see [§7.2](10-sectors.md#72-sector-0-convention-and-single-material-degradation) for the completeness caveat.

**Sector composition invariant:** For a given layer, every exposed pixel belongs to
exactly one sector, and the union of the sector masks is the full layer image ([§7.3](10-sectors.md#73-sector-mask-invariant)).

### 4.6 LROV - Layer Override Chunk

**Type tag:** `LROV` (`0x4C 0x52 0x4F 0x56`). Optional.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Per-layer timing parameter overrides. A file carries at most one `LROV` chunk; if more
than one is present, readers use the first.

```jsonc
{
  "overrides": [
    {
      "layer": 100,
      "normal_exposure_sec": 2.8,
      "lift_slow_distance_um": 6000
    },
    {
      "layer_range": [200, 250],
      "sector_id": 1,
      "normal_exposure_sec": 2.2,
      "wait_time_before_cure_sec": 0.5
    }
  ]
}
```

- Layer indices are 0-based (layer 0 = closest to build plate).
- `layer_range` is inclusive `[start, end]`.
- An entry MUST carry exactly one of `layer` or `layer_range`; an entry with both or
  neither is malformed.
- `sector_id` is optional. When present, the entry applies only to that sector on the
  matched layer(s); when absent, it applies to every sector.
- When several entries match a given `(layer, sector)` pair, the **last** matching
  entry wins. Because an entry without `sector_id` matches every sector, a later
  sector-specific entry overrides it for that sector only.
- Layers with no matching entry use META (or SECT) defaults; LROV never removes them.

### 4.7 PREV - Preview Image Chunk

**Type tag:** `PREV` (`0x50 0x52 0x45 0x56`). Optional, multiple allowed.

**Flags:** uncompressed (PNG is already compressed). Encryption optional.

A PNG image as raw bytes (no additional framing).

**Chunk flags:**

| Bit | Name | Description |
|-----|------|-------------|
| 0–3 | `preview_role` | 0 = unspecified, 1 = large (rec. 400×300), 2 = small (rec. 200×125), 3 = icon (≤64×64). Role values 4–15 are reserved. |
| 4 | `ENCRYPTED` | May be set if preview confidentiality is desired. |
| 5–31 | - | Reserved. Must be 0. |

Multiple PREV chunks are permitted. Readers should select the best preview for
their display based on `preview_role`.
