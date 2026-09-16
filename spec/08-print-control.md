# Print control chunks

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 4.5 LROV - Layer Override Chunk

**Type tag:** `LROV` (`0x4C 0x52 0x4F 0x56`). Optional, multiple allowed - one chunk per
`(layer, sector)` pair that has overrides.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Carries the timing parameters one `(layer, sector)` pair overrides, as a JSON object under
META's field names:

```jsonc
{
  "normal_exposure_ms": 2800,
  "lift_slow_distance_um": 6000,
  "wait_time_before_cure_ms": 500
}
```

Which pair the chunk belongs to is not in the payload: the pair's layer table entry carries
`first_lrov`, either `0` (no overrides) or the directory index of the chunk holding them
([§4.7](09-layer-data.md#47-ltbl---layer-table-chunk)). Nothing else points at the chunk, and
every `LROV` chunk is named by exactly one entry, so a chunk's values are applied to the pair
that names it and to no other.

- The object carries **only** the fields that pair overrides. A field it omits keeps the
  value the pair resolves without it: the object is a sparse delta, never a replacement
  set, and there is no array of entries and no fold rule - a pair has one override set or
  none, so nothing has to decide between two of them.
- Any field META carries a value for may appear, with META's names and units: integer
  milliseconds for durations, micrometers for lengths, micrometers per minute for speeds.
  The layer counts may appear too, and they do not move the ramp: the blend uses the counts
  the pair's sector resolves before any override, so an override of `bottom_layer_count` sets
  that field's value for the pairs it is applied to and leaves the ranges where they were
  ([§8](14-layer-timing.md#8-per-layer-settings-model)).
- Overrides are applied after the sector's bottom/transition blending
  ([§8](14-layer-timing.md#8-per-layer-settings-model)), so a field an `LROV` chunk carries
  is the value the layer is printed with, whatever range it falls in.

**Reader support: REQUIRED.** Writing the chunk is the encoder's choice - a slicer may write
per-layer settings or leave them out, and a file that needs no overrides is complete without
one. Honoring it is not a choice. A conforming reader MUST apply the overrides of every
`LROV` chunk that a layer it prints points at, and a reader that does not implement overrides
MUST refuse a file in which any layer table entry carries a non-zero `first_lrov`, rather
than print that pair at the values its sector resolves to on its own.

The reason is that this is the one degradation a printer cannot notice. A layer printed at
its sector's exposure instead of its override is a print that fails quietly: the file is
structurally valid, every checksum still passes, and nothing in the output says a chunk was
ignored. So the rule is the same one [§4.12](10-scene-chunks.md#412-extd---extension-chunk)
applies to an unimplemented `critical` extension, and the same principle as
[§7.2](13-sectors.md#72-sector-0-convention-and-single-material-degradation): a capability a
reader lacks makes a file unprintable to it, not printable with approximations. A slicer
that knows its target cannot honor overrides should not write them; a printer that meets
them must.

## 4.6 PREV - Preview Image Chunk

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
