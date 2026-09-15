# Chunk types

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 4. Chunk Types

A LUMEN file is composed of typed chunks. The table below summarizes every
chunk defined by this specification. Developers can scan this to understand
the file's capabilities at a glance; detailed binary layouts follow.

| Tag | Name | Required | Reader support | Encrypted | Purpose |
|-----|------|----------|----------------|-----------|---------|
| `HDR\0` | Header | Yes | Required | No | Display dimensions, layer count, encoder identity |
| `META` | Metadata | Yes | Required | Yes | Print parameters as JSON (exposure, lift, motion) |
| `PROF` | Print Profile | No | Optional | Yes | Named, versioned, reusable profile for Odyssey import |
| `AUTH` | Authentication | No | Required when the file is encrypted | No | Encryption metadata, key wrapping, machine binding |
| `LROV` | Layer Override | No | **Required** - refuse a file you cannot honor ([§4.6](05-print-control.md#46-lrov---layer-override-chunk)) | Yes | Timing overrides for one `(layer, sector)` pair |
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
of it. The chunks that carry the print itself - `HDR`, `META`, `LTBL`, `LAYR` - are joined
there by `LROV`, because a printer that ignores overrides prints those layers at the wrong
exposure, and nothing in the file says so afterwards.

### 4.1 HDR - File Header Chunk

**Type tag:** `HDR\0` (`0x48 0x44 0x52 0x00`). Required. Must be the first chunk.

**Flags:** uncompressed, unencrypted.

Carries display and build dimensions. Separated from the fixed header so it can grow
across format versions without changing the 32-byte magic header.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `hdr_version` | Layout version. `1` for this spec. |
| 4 | 4 | `u32` | `encoder_name_len` | Byte length of `encoder_name`. |
| 8 | N | `[u8; N]` | `encoder_name` | UTF-8. e.g. `"DragonFruit 1.0"`. |
| 8+N | 8 | `u64` | `created_unix_sec` | Unix timestamp (seconds). |
| 16+N | 4 | `u32` | `display_width_px` | Logical display width. |
| 20+N | 4 | `u32` | `display_height_px` | Logical display height. |
| 24+N | 4 | `u32` | `physical_width_px` | Physical LCD panel width in pixels (e.g. 11520 for a 12K display). |
| 28+N | 4 | `u32` | `physical_height_px` | Physical LCD panel height in pixels. |
| 32+N | 4 | `u32` | `build_width_um` | Build plate X dimension, in micrometers. |
| 36+N | 4 | `u32` | `build_depth_um` | Build plate Y dimension, in micrometers. |
| 40+N | 4 | `u32` | `build_height_um` | Build plate Z dimension, in micrometers. |
| 44+N | 4 | `u32` | `layer_height_um` | Default layer thickness, in micrometers. |
| 48+N | 4 | `u32` | `total_layers` | Total layer count. |

**Display readiness.** Layer masks are stored exactly as the printer must expose them.
Mirroring (`mirror_x` / `mirror_y` in the slicer's build settings) is applied by the
slicer before encoding, and pixel values are already scaled to the panel's bit depth.
The file header therefore carries no mirror, rotation or bit-depth field, and a reader MUST NOT
apply an additional transform. Firmware-side mirroring is a calibration concern that
belongs to the printer, not the file ([§1.1](01-overview.md#11-what-lumen-is-not)).

### 4.2 META - Metadata Chunk

**Type tag:** `META` (`0x4D 0x45 0x54 0x41`). Required.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Human-readable print parameters as a single JSON object.

**Required fields:**

```jsonc
{
  "meta_version": 1,
  "normal_exposure_ms": 2500,
  "bottom_exposure_ms": 30000,
  "bottom_layer_count": 4,
  "transition_layer_count": 8,
  "layer_height_um": 50,
  "lift_slow_distance_um": 5000,
  "lift_slow_speed_um_min": 65000,
  "retract_fast_distance_um": 5000,
  "retract_fast_speed_um_min": 150000
}
```

**Optional fields:**

```jsonc
{
  // Two-stage motion: a lift runs slow then fast, a retract fast then slow.
  "lift_fast_distance_um": 3000,
  "lift_fast_speed_um_min": 180000,
  "retract_slow_distance_um": 3000,
  "retract_slow_speed_um_min": 180000,

  // Bottom-layer overrides (inherit from normal if absent)
  "bottom_lift_slow_distance_um": 6000,
  "bottom_lift_slow_speed_um_min": 50000,
  "bottom_lift_fast_distance_um": 4000,
  "bottom_lift_fast_speed_um_min": 120000,
  "bottom_retract_fast_distance_um": 6000,
  "bottom_retract_fast_speed_um_min": 100000,
  "bottom_retract_slow_distance_um": 4000,
  "bottom_retract_slow_speed_um_min": 120000,

  // Wait/rest times (milliseconds)
  "wait_time_before_cure_ms": 1000,
  "wait_time_after_cure_ms": 0,
  "wait_time_after_lift_ms": 500,
  "bottom_wait_time_before_cure_ms": 1500,
  "bottom_wait_time_after_cure_ms": 0,
  "bottom_wait_time_after_lift_ms": 1000,

  // PWM (0–255, default 255)
  "light_pwm": 255,
  "bottom_light_pwm": 255,

  // Temperature control - target temperatures in Celsius (optional)
  // Omitted or null = printer default (unheated)
  "chamber_temperature_c": 30.0,
  "vat_temperature_c": 28.0,

  // Resin working curve - experimental, for future physics-based exposure
  // calculation by Odyssey firmware. If omitted, the printer falls back to
  // the traditional exposure-time model.
  "cure_curve": {
    "dp_um": 120,           // Penetration depth (μm) - how deep UV penetrates before dropping to 1/e
    "ec_mj_cm2": 7.5,         // Critical exposure (mJ/cm²) - energy at which resin begins to cure
    "e0_mj_cm2": 3.0          // Base energy (mJ/cm²) - energy absorbed before polymerization starts
  },

  // Anti-aliasing (informational)
  "anti_aliasing": {
    "enabled": true,
    "level": 8,
    "mode": "blur",
    "minimum_alpha_percent": 35.0
  },

  // Material library. One entry per distinct material used by this print.
  // `META.sectors[].material_index` indexes into this array; sector 0 defaults to index 0.
  "materials": [
    {
      "name": "Standard Grey",
      "brand": "DragonFruit",
      "family": "standard",
      "density_g_ml": 1.1,
      "color_rgba": [128, 128, 128, 255]
    }
  ],

  // Per-sector base timing and optional identity. One entry per sector >= 1;
  // sector 0 has no entry and resolves from META alone. Absent fields are
  // inherited from META field by field, and any timing field may appear here.
  "sectors": [
    {
      "sector_id": 1,                 // required, unique, >= 1
      "material_index": 1,            // optional, indexes META.materials
      "color_rgba": [0, 255, 0, 128],  // optional display hint; does not affect exposure
      "name": "Support",              // optional
      "normal_exposure_ms": 3000,     // and any other META timing field
      "bottom_layer_count": 5
    }
  ],

  // Printer identity
  "printer": {
    "name": "Ares 12K",
    "manufacturer": "Open Resin Alliance",
    "firmware_version": "2.1.0",
    "serial": ""
  },

  // Scale compensation (percent)
  "scale_compensation_pct": { "x": 0.0, "y": 0.0, "z": 0.0 },

  // Estimates (informational)
  "estimated_print_time_sec": 14400,
  "estimated_resin_volume_ml": 42.5,

  // Slicer attribution
  "slicer": {
    "name": "DragonFruit",
    "version": "1.0.0",
    "url": "https://openresin.org"
  },

  // Custom key-value metadata
  "extra": {}
}
```

**Motion model.** Lift and retract are each performed in two segments, and a
`*_distance*` field is the length of one segment, not a total:

| Segment | Distance | Speed |
|---------|----------|-------|
| Lift, slow - the peel, to break the layer away from the film | `lift_slow_distance_um` | `lift_slow_speed_um_min` |
| Lift, fast - the remainder of the lift | `lift_fast_distance_um` | `lift_fast_speed_um_min` |
| Retract, fast - most of the return | `retract_fast_distance_um` | `retract_fast_speed_um_min` |
| Retract, slow - the final approach | `retract_slow_distance_um` | `retract_slow_speed_um_min` |

A lift runs its slow segment first and its fast segment second; a retract runs its fast
segment first and its slow segment second. The name says which segment it is, so the order
of execution is never in doubt, and it is the same fact in both directions - which is why
the fields are named for the role rather than numbered, since the first segment of a lift
is the slow one and the first segment of a retract is the fast one.

The name does not constrain the speeds: an encoder may set either segment faster than the
other, and a validator must not require that the slow segment is the slower of the two. The
name describes the part the segment plays in the move, not a comparison.

The total travel of a move is the sum of its two segments. A segment whose distance or speed
is `0` is not performed, so a single-stage move is the degenerate case: a single-stage lift
sets `lift_fast_distance_um` to `0`, and a single-stage retract sets `retract_slow_distance_um`
to `0`. The `bottom_*` fields follow the same model.

**Field resolution for readers:**

1. Start with META's values as defaults for all layers. For a sector `>= 1`, its entry in `META.sectors` replaces META's value for every field it carries, so a sector resolves field by field; a sector with no entry, sector 0 included, resolves from META alone.
2. Apply bottom/transition blending over the ranges that sector resolves with: layers in its bottom range use bottom-prefixed values; layers in its transition range interpolate between bottom and normal values ([§8](11-layer-timing.md#8-per-layer-settings-model) defines the formula and which fields participate).
3. If the `(layer, sector)` pair's layer table entry carries a non-zero `first_lrov`, apply the fields that `LROV` chunk holds ([§4.6](05-print-control.md#46-lrov---layer-override-chunk)).
4. **Absent fields.** A field META does not carry, that the sector's `META.sectors` entry does not supply for the sector and that the pair's `LROV` chunk does not override, resolves to `0` for a distance, speed or duration - a segment or a pause that is not performed - and to `255` for `light_pwm`. Absent does not mean "whatever the implementation usually does": two readers must resolve the same file to the same numbers, so an encoder that leaves a field out is asking for zero. A field with no meaning to zero is not in this class, and is absent rather than zero when META does not carry it: `chamber_temperature_c` and `vat_temperature_c` are targets the printer uses or does not, and the `cure_curve` is either present or not.

See [§8](11-layer-timing.md#8-per-layer-settings-model) for the complete layer timing pipeline.

**Materials:** `materials` is the authoritative material library for this print.
`META.sectors[].material_index` indexes it and defaults to `0`. A single-material print carries
a one-element array and sector 0 uses element 0. If `materials` is absent, material
identity is unknown and consumers fall back to their own default.

**Sectors:** `sectors` is optional. An entry carries the base timing for one sector `>= 1` and
whatever identity that sector has; sector 0 has no entry, and a sector that has no entry
resolves from META alone with no material of its own - which is the default, since a sector
carries no material unless `material_index` says it does. Each entry is a JSON object with a
required `sector_id` (`>= 1`, unique among the entries); a file MUST NOT carry two entries
with the same `sector_id`. Every timing field is optional and inherited per field, and that
covers the layer counts like any other timing field: an entry may carry `bottom_layer_count`
and `transition_layer_count` of its own, and one that does is blended over **its own** bottom
and transition ranges. Its bottom range can be longer than META's, its transition steps land
on different layers, and two sectors in one file can disagree about where the bottom range
ends - which is the point, since a support material and a model resin rarely want the same
one ([§8](11-layer-timing.md#8-per-layer-settings-model)). When `material_index` is present
the referenced `materials` array MUST exist, be non-empty and contain that index. `color_rgba`
is a display hint that overrides the referenced material's color for this sector; it does not
affect exposure.


Lengths are integer micrometers, speeds integer micrometers per minute, and durations
integer milliseconds, so a reader compares them exactly instead of within a tolerance. The
one duration not in milliseconds is META's `estimated_print_time_sec`, an informational
estimate reported in whole seconds: a print that runs for hours is not known to the
millisecond, and reporting one would claim a precision nothing in the format supports. An
encoder holding a finer value rounds to the nearest unit; nothing below one unit is
expressible, and no field carries a fractional micrometer, millisecond or second. The
remaining numeric fields - energy densities, temperatures, percentages and densities - are
ordinary JSON numbers, and readers must accept both integer and floating-point syntax for
those. Readers must ignore unknown JSON keys.

Durations are whole numbers, and there are no exceptions to that: every `*_ms` field holds
an integer number of milliseconds and `estimated_print_time_sec` an integer number of
seconds. A value with a fractional part (`2500.5`, or `14400.5` for an estimate) is
invalid, and an encoder MUST write integer syntax. A reader MAY additionally reject
integral floating-point syntax such as `2500.0`; a file MUST NOT depend on which of the two
a reader does, so no file may carry `2500.0` where `2500` is meant.

### 4.3 PROF - Print Profile Chunk

**Type tag:** `PROF` (`0x50 0x52 0x4F 0x46`). Optional.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Carries a **named, versioned, reusable print profile** that Odyssey-compatible
printer firmware can import into its profile library. This is distinct from META:
META defines the resolved parameters for this specific print job; PROF defines a
reusable profile that can be saved, shared, and applied to future prints.

When a LUMEN-capable printer receives a file with a `PROF` chunk, it may:
- Use the file's META settings directly (the default).
- Import the PROF profile into its local profile store for future use.
- Apply a printer-side override profile instead of either.

A file carries at most one `PROF` chunk; if more than one is present, readers use the
first.

**PROF JSON schema:**

```jsonc
{
  // Required: profile identity
  "profile_name": "ABS-Like Grey - 12K",
  "profile_version": "1.2.0",
  "profile_type": "combined",       // "material", "printer", or "combined"

  // Optional but recommended: unique identifier for deduplication
  "profile_uuid": "550e8400-e29b-41d4-a716-446655440000",

  // Optional: attribution
  "author": "DragonFruit 1.0",
  "created_unix_sec": 1710000000,
  "description": "ABS-like grey resin, optimized for 12K printers",

  // Optional: printer compatibility hints
  "compatible_printers": [
    {
      "manufacturer": "Open Resin Alliance",
      "model_pattern": "Ares 12K*",
      "display_width_px": 11520,
      "display_height_px": 6480,
      "pixel_size_um": 19
    }
  ],

  // Optional: printer definition (when profile_type = "printer" or "combined")
  "printer": {
    "name": "Ares 12K",
    "manufacturer": "Open Resin Alliance",
    "display_width_px": 11520,
    "display_height_px": 6480,
    "pixel_size_um": 19,
    "build_width_um": 218000,
    "build_depth_um": 123000,
    "build_height_um": 250000,
    "bit_depth": 8
  },

  // Required: all timing and motion settings (same field names as META)
  "settings": {
    "layer_height_um": 50,
    "normal_exposure_ms": 2500,
    "bottom_exposure_ms": 30000,
    "bottom_layer_count": 4,
    "transition_layer_count": 8,

    "lift_slow_distance_um": 5000,
    "lift_slow_speed_um_min": 65000,
    "retract_fast_distance_um": 5000,
    "retract_fast_speed_um_min": 150000,

    "lift_fast_distance_um": 3000,
    "lift_fast_speed_um_min": 180000,
    "retract_slow_distance_um": 3000,
    "retract_slow_speed_um_min": 180000,

    "bottom_lift_slow_distance_um": 6000,
    "bottom_lift_slow_speed_um_min": 50000,
    "bottom_lift_fast_distance_um": 4000,
    "bottom_lift_fast_speed_um_min": 120000,
    "bottom_retract_fast_distance_um": 6000,
    "bottom_retract_fast_speed_um_min": 100000,
    "bottom_retract_slow_distance_um": 4000,
    "bottom_retract_slow_speed_um_min": 120000,

    "wait_time_before_cure_ms": 1000,
    "wait_time_after_cure_ms": 0,
    "wait_time_after_lift_ms": 500,
    "bottom_wait_time_before_cure_ms": 1500,
    "bottom_wait_time_after_cure_ms": 0,
    "bottom_wait_time_after_lift_ms": 1000,

    "light_pwm": 255,
    "bottom_light_pwm": 255,

    // Temperature control - target temperatures in Celsius (optional)
    "chamber_temperature_c": 30.0,
    "vat_temperature_c": 28.0,

    // Resin working curve - experimental ([§5.7](08-layer-encoding.md#57-resin-working-curve-experimental)). If omitted, printer falls back
    // to traditional exposure-time model.
    "cure_curve": {
      "dp_um": 120,
      "ec_mj_cm2": 7.5,
      "e0_mj_cm2": 3.0
    }
  },

  // Optional: anti-aliasing preferences
  "anti_aliasing": {
    "enabled": true,
    "level": 8,
    "mode": "blur",
    "minimum_alpha_percent": 35.0,
    "blur_brush_radius_px": 4,
    "blur_brush_kernel": "gaussian",
    "blur_brush_sigma_x": 2.0,
    "blur_brush_sigma_y": 2.0,
    "z_blend_look_back": 3,
    "z_blend_fade_px": 200,
    "dither_enabled": false
  },

  // Optional: material library (same entry schema and indexing as META.materials)
  "materials": [
    {
      "name": "ABS-Like Grey",
      "brand": "DragonFruit",
      "family": "abs-like",
      "density_g_ml": 1.1,
      "color_rgba": [128, 128, 128, 255],
      "bottle_price": 29.99,
      "bottle_capacity_ml": 1000
    }
  ],

  // Optional: scale compensation
  "scale_compensation_pct": { "x": 0.5, "y": 0.5, "z": 0.0 },

  // Optional: custom vendor/slicer metadata
  "extra": {}
}
```

**Design notes:**
- The `settings` namespace uses the same field names as META so a printer can
  trivially use a PROF as the source of default print parameters.
- `profile_uuid` enables the printer to detect duplicate imports (same profile
  already in the library).
- `compatible_printers` provides hints so the printer can warn if a profile was
  designed for different hardware (different pixel size, resolution, etc.).
- When both META and PROF are present, META is authoritative for this print job.
  PROF is the reusable template that MAY have been used to produce META, but
  META may diverge (e.g., if the user tweaked exposure for this specific print).
- `extra` carries vendor-specific profile metadata (e.g., DragonFruit's internal
  profile store serialization format).
