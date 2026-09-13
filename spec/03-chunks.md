# Chunk types

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 4. Chunk Types

A LUMEN file is composed of typed chunks. The table below summarizes every
chunk defined by this specification. Developers can scan this to understand
the file's capabilities at a glance; detailed binary layouts follow.

| Tag | Name | Required | Encrypted | Purpose |
|-----|------|----------|-----------|---------|
| `HDR\0` | Header | Yes | No | Display dimensions, layer count, encoder identity |
| `META` | Metadata | Yes | Yes | Print parameters as JSON (exposure, lift, motion) |
| `PROF` | Print Profile | No | Yes | Named, versioned, reusable profile for Odyssey import |
| `AUTH` | Authentication | No | No | Encryption metadata, key wrapping, machine binding |
| `SECT` | Sector Definition | No* | Yes | Per-material exposure groups for multi-material printing |
| `LROV` | Layer Override | No | Yes | Per-layer or per-range timing overrides |
| `PREV` | Preview Image | No | Optional | PNG preview images, multiple roles supported |
| `LTBL` | Layer Table | Yes | No | Per-layer block index and byte offsets for random access |
| `ZDIC` | Zstd Dictionary | No | Yes | Trained dictionary shared by all LAYR block frames |
| `LAYR` | Layer Data | Yes | Yes | Layer masks as independent zstd block frames |
| `LHAS` | Layer Hashes | No | No | SHA-256 Merkle tree for integrity verification |
| `VOXL` | Embedded Scene | No | Yes | Complete VOXL scene file for round-trip re-editing |
| `EXTD` | Extension | No | Per-extension | Vendor-specific or future standard extensions |

\* Required when `MULTI_SECTOR` flag is set.

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
| 32+N | 4 | `u32` | `build_width_um` | Build plate X dimension, in micrometres. |
| 36+N | 4 | `u32` | `build_depth_um` | Build plate Y dimension, in micrometres. |
| 40+N | 4 | `u32` | `build_height_um` | Build plate Z dimension, in micrometres. |
| 44+N | 4 | `u32` | `layer_height_um` | Default layer thickness, in micrometres. |
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
  "normal_exposure_sec": 2.5,
  "bottom_exposure_sec": 30.0,
  "bottom_layer_count": 4,
  "transition_layer_count": 8,
  "layer_height_um": 50,
  "lift_distance_um": 5000,
  "lift_speed_um_min": 65000,
  "retract_distance_um": 5000,
  "retract_speed_um_min": 150000
}
```

**Optional fields:**

```jsonc
{
  // Two-stage motion
  "lift_distance2_um": 3000,
  "lift_speed2_um_min": 180000,
  "retract_distance2_um": 3000,
  "retract_speed2_um_min": 180000,

  // Bottom-layer overrides (inherit from normal if absent)
  "bottom_lift_distance_um": 6000,
  "bottom_lift_speed_um_min": 50000,
  "bottom_lift_distance2_um": 4000,
  "bottom_lift_speed2_um_min": 120000,
  "bottom_retract_distance_um": 6000,
  "bottom_retract_speed_um_min": 100000,
  "bottom_retract_distance2_um": 4000,
  "bottom_retract_speed2_um_min": 120000,

  // Wait/rest times (seconds)
  "wait_time_before_cure_sec": 1.0,
  "wait_time_after_cure_sec": 0.0,
  "wait_time_after_lift_sec": 0.5,
  "bottom_wait_time_before_cure_sec": 1.5,
  "bottom_wait_time_after_cure_sec": 0.0,
  "bottom_wait_time_after_lift_sec": 1.0,

  // Delay mode: "light_off" or "wait_time". Defaults to "light_off" if omitted.
  "delay_mode": "light_off",
  "light_off_delay_sec": 1.0,
  "bottom_light_off_delay_sec": 1.0,

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
  // SECT.material_index indexes into this array; sector 0 defaults to index 0.
  "materials": [
    {
      "name": "Standard Grey",
      "brand": "DragonFruit",
      "family": "standard",
      "density_g_ml": 1.1,
      "color_rgba": [128, 128, 128, 255]
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
| Lift 1 - slow peel, to break the layer away from the film | `lift_distance_um` | `lift_speed_um_min` |
| Lift 2 - fast, the remainder of the lift | `lift_distance2_um` | `lift_speed2_um_min` |
| Retract 1 - fast, most of the return | `retract_distance_um` | `retract_speed_um_min` |
| Retract 2 - slow final approach | `retract_distance2_um` | `retract_speed2_um_min` |

The total travel of a move is the sum of its two segments. A segment whose distance
or speed is `0.0` is not performed, so a single-stage move is the degenerate case:
set the `*2` fields to `0.0`. The `bottom_*` fields follow the same model.

**Field resolution for readers:**

1. Start with META values as defaults for all layers (and SECT values per-sector, if multi-sector).
2. Apply bottom/transition blending: layers in the bottom range use bottom-prefixed values; layers in the transition range interpolate between bottom and normal values ([§8](11-layer-timing.md#8-per-layer-settings-model) defines the formula and which fields participate).
3. If `LROV` chunk present, override specific fields for specific layers (last matching entry wins).

See [§8](11-layer-timing.md#8-per-layer-settings-model) for the complete layer timing pipeline.

**Materials:** `materials` is the authoritative material library for this print.
`SECT.material_index` indexes it and defaults to `0`. A single-material print carries
a one-element array and sector 0 uses element 0. If `materials` is absent, material
identity is unknown and consumers fall back to their own default.

Lengths are integer micrometres and speeds integer micrometres per minute, so a reader
compares them exactly instead of within a tolerance. An encoder holding a finer value
rounds to the nearest unit; a length or speed below one unit is not expressible, and no
field carries a fractional micrometre. The remaining numeric fields - exposure and wait
times, energy densities, temperatures, percentages, densities - are ordinary JSON numbers,
and readers must accept both integer and floating-point syntax for those. Readers must
ignore unknown JSON keys.

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
    "normal_exposure_sec": 2.5,
    "bottom_exposure_sec": 30.0,
    "bottom_layer_count": 4,
    "transition_layer_count": 8,

    "lift_distance_um": 5000,
    "lift_speed_um_min": 65000,
    "retract_distance_um": 5000,
    "retract_speed_um_min": 150000,

    "lift_distance2_um": 3000,
    "lift_speed2_um_min": 180000,
    "retract_distance2_um": 3000,
    "retract_speed2_um_min": 180000,

    "bottom_lift_distance_um": 6000,
    "bottom_lift_speed_um_min": 50000,
    "bottom_lift_distance2_um": 4000,
    "bottom_lift_speed2_um_min": 120000,
    "bottom_retract_distance_um": 6000,
    "bottom_retract_speed_um_min": 100000,
    "bottom_retract_distance2_um": 4000,
    "bottom_retract_speed2_um_min": 120000,

    "wait_time_before_cure_sec": 1.0,
    "wait_time_after_cure_sec": 0.0,
    "wait_time_after_lift_sec": 0.5,
    "bottom_wait_time_before_cure_sec": 1.5,
    "bottom_wait_time_after_cure_sec": 0.0,
    "bottom_wait_time_after_lift_sec": 1.0,

    "delay_mode": "light_off",
    "light_off_delay_sec": 1.0,
    "bottom_light_off_delay_sec": 1.0,

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
  profile store serialisation format).
