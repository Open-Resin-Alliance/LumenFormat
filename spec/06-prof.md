# Print profile chunk

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

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

    // Resin working curve - experimental ([§5.8](11-layer-encoding.md#58-resin-working-curve-experimental)). If omitted, printer falls back
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
