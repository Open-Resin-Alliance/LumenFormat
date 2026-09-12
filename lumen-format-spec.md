# .lumen Format Specification v1.0

**Lead Developer:** Paul Skapczyk  
**Maintaining Authority:** Open Resin Alliance  
**Project:** Open Resin Alliance - Next-Generation Print File Format  
**Status:** Draft Specification  
**License:** MIT

---

## Abstract

The `.lumen` format is a next-generation, open-source print file format for resin
(MSLA) 3D printing, developed as part of the Open Resin Alliance ecosystem. It is
designed to complement the existing ORA infrastructure - serving as the native
output format for the **DragonFruit** slicer and the primary print format
consumed by **Odyssey** firmware (via its **Orion** frontend).

Existing container formats (CTB, GOO, AFZ, NanoDLP) were reverse-engineered from
proprietary ecosystems. They carry the legacy of fixed binary layouts, weak
compression, vendor obfuscation, and fundamental design constraints that limit
what next-generation hardware can achieve. Lumen breaks from this lineage
entirely. It is designed from first principles to be the most efficient,
flexible, and future-proof resin print format ever specified - with no
proprietary baggage and no compromises made for legacy compatibility.

This document is the normative specification for Lumen v1.0. It defines every
byte on disk, every semantic invariant, and every validation rule a conforming
reader or writer must observe.

### Reader's Guide

This document is written for two audiences, and structured so each can find
what they need without reading the whole thing:

| Audience | Recommended path |
|----------|-----------------|
| **Engineers evaluating Lumen** (product managers, engineering leads, curious hackers) | Read §1 (Design Philosophy), §2 (Core Conventions), the §4 chunk summary table, §5 intro, §6 intro, §9 intro, and §12 (Comparison). Skip binary layout tables unless you need them. |
| **Developers implementing Lumen** (encoder/decoder authors, firmware engineers) | Read everything. Start with §3 (File Structure) and §4 (Chunk Types) for the container, then §5 (Layer Mask Encoding) for the REE spec. Reference §11 (Validation) for your test plan. |

Sections marked with implementation-level binary tables assume the reader is
writing code against the format. Sections with broader prose and design
rationale are written for a general engineering audience.

---

## 1. Design Philosophy

Lumen is built on six principles that reflect the values of the Open Resin
Alliance:

1. **Compression efficiency first.** Modern 8K–12K printers produce 30–75
   megapixel layers. A 2,000-layer print at 12K resolution represents
   approximately 150 GB of raw pixel data before compression. Lumen combines
   Run-End Encoding (REE), zstd cross-layer dictionary compression, and a novel
   split encoding strategy for anti-aliased prints to push compressed file sizes
   as low as the underlying information theory allows.

2. **Human-inspectable metadata.** Print parameters, material definitions,
   per-layer overrides, and machine metadata are stored as structured JSON.
   A user can inspect these with standard tools. Binary encoding is reserved
   exclusively for layer masks and previews where it provides unambiguous value.

3. **Extensible by design.** A chunk-based container with typed sections ensures
   the format can grow without breaking existing readers. Unknown chunks are
   skipped. Known chunks carry version sub-fields so a future v2 reader can
   still parse v1 data without modification.

4. **Multi-material from the ground up.** Sectors (exposure groups) are a
   first-class concept, not an afterthought. Each layer can carry multiple
   independent masks, each with its own resin, exposure, and motion profile -
   ready for the multi-vat hardware that will define the next decade of resin
   printing.

5. **Per-layer settings.** Any timing parameter can be overridden for any layer
   or range of layers. This replaces the rigid "bottom layers, transition
   layers, normal layers" model that has constrained every existing format.

6. **Open and transparent.** No obfuscation, no mandatory encryption designed
   for vendor lock-in. Optional authenticated encryption is available for secure
   facilities that require confidentiality - but it is the user's choice, never
   the vendor's demand.

### 1.1 What Lumen Is Not

To avoid confusion with other parts of the ORA ecosystem, Lumen is explicitly
**not**:

- **Not a scene format.** Lumen carries resolved print data (layer masks,
  exposure settings, motion parameters). For editable 3D scenes with models,
  supports, and modifiers, see the VOXL format. Lumen can *embed* a VOXL scene
  (§4.12) for round-trip editing, but the format's primary purpose is print
  execution.

- **Not a streaming protocol.** Lumen is a file format, designed for storage
  and transfer as a complete unit. It is not intended for real-time printer
  control over a network.

- **Not a printer-specific format.** Lumen is printer-agnostic. It carries
  display dimensions and timing parameters that any compatible firmware can
  interpret. Printer-specific calibration data belongs in the firmware, not
  in the print file.

- **Not a replacement for existing formats - yet.** Lumen requires Odyssey
  firmware. Stock printers still need CTB, GOO, or other legacy formats.
  As Odyssey adoption grows, Lumen may replace them.

---

## 2. Core Conventions

| Property | Value |
|----------|-------|
| Extension | `.lumen` |
| Media type | `application/x-lumen` (provisional) |
| Magic bytes | `LUMN` (`0x4C 0x55 0x4D 0x4E`) |
| Endianness | Little-endian (all multi-byte integers) |
| Coordinate basis | Right-handed, Z-up |
| Units | Millimeters (`mm`), millimeters per minute (`mm/min`) |
| Range notation | `a..b` is half-open `[a, b)`. `for i in 0..N` iterates `i = 0, 1, ..., N-1`. |

Format detection: a `.lumen` file begins with the four ASCII bytes `LUMN`.

---

## 3. File Structure

A `.lumen` file is a chunk-based binary container with the directory placed at the
**end** of the file (like ZIP's central directory). This enables streaming writers to
append chunks in a single pass without knowing the final layout upfront.

```
+-------------------+
| File Header       |  32 bytes, fixed
+-------------------+
| Chunk 0           |  HDR (required, must be first)
+-------------------+
| Chunk 1           |  META (required)
+-------------------+
| Chunk 2           |  PROF (optional, reusable print profile)
+-------------------+
| Chunk 3           |  AUTH (optional, encryption metadata)
+-------------------+
| Chunk 4           |  SECT (optional, per-sector definitions)
+-------------------+
| Chunk 5           |  LROV (optional, per-layer overrides)
+-------------------+
| Chunk 6           |  ZDIC (optional, zstd dictionary for LAYR blocks)
+-------------------+
|       ...         |
+-------------------+
| Chunk N           |  (any remaining chunks in any order)
+-------------------+
| Chunk Directory   |  chunk_count × 32 bytes
+-------------------+
| Directory Trailer |  8 bytes: "LEND" + CRC-32C
+-------------------+
```

Only HDR must be the first chunk. All other chunks may appear in any order;
the layout above is a recommendation, not a requirement. Readers must tolerate
any ordering.

### 3.1 File Header

32 bytes, fixed. Always at offset 0.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `magic` | `LUMN` (`0x4C 0x55 0x4D 0x4E`) |
| 4 | 4 | `u32` | `version` | File format version. `1` for this spec. |
| 8 | 8 | `u64` | `dir_offset` | Byte offset from start of file to Chunk Directory. |
| 16 | 4 | `u32` | `chunk_count` | Total number of chunks (matching directory entries). |
| 20 | 4 | `u32` | `flags` | Bitfield. See below. |
| 24 | 8 | `u64` | `total_uncompressed_size` | Sum of uncompressed sizes of all chunks. `0` = unknown (streaming writers). |

**Flags bitfield (bit 0 = LSB):**

| Bit | Name | Description |
|-----|------|-------------|
| 0 | `HAS_PREVIEW` | File contains ≥1 `PREV` chunk. |
| 1 | `MULTI_SECTOR` | File uses sector-based (multi-material) layer encoding. |
| 2 | `HAS_EXTENSIONS` | File contains ≥1 `EXTD` chunk. |
| 3 | `ENCRYPTED` | File contains an `AUTH` chunk; sensitive chunks are encrypted. |
| 4 | `HAS_LAYER_HASHES` | File contains an `LHAS` chunk with per-layer SHA-256 hashes and Merkle root. |
| 5–31 | - | Reserved. Must be 0. Readers must ignore unknown flags. |

### 3.2 Chunk Descriptor

Each entry in the Chunk Directory is 32 bytes.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `chunk_type` | Four ASCII characters. e.g. `HDR\0`, `META`. |
| 4 | 8 | `u64` | `offset` | Absolute byte offset from start of file to chunk payload. `0` = null descriptor (skip). |
| 12 | 8 | `u64` | `size_uncompressed` | Size of chunk payload after decompression. |
| 20 | 8 | `u64` | `size_compressed` | Size as stored. `0` = uncompressed. |
| 28 | 4 | `u32` | `flags` | Chunk-specific flags. See per-chunk definitions. |

**Stored size:** `size_compressed` is the payload's on-disk byte length, including
any AEAD framing (§9.3). `0` means the payload is stored raw - no zstd frame and no
encryption - in which case the on-disk length is `size_uncompressed`.

**Compression:** whether a chunk payload carries a zstd frame is a property of its
chunk type, not of `size_compressed` (§6.3). For a compressed chunk the payload is a
zstd frame that decompresses to `size_uncompressed` bytes; for an uncompressed chunk
the payload bytes are the chunk data itself. This matters for chunks that are stored
uncompressed but may still be encrypted (`ZDIC`, `PREV`): their `size_compressed` is
non-zero yet there is no zstd layer to undo.

**Encryption:** if the `ENCRYPTED` flag (bit 4) is set in the chunk descriptor's `flags`
field, the payload (on-disk bytes, i.e. the zstd frame) is encrypted. See §9.
This is per-chunk encryption, distinct from the file-level `ENCRYPTED` flag
(header bit 3) which signals the presence of an `AUTH` chunk.

**Null descriptors** (`offset == 0`) are ignored. Writers may pre-allocate directory
space with null descriptors.

### 3.3 Directory Trailer

Last 8 bytes of the file.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `trailer_magic` | `LEND` (`0x4C 0x45 0x4E 0x44`) |
| 4 | 4 | `u32` | `trailer_crc32c` | CRC-32C (Castagnoli) of `bytes[0 .. file_len-8]`. |

**Reading a .lumen file:**

1. Seek to `file_size - 8`. Read trailer. Verify `trailer_magic == "LEND"`.
2. Read the 32-byte header from offset 0. Verify `magic == "LUMN"` and `version` is recognized.
3. Seek to `header.dir_offset`. Read `header.chunk_count` × 32-byte descriptors.
4. For each descriptor with `offset != 0`, read the stored payload; decrypt if the
   chunk flags have bit 4 set; decompress if the chunk type is compressed (§6.3);
   dispatch by `chunk_type`.

---

## 4. Chunk Types

A Lumen file is composed of typed chunks. The table below summarizes every
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
| 32+N | 4 | `f32` | `build_width_mm` | Build plate X dimension. |
| 36+N | 4 | `f32` | `build_depth_mm` | Build plate Y dimension. |
| 40+N | 4 | `f32` | `build_height_mm` | Build plate Z dimension. |
| 44+N | 4 | `f32` | `layer_height_mm` | Default layer thickness. |
| 48+N | 4 | `u32` | `total_layers` | Total layer count. |

### 4.2 META - Metadata Chunk

**Type tag:** `META` (`0x4D 0x45 0x54 0x41`). Required.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Human-readable print parameters as a single JSON object.

**Required fields:**

```jsonc
{
  "normal_exposure_sec": 2.5,
  "bottom_exposure_sec": 30.0,
  "bottom_layer_count": 4,
  "transition_layer_count": 8,
  "layer_height_mm": 0.05,
  "lift_distance_mm": 5.0,
  "lift_speed_mm_min": 65.0,
  "retract_distance_mm": 5.0,
  "retract_speed_mm_min": 150.0
}
```

**Optional fields:**

```jsonc
{
  // Two-stage motion
  "lift_distance2_mm": 3.0,
  "lift_speed2_mm_min": 180.0,
  "retract_distance2_mm": 3.0,
  "retract_speed2_mm_min": 180.0,

  // Bottom-layer overrides (inherit from normal if absent)
  "bottom_lift_distance_mm": 6.0,
  "bottom_lift_speed_mm_min": 50.0,
  "bottom_lift_distance2_mm": 4.0,
  "bottom_lift_speed2_mm_min": 120.0,
  "bottom_retract_distance_mm": 6.0,
  "bottom_retract_speed_mm_min": 100.0,
  "bottom_retract_distance2_mm": 4.0,
  "bottom_retract_speed2_mm_min": 120.0,
  "bottom_retract_height2_mm": 0.0,

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
    "dp_um": 120.0,           // Penetration depth (μm) - how deep UV penetrates before dropping to 1/e
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

**Field resolution for readers:**

1. Start with META values as defaults for all layers (and SECT values per-sector, if multi-sector).
2. Apply bottom/transition blending: layers in the bottom range use bottom-prefixed values; layers in the transition range linearly interpolate between bottom and normal values.
3. If `LROV` chunk present, override specific fields for specific layers (last matching entry wins).

See §8 for the complete layer timing pipeline.

**Materials:** `materials` is the authoritative material library for this print.
`SECT.material_index` indexes it and defaults to `0`. A single-material print carries
a one-element array and sector 0 uses element 0. If `materials` is absent, material
identity is unknown and consumers fall back to their own default.

Readers must accept both integer and floating-point JSON number syntax for `f32`
fields. Readers must ignore unknown JSON keys.

### 4.3 PROF - Print Profile Chunk

**Type tag:** `PROF` (`0x50 0x52 0x4F 0x46`). Optional.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Carries a **named, versioned, reusable print profile** that Odyssey-compatible
printer firmware can import into its profile library. This is distinct from META:
META defines the resolved parameters for this specific print job; PROF defines a
reusable profile that can be saved, shared, and applied to future prints.

When a Lumen-capable printer receives a file with a `PROF` chunk, it may:
- Use the file's META settings directly (the default).
- Import the PROF profile into its local profile store for future use.
- Apply a printer-side override profile instead of either.

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
      "display_height_px": 6320,
      "pixel_size_um": 19.0
    }
  ],

  // Optional: printer definition (when profile_type = "printer" or "combined")
  "printer": {
    "name": "Ares 12K",
    "manufacturer": "Open Resin Alliance",
    "display_width_px": 11520,
    "display_height_px": 6320,
    "pixel_size_um": 19.0,
    "build_width_mm": 218.0,
    "build_depth_mm": 123.0,
    "build_height_mm": 250.0,
    "bit_depth": 8
  },

  // Required: all timing and motion settings (same field names as META)
  "settings": {
    "layer_height_mm": 0.05,
    "normal_exposure_sec": 2.5,
    "bottom_exposure_sec": 30.0,
    "bottom_layer_count": 4,
    "transition_layer_count": 8,

    "lift_distance_mm": 5.0,
    "lift_speed_mm_min": 65.0,
    "retract_distance_mm": 5.0,
    "retract_speed_mm_min": 150.0,

    "lift_distance2_mm": 3.0,
    "lift_speed2_mm_min": 180.0,
    "retract_distance2_mm": 3.0,
    "retract_speed2_mm_min": 180.0,

    "bottom_lift_distance_mm": 6.0,
    "bottom_lift_speed_mm_min": 50.0,
    "bottom_lift_distance2_mm": 4.0,
    "bottom_lift_speed2_mm_min": 120.0,
    "bottom_retract_distance_mm": 6.0,
    "bottom_retract_speed_mm_min": 100.0,
    "bottom_retract_distance2_mm": 4.0,
    "bottom_retract_speed2_mm_min": 120.0,
    "bottom_retract_height2_mm": 0.0,

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

    // Resin working curve - experimental (§5.6). If omitted, printer falls back
    // to traditional exposure-time model.
    "cure_curve": {
      "dp_um": 120.0,
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

### 4.4 AUTH - Authentication & Encryption Chunk

**Type tag:** `AUTH` (`0x41 0x55 0x54 0x48`). Optional.

**Flags:** uncompressed, unencrypted.

Present only when the `ENCRYPTED` flag is set in the file header. Carries the
metadata needed to derive or unwrap the session key.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `cipher_id` | ASCII. `A256G` = AES-256-GCM, `C20P1` = ChaCha20-Poly1305. |
| 4 | 4 | `u32` | `auth_version` | Layout version. `1` for this spec. |
| 8 | 4 | `u32` | `mode` | Bitfield: bit 0 = password, bit 1 = machine-binding. |
| 12 | 4 | `u32` | `password_section_len` | Byte length of password section. 0 if not used. |
| 16 | 4 | `u32` | `machine_section_len` | Byte length of machine-binding section. 0 if not used. |
| 20 | N | - | `password_section` | See §4.4.1. |
| 20+N | M | - | `machine_section` | See §4.4.2. |

#### 4.4.1 Password Section

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 16 | `[u8; 16]` | `salt` | Random salt for Argon2id. |
| 16 | 4 | `u32` | `iterations` | Argon2id time cost. |
| 20 | 4 | `u32` | `memory_kib` | Argon2id memory cost in KiB. |
| 24 | 1 | `u8` | `parallelism` | Argon2id lanes. |
| 25 | 12 | `[u8; 12]` | `kw_nonce` | Nonce for AES-256-KW. |
| 37 | 40 | `[u8; 40]` | `wrapped_key` | Session key wrapped with Argon2id-derived KEK (AES-256-KW, RFC 3394). |

To decrypt: derive a 256-bit KEK from the password + salt + Argon2id parameters,
then unwrap `wrapped_key` with AES-256-KW to recover the session key.

#### 4.4.2 Machine-Binding Section

Contains one or more recipient entries. Each entry:

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 32 | `[u8; 32]` | `machine_fp` | SHA-256 fingerprint of the machine's public key. |
| 32 | 32 | `[u8; 32]` | `ephemeral_pk` | Sender's ephemeral X25519 public key. |
| 64 | 12 | `[u8; 12]` | `kw_nonce` | Nonce for AES-256-KW. |
| 76 | 40 | `[u8; 40]` | `wrapped_key` | Session key wrapped with ECDH-derived KEK. |

Total per entry: 116 bytes. `machine_section_len / 116` gives the recipient count.

To decrypt: the machine performs X25519 ECDH with its private key and
`ephemeral_pk`, derives a KEK from the shared secret via HKDF-SHA-256, then
unwraps `wrapped_key` with AES-256-KW.

**Notes:**
- All recipient entries wrap the **same** session key - any authorized machine
  can decrypt.
- A file may use password mode only, machine-binding only, or both (the session
  key is the same; both sections wrap it independently).

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
  see §7.2 for the completeness caveat.

**Sector composition invariant:** For a given layer, every exposed pixel belongs to
exactly one sector, and the union of the sector masks is the full layer image (§7.3).

### 4.6 LROV - Layer Override Chunk

**Type tag:** `LROV` (`0x4C 0x52 0x4F 0x56`). Optional.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Per-layer timing parameter overrides.

```jsonc
{
  "overrides": [
    {
      "layer": 100,
      "normal_exposure_sec": 2.8,
      "lift_distance_mm": 6.0
    },
    {
      "layer_range": [200, 250],
      "sector_id": 1,
      "normal_exposure_sec": 2.2,
      "wait_time_before_cure_sec": 0.5
    }
  ],
  "use_defaults_for_unmatched": true
}
```

- Layer indices are 0-based (layer 0 = closest to build plate).
- `layer_range` is inclusive `[start, end]`.
- `sector_id` is optional. When present, the entry applies only to that sector on the
  matched layer(s); when absent, it applies to every sector.
- When several entries match a given `(layer, sector)` pair, the **last** matching
  entry wins. Because an entry without `sector_id` matches every sector, a later
  sector-specific entry overrides it for that sector only.
- `use_defaults_for_unmatched` defaults to `true` if absent. When `true`, unmatched layers use META (or SECT) defaults.

### 4.7 PREV - Preview Image Chunk

**Type tag:** `PREV` (`0x50 0x52 0x45 0x56`). Optional, multiple allowed.

**Flags:** uncompressed (PNG is already compressed). Encryption optional.

A PNG image as raw bytes (no additional framing).

**Chunk flags:**

| Bit | Name | Description |
|-----|------|-------------|
| 0–3 | `preview_role` | 0 = unspecified, 1 = large (rec. 400×300), 2 = small (rec. 200×125), 3 = icon (≤64×64). 4–15 reserved. |
| 4 | `ENCRYPTED` | May be set if preview confidentiality is desired. |
| 5–31 | - | Reserved. Must be 0. |

Multiple PREV chunks are permitted. Readers should select the best preview for
their display based on `preview_role`.

### 4.8 LTBL - Layer Table Chunk

**Type tag:** `LTBL` (`0x4C 0x54 0x42 0x4C`). Required.

**Flags:** uncompressed, unencrypted.

Maps layer indices to a block of the LAYR chunk and a byte range within that
block's decompressed output. Enables random access by decompressing only the block
that contains the target layer.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `table_version` | Layout version. `1` for this spec. |
| 4 | 4 | `u32` | `layer_count` | Must equal `HDR.total_layers`. |
| 8 | 4 | `u32` | `entry_size` | Bytes per entry. `20` for v1. Readers must stride by this value. |
| 12 | N | - | `entries` | `layer_count` × `entry_size` bytes. |

**Layer Entry (v1, 20 bytes):**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 8 | `u64` | `data_offset` | Byte offset from the start of the decompressed output of block `block_index`. |
| 8 | 4 | `u32` | `block_index` | Index into the LAYR block table (§4.10) of the block containing this layer. |
| 12 | 4 | `u32` | `data_size` | Byte size of this layer's REE data within its block. |
| 16 | 4 | `u32` | `sector_count` | Sectors active on this layer. 0 = empty layer (all black). |

### 4.9 ZDIC - Zstd Dictionary Chunk

**Type tag:** `ZDIC` (`0x5A 0x44 0x49 0x43`). Optional.

**Flags:** uncompressed. Encrypted if `AUTH` present.

Carries the zstd dictionary shared by the LAYR block frames. The dictionary MUST be
available before any LAYR block is decompressed. Because a trained dictionary is
built from samples of the print's own layer data, it is treated as content: it is
encrypted alongside the other content chunks when `AUTH` is present.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `zdic_version` | Layout version. `1` for this spec. |
| 4 | 4 | `u32` | `dict_id` | Zstd dictionary ID (`ZSTD_getDictID_fromDict()`). Must equal the dictionary ID reported by every LAYR block frame. |
| 8 | 4 | `u32` | `dict_size` | Byte length of `dict_bytes`. Must not exceed 112 640 bytes (zstd's `ZDICT_DICTSIZE_MAX`). |
| 12 | N | `[u8; N]` | `dict_bytes` | Raw dictionary bytes exactly as produced by `ZDICT_trainFromBuffer()`. |

**Presence rules:**

- If any LAYR block frame was compressed with a dictionary, exactly one `ZDIC` chunk
  MUST be present, and every block frame's dictionary ID MUST equal `ZDIC.dict_id`.
- If no dictionary was used, `ZDIC` MUST be absent and every block frame's
  dictionary ID MUST be `0`.
- A file MUST NOT contain more than one non-null `ZDIC` chunk.

**Design notes:**

- `ZDIC` is stored uncompressed so it can be handed directly to the decompressor,
  without a preliminary decompression pass.
- The dictionary is not covered by the `LHAS` Merkle tree (which covers layer data).
  Files that need full-artifact integrity rely on the `CRC-32C` trailer or an
  `EXTD`/`SIGN` signature.

### 4.10 LAYR - Layer Data Chunk

**Type tag:** `LAYR` (`0x4C 0x41 0x59 0x52`). Required.

**Flags:** uncompressed at the chunk level; contains zstd-compressed block frames.
Encrypted if `AUTH` present (see §9.3 - each block frame is a separate AEAD unit).

Contains all layer mask data as a sequence of independent zstd frames, called
**blocks**. Block `k` holds a contiguous run of layers; the layers inside a block
are concatenated in layer order:

```
[layer_a_data] [layer_{a+1}_data] ... [layer_b_data]
```

A layer's data starts at `LTBL.entries[i].data_offset` within the decompressed
output of block `LTBL.entries[i].block_index` and has size
`LTBL.entries[i].data_size`.

**Payload layout:**

```
layr_header:
  layr_version            : u32   - Layout version. 1 for this spec.
  block_count             : u32   - Number of zstd block frames.
  block_table_entry_size  : u32   - Bytes per block table entry. 16 for v1.
  block_table             : block_count × block_table_entry_size bytes

block_region:
  [block_0_frame] [block_1_frame] ... [block_{block_count-1}_frame]
```

The chunk descriptor for `LAYR` stores the container uncompressed: `size_compressed`
is `0` and `size_uncompressed` is the container's byte length. The `ENCRYPTED` chunk
flag still applies - it selects whether the block frames inside the container are
sealed (§9.3).

**Block table entry (v1, 16 bytes):**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 8 | `u64` | `frame_offset` | Byte offset of the block frame from the start of `block_region`. |
| 8 | 4 | `u32` | `frame_size` | Stored size of the frame. Includes AEAD framing overhead when block frames are encrypted. |
| 12 | 4 | `u32` | `uncompressed_size` | Exact size of the block's decompressed output. |

**Block invariants:**

- `block_count >= 1` and `block_count <= HDR.total_layers`.
- Blocks are ordered and cover every layer exactly once: block `0` starts at layer 0,
  block `k+1` begins where block `k` ends, and therefore
  `LTBL.entries[i].block_index` is non-decreasing in `i`.
- Every block index in `0..block_count` is referenced by at least one layer.
- Decompressing block `k` yields exactly `block_table[k].uncompressed_size` bytes.
- A block frame with a non-zero zstd dictionary ID requires a `ZDIC` chunk (§4.9)
  whose `dict_id` matches.

**Recommended block size:** 32–64 layers. Small enough that a reader seeking to an
arbitrary layer decompresses only a few megabytes, large enough that the shared
dictionary and inter-layer similarity keep compression close to what a single frame
would achieve. Encoders MAY choose any size that satisfies the invariants above.

**Per-layer data format - single-sector** (`MULTI_SECTOR` flag = 0):

Each layer's data begins with a 1-byte encoding tag, followed by the encoded
mask data:

```
tag          : u8         - Encoding tag. See the encoding tag table in §5.
mask_data    : [u8]       - REE stream in the format specified by the tag.
```

Empty layers (`sector_count == 0`) store zero bytes of data - no tag byte and no
mask. This is the canonical encoding for an all-black layer.

**Per-layer data format - multi-sector** (`MULTI_SECTOR` flag = 1):

```
sector_count  : varint
[sector_0_id  : varint]  [sector_0_size : varint]  [sector_0_tag : u8]  [sector_0_mask_data]
[sector_1_id  : varint]  [sector_1_size : varint]  [sector_1_tag : u8]  [sector_1_mask_data]
...
```

`sector_N_size` gives the byte length of `[sector_N_tag + sector_N_mask_data]`
(i.e., everything following `sector_N_size` for that sector). To skip an unknown
sector, advance `sector_N_size` bytes after reading `sector_N_size`.

Empty layers (`sector_count == 0`) store zero bytes in multi-sector mode as well:
there is no `sector_count` varint. The reader learns the layer is empty from
`LTBL.entries[i].sector_count`; `LTBL.entries[i].data_size` MUST be `0`.

### 4.11 LHAS - Layer Hash Chunk

**Type tag:** `LHAS` (`0x4C 0x48 0x41 0x53`). Optional.

**Flags:** uncompressed, unencrypted.

Carries per-layer cryptographic hashes and a Merkle tree root for integrity
verification. This enables:

- **Resume-after-power-loss:** verify which layers are intact on restart.
- **Silent corruption detection:** network transfer errors, bit rot on storage.
- **Bounded verification:** verify any single layer by decompressing only the block
  that contains it (§4.10), not the whole file.

**Payload:**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 1 | `u8` | `hash_algorithm` | `0x01` = SHA-256. |
| 1 | 1 | `u8` | `hash_size` | `32` for SHA-256. |
| 2 | 4 | `u32` | `layer_count` | Must equal `HDR.total_layers`. |
| 6 | 32 | `[u8; 32]` | `merkle_root` | Root hash of the Merkle tree over all layer hashes. |
| 38 | N | - | `layer_hashes` | `layer_count × hash_size` bytes. `layer_hashes[i]` = SHA-256 of layer `i`'s data exactly as it appears in the decompressed output of its block: the byte range `[LTBL.entries[i].data_offset, + data_size)` (an empty layer hashes the empty string). |

**Merkle tree construction:**

1. **Leaf layer:** Let `H[i]` = `layer_hashes[i]` for `i` in `0..layer_count`.
2. **Pad** `H` to the next power of 2 by repeating the last hash:
   `padded_len = 2^ceil(log2(layer_count))`.
3. **Build tree bottom-up:**
   ```
   while len(H) > 1:
       for j in 0..len(H)/2:
           parent[j] = SHA-256(H[2j] || H[2j+1])
       H = parent
   ```
4. The single remaining hash in `H` is the `merkle_root`.

**Verifying a single layer `i`:** the reader needs the layer's hash, its sibling
hashes along the Merkle path (`ceil(log2(layer_count))` hashes), and the
`merkle_root`. Recompute the path upwards; the result must equal `merkle_root`.

**Verifying the entire file:**
1. Decompress each block and, for each layer it contains, compute SHA-256 over the
   layer's byte range within that block's output.
2. Verify each hash matches `layer_hashes[i]`.
3. Recompute the Merkle root from `layer_hashes`; verify it matches `merkle_root`.

**Design notes:**
- LHAS is uncompressed so it can be verified without initializing the decompressor.
- The Merkle root in LHAS replaces the weaker CRC-32C trailer for integrity
  purposes. The CRC-32C trailer remains for quick file-completeness checks.
- 32 bytes per layer = 320 KB for a 10 000-layer print - acceptable overhead
  for the integrity guarantee.
- For memory-constrained devices, the verifier processes one block at a time:
  decompress the block, hash each layer it contains, fold those hashes into the
  Merkle tree, then release the block. Peak memory is one block plus the leaf hash
  table, never the whole layer stream.

### 4.12 VOXL - Embedded Scene Chunk

**Type tag:** `VOXL` (`0x56 0x4F 0x58 0x4C`). Optional.

**Flags:** zstd-compressed. Encrypted if `AUTH` present.

Embeds the complete DragonFruit VOXL scene file that produced this print. This
makes the `.lumen` file a **self-contained, re-editable project** - the user
never loses the source. Any compatible slicer can extract the VOXL, restore the
full scene (models, supports, modifiers, hollowing state), and continue editing
as if the file had never been closed.

**Payload:** The raw bytes of a VOXL file (see `docs/dev/voxl-format-spec.md`).
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
  Lumen print parameters (strict mode).

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
| 0–7 | - | Reserved for standard chunk flags (bit 4 = `ENCRYPTED`, see §3.2). |
| 8–23 | `vendor_id` | Vendor identifier (registered with ORA). `0x0000` = ORA standard extension. |
| 24 | `critical` | If set, a reader that does not recognize this extension must refuse to print. |
| 25–31 | - | Reserved. Must be 0. |

Readers skip unknown EXTD chunks (or refuse if `critical` is set).

**Reserved ORA-standard extension types (`vendor_id = 0`):**

| `ext_type` | Name | Purpose |
|------------|------|---------|
| `SIGN` | Signature | Cryptographic signature for file authenticity. |
| `BLKP` | Blocked LAYR | Alternative: independently-compressed layer blocks for memory-constrained readers. |
| `VLYR` | Variable Layers | Per-layer height values (future variable layer height). |
| `CMLT` | Compression ML | Extended dictionary training metadata. |
| `CMAP` | Color Map | Per-sector color channel mapping for multi-color printing. |

---

## 5. Layer Mask Encoding

This section defines how individual layer images are encoded into compact byte
streams. Lumen replaces the run-length encoding (RLE) used by every existing
format with **run-end encoding (REE)** - a strictly more efficient representation
that stores fewer numbers per run. For anti-aliased prints, a novel **split
encoding** separates the bulk binary geometry from the sparse edge pixels,
enabling zstd to compress each at its optimal rate.

Lumen supports three encoding strategies per layer, selected by a 1-byte tag
prepended to each layer's mask data within its block's decompressed output:

| Tag | Encoding | Use case |
|-----|----------|----------|
| `0x00` | Binary REE (§5.3) | No anti-aliasing - every pixel is 0 or 255. |
| `0x01` | Grayscale REE (§5.4) | Anti-aliased - full 8-bit per pixel. |
| `0x02` | Split REE + sparse AA (§5.5) | Anti-aliased, but most pixels are solid 0/255. Bulk of layer encoded as binary REE; edge AA pixels stored as a sparse overlay. |

Tags `0x03`–`0xFF` are reserved. Readers must refuse a layer with an unknown tag.

### 5.1 Rationale

REE replaces classic RLE `(value, length)` with `(value, end_position)` where
`end_position` is the cumulative absolute pixel index where the run ends. For binary
images where runs strictly alternate, run values
are implicit - only end positions are stored.

The split encoding (tag `0x02`) exploits the observation that in an anti-aliased
print the AA gradient only exists within a narrow band along geometry edges -
the majority of pixels remain solid 0 or 255. Encoding the bulk as binary REE
and the edges as a sparse overlay is expected to substantially reduce the
compressed size compared to full grayscale REE for high-resolution prints.

### 5.2 Varint Encoding

All variable-length integers use Protocol Buffers-style continuation-bit varints:

- 7 data bits per byte; MSB = 1 means more bytes follow.
- Least-significant group first.
- Must use the shortest possible encoding (no overlong forms).
- Maximum length is 10 bytes (the maximum for a 64-bit unsigned value).
- A varint continuing past the end of its containing buffer is malformed; the file must be rejected.

| Value range | Bytes |
|-------------|-------|
| 0 – 127 | 1 |
| 128 – 16 383 | 2 |
| 16 384 – 2 097 151 | 3 |
| 2 097 152 – 268 435 455 | 4 |

Examples: `0` → `[0x00]`, `128` → `[0x80, 0x01]`,
`1920×1080 = 2 073 600` → 3 bytes, `11520×6480 = 74 649 600` → 4 bytes.

**Practical bounds:** `run_count` and `aa_pixel_count` must not exceed `total_pixels + 1`
(a run cannot be shorter than one pixel). Readers should reject values exceeding this bound
before allocating decode buffers.

### 5.3 Binary REE (No Anti-Aliasing)

Used when every pixel is 0 or 255.
Runs strictly alternate: even runs are black, odd runs are white.

**Stream format:**

```
first_value : u8        - Value of the first run. 0x00 = black, 0xFF = white.
run_count   : varint    - Number of runs (K). 0 = empty layer (all black).
end_pos_0   : varint    - End of run 0.
end_pos_1   : varint    - End of run 1.
...
end_pos_{K-2}: varint   - End of second-to-last run.
- end_pos_{K-1} is IMPLICIT = total_pixels (not stored).
```

- `run_count == 0`: decodes to all black. `first_value` is 0x00, `run_count` is
  varint `0`. Decoders MUST accept this form, but it is **not canonical**: an
  all-black layer MUST be stored as an empty layer (`LTBL.sector_count == 0`,
  `data_size == 0`, no bytes). Encoders MUST NOT emit `run_count == 0`; strict-mode
  validators reject it.
- `run_count == 1`: one solid run to total_pixels. `first_value` gives the color, `run_count` is varint `1`. Zero end positions.
- `run_count >= 2`: K–1 end positions stored (the last is implicit).

**Delta pre-encoding:** Before concatenating into LAYR, end positions are converted
to deltas. The encoder writes each delta as the difference from the previous
cumulative position, producing smaller integers that form better cross-layer
patterns for zstd:

```
write first_value as u8
write run_count as varint
prev = 0
for i in 0..K-1:
    delta = end_pos[i] - prev
    write delta as varint
    prev = end_pos[i]
```

The decoder reverses this:

```
first_value = read_u8()
run_count = read_varint()
cumulative = 0
for i in 0..K-1:
    delta = read_varint()
    cumulative += delta
    end_pos[i] = cumulative
```

Delta encoding converts cumulative positions to run lengths, which are smaller
numbers and form better cross-layer patterns for zstd.

**Decoding algorithm:**

```
total_pixels = width × height
first_value = read_u8()        // 0x00 or 0xFF
run_count = read_varint()
if run_count == 0: fill 0; return
if run_count == 1: fill first_value; return

value = first_value
start = 0
for i in 0..run_count:
    end_pos = (i == run_count-1) ? total_pixels : read_and_accumulate_delta()
                                    // read_and_accumulate_delta: read varint, add to cumulative, return result
                                    // (see delta decoder pseudocode above)
    fill_mask[start .. end_pos] = value
    value = 255 - value       // toggle
    start = end_pos
```

### 5.4 Grayscale REE (Anti-Aliased)

Used when pixels may have any 8-bit value (0-255).

**Stream format:**

```
run_count  : varint    - Number of runs. 0 = all black.
value_0    : u8        - Value of the first run (typically 0x00 for black, 0xFF for white).
end_pos_0  : varint
value_1    : u8
end_pos_1  : varint
...
value_{K-1}: u8        - Note: last end_pos is stored (unlike binary REE).
end_pos_{K-1}: varint   - Must equal total_pixels.
```

**Decoding algorithm:**

```
run_count = read_varint()
if run_count == 0: fill 0; return

start = 0
for i in 0..run_count:
    value = read_u8()
    end_pos = read_varint()
    fill_mask[start .. end_pos] = value
    start = end_pos
assert start == total_pixels
```

**Why the last end_pos is stored for grayscale:** In binary REE the final run value
is known (it alternates from the first). In grayscale REE it is not. Storing the
last end_pos (= total_pixels) costs 1 varint (~1–4 bytes) and keeps the decoder
loop uniform.

**Grayscale REE is NOT delta-encoded** before zstd (the u8 values break the
pure-delta stream; the compression gain from delta encoding is marginal with
explicit values present).

### 5.5 Split Encoding: Binary REE + Sparse AA Overlay (tag `0x02`)

For anti-aliased layers where most pixels are solid 0 or 255, split encoding
stores the bulk geometry as a compact binary REE mask and the AA edge pixels as
a sparse overlay. This is designed to produce substantially smaller compressed
output than full grayscale REE for AA prints at high resolutions.

**How it works:**

1. The encoder thresholds the grayscale layer at 127 to produce a binary mask
   (0 or 255).
2. The encoder identifies AA pixels: any pixel whose actual grayscale value
   differs from the thresholded value. These are expected to be a small fraction
   of total pixels (edge pixels only).
3. The binary mask is encoded as standard binary REE (§5.3).
4. The AA overlay is encoded as a **sparse indexed stream** of (position, value)
   pairs covering the AA pixels.

**Stream format:**

```
tag                : u8 = 0x02
binary_ree         : binary REE stream (§5.3) for the thresholded mask
aa_pixel_count     : varint    - number of AA pixels in the overlay
aa_positions       : varint[aa_pixel_count]  - delta-encoded absolute pixel indices
aa_values          : u8[aa_pixel_count]      - grayscale values (0–255)
```

The `aa_positions` array uses delta encoding: `positions[0]` is the first AA pixel
index; for `i > 0`, `positions[i] = aa_pixel_index[i] - aa_pixel_index[i-1]`.
Since AA pixels cluster along geometry edges, consecutive deltas are small
(often 1–8 pixels), making them highly compressible via varint.

**Decoding algorithm:**

```
// Step 1: decode binary mask
decode_binary_ree() → fill mask with 0 or 255

// Step 2: decode AA overlay
aa_count = read_varint()
if aa_count == 0: return   // pure binary, no AA pixels

pos = 0
for i in 0..aa_count:
    delta = read_varint()
    pos += delta            // reconstruct absolute pixel index
    value = read_u8()
    mask[pos] = value       // overwrite the thresholded value
```

**Encoding guidelines:**

- An encoder should choose split encoding (tag `0x02`) when the AA pixel
  fraction is low (the common case for anti-aliased geometry edges). When the
  fraction is high (e.g., heavy Z-blur, all-layer dither), fall back to
  grayscale REE (tag `0x01`).
- The split encoding naturally handles empty AA overlays (`aa_pixel_count = 0`).
  In that case the layer is purely binary and the split stream is functionally
  equivalent to tag `0x00`, but encoders should prefer tag `0x00` for clarity.
- The sparse overlay covers **all** AA pixels, not just interior edges. If a
  pixel's grayscale value differs from the binary threshold result, it must be
  included - even if it is surrounded by other AA pixels on the same edge.

**Projected comparison at 12K resolution (11520×6480, 2000 layers):**

These are design estimates, not benchmarks. Actual results will vary with geometry
complexity, AA settings, and zstd dictionary effectiveness.

| Encoding | Per-layer REE overhead | Compressed LAYR (projected) | Notes |
|----------|------------------------|------------------------------|-------|
| Binary REE | Minimal (end positions only) | Small | No AA information at all. |
| Grayscale REE | Per-run value byte overhead | Larger | Every pixel carries a u8 run value. |
| Split REE + sparse AA | Binary REE + sparse overlay | Substantially smaller than grayscale | Bulk as binary REE, edges as sparse overlay. |

### 5.6 Resin Working Curve (Experimental)

The `cure_curve` object in META and PROF provides the three fundamental parameters
of a resin's photopolymerization behavior. When present, Odyssey firmware can
compute the required exposure time from first principles rather than relying on
fixed trial-and-error values.

**The Beer-Lambert cure model for MSLA:**

The cure depth `Cd` achieved by exposure energy `E` is:

```
Cd = Dp × ln(E / Ec)
```

Where:
- **Dp** (`dp_um`): Penetration depth in microns - the depth at which UV
  irradiance drops to 1/e (~37%) of the surface value. Higher Dp = deeper
  curing per unit energy. Determined by resin chemistry and pigment load.
- **Ec** (`ec_mj_cm2`): Critical exposure in mJ/cm² - the minimum energy
  required to reach the gel point (resin transitions from liquid to solid).
- **E0** (`e0_mj_cm2`): Base energy in mJ/cm² - energy absorbed by the resin
  before polymerization begins (inhibition layer, oxygen, or dye effects).

**Practical use cases:**

- **Adaptive layer height (requires VOXL):** The cure curve tells Odyssey what
  exposure to use for a given layer height, but changing the layer height
  requires re-slicing the source geometry - you cannot derive 30 μm layers from
  fixed 50 μm layer data. When a `.lumen` file includes both a `VOXL` chunk
  (§4.12) and `cure_curve` parameters, Odyssey can re-slice the scene using the
  `dragonfruit-slicing-engine` Rust crate (the same engine that produced the
  original file), then compute the correct exposure from the curve:  
  `E_new = Ec × exp(Cd_new / Dp)`. No guesswork, no test prints. Without the
  VOXL, the cure curve still helps validate that the existing exposure is
  appropriate for the given layer height.
- **Batch compensation:** Different resin batches have slightly different Dp/Ec.
  A profile with measured batch parameters automatically corrects exposure
  without requiring re-slicing.
- **Multi-resin blending:** If a multi-vat printer mixes two resins, the blended
  parameters can be derived from the individual cure curves.

**Status:** Experimental. These fields are defined for future use. Odyssey
firmware that does not implement the cure model must fall back to the
traditional `normal_exposure_sec` / `bottom_exposure_sec` values in META.
Encoders may omit `cure_curve` entirely.

---

## 6. Compression Strategy

Compression is the single most important factor in a modern print file format.
A 12K printer generates 74.6 million pixels per layer; across 2,000 layers that
is 149 GB of raw data. Without aggressive compression, files are unmanageably
large for storage, network transfer, and embedded-printer memory.

Lumen's compression strategy has two layers. First, the REE encoding (§5)
reduces the per-layer information content well below that of raw pixels or
classic RLE. Second, zstd compresses the layer data stream in blocks with a shared
trained dictionary, exploiting the fact that adjacent layers in a
3D print are nearly identical - only the edges change. No existing resin print
format does cross-layer compression; this alone is expected to yield a step
change in compressed file sizes.

### 6.1 Why zstd

| Property | zlib/deflate | zstd |
|----------|-------------|------|
| Compression ratio | baseline | Consistently better at equivalent speed |
| Decompression speed | Baseline | Significantly faster (see zstd benchmarks) |
| Compression speed | Baseline | Significantly faster at default levels |
| Dictionary support | raw deflate only | First-class training API |
| Streaming API | Yes | Yes |

Benchmark data is published by the zstd project (RFC 8878). The key design
decision is that zstd's combination of higher ratio, faster decompression, and
first-class dictionary training makes it the right choice for cross-layer
compression of REE data.

### 6.2 Dictionary Compression for LAYR

1. Encode all layers to REE streams, in layer order.
2. Split the layer sequence into contiguous blocks (§4.10). Recommended: 32–64
   layers per block.
3. Sample the first `min(256, total_layers)` layers for a training set.
4. Train a zstd dictionary with `ZDICT_trainFromBuffer()`.
5. Store the dictionary in a `ZDIC` chunk (§4.9).
6. Compress each block independently with `ZSTD_compress_usingDict()`.

The dictionary captures statistical patterns in REE data. Because adjacent layers
are highly similar (only the edges change between adjacent layers), a dictionary
trained on the first 256 layers should generalize to the entire print. If dictionary
training fails (degenerate geometry, very small prints), omit the `ZDIC` chunk and
compress each block with standard zstd, without a dictionary.

**Why blocks instead of one frame.** A single frame compresses marginally better,
but a zstd frame cannot be decompressed partially. That would make `LTBL` random
access, per-layer `LHAS` verification, resume-after-power-loss, and parallel block
decode all impossible, and would force a full-copy decompression buffer of hundreds
of megabytes on embedded readers. Block frames make each of those operations real.
The cost is one frame header per block and a small ratio loss, largely recovered by
the shared dictionary.

### 6.3 Per-Chunk Compression Policy

The compressed/uncompressed choice in the table below is **normative**: it tells a
reader whether a chunk payload carries a zstd frame. The levels are recommendations.

| Chunk | Compression | Rationale |
|-------|------------|-----------|
| HDR | None | Tiny (~50 bytes); read before decompressor init. |
| AUTH | None | Tiny (~few hundred bytes); read before decompressor init. |
| META | zstd level 3 | Small payload; speed matters. |
| SECT | zstd level 3 | Small payload. |
| LROV | zstd level 3 | Small payload. |
| PREV | None | PNG is already compressed. |
| LTBL | None | Needed for random access; 20 bytes/layer is acceptable. |
| ZDIC | None | Raw dictionary bytes; read before any LAYR block decompression. |
| LAYR | zstd level 3–6 per block, shared dictionary | Bulk of file; level 3 for interactive, level 6 for final export. |
| VOXL | zstd level 3 | VOXL V2 already uses zlib internally; zstd recompression yields additional reduction. |
| LHAS | None | Needed for integrity checks before decompressor init. |
| EXTD | Per-extension | Extension defines its own recommendation. |

---

## 7. Multi-Material / Sector Model

### 7.1 Conceptual Model

A **sector** is a named exposure group with its own timing parameters and per-layer
mask data. Use cases:

- **Single material:** One sector (sector 0). Standard today.
- **Support/model split:** Sector 0 = model, sector 1 = supports. Support material
  uses faster exposure.
- **Multi-resin printing:** Different regions printed with different resins (future
  multi-vat hardware).

### 7.2 Sector 0 Convention and Single-Material Degradation

Sector 0 is the **primary** or **default** sector. It is implicitly present in every
non-empty layer: if a layer's sector list omits sector 0, sector 0's mask for that
layer is empty (all black), and the layer's remaining sectors cover the image.

Even in multi-sector files, a single-material reader can:

1. Ignore all `SECT` chunks.
2. Decode only sector 0 masks from each layer (parsing the multi-sector varint
   framing to locate sector 0's data — a small overhead of a few varint decodes
   per layer).
3. Apply META default timing to all layers.

Because sectors partition the layer image (§7.3), a layer whose sectors ≥ 1 are
non-empty is **not** fully represented by sector 0 alone. A reader that decodes only
sector 0 MUST therefore detect non-empty non-zero sectors and report the print as
incomplete — warn in loose mode, refuse in strict mode. Reporting such a print as
complete is a conformance failure. Layers whose only non-empty sector is sector 0
are unaffected.

This is a deliberate trade-off: the partition model is what makes multi-vat hardware
correct, and it means single-material compatibility is "print what you can print,
and say so" rather than silent infidelity.

### 7.3 Sector Mask Invariant

For a given layer, all sector masks are pairwise non-overlapping and their union is
exactly the layer's exposed image: every exposed pixel belongs to exactly one
sector. Encoders MUST guarantee this; readers SHOULD verify it in strict mode. An
empty layer has no sectors (`sector_count == 0`).

---

## 8. Per-Layer Settings Model

The layer timing pipeline resolves as follows for each layer index `i`:

1. **Base values** from META (and SECT, if multi-sector).
2. **Bottom/transition blending:** Layers `0 .. bottom_layer_count-1` use bottom
   values. Layers `bottom_layer_count .. bottom_layer_count+transition_layer_count-1`
   linearly interpolate between bottom and normal values.
3. **LROV overrides:** Any matching `layer` or `layer_range` entry in LROV overrides
   the interpolated value for the sectors it targets (`sector_id` absent = all
   sectors). The last matching entry wins per `(layer, sector)` pair.

This models the existing bottom/normal/transition behavior while allowing arbitrary
per-layer overrides.

---

## 9. Encryption Model

### 9.1 Design Principles

- **User-initiated, not mandatory.** Files are plaintext by default.
- **AEAD only.** Authenticated encryption prevents undetected tampering.
- **Compress-then-encrypt.** zstd compression is applied first, then the compressed
  frame is encrypted.
- **Content-scoped encryption.** The directory, HDR, AUTH, LTBL, and the LAYR header
  and block table remain plaintext. Everything that carries content or content-derived
  data (LAYR block frames, ZDIC, META, PROF, SECT, LROV, VOXL) is encrypted. PREV is
  optionally encrypted.

### 9.2 Encryption Algorithm

Two options, identified in the AUTH chunk:

| `cipher_id` | Algorithm | Nonce size | Tag size | Notes |
|-------------|-----------|------------|----------|-------|
| `A256G` | AES-256-GCM | 12 bytes | 16 bytes | Hardware-accelerated on x86 (AES-NI) and ARM (AES extensions). |
| `C20P1` | ChaCha20-Poly1305 | 12 bytes | 16 bytes | Faster in software; constant-time on all platforms. |

### 9.3 Encryption Format

When chunk flags bit 4 (`ENCRYPTED`) is set, each **encrypted unit** in the chunk
payload is sealed independently:

```
nonce        : [u8; 12]     - Random, unique per unit.
ciphertext   : [u8; N]      - Encrypted payload bytes.
tag          : [u8; 16]     - AEAD authentication tag.
```

`AEAD-Open(key, nonce, ciphertext, associated_data)` MUST verify the tag before any
parsing or decompression. `associated_data` binds the unit to its identity in the
file: `chunk_type || 0x00 || unit_index_le_u32`. For a single-unit chunk,
`unit_index` is `0`.

For every chunk except `LAYR`, the chunk payload is exactly one unit, and the chunk
descriptor's `size_compressed` includes the 28-byte framing overhead.

For `LAYR`, the `layr_header` and `block_table` stay plaintext and each block frame
is its own unit (`unit_index` = block index, §4.10). This keeps per-block random
access working on encrypted files: a reader can seek to a block, decrypt just that
block, and decompress it instead of streaming the whole ciphertext. The block
table's `frame_size` includes the 28-byte overhead for its unit.

### 9.4 Session Key Lifecycle

1. Generate 256-bit random session key at encode time.
2. Encrypt each sensitive unit with the session key (unique random nonce per unit; §9.3).
3. Wrap the session key:
   - **Password mode:** Derive KEK from password via Argon2id, wrap with AES-256-KW.
   - **Machine mode:** For each authorized machine, derive KEK via X25519 ECDH +
     HKDF-SHA-256, wrap with AES-256-KW.
4. Store wrapping metadata in AUTH chunk.

The session key is the same for all chunks in the file. Multiple wrapping entries
enable multiple authorized machines without re-encrypting the entire payload.

---

## 10. Versioning and Forward Compatibility

### 10.1 Version Numbers

| Level | Field | Description |
|-------|-------|-------------|
| File | `header.version` | Breaking changes to the binary container. |
| HDR chunk | `hdr_version` | New fields added to HDR; compatible across file versions. |
| LTBL chunk | `table_version` | Changes to layer entry layout. |
| AUTH chunk | `auth_version` | Changes to encryption metadata layout. |
| LAYR chunk | `layr_version` | Changes to the block framing layout. |
| ZDIC chunk | `zdic_version` | Changes to the dictionary chunk layout. |
| EXTD chunk | `ext_version` | Per-extension versioning. |

### 10.2 Forward Compatibility Mechanisms

1. **Unknown chunk types:** Skip (chunk descriptor gives byte range).
2. **Unknown chunk flags:** Ignore within known types.
3. **Unknown JSON keys:** Ignore in META, SECT, LROV payloads.
4. **New HDR fields:** Stride using `hdr_version`.
5. **New LTBL fields:** Stride using `entry_size`.
6. **Unknown EXTD with `critical = 1`:** Refuse file.
7. **Unknown EXTD with `critical = 0`:** Skip.

### 10.3 Deprecation Policy

No chunk type or field is removed in a minor version bump. If a better mechanism
replaces an existing chunk, both are present during a transition period; readers
prefer the newer one.

---

## 11. Reader Validation Requirements

### 11.1 Structural Validation

- [ ] Magic bytes `LUMN` at offset 0.
- [ ] Trailer magic `LEND` at `file_size - 8`.
- [ ] Trailer CRC-32C matches `bytes[0 .. file_len-8]`.
- [ ] `header.version` is recognized.
- [ ] `header.dir_offset` is within file bounds.
- [ ] Chunk count matches directory entries.
- [ ] No two chunks overlap. A chunk's stored extent is `[offset, offset + size_compressed)`
  when `size_compressed > 0`, and `[offset, offset + size_uncompressed)` when
  `size_compressed == 0`. Exception: null descriptors (`offset == 0`).
- [ ] `HDR` chunk present and is first chunk (offset immediately after 32-byte
  header).
- [ ] `META` chunk present.
- [ ] `LTBL` chunk present.
- [ ] `LAYR` chunk present, and its `layr_header` is well-formed (`block_count >= 1`).
- [ ] If any LAYR block frame references a zstd dictionary (dictionary ID `!= 0`), exactly one `ZDIC` chunk is present and every block frame's dictionary ID equals `ZDIC.dict_id`.
- [ ] If `HAS_PREVIEW` flag set, ≥1 `PREV` chunk present.
- [ ] If `HAS_EXTENSIONS` flag set, ≥1 `EXTD` chunk present.
- [ ] If `HAS_LAYER_HASHES` flag set, `LHAS` chunk present.
- [ ] If `LHAS` chunk present, `layer_count` equals `HDR.total_layers`.

### 11.2 Semantic Validation

- [ ] `HDR.total_layers > 0` and `HDR.total_layers == LTBL.layer_count`.
- [ ] `LTBL.entry_size >= 20`. The layout is fixed through offset 20; future versions may append fields after offset 20, and readers stride by `entry_size` to skip unknown trailing fields.
- [ ] `HDR.layer_height_mm > 0.0`.
- [ ] `HDR.build_width_mm > 0.0`, `HDR.build_depth_mm > 0.0`, `HDR.build_height_mm > 0.0`.
- [ ] `HDR.encoder_name_len <= 256` (or the HDR chunk's `size_uncompressed` as an implicit upper bound).
- [ ] Every `LTBL.entries[i].block_index` is less than `LAYR.block_count`, and the sequence of `block_index` values is non-decreasing in `i`.
- [ ] (Multi-sector only) For every layer `i` with `LTBL.entries[i].sector_count > 0`, the `sector_count` varint at the start of that layer's data within its block equals `LTBL.entries[i].sector_count` (the LAYR value is authoritative for decoding). Layers with `sector_count == 0` store no bytes at all. In single-sector mode, layer data starts with the encoding tag byte, not a `sector_count` varint.
- [ ] `HDR.display_width_px × display_height_px > 0`.
- [ ] `HDR.physical_width_px` is a multiple of `display_width_px` (1× if no
  sub-pixel packing).
- [ ] META JSON contains all required fields (`normal_exposure_sec`, `bottom_exposure_sec`, `bottom_layer_count`, `transition_layer_count`, `layer_height_mm`, `lift_distance_mm`, `lift_speed_mm_min`, `retract_distance_mm`, `retract_speed_mm_min`).
- [ ] `META.normal_exposure_sec > 0.0`.
- [ ] `META.bottom_exposure_sec > 0.0`.
- [ ] `META.layer_height_mm > 0.0`.
- [ ] If `MULTI_SECTOR` flag set, ≥1 `SECT` chunk present.
- [ ] All `SECT.sector_id` values unique.
- [ ] If `META.materials` is present, it is a non-empty array and every entry has a non-empty `name`.
- [ ] If `SECT.material_index` is present, the referenced materials array exists and contains that index.
- [ ] If `PROF.materials` is present, it satisfies the same shape rules as `META.materials`.
- [ ] If `ENCRYPTED` flag set, `AUTH` chunk present and recognized cipher.
- [ ] All `LROV` layer indices in `[0, total_layers-1]`.
- [ ] `LROV` layer ranges have `end >= start`.
- [ ] `LROV` `sector_id`, when present, is `0` or matches a defined `SECT.sector_id`.
- [ ] If `PROF` chunk present, `profile_name` and `profile_version` are non-empty strings.
- [ ] If `PROF` chunk present, `profile_type` is one of `"material"`, `"printer"`, `"combined"`.
- [ ] If `PROF` chunk present, `settings.normal_exposure_sec > 0.0` and `settings.bottom_exposure_sec > 0.0`.
- [ ] If `PROF` chunk present, `settings.layer_height_mm > 0.0`.
- [ ] If `PROF.settings.cure_curve` present, `dp_um > 0.0`, `ec_mj_cm2 > 0.0`, `e0_mj_cm2 >= 0.0`.
- [ ] If `PROF` chunk present with `profile_uuid`, the UUID string is well-formed (36 characters, 8-4-4-4-12 hex pattern).
- [ ] If `META.cure_curve` present, `dp_um > 0.0`, `ec_mj_cm2 > 0.0`, `e0_mj_cm2 >= 0.0`.
- [ ] If `META.chamber_temperature_c` or `vat_temperature_c` present, values are in range `[0.0, 120.0]`.
- [ ] If `LHAS` chunk present, recompute Merkle root from `layer_hashes` and verify it matches `merkle_root`.
- [ ] (Strict mode) If `LHAS` chunk present, decompress and hash each layer; verify against `layer_hashes`.
- [ ] If `VOXL` chunk present, payload is a valid VOXL file (parseable, recognized version, passes VOXL validation rules).
- [ ] (Strict mode) If `VOXL` chunk present, scene metadata (printer name, resolution) is consistent with `HDR` fields.

### 11.3 Layer Data Validation (post-decompression)

- [ ] `layr_header.block_count >= 1` and `layr_header.block_count <= HDR.total_layers`.
- [ ] Block table entries are contiguous and ordered: `frame_offset[0] == 0` and `frame_offset[k+1] == frame_offset[k] + frame_size[k]` for all `k`.
- [ ] The end of the last block frame lies within the LAYR chunk payload.
- [ ] Every block index in `0..block_count` is referenced by at least one LTBL entry.
- [ ] Decompressing block `k` yields exactly `block_table[k].uncompressed_size` bytes.
- [ ] A block frame's zstd dictionary ID equals `ZDIC.dict_id` when `ZDIC` is present, and is `0` when it is absent.
- [ ] For each LTBL entry: `data_offset + data_size <= block_table[block_index].uncompressed_size`.
- [ ] All varints are well-formed: minimally encoded (no overlong forms), terminated within the containing buffer, and at most 10 bytes (the maximum for a 64-bit value).
- [ ] Layer encoding tag is in `{0x00, 0x01, 0x02}`. Reject any layer with an unknown tag.
- [ ] For binary REE (tag `0x00`): `first_value` must be `0x00` or `0xFF`.
- [ ] For empty layers (`sector_count == 0`): `data_size` must be 0.
- [ ] (Strict mode) No layer uses the non-canonical `run_count == 0` form; all-black layers are stored as empty layers.
- [ ] REE streams decode to strictly increasing end positions.
- [ ] Last end position equals `total_pixels`.
- [ ] (Strict mode) Sector masks at each layer sum to `total_pixels` and are
  non-overlapping.

### 11.4 Encryption Validation

- [ ] If `ENCRYPTED` flag set, all LAYR/META/PROF/SECT/LROV/VOXL/ZDIC chunks have the encrypted flag set, and LAYR block frames are individually sealed (§9.3).
- [ ] Auth tag verifies for each encrypted chunk (decryption integrity check).
- [ ] `AUTH.mode` has at least one bit set.
- [ ] If `AUTH.mode` bit 0 is set, `password_section_len >= 77` (minimum password section size; see §4.4.1).
- [ ] If `AUTH.mode` bit 1 is set, `machine_section_len >= 116` and `machine_section_len % 116 == 0` (must contain at least one complete recipient entry; see §4.4.2).
- [ ] Machine-binding entries have valid key lengths.
- [ ] Argon2id parameters are within reasonable bounds (`iterations >= 1`,
  `memory_kib >= 8192`).

### 11.5 Validation Levels

- **Loose** (default for printing): Accept structurally valid files. Skip unknown
  chunks/fields.
- **Strict** (file verification tools): Enforce all semantic validations. Warn on
  non-critical issues, error on critical ones.

---

## 12. Comparison with Existing Formats

| Feature | CTB v5 | GOO | AFZ (Anycubic) | NanoDLP | **Lumen v1** |
|---------|--------|-----|----------------|---------|-------------|
| Container | Flat binary, fixed header | Flat binary, 195 KB header | ZIP archive | ZIP archive | Chunk directory (extensible) |
| Endianness | LE | BE | LE | LE | LE |
| Metadata | Fixed-offset binary | Fixed-offset binary | JSON files in ZIP | JSON files in ZIP | JSON in typed chunks |
| Human-readable params | No | No | Yes (unzip) | Yes | Yes (`strings` + decompress) |
| Layer encoding | Variable-length RLE, XOR-obfuscated | 0x55-magic RLE, checksum | PW0 RLE (4-bit quant) | PNG (deflate) | REE + zstd with dictionary |
| Compression | RLE only (weak) | RLE only (weak) | Deflate per-entry | Deflate per PNG | zstd cross-layer with dictionary |
| Cross-layer compression | No | No | No | No | Yes (shared-dictionary block frames) |
| Encryption | AES-256-CBC (optional, v5enc) | No | No | No | Optional AEAD (AES-256-GCM / ChaCha20-Poly1305) |
| Encryption purpose | Vendor lock-in (forced by printer) | - | - | - | User security (opt-in) |
| Per-layer overrides | No (bottom/normal/transition) | No | No | No | Yes (LROV, arbitrary overrides) |
| Embedded print profile | No | No | No | No | Yes (PROF chunk - importable by Odyssey firmware) |
| Embedded source scene | No | No | No | No | Yes (VOXL chunk - round-trip re-editable) |
| Multi-material | No | No | No | No | Yes (SECT + per-layer sector masks) |
| Extensibility | No (must reverse-engineer) | No | No | No | Yes (EXTD chunks, vendor IDs) |
| Max resolution | ~16K (32-bit offsets) | Fixed header limit | Unlimited (ZIP64) | Unlimited | Unlimited (64-bit offsets) |
| Preview images | 2× RGB15 RLE (fixed size) | 2× PNG in header (fixed size) | 3× PNG in ZIP | 1× PNG in ZIP | 1+N PNG in PREV chunks (flexible) |
| AA support | Grayscale RLE | Grayscale RLE | 4-bit PW0 | Full 8-bit PNG | Full 8-bit REE + split encoding + zstd |
| Temperature control | No | No | No | No | Yes (chamber + vat, Celsius) |
| Resin cure curve | No | No | No | No | Yes (Dp, Ec, E0 - experimental, for physics-based exposure) |
| Per-layer integrity | No | No (checksum per layer, weak) | ZIP CRC32 per entry | ZIP CRC32 per entry | SHA-256 Merkle tree (LHAS chunk) + CRC-32C trailer |
| Validation | CRC32 (encrypted only) | One's-complement per layer | ZIP CRC32 per entry | ZIP CRC32 per entry | CRC-32C trailer + structural + semantic + Merkle root |

---

## Appendix A: Example File Layout

Single-sector, 100 layers, 1920×1080, no encryption (illustrative estimates):

```
Offset    Size    Content
------    ----    -------
0         32      File header: LUMN, v1, dir_offset=<end>, chunk_count=8, flags=0x01
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

---

## Appendix B: Reference Encoder Integration

The Lumen encoder follows the existing plugin pattern (`FormatEncoder` +
`RleStreamEncoder` traits defined in
`rust/dragonfruit-slicing-engine/src/encoders/mod.rs`):

```
plugins/lumen/
  pluginDefinition.ts
  pluginManifest.ts
  slicing/
    lumenFormatDefinition.ts      - SlicingFormatDefinition (layerDataKind: 'raw-mask')
    rust/
      encoder_impl.rs             - FormatEncoder + RleStreamEncoder impl
      lumen_layout.rs             - Chunk assembly, REE encoding, block framing, zstd compression
      lumen_metadata.rs           - JSON builders for META, SECT, LROV
      lumen_crypto.rs             - AUTH chunk, AEAD encrypt/decrypt, key wrapping
      lumen_types.rs              - Consts, LumenPreparedLayer, etc.
```

Key integration points:
- `output_format()` returns `".lumen"`.
- `requires_raw_mask_layers()` returns `true`, `requires_png_layers()` returns `false`.
- `create_rle_stream_encoder()` receives `Vec<RleRun>` per layer and converts each
  layer to a REE stream.
- `finalize_to_bytes()` splits the accumulated layer streams into blocks, trains the
  zstd dictionary into a `ZDIC` chunk, compresses each block independently, and
  assembles the complete chunk layout (`ZDIC`, `LTBL`, `LAYR`, `VOXL`, directory,
  trailer).
- `parallel_encode_fn()` enables parallel RLE→REE conversion via rayon; block
  compression is likewise independent per block.

---

## Appendix C: References

### Standards & RFCs

| Reference | Topic |
|-----------|-------|
| [zstd RFC 8878](https://datatracker.ietf.org/doc/html/rfc8878) | Zstandard compression algorithm |
| [Protocol Buffers Varint Encoding](https://protobuf.dev/programming-guides/encoding/#varints) | Continuation-bit varint format used for REE |
| [AES-256-KW (RFC 3394)](https://datatracker.ietf.org/doc/html/rfc3394) | Key wrapping for session key encryption |
| [Argon2id (RFC 9106)](https://datatracker.ietf.org/doc/html/rfc9106) | Memory-hard password KDF |
| [X25519 ECDH (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748) | Elliptic-curve key agreement for machine binding |
| [ChaCha20-Poly1305 (RFC 8439)](https://datatracker.ietf.org/doc/html/rfc8439) | AEAD cipher option |
| [AES-GCM (NIST SP 800-38D)](https://csrc.nist.gov/publications/detail/sp/800-38d/final) | AEAD cipher option |
| [SHA-256 (FIPS 180-4)](https://csrc.nist.gov/publications/detail/fips/180/4/final) | Merkle tree hash function |
| [CRC-32C (RFC 3720 §12.1)](https://datatracker.ietf.org/doc/html/rfc3720#section-12.1) | Castagnoli CRC for file trailer |

### DragonFruit Project Internals

| Reference | Topic |
|-----------|-------|
| [`docs/dev/voxl-format-spec.md`](voxl-format-spec.md) | VOXL native scene container specification (embedded via VOXL chunk, §4.12) |
| [`rust/dragonfruit-slicing-engine/src/encoders/mod.rs`](../../rust/dragonfruit-slicing-engine/src/encoders/mod.rs) | `FormatEncoder` and `RleStreamEncoder` trait contracts |
| [`rust/dragonfruit-slicing-engine/docs/ARCHITECTURE.md`](../../rust/dragonfruit-slicing-engine/docs/ARCHITECTURE.md) | Slicing engine architecture overview |
| [`rust/dragonfruit-slicing-engine/src/rle.rs`](../../rust/dragonfruit-slicing-engine/src/rle.rs) | Core RLE types consumed by the Lumen REE encoder |

### Related Format Specifications

| Reference | Topic |
|-----------|-------|
| [UVTools](https://github.com/sn4k3/UVTools) | ChiTuBox binary format (community reverse-engineering) |
| [GOO file format](https://github.com/elegooofficial/GOO) | Elegoo binary format |
| [NanoDLP format](https://docs.nano3dtech.com/manual/format/) | NanoDLP ZIP-based format |
| [ZIP APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | ZIP archive format (used by AFZ, NanoDLP; referenced for Lumen's chunk-directory-at-end design) |

---

## License

```
MIT License

Copyright (c) 2026 Open Resin Alliance

Permission is hereby granted, free of charge, to any person obtaining a copy
of this specification and associated documentation files (the "Specification"),
to deal in the Specification without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Specification, and to permit persons to whom the
Specification is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Specification.

THE SPECIFICATION IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SPECIFICATION OR THE USE OR OTHER DEALINGS IN
THE SPECIFICATION.
```

## Format Governance

The Open Resin Alliance serves as the steward of the Lumen format. This is an
ecosystem coordination role, not a legal restriction - the Specification is
licensed under MIT and may be freely implemented, extended, and forked.

To protect interoperability across implementations:

- The Alliance maintains the canonical version of this Specification.
- Vendor IDs for `EXTD` chunks are registered through the Alliance to prevent
  collisions between independent implementations. Vendor ID `0x0000` is
  reserved for extensions standardized as part of the core specification.
- Format version numbers are ratified by the Alliance to ensure a single,
  coherent version lineage.

These conventions are voluntary. Implementers who wish to interoperate
smoothly within the Lumen ecosystem are encouraged to coordinate through the
Alliance, but they are under no legal obligation to do so.
