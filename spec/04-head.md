# File header chunk

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

### 4.1 HEAD - File Header Chunk

**Type tag:** `HEAD` (`0x48 0x45 0x41 0x44`). Required. Must be the first chunk.

**Flags:** uncompressed, unencrypted.

Carries display and build dimensions. Separated from the fixed header so it can grow
across format versions without changing the 32-byte magic header.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `head_version` | Layout version. `1` for this spec. |
| 4 | 4 | `u32` | `encoder_name_len` | Byte length of `encoder_name`. |
| 8 | N | `[u8; N]` | `encoder_name` | UTF-8. e.g. `"DragonFruit 1.0"`. |
| 8+N | 8 | `u64` | `created_unix_sec` | Unix timestamp (seconds). |
| 16+N | 4 | `u32` | `display_width_px` | Display width in pixels: the layer mask grid. |
| 20+N | 4 | `u32` | `display_height_px` | Display height in pixels: the layer mask grid. |
| 24+N | 4 | `u32` | `build_width_um` | Build plate X dimension, in micrometers. |
| 28+N | 4 | `u32` | `build_depth_um` | Build plate Y dimension, in micrometers. |
| 32+N | 4 | `u32` | `build_height_um` | Build plate Z dimension, in micrometers. |
| 36+N | 4 | `u32` | `layer_height_um` | Default layer thickness, in micrometers. |
| 40+N | 4 | `u32` | `total_layers` | Total layer count. |

**Display readiness.** Layer masks are stored exactly as the printer must expose them: one
8-bit value per pixel over the grid `display_width_px × display_height_px`
([§5](11-layer-encoding.md#5-layer-mask-encoding)), where `0x00` is black - no exposure - `0xFF`
is white, the pixel's full exposure, and a value in between is a fraction of it. A reader MUST NOT
apply a transform of its own - no mirror, no rotation, no rescale of the value range.

Two things a header could have carried are deliberately left out, because each is already settled
by the time the file exists:

- **Mirroring.** `mirror_x` / `mirror_y` are build settings the slicer resolves before encoding.
  Firmware-side mirroring is a calibration concern that belongs to the printer, not the file
  ([§1.1](01-overview.md#11-what-lumen-is-not)).
- **Bit depth.** Every mask pixel is 8 bits, whatever the display can emit, and the file does not
  record what that is. A printer whose display produces all 256 levels uses each value as stored;
  a display with fewer levels cannot, so the printer reduces each value to a level it has. Where
  that reduction matters an encoder resolves it before writing - dithering towards the display's
  levels, or quantizing onto them - so a mask written for a display of fewer levels is an ordinary
  8-bit mask that happens to use few distinct values. Nothing in the bytes distinguishes it from a
  print for a display with more levels, and a reader MUST NOT infer a bit depth from them. The
  `printer.bit_depth` a `PROF` chunk ([§4.3](06-prof.md#43-prof---print-profile-chunk)) may carry describes
  the machine a profile was written for, not the layer data in the file.

A mask grid is the finest grid a print has to name, because it is the one the printer drives: a
panel whose controller or LCD drives more than one pixel per mask pixel expands the grid itself,
from the value it was given, and no field is needed to say so.

**Layer thickness.** `HEAD.layer_height_um` and `META.layer_height_um` state the same nominal
figure - the thickness the print was sliced at - and an encoder MUST write the same value in
both. They are two views of one fact rather than two settings: a reader that prints resolves
the thickness through the pipeline of [§8](14-layer-timing.md#8-per-layer-settings-model),
which starts from META (or the sector's override, or an `LROV` payload) and never consults
`HEAD`, and a reader that only summarizes a file - a file manager showing a layer count and a
layer height - reads the header without opening a `META` chunk. Where a file disagrees with
itself the resolved value governs and no check depends on the pair; the encoder obligation is
what keeps the two from drifting.

**Writer identity.** `encoder_name` identifies the program that wrote the file, for support
and for provenance: UTF-8, free-form, at most 256 bytes, typically a product name and its
version (`"DragonFruit 1.0"`). Nothing in the format depends on it, no two encoders need to
agree on its spelling, and a reader MUST NOT attach meaning to it beyond displaying it. An
encoder SHOULD write a stable name for itself rather than a per-build or per-user string.

**Timestamps.** `created_unix_sec` is the wall-clock time the file was written, and an encoder
writes it. It is an input rather than a derived value, so it is one of the two things left out
of the byte-reproducibility guarantee of [§5.6](11-layer-encoding.md#56-canonical-encoding): an
encoder given the same scene and the same settings and the same `created_unix_sec` produces the
same file, and one that stamps the current time produces a file that differs in this field and
in the trailer CRC. The other exception is sealed output, whose keys and nonces come from a
random source ([§9.4](15-encryption.md#94-session-key-lifecycle)).
