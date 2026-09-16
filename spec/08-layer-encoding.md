# Layer mask encoding

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 5. Layer Mask Encoding

This section defines how individual layer images are encoded into compact byte
streams. LUMEN replaces the run-length encoding (RLE) used by every existing
format with **run-end encoding (REE)**. Binary REE stores end positions only, with
run values implicit in their strict alternation, so a binary layer costs fewer numbers
per run than classic RLE. Grayscale REE stores one value and one length per run - the
same count as RLE - and takes its gains from cross-layer compression. For
anti-aliased prints, a novel **split encoding** separates the bulk binary geometry
from the sparse edge pixels, enabling zstd to compress each at its optimal rate.

LUMEN supports three encoding strategies per layer, selected by a 1-byte tag
prepended to each layer's mask data within its `LAYR` chunk's decompressed output:

| Tag | Encoding | Use case |
|-----|----------|----------|
| `0x00` | Binary REE ([§5.3](#53-binary-ree-no-anti-aliasing)) | No anti-aliasing - every pixel is 0 or 255. |
| `0x01` | Grayscale REE ([§5.4](#54-grayscale-ree-anti-aliased)) | Anti-aliased - full 8-bit per pixel. |
| `0x02` | Split REE + sparse AA ([§5.5](#55-split-encoding-binary-ree--sparse-aa-overlay-tag-0x02)) | Anti-aliased, but most pixels are solid 0/255. Bulk of layer encoded as binary REE; edge AA pixels stored as a sparse overlay. |

Tags `0x03`–`0xFF` are reserved. Readers must refuse a layer with an unknown tag.

Encoders MUST emit the canonical byte stream for the tag they choose; [§5.6](#56-canonical-encoding) defines the
canonical form of each tag and the rules for choosing one.

`total_pixels`, used throughout this section, is the number of pixels in a layer
mask: `HEAD.display_width_px × HEAD.display_height_px`.

### 5.1 Rationale

Conceptually, REE replaces classic RLE `(value, length)` with `(value, end_position)`
where `end_position` is the cumulative absolute pixel index where the run ends. Binary REE
stores those positions as the differences between them - the run lengths ([§5.3](#53-binary-ree-no-anti-aliasing)) -
while grayscale REE stores them absolutely ([§5.4](#54-grayscale-ree-anti-aliased)). For binary images where runs
strictly alternate, run values are implicit, so only the lengths are stored.

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
Runs alternate in value, starting from `first_value`: run `i` carries `first_value` when
`i` is even, and the opposite value when `i` is odd.

**Stream format (as stored):**

```
first_value : u8        - Value of the first run. 0x00 = black, 0xFF = white.
run_count   : varint    - Number of runs (K). 0 = empty layer (all black).
run_len_0   : varint    - Length in pixels of run 0.
run_len_1   : varint    - Length in pixels of run 1.
...
run_len_{K-2}: varint   - Length in pixels of run K-2.
- The last run's length is IMPLICIT: run K-1 ends at total_pixels.
```

A stored value is the difference between consecutive end positions, i.e. a run length.
Storing lengths rather than absolute positions keeps the integers small and gives zstd
better cross-layer patterns.

- `run_count == 0`: decodes to all black. `first_value` is 0x00, `run_count` is
  varint `0`. Decoders MUST accept this form, but it is **not canonical**: an
  all-black `(layer, sector)` MUST be stored as an empty slice (`LTBL` entry
  `data_size == 0`, no bytes). Encoders MUST NOT emit `run_count == 0`; strict-mode
  validators reject it.
- `run_count == 1`: one solid run to total_pixels. `first_value` gives the color, `run_count` is varint `1`. Zero stored lengths.
- `run_count >= 2`: K–1 run lengths are stored (the last run's length is implicit).
- Every stored length is `>= 1`, the implicit final length is `>= 1`, and the lengths sum
  to exactly `total_pixels` ([§5.6](#56-canonical-encoding)).

**Encoding algorithm.** Each value written after `run_count` is a run length, derived
from the end positions. The lengths are stored as significance planes
([§5.3.1](#531-significance-planes)), so a length's high byte does not sit between two
noisy low bytes:

```
write first_value as u8
write run_count as varint
prev = 0
lengths = []
for i in 0..K-1:
    delta = end_pos[i] - prev
    lengths.append(delta)
    prev = end_pos[i]
write PLANES(lengths)
```

The decoder reverses this:

```
first_value = read_u8()
run_count = read_varint()
planes = read_planes()     // always present: four lengths, zero when nothing is stored
cumulative = 0
for i in 0..K-1:
    delta = planes.next_varint()
    cumulative += delta
    end_pos[i] = cumulative
```

Absolute end positions are recovered by accumulating the stored lengths.

**Decoding algorithm:**

```
total_pixels = display_width_px × display_height_px
first_value = read_u8()        // 0x00 or 0xFF
run_count = read_varint()
if run_count == 0: fill 0; return   // non-canonical, and may carry no plane header
planes = read_planes()     // always present: four lengths, zero when nothing is stored
if run_count == 1: fill first_value; return

value = first_value
cumulative = 0
start = 0
for i in 0..run_count:
    if i == run_count-1:
        end_pos = total_pixels
    else:
        cumulative += planes.next_varint()
        end_pos = cumulative
    fill_mask[start .. end_pos] = value
    value = 255 - value       // toggle
    start = end_pos
```

### 5.3.1 Significance Planes

A run-length varint array is stored as four *significance planes* rather than as a
stream of interleaved varints. The bytes of a varint are the least significant seven
bits first; byte `j` of every varint goes to plane `j`, and the four plane lengths
are written ahead of the planes themselves:

```
PLANES(n varints):
  plane_lengths : 4 × varint    - byte length of planes 0..3, 0 when empty
  plane bytes   : plane_0 ‖ plane_1 ‖ plane_2 ‖ plane_3
```

A decoder reads the four lengths, then walks the planes in step: to read a varint it
takes one byte from plane 0, another from plane 1 while the continuation bit is set,
and so on. No count of varints is needed to find the end of a plane, and a varint's
length is implied by its own bytes.

The arrangement exists for the compressor. A run length of a few thousand pixels is
two or three bytes whose high bytes are nearly constant along a scanline, and whose
low bytes are essentially random; interleaved, the constant bytes are separated by
random ones and zstd can match neither. Grouped, the high planes collapse: measured
on an 801-layer 15120×6230 print, the length planes held 1 841 442, 1 605 303, 845
and 804 bytes and compressed to 994 454, 43 614, 718 and 49 - plane 1 by a factor of
37, and the print by a factor of 1.21 overall.

Two rules follow. The planes are **prefix-closed**: a varint that reaches plane `j`
also occupies planes `0..j-1`, so a non-empty plane may not follow an empty one, and
a strict-mode validator rejects streams that break this. The four lengths are always
written, so a stream with no stored varints costs four zero bytes - four bytes per
layer, against the 21% the arrangement returns on a detailed print. A stream that
ends immediately after its run count is therefore **not** canonical; a decoder MAY
accept it for the non-canonical `run_count == 0` form, which strict mode rejects
anyway ([§5.3](#53-binary-ree-no-anti-aliasing)).

### 5.4 Grayscale REE (Anti-Aliased)

Used when pixels may have any 8-bit value (0-255).

**Stream format:**

```
run_count  : varint     - Number of runs. 0 = all black.
values     : u8[run_count]        - the value of every run, in order
lengths    : PLANES(run_count - 1) - the length of every run but the last
```

The final run's length is implicit: it ends at `total_pixels`, which the reader
knows already.

**Decoding algorithm:**

```
run_count = read_varint()
if run_count == 0: fill 0; return
values = read_bytes(run_count)
planes = read_planes()     // always present: four lengths, zero when nothing is stored
start = 0
for i in 0..run_count:
    length = (i == run_count-1) ? total_pixels - start : planes.next_varint()
    fill_mask[start .. start + length] = values[i]
    start += length
assert start == total_pixels
```

**Why the values are hoisted and the final length is implicit:** a reader knows
`total_pixels`, so the final run's length is whatever remains; storing it - as
earlier drafts did, as an absolute end position equal to `total_pixels` - carried no
information and cost up to four bytes. Writing the values as one array rather than
interleaving them with the lengths is also what the split encoding's overlay does:
an edge's values are a few repeated bytes, and keeping them out of the length stream
leaves that stream smooth for the planes of [§5.3.1](#531-significance-planes).

**Canonical form.** Every run length is `>= 1` (so the end positions are strictly
increasing), the final end position equals `total_pixels`, and no two adjacent runs carry
the same value - they would be a single run. `run_count == 0` decodes to all black but is
**not canonical**: an all-black `(layer, sector)` uses the empty-slice form (`LTBL.entry
data_size == 0`). A layer whose pixels are all `0x00` or `0xFF` MUST use binary REE
instead ([§5.6](#56-canonical-encoding)).

**Grayscale REE stores lengths, not end positions.** Absolute end positions grow with
the layer's pixel count, so every run past pixel 127 paid an extra varint byte a
length does not, and they repeat neither within a layer nor across layers - the
worst input for a compressor. Lengths are bounded by the row width and cluster, which
is what the planes of [§5.3.1](#531-significance-planes) then exploit.

### 5.5 Split Encoding: Binary REE + Sparse AA Overlay (tag `0x02`)

For anti-aliased layers where most pixels are solid 0 or 255, split encoding
stores the bulk geometry as a compact binary REE mask and the AA edge pixels as
a sparse overlay. This is designed to produce substantially smaller compressed
output than full grayscale REE for AA prints at high resolutions.

**How it works:**

1. The encoder thresholds the grayscale layer to a binary mask: `255` where the
   grayscale value is `>= 128`, otherwise `0`.
2. The AA pixels are exactly those whose grayscale value is neither `0x00` nor `0xFF` -
   equivalently, the pixels where the thresholded value differs from the original. They
   are expected to be a small fraction of total pixels (edge pixels only), and the set is
   uniquely determined by the pixel content ([§5.6](#56-canonical-encoding)).
3. The binary mask is encoded as standard binary REE ([§5.3](#53-binary-ree-no-anti-aliasing)).
4. The AA overlay is encoded as a **sparse indexed stream** of (position, value)
   pairs covering the AA pixels.

**Stream format:**

```
tag                : u8 = 0x02
binary_ree         : binary REE stream ([§5.3](#53-binary-ree-no-anti-aliasing)) for the thresholded mask
aa_pixel_count     : varint    - number of AA pixels in the overlay
aa_positions       : PLANES(aa_pixel_count)  - delta-encoded absolute pixel indices
aa_values          : u8[aa_pixel_count]      - grayscale values (0–255)
```

The `aa_positions` array uses delta encoding: `positions[0]` is the first AA pixel
index; for `i > 0`, `positions[i] = aa_pixel_index[i] - aa_pixel_index[i-1]`.
Since AA pixels cluster along geometry edges, consecutive deltas are small
(often 1–8 pixels), and the significance planes of [§5.3.1](#531-significance-planes)
keep the occasional large delta from spoiling a stream that is otherwise a run of
ones.

**Decoding algorithm:**

```
// Step 1: decode binary mask
decode_binary_ree() → fill mask with 0 or 255

// Step 2: decode AA overlay: every position, then every value
aa_count = read_varint()
if aa_count == 0: return   // pure binary, no AA pixels

pos = 0
positions = []
for i in 0..aa_count:
    pos += read_varint()     // delta-encoded absolute pixel index
    positions.push(pos)
for i in 0..aa_count:
    mask[positions[i]] = read_u8()   // overwrite the thresholded value
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

### 5.6 Canonical Encoding

`LHAS` ([§4.10](06-layer-data.md#410-lhas---layer-hash-chunk)) hashes the decompressed bytes of each layer, so a stream that is legal
but not canonical yields a different hash for identical pixel content. This section
defines the canonical form for each tag, and the one choice left to the encoder.

**Tag choice.**

- A `(layer, sector)` with no exposed pixels uses the empty-slice form (`LTBL` entry
  `data_size == 0`); no tag is stored.
- A layer whose pixels are all `0x00` or `0xFF` MUST use tag `0x00` (binary REE).
- Otherwise the layer MUST use tag `0x01` (grayscale REE) or tag `0x02` (split REE).
  Either is permitted; see "Reproducibility scope" below.

**Canonical binary REE (tag `0x00`).** `first_value` is `0x00` or `0xFF`. Every stored
run length is `>= 1`, the implicit length of the final run is `>= 1`, and the run lengths
sum to exactly `total_pixels`. Runs alternate by construction, so adjacent runs never
share a value.

**Canonical grayscale REE (tag `0x01`).** Every run length is `>= 1` (so the end
positions are strictly increasing), the final end position equals `total_pixels`, and no
two adjacent runs carry the same value - they would be a single run.

**Canonical split REE (tag `0x02`).** The binary component thresholds as
`255 if v >= 128 else 0`, and the AA overlay contains exactly the pixels whose value is
neither `0x00` nor `0xFF`, listed with strictly increasing indices. The overlay is
therefore uniquely determined by the pixel content and cannot be padded or reordered.

**Reproducibility scope.**

- Deterministic: the empty-slice form and tag `0x00` fix the bytes for their content.
- Encoder's choice: tag `0x01` versus tag `0x02`. Picking the smaller requires encoding
  both, which is a cost/ratio trade-off rather than a correctness one. An encoder that
  evaluates both SHOULD break ties in favour of tag `0x01`.
- Required of every encoder: identical input and settings produce identical output, so
  re-slicing the same scene yields the same file and the same `LHAS` hashes.
- Not claimed: that two different encoders produce identical bytes, or identical `LHAS`
  hashes, for the same layer.

A decoder MUST accept any stream that satisfies [§5.3](#53-binary-ree-no-anti-aliasing)-[§5.5](#55-split-encoding-binary-ree--sparse-aa-overlay-tag-0x02), canonical or not; strict-mode
validators MAY reject non-canonical streams ([§11.3](14-validation.md#113-layer-data-validation-post-decompression)).

### 5.7 Resin Working Curve (Experimental)

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

- **Adaptive layer height (not available in v1):** The cure curve tells Odyssey what
  exposure to use for a given layer height, but changing the layer height
  requires re-slicing the source geometry - you cannot derive 30 μm layers from
  fixed 50 μm layer data. When a `.lumen` file includes both a `VOXL` chunk
  ([§4.11](07-scene-chunks.md#411-voxl---embedded-scene-chunk)) and `cure_curve` parameters, Odyssey can re-slice the scene using the
  `dragonfruit-slicing-engine` Rust crate (the same engine that produced the
  original file), then compute the correct exposure from the curve:  
  `E_new = Ec × exp(Cd_new / Dp)`. No guesswork, no test prints. Without the
  VOXL, the cure curve still helps validate that the existing exposure is
  appropriate for the given layer height.

  **Adaptive layer height is not available in v1.** It needs per-layer heights in the
  file, and v1 has nowhere to put them: `HEAD.layer_height_um` is a single default, and
  the `VLYR` extension is non-critical ([§4.12](07-scene-chunks.md#412-extd---extension-chunk)), so a conforming reader may skip it and
  print at the wrong Z. A future core mechanism - most likely an `LTBL` field - is
  required first. Until then encoders MUST NOT emit variable-height `.lumen` files, and
  the cure curve's v1 role is limited to validating the exposure for the fixed layer
  height in use.
- **Batch compensation:** Different resin batches have slightly different Dp/Ec.
  A profile with measured batch parameters automatically corrects exposure
  without requiring re-slicing.
- **Multi-resin blending:** If a multi-vat printer mixes two resins, the blended
  parameters can be derived from the individual cure curves.

**Status:** Experimental. These fields are defined for future use. Odyssey
firmware that does not implement the cure model must fall back to the
traditional `normal_exposure_ms` / `bottom_exposure_ms` values in META.
Encoders may omit `cure_curve` entirely.
