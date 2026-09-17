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
from the sparse edge pixels, enabling zstd to compress each at its optimal rate. An
**attached encoding** carries that split further: the overlay's positions are implied by
the geometry runs they sit on rather than stored per pixel.

LUMEN supports four encoding strategies per layer, selected by a 1-byte tag
prepended to each layer's mask data within its `LAYR` chunk's decompressed output:

| Tag | Encoding | Use case |
|-----|----------|----------|
| `0x00` | Binary REE ([§5.3](#53-binary-ree-no-anti-aliasing)) | No anti-aliasing - every pixel is 0 or 255. |
| `0x01` | Grayscale REE ([§5.4](#54-grayscale-ree-anti-aliased)) | Anti-aliased - full 8-bit per pixel. |
| `0x02` | Split REE + sparse AA ([§5.5](#55-split-encoding-binary-ree--sparse-aa-overlay-tag-0x02)) | Anti-aliased, but most pixels are solid 0/255. Bulk of layer encoded as binary REE; edge AA pixels stored as a sparse overlay. |
| `0x03` | Attached REE ([§5.6](#56-attached-encoding-parity-split-ree--attached-aa-tag-0x03)) | Anti-aliased, with the AA pixels along the edges of the geometry. The same core, its run lengths split by parity and self-delta coded; an AA pixel on a run's boundary is named by two bits of that run, and only the AA pixels inside a run are listed by position. |

Tags `0x04`–`0xFF` are reserved. Readers must refuse a layer with an unknown tag.

Encoders MUST emit the canonical byte stream for the tag they choose; [§5.7](#57-canonical-encoding) defines the
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

The attached encoding (tag `0x03`) adds two observations. A row-major run list interleaves
the boundary a filled region leaves with the boundary the next region enters, so run lengths
of one parity describe the same kind of edge on successive regions rather than neighbours in
the image: splitting the list by parity separates two sequences that are each smoother than
the interleaved one, and each is then delta coded against its own kind. And an anti-aliased
edge exists where geometry crosses a pixel boundary, so most AA pixels are the first or last
pixel of the core run they sit in - two attachment bits per run name them, at a quarter of a
byte per run, where the split encoding's position array charged a delta for every one.

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

**Four bytes is the ceiling inside a plane array.** A varint array is stored as four
significance planes ([§5.3.1](#531-significance-planes)), so a *stored* value - a run
length, or an anti-aliasing overlay delta - is at most 268 435 455, and a fifth byte has
nowhere to go: a decoder rejects a varint that continues past plane 3 (`ree.varint`), and
an encoder refuses to write one. The ten-byte maximum above applies to the varints a
stream carries outside a plane array - `run_count`, `aa_pixel_count` and `escape_count`,
whose values this revision bounds by `total_pixels + 1`. The practical consequence is a
bound on the mask grid: a layer of more than 2²⁸ pixels cannot be run-end encoded, because
a single run could need a five-byte length. The largest display this specification can
carry is therefore 268 435 455 mask pixels, about 3.6× a 12K panel; a grid that wide is a
v2 matter, not a v1 one.

**Practical bounds:** `run_count`, `aa_pixel_count` and `escape_count` must not exceed
`total_pixels + 1`, and `escape_count` may not exceed `aa_pixel_count` (a run cannot be
shorter than one pixel, and an escape is an overlay pixel). Readers should reject values
exceeding these bounds before allocating decode buffers.

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
  to exactly `total_pixels` ([§5.7](#57-canonical-encoding)).

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
length is implied by its own bytes. Because there are four planes and no fifth, every
value an array stores is at most `0x0FFF_FFFF` ([§5.2](#52-varint-encoding)), which is
what bounds the mask grid the format can carry.

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
instead ([§5.7](#57-canonical-encoding)).

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
   uniquely determined by the pixel content ([§5.7](#57-canonical-encoding)).
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

### 5.6 Attached Encoding: Parity-Split REE + Attached AA (tag `0x03`)

For anti-aliased layers whose AA pixels form a band along the edges of the geometry, the
attached encoding stores the core the split encoding stores and stops paying for the
position of most of the overlay: an AA pixel that is the first or last pixel of a core run
is named by two bits of that run, and only the AA pixels strictly inside a run are listed
by position. The core's run lengths are split by parity and delta coded within each parity,
which keeps the bytes that name the runs about as small as the binary form's. Like tag
`0x02`, the form is self-contained - no slice's stream refers to another's - so `LTBL`
random access ([§6.2](12-compression.md#62-dictionary-compression-for-layr)) is unchanged.

Measured on a synthetic anti-aliased print, the split encoding's overlay positions cost
98 KB of a 376 KB stream, against 234 KB for the overlay's values and 36 KB for the
thresholded core; the attachment bits replace that array. Across the synthetic AA prints
measured for this revision, the attached form is 15% to 50% smaller than the split form the
reference encoder writes for the same pixels.

**Stream format (as stored):**

```
tag              : u8 = 0x03
first_value      : u8                     - value of the core's first run: 0x00 or 0xFF
run_count        : varint                 - runs in the thresholded core (K); 0 is the non-canonical all-black form
even_lengths     : PLANES(ceil((K-1)/2))  - stored lengths at even indices: runs 0, 2, 4, ...
odd_lengths      : PLANES(floor((K-1)/2)) - stored lengths at odd indices: runs 1, 3, 5, ...
aa_pixel_count   : varint                 - pixels in the overlay, in the walk order below
attach_bits      : ceil(K/4) bytes        - two bits per core run
escape_count     : varint                 - overlay pixels that no attachment bit names
escape_positions : PLANES(escape_count)   - delta-encoded absolute pixel indices
aa_values        : PLANES(aa_pixel_count) - the overlay's values, in the walk order
```

**The core.** The core is `threshold(mask)`: `255` where the pixel is `>= 128`, otherwise
`0`. Its runs alternate in value from `first_value` - run `i` carries `first_value` when
`i` is even and the opposite value when `i` is odd - and its length array holds the first
`K-1` run lengths in order, run `K-1` being implicit and ending at `total_pixels`. The AA
pixels are the mask's pixels that are neither `0x00` nor `0xFF`, and the decoded mask is the
core with those pixels written over it. A canonical stream's core is therefore
`threshold(mask)` - the same core [§5.5](#55-split-encoding-binary-ree--sparse-aa-overlay-tag-0x02)
encodes, carrying the overlay differently.

`run_count == 0` is the non-canonical form tag `0x00` also has: it decodes to one black run
over the whole layer, so `first_value` is spent and no length is stored, and the fields that
follow describe an overlay over a core that is black everywhere - `attach_bits` is
`ceil(0/4)`, no bytes at all, so every overlay pixel of that form is an escape. Decoders
MUST accept the form; it is not canonical, and strict-mode validators reject it
(`ree.no_run_count_zero`, [§11.3](17-validation.md#113-layer-data-validation-post-decompression)).

**The parity split.** Stored index `j`, which is run `j`'s length, goes to `even_lengths`
when `j` is even and to `odd_lengths` when `j` is odd, so the two arrays hold
`ceil((K-1)/2)` and `floor((K-1)/2)` values. Stored value `j` is the length itself for
`j < 2`, and `zigzag(length[j] - length[j-2])` for `j >= 2`: each array's first entry is an
absolute length - run 0's in one array and run 1's in the other - and every later entry is a
zigzagged difference against the entry two runs back, which is the previous entry of the
*same* array. The two arrays are therefore walked forward and independently, and same-parity
lengths that are alike collapse exactly as a single length array does
([§5.3.1](#531-significance-planes)).

**Zigzag.** A signed difference `d` is stored as `zigzag(d) = 2d` when `d >= 0` and
`-2d - 1` when `d < 0`; a reader recovers it as `unzigzag(u) = (u >> 1) ^ -(u & 1)`. Either
sign costs one varint, which is what lets a planes array carry differences that run in both
directions.

**Attachment bits.** Two bits per core run, four runs to a byte: run `r` owns the bits at
`2 * (r % 4)` of byte `r / 4`, the first saying "the run's first pixel is an AA pixel" and
the second "the run's last pixel is an AA pixel". `attach_bits` is `ceil(K/4)` bytes; the
bits past the last run address no run and are zero; and a run of one pixel clears its second
bit - it has one pixel, its first, and naming it twice would place one value twice
(`ree.attach_bits`, [§11.3](17-validation.md#113-layer-data-validation-post-decompression)).

**Escape positions.** An AA pixel that no attachment bit names is an **escape**, and an
escape lies strictly inside its core run - its offset in that run is neither `0` nor
`length - 1`. `escape_count` is their number, and `escape_positions` holds their absolute
pixel indices delta coded as tag `0x02`'s overlay positions are: entry `0` is the index
itself, entry `i > 0` is `position[i] - position[i-1]`. They are strictly increasing and
every one of them is below `total_pixels` (`ree.attach_positions`, [§11.3](17-validation.md#113-layer-data-validation-post-decompression)).

**The walk.** The overlay's pixels are visited in pixel order: for each core run in turn,
the run's first pixel when its first bit is set, then the escapes strictly inside that run
in increasing order, then the run's last pixel when its second bit is set. A run is visited
before the runs that follow it, a first pixel precedes the escapes inside it, and those
precede its last pixel, so the walk is the layer's AA pixels in increasing index order -
the bits and the escapes only decide which of them are listed where. `aa_pixel_count` is
exactly how many pixels the walk yields: the attachment bits that are set, plus the escapes.

**Overlay values.** `aa_values` holds those pixels' values in the walk's order, as one
planes array: entry `0` is its value as it is, and entry `i > 0` is
`unzigzag(stored[i]) + value[i-1]`. Consecutive entries are neighbouring edge pixels, whose
values differ by a little, so a band's ramp is a run of small numbers rather than eight bits
of magnitude per pixel. Every value is a byte (`0x00`-`0xFF`), and a stored one that is not
is refused (`ree.attach_count`, [§11.3](17-validation.md#113-layer-data-validation-post-decompression)).

**Encoding algorithm.** The encoder thresholds the mask as it walks its runs; a run's length
is stored when the next run arrives, because only then is the run known not to be the last.
The overlay is decided from the same runs, and the two structures are one sequence:

```
write 0x03 as u8
write first_value as u8              // the core's first run's value
write K as varint                    // the core's run count
for parity in 0, 1:
    write PLANES(the stored values whose stored index j % 2 == parity)
        // value 0 and value 1 are lengths as they are; value j >= 2 is
        // zigzag(length[j] - length[j-2])
write aa_pixel_count as varint       // set attachment bits + escapes
write attach_bits                    // ceil(K / 4) bytes, two bits per run
write escape_count as varint
write PLANES(the escapes' deltas)    // the first absolute, then each difference
write PLANES(the overlay's values)   // walk order: entry 0 as it is, then
                                     // zigzag(value[i] - value[i-1])
```

- A run whose first pixel is an AA pixel sets its first bit, and a run of more than one pixel
  whose last pixel is an AA pixel sets its second bit.
- Every AA pixel strictly inside its run is an escape, and the escapes are listed in
  increasing pixel order.
- The walk is what both sides count: a stream whose bits and escapes describe a different
  number of pixels than `aa_pixel_count` is not one an encoder can write
  (`ree.attach_count`, [§11.3](17-validation.md#113-layer-data-validation-post-decompression)).

**Decoding algorithm:**

```
first_value = read_u8()
run_count = read_varint()
even = read_planes()               // always present: four lengths, zero when empty
odd = read_planes()
lengths = []
last = [0, 0]                      // the last length each parity produced
for j in 0..run_count-1:
    parity = j % 2
    stored = (parity == 0 ? even : odd).next_varint()
    lengths[j] = (j < 2) ? stored : last[parity] + unzigzag(stored)
    last[parity] = lengths[j]

aa_pixel_count = read_varint()
bits = read_bytes(ceil(run_count / 4))
escape_count = read_varint()
pos = 0
escapes = []
for i in 0..escape_count:
    pos += read_varint()           // delta-encoded absolute pixel index
    escapes.push(pos)
values = read_planes()             // PLANES(aa_pixel_count); entry 0 is not a delta

// Step 1: the core's runs, as binary REE walks them
value = first_value
start = 0
for i in 0..run_count:
    end = (i == run_count-1) ? total_pixels : start + lengths[i]
    fill_mask[start .. end] = value
    value = 255 - value            // toggle
    start = end
assert start == total_pixels

// Step 2: the overlay, in the walk's order
value = 0
value_index = 0
overlay_value():
    stored = values.next_varint()
    value = (value_index == 0) ? stored : value + unzigzag(stored)
    value_index += 1
    return value

escape = 0
start = 0
for i in 0..run_count:
    end = (i == run_count-1) ? total_pixels : start + lengths[i]
    first = (bits[i >> 2] >> ((i & 3) * 2)) & 1
    last = (bits[i >> 2] >> ((i & 3) * 2 + 1)) & 1
    if first: mask[start] = overlay_value()
    while escape < escape_count && escapes[escape] < end:
        assert start < escapes[escape] < end - 1   // strictly inside the run
        mask[escapes[escape]] = overlay_value()
        escape += 1
    if last: mask[end - 1] = overlay_value()
    start = end
assert value_index == aa_pixel_count
```

**Worked example.** A 12-pixel layer holding `C0 00 00 00 FF FF 90 80 00 00 B0 FF`
thresholds to the runs `FF×1 00×3 FF×4 00×2 FF×2`, so `first_value` is `0xFF`, `K` is 5 and
the stored lengths are `1 3 4 2` (the implicit fifth run covers the last 2 pixels). Its AA
pixels are `0, 6, 7, 10`: runs 0, 2 and 4 name `0`, `7` and `10` with their attachment bits,
`6` - two pixels into run 2 - is the one escape, and the walk visits `0xC0`, `0x90`, `0x80`,
`0xB0`. The stream is 33 bytes:

```
03 FF 05                   - tag, first_value 0xFF, K = 5
02 00 00 00 01 06          - even_lengths: PLANES([1, zigzag(4-1) = 6])
02 00 00 00 03 01          - odd_lengths:  PLANES([3, zigzag(2-3) = 1])
04                         - aa_pixel_count
21 01                      - attach_bits: run 0 first, run 2 last, run 4 first
01                         - escape_count
01 00 00 00 06             - escape_positions: PLANES([6])
04 01 00 00 C0 5F 1F 60 01 - aa_values: PLANES([0xC0, zigzag(0x90-0xC0) = 95,
                              zigzag(0x80-0x90) = 31, zigzag(0xB0-0x80) = 96])
```

**Degenerate shapes.** Every plane array writes its four lengths whether or not it holds a
value, so the header is unconditional: a `K` of 1 costs `PLANES(0)` in each length array, an
empty escape list and an overlay of no AA pixel cost `PLANES(0)` each, and a `K` of 2 stores
its one length - run 0's - in `even_lengths` and nothing in `odd_lengths`. A layer that is
all one value and carries no AA pixel therefore states itself in 22 bytes where tag `0x00`
states the same layer in 7, which is why tag `0x00` remains the canonical choice for it
([§5.7](#57-canonical-encoding)). A run of one pixel whose pixel is an AA pixel carries its
first bit and no second; an escape sits at least one pixel inside its run, so a two-pixel run
has none and a long run's second pixel is the first offset an escape can take.

### 5.7 Canonical Encoding

`LHAS` ([§4.10](09-layer-data.md#410-lhas---layer-hash-chunk)) hashes the decompressed bytes of each layer, so a stream that is legal
but not canonical yields a different hash for identical pixel content. This section
defines the canonical form for each tag, and the one choice left to the encoder.

**Tag choice.**

- A `(layer, sector)` with no exposed pixels uses the empty-slice form (`LTBL` entry
  `data_size == 0`); no tag is stored.
- A layer whose pixels are all `0x00` or `0xFF` MUST use tag `0x00` (binary REE) or tag
  `0x03` (attached REE) with `aa_pixel_count == 0`, where the attached form degenerates to
  the parity-split binary core. Either is permitted; see "Reproducibility scope" below.
- Otherwise the layer MUST use tag `0x01` (grayscale REE), tag `0x02` (split REE) or tag
  `0x03` (attached REE). Tag `0x03` with a non-zero `aa_pixel_count` is the attached form,
  and any of the three is permitted; see "Reproducibility scope" below.

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

**Canonical attached REE (tag `0x03`).** The core is the run decomposition of
`threshold(mask)` (`255 if v >= 128 else 0`), so `first_value` is its first run's value and
the stored lengths are that decomposition's first `K-1` run lengths in order - every length
`>= 1`, and together with the implicit final run they sum to exactly `total_pixels`. Stored
index `j` is the length's position in that array and its stored value is the length itself
for `j < 2` and `zigzag(length[j] - length[j-2])` after that, so no length can be reordered,
padded or dropped. `attach_bits` sets exactly the bits of the runs whose first or last pixel
is an AA pixel - a run of one pixel clears its second bit, and the bits past the last run are
clear; the escapes are exactly the AA pixels strictly inside their run, strictly increasing;
and every overlay value is neither `0x00` nor `0xFF` and thresholds to the value of the core
run it is written into. With `aa_pixel_count == 0` the form states a layer that has no AA
pixels at all, and the whole overlay is empty by the same rules.

**Reproducibility scope.**

- Deterministic: the empty-slice form and tag `0x00` fix the bytes for their content.
- Encoder's choice: the tag among those permitted for the layer. Picking the smaller
  requires encoding the candidates, which is a cost/ratio trade-off rather than a correctness
  one, and the comparison is on compressed size - a stream's raw length does not predict it
  ([§B.4](20-appendix-b-encoder.md#b4-the-defaults-and-where-they-come-from)). An encoder that
  evaluates them SHOULD break ties in favour of the lower tag.
- Required of every encoder: identical input and settings produce identical output, so
  re-slicing the same scene yields the same file and the same `LHAS` hashes. Two things are
  inputs rather than derived values, and a file that differs only in them is still the same
  file in every other byte: the creation timestamp an encoder stamps into `HEAD`, and - for
  sealed output - the random keys and nonces of [§9.4](15-encryption.md#94-session-key-lifecycle)
  ([§4.1](04-head.md#41-head---file-header-chunk)).
- Not claimed: that two different encoders produce identical bytes, or identical `LHAS`
  hashes, for the same layer.

A decoder MUST accept any stream that satisfies [§5.3](#53-binary-ree-no-anti-aliasing)-[§5.6](#56-attached-encoding-parity-split-ree--attached-aa-tag-0x03), canonical or not; strict-mode
validators MAY reject non-canonical streams ([§11.3](17-validation.md#113-layer-data-validation-post-decompression)).

### 5.8 Resin Working Curve (Experimental)

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
  ([§4.11](10-scene-chunks.md#411-voxl---embedded-scene-chunk)) and `cure_curve` parameters, Odyssey can re-slice the scene using the
  `dragonfruit-slicing-engine` Rust crate (the same engine that produced the
  original file), then compute the correct exposure from the curve:  
  `E_new = Ec × exp(Cd_new / Dp)`. No guesswork, no test prints. Without the
  VOXL, the cure curve still helps validate that the existing exposure is
  appropriate for the given layer height.

  **Adaptive layer height is not available in v1.** It needs per-layer heights in the
  file, and v1 has nowhere to put them: `HEAD.layer_height_um` is a single default, and
  the `VLYR` extension is non-critical ([§4.12](10-scene-chunks.md#412-extd---extension-chunk)), so a conforming reader may skip it and
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
