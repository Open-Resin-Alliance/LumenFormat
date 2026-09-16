# File structure

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 3. File Structure

A `.lumen` file is a chunk-based binary container with the directory placed at the
**end** of the file (like ZIP's central directory). This enables streaming writers to
append chunks in a single pass without knowing the final layout upfront.

```
+-------------------+
| File Header       |  32 bytes, fixed
+-------------------+
| Chunk 0           |  HEAD (required, must be first)
+-------------------+
| Chunk 1           |  META (required)
+-------------------+
| Chunk 2           |  PROF (optional, reusable print profile)
+-------------------+
| Chunk 3           |  AUTH (optional, encryption metadata)
+-------------------+
| Chunk 4           |  LROV (optional, per-(layer, sector) overrides)
+-------------------+
| Chunk 5           |  ZDIC (optional, zstd dictionary shared by the LAYR frames)
+-------------------+
| Chunk 6           |  LTBL (required, the layer table)
+-------------------+
| Chunk 7           |  LAYR (required, one per (sector, layer group))
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

Only HEAD must be the first chunk. All other chunks may appear in any order;
the layout above is a recommendation, not a requirement. Readers must tolerate
any ordering.

`HEAD` is the first entry in the chunk directory, and this revision's writer places its
payload at offset 32, immediately after the fixed header. A reader MUST NOT require that
offset: what it reads is the directory, and a gap between the header and the first payload
is legal as long as the descriptor says so ([§3.2](#32-chunk-descriptor)).

### 3.1 File Header

32 bytes, fixed. Always at offset 0.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `magic` | `LUMN` (`0x4C 0x55 0x4D 0x4E`) |
| 4 | 4 | `u32` | `version` | File format version. `1` for this spec. |
| 8 | 8 | `u64` | `dir_offset` | Byte offset from start of file to Chunk Directory. |
| 16 | 4 | `u32` | `chunk_count` | Total number of chunks (matching directory entries). |
| 20 | 4 | `u32` | `flags` | Bitfield. See below. |
| 24 | 8 | `u64` | `total_uncompressed_size` | Sum of every chunk's `size_uncompressed` field. `0` = unknown (streaming writers). |

**Flags bitfield (bit 0 = LSB):**

Presence of `PREV`, `EXTD` and `LHAS` is discovered from the chunk directory, not
from the header; only the two flags below are assigned.

| Bit | Name | Description |
|-----|------|-------------|
| 0 | - | Retired. A writer MUST clear it; a reader MUST reject a file that sets it. |
| 1 | `MULTI_SECTOR` | At least one layer carries more than one sector. |
| 2 | - | Retired. A writer MUST clear it; a reader MUST reject a file that sets it. |
| 3 | `ENCRYPTED` | File contains an `AUTH` chunk; content chunks are encrypted. |
| 4 | - | Retired. A writer MUST clear it; a reader MUST reject a file that sets it. |
| 5–31 | - | Unassigned. A writer MUST clear them; a reader MUST ignore them. |

Bits 0–4 are the control range this revision knows: bit 1 and bit 3 are assigned, and the
other three were assigned in earlier drafts and are retired. A file that sets a retired bit
was written against a header layout this revision does not know - the bit said something
then and says nothing now - so a reader rejects it rather than guess, and validation reports
it under `header.flags_reserved`. Bits 5–31 were never assigned to anything, so a set bit
there is a future flag: a v1 reader has nothing to lose by ignoring it, and MUST.

**`total_uncompressed_size`** is a plain sum of the descriptors' `size_uncompressed`
fields, `LAYR` chunks included. For `LAYR` that field is the container's byte length rather
than a decompressed length ([§4.9](09-layer-data.md#49-layr---layer-data-chunk)), so a
writer must not substitute the frame's declared content size for it; a validator compares
the header against that same sum ([§11.1](17-validation.md#111-structural-validation)).

### 3.2 Chunk Descriptor

Each entry in the Chunk Directory is 32 bytes.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `chunk_type` | Four ASCII characters. e.g. `HEAD`, `META`. |
| 4 | 8 | `u64` | `offset` | Absolute byte offset from start of file to chunk payload. `0` = null descriptor (skip). |
| 12 | 8 | `u64` | `size_uncompressed` | Size of the payload after decompression. `LAYR` is the exception: the container's byte length ([§4.9](09-layer-data.md#49-layr---layer-data-chunk)). |
| 20 | 8 | `u64` | `size_compressed` | Size as stored. `0` = the payload is stored as it is, with nothing wrapped around it. |
| 28 | 4 | `u32` | `flags` | Chunk flags. Bit 4 is common to every chunk type; the rest are per-chunk. See below. |

**Chunk flags (bit 0 = LSB):**

| Bit | Name | Description |
|-----|------|-------------|
| 4 | `ENCRYPTED` | The payload is sealed ([§9.3](15-encryption.md#93-encryption-format)). Assigned for every chunk type; the only bit a reader may act on without knowing the type. |
| 0–3, 5–31 | - | Chunk-specific. Reserved and zero unless the chunk's own section assigns them, which `PREV` ([§4.6](08-print-control.md#46-prev---preview-image-chunk)) and `EXTD` ([§4.12](10-scene-chunks.md#412-extd---extension-chunk)) do. |

A reader that does not implement a chunk type MUST NOT read anything out of its `flags` but
bit 4, and MUST NOT reject a chunk for a set bit its own section does not assign: the bit may
belong to a later revision of that chunk, which is what its sub-version field is for
([§10.2](16-versioning.md#102-forward-compatibility-mechanisms)).

**Stored size:** `size_compressed` is the payload's on-disk byte length, including
any AEAD framing ([§9.3](15-encryption.md#93-encryption-format)). `0` means the payload is stored as it
is, with nothing wrapped around it, so the on-disk length is `size_uncompressed`.

**Compression:** whether a chunk payload carries a zstd frame is a property of its
chunk type, not of `size_compressed` ([§6.3](12-compression.md#63-per-chunk-compression-policy)), with one exception - `EXTD`, whose
compression is per-extension ([§4.12](10-scene-chunks.md#412-extd---extension-chunk)). For `EXTD` the descriptor
answers instead, and the rule is the one this section has already given for `size_compressed`:
an unsealed extension with a non-zero `size_compressed` holds a zstd frame, and one with
`size_compressed == 0` holds its payload as it is. A sealed extension is left alone, as its
framing hides whether a frame is inside and no standard extension exists to say. For a
compressed chunk the payload is a
zstd frame that decompresses to `size_uncompressed` bytes; for an uncompressed chunk
the payload bytes are the chunk data itself. This matters for chunks that are stored
uncompressed but may still be encrypted (`ZDIC`, `PREV`): their `size_compressed` is
non-zero yet there is no zstd layer to undo.

`LAYR` is the one chunk whose `size_uncompressed` is not its decompressed size. Its payload
is a version field followed by exactly one zstd frame ([§4.9](09-layer-data.md#49-layr---layer-data-chunk)), and `size_uncompressed` is the
byte length of that container - what an unsealed chunk stores, since the version field is
never compressed. The frame's output length is not in the descriptor: it is the content size
the frame declares, and every `LAYR` frame carries one.

**Encryption:** if the `ENCRYPTED` flag (bit 4) is set in the chunk descriptor's
`flags` field, the payload is encrypted as described in
[§9.3](15-encryption.md#93-encryption-format): for most chunks the whole payload is
one sealed unit, while `LAYR` keeps its version field plaintext and seals the one
frame that follows it. This is per-chunk encryption, distinct from the
file-level `ENCRYPTED` flag (header bit 3) which signals the presence of an `AUTH`
chunk.

**Null descriptors** (`offset == 0`) are ignored. Writers may pre-allocate directory
space with null descriptors.

**Alignment.** Readers MUST NOT assume any alignment for a chunk payload. Writers
SHOULD place payloads at 8-byte-aligned offsets - the explicit `offset` field makes the
resulting gaps free - so an embedded reader can map or DMA into a payload directly.

**The payload region.** Every chunk payload lies in `[32, dir_offset)`: after the fixed
header and before the directory. A chunk that starts inside the directory or after it is a
`dir.chunk_extent` failure ([§11.1](17-validation.md#111-structural-validation)), even when
its bytes do not overlap a descriptor - the directory is written last and read first, and a
payload past its start is a file whose layout does not mean what the header says.

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
   chunk flags have bit 4 set; decompress if the chunk type is compressed ([§6.3](12-compression.md#63-per-chunk-compression-policy));
   dispatch by `chunk_type`.
