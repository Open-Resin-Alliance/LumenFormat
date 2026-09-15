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

Presence of `PREV`, `EXTD` and `LHAS` is discovered from the chunk directory, not
from the header; only the two flags below are defined.

| Bit | Name | Description |
|-----|------|-------------|
| 0 | - | Reserved. Must be 0. |
| 1 | `MULTI_SECTOR` | At least one layer carries more than one sector. |
| 2 | - | Reserved. Must be 0. |
| 3 | `ENCRYPTED` | File contains an `AUTH` chunk; content chunks are encrypted. |
| 4 | - | Reserved. Must be 0. |
| 5–31 | - | Reserved. Must be 0. Readers must ignore unknown flags. |

### 3.2 Chunk Descriptor

Each entry in the Chunk Directory is 32 bytes.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `chunk_type` | Four ASCII characters. e.g. `HEAD`, `META`. |
| 4 | 8 | `u64` | `offset` | Absolute byte offset from start of file to chunk payload. `0` = null descriptor (skip). |
| 12 | 8 | `u64` | `size_uncompressed` | Size of the payload after decompression. `LAYR` is the exception: the container's byte length ([§4.9](06-layer-data.md#49-layr---layer-data-chunk)). |
| 20 | 8 | `u64` | `size_compressed` | Size as stored. `0` = the payload is stored as it is, with nothing wrapped around it. |
| 28 | 4 | `u32` | `flags` | Chunk-specific flags. See per-chunk definitions. |

**Stored size:** `size_compressed` is the payload's on-disk byte length, including
any AEAD framing ([§9.3](12-encryption.md#93-encryption-format)). `0` means the payload is stored as it
is, with nothing wrapped around it, so the on-disk length is `size_uncompressed`.

**Compression:** whether a chunk payload carries a zstd frame is a property of its
chunk type, not of `size_compressed` ([§6.3](09-compression.md#63-per-chunk-compression-policy)). For a compressed chunk the payload is a
zstd frame that decompresses to `size_uncompressed` bytes; for an uncompressed chunk
the payload bytes are the chunk data itself. This matters for chunks that are stored
uncompressed but may still be encrypted (`ZDIC`, `PREV`): their `size_compressed` is
non-zero yet there is no zstd layer to undo.

`LAYR` is the one chunk whose `size_uncompressed` is not its decompressed size. Its payload
is a version field followed by exactly one zstd frame ([§4.9](06-layer-data.md#49-layr---layer-data-chunk)), and `size_uncompressed` is the
byte length of that container - what an unsealed chunk stores, since the version field is
never compressed. The frame's output length is not in the descriptor: it is the content size
the frame declares, and every `LAYR` frame carries one.

**Encryption:** if the `ENCRYPTED` flag (bit 4) is set in the chunk descriptor's
`flags` field, the payload is encrypted as described in
[§9.3](12-encryption.md#93-encryption-format): for most chunks the whole payload is
one sealed unit, while `LAYR` keeps its version field plaintext and seals the one
frame that follows it. This is per-chunk encryption, distinct from the
file-level `ENCRYPTED` flag (header bit 3) which signals the presence of an `AUTH`
chunk.

**Null descriptors** (`offset == 0`) are ignored. Writers may pre-allocate directory
space with null descriptors.

**Alignment.** Readers MUST NOT assume any alignment for a chunk payload. Writers
SHOULD place payloads at 8-byte-aligned offsets - the explicit `offset` field makes the
resulting gaps free - so an embedded reader can map or DMA into a payload directly.

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
   chunk flags have bit 4 set; decompress if the chunk type is compressed ([§6.3](09-compression.md#63-per-chunk-compression-policy));
   dispatch by `chunk_type`.
