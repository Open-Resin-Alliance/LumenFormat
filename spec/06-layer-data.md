# Layer data chunks

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

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
| 8 | 4 | `u32` | `block_index` | Index into the LAYR block table ([§4.10](#410-layr---layer-data-chunk)) of the block containing this layer. |
| 12 | 4 | `u32` | `data_size` | Byte size of this layer's REE data within its block. |
| 16 | 4 | `u32` | `sector_count` | Sectors active on this layer. 0 = empty layer (all black); in single-sector mode a non-empty layer has exactly `1`. |

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
- Writers MUST NOT suppress the zstd dictionary ID (`ZSTD_c_dictIDFlag`). Every block
  frame compressed with the dictionary reports `dict_id`, so a reader can always tell
  whether a dictionary is required.

**Design notes:**

- `ZDIC` is stored uncompressed so it can be handed directly to the decompressor,
  without a preliminary decompression pass.
- The dictionary is not covered by the `LHAS` Merkle tree (which covers layer data).
  Files that need full-artifact integrity rely on the `CRC-32C` trailer or an
  `EXTD`/`SIGN` signature.

### 4.10 LAYR - Layer Data Chunk

**Type tag:** `LAYR` (`0x4C 0x41 0x59 0x52`). Required.

**Flags:** uncompressed at the chunk level; contains zstd-compressed block frames.
Encrypted if `AUTH` present (see [§9.3](12-encryption.md#93-encryption-format) - each block frame is a separate AEAD unit).

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
  block_table_entry_size  : u32   - Bytes per block table entry. 24 for v1.
  block_table             : block_count × block_table_entry_size bytes

block_region:
  [block_0_frame] [block_1_frame] ... [block_{block_count-1}_frame]
```

The chunk descriptor for `LAYR` stores the container uncompressed, but
`size_compressed` depends on whether the block frames are sealed: `0` when they are
not, and the stored container length - including the 28 bytes of AEAD framing per
sealed block frame ([§9.3](12-encryption.md#93-encryption-format)) - when they are. `size_uncompressed` is the
container's byte length either way.

**Block table entry (v1, 24 bytes):**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 8 | `u64` | `frame_offset` | Byte offset of the block frame from the start of `block_region`. |
| 8 | 8 | `u64` | `frame_size` | Stored size of the frame. Includes AEAD framing overhead when block frames are encrypted. |
| 16 | 8 | `u64` | `uncompressed_size` | Exact size of the block's decompressed output. |

Both sizes are 64-bit because a block's output is not bounded by `u32`: worst-case
REE (a dithered or checkerboard layer) is roughly 5 bytes per pixel, so a 64-layer
block at 12K can exceed 4 GB even though a single layer cannot.

**Block invariants:**

- `block_count >= 1` and `block_count <= HDR.total_layers`.
- Blocks are ordered and cover every layer exactly once: block `0` starts at layer 0,
  block `k+1` begins where block `k` ends, and therefore
  `LTBL.entries[i].block_index` is non-decreasing in `i`.
- Every block index in `0..block_count` is referenced by at least one layer.
- Decompressing block `k` yields exactly `block_table[k].uncompressed_size` bytes.
- A block frame with a non-zero zstd dictionary ID requires a `ZDIC` chunk ([§4.9](#49-zdic---zstd-dictionary-chunk))
  whose `dict_id` matches.

**Recommended block size:** 32–64 layers. Small enough that a reader seeking to an
arbitrary layer decompresses only a few megabytes, large enough that the shared
dictionary and inter-layer similarity keep compression close to what a single frame
would achieve. Encoders MAY choose any size that satisfies the invariants above.

**Per-layer data format - single-sector** (`MULTI_SECTOR` flag = 0):

Each layer's data begins with a 1-byte encoding tag, followed by the encoded
mask data:

```
tag          : u8         - Encoding tag. See the encoding tag table in [§5](08-layer-encoding.md#5-layer-mask-encoding).
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
  that contains it ([§4.10](#410-layr---layer-data-chunk)), not the whole file.

**Payload:**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 1 | `u8` | `hash_algorithm` | `0x01` = SHA-256. |
| 1 | 1 | `u8` | `hash_size` | `32` for SHA-256. |
| 2 | 4 | `u32` | `layer_count` | Must equal `HDR.total_layers`. |
| 6 | 32 | `[u8; 32]` | `merkle_root` | Root hash of the Merkle tree over all layer hashes. |
| 38 | N | - | `layer_hashes` | `layer_count × hash_size` bytes. `layer_hashes[i]` is the leaf hash `SHA-256(0x00 \|\| d)`, where `d` is layer `i`'s data exactly as it appears in the decompressed output of its block: the byte range `[LTBL.entries[i].data_offset, + data_size)`. An empty layer stores `SHA-256(0x00)`. |

Because these hashes cover decompressed bytes, they are reproducible only if encoders
agree on the byte stream; [§5.6](08-layer-encoding.md#56-canonical-encoding) defines that canonical form.

**Merkle tree construction** (domain-separated, RFC 6962 style):

1. **Leaves:** `H[i] = SHA-256(0x00 || layer_data_i)` for `i` in `0..layer_count`,
   where `layer_data_i` is the byte range defined for `layer_hashes[i]` above.
   `layer_hashes[i]` stores this leaf hash.
2. **Internal nodes:** `parent = SHA-256(0x01 || left || right)`.
3. **Odd levels:** when a level holds an odd number of nodes, the final node is
   promoted to the next level unchanged. Hashes are never duplicated or repeated.
4. **Root:** repeat steps 2-3, promoting the odd node at each level, until one node
   remains. That node is `merkle_root`. For `layer_count == 1` the root is the single
   leaf.

The `0x00`/`0x01` prefixes keep leaf hashes distinguishable from internal-node
hashes, so two different layer sets cannot produce the same root.

**Verifying a single layer `i`:** compute the leaf hash `SHA-256(0x00 || d)`, combine
it with sibling hashes along the Merkle path (at most `ceil(log2(layer_count))` of
them) using the internal-node rule, and check that the result equals `merkle_root`.
Every sibling hash is recoverable from `layer_hashes`.

**Verifying the entire file:**
1. Decompress each block and, for each layer it contains, compute `SHA-256(0x00 || d)`
   over the layer's byte range `d` within that block's output.
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
