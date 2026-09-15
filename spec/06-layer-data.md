# Layer data chunks

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 4.7 LTBL - Layer Table Chunk

**Type tag:** `LTBL` (`0x4C 0x54 0x42 0x4C`). Required. Exactly one per file.

**Flags:** uncompressed, unencrypted.

Indexes the chunk directory for every `(layer, sector)` pair: which `LAYR` chunk holds that
pair's data, where inside that chunk's decompressed output the slice lies, and which `LROV`
chunk carries its overrides. The table is also the only place a file says which sectors a
layer carries, and in which order.

**Header:**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `table_version` | Layout version. `1` for this spec. |
| 4 | 4 | `u32` | `layer_count` | Must equal `HEAD.total_layers`. |
| 8 | 4 | `u32` | `entry_size` | Bytes per entry. `28` for v1. Readers must stride by this value. |
| 12 | 4 | `u32` | `entry_count` | Total entries: the sum, over every layer's first entry, of `1 + additional_sector_count`. The table ends exactly there. |
| 16 | N | - | `entries` | `entry_count` × `entry_size` bytes. |

**Entry (v1, 28 bytes).** One per `(layer, sector)`, grouped by layer, ascending `sector_id`
within a layer, a layer's first entry being sector 0's:

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `data_size` | Bytes of this layer's data for this sector; `0` = none. |
| 4 | 4 | `u32` | `first_lrov` | Directory index of this `(layer, sector)`'s `LROV` chunk; `0` = no overrides (index 0 is `HEAD`, so `0` is safely NULL). |
| 8 | 4 | `u32` | `first_layr` | Directory index of the `LAYR` chunk holding this sector's run. |
| 12 | 4 | `u32` | `additional_sector_count` | Further entries for this layer, ascending `sector_id`; non-zero only on the layer's first entry. |
| 16 | 8 | `u64` | `data_offset` | Offset of this layer's slice inside `first_layr`'s decompressed output. |
| 24 | 4 | `u32` | `sector_id` | This entry's sector; `0` is primary. |

A layer's entries are contiguous: the entry for `(layer L, sector 0)` is the first of the
`1 + additional_sector_count` entries that follow it, and the reader reaches layer `L + 1` by
stepping over exactly that many. Since the count lives on the first entry, the file states
each layer's sector count once, and the rest of the entries are ordered by the `sector_id`
they carry.

**Invariants:**

- `entry_count` equals the sum of `1 + additional_sector_count` over each layer's first entry,
  the table holds exactly that many entries - no trailing slack, no entry past the end - and
  a layer's non-first entries carry `additional_sector_count == 0`.
- The chunk payload is exactly `16 + entry_count × entry_size` bytes: the table ends at the
  end of the chunk, with no slack after it.
- Within a layer, `sector_id` ascends and is unique; a layer's first entry is sector 0's.
- `first_layr` is a `LAYR` chunk directory index, and `data_offset + data_size` fits the
  decompressed output of that chunk.
- Slices of one `LAYR` chunk do not overlap: no two entries that name the same chunk describe
  intersecting byte ranges.
- `first_lrov` is `0` or an `LROV` chunk directory index; it is `0` only when that
  `(layer, sector)` has no overrides, and every `LROV` chunk in the file is named by exactly
  one entry - no two entries share one, and none is left unreferenced
  ([§4.5](05-print-control.md#45-lrov---layer-override-chunk)).
- A layer whose every entry has `data_size == 0` is the empty layer, all black.

**Sectors and the `MULTI_SECTOR` flag.** `MULTI_SECTOR` is set exactly when at least one layer
carries more than one sector ([§3.1](02-file-structure.md#31-file-header)). A single-sector
file has one entry per layer, all with `sector_id == 0` and
`additional_sector_count == 0`, and is laid out like any other: there is no second layout for
the single-sector case.

## 4.8 ZDIC - Zstd Dictionary Chunk

**Type tag:** `ZDIC` (`0x5A 0x44 0x49 0x43`). Optional.

**Flags:** uncompressed. Encrypted if `AUTH` present.

Carries the zstd dictionary shared by the `LAYR` frames. The dictionary MUST be
available before any `LAYR` frame is decompressed. Because a trained dictionary is
built from samples of the print's own layer data, it is treated as content: it is
encrypted alongside the other content chunks when `AUTH` is present.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `u32` | `zdic_version` | Layout version. `1` for this spec. |
| 4 | 4 | `u32` | `dict_id` | Zstd dictionary ID (`ZSTD_getDictID_fromDict()`). Must equal the dictionary ID reported by every `LAYR` frame. |
| 8 | 4 | `u32` | `dict_size` | Byte length of `dict_bytes`. Must not exceed 112 640 bytes (zstd's `ZDICT_DICTSIZE_MAX`). |
| 12 | N | `[u8; N]` | `dict_bytes` | Raw dictionary bytes exactly as produced by `ZDICT_trainFromBuffer()`. |

**Presence rules:**

- If any `LAYR` frame was compressed with a dictionary, exactly one `ZDIC` chunk
  MUST be present, and every `LAYR` frame's dictionary ID MUST equal `ZDIC.dict_id`.
- If no dictionary was used, `ZDIC` MUST be absent and every `LAYR` frame's
  dictionary ID MUST be `0`.
- A file MUST NOT contain more than one non-null `ZDIC` chunk.
- Writers MUST NOT suppress the zstd dictionary ID (`ZSTD_c_dictIDFlag`). Every `LAYR`
  frame compressed with the dictionary reports `dict_id`, so a reader can always tell
  whether a dictionary is required.

**Design notes:**

- `ZDIC` is stored uncompressed so it can be handed directly to the decompressor,
  without a preliminary decompression pass.
- The dictionary is not covered by the `LHAS` Merkle tree (which covers layer data).
  Files that need full-artifact integrity rely on the `CRC-32C` trailer or an
  `EXTD`/`SIGN` signature.

## 4.9 LAYR - Layer Data Chunk

**Type tag:** `LAYR` (`0x4C 0x41 0x59 0x52`). Required. One chunk per `(sector, layer
group)`.

**Flags:** uncompressed container; the frame inside is zstd-compressed. Encrypted if `AUTH`
present - the version field stays plaintext and the frame is the sealed unit
([§9.3](12-encryption.md#93-encryption-format)).

A chunk holds one sector's mask data for a run of layers, and never two sectors' data: the
sector a chunk belongs to is stated by the layer table entries that name it, not by the
chunk. The chunk carries exactly one zstd frame over the concatenation of that group's layer
data for that sector, layers in ascending order:

```
[layer_a_data] [layer_{a+1}_data] ... [layer_b_data]
```

A layer's data for this sector starts at `LTBL` entry `data_offset` within the frame's
decompressed output and has size `data_size`; the entry's `first_layr` names this chunk. A
sector that is absent from a layer contributes no bytes to the frame, and its entry carries
`data_size == 0`.

**Payload layout:**

```
layr_version : u32   - Layout version. 1 for this spec.
frame        : [u8]  - One zstd frame over the concatenation described above.
```

**Descriptor.** The version field is a container header, not part of the frame:
`size_uncompressed` is the container's byte length - 4 plus the frame's stored length - and
`size_compressed` is `0` when the frame is not sealed, the container's stored length when it
is. Sealing adds 28 bytes of AEAD framing ([§9.3](12-encryption.md#93-encryption-format)), so
a sealed container is `4 + 28 + frame_length` bytes and the frame's stored length is
`size_compressed - 32`. Neither figure is the frame's output length: that is the content size
the frame itself declares ([§3.2](02-file-structure.md#32-chunk-descriptor)).

There is no block table and no per-layer framing. The frame's output carries the layers'
data back to back, and the layer table is what says where each slice begins and ends.

**Frame invariants:**

- The frame MUST declare its content size, and decompressing it MUST yield exactly that many
  bytes. The content size is the length of the concatenation above; a reader sizes its
  decode buffer from it, so it never trusts a second field to agree with a first.
- A frame with a non-zero zstd dictionary ID requires a `ZDIC` chunk ([§4.8](#48-zdic---zstd-dictionary-chunk))
  whose `dict_id` matches, and every `LAYR` frame in the file agrees with `ZDIC.dict_id`.
- For every entry that names this chunk, `data_offset + data_size` is at most the frame's
  decompressed length, and the byte ranges those entries describe do not overlap.

**Recommended frame span:** 32–64 layers. Small enough that a reader seeking to an
arbitrary layer decompresses only a few megabytes, large enough that the shared
dictionary and inter-layer similarity keep compression close to what a single frame
would achieve. Encoders MAY choose any span that satisfies the invariants above; a
frame per layer also conforms.

**Per-layer data format.** Every `(layer, sector)` slice begins with a 1-byte encoding tag,
followed by the encoded mask data:

```
tag          : u8         - Encoding tag. See the encoding tag table in [§5](08-layer-encoding.md#5-layer-mask-encoding).
mask_data    : [u8]       - REE stream in the format specified by the tag.
```

Sector identity is structural, so the stream carries no sector framing: no `sector_count`
varint, no per-sector id and no per-sector length. Each sector's data is encoded on its own,
exactly as a single-sector file's layer is, and a reader that decodes one sector reads the
same byte form whether or not the file has others.

A `(layer, sector)` with no exposed pixels has `data_size == 0` and stores no bytes - no tag
byte and no mask. That is the canonical encoding for an all-black slice, and it is the same
form whether the layer as a whole is empty or only this sector is.

## 4.10 LHAS - Layer Hash Chunk

**Type tag:** `LHAS` (`0x4C 0x48 0x41 0x53`). Optional.

**Flags:** uncompressed, unencrypted.

Carries per-layer cryptographic hashes and a Merkle tree root for integrity
verification. This enables:

- **Resume-after-power-loss:** verify which layers are intact on restart.
- **Silent corruption detection:** network transfer errors, bit rot on storage.
- **Bounded verification:** verify any single layer by decompressing only the `LAYR`
  chunks that hold its slices ([§4.9](#49-layr---layer-data-chunk)), not the whole file.

**Payload:**

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 1 | `u8` | `hash_algorithm` | `0x01` = SHA-256. |
| 1 | 1 | `u8` | `hash_size` | `32` for SHA-256. |
| 2 | 4 | `u32` | `layer_count` | Must equal `HEAD.total_layers`. |
| 6 | 32 | `[u8; 32]` | `merkle_root` | Root hash of the Merkle tree over all layer hashes. |
| 38 | N | - | `layer_hashes` | `layer_count × hash_size` bytes. `layer_hashes[i]` is the leaf hash `SHA-256(0x00 \|\| d)`, where `d` is layer `i`'s data: the slices its `LTBL` entries describe, concatenated in ascending `sector_id`, each byte range `[data_offset, + data_size)` taken from its `LAYR` chunk's decompressed output. An empty layer stores `SHA-256(0x00)`. |

Because these hashes cover decompressed bytes, they are reproducible only if encoders
agree on the byte stream; [§5.6](08-layer-encoding.md#56-canonical-encoding) defines that canonical form.

**Merkle tree construction** (domain-separated, RFC 6962 style):

1. **Leaves:** `H[i] = SHA-256(0x00 || layer_data_i)` for `i` in `0..layer_count`,
   where `layer_data_i` is the byte string defined for `layer_hashes[i]` above.
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
1. Decompress each `LAYR` chunk's frame and recover each layer's slices from it; for a
   layer whose entries name more than one chunk, concatenate its slices in ascending
   `sector_id` before hashing.
2. Verify each hash matches `layer_hashes[i]`.
3. Recompute the Merkle root from `layer_hashes`; verify it matches `merkle_root`.

**Design notes:**
- LHAS is uncompressed so it can be verified without initializing the decompressor.
- The Merkle root in LHAS replaces the weaker CRC-32C trailer for integrity
  purposes. The CRC-32C trailer remains for quick file-completeness checks.
- 32 bytes per layer = 320 KB for a 10 000-layer print - acceptable overhead
  for the integrity guarantee.
- For memory-constrained devices, the verifier processes one `LAYR` chunk at a time:
  decompress the chunk, hash each layer slice it holds, fold those hashes into the
  Merkle tree, then release the chunk. Peak memory is one chunk plus the leaf hash
  table, never the whole layer stream.
