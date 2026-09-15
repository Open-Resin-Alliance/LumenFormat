# Reader validation requirements

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 11. Reader Validation Requirements

### 11.1 Structural Validation

- [ ] Magic bytes `LUMN` at offset 0.
- [ ] Trailer magic `LEND` at `file_size - 8`.
- [ ] Trailer CRC-32C matches `bytes[0 .. file_len-8]`.
- [ ] `header.version` is recognized.
- [ ] `HDR.hdr_version`, `LTBL.table_version`, `LAYR.layr_version`, `ZDIC.zdic_version` and `AUTH.auth_version` are recognized.
- [ ] `header.dir_offset` is within file bounds.
- [ ] If `header.total_uncompressed_size != 0`, it equals the sum of every chunk's `size_uncompressed`.
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
- [ ] If `LHAS` chunk present, `layer_count` equals `HDR.total_layers`.

### 11.2 Semantic Validation

- [ ] `HDR.total_layers > 0` and `HDR.total_layers == LTBL.layer_count`.
- [ ] `LTBL.entry_size >= 20`. The layout is fixed through offset 20; future versions may append fields after offset 20, and readers stride by `entry_size` to skip unknown trailing fields.
- [ ] `HDR.layer_height_um > 0`.
- [ ] `HDR.build_width_um > 0`, `HDR.build_depth_um > 0`, `HDR.build_height_um > 0`.
- [ ] `HDR.encoder_name_len <= 256`, and `HDR.size_uncompressed >= 52 + encoder_name_len` - the fixed fields before and after the name total 52 bytes, so a v1 `HDR` chunk is exactly `52 + encoder_name_len` bytes.
- [ ] Every `LTBL.entries[i].block_index` is less than `LAYR.block_count`, and the sequence of `block_index` values is non-decreasing in `i`.
- [ ] (Multi-sector only) For every layer `i` with `LTBL.entries[i].sector_count > 0`, the `sector_count` varint at the start of that layer's data within its block equals `LTBL.entries[i].sector_count` (the LAYR value is authoritative for decoding). Layers with `sector_count == 0` store no bytes at all. In single-sector mode, layer data starts with the encoding tag byte, not a `sector_count` varint.
- [ ] (Single-sector only) Every non-empty layer has `LTBL.entries[i].sector_count == 1`.
- [ ] `HDR.display_width_px × display_height_px > 0`.
- [ ] `HDR.physical_width_px` is an integer multiple of `display_width_px`, and `physical_height_px` is an integer multiple of `display_height_px`. A ratio of 1 means one display pixel per physical pixel.
- [ ] `META.meta_version` is present and recognized.
- [ ] META JSON contains all required fields (`meta_version`, `normal_exposure_ms`, `bottom_exposure_ms`, `bottom_layer_count`, `transition_layer_count`, `layer_height_um`, `lift_slow_distance_um`, `lift_slow_speed_um_min`, `retract_fast_distance_um`, `retract_fast_speed_um_min`).
- [ ] Every `*_ms` field in META is a JSON integer. A value with a fractional part such as `2500.5` is invalid (`meta.time_integer`); see [§4.2](03-chunks.md#42-meta---metadata-chunk) for the encoders' and readers' obligations.
- [ ] `META.normal_exposure_ms > 0`, as an integer comparison.
- [ ] `META.bottom_exposure_ms > 0`, as an integer comparison.
- [ ] `META.layer_height_um > 0`.
- [ ] If `MULTI_SECTOR` flag set, ≥1 `SECT` chunk present.
- [ ] All `SECT.sector_id` values unique.
- [ ] Every `*_ms` field in a `SECT` chunk is a JSON integer (`sect.time_integer`).
- [ ] If `META.materials` is present, it is a non-empty array and every entry has a non-empty `name`.
- [ ] If `SECT.material_index` is present, the referenced materials array exists and contains that index.
- [ ] If `PROF.materials` is present, it satisfies the same shape rules as `META.materials`.
- [ ] If `ENCRYPTED` flag set, `AUTH` chunk present and recognized cipher.
- [ ] All `LROV` layer indices in `[0, total_layers-1]`.
- [ ] `LROV` layer ranges have `end >= start`.
- [ ] `LROV` `sector_id`, when present, is `0` or matches a defined `SECT.sector_id`.
- [ ] Every `*_ms` field in an `LROV` entry is a JSON integer (`lrov.time_integer`).
- [ ] If `PROF` chunk present, `profile_name` and `profile_version` are non-empty strings.
- [ ] If `PROF` chunk present, `profile_type` is one of `"material"`, `"printer"`, `"combined"`.
- [ ] If `PROF` chunk present, `settings.normal_exposure_ms > 0` and `settings.bottom_exposure_ms > 0`, as integer comparisons.
- [ ] Every `*_ms` field in `PROF.settings` is a JSON integer (`prof.settings_time_integer`).
- [ ] If `PROF` chunk present, `settings.layer_height_um > 0`.
- [ ] If `PROF.settings.cure_curve` present, `dp_um > 0`, `ec_mj_cm2 > 0.0`, `e0_mj_cm2 >= 0.0`.
- [ ] If `PROF` chunk present with `profile_uuid`, the UUID string is well-formed (36 characters, 8-4-4-4-12 hex pattern).
- [ ] Every `LROV` entry carries exactly one of `layer` or `layer_range` ([§4.6](05-print-control.md#46-lrov---layer-override-chunk)).
- [ ] If `PREV` chunk present, `preview_role` is 0–3 and reserved flag bits 5–31 are 0 ([§4.7](05-print-control.md#47-prev---preview-image-chunk)).
- [ ] (Strict mode) If `PREV` chunk present, its payload begins with the PNG signature and its `IHDR` is well-formed ([§4.7](05-print-control.md#47-prev---preview-image-chunk)).
- [ ] If `META.cure_curve` present, `dp_um > 0`, `ec_mj_cm2 > 0.0`, `e0_mj_cm2 >= 0.0`.
- [ ] If `META.chamber_temperature_c` or `vat_temperature_c` present, values are in range `[0.0, 120.0]`.
- [ ] If `LHAS` chunk present, recompute Merkle root from `layer_hashes` and verify it matches `merkle_root`.
- [ ] (Strict mode) If `LHAS` chunk present, decompress and hash each layer; verify against `layer_hashes`.
- [ ] (Strict mode) If `VOXL` chunk present, the payload is recognizable as VOXL: it begins with the V2 magic `VOXL` or with the V1 JSON document marker `{` ([§4.12](07-scene-chunks.md#412-voxl---embedded-scene-chunk)). Whether it is a *valid* VOXL file is VOXL's business, checked by whatever parses the scene; a print reader never needs to know.
- [ ] Every `EXTD` payload is at least 8 bytes: `ext_version` and `ext_type` make up the fixed part of the frame ([§4.13](07-scene-chunks.md#413-extd---extension-chunk)).
- [ ] `EXTD` `ext_type` is four ASCII characters.
- [ ] `EXTD` reserved flag bits - 0-3, 5-7 and 25-31 - are 0 ([§4.13](07-scene-chunks.md#413-extd---extension-chunk)).
- [ ] No `EXTD` chunk that a reader does not implement carries `critical = 1`: such a file is unprintable to that reader rather than printable with approximations ([§4.13](07-scene-chunks.md#413-extd---extension-chunk)).

### 11.3 Layer Data Validation (post-decompression)

- [ ] `layr_header.block_count >= 1` and `layr_header.block_count <= HDR.total_layers`.
- [ ] `layr_header.block_table_entry_size >= 24`, and the block table holds exactly `block_count` entries of that size.
- [ ] Block table entries are contiguous and ordered: `frame_offset[0] == 0` and `frame_offset[k+1] == frame_offset[k] + frame_size[k]` for all `k`.
- [ ] The end of the last block frame lies within the LAYR chunk payload.
- [ ] Every block index in `0..block_count` is referenced by at least one LTBL entry.
- [ ] Decompressing block `k` yields exactly `block_table[k].uncompressed_size` bytes.
- [ ] Before allocating, each block's `uncompressed_size` is checked against an upper bound derived from the layers it contains (grayscale REE costs at most about 5 bytes per pixel plus framing), so a corrupt or hostile chunk cannot force an unbounded allocation.
- [ ] A block frame's zstd dictionary ID equals `ZDIC.dict_id` when `ZDIC` is present, and is `0` when it is absent.
- [ ] For each LTBL entry: `data_offset + data_size <= block_table[block_index].uncompressed_size`.
- [ ] All varints are well-formed: minimally encoded (no overlong forms), terminated within the containing buffer, and at most 10 bytes (the maximum for a 64-bit value).
- [ ] Layer encoding tag is in `{0x00, 0x01, 0x02}`. Reject any layer with an unknown tag.
- [ ] Split-encoded layers (tag `0x02`): `aa_positions` values are strictly increasing, every position is `< total_pixels`, and `aa_values` holds exactly `aa_pixel_count` bytes.
- [ ] For binary REE (tag `0x00`): `first_value` must be `0x00` or `0xFF`.
- [ ] For empty layers (`sector_count == 0`): `data_size` must be 0.
- [ ] (Strict mode) No layer uses the non-canonical `run_count == 0` form; all-black layers are stored as empty layers.
- [ ] (Strict mode) Binary REE (tag `0x00`): every stored run length is `>= 1`, the implicit final run length is `>= 1`, and the lengths sum to exactly `total_pixels`.
- [ ] (Strict mode) Grayscale REE (tag `0x01`): every run length is `>= 1` and no two adjacent runs carry the same value.
- [ ] (Strict mode) A layer whose pixels are all `0x00`/`0xFF` is not stored as grayscale REE; it uses tag `0x00`.
- [ ] (Strict mode) Split REE (tag `0x02`): the binary component thresholds at `v >= 128`, and the overlay covers exactly the pixels whose value is neither `0x00` nor `0xFF`.
- [ ] REE streams decode to strictly increasing end positions.
- [ ] Last end position equals `total_pixels`.
- [ ] (Strict mode) Sector masks at each layer sum to `total_pixels` and are
  non-overlapping.

### 11.4 Encryption Validation

- [ ] If `ENCRYPTED` flag set, all LAYR/META/PROF/SECT/LROV/VOXL/ZDIC chunks have the encrypted flag set, every LAYR block frame is at least 28 bytes (one sealed unit), and LAYR block frames are individually sealed ([§9.3](12-encryption.md#93-encryption-format)).
- [ ] If `ENCRYPTED` flag set, `HDR`, `AUTH` and `LTBL` do **not** have the encrypted flag set, and neither do the LAYR header and block table ([§9.1](12-encryption.md#91-design-principles)).
- [ ] If the `ENCRYPTED` flag is clear, no chunk descriptor sets the encrypted bit: there is no key in the file that could open such a chunk ([§9.1](12-encryption.md#91-design-principles)).
- [ ] Auth tag verifies for each encrypted chunk (decryption integrity check).
- [ ] `AUTH.mode` has at least one bit set.
- [ ] If `AUTH.mode` bit 0 is set, `password_section_len >= 65` (the fixed password section size; see [§4.4.1](04-chunk-auth.md#441-password-section)).
- [ ] If `AUTH.mode` bit 1 is set, `machine_section_len >= 104` and `machine_section_len % 104 == 0` (must contain at least one complete recipient entry; see [§4.4.2](04-chunk-auth.md#442-machine-binding-section)).
- [ ] Machine-binding entries have valid key lengths.
- [ ] Argon2id parameters are within the reader's supported budget. Readers MUST reject a file whose derivation cost exceeds that budget rather than attempting it - a hostile file can otherwise exhaust memory. Recommended ceilings: `iterations <= 10`, `memory_kib <= 4 194 304`, `parallelism <= 16`.

### 11.5 Validation Levels

- **Loose** (default for printing): Accept structurally valid files. Skip unknown
  chunks/fields.
- **Strict** (file verification tools): Enforce all semantic validations. Warn on
  non-critical issues, error on critical ones.

Checks marked *strict mode* above MUST NOT fail a loose-mode read: a loose reader
accepts them, a strict validator rejects them.

The `*_ms` integer checks (`meta.time_integer`, `sect.time_integer`,
`prof.settings_time_integer`, `lrov.time_integer`) are not strict-only. A duration with a
fractional part is a type violation, not a canonicalization preference, so a loose reader
rejects it too. Whether a reader *additionally* rejects integral floating-point syntax
such as `2500.0` is the reader's choice ([§4.2](03-chunks.md#42-meta---metadata-chunk)); no
file may rely on either answer, and the corpus pins neither.

### 11.6 Conformance Corpus

The repository carries byte-exact test vectors and an independent validator under
[`test-vectors/`](test-vectors/). Implementations SHOULD validate against them. Each
valid vector pins the uncompressed structures it contains exactly - the file header,
`HDR`, `AUTH`, `LTBL`, the `LAYR` header and block table, `LHAS`, every REE stream, the
chunk directory and the trailer - and each invalid vector fails exactly one named check
from this section. Compressed payloads are pinned by property rather than by byte,
because zstd output is not stable across versions. The encrypted vectors carry their
test password and recipient key in the manifest.

Coverage is not exhaustive. The corpus exercises single- and multi-sector layer data,
the empty-layer form, all three encoding tags, dictionary compression, multi-block
framing, both encryption modes and both ciphers, and every chunk type this
specification defines. Two things are pinned at the transport level only: the `VOXL`
payload is byte-exact while VOXL's own validation stays outside this specification, and
`EXTD` covers the frame and the flag semantics while individual extension payloads
remain vendor-defined and are not pinned. See `test-vectors/README.md` for the
check-name convention and the full scope.
