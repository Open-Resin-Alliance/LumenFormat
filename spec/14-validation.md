# Reader validation requirements

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 11. Reader Validation Requirements

Every rule below is named `<group>.<rule>`, and implementations SHOULD report the failing
rule under that name, which is also how the conformance corpus names it
([§11.6](#116-conformance-corpus)).

This revision made a sector structural - one `LAYR` chunk and one optional `LROV` chunk per
`(layer, sector)`, addressed by the layer table - so the checks that named the old shapes are
retired, and their names must not appear in a conforming validator's report: `sect.*` and
`presence.sect` (the chunk is withdrawn, [§4.5](05-print-control.md#45-withdrawn-sect---sector-definition-chunk));
`sector.count_match` and the other rules over the in-band sector framing, which no longer
exists; `layr.block_*` and the rules over the `layr_header` and its block table;
the `ltbl.*` rules that named a `block_index` (`ltbl.block_index_in_range`) or a block's
decompressed size (`ltbl.offsets_within_block`); the `LROV` entries-array rules
(`lrov.entry_form`, `lrov.layer_index_range`, `lrov.layer_range_order`, `lrov.sector_id_defined`),
since an `LROV` chunk names neither a layer nor a sector; `lrov.identity_consistent`, since a
sector's identity is META's and is stated once; and `ltbl.empty_layer_no_bytes`, which had no
companion field left to contradict. What replaced them is named in the lists below.

### 11.1 Structural Validation

- [ ] Magic bytes `LUMN` at offset 0 (`header.magic`).
- [ ] Trailer magic `LEND` at `file_size - 8` (`trailer.magic`).
- [ ] Trailer CRC-32C matches `bytes[0 .. file_len-8]` (`trailer.crc32c`).
- [ ] `header.version` is recognized (`header.version`).
- [ ] `header.flags` sets no reserved bit: bits 0, 2 and 4 are `0` (`header.flags_reserved`).
- [ ] `header.dir_offset` is within the file, and the whole directory fits inside it (`header.dir_offset`).
- [ ] `header.chunk_count` matches the number of directory entries (`header.chunk_count`).
- [ ] Every chunk descriptor is readable as a 32-byte entry (`dir.descriptor`).
- [ ] If `header.total_uncompressed_size != 0`, it equals the sum of every chunk's `size_uncompressed` (`header.total_uncompressed_size`).
- [ ] No two chunks overlap, and no chunk's stored extent lies outside the file or inside the directory (`dir.overlap`, `dir.chunk_extent`). A chunk's stored extent is `[offset, offset + size_compressed)`
  when `size_compressed > 0`, and `[offset, offset + size_uncompressed)` when
  `size_compressed == 0`. Exception: null descriptors (`offset == 0`). A `LAYR` chunk's
  extent follows the same rule: its `size_uncompressed` is the container's byte length, and a
  sealed container's is `size_compressed` ([§4.10](06-layer-data.md#410-layr---layer-data-chunk)).
- [ ] `HEAD` chunk present (`presence.head`) and is the first chunk, at the offset immediately
  after the 32-byte header (`dir.head_first`).
- [ ] `META` chunk present (`presence.meta`).
- [ ] `LTBL` chunk present, and at most one (`presence.ltbl`).
- [ ] At least one `LAYR` chunk present (`presence.layr`); each is at least 4 bytes (its
  `layr_version`) and holds exactly one frame after that field.
- [ ] `HEAD.head_version` (`head.version`), `LTBL.table_version` (`ltbl.version`), `ZDIC.zdic_version` (`zdic.version`), `AUTH.auth_version` (`auth.version`) and `META.meta_version` (`meta.version`) are recognized, and so is the `layr_version` of every `LAYR` chunk - the field is per chunk, so one unrecognized value is enough (`layr.version`).
- [ ] The `AUTH` payload is long enough for the sections it declares (`auth.frame`).
- [ ] `ZDIC`, when present, is well formed: `dict_size` does not exceed 112 640 bytes and the chunk holds that many bytes (`zdic.dict_size`), and no more than one non-null `ZDIC` chunk is present (`zdic.single`).
- [ ] A dictionary is present exactly when the `LAYR` frames use one (`presence.zdic`): if any frame references a zstd dictionary (dictionary ID `!= 0`), exactly one `ZDIC` chunk is present and every frame that references a dictionary references *that* one (`layr.dict_id_match`, `zdic.dict_id_match`); if no frame references a dictionary, no `ZDIC` chunk is present and every frame's dictionary ID is `0` (`layr.dict_id_absent`). An encoder may compress one frame without the dictionary another frame uses, so a frame that reports none is not a mismatch - "the file carries a dictionary nothing uses" is this rule's own failure, reported as `presence.zdic`, and it is reported after the frames' half so a file that breaks both is named by the frames' rule.
- [ ] If `LHAS` chunk present, its payload is long enough for its header and hashes (`lhas.frame`), `hash_algorithm` is `0x01` (`lhas.hash_algorithm`), and `layer_count` equals `HEAD.total_layers` (`lhas.layer_count`).

### 11.2 Semantic Validation

- [ ] `HEAD.total_layers > 0` and `HEAD.total_layers == LTBL.layer_count` (`head.total_layers`, `ltbl.layer_count`).
- [ ] `LTBL.entry_size >= 28` (`ltbl.entry_size`). The entry layout is fixed through offset 28; future versions may append fields after offset 28, and readers stride by `entry_size` to skip unknown trailing fields.
- [ ] `LTBL.entry_count` equals the sum of `1 + additional_sector_count` over each layer's first entry, the table holds exactly that many entries and **ends exactly there** - a payload shorter or longer than `entry_count` entries is this check's failure, not `ltbl.entry_size` - and `additional_sector_count` is `0` on every non-first entry (`ltbl.entry_count`).
- [ ] The entries describe every layer the header declares and no other: walking the table from layer 0 reaches layer `HEAD.total_layers-1` and stops, and no entry names a layer outside that range (`ltbl.layer_index_range`).
- [ ] Within a layer, `sector_id` ascends (`ltbl.sector_ids_ascending`) and no two entries carry the same `sector_id` (`ltbl.sector_id_unique`).
- [ ] A layer's first entry is sector 0's: its `sector_id` is `0` (`ltbl.first_entry_is_sector_zero`).
- [ ] Every `LTBL` entry's `first_layr` is a directory index whose chunk is a `LAYR` chunk (`ltbl.first_layr_in_range`).
- [ ] For every `LTBL` entry, `data_offset + data_size` is at most the decompressed length of the frame that `first_layr` names (`ltbl.offset_within_chunk`).
- [ ] No two entries that name the same `LAYR` chunk describe overlapping byte ranges (`ltbl.slices_disjoint`).
- [ ] `first_lrov` is `0` or a directory index whose chunk is an `LROV` chunk (`ltbl.first_lrov_in_range`). `0` says that `(layer, sector)` has no overrides; what contradicts it is an `LROV` chunk no entry names whose payload no named chunk also carries - a set of overrides that can never be applied to anything, which is a `0` that lies (`ltbl.first_lrov_null`). A chunk that no entry names but whose payload *is* carried by a named chunk contradicts nothing: those values are applied at the pair that names their twin, so that file is the orphan case, not this one. Every `LROV` chunk named by exactly one entry is the third rule (`lrov.orphan`).
- [ ] The `MULTI_SECTOR` flag (header bit 1) is set exactly when some layer carries more than one sector (`head.multi_sector_flag`).
- [ ] `HEAD.layer_height_um > 0` (`head.layer_height`).
- [ ] `HEAD.build_width_um > 0`, `HEAD.build_depth_um > 0`, `HEAD.build_height_um > 0` (`head.build_dims`).
- [ ] `HEAD.encoder_name_len <= 256`, and `HEAD.size_uncompressed >= 52 + encoder_name_len` (`head.frame`) - the fixed fields before and after the name total 52 bytes, so a v1 `HEAD` chunk is exactly `52 + encoder_name_len` bytes.
- [ ] `HEAD.display_width_px × display_height_px > 0` (`head.display_pixels`).
- [ ] `HEAD.physical_width_px` is an integer multiple of `display_width_px`, and `physical_height_px` is an integer multiple of `display_height_px` (`head.physical_multiple`). A ratio of 1 means one display pixel per physical pixel.
- [ ] The META payload is a JSON object (`meta.json`).
- [ ] META JSON contains all required fields (`meta.required_fields`): `meta_version`, `normal_exposure_ms`, `bottom_exposure_ms`, `bottom_layer_count`, `transition_layer_count`, `layer_height_um`, `lift_slow_distance_um`, `lift_slow_speed_um_min`, `retract_fast_distance_um`, `retract_fast_speed_um_min`.
- [ ] Every `*_ms` field in META, and `estimated_print_time_sec`, is a JSON integer (`meta.time_integer`). A value with a fractional part such as `2500.5` is invalid; the rule covers the timing fields of META's `sectors` entries too, since they are META's fields. See [§4.2](03-chunks.md#42-meta---metadata-chunk) for the encoders' and readers' obligations.
- [ ] `META.normal_exposure_ms > 0` and `META.bottom_exposure_ms > 0`, as integer comparisons (`meta.exposure`).
- [ ] `META.layer_height_um > 0` (`meta.layer_height`).
- [ ] If `META.materials` is present, it is a non-empty array and every entry has a non-empty `name` (`meta.materials_shape`).
- [ ] `META.sectors`, when present, is an array of JSON objects, each carrying an integer `sector_id >= 1`, unique across the array (`meta.sectors_shape`).
- [ ] If `META.sectors[i].material_index` is present, `META.materials` exists, is non-empty and contains that index (`meta.sector_material_index`).
- [ ] If `META.cure_curve` present, `dp_um > 0`, `ec_mj_cm2 > 0.0`, `e0_mj_cm2 >= 0.0` (`meta.cure_curve`).
- [ ] If `META.chamber_temperature_c` or `vat_temperature_c` present, values are in range `[0.0, 120.0]` (`meta.temperature_range`).
- [ ] `AUTH` is present exactly when the `ENCRYPTED` flag is set (`presence.auth`), and its cipher is recognized (`auth.cipher_known`).
- [ ] Each `LROV` payload is a JSON object (`lrov.json`).
- [ ] Every `*_ms` field in an `LROV` payload is a JSON integer (`lrov.time_integer`).
- [ ] If `PROF` chunk present, `profile_name` and `profile_version` are non-empty strings (`prof.profile_identity`).
- [ ] If `PROF` chunk present, `profile_type` is one of `"material"`, `"printer"`, `"combined"` (`prof.profile_type`).
- [ ] If `PROF` chunk present, `settings.normal_exposure_ms > 0` and `settings.bottom_exposure_ms > 0`, as integer comparisons (`prof.settings_exposure`).
- [ ] Every `*_ms` field in `PROF.settings` is a JSON integer (`prof.settings_time_integer`).
- [ ] If `PROF` chunk present, `settings.layer_height_um > 0` (`prof.settings_layer_height`).
- [ ] If `PROF.settings.cure_curve` present, `dp_um > 0`, `ec_mj_cm2 > 0.0`, `e0_mj_cm2 >= 0.0` (`prof.cure_curve`).
- [ ] If `PROF` chunk present with `profile_uuid`, the UUID string is well-formed (36 characters, 8-4-4-4-12 hex pattern, `prof.profile_uuid`).
- [ ] If `PROF.materials` is present, it satisfies the same shape rules as `META.materials` (`prof.materials_shape`).
- [ ] If `PREV` chunk present, `preview_role` is 0–3 and reserved flag bits 5–31 are 0 (`prev.flags`, [§4.7](05-print-control.md#47-prev---preview-image-chunk)).
- [ ] (Strict mode) If `PREV` chunk present, its payload begins with the PNG signature and its `IHDR` is well-formed (`prev.png_signature`, [§4.7](05-print-control.md#47-prev---preview-image-chunk)).
- [ ] If `LHAS` chunk present, recompute Merkle root from `layer_hashes` and verify it matches `merkle_root` (`lhas.root_recompute`).
- [ ] (Strict mode) If `LHAS` chunk present, decompress and hash each layer; verify against `layer_hashes` (`lhas.leaf_match`).
- [ ] (Strict mode) If `VOXL` chunk present, the payload is recognizable as VOXL: it begins with the V2 magic `VOXL` or with the V1 JSON document marker `{` (`voxl.signature`) ([§4.12](07-scene-chunks.md#412-voxl---embedded-scene-chunk)). Whether it is a *valid* VOXL file is VOXL's business, checked by whatever parses the scene; a print reader never needs to know.
- [ ] Every `EXTD` payload is at least 8 bytes: `ext_version` and `ext_type` make up the fixed part of the frame (`extd.frame`, [§4.13](07-scene-chunks.md#413-extd---extension-chunk)).
- [ ] `EXTD` `ext_type` is four ASCII characters (`extd.ext_type`).
- [ ] `EXTD` reserved flag bits - 0-3, 5-7 and 25-31 - are 0 (`extd.flags`, [§4.13](07-scene-chunks.md#413-extd---extension-chunk)).
- [ ] No `EXTD` chunk that a reader does not implement carries `critical = 1` (`extd.critical`): such a file is unprintable to that reader rather than printable with approximations ([§4.13](07-scene-chunks.md#413-extd---extension-chunk)).

### 11.3 Layer Data Validation (post-decompression)

- [ ] Before decompressing, a `LAYR` frame declares its content size (`layr.content_size_present`). The descriptor does not carry the frame's output length, so a frame without one is rejected rather than allocated for ([§4.10](06-layer-data.md#410-layr---layer-data-chunk)).
- [ ] The declared content size is at most the bound the chunk's slices justify (grayscale REE costs at most about 5 bytes per pixel plus framing per slice, `layr.allocation_bound`), so a corrupt or hostile chunk cannot force an unbounded allocation.
- [ ] Decompressing a `LAYR` frame succeeds and yields exactly the size the frame declares, and no more (`layr.frame_decompressed_size`).
- [ ] A frame's zstd dictionary ID equals `ZDIC.dict_id` when `ZDIC` is present (`layr.dict_id_match`, `zdic.dict_id_match`), and is `0` when it is absent (`layr.dict_id_absent`).
- [ ] For each `LTBL` entry: `data_offset + data_size` is within the decompressed output of the chunk `first_layr` names (`ltbl.offset_within_chunk`), and entries naming one chunk do not overlap (`ltbl.slices_disjoint`).
- [ ] All varints are well-formed: minimally encoded (no overlong forms), terminated within the containing buffer, and at most 10 bytes (the maximum for a 64-bit value, `ree.varint`).
- [ ] Layer encoding tag is in `{0x00, 0x01, 0x02}` (`ree.tag`). Reject any layer with an unknown tag.
- [ ] Split-encoded layers (tag `0x02`): `aa_positions` values are strictly increasing and every position is `< total_pixels` (`ree.split_positions`), and `aa_values` holds exactly `aa_pixel_count` bytes.
- [ ] For binary REE (tag `0x00`): `first_value` must be `0x00` or `0xFF` (`ree.first_value`).
- [ ] REE streams decode to strictly increasing end positions, and the last end position equals `total_pixels` (`ree.end_positions`).
- [ ] (Strict mode) Significance planes ([§5.3.1](08-layer-encoding.md#531-significance-planes)): a stream's four plane lengths describe planes that are prefix-closed - a non-empty plane may not follow an empty one - and the fixed bytes, the plane lengths and the planes account for exactly `data_size` (`ree.planes`, `ree.no_trailing_bytes`).
- [ ] A slice's stored bytes and its `data_size` agree: the stream at `data_offset` consumes exactly `data_size` bytes with nothing left over (`ree.data_size`, `ree.no_trailing_bytes`), and a slice with `data_size == 0` carries no stream at all - it is an all-black `(layer, sector)` ([§5.6](08-layer-encoding.md#56-canonical-encoding)).
- [ ] (Strict mode) No slice uses the non-canonical `run_count == 0` form (`ree.no_run_count_zero`); an all-black slice is stored with `data_size == 0` and no bytes ([§5.3](08-layer-encoding.md#53-binary-ree-no-anti-aliasing)).
- [ ] (Strict mode) Binary REE (tag `0x00`): every stored run length is `>= 1`, the implicit final run length is `>= 1`, and the lengths sum to exactly `total_pixels` (`ree.run_lengths`).
- [ ] (Strict mode) Grayscale REE (tag `0x01`): every run length is `>= 1` and no two adjacent runs carry the same value (`ree.grayscale_runs`).
- [ ] (Strict mode) A slice whose pixels are all `0x00`/`0xFF` is not stored as grayscale REE; it uses tag `0x00` (`ree.grayscale_all_binary`).
- [ ] (Strict mode) Split REE (tag `0x02`): the binary component thresholds at `v >= 128`, and the overlay covers exactly the pixels whose value is neither `0x00` nor `0xFF` (`ree.split_threshold`).
- [ ] (Strict mode) The sector masks of one layer are pairwise disjoint: no pixel is exposed by two sectors of the same layer, and their union is the layer's exposed image (`sector.partition`). Two sectors of a layer live in different `LAYR` chunks, so this compares the slices the layer's entries name ([§7.3](10-sectors.md#73-sector-mask-invariant)).

### 11.4 Encryption Validation

- [ ] If `ENCRYPTED` flag set, all `LAYR`/`META`/`PROF`/`LROV`/`VOXL`/`ZDIC` chunks have the encrypted flag set (`crypt.chunk_flags`), every `LAYR` frame is at least 28 bytes (one sealed unit), and every `LAYR` frame is individually sealed ([§9.3](12-encryption.md#93-encryption-format)).
- [ ] If `ENCRYPTED` flag set, `HEAD`, `AUTH` and `LTBL` do **not** have the encrypted flag set, and a `LAYR` chunk's 4-byte version field is plaintext inside its sealed chunk ([§9.1](12-encryption.md#91-design-principles)).
- [ ] If the `ENCRYPTED` flag is clear, no chunk descriptor sets the encrypted bit: there is no key in the file that could open such a chunk (`crypt.no_key`, [§9.1](12-encryption.md#91-design-principles)).
- [ ] Each sealed unit opens with `associated_data = chunk_type || 0x00 || unit_index_le_u32`, where `unit_index` is `0` for a single-unit chunk and the `LAYR` chunk's directory index for a `LAYR` chunk (`crypt.unit_index_binding`). A sealed frame presented at another `LAYR` chunk's directory index therefore fails its tag check: an implementation that opens it anyway has not bound the unit to its identity.
- [ ] Auth tag verifies for each encrypted chunk (decryption integrity check, `crypt.tag_verify`).
- [ ] `AUTH.mode` has at least one bit set (`crypt.mode_empty`).
- [ ] If `AUTH.mode` bit 0 is set, `password_section_len >= 65` (the fixed password section size, `crypt.password_section_len`; see [§4.4.1](04-chunk-auth.md#441-password-section)).
- [ ] If `AUTH.mode` bit 1 is set, `machine_section_len >= 104` and `machine_section_len % 104 == 0` (must contain at least one complete recipient entry, `crypt.machine_section_len`; see [§4.4.2](04-chunk-auth.md#442-machine-binding-section)).
- [ ] Machine-binding entries are well formed (`crypt.recipient_entry`), and an exchange that yields the all-zero shared secret is rejected rather than used as a KEK (`crypt.low_order_point`, [§4.4.2](04-chunk-auth.md#442-machine-binding-section)).
- [ ] A wrapped session key that does not unwrap is reported as an unwrap failure (`crypt.key_unwrap`), and a file whose key cannot be recovered - wrong password, or no recipient entry matching this machine - is refused rather than partially decrypted (`crypt.no_key`).
- [ ] Argon2id parameters are within the reader's supported budget (`crypt.argon2_budget`). Readers MUST reject a file whose derivation cost exceeds that budget rather than attempting it - a hostile file can otherwise exhaust memory. Recommended ceilings: `iterations <= 10`, `memory_kib <= 4 194 304`, `parallelism <= 16`.

### 11.5 Validation Levels

- **Loose** (default for printing): Accept structurally valid files. Skip unknown
  chunks and fields - ones this revision does not define, or that the reader has no use
  for, such as `PREV`, `PROF` or `LHAS`. Skipping never reaches a chunk the reader must act
  on: an `LROV` chunk a reader cannot honor makes the file unprintable to it, not printable
  without overrides ([§4.6](05-print-control.md#46-lrov---layer-override-chunk)).
- **Strict** (file verification tools): Enforce all semantic validations. Warn on
  non-critical issues, error on critical ones.

Checks marked *strict mode* above MUST NOT fail a loose-mode read: a loose reader
accepts them, a strict validator rejects them.

The duration integer checks (`meta.time_integer`, `prof.settings_time_integer`,
`lrov.time_integer`) are not strict-only. A duration with a
fractional part is a type violation, not a canonicalization preference, so a loose reader
rejects it too. They cover every duration in the timing namespace - META's `sectors`
entries are META's fields, so `meta.time_integer` covers them - and `meta.time_integer`
also covers META's `estimated_print_time_sec`, which is whole seconds rather than
milliseconds ([§4.2](03-chunks.md#42-meta---metadata-chunk)). Whether a reader
*additionally* rejects integral floating-point syntax such as `2500.0` is the reader's
choice, and no file may rely on either answer.

### 11.6 Conformance Corpus

The repository carries byte-exact test vectors and an independent validator under
[`test-vectors/`](test-vectors/). Implementations SHOULD validate against them. Each
valid vector pins the uncompressed structures it contains exactly - the file header,
`HEAD`, `META` with its `sectors` entries, `AUTH`, `LTBL`, every `LAYR` chunk's
`layr_version` and the decompressed output of its frame, `LHAS`, every REE stream, the
chunk directory and the trailer - and each invalid vector fails exactly one named check
from this section. Each valid vector also records the settings a conforming reader must
resolve for a sample of `(layer, sector)` points, which pins the [§8](11-layer-timing.md#8-per-layer-settings-model)
pipeline - base values, bottom and transition blending, absent-field defaults, and the
`LROV` overrides a reader is required to apply ([§4.6](05-print-control.md#46-lrov---layer-override-chunk)) -
rather than only the bytes. Compressed payloads are pinned by property rather than by byte,
because zstd output is not stable across versions. The encrypted vectors carry their
test password and recipient key in the manifest.

Coverage is not exhaustive. The corpus exercises single- and multi-sector layer data,
the empty-slice form, all three encoding tags, dictionary compression, files with more
than one `LAYR` chunk, both encryption modes and both ciphers, and every chunk type this
specification defines. The `LAYR` unit-index binding is exercised by such a file: two
`LAYR` chunks whose sealed frames are interchangeable in shape, so moving one to the other
chunk's directory index is a failure rather than an accepted file. Two things are pinned at
the transport level only: the `VOXL` payload is byte-exact while VOXL's own validation stays
outside this specification, and `EXTD` covers the frame and the flag semantics while
individual extension payloads remain vendor-defined and are not pinned. See
`test-vectors/README.md` for the check-name convention and the full scope.
