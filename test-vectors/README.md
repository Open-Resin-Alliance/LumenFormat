# LUMEN test vectors

Byte-exact `.lumen` files plus an independent validator, for implementations of
[`../spec/01-overview.md`](../spec/01-overview.md). The vectors are written against
LUMEN v1.0 and are validated against it.

## Layout

| Path | Contents |
|------|----------|
| `valid/*.lumen` | Files a conforming reader must accept |
| `invalid/*.lumen` | Files a conforming reader must reject, each failing the check its manifest entry names |
| `manifest.json` | Golden data for every vector: sizes, offsets, the layer table, each `LAYR` chunk's frame and version, per-layer hashes, Merkle root, CRC-32C, the timing a conforming reader must resolve for a sample of `(layer, sector)` points, and the credentials and parameters for encrypted vectors |
| [`../rust/corpus-gen`](../rust/corpus-gen) | `make_vectors`: the reference encoder that regenerates the corpus from the specification |
| [`../rust/corpus`](../rust/corpus) | `verify_vectors`: the independent reader and validator. `cross_check` points that same reader at files the reference crate wrote |

`verify_vectors` shares no code with `make_vectors`, and neither depends on the
reference crate: the primitives and the reader logic are reimplemented from the spec.
Agreement between them is therefore evidence that the specification is unambiguous,
not that one module is self-consistent.

## Running

```sh
cd rust
cargo run --release -p lumen-corpus --bin verify_vectors         # validate the committed corpus
cargo run --release -p lumen-corpus --bin verify_vectors -- -v   # print every individual check
cargo run --release -p lumen-corpus-gen --bin make_vectors       # regenerate valid/, invalid/ and manifest.json
```

`cross_check` runs the same validator against files the reference crate wrote rather
than against the committed corpus, which checks the opposite direction of the same
claim - an independent reader accepting our writer's bytes. It needs those files first:

```sh
cargo run -p lumen-format --example make_test_file -- /tmp/sample
cargo run --release -p lumen-corpus --bin cross_check -- /tmp/sample
```

`verify_vectors` exits 0 only if every valid vector passes **and** every invalid
vector fails the check its manifest entry advertises. It also re-checks each committed
file against the golden values in `manifest.json`.

The exit status is **3** when the run did not cover the whole corpus: not 0, because the
run proves less than it claims, and not 1, which means an actual check failed. A vector
is uncovered when the reader stopped before its last check, which is how a file too
broken to parse is reported rather than crashed on.

## What is exact, and what is not

The spec leaves two things to the encoder (section 5.6): the choice between
grayscale REE and split REE for a layer, and the number of layers a `LAYR` chunk
covers. It also mandates zstd, whose output bytes are not stable across versions,
levels or builds.

So this corpus pins:

- **Exactly** - the file header, `HEAD`, `AUTH`, the `LTBL` header and every 28-byte entry,
  each `LAYR` chunk's version field, `LHAS`, every REE stream, the chunk directory and the
  trailer CRC-32C, plus the decompressed bytes of every layer, the Merkle root over them,
  every sealed unit (nonce, ciphertext and tag, whose associated data binds a `LAYR` frame to
  the directory index of its chunk), and the plaintext payload bytes of every `PROF`, `LROV`,
  `PREV`, `VOXL` and `EXTD` chunk (`chunk_payload_sha256` in the manifest; `LROV`, `PREV` and
  `EXTD` are lists in file order).
- **By property** - compressed payload bytes. The manifest records the
  zstd version and level, each frame's dictionary ID and declared content size;
  `verify_vectors` asserts those instead of byte equality.

Re-running `make_vectors` under a different zstd version may change
`file_sha256`, the chunk sizes and the trailer CRC-32C. The uncompressed
structures and all layer hashes must not change. Regeneration is deterministic
for a fixed zstd version, including the encrypted vectors, because every
nonce, salt and key is derived from a fixed seed (see *Test credentials*).

## Resolved timing

Bytes are not the whole contract. §8 resolves one `(layer, sector)` pair's settings from META,
that sector's `META.sectors` entry, the bottom/transition blend and the pair's own `LROV`
chunk, and §4.6 makes applying overrides mandatory for a reader: a printer that ignores them
prints those layers at the wrong exposure, and nothing in the file says so afterwards. So
every valid vector also carries `resolved_timing` in the manifest - for a sample of
`(layer, sector)` points, the settings a conforming reader must resolve, field for field, as
integers. Temperatures and the cure curve are not pinned: they pass through from META or a
sector's entry unblended, and this pins the pipeline that does the blending.

The sample covers every branch rather than every layer, and each sector is sampled on the
boundaries **it** resolves with: a `META.sectors` entry may carry its own
`bottom_layer_count`/`transition_layer_count`, and then that sector blends over a different
range than META's ([§4.2](../spec/03-chunks.md#42-meta---metadata-chunk)). For each sector
`s`, with `B_s` and `T_s` the counts that sector supplies or inherits and `N = total_layers`:

- layers `{0, 1, B_s-1, B_s, B_s+T_s, N-1}`, each clamped into range, plus every layer that
  has an `LROV` chunk for `s` and each of those layers' immediate neighbours;
- the points for `s` are those layers at `s`, and the sample is the union over the sectors
  `{0}`, every sector `META.sectors` defines, and every sector an `LROV` chunk belongs to.

So a vector's points include each sector's bottom range, first interpolation step, first
fully-normal layer, last layer, and each override boundary next to the layer it does not
reach.

`layer-overrides` is the one to read first for the overrides: seven `LROV` chunks cover layer
2, a range of three layers written one chunk per layer, a second range and layer 4, which the
first range covers as well - and because an override set belongs to the pair that names it,
layer 4 keeps the range's exposure and gains only the single-layer chunk's wait.
`sector-blend-ranges` is the one for the ranges themselves, where META's bottom range ends at
layer 2 and sector 1's own ends at layer 5.

## Valid vectors

| Vector | Layers | Chunks | Cipher / mode | Exercises |
|--------|--------|--------|---------------|-----------|
| `binary-basic` | 6 | 3 | - | Six layers over one sector covering the empty-layer form, binary REE, grayscale REE and split REE, in three LAYR chunks of two layers each with no dictionary, over a bottom range whose motion, wait and PWM values differ from the normal ones: the bottom layers take the bottom-prefixed values verbatim, the transition layer blends them, and light_pwm switches to the normal value at the first non-bottom layer instead of blending. |
| `ree-degenerate-arrays` | 5 | 3 | - | Five layers over one sector pinning every REE array that holds no varints: layer 0 is one run of 0xFF (tag 0x00, run_count 1), layer 1 one run of 0x80 (tag 0x01, run_count 1, one value byte), layers 2 and 3 are splits whose thresholded core is a single run - 0xFF over a 0xC0 band at 1000..1200, whose first delta is two bytes, and 0x00 under a 0x40 band at 0..500, whose first delta is 0 - and layer 4 is a split whose overlay is empty, the all-0xFF mask of layer 0 written under tag 0x02. Every one of those arrays still carries its four plane lengths as zeros: the header is unconditional, so a reader that returned before consuming it would leave four bytes behind and fail `ree.no_trailing_bytes` on a canonical stream. Layer 4 is the one stream shape the canonical tag choice of §5.6 cannot reach - an all-0x00/0xFF slice should carry tag 0x00 - and no check refuses the split form, so it is decodable rather than invalid: this corpus has no stricter bucket for a non-canonical stream that breaks no rule, and §5.6 requires a decoder to accept any stream satisfying §5.3-§5.5. |
| `dict-multi-block` | 64 | 4 | - | 64 layers with a trained ZDIC dictionary, in four LAYR chunks of sixteen layers each, every frame carrying the dictionary's id. |
| `multi-sector` | 4 | 4 | - | Four layers with two non-overlapping sectors, the second defined by META.sectors: layer 2 carries no data at all and is the empty layer, its single sector-0 entry holding a zero length, and two LROV chunks override one layer of one sector each - sector 1 of layer 0 and sector 0 of layer 1 - so the timing of a point is the timing of that point and not of its layer. |
| `sector-blend-ranges` | 10 | 4 | - | Ten layers over two sectors whose META.sectors entry for sector 1 carries bottom_layer_count 5 and no transition_layer_count, so sector 1 is blended over a bottom range of its own and inherits META's transition count; layer 4 is the layer where the two readings part, fully normal at 2500 ms for sector 0 and still a bottom layer at 30000 ms for sector 1, and their transition steps fall on layers 2 and 5 rather than together. |
| `encrypted-password` | 32 | 2 | AES-256-GCM, password | Password-mode AES-256-GCM: an Argon2id-wrapped session key, a sealed dictionary and metadata, and two LAYR chunks whose frames are sealed one by one under the directory index of the chunk that carries each. |
| `encrypted-machine` | 4 | 1 | ChaCha20-Poly1305, machine binding | Machine-mode ChaCha20-Poly1305 with three recipient entries: a foreign machine, a decoy entry for our own fingerprint whose ephemeral key is the low-order point, and the real entry. A reader that unwraps the decoy without rejecting the all-zero shared secret recovers a different session key and cannot decrypt the file. |
| `encrypted-both` | 6 | 6 | AES-256-GCM, password, machine binding | Both wrapping modes set in one AUTH chunk, with two sectors whose frames are sealed one by one, each under the directory index of the chunk that carries it. |
| `print-profile` | 4 | 2 | AES-256-GCM, password | Password-mode AES-256-GCM with a sealed PROF chunk: profile identity, a material library, and a settings block reusing META's field names, including the experimental cure curve. |
| `layer-overrides` | 10 | 2 | - | Ten layers of one sector with seven LROV chunks: a single layer, a range of three layers written as one chunk per layer, a second range, and layer 4, which the first range covers too. An override set belongs to exactly one (layer, sector) - the entry that names the chunk is the only thing that places it - so nothing folds: layer 4 resolves to the values of its own set, which keeps the range's exposure and wait while taking the single-layer chunk's wait after the lift. |
| `previews` | 4 | 2 | AES-256-GCM, password | Password-mode AES-256-GCM with two PREV chunks: a large preview in the clear and a sealed icon. Preview sealing is optional even when the file is encrypted, so both forms are valid in the same file. |
| `embedded-scene` | 4 | 2 | AES-256-GCM, password | Password-mode AES-256-GCM with a sealed VOXL chunk: the scene bytes are copied in and must come back out unchanged, while LUMEN itself never parses them. |
| `extensions` | 4 | 2 | - | Two non-critical EXTD chunks - one reserved ORA type code and one vendor extension - exercising the frame, the vendor id and critical flag bit, and the rule that readers skip extensions they do not implement. |

## Invalid vectors

| Vector | Defect | Expected failure |
|--------|--------|------------------|
| `ltbl-entry-count` | LTBL's entry_count says seven while the table holds six entries, so the table does not end where the header says it does. | `ltbl.entry_count` |
| `ltbl-entry-count-overrun` | The last entry claims one further entry for its layer, so the sum of 1 + additional_sector_count over the layers' first entries runs one past the table the header declares. | `ltbl.entry_count` |
| `ltbl-sector-ids-descending` | Layer 0 carries sectors 0, 1 and 2, and its last two entries are written in the order 0, 2, 1: the ids descend where the table requires them to ascend. | `ltbl.sector_ids_ascending` |
| `ltbl-sector-id-duplicate` | Layer 0's two entries both name sector 0, so the layer carries one sector twice instead of two sectors once. | `ltbl.sector_id_unique` |
| `ltbl-first-entry-not-sector-zero` | Layer 1's only entry names sector 3. Sector 0 is primary and implicitly present on every layer with data, so a layer's first entry is sector 0's. | `ltbl.first_entry_is_sector_zero` |
| `ltbl-first-layr-not-layr` | Entry 0 names directory index 2, which is the LTBL chunk itself, so the slice has no frame to be read out of. | `ltbl.first_layr_in_range` |
| `ltbl-offset-past-frame` | Entry 1 claims 0x00FFFFFF bytes even though it is the last slice of the frame it names, so its end lies past the frame's decompressed output. | `ltbl.offset_within_chunk` |
| `ltbl-slices-overlap` | Entries 2 and 3 are two slices of one frame and both now start at offset 0, so layers 2 and 3 would be read out of the same bytes. | `ltbl.slices_disjoint` |
| `ltbl-first-lrov-zero` | Layer 2's entry names no LROV chunk although the file carries one for that point: first_lrov is 0 exactly when a (layer, sector) has no overrides. Because an LROV payload carries no identity, that chunk is now unreachable - this file violates lrov.orphan as well, and the check order decides which is reported. | `ltbl.first_lrov_null` |
| `ltbl-first-lrov-not-lrov` | Entry 0 names directory index 2, which is the LTBL chunk, as the override set of its point, so the entry points at a chunk that carries no overrides. | `ltbl.first_lrov_in_range` |
| `lrov-shared-chunk` | Entry 0 names the same LROV chunk as layer 2's entry, so one override set is claimed by two points at once. The payload carries no layer and no sector, so a reader cannot tell which of the two it belongs to - it would have to apply layer 2's override to layer 0 as well, or ignore one of them. | `lrov.orphan` |
| `lrov-orphan-chunk` | The file carries an LROV chunk that no entry names. An LROV payload carries no layer and no sector - the entry that names the chunk is what places it - so these overrides can never be applied to anything, and a reader that silently ignores them prints the wrong timings. | `lrov.orphan` |
| `lrov-not-json` | An LROV payload is truncated JSON, so the override set cannot be read at all. | `lrov.json` |
| `lrov-wait-fractional` | An LROV payload carries wait_time_before_cure_ms = 500.5. A wait time is a whole number of milliseconds, so a fractional value is not a duration this format can express. | `lrov.time_integer` |
| `run-count-zero-all-black` | Layer 0 stores all-black as tag 0x00 with run_count 0 instead of the empty-layer form. | `ree.no_run_count_zero` *(strict)* |
| `layr-container-version` | A LAYR container declares version 2, which no reader implements; the frame behind it is well formed, so only the version refuses the file. | `layr.version` |
| `layr-content-size-absent` | The LAYR frames are compressed without their content size. A writer MUST declare it (spec 4.10), because the descriptor's size_uncompressed is the container's length and the reader has nothing else to size the frame's output from. | `layr.content_size_present` |
| `layr-frame-size-lie` | The first LAYR frame's header declares one byte more than the frame decompresses to, so its output cannot be allocated or checked against the declaration. | `layr.frame_decompressed_size` |
| `layr-frame-corrupt` | The first block header of the first LAYR frame is rewritten to the reserved block type 3, so the frame cannot be decompressed. | `layr.frame_decompressed_size` |
| `layr-dict-id-mismatch` | ZDIC.dict_id is rewritten while the frames keep the id of the dictionary they were compressed with, so every LAYR frame disagrees with the file's dictionary. | `layr.dict_id_match` |
| `layr-dict-id-without-zdic` | The frames are compressed with a trained dictionary but the file carries no ZDIC chunk, so their dictionary ids name a dictionary no reader can find. | `layr.dict_id_absent` |
| `crypt-unit-index-binding` | Every sealed LAYR frame is bound to unit index 0 instead of the directory index of the chunk that carries it. Each frame is intact, but a reader that authenticates it under the chunk's own index must refuse the file - which is what stops a ciphertext from being swapped between two LAYR chunks, since with one unit per chunk an all-zero index would authenticate in either place. | `crypt.unit_index_binding` |
| `ltbl-layer-index-range` | Layer 1's entry claims one further entry, so the walk takes layer 1 and layer 2 for one layer and reaches layer 2 of a four-layer file; the entries no longer cover every layer the header declares. The merged layer also holds sector 0 twice, which is what the entries it swallowed carry. | `ltbl.layer_index_range` |
| `layr-allocation-bound` | The file's only LAYR frame declares a decompressed size of 2147483647 bytes, some four thousand times what the slices pointing into it could hold, so a reader that sizes its buffer from the declaration allocates two gigabytes for a layer group of a 64 by 48 display. | `layr.allocation_bound` |
| `presence-zdic-unused` | The file carries a ZDIC chunk while every LAYR frame declares no dictionary (dictionary id 0), so the dictionary is present but nothing in the file refers to it. | `presence.zdic` |
| `meta-sectors-shape` | META.sectors has two entries with sector_id 1, so the sector's timing is defined twice over. | `meta.sectors_shape` |
| `meta-sector-material-index` | META.sectors[0].material_index is 3 while META.materials holds one entry, so the sector names a material that is not there. | `meta.sector_material_index` |
| `merkle-root-mismatch` | One byte of merkle_root is flipped, so recomputation from layer_hashes disagrees. | `lhas.root_recompute` |
| `layer-hash-mismatch` | Layer 0's stored leaf hash is altered and merkle_root recomputed to match, so only hashing the actual bytes catches it. | `lhas.leaf_match` *(strict)* |
| `multi-sector-flag-clear` | The file's layers carry two sectors but the header does not set MULTI_SECTOR, so a reader that trusts the flag prints one sector per layer and never notices the rest. | `head.multi_sector_flag` |
| `multi-sector-flag-set` | No layer of the file carries more than one sector, but the header sets MULTI_SECTOR, so the flag promises a structure the file does not have. | `head.multi_sector_flag` |
| `trailer-crc-mismatch` | The trailer CRC-32C does not match the file bytes. | `trailer.crc32c` |
| `meta-exposure-fractional` | META carries normal_exposure_ms = 2500.5. Durations are exact whole milliseconds, so a fractional value is not a duration this format can express. | `meta.time_integer` |
| `encrypted-flag-without-auth` | The file header sets ENCRYPTED but there is no AUTH chunk, so no session key can ever be derived. | `presence.auth` |
| `auth-cipher-unknown` | AUTH.cipher_id is XXXX, which names no algorithm. | `auth.cipher_known` |
| `crypt-mode-empty` | AUTH.mode is 0: neither a password nor a machine binding is declared, so the session key is unreachable. | `crypt.mode_empty` |
| `crypt-argon2-budget` | The password section declares Argon2id iterations = 99, above the recommended ceiling of 10; it is otherwise coherent, so only the cost rule refuses it. | `crypt.argon2_budget` |
| `crypt-password-len-short` | AUTH declares a 64-byte password section, one byte short of the fixed section size. | `crypt.password_section_len` |
| `crypt-machine-len-empty` | AUTH.mode sets machine-binding but the machine section is empty: no recipient can ever unwrap the session key. | `crypt.machine_section_len` |
| `crypt-plaintext-content` | ZDIC's descriptor does not set the encrypted flag although the file is encrypted; its bytes are sealed regardless, so the flag is the only disagreement. | `crypt.chunk_flags` |
| `crypt-tag-corrupt` | One ciphertext byte of the first sealed LAYR frame is flipped, so its AEAD tag must fail; a reader must not decompress or parse a frame it cannot authenticate. | `crypt.tag_verify` |
| `prof-type-unknown` | PROF.profile_type is "resin", which is not one of the three defined types. | `prof.profile_type` |
| `prof-identity-empty` | PROF.profile_name is an empty string. | `prof.profile_identity` |
| `prof-settings-exposure` | PROF settings carry a zero normal exposure. | `prof.settings_exposure` |
| `prof-settings-layer-height` | PROF settings carry a zero layer height. | `prof.settings_layer_height` |
| `prof-cure-curve` | PROF cure curve has dp_um = 0.0, which no resin can have. | `prof.cure_curve` |
| `prof-uuid-malformed` | PROF.profile_uuid is not a UUID. | `prof.profile_uuid` |
| `prof-materials-shape` | PROF.materials is an empty array, which the META.materials shape rules forbid. | `prof.materials_shape` |
| `prev-flags` | A PREV chunk sets reserved flag bit 5 alongside role 1; only bits 0-3 carry the role. | `prev.flags` |
| `prev-not-png` | A PREV payload does not begin with the PNG signature. A loose reader ignores previews and must still accept the file; a strict validator rejects it. | `prev.png_signature` *(strict)* |
| `voxl-not-voxl` | The embedded scene is a JSON array rather than a VOXL document: the payload begins with neither the V2 magic nor the V1 document marker. A loose reader never looks inside the chunk and must still accept the file; a strict validator rejects it. | `voxl.signature` *(strict)* |
| `extd-critical` | An extension sets the critical bit, so a reader that does not implement it must refuse the file rather than print an approximation. | `extd.critical` |
| `extd-truncated` | An EXTD payload is four bytes, too short to carry ext_version and ext_type. | `extd.frame` |
| `extd-reserved-flags` | An EXTD chunk sets reserved flag bit 0, which must be 0. | `extd.flags` |
| `extd-type-nonascii` | An EXTD ext_type is four non-ASCII bytes, so no reader can name the extension. | `extd.ext_type` |
| `sealed-without-auth` | META's descriptor sets the encrypted bit while the file header does not, so the file carries no AUTH chunk and no key could open it. | `crypt.chunk_flags` |

## Check names

Checks are named `<group>.<rule>`, mirroring section 11:
`trailer.*`, `header.*`, `dir.*`, `presence.*`, `head.*`, `auth.*`,
`meta.*`, `prof.*`, `lrov.*`, `prev.*`, `voxl.*`, `extd.*`, `ltbl.*`,
`layr.*`, `zdic.*`, `lhas.*`, `ree.*`, `sector.*`, `crypt.*`.

Every `*_ms` duration is checked by the chunk that carries it: `meta.time_integer`
(which also covers the durations in `META.sectors`), `prof.settings_time_integer`
and `lrov.time_integer`. A duration with a fractional part is a type violation
rather than a precision problem, so none of them is strict-only: a loose reader
rejects it too (section 11.5).

Implementations are encouraged to use the same names when reporting which rule
failed. Use them verbatim as `expected_failure` when adding vectors.

## Cryptographic parameters

The spec fixes the algorithms and leaves the rest to these vectors:

- Session key 256 bits, one per file, wrapped independently by each method.
- Password mode: Argon2id per RFC 9106, version `0x13`, 32-byte output, no secret
  key and no associated data, the password encoded as UTF-8, then AES-256-KW
  (RFC 3394) over the session key.
- Machine binding: `ss = X25519(recipient_private, ephemeral_pk)`, rejected when it
  is all zero; `KEK = HKDF-SHA-256(IKM = ss, salt = machine_fp, info = "LUMEN
  machine-binding v1\0" || ephemeral_pk || machine_fp, L = 32)`; then AES-256-KW.
  `machine_fp` is the SHA-256 of the recipient's 32-byte X25519 public key.
- Unit framing: `nonce[12] || ciphertext || tag[16]`, AAD
  `chunk_type || 0x00 || unit_index_le_u32`, with `unit_index` 0 for every chunk
  except `LAYR`, where it is the block index.
- Compress-then-encrypt: a compressed chunk's unit seals the zstd frame, so
  `size_uncompressed` is the length of the plaintext JSON, not of the frame.

## Test credentials

Everything an implementer needs to read the encrypted vectors is in
`manifest.json`, under each vector's `crypto` block:

- `password_utf8` and `argon2` for password-mode vectors.
- `local_recipient_index` and `local_recipient_private_key` (a hex X25519 private
  key) for machine-binding vectors.

`encrypted-machine` has three recipients and only the last is ours. Entry 0 is
another machine, which a reader must skip by fingerprint. Entry 1 carries *our*
fingerprint with the ephemeral key set to the low-order point, so the shared secret
is the all-zero value that §4.4.2 requires a reader to reject — and it wraps a
*different* session key, so a reader that unwraps it without checking cannot
decrypt the file at all. Only entry 2 recovers the real key.

> **These are public test values.** The nonces, salts, session keys and recipient
> keys in this corpus come from `SHAKE-256` over a fixed seed, so the files
> regenerate byte for byte. Real encoders MUST draw every nonce, salt and key from a
> CSPRNG, must never reuse a nonce, and must not treat this corpus as a model for
> key management.

## Adding a vector

1. Add a builder in [`../rust/corpus-gen`](../rust/corpus-gen) (and, for invalid
   vectors, a mutation plus its expected check name). Encrypted vectors go through
   `build_encrypted_vector`, which also records the `crypto` block.
2. `cargo run --release -p lumen-corpus-gen --bin make_vectors` (from `rust/`)
3. `cargo run --release -p lumen-corpus --bin verify_vectors -- -v`
4. Commit the `.lumen` files and `manifest.json` together.

## Notes

- `make_vectors` self-tests its CRC-32C against the standard check value
  (`"123456789"` → `0xE3069283`) before generating anything, and
  `verify_vectors` repeats that self-test before validating. The generator also
  asserts that its own password section unwraps to the session key it sealed with.
- The vectors use a 64×48 display (3 072 pixels) except `dict-multi-block` and
  `encrypted-password`, which use 256×192 (49 152 pixels) so that the zstd
  dictionary has enough sample data to train on. Display size is irrelevant to
  every rule the vectors exercise.
- An `LROV` chunk belongs to exactly one `(layer, sector)`: the layer table entry that names
  it is what places it, and the payload carries no layer and no sector of its own. A `PREV`
  chunk carries its role in its descriptor's flag bits 0-3, with bits
  5-31 reserved, and there may be several `PREV` chunks in a file.
- `EXTD` is pinned at the frame level: `ext_version`, `ext_type`, the `vendor_id` field
  and the `critical` bit, plus the rule that a reader must refuse a critical extension it
  does not implement. This validator implements none, so any critical extension fails
  here - the check is deliberately reader-relative. Extension payloads themselves are
  vendor-defined: they are copied through, never interpreted.
- The `VOXL` vector pins the transport contract only: the scene is copied in and must
  come back out byte for byte, and LUMEN never parses it. Its payload is a synthetic
  V1 document rather than a real slice, which is sufficient precisely because the chunk
  is opaque to a LUMEN reader. VOXL's own validation belongs to VOXL, and a print
  reader that skips the chunk entirely is conforming.
