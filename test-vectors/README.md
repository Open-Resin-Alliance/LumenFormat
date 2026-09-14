# LUMEN test vectors

Byte-exact `.lumen` files plus an independent validator, for implementations of
[`../spec/01-overview.md`](../spec/01-overview.md). The vectors are written against
LUMEN v1.0 and are validated against it.

## Layout

| Path | Contents |
|------|----------|
| `valid/*.lumen` | Files a conforming reader must accept |
| `invalid/*.lumen` | Files a conforming reader must reject, each failing the check its manifest entry names |
| `manifest.json` | Golden data for every vector: sizes, offsets, block table, per-layer hashes, Merkle root, CRC-32C, and the credentials and parameters for encrypted vectors |
| `make_vectors.py` | Reference encoder that regenerates the corpus from the specification |
| `verify_vectors.py` | Independent reader and validator |
| `cross_check.py` | Points that validator at files the Rust implementation wrote; see [`../rust/lumen/`](../rust/lumen/) |

`verify_vectors.py` shares no code with `make_vectors.py`: the primitives and the
reader logic are reimplemented from the spec. Agreement between them is therefore
evidence that the specification is unambiguous, not that one module is
self-consistent.

## Running

```sh
pip install zstandard cryptography argon2-cffi
python verify_vectors.py        # validate the committed corpus
python verify_vectors.py -v     # print every individual check
python make_vectors.py          # regenerate valid/, invalid/ and manifest.json
```

`cross_check.py` runs `verify_vectors.py` against a file written by the Rust
implementation rather than against the committed corpus, which checks the
opposite direction of the same claim - an independent reader accepting our
writer's bytes. It needs those files first:

```sh
cargo run --manifest-path rust/lumen/Cargo.toml --example make_test_file -- /tmp/sample
python cross_check.py /tmp/sample
```

`verify_vectors.py` exits 0 only if every valid vector passes **and** every invalid
vector fails the check its manifest entry advertises. It also re-checks each committed
file against the golden values in `manifest.json`.

`cryptography` and `argon2-cffi` are needed only for the encrypted vectors. Without
them the plaintext vectors still validate, every encrypted vector is reported as
`SKIP`, and the exit status is **3**: not 0, because the run did not cover the whole
corpus, and not 1, which means an actual check failed.

## What is exact, and what is not

The spec leaves two things to the encoder (section 5.6): the choice between
grayscale REE and split REE for a layer, and the block size. It also mandates
zstd, whose output bytes are not stable across versions, levels or builds.

So this corpus pins:

- **Exactly** - the file header, `HDR`, `AUTH`, `LTBL`, the `LAYR` header and block
  table, `LHAS`, every REE stream, the chunk directory and the trailer CRC-32C,
  plus the decompressed bytes of every layer, the Merkle root over them, every
  sealed unit (nonce, ciphertext and tag), and the plaintext payload bytes of every
  `PROF`, `LROV`, `PREV`, `VOXL` and `EXTD` chunk (`chunk_payload_sha256` in the manifest;
  `PREV` and `EXTD` are lists in file order).
- **By property** - compressed payload bytes. The manifest records the
  zstandard version and level, the frame's dictionary ID and the decompressed
  size; `verify_vectors.py` asserts those instead of byte equality.

Re-running `make_vectors.py` under a different zstandard version may change
`file_sha256`, the chunk sizes and the trailer CRC-32C. The uncompressed
structures and all layer hashes must not change. Regeneration is deterministic
for a fixed zstandard version, including the encrypted vectors, because every
nonce, salt and key is derived from a fixed seed (see *Test credentials*).

## Valid vectors

| Vector | Layers | Blocks | Cipher / mode | Exercises |
|--------|--------|--------|---------------|-----------|
| `binary-basic` | 6 | 3 | - | the empty-layer form, binary REE, grayscale REE, split REE, multi-block framing, single-sector layer data |
| `dict-multi-block` | 64 | 4 | - | `ZDIC`, dictionary-ID agreement across every block frame, four-block framing, split and grayscale REE at scale |
| `multi-sector` | 4 | 2 | - | `MULTI_SECTOR`, the per-layer sector varint framing, per-layer sector tags, the partition invariant, a layer with a single active sector inside a multi-sector file, an empty layer |
| `encrypted-password` | 32 | 2 | AES-256-GCM, password | the `AUTH` chunk and its fixed 65-byte password section, Argon2id and AES-256-KW unwrapping to the session key, a sealed dictionary, sealed metadata, two blocks of individually sealed layer frames with their per-block AAD, and dictionary-ID agreement across sealed frames |
| `encrypted-machine` | 4 | 1 | ChaCha20-Poly1305, machine binding | three recipient entries, matching by `machine_fp` without contacting the other recipients, X25519 and HKDF-SHA-256 and AES-256-KW unwrapping, the low-order-point entry that must be rejected, the second cipher, a single sealed block |
| `encrypted-both` | 6 | 3 | AES-256-GCM, both modes | mode bits 0 and 1 in one `AUTH`, one session key wrapped both ways, sealed `SECT` and sealed layer frames in a multi-sector file |
| `print-profile` | 4 | 2 | AES-256-GCM, password | a sealed `PROF`: profile identity and UUID, a material library, and a `settings` block reusing META's field names including the experimental cure curve |
| `layer-overrides` | 10 | 2 | - | `LROV`: a single-layer override, an inclusive `layer_range` scoped to sector 0, and a range that applies to every sector |
| `previews` | 4 | 2 | AES-256-GCM, password | two `PREV` chunks in one file - a large preview in the clear and a sealed icon - with the role in the descriptor's flags. Preview sealing is optional even when the file is encrypted |
| `embedded-scene` | 4 | 2 | AES-256-GCM, password | a sealed `VOXL` chunk: an embedded scene is copied in and must come back out unchanged, while LUMEN itself never parses it |
| `extensions` | 4 | 2 | - | two non-critical `EXTD` chunks - a reserved ORA type code and a vendor extension - pinning the frame, the `vendor_id` field and the `critical` bit, and the rule that readers skip extensions they do not implement |

The encrypted vectors also pin the two encryption flags that the spec assigns
different bit numbers: the file header's bit 3 (`ENCRYPTED`, "an `AUTH` chunk is
present") and the chunk descriptor's bit 4 ("this payload is sealed"). `HDR`,
`AUTH`, `LTBL` and the LAYR header and block table carry neither.

## Invalid vectors

`expected_failure` is the check name that must fail, and it must be the **first** check
to fail. For almost every vector it is the only failure. Where a defect necessarily
unsatisfies a dependent rule as well - an `EXTD` payload too short to hold an `ext_type`
cannot satisfy the type rule either - the advertised check still has to come first, and
`verify_vectors.py` enforces exactly that.

Except for `trailer-crc-mismatch`, every file carries a deliberately introduced defect
and a recomputed trailer CRC-32C, so a reader reaches the intended check rather than
stopping at the file-completeness check first.

| Vector | Defect | Expected failure |
|--------|--------|------------------|
| `empty-layer-with-bytes` | `LTBL` entry 0 has `sector_count == 0` but `data_size == 2` | `ltbl.empty_layer_no_bytes` |
| `run-count-zero-all-black` | an all-black layer uses the non-canonical tag `0x00` / `run_count == 0` form | `ree.no_run_count_zero` *(strict)* |
| `block-index-out-of-range` | `LTBL` entry 1 names block 99 of 3 | `ltbl.block_index_in_range` |
| `block-table-gap` | a one-byte gap between block 0's frame end and block 1's `frame_offset` | `layr.block_table_contiguous` |
| `merkle-root-mismatch` | one byte of `merkle_root` flipped | `lhas.root_recompute` |
| `layer-hash-mismatch` | layer 0's stored leaf altered, `merkle_root` recomputed to match | `lhas.leaf_match` *(strict)* |
| `layer-range-past-block` | `LTBL` entry 2 claims a `data_size` past its block's decompressed size | `ltbl.offsets_within_block` |
| `trailer-crc-mismatch` | the trailer CRC-32C does not match the file bytes | `trailer.crc32c` |
| `encrypted-flag-without-auth` | the header sets `ENCRYPTED` and there is no `AUTH` chunk | `presence.auth` |
| `auth-cipher-unknown` | `AUTH.cipher_id` is `XXXX` | `auth.cipher_known` |
| `crypt-mode-empty` | `AUTH.mode` is 0, so neither wrapping method is declared | `crypt.mode_empty` |
| `crypt-password-len-short` | a password section of 64 bytes, one short of the fixed size | `crypt.password_section_len` |
| `crypt-machine-len-empty` | machine mode with an empty machine section | `crypt.machine_section_len` |
| `crypt-argon2-budget` | a coherent password section declaring Argon2id `iterations = 99`, past the ceiling of 10 | `crypt.argon2_budget` |
| `crypt-plaintext-content` | `ZDIC`'s descriptor does not set the encrypted flag although the file is encrypted | `crypt.chunk_flags` |
| `sealed-without-auth` | `META`'s descriptor sets the encrypted flag although the file has no `AUTH` chunk, so no key exists | `crypt.chunk_flags` |
| `crypt-tag-corrupt` | one ciphertext byte of LAYR block 0 flipped, which its tag must reject | `crypt.tag_verify` |
| `prof-type-unknown` | `PROF.profile_type` is `"resin"` | `prof.profile_type` |
| `prof-identity-empty` | `PROF.profile_name` is empty | `prof.profile_identity` |
| `prof-settings-exposure` | `PROF` settings carry a zero normal exposure | `prof.settings_exposure` |
| `prof-settings-layer-height` | `PROF` settings carry a zero layer height | `prof.settings_layer_height` |
| `prof-cure-curve` | `PROF` cure curve has `dp_um = 0.0` | `prof.cure_curve` |
| `prof-uuid-malformed` | `PROF.profile_uuid` is not a UUID | `prof.profile_uuid` |
| `prof-materials-shape` | `PROF.materials` is an empty array | `prof.materials_shape` |
| `lrov-entry-form-both` | an `LROV` entry carries both `layer` and `layer_range` | `lrov.entry_form` |
| `lrov-layer-out-of-range` | an `LROV` entry overrides layer 40 of a ten-layer file | `lrov.layer_index_range` |
| `lrov-range-reversed` | an `LROV` `layer_range` ends before it begins | `lrov.layer_range_order` |
| `lrov-sector-undefined` | an `LROV` entry targets a sector no `SECT` defines | `lrov.sector_id_defined` |
| `prev-flags` | a `PREV` chunk sets reserved flag bit 5 alongside its role | `prev.flags` |
| `prev-not-png` | a `PREV` payload does not begin with the PNG signature | `prev.png_signature` *(strict)* |
| `voxl-not-voxl` | the embedded scene is a JSON array, so the payload begins with neither the V2 magic nor the V1 document marker | `voxl.signature` *(strict)* |
| `extd-critical` | an `EXTD` chunk sets the `critical` bit on an extension no reader implements | `extd.critical` |
| `extd-truncated` | an `EXTD` payload is four bytes, too short for `ext_version` and `ext_type` | `extd.frame` |
| `extd-reserved-flags` | an `EXTD` chunk sets reserved flag bit 0 | `extd.flags` |
| `extd-type-nonascii` | an `EXTD` `ext_type` is four non-ASCII bytes | `extd.ext_type` |

Four vectors are marked *(strict)*: the defect is invisible to a loose-mode reader
(section 11.5) and must only be caught by a strict-mode validator. The manifest
records this as `strict_only`, and `verify_vectors.py` asserts that a loose-mode
reader accepts them — so the corpus pins the loose/strict distinction itself, not
just the checks.

`crypt-argon2-budget` is the one invalid vector a reader *could* decrypt: its
password section is coherent, and only the cost ceiling refuses it. A validator must
not attempt a derivation it has already rejected, which is why the file also pins
that the refusal happens before any crypto work.

## Check names

Checks are named `<group>.<rule>`, mirroring section 11:
`trailer.*`, `header.*`, `dir.*`, `chunk.*`, `presence.*`, `hdr.*`, `auth.*`,
`meta.*`, `sect.*`, `prof.*`, `lrov.*`, `prev.*`, `voxl.*`, `extd.*`, `ltbl.*`,
`layr.*`, `zdic.*`, `lhas.*`, `ree.*`, `sector.*`, `crypt.*`.

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

1. Add a builder in `make_vectors.py` (and, for invalid vectors, a mutation plus
   its expected check name). Encrypted vectors go through
   `build_encrypted_vector`, which also records the `crypto` block.
2. `python make_vectors.py`
3. `python verify_vectors.py -v`
4. Commit the `.lumen` files and `manifest.json` together.

## Notes

- `make_vectors.py` self-tests its CRC-32C against the standard check value
  (`"123456789"` → `0xE3069283`) before generating anything, and
  `verify_vectors.py` repeats that self-test before validating. The generator also
  asserts that its own password section unwraps to the session key it sealed with.
- The vectors use a 64×48 display (3 072 pixels) except `dict-multi-block` and
  `encrypted-password`, which use 256×192 (49 152 pixels) so that the zstd
  dictionary has enough sample data to train on. Display size is irrelevant to
  every rule the vectors exercise.
- `LROV` entries carry exactly one of `layer` or `layer_range`; the corpus pins that
  form. A `PREV` chunk carries its role in its descriptor's flag bits 0-3, with bits
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
