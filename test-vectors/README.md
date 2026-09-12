# Lumen test vectors

Byte-exact `.lumen` files plus an independent validator, for implementations of
[`../lumen-format-spec.md`](../lumen-format-spec.md).

## Layout

| Path | Contents |
|------|----------|
| `valid/*.lumen` | Files a conforming reader must accept |
| `invalid/*.lumen` | Files a conforming reader must reject, each failing exactly one documented check |
| `manifest.json` | Golden data for every vector: sizes, offsets, block table, per-layer hashes, Merkle root, CRC-32C |
| `make_vectors.py` | Reference encoder that regenerates the corpus from the specification |
| `verify_vectors.py` | Independent reader and validator |

`verify_vectors.py` shares no code with `make_vectors.py`: the primitives and the
reader logic are reimplemented from the spec. Agreement between them is therefore
evidence that the specification is unambiguous, not that one module is
self-consistent.

## Running

```sh
pip install zstandard
python verify_vectors.py        # validate the committed corpus
python verify_vectors.py -v     # print every individual check
python make_vectors.py          # regenerate valid/, invalid/ and manifest.json
```

`verify_vectors.py` exits non-zero unless every valid vector passes **and** every
invalid vector fails exactly the check its manifest entry advertises. It also
re-checks each committed file against the golden values in `manifest.json`.

## What is exact, and what is not

The spec leaves two things to the encoder (section 5.6): the choice between
grayscale REE and split REE for a layer, and the block size. It also mandates
zstd, whose output bytes are not stable across versions, levels or builds.

So this corpus pins:

- **Exactly** - the file header, `HDR`, `LTBL`, the `LAYR` header and block
  table, `LHAS`, every REE stream, the chunk directory and the trailer CRC-32C,
  plus the decompressed bytes of every layer and the Merkle root over them.
  These are all in `manifest.json`.
- **By property** - compressed payload bytes. The manifest records the
  zstandard version and level, the frame's dictionary ID and the decompressed
  size; `verify_vectors.py` asserts those instead of byte equality.

Re-running `make_vectors.py` under a different zstandard version may change
`file_sha256`, the chunk sizes and the trailer CRC-32C. The uncompressed
structures and all layer hashes must not change. Regeneration is deterministic
for a fixed zstandard version.

## Valid vectors

| Vector | Layers | Blocks | Dictionary | Exercises |
|--------|--------|--------|-----------|-----------|
| `binary-basic` | 6 | 3 | no | the empty-layer form, binary REE, grayscale REE, split REE, multi-block framing, single-sector layer data |
| `dict-multi-block` | 64 | 4 | yes (trained, 1024 bytes) | `ZDIC`, dictionary-ID agreement across every block frame, four-block framing, split and grayscale REE at scale |
| `multi-sector` | 4 | 2 | no | `MULTI_SECTOR`, the per-layer sector varint framing, per-layer sector tags, the partition invariant, a layer with a single active sector inside a multi-sector file, an empty layer |

## Invalid vectors

`expected_failure` is the check name that must fail. Except for
`trailer-crc-mismatch`, every file carries a deliberately introduced defect and a
recomputed trailer CRC-32C, so a reader reaches the intended check rather than
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

Two vectors are marked *(strict)*: the defect is invisible to a loose-mode reader
(section 11.5) and must only be caught by a strict-mode validator. The manifest
records this as `strict_only`, and `verify_vectors.py` asserts that a loose-mode
reader accepts them — so the corpus pins the loose/strict distinction itself, not
just the checks.

## Check names

Checks are named `<group>.<rule>`, mirroring section 11:
`trailer.*`, `header.*`, `dir.*`, `chunk.*`, `presence.*`, `hdr.*`, `meta.*`,
`sect.*`, `ltbl.*`, `layr.*`, `zdic.*`, `lhas.*`, `ree.*`, `sector.*`.

Implementations are encouraged to use the same names when reporting which rule
failed. Use them verbatim as `expected_failure` when adding vectors.

## Adding a vector

1. Add a builder in `make_vectors.py` (and, for invalid vectors, a mutation plus
   its expected check name).
2. `python make_vectors.py`
3. `python verify_vectors.py -v`
4. Commit the `.lumen` files and `manifest.json` together.

## Notes

- `make_vectors.py` self-tests its CRC-32C against the standard check value
  (`"123456789"` → `0xE3069283`) before generating anything, and
  `verify_vectors.py` repeats that self-test before validating.
- The vectors use a 64×48 display (3 072 pixels) except `dict-multi-block`, which
  uses 256×192 (49 152 pixels) so that the zstd dictionary has enough sample data
  to train on. Display size is irrelevant to every rule the vectors exercise.
- No vector covers encryption (`AUTH`), previews (`PREV`) or embedded scenes
  (`VOXL`). Those need key material, a PNG encoder and a VOXL writer
  respectively; they are candidates for a later pass.
