# LumenFormat: The LUMEN Print Format

[![LUMEN version](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FOpen-Resin-Alliance%2FLumenFormat%2Fmain%2Fstatus.json&query=%24.version&label=LUMEN&style=for-the-badge&color=blueviolet)](status.json)
[![Revision status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FOpen-Resin-Alliance%2FLumenFormat%2Fmain%2Fstatus.json&query=%24.status&label=revision&style=for-the-badge&color=orange)](status.json)
[![CI](https://img.shields.io/github/actions/workflow/status/Open-Resin-Alliance/LumenFormat/ci.yml?branch=main&label=CI&style=for-the-badge)](https://github.com/Open-Resin-Alliance/LumenFormat/actions/workflows/ci.yml)
[![GitHub license](https://img.shields.io/github/license/Open-Resin-Alliance/LumenFormat.svg?style=for-the-badge)](LICENSE)
[![Discord](https://img.shields.io/discord/1281738817417777204?style=for-the-badge&logo=discord&logoColor=white&color=%235865F2)](https://discord.gg/beFeTaPH6v)

LUMEN is the Open Resin Alliance's open print file format for resin (MSLA) 3D printing:
run-end encoded layer masks in independently compressed zstd frames, human-inspectable JSON
metadata in typed chunks, multi-material sectors, per-layer settings, and optional
authenticated encryption. It is the native output format of the **DragonFruit** slicer and
the print format **Odyssey** firmware consumes through its **Orion** frontend.

This repository is the specification, plus everything that keeps it honest: the normative
text under [`spec/`](spec/), the byte-exact conformance corpus under
[`test-vectors/`](test-vectors/), and the reference encoder, decoder and validator under
[`rust/lumen/`](rust/lumen/). The three are one artifact - the crate's tests read the
corpus, and the corpus is the contract the specification publishes - so CI runs them
against each other on every change.

> :warning: **LUMEN v1.0 is a draft revision.** A draft may be revised in place, so check
> [`status.json`](status.json) before depending on a detail. Once a revision is published
> it is immutable and every later change ships as a new revision.

## Table of Contents

- [About LUMEN](#about-lumen)
- [What is in this repository](#what-is-in-this-repository)
- [Reading the specification](#reading-the-specification)
- [Status and versioning](#status-and-versioning)
- [Conformance corpus](#conformance-corpus)
- [Reference implementation](#reference-implementation)
- [Continuous integration](#continuous-integration)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## About LUMEN

| Property | Value |
|----------|-------|
| Extension | `.lumen` |
| Media type | `application/vnd.openresin.lumen` (vendor tree) |
| Magic bytes | `LUMN` (`0x4C 0x55 0x4D 0x4E`) |
| Container version | `header.version = 1` for LUMEN v1.0 |
| Units | Micrometers (`um`), micrometers per minute (`um/min`) and milliseconds (`ms`); whole seconds for the Unix timestamp and the estimated print time. Lengths, speeds and durations are integers |

The format is built on six principles (§1): compression efficiency first, human-inspectable
metadata, extensible by design, multi-material from the ground up, per-layer settings, and
open and transparent - no obfuscation and no mandatory encryption. Metadata, profiles and
previews are JSON where that is useful; binary encoding is reserved for layer masks, where
it pays for itself.

LUMEN is deliberately **not** a scene format (that is VOXL, which a `.lumen` file may embed
for round-trip editing), not a streaming protocol, not printer-specific, and not a drop-in
replacement for CTB or GOO - it needs firmware that implements it (§1.1).

Where the formats it is meant to replace were reverse-engineered from proprietary
ecosystems, LUMEN is designed from first principles: a chunk directory at the end of the
file, a single `header.version` lineage, and no constraints kept for legacy compatibility.
§12 places the result beside CTB v5, GOO, AFZ and NanoDLP.

## What is in this repository

| Path | Contents |
|------|----------|
| [`spec/`](spec/) | The normative specification, published in 22 parts ([below](#reading-the-specification)) |
| [`test-vectors/`](test-vectors/) | Byte-exact `.lumen` conformance corpus, its manifest, and an independent validator |
| [`rust/lumen/`](rust/lumen/) | The reference implementation: encoder, decoder and validator (crate `lumen-format`) |
| [`rust/corpus-gen/`](rust/corpus-gen/) | `make_vectors`: regenerates the corpus from the specification, independently of the reference crate |
| [`rust/corpus/`](rust/corpus/) | `verify_vectors` and `cross_check`: the specification's own reader, independent of both |
| Repository root | The DragonFruit plugin for `.lumen` (`pluginDefinition.ts` and `slicing/`), which DragonFruit imports as the submodule at its `plugins/lumen` |
| [`status.json`](status.json) | The machine-readable revision declaration: version, status, published git ref |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Runs the corpus, the crate and the cross-check on every change |
| [`LICENSE`](LICENSE) | MIT |

Rendered specification: <https://openresin.org/specs/lumen>

## Reading the specification

Start at [`spec/01-overview.md`](spec/01-overview.md). The specification is published in
parts under [`spec/`](spec/), in reading order, and section numbers (`§3.1`) are stable
anchors across them - a link into a section keeps working whichever part it lives in.
Section numbers track the subject, not the file: §4 is split across eight parts so each
chunk group can be read on its own.

| Part | Sections | Covers |
|------|----------|--------|
| [`01-overview.md`](spec/01-overview.md) | §1-2 | Design philosophy, core conventions, what LUMEN is not |
| [`02-file-structure.md`](spec/02-file-structure.md) | §3 | Header, chunk directory at the end of the file, trailer |
| [`03-chunks.md`](spec/03-chunks.md) | §4 | The chunk type summary: what each chunk is for, required to write, mandatory to honor |
| [`04-head.md`](spec/04-head.md) | §4.1 | `HEAD`: display dimensions, build volume, layer count |
| [`05-meta.md`](spec/05-meta.md) | §4.2 | `META`: exposure, motion, waits, PWM, materials, sectors |
| [`06-prof.md`](spec/06-prof.md) | §4.3 | `PROF`: a named, reusable print profile |
| [`07-chunk-auth.md`](spec/07-chunk-auth.md) | §4.4 | `AUTH`, password and machine-binding sections |
| [`08-print-control.md`](spec/08-print-control.md) | §4.5-4.6 | `LROV`, `PREV` |
| [`09-layer-data.md`](spec/09-layer-data.md) | §4.7-4.10 | `LTBL`, `ZDIC`, `LAYR`, `LHAS` |
| [`10-scene-chunks.md`](spec/10-scene-chunks.md) | §4.11-4.12 | `VOXL` embedded scene, `EXTD` extensions |
| [`11-layer-encoding.md`](spec/11-layer-encoding.md) | §5 | Run-end encoding: binary, grayscale and split REE |
| [`12-compression.md`](spec/12-compression.md) | §6 | zstd frame framing and the shared trained dictionary |
| [`13-sectors.md`](spec/13-sectors.md) | §7 | Multi-material sectors and the sector mask invariant |
| [`14-layer-timing.md`](spec/14-layer-timing.md) | §8 | Per-layer settings, bottom/transition blending, overrides |
| [`15-encryption.md`](spec/15-encryption.md) | §9 | AEAD framing, Argon2id passwords, X25519 machine binding |
| [`16-versioning.md`](spec/16-versioning.md) | §10 | Revision numbering, forward compatibility, change control |
| [`17-validation.md`](spec/17-validation.md) | §11 | Every check a conforming reader runs, loose and strict |
| [`18-comparison.md`](spec/18-comparison.md) | §12 | LUMEN against CTB, GOO, AFZ and NanoDLP |
| [`19-appendix-a-example.md`](spec/19-appendix-a-example.md) | Appendix A | The example files the reference implementation writes, layout by layout |
| [`20-appendix-b-encoder.md`](spec/20-appendix-b-encoder.md) | Appendix B | The reference implementation: the crate and the slicer adapter that ships |
| [`21-appendix-c-references.md`](spec/21-appendix-c-references.md) | Appendix C | Standards, RFCs and related format specifications |
| [`22-license.md`](spec/22-license.md) | - | MIT text and format governance |

Two audiences are expected, and the Reader's Guide in
[`spec/01-overview.md`](spec/01-overview.md) says where each can start: engineers evaluating
the format can read the philosophy, the conventions, the chunk summary table, the
introductions to layer encoding, compression and encryption, and §12; implementers read
everything, and keep §11 open as their test plan.

## Status and versioning

[`status.json`](status.json) is the machine-readable answer to "which revision is this, and
is it finished". The website reads it, so the specification published at
<https://openresin.org/specs/lumen> is the one this repository declares - a draft in
progress is not published by being pushed.

| Field | Meaning |
|-------|---------|
| `version` | The revision of the working tree |
| `status` | `draft` or `published` |
| `stable` | The git ref of the published revision, once there is one; a published ref is never moved |
| `updated`, `license` | When the declaration was last changed, and the specification's license |

A revision is a draft until this file says otherwise, and a draft may be revised in place -
that is what the declaration is for. Once published it is immutable, and §10.3 ships every
later change as a new revision:

| Class | What it covers | Ships as |
|-------|----------------|----------|
| **Correction** | Text that contradicts another part, a wrong offset, length or unit, an undefined term, an ambiguity two conforming implementations could read two ways | `v1.0.1` |
| **Additive** | A new optional chunk type, JSON key, reserved code, extension type, or check a reader may skip | `v1.1`, `header.version` unchanged |
| **Breaking** | A different layout for an existing field, a changed meaning for an existing value, a removed field, or different algorithm constants | `v2.0`, with `header.version = 2` |

So an implementation can name the revision it was written against and be understood. A
correction that resolves an ambiguity names the reading that is now correct, and a file
produced under another reading is not conforming for that revision - the encryption
constants in §4.4.1 were pinned that way while this document was still a draft.

## Conformance corpus

[`test-vectors/`](test-vectors/) holds byte-exact `.lumen` files and a validator written
independently of the specification's own encoder:

| Path | Contents |
|------|----------|
| `valid/*.lumen` | 14 files a conforming reader must accept, each pinning the structures it contains |
| `invalid/*.lumen` | 59 files a conforming reader must reject, each failing the check its manifest entry names, which is the first one the validator order reaches |
| `manifest.json` | Golden data for every vector: sizes, offsets, the layer table, each `LAYR` chunk's frame, per-layer hashes, Merkle root, CRC-32C, the timing a conforming reader must resolve for a sample of `(layer, sector)` points, and the credentials for encrypted vectors |
| [`rust/corpus-gen/`](rust/corpus-gen/) | `make_vectors`: reference encoder that regenerates the corpus from the specification |
| [`rust/corpus/`](rust/corpus/) | `verify_vectors`: independent reader and validator, sharing no code with the generator. `cross_check` runs it against files the reference crate wrote |

Because the generator and the validator share no code, and neither depends on the reference
crate, agreement between them is evidence that the specification is unambiguous rather than
that one module is self-consistent. Five invalid vectors are marked `strict_only`: their
defect is invisible to a loose-mode reader, and the corpus asserts that a loose read accepts
them, which pins the loose/strict distinction itself.

The manifest also records the settings a conforming reader must resolve for a sample of
`(layer, sector)` points, so the §8 pipeline - base values, bottom/transition blending, the
overrides - is checkable by any implementation and not only by this crate's own tests. That
is what makes §4.5's mandatory handling of per-layer overrides enforceable rather than
prose.

```sh
cd rust
cargo run --release -p lumen-corpus --bin verify_vectors        # validate the committed corpus
cargo run --release -p lumen-corpus --bin verify_vectors -- -v  # print every individual check
cargo run --release -p lumen-corpus-gen --bin make_vectors      # regenerate the corpus
```

`verify_vectors` exits 0 only if every valid vector passes and every invalid vector fails
the check it advertises. The exit status is 3 when the run did not cover the whole corpus -
not 0, because the run proves less than it claims, and not 1, which means a check failed.

The corpus fixes what the specification leaves open, and is explicit about what it cannot
pin: compressed payload bytes depend on the zstd version and level, so the manifest records
the version, level, each frame's dictionary ID and declared content size and the validator
asserts those rather than byte equality. Everything uncompressed - the header, `HEAD`, `AUTH`,
the `LTBL` header and its 28-byte entries, each `LAYR` chunk's version field, every REE
stream, the directory and the trailer - is exact.
[`test-vectors/README.md`](test-vectors/README.md) has the per-vector table and the check
names implementations are encouraged to report verbatim.

## Reference implementation

[`rust/lumen/`](rust/lumen/) is the encoder, decoder and validator for anything that reads
or writes `.lumen` without re-deriving the format from the text. The crate is
`lumen-format` and the library target is `lumen`, so code reads `use lumen::…`. It is not
on crates.io yet, so consume it from this repository:

```toml
[dependencies]
# Beside a checkout of this repository:
lumen-format = { path = "../LumenFormat/rust/lumen" }
# Inside DragonFruit, where this repository is the plugins/lumen submodule:
lumen-format = { path = "plugins/lumen/rust/lumen" }
```

Consumers are adapters over it rather than parallel implementations - DragonFruit maps its
own settings into `META`/`PROF` and hands the crate layer masks, Odyssey implements its
`PrintFile` trait over `LumenFile` - because every divergence between two implementations is
a compatibility bug that only shows up on a printer. `LumenFile` borrows the container's
bytes and decompresses one frame per layer request, so a firmware reader streams a
2,000-layer print through a bounded buffer; the crate's test suite measures that bound
rather than asserting it in prose.

```sh
cd rust/lumen
cargo test                                   # unit, conformance and round trip
cargo test --test conformance                # the corpus only
```

The conformance tests read the corpus from beside the specification, so they run from a
checkout of this repository. Rust 1.85 or later, edition 2021; the crate is MIT OR
Apache-2.0, matching the specification's MIT license while remaining usable by GPL-3.0
consumers. [`rust/lumen/README.md`](rust/lumen/README.md) documents reading, writing,
validating, encryption and the deliberate non-goals (`VOXL` parsing, extension payloads and
signatures).

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on any change to `spec/`,
`test-vectors/`, `rust/` or the workflow itself, because a change to any of them is a change
to what has to keep working:

| Job | Checks |
|-----|--------|
| Format, lint, test and package | `cargo fmt --all --check`, `clippy --workspace -D warnings`, the workspace test suite, and `cargo publish -p lumen-format --dry-run` - a crate whose tests cannot run once unpacked is not publishable |
| Minimum supported Rust version | The published crate's suite on 1.85.0 with the committed lock, so the declared floor is verified rather than estimated |
| wasm32 build | `cargo check -p lumen-format --lib --target wasm32-unknown-unknown` with `clang` installed, because DragonFruit builds this crate for its webview |
| Corpus and cross-implementation check | The generator reproduces the committed corpus byte for byte, that corpus validates under the specification's own reader, and a file the crate wrote validates under that same reader |

## Contributing

Corrections and discussion are welcome as issues on this repository. A change to the format
is a change to three things at once, and a pull request is expected to carry all of them:
the specification text, the corpus vectors that pin the new behavior, and the reference
implementation. That is exactly what CI checks.

- A **correction** should say which part contradicts which, or which two readings are
  possible, and it ships as a patch revision.
- New behavior needs a vector: `make_vectors` builds it, `verify_vectors` proves it, and the
  generated files plus `manifest.json` are committed together. CI regenerates the corpus and
  fails if the tree moves, so a hand-edited vector cannot slip through.
- Vendor IDs for `EXTD` chunks are registered through the Alliance to avoid collisions
  between independent implementations ([§4.12](spec/10-scene-chunks.md#412-extd---extension-chunk)). These conventions are voluntary; coordination
  keeps the ecosystem interoperable, but the license lets you implement, extend and fork
  without asking.

Who wrote what is recorded by the repository's git history.

## License

The specification is MIT - see [`LICENSE`](LICENSE) and
[`spec/22-license.md`](spec/22-license.md). The reference implementation
under [`rust/lumen/`](rust/lumen/) is dual-licensed MIT OR Apache-2.0. The Open Resin
Alliance stewards the format, which is an ecosystem coordination role rather than a legal
restriction.

## Contact

Questions, corrections and interoperability reports are welcome on the
[Open Resin Alliance Discord](https://discord.gg/beFeTaPH6v), or as an issue on
[this repository](https://github.com/Open-Resin-Alliance/LumenFormat/issues). More from the
Alliance is at <https://openresin.org>.
