# LUMEN Format Specification

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->



**Lead Developer:** Paul Skapczyk  
**Maintaining Authority:** Open Resin Alliance  
**Project:** Open Resin Alliance - Next-Generation Print File Format  
**Status:** Draft Specification  
**License:** MIT

---

## Abstract

The LUMEN format is a next-generation, open-source print file format for resin
(MSLA) 3D printing, developed as part of the Open Resin Alliance ecosystem. It is
designed to complement the existing ORA infrastructure - serving as the native
output format for the **DragonFruit** slicer and the primary print format
consumed by **Odyssey** firmware (via its **Orion** frontend).

Existing container formats (CTB, GOO, AFZ, NanoDLP) were reverse-engineered from
proprietary ecosystems. They carry the legacy of fixed binary layouts, weak
compression, vendor obfuscation, and fundamental design constraints that limit
what next-generation hardware can achieve. LUMEN breaks from this lineage
entirely. It is designed from first principles to be the most efficient,
flexible, and future-proof resin print format ever specified - with no
proprietary baggage and no compromises made for legacy compatibility.

This document is the normative specification for LUMEN v1.0. It defines every
byte on disk, every semantic invariant, and every validation rule a conforming
reader or writer must observe.

### Reader's Guide

This document is written for two audiences, and structured so each can find
what they need without reading the whole thing:

| Audience | Recommended path |
|----------|-----------------|
| **Engineers evaluating LUMEN** (product managers, engineering leads, curious hackers) | Read [§1](#1-design-philosophy) (Design Philosophy), [§2](#2-core-conventions) (Core Conventions), the [§4](03-chunks.md#4-chunk-types) chunk summary table, [§5](08-layer-encoding.md#5-layer-mask-encoding) intro, [§6](09-compression.md#6-compression-strategy) intro, [§9](12-encryption.md#9-encryption-model) intro, and [§12](15-comparison.md#12-comparison-with-existing-formats) (Comparison). Skip binary layout tables unless you need them. |
| **Developers implementing LUMEN** (encoder/decoder authors, firmware engineers) | Read everything. Start with [§3](02-file-structure.md#3-file-structure) (File Structure) and [§4](03-chunks.md#4-chunk-types) (Chunk Types) for the container, then [§5](08-layer-encoding.md#5-layer-mask-encoding) (Layer Mask Encoding) for the REE spec. Reference [§11](14-validation.md#11-reader-validation-requirements) (Validation) for your test plan. |

Sections marked with implementation-level binary tables assume the reader is
writing code against the format. Sections with broader prose and design
rationale are written for a general engineering audience.

---

## 1. Design Philosophy

LUMEN is built on six principles that reflect the values of the Open Resin
Alliance:

1. **Compression efficiency first.** Modern 8K–12K printers produce 30–75
   megapixel layers. A 2,000-layer print at 12K resolution represents
   approximately 150 GB of raw pixel data before compression. LUMEN combines
   Run-End Encoding (REE), zstd cross-layer dictionary compression, and a novel
   split encoding strategy for anti-aliased prints to push compressed file sizes
   as low as the underlying information theory allows.

2. **Human-inspectable metadata.** Print parameters, material definitions,
   per-layer overrides, and machine metadata are stored as structured JSON.
   A user can inspect these with standard tools. Binary encoding is reserved
   exclusively for layer masks and previews where it provides unambiguous value.

3. **Extensible by design.** A chunk-based container with typed sections ensures
   the format can grow without breaking existing readers. Unknown chunks are
   skipped. Known chunks carry version sub-fields so a future v2 reader can
   still parse v1 data without modification.

4. **Multi-material from the ground up.** Sectors (exposure groups) are a
   first-class concept, not an afterthought. Each layer can carry multiple
   independent masks, each with its own resin, exposure, and motion profile -
   ready for the multi-vat hardware that will define the next decade of resin
   printing.

5. **Per-layer settings.** Any timing parameter can be overridden for any layer
   or range of layers. This replaces the rigid "bottom layers, transition
   layers, normal layers" model that has constrained every existing format.

6. **Open and transparent.** No obfuscation, no mandatory encryption designed
   for vendor lock-in. Optional authenticated encryption is available for secure
   facilities that require confidentiality - but it is the user's choice, never
   the vendor's demand.

### 1.1 What LUMEN Is Not

To avoid confusion with other parts of the ORA ecosystem, LUMEN is explicitly
**not**:

- **Not a scene format.** LUMEN carries resolved print data (layer masks,
  exposure settings, motion parameters). For editable 3D scenes with models,
  supports, and modifiers, see the VOXL format. LUMEN can *embed* a VOXL scene
  ([§4.12](07-scene-chunks.md#412-voxl---embedded-scene-chunk)) for round-trip editing, but the format's primary purpose is print
  execution.

- **Not a streaming protocol.** LUMEN is a file format, designed for storage
  and transfer as a complete unit. It is not intended for real-time printer
  control over a network.

- **Not a printer-specific format.** LUMEN is printer-agnostic. It carries
  display dimensions and timing parameters that any compatible firmware can
  interpret. Printer-specific calibration data belongs in the firmware, not
  in the print file.

- **Not a replacement for existing formats - yet.** LUMEN requires Odyssey
  firmware. Stock printers still need CTB, GOO, or other legacy formats.
  As Odyssey adoption grows, LUMEN may replace them.

---

## 2. Core Conventions

| Property | Value |
|----------|-------|
| Extension | `.lumen` |
| Media type | `application/vnd.openresin.lumen` (vendor tree; see [Appendix D](19-appendix-d-media-type.md#appendix-d-media-type-registration)) |
| Magic bytes | `LUMN` (`0x4C 0x55 0x4D 0x4E`) |
| Endianness | Little-endian (all multi-byte integers) |
| Coordinate basis | Right-handed, Z-up |
| Image orientation | Layer masks are stored as the printer must expose them; readers apply no flip ([§4.1](03-chunks.md#41-hdr---file-header-chunk)). |
| Units | Millimeters (`mm`), millimeters per minute (`mm/min`) |
| Range notation | `a..b` is half-open `[a, b)`. `for i in 0..N` iterates `i = 0, 1, ..., N-1`. |

Format detection: a `.lumen` file begins with the four ASCII bytes `LUMN`.
