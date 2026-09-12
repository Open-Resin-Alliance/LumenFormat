# Multi-material sectors

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 7. Multi-Material / Sector Model

### 7.1 Conceptual Model

A **sector** is a named exposure group with its own timing parameters and per-layer
mask data. Use cases:

- **Single material:** One sector (sector 0). Standard today.
- **Support/model split:** Sector 0 = model, sector 1 = supports. Support material
  uses faster exposure.
- **Multi-resin printing:** Different regions printed with different resins (future
  multi-vat hardware).

### 7.2 Sector 0 Convention and Single-Material Degradation

Sector 0 is the **primary** or **default** sector. It is implicitly present in every
non-empty layer: if a layer's sector list omits sector 0, sector 0's mask for that
layer is empty (all black), and the layer's remaining sectors cover the image.

Even in multi-sector files, a single-material reader can:

1. Ignore all `SECT` chunks.
2. Decode only sector 0 masks from each layer (parsing the multi-sector varint
   framing to locate sector 0's data — a small overhead of a few varint decodes
   per layer).
3. Apply META default timing to all layers.

Because sectors partition the layer image ([§7.3](#73-sector-mask-invariant)), a layer whose sectors ≥ 1 are
non-empty is **not** fully represented by sector 0 alone. A reader that decodes only
sector 0 MUST therefore detect non-empty non-zero sectors and report the print as
incomplete — warn in loose mode, refuse in strict mode. Reporting such a print as
complete is a conformance failure. Layers whose only non-empty sector is sector 0
are unaffected.

This is a deliberate trade-off: the partition model is what makes multi-vat hardware
correct, and it means single-material compatibility is "print what you can print,
and say so" rather than silent infidelity.

### 7.3 Sector Mask Invariant

For a given layer, all sector masks are pairwise non-overlapping and their union is
exactly the layer's exposed image: every exposed pixel belongs to exactly one
sector. Encoders MUST guarantee this; readers SHOULD verify it in strict mode. An
empty layer has no sectors (`sector_count == 0`).
