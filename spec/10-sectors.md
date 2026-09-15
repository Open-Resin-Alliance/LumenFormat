# Multi-material sectors

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 7. Multi-Material / Sector Model

### 7.1 Conceptual Model

A **sector** is an exposure group with its own timing parameters and its own mask data for
each layer. On a given layer, a sector is a pair:

- an **override set** - that `(layer, sector)`'s `LROV` chunk, or none
  ([§4.5](05-print-control.md#45-lrov---layer-override-chunk)), and
- a **data slice** - that `(layer, sector)`'s byte range inside the `LAYR` chunk for its
  sector ([§4.9](06-layer-data.md#49-layr---layer-data-chunk)), or none.

Those two, plus the layer table entry that names both
([§4.7](06-layer-data.md#47-ltbl---layer-table-chunk)), are all a sector is in the layer
stream. There is no in-band sector id and no per-layer framing to parse: a sector's data is
its own chunk, and the entry that points at it is where a reader learns which sector it is
looking at. Anything a sector carries beyond that - a name, a colour, a material, and the
timing it starts from - is declared once in `META.sectors` ([§4.2](03-chunks.md#42-meta---metadata-chunk)).

Use cases:

- **Single material:** one sector (sector 0). Standard today. A sector carries no material by
  default - `material_index` is optional, and absent it a printer uses the material it has
  loaded.
- **Multi-material:** several sectors on the same layer, each with its own exposure and,
  opt-in, its own `material_index` into `META.materials`: a support region cured differently
  from the model, or, on future multi-vat hardware, two resins in one layer.

### 7.2 Sector 0 Convention and Single-Material Degradation

Sector 0 is the **primary** or **default** sector, and it is implicitly present on every
layer that carries data: a layer's first entry is sector 0's, and it is there whether or not
that sector has anything to print.

Even in multi-sector files, a single-material reader can:

1. Print the layer's first entry - sector 0's slice - and its resolved timing.
2. Reach the next layer by stepping over the `additional_sector_count` entries that follow,
   without decoding anything they point at.
3. Apply META's timing, which is what sector 0 resolves from: sector 0 has no `META.sectors`
   entry and no `LROV` it does not name.

Because sectors partition the layer image ([§7.3](#73-sector-mask-invariant)), a layer whose
sectors `>= 1` are non-empty is **not** fully represented by sector 0 alone. A reader that
prints sector 0 only MUST therefore detect non-empty non-zero sectors and report the print as
incomplete - warn in loose mode, refuse in strict mode. Reporting such a print as complete is
a conformance failure. Layers whose only non-empty sector is sector 0 are unaffected.

The detection costs nothing and needs no decompression: the layer table states which layers
carry more than one sector, and which of those entries hold data, so a reader knows a file is
more than it prints before it decodes a byte.

This is a deliberate trade-off: the partition model is what makes multi-vat hardware
correct, and it means single-material compatibility is "print what you can print,
and say so" rather than silent infidelity.

### 7.3 Sector Mask Invariant

For a given layer, all sector masks are pairwise non-overlapping and their union is
exactly the layer's exposed image: every exposed pixel belongs to exactly one
sector. Encoders MUST guarantee this; readers SHOULD verify it in strict mode. An
empty layer is one whose every entry carries `data_size == 0`.

The invariant is unchanged in substance, and it now spans chunks: two sectors of one layer
are never slices of the same `LAYR` chunk, since a chunk carries one sector's data, so
verifying a layer means decoding the slices its entries name and comparing them - not
walking one stream that holds them all.
