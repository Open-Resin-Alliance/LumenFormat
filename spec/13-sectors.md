# Multi-material sectors

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 7. Multi-Material / Sector Model

### 7.1 Conceptual Model

A **sector** is an exposure group with its own timing parameters and its own mask data for
each layer. On a given layer, a sector is a pair:

- an **override set** - that `(layer, sector)`'s `LROV` chunk, or none
  ([§4.5](08-print-control.md#45-lrov---layer-override-chunk)), and
- a **data slice** - that `(layer, sector)`'s byte range inside the `LAYR` chunk for its
  sector ([§4.9](09-layer-data.md#49-layr---layer-data-chunk)), or none.

Those two, plus the layer table entry that names both
([§4.7](09-layer-data.md#47-ltbl---layer-table-chunk)), are all a sector is in the layer
stream. There is no in-band sector id and no per-layer framing to parse: a sector's data is
its own chunk, and the entry that points at it is where a reader learns which sector it is
looking at. Anything a sector carries beyond that - a name, a colour, a material, and the
timing it starts from - is declared once in `META.sectors` ([§4.2](05-meta.md#42-meta---metadata-chunk)).

Use cases:

- **Single material:** one sector (sector 0). Standard today. A sector carries no material by
  default - `material_index` is optional, and absent it a printer uses the material it has
  loaded.
- **Multi-material:** several sectors on the same layer, each with its own exposure and,
  opt-in, its own `material_index` into `META.materials`: a support region cured differently
  from the model, or, on future multi-vat hardware, two resins in one layer.

**Print sequence within a layer.** A layer that carries more than one sector is exposed
one sector at a time, in ascending `sector_id`, and each sector performs its own resolved
cure-and-move cycle: it exposes its mask for its own exposure time, at its own PWM, and then
runs its own lift, retract and pause profile from
[§8](14-layer-timing.md#8-per-layer-settings-model) before the next sector begins. The
platform returns to the same layer height for each of them - the layer's Z is one fact, its
exposures are several - so a two-resin layer is two complete cycles at one Z, not two layers.

Two things follow, and they are why the sequence is stated rather than left to the printer:

- **The masks are disjoint, so the order cannot change the geometry.** A pixel belongs to one
  sector ([§7.3](#73-sector-mask-invariant)), so exposing sector 0 first and sector 1 second
  cures the same pixels as the reverse order, and no pixel is cured twice.
- **A printer that cannot make more than one exposure per layer cannot print the file as it
  stands.** It prints sector 0 and reports the print as incomplete
  ([§7.2](#72-sector-0-convention-and-single-material-degradation)); it must not merge sectors,
  average them, or print one of them at the other's exposure.

A multi-vat printer likewise exposes the sectors in ascending `sector_id`; which vat is active
during which exposure is hardware state, not file data, and this specification carries no
per-sector machine or vat binding. A file's sectors are ordered by their ids and by nothing
else.

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

For a given layer, the sector masks are pairwise disjoint: no pixel is exposed by two sectors
of the same layer. Two obligations sit on either side of that, and only the first is something
a reader can check.

- **What a reader verifies (strict mode).** The masks of one layer's sectors do not overlap.
  This is decidable from the file: decode the slices the layer's entries name and look for a
  pixel two of them expose. A validator rejects the layer under `sector.partition`
  ([§11.3](17-validation.md#113-layer-data-validation-post-decompression)).
- **What an encoder guarantees.** The masks together are the layer's exposed image: every
  pixel the slice's geometry exposes belongs to exactly one sector. No reader can check this,
  because the file does not carry the geometry the masks were derived from - there is nothing
  to compare the union against - so it is an encoder obligation of the same kind as "the mask
  is the slice of the model at this Z". A file whose sector 0 carries the model's left half and
  whose sector 1 carries nothing passes the overlap check and is still not a print of the
  model.

An empty layer is one whose every entry carries `data_size == 0`, and its sector masks are
empty, which is trivially disjoint.

The invariant is unchanged in substance, and it spans chunks: two sectors of one layer
are never slices of the same `LAYR` chunk, since a chunk carries one sector's data, so
verifying a layer means decoding the slices its entries name and comparing them - not
walking one stream that holds them all.
