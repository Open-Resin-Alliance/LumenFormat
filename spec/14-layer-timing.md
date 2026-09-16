# Per-layer settings

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 8. Per-Layer Settings Model

The pipeline below resolves the settings of one `(layer, sector)` pair. A file resolves it per
pair, not per layer: two sectors of the same layer can differ in every field, and each is
blended over the ranges its own sector supplies.

1. **Base values** from META. For a sector `>= 1`, its `META.sectors` entry replaces META's
   value for every field that entry carries, so the base is META resolved field by field for
   that sector ([§4.2](05-meta.md#42-meta---metadata-chunk)). A sector with no entry - sector
   0 among them - takes META as it stands.
2. **Bottom/transition blending:** Layers `0 .. bottom_layer_count-1` use the
   bottom-prefixed values verbatim. For a layer `i` in the transition range
   `bottom_layer_count .. bottom_layer_count+transition_layer_count-1`, let

   ```
   N = transition_layer_count + 1
   k = i - bottom_layer_count + 1        (1 <= k <= transition_layer_count)
   value = round((bottom_value × (N − k) + normal_value × k) / N)
   ```

   and set each **interpolatable** value to the result. The arithmetic is exact integer
   arithmetic end to end and `round` rounds half away from zero: a remainder of exactly
   half a unit rounds up in magnitude. No floating-point step remains in the pipeline, and
   nothing is rounded twice. Every quantity is an integer - the layer counts, `k`, `N` and
   each interpolatable value - so two implementations given the same META (its `sectors`
   entries included) and `LROV` inputs derive the same value for every field of every
   `(layer, sector)` pair. The first fully-normal layer is
   `bottom_layer_count + transition_layer_count`, where `k = N` and the formula
   collapses to `normal_value` exactly.

   `bottom_layer_count` and `transition_layer_count` here are the ones this pair's sector
   resolves with. A `META.sectors` entry that carries either count replaces META's for that
   sector, and the pair is then blended over **its own** bottom and transition ranges: its
   bottom range can be longer than META's, its transition steps land on different layers, and
   two sectors in one file can be in different stages on the same layer
   ([§4.2](05-meta.md#42-meta---metadata-chunk)). A reader MUST NOT resolve
   the ranges once from META and apply them to every sector.

   Interpolatable values are exposure times, lift/retract distances and speeds, and wait
   times. A `bottom_*` value that is absent equals its normal counterpart, which makes
   that field's interpolation a no-op. The values that do **not** interpolate are PWM and
   the layer counts: `light_pwm`/`bottom_light_pwm` switch to the normal value at the
   first non-bottom layer, and `bottom_layer_count` and `transition_layer_count` are
   taken verbatim from the base the sector resolves - META's, or a `META.sectors` entry's
   where it carries them.
3. **LROV overrides:** the pair's layer table entry names its `LROV` chunk, or `0` for none
   ([§4.7](09-layer-data.md#47-ltbl---layer-table-chunk)). The fields that chunk carries
   replace the interpolated values, field by field; a field it omits keeps the value the
   sector resolved, and no second chunk competes with it. A conforming reader
   MUST apply them: a printer that cannot honor overrides refuses the file rather than
   print these layers at the wrong exposure ([§4.5](08-print-control.md#45-lrov---layer-override-chunk)).

This models the existing bottom/normal/transition behavior while allowing arbitrary
per-pair overrides.
