# Per-layer settings

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 8. Per-Layer Settings Model

The layer timing pipeline resolves as follows for each layer index `i`:

1. **Base values** from META (and SECT, if multi-sector).
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
   each interpolatable value - so two implementations given the same META, SECT and LROV
   inputs derive the same value for every field of every layer. The first fully-normal
   layer is `bottom_layer_count + transition_layer_count`, where `k = N` and the formula
   collapses to `normal_value` exactly.

   Interpolatable values are exposure times, lift/retract distances and speeds, and wait
   times. A `bottom_*` value that is absent equals its normal counterpart, which makes
   that field's interpolation a no-op. The values that do **not** interpolate are PWM and
   the layer counts: `light_pwm`/`bottom_light_pwm` switch to the normal value at the
   first non-bottom layer, and `bottom_layer_count` and `transition_layer_count` are
   taken verbatim from META.
3. **LROV overrides:** Any matching `layer` or `layer_range` entry in LROV overrides
   the interpolated value for the sectors it targets (`sector_id` absent = all
   sectors). The last matching entry wins per `(layer, sector)` pair.

This models the existing bottom/normal/transition behavior while allowing arbitrary
per-layer overrides.
