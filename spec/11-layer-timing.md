# Per-layer settings

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 8. Per-Layer Settings Model

The layer timing pipeline resolves as follows for each layer index `i`:

1. **Base values** from META (and SECT, if multi-sector).
2. **Bottom/transition blending:** Layers `0 .. bottom_layer_count-1` use the
   bottom-prefixed values verbatim. For a layer `i` in the transition range
   `bottom_layer_count .. bottom_layer_count+transition_layer_count-1`, let

   ```
   t = (i - bottom_layer_count + 1) / (transition_layer_count + 1)
   ```

   and set each **interpolatable** value to
   `bottom_value + t × (normal_value - bottom_value)`. The first fully-normal layer is
   therefore `bottom_layer_count + transition_layer_count`, where `t = 1`.

   Interpolatable values are the continuous motion and timing parameters: exposure
   times, lift/retract distances and speeds, and wait times. A
   `bottom_*` value that is absent equals its normal counterpart, which makes that
   field's interpolation a no-op. Integer and categorical values do **not** interpolate:
   `light_pwm`/`bottom_light_pwm` switch to the normal value at the first non-bottom
   layer, and `bottom_layer_count` and `transition_layer_count` are taken verbatim from
   META.
3. **LROV overrides:** Any matching `layer` or `layer_range` entry in LROV overrides
   the interpolated value for the sectors it targets (`sector_id` absent = all
   sectors). The last matching entry wins per `(layer, sector)` pair.

This models the existing bottom/normal/transition behavior while allowing arbitrary
per-layer overrides.
