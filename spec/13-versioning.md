# Versioning and compatibility

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 10. Versioning and Forward Compatibility

### 10.1 Version Numbers

| Level | Field | Description |
|-------|-------|-------------|
| File | `header.version` | Breaking changes to the binary container. |
| HDR chunk | `hdr_version` | New fields added to HDR; compatible across file versions. |
| META chunk | `meta_version` | Additive changes to the META JSON schema. `SECT` and `LROV` payloads share this schema version. |
| LTBL chunk | `table_version` | Changes to layer entry layout. |
| AUTH chunk | `auth_version` | Changes to encryption metadata layout. |
| LAYR chunk | `layr_version` | Changes to the block framing layout. |
| ZDIC chunk | `zdic_version` | Changes to the dictionary chunk layout. |
| EXTD chunk | `ext_version` | Per-extension versioning. |

### 10.2 Forward Compatibility Mechanisms

1. **Unknown chunk types:** Skip (chunk descriptor gives byte range).
2. **Unknown chunk flags:** Ignore within known types.
3. **Unknown JSON keys:** Ignore in META, SECT, LROV payloads.
4. **New HDR fields:** Parse the layout for the `hdr_version` present. An unrecognized
   `hdr_version` is rejected - forward striding is impossible when the new fields'
   widths are unknown.
5. **New LTBL fields:** Stride using `entry_size`.
6. **Unknown EXTD with `critical = 1`:** Refuse file.
7. **Unknown EXTD with `critical = 0`:** Skip.

### 10.3 Deprecation Policy

No chunk type or field is removed in a minor version bump. If a better mechanism
replaces an existing chunk, both are present during a transition period; readers
prefer the newer one.
