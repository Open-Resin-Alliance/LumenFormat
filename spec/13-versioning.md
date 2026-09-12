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

`header.version` is the container version, not the version of this document: LUMEN
v1.0 is carried by `header.version = 1`. A revision that changes the container
layout bumps `header.version`; one that only adds fields bumps that field's own
sub-version.

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

### 10.3 Change Control

LUMEN v1.0 is published, so this specification is a contract: a file that conforms to
it must keep working. Every change to a published revision falls into one of three
classes, and the class decides what the change may touch.

| Class | What it covers | Version effect |
|-------|----------------|----------------|
| **Erratum** | Text that contradicts another part; a wrong offset, length or unit; an undefined term; an ambiguity that two conforming implementations could read two ways. | none |
| **Additive** | A new optional chunk type, JSON key, reserved code, extension type, or validation check a conforming reader may skip. | that field's own sub-version where it has one; `header.version` unchanged |
| **Breaking** | A different layout for an existing field, a changed meaning for an existing value, a removed chunk or field, or different constants for an algorithm this document specifies. | `header.version` is bumped |

**Errata** are the only changes that may alter the text of a published revision in
place. An erratum may resolve an ambiguity, including one this document caused, but
it MUST NOT change what a conforming encoder writes for an input the specification
already determined. Where an ambiguity had no single reading, the erratum names the
reading that is now correct, and a file produced under another reading is not a v1.0
file. The encryption constants in
[§4.4.1](04-chunk-auth.md#441-password-section) were fixed this way.

**Additive** changes ship as a minor revision of this document (`v1.1`) and leave
`header.version = 1`. A reader that predates one skips what it does not know
([§10.2](#102-forward-compatibility-mechanisms)), and a file is never invalid merely
because it was written against a newer minor revision. Conversely, a reader MUST NOT
require an optional mechanism in order to decode a file that does not use it.

**Breaking** changes ship as `v2.0` with `header.version = 2`, and both versions
coexist: v1 files stay readable and printable, and nothing is re-encoded behind the
user's back. Where a better mechanism replaces an existing chunk, both are present
during a transition period and readers prefer the newer one - but the older chunk is
not removed before v2.

**What every revision guarantees:**

- A file written by a conforming v1 encoder is readable by every conforming v1
  reader, including readers that implement none of its optional chunks.
- A field's meaning never changes silently. Redefining a value requires that field's
  sub-version or a container version bump.
- Each published revision records its class and its changes in the repository's
  release notes, so an implementation can audit itself against it.

A correction that changes what a conforming encoder writes is not an erratum: it waits
for the next minor or major revision.
