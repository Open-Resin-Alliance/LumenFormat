# Versioning and compatibility

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 10. Versioning and Forward Compatibility

### 10.1 Version Numbers

| Level | Field | Description |
|-------|-------|-------------|
| File | `header.version` | Breaking changes to the binary container. |
| HEAD chunk | `head_version` | New fields added to HEAD; compatible across file versions. |
| META chunk | `meta_version` | Additive changes to the META JSON schema. `LROV` and `PROF.settings` carry META's field names and units. |
| LTBL chunk | `table_version` | Changes to the layer table's header or entry layout. |
| AUTH chunk | `auth_version` | Changes to encryption metadata layout. |
| LAYR chunk | `layr_version` | Changes to the chunk's container or frame layout. |
| ZDIC chunk | `zdic_version` | Changes to the dictionary chunk layout. |
| EXTD chunk | `ext_version` | Per-extension versioning. |

`header.version` is the container version, not the version of this document: LUMEN
v1.0 is carried by `header.version = 1`. A revision that changes the container
layout bumps `header.version`; one that only adds fields bumps that field's own
sub-version.

This revision rearranges the container - a sector's data and overrides have their own
chunks, and the layer table indexes the chunk directory directly - and still carries
`header.version = 1`, because v1.0 is a draft: a draft's layout is still being settled, and
the number moves when a revision that fixes the layout is published, not on every edit
before that ([§10.3](#103-change-control)).

### 10.2 Forward Compatibility Mechanisms

1. **Unknown chunk types:** Skip (chunk descriptor gives byte range). This covers chunk
   types this revision does not define, and chunks a reader has no use for. It does not
   cover a *defined* chunk whose handling changes what is printed: those are implemented, or
   the file is refused - `LROV` ([§4.5](08-print-control.md#45-lrov---layer-override-chunk)),
   and an unimplemented `critical` extension (item 6 below).
2. **Unknown chunk flags:** Ignore within known types.
3. **Unknown JSON keys:** Ignore in the JSON payloads this specification defines - META,
   `PROF` and `LROV`. An added key is how an additive change reaches a reader that predates it.
4. **New HEAD fields:** Parse the layout for the `head_version` present. An unrecognized
   `head_version` is rejected - forward striding is impossible when the new fields'
   widths are unknown.
5. **New LTBL fields:** Stride using `entry_size`.
6. **Unknown EXTD with `critical = 1`:** Refuse file.
7. **Unknown EXTD with `critical = 0`:** Skip.

### 10.3 Change Control

A published revision is a contract: a file that conforms to it must keep working, and its
text does not change. Every change ships as a new revision, and the kind of change decides
which number moves.

| Class | What it covers | Ships as |
|-------|----------------|----------|
| **Correction** | Text that contradicts another part; a wrong offset, length or unit; an undefined term; an ambiguity that two conforming implementations could read two ways. It MUST NOT change what a conforming encoder writes for an input the specification already determined. | a patch revision, `v1.0.1` |
| **Additive** | A new optional chunk type, JSON key, reserved code, extension type, or validation check a conforming reader may skip. | a minor revision, `v1.1`; that field's own sub-version where it has one, and `header.version` unchanged |
| **Breaking** | A different layout for an existing field, a changed meaning for an existing value, a removed chunk or field, or different constants for an algorithm this document specifies. | a major revision, `v2.0`, with `header.version = 2` |

**A revision is a draft until the repository declares it published, and a draft may be
revised in place** - that is what the declaration is for. Once published it is immutable:
the text of `v1.0` is the text of `v1.0` for good, and any change to it, including a
correction, is a new revision with its own number. An implementation can therefore name the
revision it was written against and be understood, which is the whole point of the number.

A correction that resolves an ambiguity with no single reading names the reading that is now
correct, and a file produced under another reading is not a conforming file for that
revision. The encryption constants in
[§4.4.1](07-chunk-auth.md#441-password-section) were pinned this way, while this document was
still a draft.

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
- Each published revision records its class and its changes in the repository's release
  notes, so an implementation can audit itself against it.
- A published revision's text never changes. Corrections reach it as a new revision, which
  an implementation can see and choose to adopt.

A change that alters what a conforming encoder writes is not a correction: it is additive or
breaking, and it takes the number that says so.

**Checks are part of the contract.** The list in [§11](17-validation.md#11-reader-validation-requirements)
is what a validator enforces, so a revision that adds one can turn a file that used to pass
into a file that fails. While a revision is a draft that is a correction like any other. Once
it is published, the class depends on what the old text said: a check for a rule the text
already stated is a correction, because the file was never conforming to begin with; a check
for a rule the text left open - a value it never bounded, a field it never constrained - is
breaking, because the files written under the old text conformed to it as it was, and a
printer that starts refusing them has stopped printing the same file.
