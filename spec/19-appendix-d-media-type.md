# Media type registration

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## Appendix D: Media Type Registration

The media type has not been submitted to IANA. The registration below follows the
template of RFC 6838 §5.6 and is ready to submit; the name is free in the registry
(no `application/vnd.openresin.*` and no `*lumen` subtype is currently assigned).
Until it is submitted, implementations SHOULD use the type as specified here.

Registration in the vendor tree costs nothing, and the Alliance is squarely
eligible: RFC 6838 §3.2 states that "industry consortia as well as non-commercial
entities that do not qualify as recognized standards-related organizations can
quite appropriately register media types in the vendor tree". The procedure is
**Expert Review**: a media types reviewer appointed by the IETF Applications Area
Director checks the submission against RFC 6838 and returns anything that does not
conform for revision. Publication as an RFC is explicitly *not* required for
vendor-tree registrations (RFC 6838 §4.10), and a provisional registration is not available
either - that process exists only for the standards tree (RFC 6838 §5.2.1). Posting the
template to the `media-types@iana.org` list for comment before submitting is
strongly encouraged (RFC 6838 §5.2).

**Type name:** `application`

**Subtype name:** `vnd.openresin.lumen`

**Required parameters:** none

**Optional parameters:** none

**Encoding considerations:** binary. A `.lumen` file is a little-endian binary
container, not text, and MUST NOT be carried through a text-only channel without
a content-transfer-encoding such as base64.

**Security considerations:** see [§9](12-encryption.md#9-encryption-model). Files are plaintext by default; the optional
authenticated encryption provides confidentiality and per-chunk integrity but
**not** authenticity ([§9.1](12-encryption.md#91-design-principles)). Readers must bound all work performed on untrusted
input - Argon2id parameters, chunk uncompressed sizes and block decompressed sizes
are attacker-controlled and must be checked before allocation ([§11.3](14-validation.md#113-layer-data-validation-post-decompression), [§11.4](14-validation.md#114-encryption-validation)). As
with any print file, file-derived paths and metadata should be treated as
untrusted.

**Interoperability considerations:** format detection is reliable from content
alone - the four ASCII bytes `LUMN` (`0x4C 0x55 0x4D 0x4E`) at offset 0 - so the
file extension is not needed to identify a file. Forward-compatibility rules are
in [§10](13-versioning.md#10-versioning-and-forward-compatibility): unknown chunk types and unknown JSON keys are skipped, while an unknown
`EXTD` chunk with `critical = 1` MUST cause the file to be refused. Reader
behaviour is specified in [§11](14-validation.md#11-reader-validation-requirements) and exercised by the conformance corpus in
`test-vectors/` ([§11.6](14-validation.md#116-conformance-corpus)).

**Published specification:** `https://openresin.org/specs/lumen`, which renders this
specification in parts (source: the `spec/` directory of
`https://github.com/Open-Resin-Alliance/LumenFormat`). RFC 6838 does not require a
vendor-tree registration to be published as an RFC, but the reviewer has to be able to
read the specification, so that URL MUST resolve publicly before submitting. The
registration template is MIT-licensed (see *License*), which satisfies the requirement
in RFC 6838 §4.10 that the copyright on the template allow IANA to copy it into the
registry.

**Applications that use this media type:** DragonFruit (encoder); Odyssey
firmware, via the Orion frontend (decoder).

**Fragment identifier considerations:** none.

**Additional information:**

- Deprecated alias names for this type: `N/A`. The placeholder
  `application/x-lumen` was never emitted by a released implementation, so no alias
  is carried.
- Magic number(s): `0x4C 0x55 0x4D 0x4E` (`LUMN`), four octets at offset 0.
- File extension(s): `.lumen`
- Macintosh file type code(s): `N/A`
- Uniform Type Identifier: `org.openresin.lumen` (declared here; not yet registered
  with Apple)

These five names are the ones RFC 6838 §5.6 uses, which also requires fields that
do not apply to read `N/A` exactly - not `none`, or any other word that could be
mistaken for a response.

**Person & email address to contact for further information:** Paul Skapczyk,
`paul@openresin.org`.

**Intended usage:** COMMON

**Restrictions on usage:** `N/A`

**Author:** Open Resin Alliance

**Change controller:** Open Resin Alliance

**Provisional registration?** (standards tree only): `N/A` - provisional
registrations exist only in the standards tree (RFC 6838 §5.2.1).

### D.1 Why `openresin` rather than the Alliance's initials

`application/vnd.openresin.*` is used instead of `application/vnd.ora.*` because
the latter sits one character away from the registered
`application/vnd.oracle.*` vendor in a flat namespace, which invites collisions in
search results, tooling and human memory. `openresin` matches the Alliance's own
domain, `openresin.org`.

The standards tree (`application/lumen`, with no `vnd.` prefix) would require the
Alliance to be recognised as a standards body by IANA. The vendor tree is the
correct tree until that changes.

### D.2 Submission checklist

1. **Make the specification reachable.** The repository is private today. Either
   make `Open-Resin-Alliance/LumenFormat` public, or publish the document at a
   stable URL such as `openresin.org/specs/lumen`. Note that the website currently
   carries only a `blog` collection, so a specifications section would be new work.
2. **Submit** by pasting this appendix into
   `https://www.iana.org/form/media-types`, or by emailing it to `iana@iana.org`.
3. **Optional pre-review.** Post the template to `media-types@iana.org` first
   ([§5.2](08-layer-encoding.md#52-varint-encoding)); comments there are cheaper than a returned submission.
4. **Expect one revision round.** The reviewer returns submissions that do not meet
   RFC 6838's requirements. The two easiest fields to get wrong are the contact
   address and a reachable specification, and a name that does not match the
   specification it is registered against.
