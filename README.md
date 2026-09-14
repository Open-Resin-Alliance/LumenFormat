# LumenFormat

Specification for the LUMEN print file format (`.lumen`), by the Open Resin Alliance.
Written and maintained by Paul Skapczyk.

- **[spec/01-overview.md](spec/01-overview.md)** — start here. The specification is
  published in parts under [`spec/`](spec/), in reading order; section numbers
  (`§3.1`) are stable anchors across them.
- **[test-vectors/](test-vectors/)** — byte-exact conformance vectors and an
  independent validator
- **[rust/lumen/](rust/lumen/)** — the reference encoder, decoder and validator in
  Rust, for anything that reads or writes `.lumen` without re-deriving the format
  from this document
- **[LICENSE](LICENSE)** — MIT

Rendered: <https://openresin.org/specs/lumen>

Status: **LUMEN v1.0**, published 2026-09-12. Corrections and discussion are welcome
as GitHub issues. A revision is a draft until `status.json` says otherwise, and a draft may be revised in
place. Once published it is immutable: the specification's change-control policy (§10.3)
ships every later change as a new revision - a correction as `1.0.1`, an addition as `1.1`,
and anything that changes what a conforming encoder writes as `2.0` - so an implementation
can name the revision it was written against and be understood.

`status.json` is the machine-readable answer to "which revision is this, and is it
finished": `version` and `status` (`draft` or `published`) describe the working tree, and
`stable` names the git ref of the published revision once there is one, and a published
ref is not moved: the tag is where that revision's text lives, so editing the working tree
afterwards cannot change what is published. The website reads
this file, so the published specification it shows is the one this repository declares -
a draft in progress is not published by being pushed. Keep it current with the
specification.
