# LumenFormat

Specification for the LUMEN print file format (`.lumen`), by the Open Resin Alliance.
Written and maintained by Paul Skapczyk.

- **[spec/01-overview.md](spec/01-overview.md)** — start here. The specification is
  published in parts under [`spec/`](spec/), in reading order; section numbers
  (`§3.1`) are stable anchors across them.
- **[test-vectors/](test-vectors/)** — byte-exact conformance vectors and an
  independent validator
- **[LICENSE](LICENSE)** — MIT

Rendered: <https://openresin.org/specs/lumen>

Status: **LUMEN v1.0**, published 2026-09-12. Corrections and discussion are welcome
as GitHub issues. Once the revision is published, changes follow the change-control policy in the
specification (§10.3): an erratum may correct a published revision in place, additive
changes ship as a minor revision, and anything that changes what a conforming encoder
writes waits for the next major revision. While `status.json` says `draft`, the revision
is still being worked on and that policy does not bind it yet.

`status.json` is the machine-readable answer to "which revision is this, and is it
finished": `version` and `status` (`draft` or `published`) describe the working tree, and
`stable` names the git ref of the published revision once there is one. The website reads
this file, so the published specification it shows is the one this repository declares -
a draft in progress is not published by being pushed. Keep it current with the
specification.
