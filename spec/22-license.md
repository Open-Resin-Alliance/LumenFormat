# License and governance

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## License

```
MIT License

Copyright (c) 2026 Open Resin Alliance

Permission is hereby granted, free of charge, to any person obtaining a copy
of this specification and associated documentation files (the "Specification"),
to deal in the Specification without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Specification, and to permit persons to whom the
Specification is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Specification.

THE SPECIFICATION IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SPECIFICATION OR THE USE OR OTHER DEALINGS IN
THE SPECIFICATION.
```

## Format Governance

The Open Resin Alliance serves as the steward of the LUMEN format. This is an
ecosystem coordination role, not a legal restriction - the Specification is
licensed under MIT and may be freely implemented, extended, and forked.

To protect interoperability across implementations:

- The Alliance maintains the canonical version of this Specification.
- Vendor IDs for `EXTD` chunks are registered through the Alliance to prevent
  collisions between independent implementations. Vendor ID `0x0000` is
  reserved for extensions standardized as part of the core specification.
- Format version numbers are ratified by the Alliance to ensure a single,
  coherent version lineage.

These conventions are voluntary. Implementers who wish to interoperate
smoothly within the LUMEN ecosystem are encouraged to coordinate through the
Alliance, but they are under no legal obligation to do so.
