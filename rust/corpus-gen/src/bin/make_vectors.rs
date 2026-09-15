//! Regenerates the conformance corpus from the specification.
//!
//! Independent of both `lumen-format` and `lumen-corpus`, on purpose: this is a
//! second reading of the spec text, so the agreement between the files it writes
//! and the validator that reads them is evidence about the specification rather
//! than one implementation checking itself.

fn main() {
    std::process::exit(lumen_corpus_gen::vectors::run());
}
