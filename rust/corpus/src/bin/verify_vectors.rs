//! Validates the committed conformance corpus against its manifest.
//!
//! Four claims, and they are different claims: every valid vector passes every
//! check; every invalid vector fails the check its manifest entry names, and
//! fails *that* check first; the vectors marked `strict_only` pass a loose read
//! and fail a strict one; and the committed bytes still match the golden values
//! the manifest records.
//!
//! Exit codes are the corpus' own: 0 when the whole corpus behaved, 1 when a
//! vector did not, 3 when the run could not cover the corpus at all.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lumen_corpus::manifest::Manifest;
use lumen_corpus::{check_manifest, crc32c_self_test, reportln, validate};

/// The corpus ships with the specification, not with this crate.
fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn load_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    let mut verbose = false;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "-v" | "--verbose" => verbose = true,
            other => {
                eprintln!("unrecognised argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    if !crc32c_self_test() {
        reportln!("FATAL: CRC-32C self-test failed");
        return ExitCode::from(2);
    }

    let directory = vectors_dir();
    let manifest_path = directory.join("manifest.json");
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("{}: {error}", manifest_path.display());
            return ExitCode::from(1);
        }
    };

    let mut failures = 0usize;
    let mut incomplete = 0usize;

    reportln!("valid vectors");
    for vector in &manifest.valid {
        let path = directory.join(&vector.file);
        let checks = match validate(&path, true, vector.crypto.as_ref()) {
            Ok(checks) => checks,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                return ExitCode::from(1);
            }
        };
        if verbose {
            checks.print_verbose();
        }
        let mut bad: Vec<String> = checks
            .failed()
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        bad.extend(check_manifest(vector, &path, checks.payloads()));
        if !checks.completed() {
            incomplete += 1;
        }
        print!(
            "  {:<4} {:<24} {} checks",
            if bad.is_empty() { "PASS" } else { "FAIL" },
            vector.name,
            checks.len()
        );
        if !bad.is_empty() {
            print!("  -> {}", bad.join(", "));
        }
        reportln!();
        if !bad.is_empty() {
            failures += 1;
        }
    }

    reportln!("invalid vectors");
    for vector in &manifest.invalid {
        let path = directory.join(&vector.file);
        let checks = match validate(&path, true, vector.crypto.as_ref()) {
            Ok(checks) => checks,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                return ExitCode::from(1);
            }
        };
        if verbose {
            checks.print_verbose();
        }
        let loose = if vector.strict_only {
            match validate(&path, false, vector.crypto.as_ref()) {
                Ok(loose) => Some(loose),
                Err(error) => {
                    eprintln!("{}: {error}", path.display());
                    return ExitCode::from(1);
                }
            }
        } else {
            None
        };

        let expected = vector.expected_failure.as_str();
        let hit = checks.failed();
        let mut ok = hit.contains(&expected) && hit.first() == Some(&expected);
        let mut extra = String::new();
        if let Some(loose) = &loose {
            let accepted = loose.failed().is_empty();
            ok = ok && accepted;
            extra = format!(
                " (accepted in loose mode: {})",
                if accepted { "yes" } else { "NO" }
            );
        }
        if !checks.completed() {
            incomplete += 1;
        }
        reportln!(
            "  {:<4} {:<28} expects {:<28} got {}{}",
            if ok { "PASS" } else { "FAIL" },
            vector.name,
            expected,
            hit.first().copied().unwrap_or("(nothing failed)"),
            extra
        );
        if !ok {
            failures += 1;
        }
    }

    reportln!();
    if failures > 0 {
        reportln!("corpus: {failures} FAILURES");
    }
    if incomplete > 0 {
        reportln!("corpus: INCOMPLETE ({incomplete} vectors stopped before the last check)");
    }
    if failures == 0 && incomplete == 0 {
        reportln!("corpus: OK");
    }
    if failures > 0 {
        ExitCode::from(1)
    } else if incomplete > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}
