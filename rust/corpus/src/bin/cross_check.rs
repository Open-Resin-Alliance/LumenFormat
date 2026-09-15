//! Validates files another implementation wrote with the specification's own
//! reader - the direction a crate's own tests cannot check: another
//! implementation reading *our* bytes.
//!
//! `verify_vectors` is the corpus' independent validator. This points it at the
//! files `lumen-format`'s `make_test_file` example writes, so the agreement
//! between the two implementations is checked in the direction that a crate's
//! own tests cannot check.
//!
//! The encrypted sample is read with the credentials taken out of the file's
//! own AUTH chunk, which is also a check that the encoder put the Argon2id salt
//! and cost parameters where a reader looks for them.
//!
//!     cargo run --release -p lumen-corpus --bin cross_check -- <dir>

use std::path::Path;
use std::process::ExitCode;

use lumen_corpus::bytes::{at, hex, u32_at, u64_at};
use lumen_corpus::crypto::{Argon2Cost, CryptoBlock};
use lumen_corpus::{crc32c_self_test, reportln, validate};

/// The AUTH chunk's stored bytes, read straight out of the directory.
fn auth_payload(raw: &[u8]) -> Option<&[u8]> {
    let dir_offset = u64_at(raw, 8)?;
    let chunk_count = u32_at(raw, 16)?;
    for index in 0..chunk_count as usize {
        let base = dir_offset as usize + index * 32;
        if at(raw, base as u128, 4) != b"AUTH" {
            continue;
        }
        let offset = u64_at(raw, base + 4)?;
        let uncompressed = u64_at(raw, base + 12)?;
        let stored = u64_at(raw, base + 20)?;
        let length = if stored != 0 { stored } else { uncompressed };
        return Some(at(raw, offset as u128, length as u128));
    }
    None
}

/// The credentials `validate` wants for a password-mode file, taken from the
/// file itself.
///
/// The salt and the Argon2id cost parameters are whatever the encoder drew, so
/// reading them back is also a check that it wrote them where a reader looks.
fn password_credentials(path: &Path, password: &str) -> Result<CryptoBlock, String> {
    let raw = std::fs::read(path).map_err(|error| error.to_string())?;
    let auth = auth_payload(&raw).ok_or_else(|| "no AUTH chunk".to_string())?;
    let (Some(salt), Some(iterations), Some(memory_kib), Some(&parallelism)) = (
        auth.get(20..36),
        u32_at(auth, 36),
        u32_at(auth, 40),
        auth.get(44),
    ) else {
        return Err("the AUTH chunk is too short for a password section".to_string());
    };
    Ok(CryptoBlock {
        password_utf8: Some(password.to_string()),
        argon2: Some(Argon2Cost {
            salt: hex(salt),
            iterations,
            memory_kib,
            parallelism: u32::from(parallelism),
        }),
        local_recipient_private_key: None,
    })
}

fn main() -> ExitCode {
    let directory = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target".to_string());
    let cases = [
        ("sample.lumen", None),
        // No LHAS: §4.11 makes it optional and §10.3 forbids requiring an
        // optional mechanism, so the reference reader must accept it.
        ("sample-no-lhas.lumen", None),
        ("sample-encrypted.lumen", Some("lumen-example")),
        // Two sectors with per-layer settings: the sector rules, the partition
        // invariant and the `LROV` deltas, read back by the independent validator.
        ("sample-multi-sector.lumen", None),
    ];

    if !crc32c_self_test() {
        reportln!("FATAL: the reference validator's CRC-32C self-test failed");
        return ExitCode::from(2);
    }

    let mut failed = false;
    for (name, password) in cases {
        let path = Path::new(&directory).join(name);
        if !path.exists() {
            reportln!(
                "MISSING {} - generate it with the make_test_file example",
                path.display()
            );
            failed = true;
            continue;
        }
        let crypto = match password {
            Some(password) => match password_credentials(&path, password) {
                Ok(crypto) => Some(crypto),
                Err(error) => {
                    eprintln!("{}: {error}", path.display());
                    return ExitCode::from(1);
                }
            },
            None => None,
        };
        let checks = match validate(&path, true, crypto.as_ref()) {
            Ok(checks) => checks,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                return ExitCode::from(1);
            }
        };

        let failures = checks.failed();
        print!(
            "{:<7} {:<32} {:>3} checks",
            if failures.is_empty() { "ok" } else { "FAILED" },
            name,
            checks.len()
        );
        if !failures.is_empty() {
            print!("  {}", failures.join(", "));
        }
        reportln!();
        if !failures.is_empty() {
            failed = true;
        }
        if !checks.completed() {
            reportln!("        the validator stopped early; the run is not conclusive");
            failed = true;
        }
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
