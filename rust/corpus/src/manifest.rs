//! The corpus manifest, and the comparison against its golden values.
//!
//! `validate` answers "is this a conforming file"; this answers the different
//! question "are these the committed bytes" - the file size, the digest, the
//! layout the generator recorded, the per-layer hashes, and the plaintext of
//! the optional content chunks. Both are needed: a validator that agreed with
//! itself about a vector that was never regenerated would still be useless as
//! evidence.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bytes::{at, hex, le, u32_at, u64_at};
use crate::crypto::CryptoBlock;
use crate::reader::Payload;
use crate::reportln;
use crate::timing::{self, Resolved, TimingInputs};

/// `manifest.json`, as the generator writes it.
#[derive(Deserialize)]
pub struct Manifest {
    pub valid: Vec<Valid>,
    pub invalid: Vec<Invalid>,
}

/// One valid vector's recorded layout.
#[derive(Deserialize)]
pub struct Valid {
    pub name: String,
    pub file: String,
    pub file_size: u64,
    pub file_sha256: String,
    pub chunk_count: u32,
    pub dir_offset: u64,
    pub header_flags: u32,
    pub total_uncompressed_size: u64,
    pub trailer_crc32c: String,
    pub blocks: Vec<BlockRecord>,
    pub layers: Vec<LayerRecord>,
    pub merkle_root: String,
    #[serde(default)]
    pub crypto: Option<CryptoBlock>,
    /// The plaintext digest of each optional content chunk, keyed by type tag
    /// (§11.6). A list where the chunk may appear more than once.
    #[serde(default)]
    pub chunk_payload_sha256: Option<BTreeMap<String, Pin>>,
    /// The §8 pipeline's values at a sample of `(layer, sector)` points, which a
    /// conforming reader must resolve for them. Every valid vector carries the
    /// expectations, so a reader can check its own reading of §8 against the
    /// committed corpus rather than against itself.
    #[serde(default)]
    pub resolved_timing: Option<Vec<Value>>,
}

/// One invalid vector's claim about itself.
#[derive(Deserialize)]
pub struct Invalid {
    pub name: String,
    pub file: String,
    /// The check this vector must fail, and fail first.
    pub expected_failure: String,
    /// The defect is one a loose reader is entitled to accept (an encoding
    /// that is not canonical, not one that is wrong).
    #[serde(default)]
    pub strict_only: bool,
    #[serde(default)]
    pub crypto: Option<CryptoBlock>,
}

#[derive(Deserialize)]
pub struct BlockRecord {
    pub frame_offset: u64,
    pub frame_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Deserialize)]
pub struct LayerRecord {
    pub block_index: u32,
    pub data_size: u32,
    pub sector_count: u32,
    pub lhas_leaf: String,
}

/// A recorded digest: one payload, or one per instance of a repeated chunk.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum Pin {
    One(String),
    Many(Vec<String>),
}

/// Compare a valid vector, and its reader's parse, against the manifest's golden
/// values.
///
/// `payloads` carries the plaintext of each optional content chunk as the
/// reader decoded it, keyed by type tag, so the recorded
/// `chunk_payload_sha256` pins can be compared without re-deriving the session
/// key here. A payload the reader did not produce has no pin to check.
///
/// `timing` carries the `META`, `SECT` and `LROV` objects the same run parsed,
/// so the recorded `resolved_timing` is recomputed from §8 rather than re-read
/// here.
pub fn check_manifest(
    valid: &Valid,
    path: &Path,
    payloads: &BTreeMap<[u8; 4], Payload>,
    timing: Option<&TimingInputs>,
) -> Comparison {
    let mut failures = Vec::new();
    check_golden_values(valid, path, payloads, &mut failures);
    let timing = check_resolved_timing(valid, timing, &mut failures);
    Comparison { failures, timing }
}

/// The byte-level comparison: the recorded size, digest, layout, block table,
/// per-layer hashes, Merkle root and chunk pins, read back out of the committed
/// file.
///
/// It stops at the first structural escape - a file that is not a container has
/// no layout to compare - and reports what it found in `bad`.
fn check_golden_values(
    valid: &Valid,
    path: &Path,
    payloads: &BTreeMap<[u8; 4], Payload>,
    bad: &mut Vec<String>,
) {
    let Ok(raw) = std::fs::read(path) else {
        // The caller validated this file first, so an unreadable one is
        // already reported there.
        return;
    };

    if raw.len() as u64 != valid.file_size {
        bad.push("manifest.file_size".to_string());
    }
    if hex(&Sha256::digest(&raw)) != valid.file_sha256 {
        bad.push("manifest.file_sha256".to_string());
    }

    // Everything below reads the container structurally. A file that is not a
    // container cannot be compared against a recorded layout - and a corpus
    // whose directory no longer holds the chunks the manifest describes is a
    // broken corpus, which is what `manifest.layout` says.
    let (Some(dir_offset), Some(chunk_count)) = (u64_at(&raw, 8), u32_at(&raw, 16)) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if dir_offset != valid.dir_offset || chunk_count != valid.chunk_count {
        bad.push("manifest.directory".to_string());
    }
    let Some(total_uncompressed) = u64_at(&raw, 24) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if total_uncompressed != valid.total_uncompressed_size {
        bad.push("manifest.total_uncompressed_size".to_string());
    }
    let Some(header_flags) = u32_at(&raw, 20) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if header_flags != valid.header_flags {
        bad.push("manifest.header_flags".to_string());
    }
    let Some(trailer_crc) = raw.len().checked_sub(4).and_then(|off| u32_at(&raw, off)) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if format!("0x{trailer_crc:08X}") != valid.trailer_crc32c {
        bad.push("manifest.trailer_crc32c".to_string());
    }

    // The recorded chunk offsets, by type. Python's dict comprehension keeps
    // the last record for a repeated type; so does this.
    let mut offsets: HashMap<[u8; 4], u64> = HashMap::new();
    for index in 0..chunk_count as usize {
        let Some(base) = index
            .checked_mul(32)
            .and_then(|offset| offset.checked_add(dir_offset as usize))
        else {
            bad.push("manifest.layout".to_string());
            return;
        };
        // The fixed 32-byte record, read whole: a directory that stops inside
        // a record is a corpus the manifest does not describe.
        let Some(record) = le::<32>(&raw, base) else {
            bad.push("manifest.layout".to_string());
            return;
        };
        let ctype: [u8; 4] = record[..4].try_into().expect("a type tag is four bytes");
        offsets.insert(
            ctype,
            u64::from_le_bytes(record[4..12].try_into().expect("u64")),
        );
    }

    let Some(&layr_offset) = offsets.get(b"LAYR") else {
        bad.push("manifest.layout".to_string());
        return;
    };
    let (Some(_version), Some(block_count), Some(table_entry)) = (
        u32_at(&raw, layr_offset as usize),
        u32_at(&raw, layr_offset as usize + 4),
        u32_at(&raw, layr_offset as usize + 8),
    ) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if block_count as usize != valid.blocks.len() {
        bad.push("manifest.block_count".to_string());
    } else {
        for (index, block) in valid.blocks.iter().enumerate() {
            let Some(offset) = (index)
                .checked_mul(table_entry as usize)
                .and_then(|row| row.checked_add(12))
                .and_then(|row| row.checked_add(layr_offset as usize))
            else {
                bad.push("manifest.layout".to_string());
                return;
            };
            let (Some(frame_offset), Some(frame_size), Some(uncompressed_size)) = (
                u64_at(&raw, offset),
                u64_at(&raw, offset + 8),
                u64_at(&raw, offset + 16),
            ) else {
                bad.push("manifest.layout".to_string());
                return;
            };
            let recorded = (
                block.frame_offset,
                block.frame_size,
                block.uncompressed_size,
            );
            if (frame_offset, frame_size, uncompressed_size) != recorded {
                bad.push(format!("manifest.block[{index}]"));
                break;
            }
        }
    }

    let Some(&lhas_offset) = offsets.get(b"LHAS") else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if hex(at(&raw, lhas_offset as u128 + 6, 32)) != valid.merkle_root {
        bad.push("manifest.merkle_root".to_string());
    }

    let Some(&ltbl_offset) = offsets.get(b"LTBL") else {
        bad.push("manifest.layout".to_string());
        return;
    };
    let (Some(_table_version), Some(_layer_count), Some(entry_size)) = (
        u32_at(&raw, ltbl_offset as usize),
        u32_at(&raw, ltbl_offset as usize + 4),
        u32_at(&raw, ltbl_offset as usize + 8),
    ) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    for (index, layer) in valid.layers.iter().enumerate() {
        let Some(offset) = (index)
            .checked_mul(entry_size as usize)
            .and_then(|row| row.checked_add(12))
            .and_then(|row| row.checked_add(ltbl_offset as usize))
        else {
            bad.push("manifest.layout".to_string());
            return;
        };
        let (Some(_data_offset), Some(block_index), Some(data_size), Some(sector_count)) = (
            u64_at(&raw, offset),
            u32_at(&raw, offset + 8),
            u32_at(&raw, offset + 12),
            u32_at(&raw, offset + 16),
        ) else {
            bad.push("manifest.layout".to_string());
            return;
        };
        let recorded = (layer.block_index, layer.data_size, layer.sector_count);
        if (block_index, data_size, sector_count) != recorded {
            bad.push(format!("manifest.layer[{index}]"));
            break;
        }
        let leaf = hex(at(&raw, lhas_offset as u128 + 38 + 32 * index as u128, 32));
        if leaf != layer.lhas_leaf {
            bad.push(format!("manifest.layer[{index}].lhas_leaf"));
            break;
        }
    }

    for (ctype, want) in valid.chunk_payload_sha256.iter().flatten() {
        let Ok(key) = <[u8; 4]>::try_from(ctype.as_bytes()) else {
            continue;
        };
        let Some(got) = payloads.get(&key) else {
            continue;
        };
        if pin_mismatch(want, got) {
            bad.push("manifest.chunk_payload_sha256".to_string());
            break;
        }
    }
}

/// `manifest.json`'s expectations for one valid vector, compared.
pub struct Comparison {
    /// The checks that failed, named the way the report names them:
    /// `manifest.file_size`, `manifest.layer[3].lhas_leaf`,
    /// `manifest.resolved_timing[3,0].exposure_ms`.
    pub failures: Vec<String>,
    /// What §8's pipeline, recomputed for the vector, found.
    pub timing: Timing,
}

/// What the §8 comparison found for one vector.
///
/// The manifest's other checks are byte-level pins with nothing to say when they
/// match; this one covers a sample of points, so a vector that passes reports
/// how many points it covered - which is what tells a run that resolved them
/// from one that never looked.
pub struct Timing {
    points: Option<usize>,
    failure: Option<String>,
}

impl Timing {
    /// Whether the vector recorded the expectations and every point in them was
    /// recomputed and agreed.
    pub fn ok(&self) -> bool {
        self.points.is_some() && self.failure.is_none()
    }

    /// How many recorded points were recomputed, or `None` when the vector
    /// records none.
    pub fn points(&self) -> Option<usize> {
        self.points
    }

    /// Print the check the way the reader prints its own, so the report carries
    /// the recomputation for every vector rather than only a failure when one
    /// occurs.
    pub fn print_verbose(&self) {
        print!(
            "      {:<32} {}",
            "manifest.resolved_timing",
            if self.ok() { "PASS" } else { "FAIL" }
        );
        match (self.points, &self.failure) {
            (Some(points), None) => print!("  {points} points"),
            (Some(points), Some(failure)) => print!("  {points} points, first: {failure}"),
            (None, Some(failure)) => print!("  {failure}"),
            (None, None) => {}
        }
        reportln!();
    }
}

/// Recompute §8's pipeline for every point the manifest records, and compare.
///
/// A valid vector with no expectations fails rather than passes: the corpus
/// claims any implementation can check its reading of §8 against these numbers,
/// and it can only do that for the vectors that carry them. A recorded point the
/// rule does not call for, or a required point the manifest does not record, is
/// a failure too - a sample that silently shrank pins less than the corpus says
/// it does. The first field of a point that disagrees is the one reported - a
/// systematic disagreement would otherwise report every field of every point -
/// and the verdict keeps that first disagreement's values, which is what a
/// reader of the report needs to see the two readings side by side.
fn check_resolved_timing(
    valid: &Valid,
    timing: Option<&TimingInputs>,
    bad: &mut Vec<String>,
) -> Timing {
    let Some(points) = valid.resolved_timing.as_ref() else {
        return uncompared("the vector records no expectations", bad);
    };
    // The sampling rule always yields at least `(0, 0)`, so a list with no
    // points gives a third-party implementation nothing to agree with, which is
    // the failure this check exists to catch.
    if points.is_empty() {
        return uncompared("the vector records no points", bad);
    }
    let Some(inputs) = timing else {
        return uncompared("the reader parsed no META to resolve from", bad);
    };

    let fields = Resolved::keys();
    let mut verdict = Timing {
        points: Some(points.len()),
        failure: None,
    };
    let mut recorded_points: BTreeSet<(u32, u32)> = BTreeSet::new();
    let mut previous: Option<(u32, u32)> = None;
    for (index, point) in points.iter().enumerate() {
        let Some((layer, sector, recorded)) = recorded_point(point) else {
            bad.push(format!("manifest.resolved_timing[{index}]"));
            if verdict.failure.is_none() {
                verdict.failure = Some(format!(
                    "point {index} is not an object with a layer and a sector"
                ));
            }
            continue;
        };

        // The sample is deduplicated and sorted by `(layer, sector)`.
        let coordinate = (layer, sector);
        if previous.is_some_and(|previous| previous >= coordinate) {
            bad.push(format!("manifest.resolved_timing[{index}]"));
            if verdict.failure.is_none() {
                verdict.failure = Some(format!(
                    "point {index} ({layer},{sector}) repeats or is out of order"
                ));
            }
        }
        previous = Some(coordinate);
        recorded_points.insert(coordinate);

        let resolved = timing::resolve(inputs, layer, sector);
        let mut problem = None;
        for field in fields {
            // `keys` names every field `resolve` fills, so this is present.
            let want = resolved.get(field).expect("a resolved field");
            match recorded.get(field).and_then(Value::as_i64) {
                None => {
                    problem = Some((field, format!("not an integer, resolved {want}")));
                    break;
                }
                Some(got) if got != want => {
                    problem = Some((field, format!("manifest {got}, resolved {want}")));
                    break;
                }
                Some(_) => {}
            }
        }
        // A key §8 does not resolve is drift too, and a key the comparison
        // silently ignored is exactly what the point list is meant to catch. The
        // point's own coordinates are not resolved values.
        if problem.is_none() {
            problem = recorded
                .keys()
                .find(|key| key.as_str() != "layer" && key.as_str() != "sector")
                .filter(|key| !fields.contains(&key.as_str()))
                .map(|key| (key.as_str(), "not a field §8 resolves".to_string()));
        }
        if let Some((field, why)) = problem {
            let at = format!("[{layer},{sector}].{field}");
            bad.push(format!("manifest.resolved_timing{at}"));
            if verdict.failure.is_none() {
                verdict.failure = Some(format!("{at}: {why}"));
            }
        }
    }

    // The sample itself, recomputed from the file: every point the corpus claims
    // to pin has to be there, and a point the rule does not call for is a
    // different claim than the one the manifest makes.
    let required = timing::sampled_points(inputs);
    for (layer, sector) in required.difference(&recorded_points) {
        bad.push(format!(
            "manifest.resolved_timing[{layer},{sector}].missing"
        ));
        if verdict.failure.is_none() {
            verdict.failure = Some(format!(
                "[{layer},{sector}]: the sample the rule requires is not recorded"
            ));
        }
    }
    for (layer, sector) in recorded_points.difference(&required) {
        bad.push(format!(
            "manifest.resolved_timing[{layer},{sector}].unexpected"
        ));
        if verdict.failure.is_none() {
            verdict.failure = Some(format!(
                "[{layer},{sector}]: the sampling rule does not call for this point"
            ));
        }
    }
    verdict
}

/// The verdict for a vector whose expectations could not be compared at all: the
/// check named in the report, and why.
fn uncompared(failure: &str, bad: &mut Vec<String>) -> Timing {
    bad.push("manifest.resolved_timing".to_string());
    Timing {
        points: None,
        failure: Some(failure.to_string()),
    }
}

/// A recorded point's coordinates and its fields, when it carries both as whole
/// numbers.
fn recorded_point(point: &Value) -> Option<(u32, u32, &serde_json::Map<String, Value>)> {
    let recorded = point.as_object()?;
    let layer = u32::try_from(recorded.get("layer")?.as_i64()?).ok()?;
    let sector = u32::try_from(recorded.get("sector")?.as_i64()?).ok()?;
    Some((layer, sector, recorded))
}

fn pin_mismatch(want: &Pin, got: &Payload) -> bool {
    match (want, got) {
        (Pin::Many(want), Payload::Many(got)) => {
            let actual: Vec<String> = got.iter().map(|b| hex(&Sha256::digest(b))).collect();
            actual != *want
        }
        // A single payload where the manifest records a list is no list at all,
        // and an empty list is satisfied by anything.
        (Pin::Many(want), Payload::One(_)) => !want.is_empty(),
        (Pin::One(want), Payload::One(got)) => hex(&Sha256::digest(got)) != *want,
        (Pin::One(_), Payload::Many(_)) => true,
    }
}
