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
use crate::decompress::{frame_content_size, frame_dict_id};
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
    /// One record per `LAYR` chunk, in directory order (§4.10).
    pub layr_chunks: Vec<LayrChunkRecord>,
    /// One record per `LTBL` entry, in table order (§4.8).
    pub ltbl: Vec<LtblRecord>,
    /// One record per layer, in layer order (§4.11).
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

/// One `LAYR` chunk as the manifest records it (§4.10).
///
/// There is no block table any more, so this record *is* the chunk: the frame's
/// header, the descriptor's sizes, and the `(sector, layer group)` the chunk
/// holds - which only `LTBL` can say, and which is checked against it.
#[derive(Deserialize)]
pub struct LayrChunkRecord {
    /// Directory index.
    pub index: u32,
    pub sector_id: u32,
    pub first_layer: u32,
    pub layer_count: u32,
    pub version: u32,
    /// The frame header's dictionary ID; `0` when the frame uses none.
    pub dict_id: u32,
    /// The decompressed length the frame header declares.
    pub content_size: u64,
    /// The stored frame's byte length, without the 4-byte version field.
    pub frame_size: u64,
    /// The descriptor's `size_uncompressed`: `4 + frame_size`.
    pub stored_len: u64,
    /// Whether the frame is sealed - the descriptor's `size_compressed != 0`.
    pub sealed: bool,
}

/// One `LTBL` record as the manifest records it (§4.8), in table order.
#[derive(Deserialize)]
pub struct LtblRecord {
    pub entry_index: u32,
    /// The layer the record belongs to, which the table expresses by grouping
    /// rather than by a field.
    pub layer: u32,
    pub sector_id: u32,
    pub data_size: u32,
    pub first_lrov: u32,
    pub first_layr: u32,
    pub additional_sector_count: u32,
    pub data_offset: u64,
}

/// One layer as the manifest records it (§4.11).
#[derive(Deserialize)]
pub struct LayerRecord {
    pub index: u32,
    /// Every one of the layer's slices is empty, so the layer holds nothing.
    pub empty: bool,
    pub sector_count: u32,
    /// Sector 0's encoding tag - the first byte of its data - or `null` when it
    /// carries no data.
    #[serde(default)]
    pub tag: Option<u8>,
    /// Each sector's tag, in table order, `null` for a sector with no data.
    #[serde(default)]
    pub sector_tags: Vec<Option<u8>>,
    pub decompressed_sha256: String,
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
/// `layers` carries each layer's decompressed data - its sectors' slices
/// concatenated in ascending `sector_id` - as the reader decoded it, which is
/// what the recorded tags and per-layer digests describe.
///
/// `timing` carries the `META` and `LROV` objects the same run parsed, so the
/// recorded `resolved_timing` is recomputed from §8 rather than re-read here.
pub fn check_manifest(
    valid: &Valid,
    path: &Path,
    payloads: &BTreeMap<[u8; 4], Payload>,
    layers: &[Vec<u8>],
    timing: Option<&TimingInputs>,
) -> Comparison {
    let mut failures = Vec::new();
    check_golden_values(valid, path, payloads, layers, &mut failures);
    let timing = check_resolved_timing(valid, timing, &mut failures);
    Comparison { failures, timing }
}

/// The byte-level comparison: the recorded size, digest, layout, layer table,
/// frame headers, per-layer hashes, Merkle root and chunk pins, read back out of
/// the committed file.
///
/// It stops at the first structural escape - a file that is not a container has
/// no layout to compare - and reports what it found in `bad`.
fn check_golden_values(
    valid: &Valid,
    path: &Path,
    payloads: &BTreeMap<[u8; 4], Payload>,
    layers: &[Vec<u8>],
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

    // The recorded chunks, by directory index and by type. Python's dict
    // comprehension keeps the last record for a repeated type; so does this.
    let mut records: Vec<([u8; 4], u64, u64, u64)> = Vec::new();
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
        let offset = u64::from_le_bytes(record[4..12].try_into().expect("u64"));
        let usz = u64::from_le_bytes(record[12..20].try_into().expect("u64"));
        let csz = u64::from_le_bytes(record[20..28].try_into().expect("u64"));
        offsets.insert(ctype, offset);
        records.push((ctype, offset, usz, csz));
    }

    // ---- LAYR chunks ----------------------------------------------------
    // One chunk per (sector, layer group), and no block table: the descriptor
    // and the frame header are the whole record (§4.10). What the chunk *holds*
    // is not in the chunk at all - only `LTBL` says which points at it - so the
    // two records are checked against each other as well as against the bytes.
    let layr_chunk_count = records
        .iter()
        .filter(|(ctype, offset, _, _)| ctype == b"LAYR" && *offset != 0)
        .count();
    if layr_chunk_count != valid.layr_chunks.len() {
        bad.push("manifest.layr_chunks".to_string());
    }
    for chunk in &valid.layr_chunks {
        let Some((ctype, offset, usz, csz)) = records.get(chunk.index as usize) else {
            bad.push(format!("manifest.layr_chunk[{}]", chunk.index));
            break;
        };
        if ctype != b"LAYR" || *offset == 0 {
            bad.push(format!("manifest.layr_chunk[{}]", chunk.index));
            break;
        }
        // §3.2: a `LAYR` chunk's stored length is `size_compressed` when it is
        // sealed, and `size_uncompressed` when it is not.
        let stored_len = if *csz != 0 { *csz } else { *usz };
        let payload = at(&raw, u128::from(*offset), u128::from(stored_len));
        let frame = payload.get(4..).unwrap_or_default();
        let mut ok = u32_at(payload, 0) == Some(chunk.version)
            && stored_len == chunk.stored_len
            && chunk.frame_size + 4 == chunk.stored_len
            && chunk.sealed == (*csz != 0);
        // A sealed frame is AEAD-framed on disk, so its header is not readable
        // without the key - the reader's own `layr.*` checks cover those bytes.
        if ok && !chunk.sealed {
            ok = frame_dict_id(frame) == Some(chunk.dict_id)
                && frame_content_size(frame).flatten() == Some(chunk.content_size);
        }
        // What the chunk holds is not in the chunk: only the table says which
        // entries point at it, and a sector that is absent from a layer
        // contributes no bytes, so the layers it holds need not be every layer
        // of the span the encoder planned. What can be pinned from the file is
        // that the entries naming this chunk all belong to its sector and sit
        // inside that span.
        let pointing: Vec<&LtblRecord> = valid
            .ltbl
            .iter()
            .filter(|entry| entry.first_layr == chunk.index)
            .collect();
        // A chunk no entry names is legal: it is the empty frame a plan wrote
        // for a sector that has nothing on those layers, and `encrypted-both`
        // carries one.
        let span = chunk.first_layer..chunk.first_layer.saturating_add(chunk.layer_count);
        if pointing
            .iter()
            .any(|entry| entry.sector_id != chunk.sector_id || !span.contains(&entry.layer))
        {
            ok = false;
        }
        if !ok {
            bad.push(format!("manifest.layr_chunk[{}]", chunk.index));
            break;
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
    let (Some(_table_version), Some(layer_count), Some(entry_size), Some(entry_count)) = (
        u32_at(&raw, ltbl_offset as usize),
        u32_at(&raw, ltbl_offset as usize + 4),
        u32_at(&raw, ltbl_offset as usize + 8),
        u32_at(&raw, ltbl_offset as usize + 12),
    ) else {
        bad.push("manifest.layout".to_string());
        return;
    };
    if valid.ltbl.len() != entry_count as usize {
        bad.push("manifest.ltbl_entries".to_string());
    }
    for (index, entry) in valid.ltbl.iter().enumerate() {
        let Some(offset) = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(u64::from(entry_size)))
            .and_then(|row| row.checked_add(16))
            .and_then(|row| row.checked_add(ltbl_offset))
            .and_then(|row| usize::try_from(row).ok())
        else {
            bad.push("manifest.layout".to_string());
            return;
        };
        let (
            Some(data_size),
            Some(first_lrov),
            Some(first_layr),
            Some(additional),
            Some(data_offset),
            Some(sector_id),
        ) = (
            u32_at(&raw, offset),
            u32_at(&raw, offset + 4),
            u32_at(&raw, offset + 8),
            u32_at(&raw, offset + 12),
            u64_at(&raw, offset + 16),
            u32_at(&raw, offset + 24),
        )
        else {
            bad.push("manifest.layout".to_string());
            return;
        };
        if entry.entry_index as usize != index
            || entry.data_size != data_size
            || entry.first_lrov != first_lrov
            || entry.first_layr != first_layr
            || entry.additional_sector_count != additional
            || entry.data_offset != data_offset
            || entry.sector_id != sector_id
        {
            bad.push(format!("manifest.ltbl_entry[{index}]"));
            break;
        }
    }
    // The layer a record belongs to is the table's grouping rather than a
    // field, so the grouping has to hold: each layer's records are contiguous,
    // there are `1 + additional_sector_count` of them, and the first is sector
    // 0's.
    let grouping_holds = valid.ltbl.iter().enumerate().all(|(index, entry)| {
        match index.checked_sub(1).map(|previous| &valid.ltbl[previous]) {
            Some(previous) if previous.layer == entry.layer => entry.additional_sector_count == 0,
            _ => {
                let count = valid.ltbl[index..]
                    .iter()
                    .take_while(|later| later.layer == entry.layer)
                    .count() as u32;
                count == entry.additional_sector_count + 1 && entry.sector_id == 0
            }
        }
    });
    if !grouping_holds {
        bad.push("manifest.ltbl_layout".to_string());
    }

    // ---- layers ---------------------------------------------------------
    // Each layer's bytes are its sectors' slices concatenated in ascending
    // `sector_id`; the tags are the first byte of each slice, and a slice of no
    // bytes carries no tag (§4.11).
    if valid.layers.len() != layer_count as usize {
        bad.push("manifest.layers".to_string());
    }
    for (index, layer) in valid.layers.iter().enumerate() {
        let entries: Vec<&LtblRecord> = valid
            .ltbl
            .iter()
            .filter(|entry| entry.layer == index as u32)
            .collect();
        let mut tags: Vec<Option<u8>> = Vec::new();
        let data = layers.get(index);
        let mut offset = 0usize;
        for entry in &entries {
            let size = entry.data_size as usize;
            tags.push(
                data.and_then(|data| data.get(offset))
                    .copied()
                    .filter(|_| size != 0),
            );
            offset += size;
        }
        let ok = layer.index as usize == index
            && layer.sector_count as usize == entries.len()
            && layer.empty == entries.iter().all(|entry| entry.data_size == 0)
            && layer.sector_tags == tags
            && layer.tag == tags.first().copied().flatten()
            && data.is_some_and(|data| hex(&Sha256::digest(data)) == layer.decompressed_sha256);
        if !ok {
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
