//! The corpus manifest, and the comparison against its golden values.
//!
//! `validate` answers "is this a conforming file"; this answers the different
//! question "are these the committed bytes" - the file size, the digest, the
//! layout the generator recorded, the per-layer hashes, and the plaintext of
//! the optional content chunks. Both are needed: a validator that agreed with
//! itself about a vector that was never regenerated would still be useless as
//! evidence.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::bytes::{at, hex, le, u32_at, u64_at};
use crate::crypto::CryptoBlock;
use crate::reader::Payload;

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

/// Compare the committed bytes against the recorded golden values.
///
/// `payloads` carries the plaintext of each optional content chunk as the
/// reader decoded it, keyed by type tag, so the recorded
/// `chunk_payload_sha256` pins can be compared without re-deriving the session
/// key here. A payload the reader did not produce has no pin to check.
pub fn check_manifest(
    valid: &Valid,
    path: &Path,
    payloads: &BTreeMap<[u8; 4], Payload>,
) -> Vec<String> {
    let mut bad = Vec::new();
    let Ok(raw) = std::fs::read(path) else {
        // The caller validated this file first, so an unreadable one is
        // already reported there.
        return bad;
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
        return bad;
    };
    if dir_offset != valid.dir_offset || chunk_count != valid.chunk_count {
        bad.push("manifest.directory".to_string());
    }
    let Some(total_uncompressed) = u64_at(&raw, 24) else {
        bad.push("manifest.layout".to_string());
        return bad;
    };
    if total_uncompressed != valid.total_uncompressed_size {
        bad.push("manifest.total_uncompressed_size".to_string());
    }
    let Some(header_flags) = u32_at(&raw, 20) else {
        bad.push("manifest.layout".to_string());
        return bad;
    };
    if header_flags != valid.header_flags {
        bad.push("manifest.header_flags".to_string());
    }
    let Some(trailer_crc) = raw.len().checked_sub(4).and_then(|off| u32_at(&raw, off)) else {
        bad.push("manifest.layout".to_string());
        return bad;
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
            return bad;
        };
        // The fixed 32-byte record, read whole: a directory that stops inside
        // a record is a corpus the manifest does not describe.
        let Some(record) = le::<32>(&raw, base) else {
            bad.push("manifest.layout".to_string());
            return bad;
        };
        let ctype: [u8; 4] = record[..4].try_into().expect("a type tag is four bytes");
        offsets.insert(
            ctype,
            u64::from_le_bytes(record[4..12].try_into().expect("u64")),
        );
    }

    let Some(&layr_offset) = offsets.get(b"LAYR") else {
        bad.push("manifest.layout".to_string());
        return bad;
    };
    let (Some(_version), Some(block_count), Some(table_entry)) = (
        u32_at(&raw, layr_offset as usize),
        u32_at(&raw, layr_offset as usize + 4),
        u32_at(&raw, layr_offset as usize + 8),
    ) else {
        bad.push("manifest.layout".to_string());
        return bad;
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
                return bad;
            };
            let (Some(frame_offset), Some(frame_size), Some(uncompressed_size)) = (
                u64_at(&raw, offset),
                u64_at(&raw, offset + 8),
                u64_at(&raw, offset + 16),
            ) else {
                bad.push("manifest.layout".to_string());
                return bad;
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
        return bad;
    };
    if hex(at(&raw, lhas_offset as u128 + 6, 32)) != valid.merkle_root {
        bad.push("manifest.merkle_root".to_string());
    }

    let Some(&ltbl_offset) = offsets.get(b"LTBL") else {
        bad.push("manifest.layout".to_string());
        return bad;
    };
    let (Some(_table_version), Some(_layer_count), Some(entry_size)) = (
        u32_at(&raw, ltbl_offset as usize),
        u32_at(&raw, ltbl_offset as usize + 4),
        u32_at(&raw, ltbl_offset as usize + 8),
    ) else {
        bad.push("manifest.layout".to_string());
        return bad;
    };
    for (index, layer) in valid.layers.iter().enumerate() {
        let Some(offset) = (index)
            .checked_mul(entry_size as usize)
            .and_then(|row| row.checked_add(12))
            .and_then(|row| row.checked_add(ltbl_offset as usize))
        else {
            bad.push("manifest.layout".to_string());
            return bad;
        };
        let (Some(_data_offset), Some(block_index), Some(data_size), Some(sector_count)) = (
            u64_at(&raw, offset),
            u32_at(&raw, offset + 8),
            u32_at(&raw, offset + 12),
            u32_at(&raw, offset + 16),
        ) else {
            bad.push("manifest.layout".to_string());
            return bad;
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
    bad
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
