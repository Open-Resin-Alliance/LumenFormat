//! The reader: every check the specification defines, in the specification's
//! order.
//!
//! The order is load-bearing. A file that breaks several rules is reported
//! under the *first* one, because that is what the corpus' `expected_failure`
//! contract asserts - each invalid vector names one check, and the claim is that
//! it is the first thing a conforming reader notices. So the checks here run in
//! the phases the specification lays out: container structure, the tables, the
//! authentication block, the flags, the tags, and only then the content.
//!
//! Two properties are deliberate and worth stating plainly:
//!
//! * **A failing check never stops the ones that follow it**, except where the
//!   specification says a later phase has nothing left to examine - a file
//!   whose key did not unwrap cannot have its tags verified, and a file whose
//!   tags did not verify has no content to parse. Those two crossings are the
//!   only early exits, and both leave a complete report whose last line is
//!   `__checks_complete`.
//! * **Nothing panics on a damaged file.** Where the Python raises an
//!   uncaught exception - indexing a chunk that is not there, unpacking a
//!   structure that runs off the end - this reader stops and returns what it
//!   has, without `__checks_complete`, so a caller can tell "these are all the
//!   checks" from "this file ended the run". Neither escape is reachable from
//!   the corpus, whose vectors are containers that parse.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bytes::{at, u32_at, u64_at};
use crate::container::{Block, Entry, COMPRESSED_TYPES, ENCRYPTED_FLAG, SEALED_FLAG};
use crate::content::{
    is_int, is_number, is_uuid, lrov_indices_ok, lrov_range_ordered, materials_shape_ok,
    number_at_least, png_header_ok, scalar_eq, time_fields_integer,
};
use crate::crypto::{
    argon2_params, chunk_flag_report, open_unit, recover_session_key, CryptoBlock,
    SEALABLE_CHUNK_TYPES,
};
use crate::decompress::{frame_dict_id, Decoder};
use crate::primitives::{merkle_root, read_varint};
use crate::ree::{self, Violation};
use crate::timing::TimingInputs;

/// `META`'s required fields (§4.2).
const REQUIRED_META_FIELDS: [&str; 10] = [
    "meta_version",
    "normal_exposure_ms",
    "bottom_exposure_ms",
    "bottom_layer_count",
    "transition_layer_count",
    "layer_height_um",
    "lift_slow_distance_um",
    "lift_slow_speed_um_min",
    "retract_fast_distance_um",
    "retract_fast_speed_um_min",
];

/// The order the REE checks are reported in, which is not the order they are
/// discovered: a sector stream can break several rules at once, and the report
/// names the first one the specification lists.
const REE_ORDER: [&str; 10] = [
    "ree.tag_known",
    "ree.binary_first_value",
    "ree.binary_lengths",
    "ree.grayscale_ends",
    "ree.grayscale_adjacent",
    "ree.no_run_count_zero",
    "ree.split_overlay",
    "ree.canonical_tag_choice",
    "ree.no_trailing_bytes",
    "ree.truncated_sector",
];

/// Checks a loose reader does not run, because they judge a file's fidelity to
/// the canonical encoding rather than its readability.
const STRICT_ONLY: [&str; 5] = [
    "ree.no_run_count_zero",
    "ree.binary_lengths",
    "ree.grayscale_adjacent",
    "ree.split_overlay",
    "ree.canonical_tag_choice",
];

/// One check's verdict.
pub struct Item {
    pub name: &'static str,
    pub ok: bool,
    /// Why it failed, in the specification's own wording. Empty when the check
    /// carries no detail.
    pub detail: String,
}

/// The plaintext of a content chunk, as the reader decoded it, so a caller can
/// pin it against the generator's golden value.
pub enum Payload {
    /// A chunk that appears once.
    One(Vec<u8>),
    /// A chunk that may appear more than once, in file order.
    Many(Vec<Vec<u8>>),
}

/// Every check run against one file, in the order they were run.
#[derive(Default)]
pub struct Checks {
    items: Vec<Item>,
    payloads: BTreeMap<[u8; 4], Payload>,
    timing: Option<TimingInputs>,
}

impl Checks {
    /// Record a verdict. Returns it, so a call site can branch on it.
    pub fn check(&mut self, name: &'static str, ok: bool) -> bool {
        self.check_detail(name, ok, "")
    }

    /// Record a verdict with the specification's wording for the failure.
    pub fn check_detail(&mut self, name: &'static str, ok: bool, detail: &str) -> bool {
        self.items.push(Item {
            name,
            ok,
            detail: detail.to_string(),
        });
        ok
    }

    /// The names of the checks that failed, in order.
    pub fn failed(&self) -> Vec<&'static str> {
        self.items
            .iter()
            .filter(|item| !item.ok)
            .map(|item| item.name)
            .collect()
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The plaintext of the content chunks this run decoded, for a caller that
    /// wants to pin the bytes.
    pub fn payloads(&self) -> &BTreeMap<[u8; 4], Payload> {
        &self.payloads
    }

    /// The `META`, `SECT` and `LROV` objects this run parsed, for a caller that
    /// wants to resolve §8's pipeline independently of the reader. `None` when
    /// the run stopped before parsing them, which no conforming vector does.
    pub fn timing_inputs(&self) -> Option<&TimingInputs> {
        self.timing.as_ref()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn has(&self, name: &str) -> bool {
        self.items.iter().any(|item| item.name == name)
    }

    /// Whether the run reached the end of the specification's phases. A run
    /// that stopped early has a report, but not a whole one.
    pub fn completed(&self) -> bool {
        self.has("__checks_complete")
    }

    /// Print every check, one per line, in the format the corpus' own validator
    /// prints: name, verdict, and the wording of a failure.
    pub fn print_verbose(&self) {
        for item in &self.items {
            print!(
                "      {:<32} {}",
                item.name,
                if item.ok { "PASS" } else { "FAIL" }
            );
            if !item.ok && !item.detail.is_empty() {
                print!("  {}", item.detail);
            }
            crate::reportln!();
        }
    }
}

/// One `LTBL` record (§4.5).
struct LayerEntry {
    data_offset: u64,
    block_index: u32,
    data_size: u32,
    sector_count: u32,
}

/// Validate a file, at `strict` or loose level.
///
/// `crypto` carries the credentials an AUTH chunk needs; without them an
/// encrypted file still gets a complete structural report and its content
/// checks are reported as skipped rather than passed.
pub fn validate(path: &Path, strict: bool, crypto: Option<&CryptoBlock>) -> io::Result<Checks> {
    let raw = std::fs::read(path)?;
    Ok(validate_bytes(&raw, strict, crypto))
}

/// Validate bytes already in memory - the same reader, without the file.
pub fn validate_bytes(raw: &[u8], strict: bool, crypto: Option<&CryptoBlock>) -> Checks {
    let mut checks = Checks::default();

    // ---- container ------------------------------------------------------
    let trailer_ok = raw.len() >= 8 && &raw[raw.len() - 8..raw.len() - 4] == b"LEND";
    if !checks.check("trailer.magic", trailer_ok) {
        return checks;
    }
    let stored_crc = u32_at(raw, raw.len() - 4).expect("trailer.magic sized the file");
    checks.check(
        "trailer.crc32c",
        crc32c::crc32c(&raw[..raw.len() - 8]) == stored_crc,
    );
    if !checks.check("header.magic", raw.starts_with(b"LUMN")) {
        return checks;
    }
    checks.check("header.version", u32_at(raw, 4) == Some(1));

    // The fixed file header (§4.1): a file too short to hold it has nothing
    // further to say about itself.
    let (Some(dir_offset), Some(chunk_count), Some(flags), Some(_total_uncompressed)) = (
        u64_at(raw, 8),
        u32_at(raw, 16),
        u32_at(raw, 20),
        u64_at(raw, 24),
    ) else {
        return checks;
    };

    let directory_end = u128::from(dir_offset) + u128::from(chunk_count) * 32;
    let payload_end = raw.len() as u128 - 8;
    if !checks.check(
        "dir.bounds",
        dir_offset >= 32 && directory_end <= payload_end,
    ) {
        return checks;
    }

    let mut entries = Vec::new();
    for index in 0..chunk_count as usize {
        // dir.bounds put every fixed 32-byte record inside the file.
        let base = dir_offset as usize + index * 32;
        let record: &[u8; 32] = raw[base..base + 32]
            .try_into()
            .expect("dir.bounds sized the directory");
        entries.push(Entry {
            ctype: record[..4].try_into().expect("a type tag is four bytes"),
            offset: u64::from_le_bytes(record[4..12].try_into().expect("u64")),
            usz: u64::from_le_bytes(record[12..20].try_into().expect("u64")),
            csz: u64::from_le_bytes(record[20..28].try_into().expect("u64")),
            flags: u32::from_le_bytes(record[28..32].try_into().expect("u32")),
        });
    }
    let real: Vec<&Entry> = entries.iter().filter(|entry| entry.offset != 0).collect();

    checks.check(
        "chunk.hdr_first",
        real.first()
            .is_some_and(|entry| entry.ctype == *b"HDR\0" && entry.offset == 32),
    );
    let mut extents: Vec<(u128, u128)> = real
        .iter()
        .map(|entry| {
            (
                u128::from(entry.offset),
                u128::from(entry.offset) + u128::from(entry.size()),
            )
        })
        .collect();
    extents.sort_unstable();
    checks.check(
        "chunk.overlap",
        extents.windows(2).all(|pair| pair[0].1 <= pair[1].0),
    );
    checks.check(
        "chunk.bounds",
        real.iter()
            .all(|entry| u128::from(entry.offset) + u128::from(entry.size()) <= payload_end),
    );

    // ---- presence -------------------------------------------------------
    checks.check("presence.meta", count(&real, b"META") == 1);
    checks.check("presence.ltbl", count(&real, b"LTBL") == 1);
    checks.check("presence.layr", count(&real, b"LAYR") == 1);
    if flags & 0x02 != 0 {
        checks.check("presence.sect", !find(&real, b"SECT").is_empty());
    }
    // LHAS is optional (§4.11), and §10.3 forbids requiring an optional
    // mechanism in order to decode a file that does not use it - so its absence
    // is not a failure, and the checks over it below do not apply.
    let lhas_entries = find(&real, b"LHAS");
    let auth_entries = find(&real, b"AUTH");
    let encrypted_flag = flags & ENCRYPTED_FLAG != 0;
    let crypto_engaged = encrypted_flag || !auth_entries.is_empty() || crypto.is_some();

    // ---- HDR ------------------------------------------------------------
    let Some(hdr_entry) = first(&real, b"HDR\0") else {
        return checks;
    };
    let hdr = stored(raw, hdr_entry);
    let (Some(hdr_version), Some(name_len)) = (u32_at(hdr, 0), u32_at(hdr, 4)) else {
        return checks;
    };
    checks.check("hdr.version", hdr_version == 1);
    checks.check(
        "hdr.encoder_name_fits",
        hdr.len() >= 52 + name_len as usize && name_len <= 256,
    );
    let name_len = name_len as usize;
    let (Some(_created), Some(display_w), Some(display_h), Some(physical_w), Some(physical_h)) = (
        u64_at(hdr, 8 + name_len),
        u32_at(hdr, 16 + name_len),
        u32_at(hdr, 20 + name_len),
        u32_at(hdr, 24 + name_len),
        u32_at(hdr, 28 + name_len),
    ) else {
        return checks;
    };
    let (Some(_build_w), Some(_build_d), Some(_build_h), Some(_layer_h), Some(total_layers)) = (
        u32_at(hdr, 32 + name_len),
        u32_at(hdr, 36 + name_len),
        u32_at(hdr, 40 + name_len),
        u32_at(hdr, 44 + name_len),
        u32_at(hdr, 48 + name_len),
    ) else {
        return checks;
    };
    checks.check("hdr.total_layers", total_layers > 0);
    checks.check(
        "hdr.physical_ratio",
        display_w != 0
            && display_h != 0
            && physical_w % display_w == 0
            && physical_h % display_h == 0,
    );
    let total_pixels = display_w as usize * display_h as usize;

    // ---- LTBL -----------------------------------------------------------
    let Some(ltbl_entry) = first(&real, b"LTBL") else {
        return checks;
    };
    let ltbl = stored(raw, ltbl_entry);
    let (Some(table_version), Some(layer_count), Some(entry_size)) =
        (u32_at(ltbl, 0), u32_at(ltbl, 4), u32_at(ltbl, 8))
    else {
        return checks;
    };
    checks.check("ltbl.table_version", table_version == 1);
    checks.check("ltbl.entry_size", entry_size >= 20);
    checks.check("hdr.total_layers_matches_ltbl", layer_count == total_layers);

    let mut layers = Vec::new();
    for index in 0..layer_count as usize {
        let Some(offset) = (index)
            .checked_mul(entry_size as usize)
            .and_then(|row| row.checked_add(12))
        else {
            return checks;
        };
        let (Some(data_offset), Some(block_index), Some(data_size), Some(sector_count)) = (
            u64_at(ltbl, offset),
            u32_at(ltbl, offset + 8),
            u32_at(ltbl, offset + 12),
            u32_at(ltbl, offset + 16),
        ) else {
            return checks;
        };
        layers.push(LayerEntry {
            data_offset,
            block_index,
            data_size,
            sector_count,
        });
    }

    // ---- LAYR -----------------------------------------------------------
    let Some(layr_entry) = first(&real, b"LAYR") else {
        return checks;
    };
    let layr = stored(raw, layr_entry);
    let (Some(layr_version), Some(block_count), Some(table_entry)) =
        (u32_at(layr, 0), u32_at(layr, 4), u32_at(layr, 8))
    else {
        return checks;
    };
    checks.check("layr.version", layr_version == 1);
    checks.check(
        "layr.block_count",
        (1..=total_layers).contains(&block_count),
    );

    let mut blocks = Vec::new();
    for index in 0..block_count as usize {
        let Some(offset) = (index)
            .checked_mul(table_entry as usize)
            .and_then(|row| row.checked_add(12))
        else {
            return checks;
        };
        let (Some(frame_offset), Some(frame_size), Some(uncompressed_size)) = (
            u64_at(layr, offset),
            u64_at(layr, offset + 8),
            u64_at(layr, offset + 16),
        ) else {
            return checks;
        };
        blocks.push(Block {
            frame_offset,
            frame_size,
            uncompressed_size,
        });
    }
    let body_offset = 12 + u128::from(block_count) * u128::from(table_entry);

    // A block table with no blocks is a file the oracle cannot describe either;
    // there is no first or last entry to ask about.
    if blocks.is_empty() {
        return checks;
    }
    checks.check(
        "layr.block_table_contiguous",
        blocks[0].frame_offset == 0
            && blocks.windows(2).all(|pair| {
                u128::from(pair[1].frame_offset)
                    == u128::from(pair[0].frame_offset) + u128::from(pair[0].frame_size)
            }),
    );
    let last = blocks
        .last()
        .expect("a block table with no blocks returned above");
    checks.check(
        "layr.block_end_within_payload",
        u128::from(last.frame_offset) + u128::from(last.frame_size) + body_offset
            <= layr.len() as u128,
    );
    checks.check(
        "ltbl.block_index_in_range",
        layers.iter().all(|layer| layer.block_index < block_count),
    );
    checks.check(
        "ltbl.block_index_monotonic",
        layers
            .windows(2)
            .all(|pair| pair[0].block_index <= pair[1].block_index),
    );
    let referenced: HashSet<u32> = layers.iter().map(|layer| layer.block_index).collect();
    checks.check(
        "layr.blocks_referenced",
        referenced == (0..block_count).collect(),
    );
    checks.check(
        "ltbl.empty_layer_no_bytes",
        layers
            .iter()
            .filter(|layer| layer.sector_count == 0)
            .all(|layer| layer.data_size == 0),
    );
    checks.check(
        "ltbl.offsets_within_block",
        layers.iter().all(|layer| {
            layer.block_index < block_count
                && u128::from(layer.data_offset) + u128::from(layer.data_size)
                    <= u128::from(blocks[layer.block_index as usize].uncompressed_size)
        }),
    );

    // ---- LHAS -----------------------------------------------------------
    // The leaf table and its root are plaintext even when the layer data is
    // sealed, so the root can be recomputed without a key.
    let mut leaves: Vec<Vec<u8>> = Vec::new();
    if let Some(lhas_entry) = lhas_entries.first() {
        let lhas = stored(raw, lhas_entry);
        let (Some(&algorithm), Some(&hash_size)) = (lhas.first(), lhas.get(1)) else {
            return checks;
        };
        let Some(leaf_count) = u32_at(lhas, 2) else {
            return checks;
        };
        let root = at(lhas, 6, 32);
        for index in 0..leaf_count as usize {
            leaves.push(at(lhas, 38 + 32 * index as u128, 32).to_vec());
        }
        checks.check("lhas.hash_algorithm", algorithm == 1 && hash_size == 32);
        checks.check("lhas.layer_count", leaf_count == total_layers);
        checks.check(
            "lhas.root_recompute",
            merkle_root(&leaves).is_some_and(|computed| computed.as_slice() == root),
        );
    }

    // ---- AUTH -----------------------------------------------------------
    // If any of this fails the session key cannot be obtained, so every later
    // crypto and content-derived check is skipped rather than recorded as
    // failed.
    let mut session_key: Option<[u8; 32]> = None;
    let mut cipher_id = [0u8; 4];
    let mut decrypted: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut block_frames: Option<Vec<Option<Vec<u8>>>> = None;
    let mut tag_ok = true;
    let mut halt_crypto = false;
    let mut halt_content = false;

    let auth_entry = if auth_entries.len() == 1 {
        auth_entries.first().copied()
    } else {
        None
    };
    if crypto_engaged {
        checks.check("presence.auth", !encrypted_flag || auth_entries.len() == 1);
        if let Some(auth_entry) = auth_entry {
            let auth = stored(raw, auth_entry);
            // Only the fixed prefix can be read from a section that short.
            let head = auth.len() >= 20;
            let auth_version = if head {
                u32_at(auth, 4).unwrap_or(0)
            } else {
                0
            };
            if head {
                cipher_id.copy_from_slice(&auth[..4]);
            }
            let mode = if head {
                u32_at(auth, 8).unwrap_or(0)
            } else {
                0
            };
            let pw_len = if head {
                u32_at(auth, 12).unwrap_or(0)
            } else {
                0
            };
            let mc_len = if head {
                u32_at(auth, 16).unwrap_or(0)
            } else {
                0
            };

            let ok_version = checks.check("auth.version", auth_version == 1);
            let ok_cipher = checks.check(
                "auth.cipher_known",
                cipher_id == *b"A256" || cipher_id == *b"C20P",
            );
            let ok_mode = checks.check("crypt.mode_empty", mode != 0);
            let mut ok_password = true;
            if mode & 0x01 != 0 {
                ok_password = checks.check("crypt.password_section_len", pw_len >= 65);
            }
            let mut ok_machine = true;
            if mode & 0x02 != 0 {
                ok_machine = checks.check(
                    "crypt.machine_section_len",
                    mc_len >= 104 && mc_len % 104 == 0,
                );
            }
            let mut ok_budget = true;
            if mode & 0x01 != 0 {
                let params = argon2_params(auth, pw_len);
                ok_budget = checks.check(
                    "crypt.argon2_budget",
                    params.is_some_and(|(iterations, memory_kib, parallelism)| {
                        iterations <= 10 && memory_kib <= 4_194_304 && parallelism <= 16
                    }),
                );
            }
            if ok_version && ok_cipher && ok_mode && ok_password && ok_machine && ok_budget {
                session_key = recover_session_key(auth, crypto, mode, pw_len, mc_len);
                if session_key.is_none() {
                    halt_crypto = true;
                    halt_content = true;
                }
            } else {
                halt_crypto = true;
                halt_content = true;
            }
        } else {
            halt_crypto = true;
            halt_content = true;
        }
    }

    // ---- chunk flags ----------------------------------------------------
    // Directory metadata: checked before any decryption.
    let sealed_layr = first(&real, b"LAYR").is_some_and(|entry| entry.flags & SEALED_FLAG != 0);
    let any_sealed = real.iter().any(|entry| entry.flags & SEALED_FLAG != 0);
    if (crypto_engaged || any_sealed) && !halt_crypto {
        let (ok, detail) = chunk_flag_report(&real, &blocks, encrypted_flag, sealed_layr);
        checks.check_detail("crypt.chunk_flags", ok, &detail);
        if !ok {
            halt_crypto = true;
            halt_content = true;
        }
    }

    // ---- decrypt --------------------------------------------------------
    // The key itself was unwrapped above, because its success decides whether
    // the content checks can run at all.
    if crypto_engaged && !halt_crypto {
        checks.check("crypt.key_unwrap", session_key.is_some());
        if let Some(key) = session_key {
            for entry in &real {
                let sealable = SEALABLE_CHUNK_TYPES.contains(&&entry.ctype);
                if sealable && entry.ctype != *b"LAYR" && entry.flags & SEALED_FLAG != 0 {
                    match open_unit(&key, &cipher_id, &entry.ctype, 0, stored(raw, entry)) {
                        Ok(plain) => {
                            decrypted.insert(entry.offset, plain);
                        }
                        Err(_) => tag_ok = false,
                    }
                }
            }
            if sealed_layr {
                let mut frames = Vec::new();
                for (index, block) in blocks.iter().enumerate() {
                    let blob = at(
                        layr,
                        body_offset + u128::from(block.frame_offset),
                        u128::from(block.frame_size),
                    );
                    match open_unit(&key, &cipher_id, b"LAYR", index as u32, blob) {
                        Ok(plain) => frames.push(Some(plain)),
                        Err(_) => {
                            tag_ok = false;
                            frames.push(None);
                        }
                    }
                }
                block_frames = Some(frames);
            }
        } else {
            halt_crypto = true;
            halt_content = true;
        }
    }

    // ---- tags -----------------------------------------------------------
    // §9.3: every tag must verify before content is parsed or decompressed.
    if crypto_engaged && !halt_crypto && !checks.check("crypt.tag_verify", tag_ok) {
        halt_content = true;
    }

    // ---- content --------------------------------------------------------
    // A file whose key or tags did not check out is still validated
    // structurally, but its content is never parsed.
    if halt_content {
        checks.check("__checks_complete", true);
        return checks;
    }
    let content = Content {
        raw,
        real: &real,
        decrypted: &decrypted,
    };
    let mut payloads: BTreeMap<[u8; 4], Payload> = BTreeMap::new();

    // ---- META / SECT ----------------------------------------------------
    let Some(meta) = content.json(b"META") else {
        return checks;
    };
    let mats = meta.get("materials");
    // Durations are whole milliseconds (§4.2), so the type rule comes before
    // anything that reads a duration's value.
    checks.check("meta.time_integer", time_fields_integer(&meta));
    checks.check(
        "meta.required_fields",
        REQUIRED_META_FIELDS
            .iter()
            .all(|field| meta.get(field).is_some()),
    );
    checks.check("meta.materials_shape", materials_shape_ok(mats));

    let mut sects = Vec::new();
    for entry in find(&real, b"SECT") {
        let Some(sect) = content.json_entry(entry) else {
            return checks;
        };
        sects.push(sect);
    }
    checks.check("sect.time_integer", sects.iter().all(time_fields_integer));
    checks.check(
        "sect.sector_id_nonzero",
        sects.iter().all(|sect| {
            sect.get("sector_id")
                .is_some_and(|id| number_at_least(id, 1.0))
        }),
    );
    checks.check("sect.ids_unique", sector_ids_unique(&sects));
    checks.check(
        "sect.material_index_bounds",
        sects.iter().all(|sect| match sect.get("material_index") {
            None => true,
            Some(index) => mats
                .and_then(container_len)
                .is_some_and(|materials| index_in_range(index, materials)),
        }),
    );
    let sect_ids: Vec<&Value> = sects
        .iter()
        .filter_map(|sect| sect.get("sector_id"))
        .collect();

    // ---- PROF / LROV / PREV ---------------------------------------------
    // Optional content chunks. PROF and LROV go through the same
    // sealed/compressed path as META/SECT; PREV is uncompressed but may carry
    // its own ENCRYPTED bit (§4.7), independent of the file-level flag.
    if let Some(entry) = first(&real, b"PROF") {
        let Some(prof_plain) = content.bytes(entry) else {
            return checks;
        };
        let Some(prof) = parse_json(&prof_plain) else {
            return checks;
        };
        let prof = if prof.is_object() {
            prof
        } else {
            Value::Object(serde_json::Map::new())
        };
        let settings = prof.get("settings");
        checks.check(
            "prof.profile_identity",
            is_nonempty_string(prof.get("profile_name"))
                && is_nonempty_string(prof.get("profile_version")),
        );
        checks.check(
            "prof.profile_type",
            prof.get("profile_type")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "material" | "printer" | "combined")),
        );
        checks.check(
            "prof.settings_time_integer",
            settings.is_none_or(time_fields_integer),
        );
        checks.check(
            "prof.settings_exposure",
            settings.is_some_and(|settings| {
                settings
                    .get("normal_exposure_ms")
                    .is_some_and(is_positive_int)
                    && settings
                        .get("bottom_exposure_ms")
                        .is_some_and(is_positive_int)
            }),
        );
        checks.check(
            "prof.settings_layer_height",
            settings.is_some_and(|settings| {
                settings
                    .get("layer_height_um")
                    .is_some_and(is_positive_number)
            }),
        );
        let curve = settings.and_then(|settings| settings.get("cure_curve"));
        checks.check(
            "prof.cure_curve",
            curve.is_none_or(|curve| {
                curve.get("dp_um").is_some_and(is_positive_number)
                    && curve.get("ec_mj_cm2").is_some_and(is_positive_number)
                    && curve
                        .get("e0_mj_cm2")
                        .is_some_and(|e0| is_number(e0) && number_at_least(e0, 0.0))
            }),
        );
        checks.check(
            "prof.profile_uuid",
            prof.get("profile_uuid")
                .is_none_or(|uuid| uuid.as_str().is_some_and(is_uuid)),
        );
        checks.check(
            "prof.materials_shape",
            materials_shape_ok(prof.get("materials")),
        );
        payloads.insert(*b"PROF", Payload::One(prof_plain));
    }

    // The `LROV` body, kept for the timing inputs below.
    let mut lrov_body = None;
    if let Some(entry) = first(&real, b"LROV") {
        let Some(lrov_plain) = content.bytes(entry) else {
            return checks;
        };
        let Some(lrov) = parse_json(&lrov_plain) else {
            return checks;
        };
        let entries = lrov.get("overrides").and_then(Value::as_array);
        checks.check(
            "lrov.time_integer",
            entries.is_none_or(|entries| entries.iter().all(time_fields_integer)),
        );
        checks.check(
            "lrov.entry_form",
            entries.is_some_and(|entries| {
                entries.iter().all(|entry| {
                    entry.is_object()
                        && (entry.get("layer").is_some() != entry.get("layer_range").is_some())
                })
            }),
        );
        checks.check(
            "lrov.layer_index_range",
            entries.is_some_and(|entries| {
                entries
                    .iter()
                    .all(|entry| lrov_indices_ok(entry, total_layers))
            }),
        );
        checks.check(
            "lrov.layer_range_order",
            entries.is_some_and(|entries| entries.iter().all(lrov_range_ordered)),
        );
        checks.check(
            "lrov.sector_id_defined",
            entries.is_some_and(|entries| {
                entries.iter().all(|entry| match entry.get("sector_id") {
                    None => true,
                    Some(id) => {
                        scalar_eq(id, &Value::from(0))
                            || sect_ids.iter().any(|defined| scalar_eq(id, defined))
                    }
                })
            }),
        );
        payloads.insert(*b"LROV", Payload::One(lrov_plain));
        lrov_body = Some(lrov);
    }

    // The values §8 resolves a point from, taken from the chunks this run just
    // parsed - so a sealed file is resolved from what its key unwrapped rather
    // than from the bytes on disk. The layer count is HDR's, which the sample of
    // points is bounded by.
    checks.timing = Some(TimingInputs {
        total_layers,
        meta,
        sects,
        lrov: lrov_body,
    });

    let prev_entries = find(&real, b"PREV");
    if !prev_entries.is_empty() {
        checks.check(
            "prev.flags",
            prev_entries
                .iter()
                .all(|entry| (entry.flags & 0x0F) <= 3 && (entry.flags >> 5) == 0),
        );
        let mut previews = Vec::new();
        for entry in &prev_entries {
            let Some(plain) = content.bytes(entry) else {
                return checks;
            };
            previews.push(plain);
        }
        if strict {
            checks.check(
                "prev.png_signature",
                previews.iter().all(|preview| png_header_ok(preview)),
            );
        }
        payloads.insert(*b"PREV", Payload::Many(previews));
    }

    // ---- VOXL -----------------------------------------------------------
    // §4.12: the embedded scene is opaque to LUMEN, so §11.2 only asks a strict
    // reader to recognize which generation of VOXL it is holding. Whether the
    // scene is *valid* is VOXL's business: a print reader must never reject a
    // file over its embedded scene, so loose mode records nothing here.
    if let Some(entry) = first(&real, b"VOXL") {
        let Some(voxl) = content.bytes(entry) else {
            return checks;
        };
        if strict {
            checks.check(
                "voxl.signature",
                voxl.starts_with(b"VOXL") || voxl.starts_with(b"{"),
            );
        }
        payloads.insert(*b"VOXL", Payload::One(voxl));
    }

    // ---- EXTD -----------------------------------------------------------
    // §4.13: vendor or future-standard extensions, any number of them. The
    // fixed frame is `ext_version (u32) || ext_type (4 bytes) || ext_data`, and
    // the payload is zstd-compressed unless the extension says otherwise. EXTD
    // is required neither to be sealed nor to be clear, and this reader
    // implements no extension semantics: a payload that will not decompress
    // cannot satisfy the frame at all, so it is reported as a frame failure
    // rather than raised.
    let extd_entries = find(&real, b"EXTD");
    if !extd_entries.is_empty() {
        let mut extensions: Vec<Option<Vec<u8>>> = Vec::new();
        for entry in &extd_entries {
            extensions.push(payload_plain(raw, entry).ok());
        }
        checks.check(
            "extd.frame",
            extensions
                .iter()
                .all(|blob| blob.as_ref().is_some_and(|blob| blob.len() >= 8)),
        );
        checks.check(
            "extd.ext_type",
            extensions.iter().all(|blob| {
                blob.as_ref().is_some_and(|blob| {
                    blob.len() >= 8 && blob[4..8].iter().all(|byte| *byte < 0x80)
                })
            }),
        );
        // Descriptor flags: bits 8-23 are `vendor_id` (§4.13), bit 24 is
        // `critical`; bits 0-3, 5-7 (bit 4 is the standard ENCRYPTED flag) and
        // 25-31 are reserved and must be 0.
        checks.check(
            "extd.flags",
            extd_entries
                .iter()
                .all(|entry| (entry.flags & 0xFE00_00EF) == 0),
        );
        // `critical` is reader-relative: a reader that does not implement the
        // extension must refuse the file rather than print an approximation.
        // This reference validator implements no extension semantics, so every
        // critical EXTD is a file it must not accept.
        checks.check(
            "extd.critical",
            extd_entries
                .iter()
                .all(|entry| (entry.flags & 0x0100_0000) == 0),
        );
        payloads.insert(
            *b"EXTD",
            Payload::Many(extensions.into_iter().flatten().collect()),
        );
    }

    // ---- ZDIC -----------------------------------------------------------
    let zdic_entries = find(&real, b"ZDIC");
    let mut dictionary = Vec::new();
    let mut dict_id = 0u32;
    if let Some(entry) = zdic_entries.first() {
        let Some(zdic) = content.bytes(entry) else {
            return checks;
        };
        let (Some(version), Some(declared_dict_id), Some(dict_size)) =
            (u32_at(&zdic, 0), u32_at(&zdic, 4), u32_at(&zdic, 8))
        else {
            return checks;
        };
        dict_id = declared_dict_id;
        dictionary = at(&zdic, 12, u128::from(dict_size)).to_vec();
        checks.check("zdic.version", version == 1);
        checks.check("zdic.present_for_dict", dict_size > 0);
    }
    let Ok(mut decoder) = Decoder::new(&dictionary) else {
        return checks;
    };

    let frames: Vec<Option<&[u8]>> = match &block_frames {
        Some(frames) => frames.iter().map(Option::as_deref).collect(),
        None => blocks
            .iter()
            .map(|block| {
                Some(at(
                    layr,
                    body_offset + u128::from(block.frame_offset),
                    u128::from(block.frame_size),
                ))
            })
            .collect(),
    };

    let mut dict_ids: Vec<Option<u32>> = Vec::new();
    let mut outputs: Vec<Vec<u8>> = Vec::new();
    let mut sizes_exact = true;
    let mut decompressed = true;
    for (index, block) in blocks.iter().enumerate() {
        let Some(frame) = frames.get(index).copied().flatten() else {
            decompressed = false;
            dict_ids.push(None);
            outputs.push(Vec::new());
            continue;
        };
        dict_ids.push(frame_dict_id(frame));
        let capacity = usize::try_from(block.uncompressed_size).unwrap_or(usize::MAX);
        match decoder.decompress(frame, capacity) {
            Ok(output) => {
                sizes_exact &= output.len() == block.uncompressed_size as usize;
                outputs.push(output);
            }
            Err(_) => {
                decompressed = false;
                // A frame that parses but does not decompress contributes *two*
                // entries here, not one: the oracle records the frame header's
                // dictionary ID and then records the failure as well. The
                // duplication decides `layr.dict_id_match` - a `None` in the
                // list fails it - so it is reproduced rather than tidied.
                dict_ids.push(None);
                outputs.push(Vec::new());
            }
        }
    }
    checks.check("layr.block_decompress", decompressed);
    checks.check("layr.block_sizes_exact", sizes_exact && decompressed);
    if !zdic_entries.is_empty() {
        checks.check(
            "layr.dict_id_match",
            dict_ids.iter().all(|id| *id == Some(dict_id)),
        );
    } else {
        checks.check(
            "layr.dict_id_absent",
            dict_ids.iter().all(|id| *id == Some(0)),
        );
    }

    // ---- layer data / leaf hashes ---------------------------------------
    let mut layer_data: Vec<Vec<u8>> = Vec::new();
    for layer in &layers {
        if layer.block_index >= block_count {
            layer_data.push(Vec::new());
            continue;
        }
        let block = &outputs[layer.block_index as usize];
        layer_data.push(
            at(
                block,
                u128::from(layer.data_offset),
                u128::from(layer.data_size),
            )
            .to_vec(),
        );
    }
    if strict && !leaves.is_empty() {
        let matched = (0..layer_count as usize).all(|index| {
            match (layer_data.get(index), leaves.get(index)) {
                (Some(data), Some(leaf)) => {
                    let mut hasher = Sha256::new();
                    hasher.update([0x00]);
                    hasher.update(data);
                    hasher.finalize().as_slice() == leaf.as_slice()
                }
                // The oracle indexes both lists directly; a truncated leaf
                // table is a failure rather than a crash here.
                _ => false,
            }
        });
        checks.check("lhas.leaf_match", matched);
    }

    // ---- REE / sector decode --------------------------------------------
    let mut hits: HashSet<&'static str> = HashSet::new();
    let mut detail: HashMap<&'static str, String> = HashMap::new();
    let mut sector_match = true;
    let mut ids_unique = true;
    let mut partition_ok = true;
    for (index, layer) in layers.iter().enumerate() {
        if layer.sector_count == 0 {
            continue;
        }
        let mut report = SectorReport {
            violations: Vec::new(),
            sector_match: true,
            ids_unique: true,
            partition_ok: true,
        };
        let outcome = decode_sectors(
            &layer_data[index],
            layer,
            flags & 0x02 != 0,
            total_pixels,
            strict,
            &mut report,
        );
        // Every flag the layer set before it failed stands, which is what the
        // oracle's assignments inside its try block do.
        sector_match &= report.sector_match;
        ids_unique &= report.ids_unique;
        partition_ok &= report.partition_ok;
        let failure = match outcome {
            Ok(()) => None,
            Err(error) => {
                hits.insert("ree.truncated_sector");
                Some(error.0)
            }
        };
        for violation in report.violations {
            hits.insert(violation.code);
            if let Some(message) = violation.message {
                detail
                    .entry(violation.code)
                    .or_insert_with(|| format!("layer {index}: {message}"));
            }
        }
        if let Some(message) = failure {
            detail
                .entry("ree.truncated_sector")
                .or_insert_with(|| format!("layer {index}: {message}"));
        }
    }

    checks.check("sector.count_match", sector_match);
    checks.check("sector.ids_unique", ids_unique);
    for name in REE_ORDER {
        if STRICT_ONLY.contains(&name) && !strict {
            continue;
        }
        let message = detail.get(name).map_or("", String::as_str);
        checks.check_detail(name, !hits.contains(name), message);
    }
    if strict {
        checks.check("sector.partition", partition_ok);
    }

    checks.payloads = payloads;
    checks.check("__checks_complete", true);
    checks
}

/// The reader's view of a chunk's plaintext.
struct Content<'a> {
    raw: &'a [u8],
    real: &'a [&'a Entry],
    decrypted: &'a HashMap<u64, Vec<u8>>,
}

impl Content<'_> {
    /// A chunk's plaintext: decrypted when it is sealed, decompressed when it
    /// is compressed. `None` where the oracle raises and the run stops.
    fn bytes(&self, entry: &Entry) -> Option<Vec<u8>> {
        if entry.flags & SEALED_FLAG != 0 {
            let blob = self.decrypted.get(&entry.offset)?;
            if COMPRESSED_TYPES.contains(&&entry.ctype) {
                let capacity = usize::try_from(entry.usz).unwrap_or(usize::MAX);
                return Decoder::new(&[]).ok()?.decompress(blob, capacity).ok();
            }
            return Some(blob.clone());
        }
        payload_plain(self.raw, entry).ok()
    }

    /// The plaintext of the first chunk of a type.
    fn of(&self, ctype: &[u8; 4]) -> Option<Vec<u8>> {
        let entry = self.real.iter().copied().find(|e| &e.ctype == ctype)?;
        self.bytes(entry)
    }

    /// The plaintext of the first chunk of a type, parsed as JSON.
    fn json(&self, ctype: &[u8; 4]) -> Option<Value> {
        parse_json(&self.of(ctype)?)
    }

    fn json_entry(&self, entry: &Entry) -> Option<Value> {
        parse_json(&self.bytes(entry)?)
    }
}

fn parse_json(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// The stored payload bytes; for LAYR this is the plaintext container.
fn stored<'a>(raw: &'a [u8], entry: &Entry) -> &'a [u8] {
    at(raw, u128::from(entry.offset), u128::from(entry.size()))
}

/// Stored payload with chunk-level compression undone.
///
/// A fresh decoder each time, as the oracle uses: a chunk payload is not a
/// continuation of anything.
fn payload_plain(raw: &[u8], entry: &Entry) -> Result<Vec<u8>, crate::decompress::ZstdError> {
    let blob = stored(raw, entry);
    if entry.csz == 0 {
        return Ok(blob.to_vec());
    }
    let capacity = usize::try_from(entry.usz).unwrap_or(usize::MAX);
    Decoder::new(&[])?.decompress(blob, capacity)
}

fn find<'a>(real: &[&'a Entry], ctype: &[u8; 4]) -> Vec<&'a Entry> {
    real.iter().copied().filter(|e| &e.ctype == ctype).collect()
}

fn count(real: &[&Entry], ctype: &[u8; 4]) -> usize {
    real.iter().filter(|e| &e.ctype == ctype).count()
}

fn first<'a>(real: &[&'a Entry], ctype: &[u8; 4]) -> Option<&'a Entry> {
    real.iter().copied().find(|e| &e.ctype == ctype)
}

fn is_nonempty_string(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

/// Python's `len()`, for the containers that have one. A materials field that
/// is not one of them cannot be indexed into at all.
fn container_len(value: &Value) -> Option<usize> {
    match value {
        Value::Array(items) => Some(items.len()),
        Value::String(text) => Some(text.chars().count()),
        Value::Object(fields) => Some(fields.len()),
        _ => None,
    }
}

/// Python's `0 <= index < length`: a bool counts as the number it is, and
/// anything else that is not a number is not an index.
fn index_in_range(index: &Value, length: usize) -> bool {
    let number = match index {
        Value::Bool(true) => 1.0,
        Value::Bool(false) => 0.0,
        _ => match index.as_f64() {
            Some(number) => number,
            None => return false,
        },
    };
    number >= 0.0 && number < length as f64
}

fn is_positive_number(value: &Value) -> bool {
    is_number(value) && value.as_f64().is_some_and(|n| n > 0.0)
}

fn is_positive_int(value: &Value) -> bool {
    is_int(value) && value.as_f64().is_some_and(|n| n > 0.0)
}

/// §11.2: `sector_id` values are distinct, compared by value - so `1` and
/// `1.0` are one id, the way the oracle's `set` sees them.
fn sector_ids_unique(sects: &[Value]) -> bool {
    let ids: Vec<&Value> = sects
        .iter()
        .filter_map(|sect| sect.get("sector_id"))
        .collect();
    // The oracle builds a set of `s["sector_id"]` for every SECT, so one with
    // no id at all cannot be checked.
    if ids.len() != sects.len() {
        return false;
    }
    (0..ids.len()).all(|i| (i + 1..ids.len()).all(|j| !scalar_eq(ids[i], ids[j])))
}

/// What one layer's sectors said, whether or not the layer finished.
struct SectorReport {
    violations: Vec<Violation>,
    /// The sector count in the stream matched the table.
    sector_match: bool,
    /// No two sectors in the layer share an id.
    ids_unique: bool,
    /// No two sectors in the layer paint the same pixel.
    partition_ok: bool,
}

/// Decode one layer's sectors, in the order the reader decodes them.
///
/// The report is filled in as far as the layer gets, so a layer that fails
/// halfway still contributes the verdicts it reached - exactly where the
/// oracle's assignments sit inside its `try` block. The verdicts start true
/// because they are only ever falsified.
fn decode_sectors(
    blob: &[u8],
    layer: &LayerEntry,
    multi_sector: bool,
    total_pixels: usize,
    strict: bool,
    report: &mut SectorReport,
) -> Result<(), ree::DecodeError> {
    let owned;
    let sectors: &[&[u8]] = if multi_sector {
        let (declared, mut pos) = read_varint(blob, 0).map_err(|e| ree::DecodeError(e.0))?;
        if declared != u128::from(layer.sector_count) {
            report.sector_match = false;
        }
        let mut ids: Vec<u128> = Vec::new();
        let mut slices = Vec::new();
        for _ in 0..declared {
            let (id, next) = read_varint(blob, pos).map_err(|e| ree::DecodeError(e.0))?;
            pos = next;
            let (size, next) = read_varint(blob, pos).map_err(|e| ree::DecodeError(e.0))?;
            pos = next;
            slices.push(at(blob, pos as u128, size));
            pos = pos.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
            ids.push(id);
        }
        if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            report.ids_unique = false;
        }
        owned = slices;
        &owned
    } else {
        owned = vec![blob];
        &owned
    };

    let mut masks: Vec<Vec<u8>> = Vec::new();
    for sector in sectors {
        if sector.is_empty() {
            report.violations.push(Violation {
                code: "ree.truncated_sector",
                message: Some("empty sector data"),
            });
            continue;
        }
        let tag = sector[0];
        let body = &sector[1..];
        let (mask, end, violations) = match tag {
            0x00 => ree::binary(body, total_pixels)?,
            0x01 => {
                let (mask, end, mut violations) = ree::grayscale(body, total_pixels)?;
                if strict && mask.iter().all(|pixel| *pixel == 0 || *pixel == 255) {
                    violations.push(Violation {
                        code: "ree.canonical_tag_choice",
                        message: Some("binary content encoded as grayscale REE"),
                    });
                }
                (mask, end, violations)
            }
            0x02 => ree::split(body, total_pixels)?,
            _ => {
                report.violations.push(Violation {
                    code: "ree.tag_known",
                    message: None,
                });
                continue;
            }
        };
        report.violations.extend(violations);
        if end != body.len() {
            report.violations.push(Violation {
                code: "ree.no_trailing_bytes",
                message: Some("trailing bytes after the REE stream"),
            });
        }
        masks.push(mask);
    }

    for (i, left) in masks.iter().enumerate() {
        for right in &masks[i + 1..] {
            if left.iter().zip(right).any(|(a, b)| *a != 0 && *b != 0) {
                report.partition_ok = false;
            }
        }
    }
    Ok(())
}
