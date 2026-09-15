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
//!
//! The revised layout is structural rather than in-band: `LTBL` carries one
//! record per `(layer, sector)`, each naming its `LAYR` chunk and its slice of
//! that chunk's output, one `LROV` chunk carries one `(layer, sector)`'s timing
//! deltas, and a `LAYR` chunk is a clear version field followed by a single
//! zstd frame. Nothing about a sector is encoded inside the layer data any
//! more, so the tables are the only place a sector can be described - and the
//! checks that read them are the only place a defect in them can be reported.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::ops::Range;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bytes::{at, u32_at, u64_at};
use crate::container::{Chunk, COMPRESSED_TYPES, ENCRYPTED_FLAG, LAYR_HEADER_SIZE, SEALED_FLAG};
use crate::content::{
    cure_curve_ok, is_int, is_positive_number, is_uuid, materials_shape_ok, png_header_ok,
    sector_material_index_ok, sectors_shape_ok, sectors_time_integer, temperature_range_ok,
    time_fields_integer,
};
use crate::crypto::{
    argon2_params, chunk_flag_report, open_unit, recover_session_key, CryptoBlock,
    SEALABLE_CHUNK_TYPES,
};
use crate::decompress::{frame_content_size, frame_dict_id, Decoder};
use crate::primitives::merkle_root;
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
/// discovered: a slice's stream can break several rules at once, and the report
/// names the first one the specification lists.
const REE_ORDER: [&str; 14] = [
    "ree.varint",
    "ree.tag",
    "ree.split_positions",
    "ree.first_value",
    "ree.end_positions",
    "ree.planes",
    "ree.data_size",
    "ree.no_run_count_zero",
    "ree.run_lengths",
    "ree.grayscale_runs",
    "ree.grayscale_all_binary",
    "ree.split_all_binary",
    "ree.split_threshold",
    "ree.no_trailing_bytes",
];

/// Checks a loose reader does not run, because they judge a file's fidelity to
/// the canonical encoding rather than its readability.
const STRICT_ONLY: [&str; 7] = [
    "ree.planes",
    "ree.no_run_count_zero",
    "ree.run_lengths",
    "ree.grayscale_runs",
    "ree.grayscale_all_binary",
    "ree.split_all_binary",
    "ree.split_threshold",
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
    layers: Vec<Vec<u8>>,
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

    /// The `META` and `LROV` objects this run parsed, for a caller that wants to
    /// resolve §8's pipeline independently of the reader. `None` when the run
    /// stopped before parsing them, which no conforming vector does.
    pub fn timing_inputs(&self) -> Option<&TimingInputs> {
        self.timing.as_ref()
    }

    /// One decompressed byte range per layer: the slices of its sectors,
    /// concatenated in ascending `sector_id` - the bytes `LHAS` hashes. Empty
    /// for a layer the run never reached.
    pub fn layers(&self) -> &[Vec<u8>] {
        &self.layers
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

/// One `LTBL` record (§4.7): a `(layer, sector)`'s slice of one `LAYR` chunk.
///
/// The layer is not a field of the record - the table groups a layer's records
/// together, so the layer is where the record sits rather than what it says.
/// [`Reader::spans`] holds that grouping.
#[derive(Clone, Copy)]
struct SectorEntry {
    data_size: u32,
    first_lrov: u32,
    first_layr: u32,
    additional_sector_count: u32,
    data_offset: u64,
    sector_id: u32,
}

/// One `LTBL` record, read where the entry sits in the table.
///
/// `entry_size` is the header's stride, so a future version that appends fields
/// after offset 28 is read correctly rather than misaligned.
fn ltbl_entry(ltbl: &[u8], entry_size: u32, index: u64) -> Option<SectorEntry> {
    let base = 16u128 + u128::from(index) * u128::from(entry_size);
    let field = |offset: u128| usize::try_from(base + offset).ok();
    Some(SectorEntry {
        data_size: u32_at(ltbl, field(0)?)?,
        first_lrov: u32_at(ltbl, field(4)?)?,
        first_layr: u32_at(ltbl, field(8)?)?,
        additional_sector_count: u32_at(ltbl, field(12)?)?,
        data_offset: u64_at(ltbl, field(16)?)?,
        sector_id: u32_at(ltbl, field(24)?)?,
    })
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
    let (Some(dir_offset), Some(chunk_count), Some(flags), Some(total_uncompressed)) = (
        u64_at(raw, 8),
        u32_at(raw, 16),
        u32_at(raw, 20),
        u64_at(raw, 24),
    ) else {
        return checks;
    };
    // §3.1: bits 0, 2 and 4 are reserved, and bit 1 and bit 3 are the two flags
    // this revision defines.
    checks.check("header.flags_reserved", flags & 0x15 == 0);

    let directory_end = u128::from(dir_offset) + u128::from(chunk_count) * 32;
    let payload_end = raw.len() as u128 - 8;
    if !checks.check(
        "header.dir_offset",
        dir_offset >= 32 && directory_end <= payload_end,
    ) {
        return checks;
    }

    let mut entries = Vec::new();
    for index in 0..chunk_count as usize {
        // header.dir_offset put every fixed 32-byte record inside the file.
        let base = dir_offset as usize + index * 32;
        let record: &[u8; 32] = raw[base..base + 32]
            .try_into()
            .expect("header.dir_offset sized the directory");
        entries.push(crate::container::Entry {
            ctype: record[..4].try_into().expect("a type tag is four bytes"),
            offset: u64::from_le_bytes(record[4..12].try_into().expect("u64")),
            usz: u64::from_le_bytes(record[12..20].try_into().expect("u64")),
            csz: u64::from_le_bytes(record[20..28].try_into().expect("u64")),
            flags: u32::from_le_bytes(record[28..32].try_into().expect("u32")),
        });
    }
    // A record with a zero offset is unused, and every index the tables carry
    // is an index into the whole directory rather than into this list (§4.7),
    // so the index is kept beside the record rather than thrown away.
    let real: Vec<Chunk> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.offset != 0)
        .map(|(index, entry)| Chunk { index, entry })
        .collect();

    // §4.1: `HEAD` is present, and the first chunk - at the offset immediately
    // after the fixed header. The two are separate rules, so they are separate
    // verdicts.
    let hdr_first = first(&real, b"HEAD");
    checks.check("presence.head", hdr_first.is_some());
    checks.check(
        "dir.head_first",
        real.first()
            .is_some_and(|chunk| chunk.entry.ctype == *b"HEAD" && chunk.entry.offset == 32),
    );
    let mut extents: Vec<(u128, u128)> = real
        .iter()
        .map(|chunk| {
            (
                u128::from(chunk.entry.offset),
                u128::from(chunk.entry.offset) + u128::from(chunk.entry.size()),
            )
        })
        .collect();
    extents.sort_unstable();
    checks.check(
        "dir.overlap",
        extents.windows(2).all(|pair| pair[0].1 <= pair[1].0),
    );
    checks.check(
        "dir.chunk_extent",
        real.iter().all(|chunk| {
            u128::from(chunk.entry.offset) + u128::from(chunk.entry.size()) <= payload_end
        }),
    );
    // §3.1: the header's own figure, when it carries one, is the sum of the
    // chunks' uncompressed sizes. `0` means the writer did not know it.
    checks.check(
        "header.total_uncompressed_size",
        total_uncompressed == 0
            || total_uncompressed
                == real
                    .iter()
                    .fold(0u64, |sum, chunk| sum.saturating_add(chunk.entry.usz)),
    );

    // ---- presence -------------------------------------------------------
    // A sector is structural now: one `LAYR` chunk per (sector, layer group),
    // so a file may carry any number of them.
    checks.check("presence.meta", count(&real, b"META") == 1);
    checks.check("presence.ltbl", count(&real, b"LTBL") == 1);
    checks.check("presence.layr", count(&real, b"LAYR") >= 1);
    // LHAS is optional (§4.10), and §10.3 forbids requiring an optional
    // mechanism in order to decode a file that does not use it - so its absence
    // is not a failure, and the checks over it below do not apply.
    let lhas_entries = find(&real, b"LHAS");
    let auth_entries = find(&real, b"AUTH");
    let encrypted_flag = flags & ENCRYPTED_FLAG != 0;
    let crypto_engaged = encrypted_flag || !auth_entries.is_empty() || crypto.is_some();

    // ---- HEAD ------------------------------------------------------------
    let Some(hdr_chunk) = first(&real, b"HEAD") else {
        return checks;
    };
    let head = stored(raw, hdr_chunk.entry);
    let (Some(head_version), Some(name_len)) = (u32_at(head, 0), u32_at(head, 4)) else {
        return checks;
    };
    checks.check("head.version", head_version == 1);
    checks.check(
        "head.frame",
        head.len() >= 52 + name_len as usize && name_len <= 256,
    );
    let name_len = name_len as usize;
    let (Some(_created), Some(display_w), Some(display_h), Some(physical_w), Some(physical_h)) = (
        u64_at(head, 8 + name_len),
        u32_at(head, 16 + name_len),
        u32_at(head, 20 + name_len),
        u32_at(head, 24 + name_len),
        u32_at(head, 28 + name_len),
    ) else {
        return checks;
    };
    let (Some(build_w), Some(build_d), Some(build_h), Some(layer_h), Some(total_layers)) = (
        u32_at(head, 32 + name_len),
        u32_at(head, 36 + name_len),
        u32_at(head, 40 + name_len),
        u32_at(head, 44 + name_len),
        u32_at(head, 48 + name_len),
    ) else {
        return checks;
    };
    checks.check("head.total_layers", total_layers > 0);
    checks.check("head.layer_height", layer_h > 0);
    checks.check("head.build_dims", build_w > 0 && build_d > 0 && build_h > 0);
    checks.check(
        "head.display_pixels",
        display_w as usize * display_h as usize > 0,
    );
    checks.check(
        "head.physical_multiple",
        display_w != 0
            && display_h != 0
            && physical_w % display_w == 0
            && physical_h % display_h == 0,
    );
    let total_pixels = display_w as usize * display_h as usize;

    // ---- LTBL -----------------------------------------------------------
    let Some(ltbl_chunk) = first(&real, b"LTBL") else {
        return checks;
    };
    let ltbl = stored(raw, ltbl_chunk.entry);
    let (Some(table_version), Some(layer_count), Some(entry_size), Some(entry_count)) = (
        u32_at(ltbl, 0),
        u32_at(ltbl, 4),
        u32_at(ltbl, 8),
        u32_at(ltbl, 12),
    ) else {
        return checks;
    };
    checks.check("ltbl.version", table_version == 1);
    checks.check("ltbl.entry_size", entry_size >= 28);
    checks.check("ltbl.layer_count", layer_count == total_layers);

    // The table is walked the way a reader decodes it: a layer's first entry
    // says how many further entries that layer carries, so where the next layer
    // starts is known before its neighbours are read. `spans` records that
    // grouping, which is the layer every record belongs to.
    let mut sectors: Vec<SectorEntry> = Vec::new();
    let mut spans: Vec<Range<usize>> = Vec::new();
    // The sum of `1 + additional_sector_count` over each layer's first entry,
    // and whether the walk ever ran off the chunk. A table that stops early is
    // a defect of the count rather than a reason to abandon the file: the run
    // carries on with the entries it did read.
    let mut declared_total = 0u64;
    let mut truncated_table = false;
    let mut trailing_counts_null = true;
    'layers: for _ in 0..layer_count {
        let start = sectors.len();
        let Some(first_entry) = ltbl_entry(ltbl, entry_size, declared_total) else {
            truncated_table = true;
            break;
        };
        let count = u64::from(first_entry.additional_sector_count) + 1;
        for offset in 0..count {
            let Some(entry) = declared_total
                .checked_add(offset)
                .and_then(|index| ltbl_entry(ltbl, entry_size, index))
            else {
                truncated_table = true;
                spans.push(start..sectors.len());
                break 'layers;
            };
            // §4.7: only a layer's first entry counts further entries; a
            // non-zero count anywhere else is unaccounted-for structure.
            if offset > 0 && entry.additional_sector_count != 0 {
                trailing_counts_null = false;
            }
            sectors.push(entry);
        }
        spans.push(start..sectors.len());
        declared_total += count;
    }

    let layr_chunks = find(&real, b"LAYR");
    let lrov_chunks = find(&real, b"LROV");
    let layr_indices: HashSet<usize> = layr_chunks.iter().map(|chunk| chunk.index).collect();
    let lrov_indices: HashSet<usize> = lrov_chunks.iter().map(|chunk| chunk.index).collect();

    // §4.7: the declared count, the sum over each layer's first entry, and the
    // end of the table are one number read three ways.
    let table_ends_here =
        u128::from(declared_total) * u128::from(entry_size) + 16 == ltbl.len() as u128;
    checks.check(
        "ltbl.entry_count",
        u64::from(entry_count) == declared_total && trailing_counts_null && table_ends_here,
    );
    // §11.2: the entries describe every layer the header declares and no other,
    // so the walk from layer 0 stops inside the table. A grouping that runs off
    // the end never reaches the last layer, whether or not the counts add up.
    checks.check("ltbl.layer_index_range", !truncated_table);
    // §4.7: a layer's sectors ascend by id, and no id repeats within a layer.
    // Ascending is weak here and uniqueness is the separate rule, so a swap and
    // a repeat are different defects rather than one reported twice.
    checks.check(
        "ltbl.sector_ids_ascending",
        spans.iter().all(|span| {
            sectors[span.clone()]
                .windows(2)
                .all(|pair| pair[0].sector_id <= pair[1].sector_id)
        }),
    );
    checks.check(
        "ltbl.sector_id_unique",
        spans.iter().all(|span| {
            let ids: Vec<u32> = sectors[span.clone()]
                .iter()
                .map(|entry| entry.sector_id)
                .collect();
            (0..ids.len()).all(|i| (i + 1..ids.len()).all(|j| ids[i] != ids[j]))
        }),
    );
    checks.check(
        "ltbl.first_entry_is_sector_zero",
        spans.iter().all(|span| sectors[span.start].sector_id == 0),
    );
    // §4.7: `first_layr` names a `LAYR` chunk, and `first_lrov` is `0` or names
    // an `LROV` chunk. Both are directory indices - positions in the whole
    // directory, not in the live chunks - which is why [`Chunk`] carries one.
    // The rule that `0` means "no overrides" is decided in the content phase,
    // where the override sets the entries point at have been read: an entry's
    // `0` can only be contradicted by a set that is applied nowhere.
    checks.check(
        "ltbl.first_layr_in_range",
        sectors
            .iter()
            .all(|entry| layr_indices.contains(&(entry.first_layr as usize))),
    );
    checks.check(
        "ltbl.first_lrov_in_range",
        sectors.iter().all(|entry| {
            entry.first_lrov == 0 || lrov_indices.contains(&(entry.first_lrov as usize))
        }),
    );
    // §4.1: `MULTI_SECTOR` is set exactly when at least one layer carries more
    // than one sector - the flag is the file's claim about its own layer table.
    checks.check(
        "head.multi_sector_flag",
        (flags & 0x02 != 0) == spans.iter().any(|span| span.len() > 1),
    );

    // ---- LAYR -----------------------------------------------------------
    // One chunk per (sector, layer group): a clear `layr_version`, then a single
    // zstd frame over the group's concatenated layer data (§4.9). There is no
    // block table: the chunk is the unit, and the frame's own header carries the
    // output size a reader allocates from.
    if layr_chunks.is_empty() {
        return checks;
    }
    checks.check(
        "layr.version",
        layr_chunks
            .iter()
            .all(|chunk| u32_at(stored(raw, chunk.entry), 0) == Some(1)),
    );

    // ---- LHAS -----------------------------------------------------------
    // The leaf table and its root are plaintext even when the layer data is
    // sealed, so the root can be recomputed without a key.
    let mut leaves: Vec<Vec<u8>> = Vec::new();
    if let Some(lhas_chunk) = lhas_entries.first() {
        let lhas = stored(raw, lhas_chunk.entry);
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
        // §11.1: the payload has to hold its fixed header and one hash per
        // leaf it declares, or the hashes below are read past the end.
        checks.check(
            "lhas.frame",
            38 + u128::from(leaf_count) * u128::from(hash_size) <= lhas.len() as u128,
        );
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
    // Each `LAYR` chunk's frame once it is in the clear, by directory index.
    let mut layr_plain: HashMap<usize, Vec<u8>> = HashMap::new();
    let mut unit_index_bound = true;
    let mut tag_ok = true;
    let mut halt_crypto = false;
    let mut halt_content = false;

    let auth_chunk = if auth_entries.len() == 1 {
        auth_entries.first().copied()
    } else {
        None
    };
    if crypto_engaged {
        checks.check("presence.auth", !encrypted_flag || auth_entries.len() == 1);
        if let Some(auth_chunk) = auth_chunk {
            let auth = stored(raw, auth_chunk.entry);
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
            // §4.4: the payload holds the fixed prefix and both sections it
            // declares - the mode bits are what say which sections there are.
            let ok_frame = checks.check(
                "auth.frame",
                head && u128::from(pw_len) + u128::from(mc_len) + 20 <= auth.len() as u128,
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
            if ok_version
                && ok_cipher
                && ok_frame
                && ok_mode
                && ok_password
                && ok_machine
                && ok_budget
            {
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
    let any_sealed = real
        .iter()
        .any(|chunk| chunk.entry.flags & SEALED_FLAG != 0);
    if (crypto_engaged || any_sealed) && !halt_crypto {
        let (ok, detail) = chunk_flag_report(&real, encrypted_flag);
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
            for chunk in &real {
                let sealable = SEALABLE_CHUNK_TYPES.contains(&&chunk.entry.ctype);
                if sealable && chunk.entry.ctype != *b"LAYR" && chunk.entry.flags & SEALED_FLAG != 0
                {
                    match open_unit(
                        &key,
                        &cipher_id,
                        &chunk.entry.ctype,
                        0,
                        stored(raw, chunk.entry),
                    ) {
                        Ok(plain) => {
                            decrypted.insert(chunk.entry.offset, plain);
                        }
                        Err(_) => tag_ok = false,
                    }
                }
            }
            for chunk in &layr_chunks {
                if chunk.entry.flags & SEALED_FLAG == 0 {
                    continue;
                }
                let container = stored(raw, chunk.entry);
                let frame = container
                    .get(LAYR_HEADER_SIZE as usize..)
                    .unwrap_or_default();
                // §9.3: a `LAYR` frame's AAD binds the chunk's directory index,
                // not a unit number inside the chunk - there is one unit, so an
                // all-zero index would let two chunks' ciphertexts be swapped.
                match open_unit(&key, &cipher_id, b"LAYR", chunk.index as u32, frame) {
                    Ok(plain) => {
                        layr_plain.insert(chunk.index, plain);
                    }
                    Err(_) => {
                        // A frame that opens under some *other* directory index
                        // is not corrupt: it was sealed against the wrong one,
                        // which is the binding defect rather than a tag
                        // failure. The plaintext it yields is the real one, so
                        // the rest of the run still sees this file's content.
                        match first_index_that_opens(
                            &key,
                            &cipher_id,
                            frame,
                            chunk.index,
                            chunk_count as usize,
                        ) {
                            Some((index, plain)) => {
                                unit_index_bound = false;
                                layr_plain.insert(index, plain);
                            }
                            None => tag_ok = false,
                        }
                    }
                }
            }
        } else {
            halt_crypto = true;
            halt_content = true;
        }
    }

    // ---- unit-index binding ---------------------------------------------
    // Recorded before the tag verdict: a frame bound to the wrong index does
    // verify its tag, so the two are different findings and this one is the
    // specific one.
    if crypto_engaged && !halt_crypto && !checks.check("crypt.unit_index_binding", unit_index_bound)
    {
        halt_content = true;
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

    // ---- META -----------------------------------------------------------
    // A payload that is not a JSON object is a shape rule of its own, and the
    // rules below still report for themselves: an object META never had cannot
    // carry the fields they look for, which is a second finding rather than a
    // reason to stop.
    let Some(meta_plain) = content.of(b"META") else {
        return checks;
    };
    let meta_json = parse_json(&meta_plain);
    checks.check("meta.json", matches!(meta_json, Some(Value::Object(_))));
    let meta = match meta_json {
        Some(Value::Object(fields)) => Value::Object(fields),
        _ => Value::Object(serde_json::Map::new()),
    };
    let mats = meta.get("materials");
    // The durations `SECT` used to carry are META's now (§4.2), so META's own
    // type rule covers them: one namespace, one check.
    let sector_defs = meta.get("sectors");
    checks.check(
        "meta.time_integer",
        time_fields_integer(&meta) && sectors_time_integer(sector_defs),
    );
    checks.check(
        "meta.required_fields",
        REQUIRED_META_FIELDS
            .iter()
            .all(|field| meta.get(field).is_some()),
    );
    checks.check(
        "meta.version",
        meta.get("meta_version")
            .is_some_and(|version| is_int(version) && version.as_i64() == Some(1)),
    );
    checks.check(
        "meta.exposure",
        meta.get("normal_exposure_ms").is_some_and(is_positive_int)
            && meta.get("bottom_exposure_ms").is_some_and(is_positive_int),
    );
    checks.check(
        "meta.layer_height",
        meta.get("layer_height_um").is_some_and(is_positive_number),
    );
    checks.check("meta.materials_shape", materials_shape_ok(mats));
    checks.check("meta.sectors_shape", sectors_shape_ok(sector_defs));
    checks.check(
        "meta.sector_material_index",
        sector_material_index_ok(sector_defs, mats),
    );
    checks.check("meta.cure_curve", cure_curve_ok(meta.get("cure_curve")));
    checks.check("meta.temperature_range", temperature_range_ok(&meta));

    // ---- PROF / LROV / PREV ---------------------------------------------
    // Optional content chunks. PROF and LROV go through the same
    // sealed/compressed path as META; PREV is uncompressed but may carry
    // its own ENCRYPTED bit (§4.6), independent of the file-level flag.
    if let Some(chunk) = first(&real, b"PROF") {
        let Some(prof_plain) = content.bytes(&chunk) else {
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
        checks.check(
            "prof.cure_curve",
            cure_curve_ok(settings.and_then(|settings| settings.get("cure_curve"))),
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

    // One `LROV` chunk per (layer, sector) that has overrides (§4.5). The
    // payload is a pure delta: the sparse timing fields that point overrides,
    // and nothing else - a sector's identity and its base timing live in
    // `META.sectors`, once, rather than on every layer that touches it.
    let mut lrov_bodies: BTreeMap<usize, Value> = BTreeMap::new();
    let mut lrov_json = true;
    {
        let mut plaintexts: Vec<Vec<u8>> = Vec::new();
        for chunk in &lrov_chunks {
            let Some(lrov_plain) = content.bytes(chunk) else {
                return checks;
            };
            match parse_json(&lrov_plain) {
                Some(Value::Object(fields)) => {
                    lrov_bodies.insert(chunk.index, Value::Object(fields));
                }
                // A payload this reader cannot apply is a shape defect, not a
                // capability statement: §4.5's refusal is prose, and the file
                // is wrong rather than merely unreadable to one reader.
                _ => lrov_json = false,
            }
            plaintexts.push(lrov_plain);
        }
        if !lrov_chunks.is_empty() {
            checks.check("lrov.json", lrov_json);
            checks.check(
                "lrov.time_integer",
                lrov_bodies.values().all(time_fields_integer),
            );
            // §4.7: each `LROV` chunk is one `(layer, sector)`'s override set.
            // Two rules read that, and they are different defects, so they are
            // different verdicts - each recorded here in the order the corpus
            // asserts, the "no overrides" claim first.
            let named: HashSet<usize> = sectors
                .iter()
                .filter(|entry| entry.first_lrov != 0)
                .map(|entry| entry.first_lrov as usize)
                .collect();
            // An entry's `0` says that pair has no overrides. What contradicts
            // it is an override set nothing applies: an `LROV` chunk no entry
            // names whose payload no named chunk carries. A duplicate of a set
            // that *is* applied contradicts nothing - those values are the
            // values a reader prints for the pair that names its twin.
            let applied: Vec<&[u8]> = lrov_chunks
                .iter()
                .zip(&plaintexts)
                .filter(|(chunk, _)| named.contains(&chunk.index))
                .map(|(_, plain)| plain.as_slice())
                .collect();
            checks.check(
                "ltbl.first_lrov_null",
                lrov_chunks
                    .iter()
                    .zip(&plaintexts)
                    .filter(|(chunk, _)| !named.contains(&chunk.index))
                    .all(|(_, plain)| applied.contains(&plain.as_slice())),
            );
            // Every `LROV` chunk is named by exactly one entry. A chunk nobody
            // names is a set that will never be applied; one that two entries
            // name would be applied to a pair it never described.
            let mut references: HashMap<u32, usize> = HashMap::new();
            for entry in &sectors {
                if entry.first_lrov != 0 {
                    *references.entry(entry.first_lrov).or_default() += 1;
                }
            }
            checks.check(
                "lrov.orphan",
                lrov_chunks
                    .iter()
                    .all(|chunk| references.get(&(chunk.index as u32)) == Some(&1)),
            );
            payloads.insert(*b"LROV", Payload::Many(plaintexts));
        }
    }

    // The values §8 resolves a point from, taken from the chunks this run just
    // parsed - so a sealed file is resolved from what its key unwrapped rather
    // than from the bytes on disk. A point's overrides are the `LROV` chunk its
    // table record points at, which is the only thing that binds one to a
    // `(layer, sector)`.
    let mut overrides: BTreeMap<(u32, u32), Value> = BTreeMap::new();
    for (layer, span) in spans.iter().enumerate() {
        for entry in &sectors[span.clone()] {
            if entry.first_lrov == 0 {
                continue;
            }
            if let Some(body) = lrov_bodies.get(&(entry.first_lrov as usize)) {
                overrides.insert((layer as u32, entry.sector_id), body.clone());
            }
        }
    }
    checks.timing = Some(TimingInputs {
        total_layers,
        meta,
        overrides,
    });

    let prev_entries = find(&real, b"PREV");
    if !prev_entries.is_empty() {
        checks.check(
            "prev.flags",
            prev_entries
                .iter()
                .all(|chunk| (chunk.entry.flags & 0x0F) <= 3 && (chunk.entry.flags >> 5) == 0),
        );
        let mut previews = Vec::new();
        for chunk in &prev_entries {
            let Some(plain) = content.bytes(chunk) else {
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
    // §4.11: the embedded scene is opaque to LUMEN, so §11.2 only asks a strict
    // reader to recognize which generation of VOXL it is holding. Whether the
    // scene is *valid* is VOXL's business: a print reader must never reject a
    // file over its embedded scene, so loose mode records nothing here.
    if let Some(chunk) = first(&real, b"VOXL") {
        let Some(voxl) = content.bytes(&chunk) else {
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
    // §4.12: vendor or future-standard extensions, any number of them. The
    // fixed frame is `ext_version (u32) || ext_type (4 bytes) || ext_data`, and
    // the payload is zstd-compressed unless the extension says otherwise. EXTD
    // is required neither to be sealed nor to be clear, and this reader
    // implements no extension semantics: a payload that will not decompress
    // cannot satisfy the frame at all, so it is reported as a frame failure
    // rather than raised.
    let extd_entries = find(&real, b"EXTD");
    if !extd_entries.is_empty() {
        let mut extensions: Vec<Option<Vec<u8>>> = Vec::new();
        for chunk in &extd_entries {
            extensions.push(payload_plain(raw, chunk.entry).ok());
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
        // Descriptor flags: bits 8-23 are `vendor_id` (§4.12), bit 24 is
        // `critical`; bits 0-3, 5-7 (bit 4 is the standard ENCRYPTED flag) and
        // 25-31 are reserved and must be 0.
        checks.check(
            "extd.flags",
            extd_entries
                .iter()
                .all(|chunk| (chunk.entry.flags & 0xFE00_00EF) == 0),
        );
        // `critical` is reader-relative: a reader that does not implement the
        // extension must refuse the file rather than print an approximation.
        // This reference validator implements no extension semantics, so every
        // critical EXTD is a file it must not accept.
        checks.check(
            "extd.critical",
            extd_entries
                .iter()
                .all(|chunk| (chunk.entry.flags & 0x0100_0000) == 0),
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
    // A dictionary the frames may use: a `ZDIC` chunk that declares one. A
    // null `ZDIC` - one whose `dict_size` is `0` - is a placeholder rather than
    // a dictionary, and §4.8 speaks of "more than one non-null" chunk, so it
    // neither supplies bytes nor demands that the frames report its id.
    let mut zdic_present = false;
    checks.check("zdic.single", zdic_entries.len() <= 1);
    if let Some(chunk) = zdic_entries.first() {
        let Some(zdic) = content.bytes(chunk) else {
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
        // §4.8: `dict_size` is bounded by zstd's own maximum, and the chunk has
        // to hold that many bytes.
        checks.check(
            "zdic.dict_size",
            dict_size <= 112_640 && u128::from(dict_size) + 12 <= zdic.len() as u128,
        );
        zdic_present = dict_size > 0;
    }
    let Ok(mut decoder) = Decoder::new(&dictionary) else {
        return checks;
    };

    // ---- LAYR frames ----------------------------------------------------
    // §4.9: one frame per chunk, its dictionary id the chunk's, its declared
    // content size the reader's allocation. The clear version field is not part
    // of the sealed unit, so a frame is the container minus its four bytes.
    let frame_of = |chunk: &Chunk| -> Option<&[u8]> {
        if chunk.entry.flags & SEALED_FLAG != 0 {
            layr_plain.get(&chunk.index).map(Vec::as_slice)
        } else {
            stored(raw, chunk.entry).get(LAYR_HEADER_SIZE as usize..)
        }
    };

    // The slices each chunk holds, for the bound a frame's declared size has to
    // fit inside: a reader sizes its buffer from that figure, so a file has to
    // justify it before it is allocated for.
    let mut slices_per_chunk: HashMap<usize, u64> = HashMap::new();
    for entry in &sectors {
        *slices_per_chunk
            .entry(entry.first_layr as usize)
            .or_default() += 1;
    }

    let mut content_sizes_present = true;
    let mut allocation_ok = true;
    let mut dict_ids: Vec<Option<u32>> = Vec::new();
    let mut frames_ok = true;
    let mut outputs: HashMap<usize, Vec<u8>> = HashMap::new();
    for chunk in &layr_chunks {
        let Some(frame) = frame_of(chunk) else {
            frames_ok = false;
            continue;
        };
        // Bytes that are not a frame header at all are the decompression
        // failure below rather than a missing content size, so each of the
        // rules owns a disjoint defect.
        if let Some(declared) = frame_content_size(frame) {
            if declared.is_none() {
                content_sizes_present = false;
            }
            // §11.3: grayscale REE costs at most about five bytes per pixel
            // plus framing, over the slices this chunk holds - the most the
            // output could plausibly be.
            let slices = slices_per_chunk
                .get(&chunk.index)
                .copied()
                .unwrap_or(0)
                .max(1);
            let bound =
                slices.saturating_mul((total_pixels as u64).saturating_mul(5).saturating_add(64));
            if declared.unwrap_or(0) > bound {
                allocation_ok = false;
            }
        }
        dict_ids.push(frame_dict_id(frame));
        let hint = usize::try_from(chunk.entry.usz).unwrap_or(usize::MAX);
        match decoder.decompress(frame, hint) {
            Ok(output) => {
                outputs.insert(chunk.index, output);
            }
            Err(_) => frames_ok = false,
        }
    }
    checks.check("layr.content_size_present", content_sizes_present);
    checks.check("layr.allocation_bound", allocation_ok);
    if zdic_present {
        // Every frame that reports a dictionary reports *this* one: §4.8
        // requires the one chunk to be the dictionary for all of them.
        //
        // A frame that reports none is not this rule's business - "no
        // dictionary was used" is the presence rule's, which decides whether a
        // file may carry a dictionary the frames do not use.
        checks.check(
            "layr.dict_id_match",
            dict_ids
                .iter()
                .all(|id| id.is_none_or(|id| id == 0 || id == dict_id)),
        );
        // §11.1 names the same disagreement from the dictionary's side. It is
        // one defect with two names, so it is recorded under the frames' rule
        // first - a file that breaks it is reported there - and this verdict is
        // recorded for a reader that looks for the dictionary's half.
        checks.check(
            "zdic.dict_id_match",
            dict_ids
                .iter()
                .all(|id| id.is_none_or(|id| id == 0 || id == dict_id)),
        );
    } else {
        checks.check(
            "layr.dict_id_absent",
            dict_ids.iter().all(|id| *id == Some(0)),
        );
    }
    // §4.8 / §11.1: a dictionary is present exactly when the frames use one.
    // Recorded after the two rules that say what each side may be, so a file
    // that breaks one of those is reported under it rather than here.
    let frames_use_dictionary = dict_ids.iter().any(|id| id.is_some_and(|id| id != 0));
    checks.check("presence.zdic", frames_use_dictionary == zdic_present);
    checks.check("layr.frame_decompressed_size", frames_ok);

    // ---- slices ---------------------------------------------------------
    // §4.7: a slice lies inside its chunk's decompressed output, and two slices
    // of one chunk do not overlap - the chunk is shared by the layer group it
    // holds, so its slices are the only thing that tells them apart.
    checks.check(
        "ltbl.offset_within_chunk",
        sectors.iter().all(|entry| {
            outputs
                .get(&(entry.first_layr as usize))
                .is_some_and(|output| {
                    u128::from(entry.data_offset) + u128::from(entry.data_size)
                        <= output.len() as u128
                })
        }),
    );
    checks.check("ltbl.slices_disjoint", slices_disjoint(&sectors));

    // ---- layer data / leaf hashes ---------------------------------------
    // A layer's data is its sectors' slices concatenated in ascending
    // `sector_id` - the order the table lists them in (§4.10).
    let mut layers: Vec<Vec<u8>> = Vec::with_capacity(spans.len());
    for span in &spans {
        let mut data = Vec::new();
        for entry in &sectors[span.clone()] {
            let Some(output) = outputs.get(&(entry.first_layr as usize)) else {
                continue;
            };
            data.extend_from_slice(at(
                output,
                u128::from(entry.data_offset),
                u128::from(entry.data_size),
            ));
        }
        layers.push(data);
    }
    if strict && !leaves.is_empty() {
        let matched = (0..layer_count as usize).all(|index| {
            match (layers.get(index), leaves.get(index)) {
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
    let mut partition_ok = true;
    for (layer, span) in spans.iter().enumerate() {
        let mut masks: Vec<Vec<u8>> = Vec::new();
        for entry in &sectors[span.clone()] {
            let Some(output) = outputs.get(&(entry.first_layr as usize)) else {
                continue;
            };
            let slice = at(
                output,
                u128::from(entry.data_offset),
                u128::from(entry.data_size),
            );
            // §4.7: a (layer, sector) with no bytes carries no tag and no mask -
            // that is the canonical encoding of "nothing here", not a defect.
            if slice.is_empty() {
                continue;
            }
            let tag = slice[0];
            let body = &slice[1..];
            let where_at = || format!("layer {layer}, sector {}", entry.sector_id);
            let (mask, end, violations) = match tag {
                0x00 => match ree::binary(body, total_pixels) {
                    Ok(decoded) => decoded,
                    Err(error) => {
                        truncated(&mut hits, &mut detail, &where_at(), error);
                        continue;
                    }
                },
                0x01 => match ree::grayscale(body, total_pixels) {
                    Ok((mask, end, mut violations)) => {
                        if strict && mask.iter().all(|pixel| *pixel == 0 || *pixel == 255) {
                            violations.push(Violation {
                                code: "ree.grayscale_all_binary",
                                message: Some("binary content encoded as grayscale REE"),
                            });
                        }
                        (mask, end, violations)
                    }
                    Err(error) => {
                        truncated(&mut hits, &mut detail, &where_at(), error);
                        continue;
                    }
                },
                0x02 => match ree::split(body, total_pixels) {
                    Ok((mask, end, mut violations)) => {
                        // The overlay is already applied to this mask, so a
                        // mask that is still all-binary is a slice with no AA
                        // pixels to overlay: §5.6 stores it as tag 0x00.
                        if strict && mask.iter().all(|pixel| *pixel == 0 || *pixel == 255) {
                            violations.push(Violation {
                                code: "ree.split_all_binary",
                                message: Some("binary content encoded as split REE"),
                            });
                        }
                        (mask, end, violations)
                    }
                    Err(error) => {
                        truncated(&mut hits, &mut detail, &where_at(), error);
                        continue;
                    }
                },
                _ => {
                    hits.insert("ree.tag");
                    detail.entry("ree.tag").or_insert_with(|| {
                        format!("{}: unknown encoding tag {tag:#04X}", where_at())
                    });
                    continue;
                }
            };
            for violation in violations {
                hits.insert(violation.code);
                if let Some(message) = violation.message {
                    detail
                        .entry(violation.code)
                        .or_insert_with(|| format!("{}: {message}", where_at()));
                }
            }
            if end != body.len() {
                hits.insert("ree.no_trailing_bytes");
                detail.entry("ree.no_trailing_bytes").or_insert_with(|| {
                    format!("{}: trailing bytes after the REE stream", where_at())
                });
            }
            masks.push(mask);
        }
        // §7.3 survives the layout change: two sectors of one layer may not
        // paint the same pixel, whether their masks came from one chunk or two.
        for (i, left) in masks.iter().enumerate() {
            for right in &masks[i + 1..] {
                if left.iter().zip(right).any(|(a, b)| *a != 0 && *b != 0) {
                    partition_ok = false;
                }
            }
        }
    }

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

    checks.layers = layers;
    checks.payloads = payloads;
    checks.check("__checks_complete", true);
    checks
}

/// The directory index a sealed frame opens under when its own index does not
/// open it, with the plaintext it yields. `None` when the frame opens under no
/// index at all, which makes it a tag failure rather than a binding one.
fn first_index_that_opens(
    key: &[u8; 32],
    cipher_id: &[u8; 4],
    frame: &[u8],
    own_index: usize,
    chunk_count: usize,
) -> Option<(usize, Vec<u8>)> {
    (0..chunk_count)
        .filter(|index| *index != own_index)
        .find_map(|index| {
            open_unit(key, cipher_id, b"LAYR", index as u32, frame)
                .ok()
                .map(|plain| (index, plain))
        })
}

/// Record a stream that could not be read at all: the rule it broke, with the
/// decoder's own wording for why.
fn truncated(
    hits: &mut HashSet<&'static str>,
    detail: &mut HashMap<&'static str, String>,
    at: &str,
    error: ree::DecodeError,
) {
    hits.insert(error.name);
    detail
        .entry(error.name)
        .or_insert_with(|| format!("{at}: {}", error.message));
}

/// Whether, within each `LAYR` chunk, no two slices overlap.
///
/// A slice of no bytes is an empty range and overlaps nothing, so the entries
/// that carry no data are left out rather than counted as a collision at the
/// offset they happen to name.
fn slices_disjoint(sectors: &[SectorEntry]) -> bool {
    let mut spans: HashMap<u32, Vec<(u64, u64)>> = HashMap::new();
    for entry in sectors {
        if entry.data_size == 0 {
            continue;
        }
        spans.entry(entry.first_layr).or_default().push((
            entry.data_offset,
            entry.data_offset + u64::from(entry.data_size),
        ));
    }
    spans.values().all(|ranges| {
        let mut sorted = ranges.clone();
        sorted.sort_unstable();
        sorted.windows(2).all(|pair| pair[0].1 <= pair[1].0)
    })
}

/// The reader's view of a chunk's plaintext.
struct Content<'a> {
    raw: &'a [u8],
    real: &'a [Chunk<'a>],
    decrypted: &'a HashMap<u64, Vec<u8>>,
}

impl Content<'_> {
    /// A chunk's plaintext: decrypted when it is sealed, decompressed when it
    /// is compressed. `None` where the oracle raises and the run stops.
    fn bytes(&self, chunk: &Chunk) -> Option<Vec<u8>> {
        if chunk.entry.flags & SEALED_FLAG != 0 {
            let blob = self.decrypted.get(&chunk.entry.offset)?;
            if COMPRESSED_TYPES.contains(&&chunk.entry.ctype) {
                let capacity = usize::try_from(chunk.entry.usz).unwrap_or(usize::MAX);
                return Decoder::new(&[]).ok()?.decompress(blob, capacity).ok();
            }
            return Some(blob.clone());
        }
        payload_plain(self.raw, chunk.entry).ok()
    }

    /// The plaintext of the first chunk of a type.
    fn of(&self, ctype: &[u8; 4]) -> Option<Vec<u8>> {
        let chunk = self.real.iter().find(|chunk| &chunk.entry.ctype == ctype)?;
        self.bytes(chunk)
    }
}

fn parse_json(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// The stored payload bytes; for LAYR this is the plaintext container.
fn stored<'a>(raw: &'a [u8], entry: &crate::container::Entry) -> &'a [u8] {
    at(raw, u128::from(entry.offset), u128::from(entry.size()))
}

/// Stored payload with chunk-level compression undone.
///
/// A fresh decoder each time, as the oracle uses: a chunk payload is not a
/// continuation of anything.
fn payload_plain(
    raw: &[u8],
    entry: &crate::container::Entry,
) -> Result<Vec<u8>, crate::decompress::ZstdError> {
    let blob = stored(raw, entry);
    if entry.csz == 0 {
        return Ok(blob.to_vec());
    }
    let capacity = usize::try_from(entry.usz).unwrap_or(usize::MAX);
    Decoder::new(&[])?.decompress(blob, capacity)
}

fn find<'a>(real: &[Chunk<'a>], ctype: &[u8; 4]) -> Vec<Chunk<'a>> {
    real.iter()
        .copied()
        .filter(|chunk| &chunk.entry.ctype == ctype)
        .collect()
}

fn count(real: &[Chunk], ctype: &[u8; 4]) -> usize {
    real.iter()
        .filter(|chunk| &chunk.entry.ctype == ctype)
        .count()
}

fn first<'a>(real: &[Chunk<'a>], ctype: &[u8; 4]) -> Option<Chunk<'a>> {
    real.iter()
        .copied()
        .find(|chunk| &chunk.entry.ctype == ctype)
}

fn is_nonempty_string(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

fn is_positive_int(value: &Value) -> bool {
    is_int(value) && value.as_f64().is_some_and(|n| n > 0.0)
}
