//! The corpus: the thirteen valid vectors, the deliberate defects, and the manifest.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::container;
use crate::json;
use crate::obj;
use crate::payload::{self, Extd, ProfOverrides, ProfSettings};
use crate::png;
use crate::vector::{self, Built, CryptoSpec, Override, Role, VectorSpec};
use crate::{FORMAT_REVISION, ZSTD_LAYER_LEVEL, ZSTD_SMALL_LEVEL};

/// What the manifest says about the bytes an implementer can and cannot rely on.
const NOTE: &str = "Compressed payload bytes depend on the zstd version and level. \
Uncompressed structures (HEAD, AUTH, LTBL, LAYR's version field, LHAS, REE \
streams, directory, trailer) are exact. Sealed units are exact too: every nonce, \
salt and key is derived from a fixed SHAKE-256 seed, so regeneration is \
deterministic. Those values are public test data; real encoders must draw them from \
a CSPRNG.";

/// Generate the corpus and print what was written.
///
/// The exit code is the producer's: zero when the whole corpus was written.
pub fn run() -> i32 {
    assert_eq!(
        crc32c::crc32c(b"123456789"),
        0xE306_9283,
        "CRC-32C self-test failed"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors");
    let valid_dir = root.join("valid");
    let invalid_dir = root.join("invalid");
    fs::create_dir_all(&valid_dir).expect("valid directory");
    fs::create_dir_all(&invalid_dir).expect("invalid directory");

    let mut manifest_valid: Vec<Value> = Vec::new();
    for built in valid_vectors() {
        let name = built.meta["name"]
            .as_str()
            .expect("a named vector")
            .to_owned();
        let file = format!("valid/{name}.lumen");
        fs::write(valid_dir.join(format!("{name}.lumen")), &built.raw).expect("vector file");
        let meta = json::merge(built.meta.clone(), &[("file", Value::from(file.clone()))]);
        println!(
            "wrote {:<28} {:>6} bytes, {:>2} chunks, {} LAYR chunks",
            file,
            built.raw.len(),
            meta["chunk_count"].as_u64().expect("a chunk count"),
            meta["layr_chunks"]
                .as_array()
                .expect("a LAYR chunk list")
                .len()
        );
        manifest_valid.push(meta);
    }

    let mut manifest_invalid: Vec<Value> = Vec::new();

    // The invalid vectors are cut from the files above.
    let binary_basic = binary_basic();
    let multi = multi_sector();
    let overridden = layer_overrides();
    let dictionary = dict_multi_block();
    let encrypted_password = encrypted_password();
    let encrypted_crypto = encrypted_password.meta["crypto"].clone();
    let ltbl = binary_basic.layout.offset(b"LTBL");

    // x01: the header's entry_count does not match the table
    let mut b = binary_basic.raw.clone();
    let entry_count = container::read_u32(&b, ltbl + container::LTBL_ENTRY_COUNT);
    container::write_u32(&mut b, ltbl + container::LTBL_ENTRY_COUNT, entry_count + 1);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-entry-count",
            "LTBL's entry_count says seven while the table holds six entries, so the table does not end where the header says it does.",
            "ltbl.entry_count",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x02: an entry that claims a following entry that is not there
    let mut b = binary_basic.raw.clone();
    let last_entry = ltbl + container::LTBL_HEADER_SIZE + 5 * container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, last_entry + container::LTBL_ADDITIONAL_SECTORS, 1);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-entry-count-overrun",
            "The last entry claims one further entry for its layer, so the sum of 1 + additional_sector_count over the layers' first entries runs one past the table the header declares.",
            "ltbl.entry_count",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x03: sector ids that descend within a layer
    let three_sector = three_sector_source();
    let three_ltbl = three_sector.layout.offset(b"LTBL");
    let mut b = three_sector.raw.clone();
    let first = three_ltbl + container::LTBL_HEADER_SIZE + container::LTBL_ENTRY_SIZE;
    let second = first + container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, first + container::LTBL_SECTOR_ID, 2);
    container::write_u32(&mut b, second + container::LTBL_SECTOR_ID, 1);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-sector-ids-descending",
            "Layer 0 carries sectors 0, 1 and 2, and its last two entries are written in the order 0, 2, 1: the ids descend where the table requires them to ascend.",
            "ltbl.sector_ids_ascending",
            container::repack(&b, &three_sector.layout),
        ),
    );

    // x04: the same sector twice in one layer
    let multi_ltbl = multi.layout.offset(b"LTBL");
    let mut b = multi.raw.clone();
    let second = multi_ltbl + container::LTBL_HEADER_SIZE + container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, second + container::LTBL_SECTOR_ID, 0);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-sector-id-duplicate",
            "Layer 0's two entries both name sector 0, so the layer carries one sector twice instead of two sectors once.",
            "ltbl.sector_id_unique",
            container::repack(&b, &multi.layout),
        )
        .base("multi-sector"),
    );

    // x05: a layer whose first entry is not sector 0
    let mut b = multi.raw.clone();
    let single = multi_ltbl + container::LTBL_HEADER_SIZE + 2 * container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, single + container::LTBL_SECTOR_ID, 3);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-first-entry-not-sector-zero",
            "Layer 1's only entry names sector 3. Sector 0 is primary and implicitly present on every layer with data, so a layer's first entry is sector 0's.",
            "ltbl.first_entry_is_sector_zero",
            container::repack(&b, &multi.layout),
        )
        .base("multi-sector"),
    );

    // x06: first_layr that is not a LAYR chunk
    let mut b = binary_basic.raw.clone();
    container::write_u32(
        &mut b,
        ltbl + container::LTBL_HEADER_SIZE + container::LTBL_FIRST_LAYR,
        2,
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-first-layr-not-layr",
            "Entry 0 names directory index 2, which is the LTBL chunk itself, so the slice has no frame to be read out of.",
            "ltbl.first_layr_in_range",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x07: a slice that runs past the end of its frame
    let mut b = binary_basic.raw.clone();
    let entry = ltbl + container::LTBL_HEADER_SIZE + container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, entry + container::LTBL_DATA_SIZE, 0x00FF_FFFF);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-offset-past-frame",
            "Entry 1 claims 0x00FFFFFF bytes even though it is the last slice of the frame it names, so its end lies past the frame's decompressed output.",
            "ltbl.offset_within_chunk",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x08: two slices of one frame that overlap
    let mut b = binary_basic.raw.clone();
    let third = ltbl + container::LTBL_HEADER_SIZE + 3 * container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, third + container::LTBL_DATA_OFFSET, 0);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-slices-overlap",
            "Entries 2 and 3 are two slices of one frame and both now start at offset 0, so layers 2 and 3 would be read out of the same bytes.",
            "ltbl.slices_disjoint",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x09: an entry that says a point has no overrides while its chunk is there
    let overridden_ltbl = overridden.layout.offset(b"LTBL");
    let mut b = overridden.raw.clone();
    let entry = overridden_ltbl + container::LTBL_HEADER_SIZE + 2 * container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, entry + container::LTBL_FIRST_LROV, 0);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-first-lrov-zero",
            "Layer 2's entry names no LROV chunk although the file carries one for that point: first_lrov is 0 exactly when a (layer, sector) has no overrides. Because an LROV payload carries no identity, that chunk is now unreachable - this file violates lrov.orphan as well, and the check order decides which is reported.",
            "ltbl.first_lrov_null",
            container::repack(&b, &overridden.layout),
        )
        .base("layer-overrides"),
    );

    // x10: first_lrov that is not an LROV chunk
    let mut b = binary_basic.raw.clone();
    container::write_u32(
        &mut b,
        ltbl + container::LTBL_HEADER_SIZE + container::LTBL_FIRST_LROV,
        2,
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-first-lrov-not-lrov",
            "Entry 0 names directory index 2, which is the LTBL chunk, as the override set of its point, so the entry points at a chunk that carries no overrides.",
            "ltbl.first_lrov_in_range",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x11: two entries naming one LROV chunk
    let mut b = overridden.raw.clone();
    let shared = container::read_u32(
        &b,
        overridden_ltbl
            + container::LTBL_HEADER_SIZE
            + 2 * container::LTBL_ENTRY_SIZE
            + container::LTBL_FIRST_LROV,
    );
    container::write_u32(
        &mut b,
        overridden_ltbl + container::LTBL_HEADER_SIZE + container::LTBL_FIRST_LROV,
        shared,
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-shared-chunk",
            "Entry 0 names the same LROV chunk as layer 2's entry, so one override set is claimed by two points at once. The payload carries no layer and no sector, so a reader cannot tell which of the two it belongs to - it would have to apply layer 2's override to layer 0 as well, or ignore one of them.",
            "lrov.orphan",
            container::repack(&b, &overridden.layout),
        )
        .base("layer-overrides"),
    );

    // x12: an LROV chunk no entry names
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-orphan-chunk",
            "The file carries an LROV chunk that no entry names. An LROV payload carries no layer and no sector - the entry that names the chunk is what places it - so these overrides can never be applied to anything, and a reader that silently ignores them prints the wrong timings.",
            "lrov.orphan",
            orphan_lrov_vector(),
        ),
    );

    // x13: an LROV payload that is not a JSON object
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-not-json",
            "An LROV payload is truncated JSON, so the override set cannot be read at all.",
            "lrov.json",
            lrov_raw_vector(b"{ \"normal_exposure_ms\": 2800,"),
        ),
    );

    // x14: a fractional wait time in an override
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-wait-fractional",
            "An LROV payload carries wait_time_before_cure_ms = 500.5. A wait time is a whole \
number of milliseconds, so a fractional value is not a duration this format \
can express.",
            "lrov.time_integer",
            override_vector(vec![Override {
                layer: 2,
                sector_id: 0,
                fields: vec![
                    ("normal_exposure_ms", Value::from(2800)),
                    ("wait_time_before_cure_ms", Value::from(500.5)),
                ],
            }]),
        ),
    );

    // x15: the non-canonical run_count == 0 all-black form (decodable, not canonical)
    let source = vector::build_vector(&VectorSpec {
        name: "x-source",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 0, 0)]),
        layers_per_chunk: 2,
        force_run_count_zero: vec![0],
        ..Default::default()
    });
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "run-count-zero-all-black",
            "Layer 0 stores all-black as tag 0x00 with run_count 0 instead of the empty-layer form.",
            "ree.no_run_count_zero",
            source.raw,
        )
        .strict_only(),
    );

    // x16: an all-binary slice stored as split REE, whose overlay is empty (strict)
    let source = vector::build_vector(&VectorSpec {
        name: "x-source",
        description: "source",
        display: (64, 48),
        layers: vec![
            // Layer 0 is one run of 0xFF under tag 0x02: the stream a strict
            // reader rejects, everything else about the file conforming.
            vec![vec![(0, 3072, 255)]],
            vec![vec![(0, 300, 255)]],
            vec![vec![(0, 100, 128)]],
            vec![vec![(500, 600, 255)]],
        ],
        layers_per_chunk: 2,
        force_split: vec![0],
        ..Default::default()
    });
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "split-all-binary",
            "Layer 0 is one run of 0xFF stored as tag 0x02 with an empty overlay, where section 5.6 requires tag 0x00 for a slice whose pixels are all 0x00/0xFF: the split form has no anti-aliasing to carry and is strictly larger.",
            "ree.split_all_binary",
            source.raw,
        )
        .strict_only(),
    );

    // x17: a LAYR container whose version is not 1
    let mut b = binary_basic.raw.clone();
    container::write_u32(&mut b, layr_of(&binary_basic), 2);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-container-version",
            "A LAYR container declares version 2, which no reader implements; the frame behind it is well formed, so only the version refuses the file.",
            "layr.version",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x18: a frame that declares no decompressed size
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-content-size-absent",
            "The LAYR frames are compressed without their content size. A writer MUST declare it (spec 4.9), because the descriptor's size_uncompressed is the container's length and the reader has nothing else to size the frame's output from.",
            "layr.content_size_present",
            frame_without_content_size(),
        ),
    );

    // x19: a frame whose declared size is not its output size
    let mut b = binary_basic.raw.clone();
    let off = layr_of(&binary_basic);
    let (at, width) = content_size_field(&b[off + 4..]);
    assert_eq!(width, 1, "this vector patches a one-byte content size");
    let declared = b[off + 4 + at];
    b[off + 4 + at] = declared + 1;
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-frame-size-lie",
            "The first LAYR frame's header declares one byte more than the frame decompresses to, so its output cannot be allocated or checked against the declaration.",
            "layr.frame_decompressed_size",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x20: a frame that will not decompress at all
    let mut b = binary_basic.raw.clone();
    let block_header = off + 4 + 6;
    b[block_header] |= 0x06;
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-frame-corrupt",
            "The first block header of the first LAYR frame is rewritten to the reserved block type 3, so the frame cannot be decompressed.",
            "layr.frame_decompressed_size",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x21: frames whose dictionary id is not the ZDIC chunk's
    let zdic = dictionary.layout.offset(b"ZDIC");
    let mut b = dictionary.raw.clone();
    let dict_id = container::read_u32(&b, zdic + 4);
    container::write_u32(&mut b, zdic + 4, dict_id + 1);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-dict-id-mismatch",
            "ZDIC.dict_id is rewritten while the frames keep the id of the dictionary they were compressed with, so every LAYR frame disagrees with the file's dictionary.",
            "layr.dict_id_match",
            container::repack(&b, &dictionary.layout),
        )
        .base("dict-multi-block"),
    );

    // x22: frames that name a dictionary the file does not carry
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-dict-id-without-zdic",
            "The frames are compressed with a trained dictionary but the file carries no ZDIC chunk, so their dictionary ids name a dictionary no reader can find.",
            "layr.dict_id_absent",
            dictionary_without_zdic(),
        ),
    );

    // x23: sealed frames bound to a unit index that is not their chunk's
    let wrong_unit = vector::build_encrypted_vector(
        &VectorSpec {
            name: "x-unit-index",
            description: "source",
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 300, 255)]),
            layers_per_chunk: 2,
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "A256",
            mode: 1,
            bad_unit_index: true,
            ..Default::default()
        },
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-unit-index-binding",
            "Every sealed LAYR frame is bound to unit index 0 instead of the directory index of the chunk that carries it. Each frame is intact, but a reader that authenticates it under the chunk's own index must refuse the file - which is what stops a ciphertext from being swapped between two LAYR chunks, since with one unit per chunk an all-zero index would authenticate in either place.",
            "crypt.unit_index_binding",
            wrong_unit.raw,
        )
        .crypto(wrong_unit.meta["crypto"].clone()),
    );

    // x24: the walk reaches fewer layers than the header declares
    let mut b = multi.raw.clone();
    let layer_one = multi_ltbl + container::LTBL_HEADER_SIZE + 2 * container::LTBL_ENTRY_SIZE;
    container::write_u32(&mut b, layer_one + container::LTBL_ADDITIONAL_SECTORS, 1);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "ltbl-layer-index-range",
            "Layer 1's entry claims one further entry, so the walk takes layer 1 and layer 2 for one layer and reaches layer 2 of a four-layer file; the entries no longer cover every layer the header declares. The merged layer also holds sector 0 twice, which is what the entries it swallowed carry.",
            "ltbl.layer_index_range",
            container::repack(&b, &multi.layout),
        )
        .base("multi-sector"),
    );

    // x25: a frame that declares far more output than its slices justify
    let bound = allocation_bound_source();
    let mut b = bound.raw.clone();
    let frame = layr_of(&bound) + 4;
    let (at, width) = content_size_field(&b[frame..]);
    assert_eq!(width, 4, "this vector patches a four-byte content size");
    b[frame + at..frame + at + width].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layr-allocation-bound",
            "The file's only LAYR frame declares a decompressed size of 2147483647 bytes, some four thousand times what the slices pointing into it could hold, so a reader that sizes its buffer from the declaration allocates two gigabytes for a layer group of a 64 by 48 display.",
            "layr.allocation_bound",
            container::repack(&b, &bound.layout),
        ),
    );

    // x26: a ZDIC chunk no frame uses
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "presence-zdic-unused",
            "The file carries a ZDIC chunk while every LAYR frame declares no dictionary (dictionary id 0), so the dictionary is present but nothing in the file refers to it.",
            "presence.zdic",
            unused_dictionary(),
        ),
    );

    // x27: a sector list that names one sector twice
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "meta-sectors-shape",
            "META.sectors has two entries with sector_id 1, so the sector's timing is defined twice over.",
            "meta.sectors_shape",
            sectors_shape_vector(),
        ),
    );

    // x28: a sector naming a material the library does not have
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "meta-sector-material-index",
            "META.sectors[0].material_index is 3 while META.materials holds one entry, so the sector names a material that is not there.",
            "meta.sector_material_index",
            sector_material_vector(),
        ),
    );

    // x29: merkle root does not match the leaf table
    let mut b = binary_basic.raw.clone();
    let lhas = binary_basic.layout.offset(b"LHAS");
    b[lhas + 6] ^= 0xFF;
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "merkle-root-mismatch",
            "One byte of merkle_root is flipped, so recomputation from layer_hashes disagrees.",
            "lhas.root_recompute",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x30: layer hash does not match the layer bytes (root recomputed to stay consistent)
    let mut b = binary_basic.raw.clone();
    let leaves_off = lhas + 38;
    let n_layers = container::read_u32(&b, lhas + 2) as usize;
    let mut leaves: Vec<[u8; 32]> = (0..n_layers)
        .map(|i| {
            b[leaves_off + 32 * i..leaves_off + 32 * (i + 1)]
                .try_into()
                .expect("a leaf")
        })
        .collect();
    leaves[0][0] ^= 0xFF;
    for (i, leaf) in leaves.iter().enumerate() {
        b[leaves_off + 32 * i..leaves_off + 32 * (i + 1)].copy_from_slice(leaf);
    }
    b[lhas + 6..lhas + 38].copy_from_slice(&crate::hash::merkle_root(&leaves));
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layer-hash-mismatch",
            "Layer 0's stored leaf hash is altered and merkle_root recomputed to match, so only hashing the actual bytes catches it.",
            "lhas.leaf_match",
            container::repack(&b, &binary_basic.layout),
        )
        .strict_only()
        .base("binary-basic"),
    );

    // x31: the MULTI_SECTOR flag cleared in a file whose layers carry two sectors
    let mut b = multi.raw.clone();
    let flags = container::read_u32(&b, 20);
    container::write_u32(&mut b, 20, flags & !container::FLAG_MULTI_SECTOR);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "multi-sector-flag-clear",
            "The file's layers carry two sectors but the header does not set MULTI_SECTOR, so a reader that trusts the flag prints one sector per layer and never notices the rest.",
            "head.multi_sector_flag",
            container::repack(&b, &multi.layout),
        )
        .base("multi-sector"),
    );

    // x32: the MULTI_SECTOR flag set in a file that carries one sector per layer
    let mut b = binary_basic.raw.clone();
    let flags = container::read_u32(&b, 20);
    container::write_u32(&mut b, 20, flags | container::FLAG_MULTI_SECTOR);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "multi-sector-flag-set",
            "No layer of the file carries more than one sector, but the header sets MULTI_SECTOR, so the flag promises a structure the file does not have.",
            "head.multi_sector_flag",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x33: corrupted trailer CRC (the only failure that is not repacked)
    let mut b = binary_basic.raw.clone();
    b[binary_basic.layout.trailer_offset + 4] ^= 0xFF;
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "trailer-crc-mismatch",
            "The trailer CRC-32C does not match the file bytes.",
            "trailer.crc32c",
            b,
        )
        .base("binary-basic"),
    );

    // x34: a fractional duration. Durations are exact whole milliseconds, so a
    // value with a fractional part is not a duration the format can carry; the
    // file is otherwise valid, so the type rule is the only thing wrong with it.
    let fractional = vector::build_vector(&VectorSpec {
        name: "x-meta-fractional",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 255, 255)]),
        layers_per_chunk: 2,
        meta_extra: vec![("normal_exposure_ms", Value::from(2500.5))],
        ..Default::default()
    });
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "meta-exposure-fractional",
            "META carries normal_exposure_ms = 2500.5. Durations are exact whole \
milliseconds, so a fractional value is not a duration this format can express.",
            "meta.time_integer",
            fractional.raw,
        ),
    );

    // e01: the ENCRYPTED header flag with no AUTH chunk at all
    let mut b = binary_basic.raw.clone();
    let header_flags = container::read_u32(&b, 20);
    container::write_u32(&mut b, 20, header_flags | container::FLAG_ENCRYPTED);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "encrypted-flag-without-auth",
            "The file header sets ENCRYPTED but there is no AUTH chunk, so no session key can ever be derived.",
            "presence.auth",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // e02: an unrecognized cipher
    let auth = encrypted_password.layout.offset(b"AUTH");
    let mut b = encrypted_password.raw.clone();
    b[auth..auth + 4].copy_from_slice(b"XXXX");
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "auth-cipher-unknown",
            "AUTH.cipher_id is XXXX, which names no algorithm.",
            "auth.cipher_known",
            container::repack(&b, &encrypted_password.layout),
        )
        .base("encrypted-password")
        .crypto(encrypted_crypto.clone()),
    );

    // e03: neither wrapping mode declared
    let mut b = encrypted_password.raw.clone();
    container::write_u32(&mut b, auth + 8, 0);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-mode-empty",
            "AUTH.mode is 0: neither a password nor a machine binding is declared, so the session key is unreachable.",
            "crypt.mode_empty",
            container::repack(&b, &encrypted_password.layout),
        )
        .base("encrypted-password")
        .crypto(json::merge(
            encrypted_crypto.clone(),
            &[
                ("mode", Value::from(0)),
                ("mode_names", Value::from(Vec::<Value>::new())),
            ],
        )),
    );

    // e04: Argon2id cost above the recommended ceiling. The section is coherent, so
    // only the cost rule can refuse it.
    let argon2_budget = vector::build_encrypted_vector(
        &VectorSpec {
            name: "x-argon2-budget",
            description: "source",
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 300, 255)]),
            layers_per_chunk: 2,
            ..Default::default()
        },
        &CryptoSpec {
            argon2_params: (99, 8, 1),
            ..Default::default()
        },
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-argon2-budget",
            "The password section declares Argon2id iterations = 99, above the recommended ceiling of 10; it is otherwise coherent, so only the cost rule refuses it.",
            "crypt.argon2_budget",
            argon2_budget.raw,
        )
        .crypto(argon2_budget.meta["crypto"].clone()),
    );

    // e05: password section shorter than the fixed 65 bytes
    let password_short = vector::build_encrypted_vector(
        &VectorSpec {
            name: "x-password-short",
            description: "source",
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 300, 255)]),
            layers_per_chunk: 2,
            ..Default::default()
        },
        &CryptoSpec {
            password_trim: 1,
            ..Default::default()
        },
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-password-len-short",
            "AUTH declares a 64-byte password section, one byte short of the fixed section size.",
            "crypt.password_section_len",
            password_short.raw,
        )
        .crypto(password_short.meta["crypto"].clone()),
    );

    // e06: machine mode with an empty machine section
    let machine_empty = vector::build_encrypted_vector(
        &VectorSpec {
            name: "x-machine-empty",
            description: "source",
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 300, 255)]),
            layers_per_chunk: 2,
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "C20P",
            mode: 2,
            ..Default::default()
        },
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-machine-len-empty",
            "AUTH.mode sets machine-binding but the machine section is empty: no recipient can ever unwrap the session key.",
            "crypt.machine_section_len",
            machine_empty.raw,
        )
        .crypto(machine_empty.meta["crypto"].clone()),
    );

    // e07: a content chunk whose descriptor says plaintext while the file is encrypted
    let b = patch_chunk_flags(
        &encrypted_password.raw,
        &encrypted_password.layout,
        b"ZDIC",
        0,
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-plaintext-content",
            "ZDIC's descriptor does not set the encrypted flag although the file is encrypted; its bytes are sealed regardless, so the flag is the only disagreement.",
            "crypt.chunk_flags",
            container::repack(&b, &encrypted_password.layout),
        )
        .base("encrypted-password")
        .crypto(encrypted_crypto.clone()),
    );

    // e08: a tampered ciphertext byte inside a sealed LAYR frame
    let mut b = encrypted_password.raw.clone();
    // Past the version field and the nonce, inside the sealed frame.
    b[layr_of(&encrypted_password) + 4 + 12 + 1] ^= 0xFF;
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-tag-corrupt",
            "One ciphertext byte of the first sealed LAYR frame is flipped, so its AEAD tag must fail; a reader must not decompress or parse a frame it cannot authenticate.",
            "crypt.tag_verify",
            container::repack(&b, &encrypted_password.layout),
        )
        .base("encrypted-password")
        .crypto(encrypted_crypto.clone()),
    );

    // ---------------- PROF / LROV / PREV invalid vectors ----------------
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-type-unknown",
            "PROF.profile_type is \"resin\", which is not one of the three defined types.",
            "prof.profile_type",
            prof_vector(
                ProfSettings::default(),
                ProfOverrides {
                    profile_type: Some("resin"),
                    ..Default::default()
                },
            ),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-identity-empty",
            "PROF.profile_name is an empty string.",
            "prof.profile_identity",
            prof_vector(
                ProfSettings::default(),
                ProfOverrides {
                    profile_name: Some(""),
                    ..Default::default()
                },
            ),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-settings-exposure",
            "PROF settings carry a zero normal exposure.",
            "prof.settings_exposure",
            prof_vector(
                ProfSettings {
                    normal_exposure_ms: Some(0),
                    ..Default::default()
                },
                ProfOverrides::default(),
            ),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-settings-layer-height",
            "PROF settings carry a zero layer height.",
            "prof.settings_layer_height",
            prof_vector(
                ProfSettings {
                    layer_height_um: Some(0),
                    ..Default::default()
                },
                ProfOverrides::default(),
            ),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-cure-curve",
            "PROF cure curve has dp_um = 0.0, which no resin can have.",
            "prof.cure_curve",
            prof_vector(
                ProfSettings {
                    cure_curve: Some(obj!["dp_um" => 0, "ec_mj_cm2" => 7.5, "e0_mj_cm2" => 3.0]),
                    ..Default::default()
                },
                ProfOverrides::default(),
            ),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-uuid-malformed",
            "PROF.profile_uuid is not a UUID.",
            "prof.profile_uuid",
            prof_vector(
                ProfSettings::default(),
                ProfOverrides {
                    profile_uuid: Some("not-a-uuid"),
                    ..Default::default()
                },
            ),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prof-materials-shape",
            "PROF.materials is an empty array, which the META.materials shape rules forbid.",
            "prof.materials_shape",
            prof_vector(
                ProfSettings::default(),
                ProfOverrides {
                    materials: Some(Value::from(Vec::<Value>::new())),
                    ..Default::default()
                },
            ),
        ),
    );

    let preview = vector::build_vector(&VectorSpec {
        name: "x-prev",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 90, 255)]),
        layers_per_chunk: 2,
        prevs: vec![(png::preview(24, 18, [200, 200, 200]), 1, false)],
        ..Default::default()
    });
    let prev_off = preview.layout.offset(b"PREV");
    let b = patch_chunk_flags(&preview.raw, &preview.layout, b"PREV", 0x21);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prev-flags",
            "A PREV chunk sets reserved flag bit 5 alongside role 1; only bits 0-3 carry the role.",
            "prev.flags",
            container::repack(&b, &preview.layout),
        ),
    );

    let mut b = preview.raw.clone();
    b[prev_off..prev_off + 4].copy_from_slice(b"NOTP");
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "prev-not-png",
            "A PREV payload does not begin with the PNG signature. A loose reader ignores previews and must still accept the file; a strict validator rejects it.",
            "prev.png_signature",
            container::repack(&b, &preview.layout),
        )
        .strict_only(),
    );

    // a VOXL payload that is neither the V2 magic nor a V1 JSON document
    let not_voxl = vector::build_vector(&VectorSpec {
        name: "x-voxl",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 70, 255)]),
        layers_per_chunk: 2,
        voxl: Some(b"[{\"magic\": \"VOXL\", \"version\": 1}]".to_vec()),
        ..Default::default()
    });
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "voxl-not-voxl",
            "The embedded scene is a JSON array rather than a VOXL document: the payload begins with neither the V2 magic nor the V1 document marker. A loose reader never looks inside the chunk and must still accept the file; a strict validator rejects it.",
            "voxl.signature",
            not_voxl.raw,
        )
        .strict_only(),
    );

    let extd_critical = extd_vector(&[Extd {
        ext_type: b"DRNF",
        ext_data: b"\x00",
        vendor_id: 0x1234,
        critical: true,
        ..Default::default()
    }]);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "extd-critical",
            "An extension sets the critical bit, so a reader that does not implement it must refuse the file rather than print an approximation.",
            "extd.critical",
            extd_critical,
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "extd-truncated",
            "An EXTD payload is four bytes, too short to carry ext_version and ext_type.",
            "extd.frame",
            extd_vector(&[Extd {
                ext_type: b"",
                ext_data: b"",
                ..Default::default()
            }]),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "extd-reserved-flags",
            "An EXTD chunk sets reserved flag bit 0, which must be 0.",
            "extd.flags",
            extd_vector(&[Extd {
                ext_type: b"CMLT",
                ext_data: b"x",
                flags_extra: 0x01,
                ..Default::default()
            }]),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "extd-type-nonascii",
            "An EXTD ext_type is four non-ASCII bytes, so no reader can name the extension.",
            "extd.ext_type",
            extd_vector(&[Extd {
                ext_type: b"\x80\x81\x82\x83",
                ext_data: b"x",
                ..Default::default()
            }]),
        ),
    );

    // a chunk that claims to be sealed in a file that carries no AUTH at all
    let b = patch_chunk_flags(&binary_basic.raw, &binary_basic.layout, b"META", 0x10);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "sealed-without-auth",
            "META's descriptor sets the encrypted bit while the file header does not, so the file carries no AUTH chunk and no key could open it.",
            "crypt.chunk_flags",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // The corpus is exactly what the manifest lists.
    let expected: BTreeSet<PathBuf> = manifest_valid
        .iter()
        .chain(manifest_invalid.iter())
        .map(|record| root.join(record["file"].as_str().expect("a file name")))
        .collect();
    let mut removed = 0;
    prune(&valid_dir, &expected, &mut removed);
    prune(&invalid_dir, &expected, &mut removed);
    if removed > 0 {
        println!("\n{removed} stale vectors removed");
    }

    let (valid_count, invalid_count) = (manifest_valid.len(), manifest_invalid.len());
    let manifest = obj![
        "generator" => obj![
            "format_revision" => FORMAT_REVISION,
            "note" => NOTE,
            "zstd_layer_level" => ZSTD_LAYER_LEVEL,
            "zstd_small_level" => ZSTD_SMALL_LEVEL,
            "zstd_version" => zstd::zstd_safe::version_string(),
        ],
        "invalid" => manifest_invalid,
        "valid" => manifest_valid,
    ];
    let mut bytes = json::dumps(&manifest);
    bytes.push(b'\n');
    fs::write(root.join("manifest.json"), bytes).expect("manifest");

    println!("\nmanifest.json: {valid_count} valid, {invalid_count} invalid");
    0
}

/// Remove every `.lumen` file the corpus no longer lists.
///
/// A revision that retires a vector must retire its file too: a stale one is not
/// small noise, it is a file written to the previous layout sitting in the
/// directory a validator sweeps, so it fails as if it were a current vector.
fn prune(dir: &Path, written: &BTreeSet<PathBuf>, removed: &mut usize) {
    for entry in fs::read_dir(dir).expect("vector directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|ext| ext == "lumen") && !written.contains(&path) {
            fs::remove_file(&path).expect("stale vector");
            println!("removed stale {}", path.display());
            *removed += 1;
        }
    }
}

// --------------------------------------------------------------------------
// valid vectors
// --------------------------------------------------------------------------

/// The thirteen valid vectors, in the order the manifest lists them.
pub fn valid_vectors() -> Vec<Built> {
    vec![
        binary_basic(),
        ree_degenerate_arrays(),
        dict_multi_block(),
        multi_sector(),
        sector_blend_ranges(),
        encrypted_password(),
        encrypted_machine(),
        encrypted_both(),
        print_profile(),
        layer_overrides(),
        previews(),
        embedded_scene(),
        extensions(),
    ]
}

/// 6 layers, three REE forms, no dictionary, three LAYR chunks.
fn binary_basic() -> Built {
    let layers: Vec<vector::Layer> = vec![
        vec![vec![(0, 0, 0)]], // all black -> empty form
        vec![vec![(100, 300, 255)]],
        vec![vec![(50, 60, 255), (100, 110, 255)]],
        vec![vec![(100, 120, 128), (220, 320, 255)]], // grayscale
        vec![vec![(100, 130, 200), (150, 200, 255)]], // split (prefer_split)
        vec![vec![(3000, 3072, 255)]],
    ];
    vector::build_vector(&VectorSpec {
        name: "binary-basic",
        description: "Six layers over one sector covering the empty-layer form, binary REE, grayscale REE and split REE, in three LAYR chunks of two layers each with no dictionary, over a bottom range whose motion, wait and PWM values differ from the normal ones: the bottom layers take the bottom-prefixed values verbatim, the transition layer blends them, and light_pwm switches to the normal value at the first non-bottom layer instead of blending.",
        features: &[
            "empty-layer",
            "binary-ree",
            "grayscale-ree",
            "split-ree",
            "multi-chunk",
            "no-dictionary",
        ],
        display: (64, 48),
        layers,
        layers_per_chunk: 2,
        split_layers: vec![4],
        meta_extra: vec![
            ("bottom_lift_slow_distance_um", Value::from(7000)),
            ("bottom_lift_slow_speed_um_min", Value::from(40000)),
            ("bottom_wait_time_before_cure_ms", Value::from(1200)),
            ("bottom_wait_time_after_lift_ms", Value::from(333)),
            ("bottom_light_pwm", Value::from(200)),
        ],
        ..Default::default()
    })
}

/// 4 layers whose run-length arrays hold no varints, no dictionary, two chunks.
fn ree_degenerate_arrays() -> Built {
    // 64 x 48 over one sector: 3 072 pixels per layer.
    let layers: Vec<vector::Layer> = vec![
        // One run of 0xFF: tag 0x00, run_count 1, no stored length.
        vec![vec![(0, 3072, 255)]],
        // One run of 0x80: tag 0x01, run_count 1, one value, no stored length.
        vec![vec![(0, 3072, 128)]],
        // Every pixel thresholds to 0xFF, so the split core is one run; the
        // overlay is the 0xC0 band, whose first delta is 1000.
        vec![vec![(0, 1000, 255), (1000, 1200, 192), (1200, 3072, 255)]],
        // Every pixel thresholds to 0x00, so the core is one run of the other
        // value; the overlay starts at pixel 0, whose delta is 0.
        vec![vec![(0, 500, 64), (500, 3072, 0)]],
    ];
    vector::build_vector(&VectorSpec {
        name: "ree-degenerate-arrays",
        description: "Four layers over one sector, two LAYR chunks and no dictionary, pinning every run-length array that holds no varints: layer 0 is one run of 0xFF (tag 0x00, run_count 1), layer 1 one run of 0x80 (tag 0x01, run_count 1, one value byte), and layers 2 and 3 are splits whose thresholded core is a single run - one of 0xFF over a 0xC0 band at 1000..1200, whose first delta is two bytes, one of 0x00 under a 0x40 band at 0..500, whose first delta is 0. Each of those arrays carries its four plane lengths as zeros: the header is written unconditionally, and a reader that skipped it would leave those bytes unconsumed. The one degenerate form that is not canonical - a split whose overlay is empty, which section 5.6 forbids for an all-0x00/0xFF slice - is its own invalid vector, split-all-binary, because a valid vector must not carry a layer a strict reader is required to reject.",
        features: &[
            "binary-ree",
            "grayscale-ree",
            "split-ree",
            "single-run-stream",
            "empty-plane-array",
            "no-dictionary",
        ],
        display: (64, 48),
        layers,
        layers_per_chunk: 2,
        split_layers: vec![2, 3],
        ..Default::default()
    })
}

/// 64 layers with a trained dictionary, four LAYR chunks.
fn dict_multi_block() -> Built {
    vector::build_vector(&VectorSpec {
        name: "dict-multi-block",
        description: "64 layers with a trained ZDIC dictionary, in four LAYR chunks of sixteen layers each, every frame carrying the dictionary's id.",
        features: &[
            "dictionary",
            "dictionary-id",
            "multi-chunk",
            "grayscale-ree",
            "split-ree",
        ],
        display: (256, 192),
        layers: vector::sparse_layers(64, 256 * 192),
        layers_per_chunk: 16,
        use_dict: true,
        dict_samples_bytes: 1024,
        split_layers: every(2, 64),
        ..Default::default()
    })
}

/// 4 layers, two sectors, one override on one of the two.
fn multi_sector() -> Built {
    // The two sectors' masks partition each layer's exposed image: sector 0
    // covers the runs listed first, sector 1 the gap between them, and no pixel
    // is exposed by both (spec 7.3).
    let layers: Vec<vector::Layer> = vec![
        vec![vec![(0, 100, 255), (200, 300, 255)], vec![(100, 200, 255)]],
        vec![vec![(0, 64, 255)]],
        vec![vec![(0, 0, 0)]], // empty layer
        vec![vec![(500, 600, 255)], vec![(600, 660, 255)]],
    ];
    vector::build_vector(&VectorSpec {
        name: "multi-sector",
        description: "Four layers with two non-overlapping sectors, the second defined by META.sectors: layer 2 carries no data at all and is the empty layer, its single sector-0 entry holding a zero length, and two LROV chunks override one layer of one sector each - sector 1 of layer 0 and sector 0 of layer 1 - so the timing of a point is the timing of that point and not of its layer.",
        features: &[
            "multi-sector",
            "sector-chunks",
            "empty-layer",
            "binary-ree",
            "sector-scoped-override",
        ],
        display: (64, 48),
        layers,
        layers_per_chunk: 2,
        meta_extra: vec![("materials", standard_grey_material())],
        overrides: vec![
            Override {
                layer: 0,
                sector_id: 1,
                fields: vec![("normal_exposure_ms", Value::from(2800))],
            },
            Override {
                layer: 1,
                sector_id: 0,
                fields: vec![("lift_slow_distance_um", Value::from(6000))],
            },
        ],
        ..Default::default()
    })
}

/// 10 layers, two sectors, one of them with a bottom range of its own.
fn sector_blend_ranges() -> Built {
    // Sector 0 covers the pixels near the origin, sector 1 a band further in, on
    // every layer, so the two masks partition each layer's exposed image.
    let layers: Vec<vector::Layer> = (0..10usize)
        .map(|index| {
            let offset = 8 * index;
            vec![
                vec![(0, 128 + offset, 255u8)],
                vec![(1600 + offset, 1728 + offset, 255u8)],
            ]
        })
        .collect();
    vector::build_vector(&VectorSpec {
        name: "sector-blend-ranges",
        description: "Ten layers over two sectors whose META.sectors entry for sector 1 carries bottom_layer_count 5 and no transition_layer_count, so sector 1 is blended over a bottom range of its own and inherits META's transition count; layer 4 is the layer where the two readings part, fully normal at 2500 ms for sector 0 and still a bottom layer at 30000 ms for sector 1, and their transition steps fall on layers 2 and 5 rather than together.",
        features: &[
            "multi-sector",
            "sector-chunks",
            "sector-layer-count",
            "per-sector-bottom-range",
            "binary-ree",
        ],
        display: (64, 48),
        layers,
        layers_per_chunk: 5,
        meta_extra: vec![("materials", standard_grey_material())],
        sector_extra: vec![("bottom_layer_count", Value::from(5))],
        ..Default::default()
    })
}

/// Password mode, AES-256-GCM, dictionary, two sealed LAYR chunks.
fn encrypted_password() -> Built {
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "encrypted-password",
            description: "Password-mode AES-256-GCM: an Argon2id-wrapped session key, a sealed dictionary and metadata, and two LAYR chunks whose frames are sealed one by one under the directory index of the chunk that carries each.",
            features: &[
                "encryption",
                "password-mode",
                "aes-256-gcm",
                "argon2id",
                "dictionary",
                "sealed-frames",
                "multi-chunk",
            ],
            display: (256, 192),
            layers: vector::sparse_layers(32, 256 * 192),
            layers_per_chunk: 16,
            use_dict: true,
            dict_samples_bytes: 1024,
            split_layers: every(2, 32),
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "A256",
            mode: 1,
            ..Default::default()
        },
    )
}

/// Machine mode, ChaCha20-Poly1305, one LAYR chunk, three recipient entries.
fn encrypted_machine() -> Built {
    let layers: Vec<vector::Layer> = vec![
        vec![vec![(0, 120, 255)]],
        vec![vec![(0, 200, 128), (300, 460, 255)]],
        vec![vec![(0, 0, 0)]],
        vec![vec![(600, 700, 255)]],
    ];
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "encrypted-machine",
            description: "Machine-mode ChaCha20-Poly1305 with three recipient entries: a foreign machine, a decoy entry for our own fingerprint whose ephemeral key is the low-order point, and the real entry. A reader that unwraps the decoy without rejecting the all-zero shared secret recovers a different session key and cannot decrypt the file.",
            features: &[
                "encryption",
                "machine-binding",
                "chacha20-poly1305",
                "x25519",
                "hkdf",
                "multiple-recipients",
                "low-order-point",
            ],
            display: (64, 48),
            layers,
            layers_per_chunk: 4,
            split_layers: vec![1],
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "C20P",
            mode: 2,
            machine_roles: &[Role::Foreign, Role::Decoy, Role::Local],
            ..Default::default()
        },
    )
}

/// Both wrapping modes in one AUTH, multi-sector content.
fn encrypted_both() -> Built {
    let layers: Vec<vector::Layer> = vec![
        vec![vec![(0, 100, 255)], vec![(200, 300, 255)]],
        vec![vec![(0, 64, 255)]],
        vec![vec![(0, 0, 0)]],
        vec![vec![(500, 600, 255)], vec![(1000, 1100, 255)]],
        vec![vec![(0, 900, 255)]],
        vec![vec![(70, 90, 200), (150, 200, 255)]],
    ];
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "encrypted-both",
            description: "Both wrapping modes set in one AUTH chunk, with two sectors whose frames are sealed one by one, each under the directory index of the chunk that carries it.",
            features: &[
                "encryption",
                "password-mode",
                "machine-binding",
                "multi-sector",
                "sealed-frames",
                "aes-256-gcm",
            ],
            display: (64, 48),
            layers,
            layers_per_chunk: 2,
            split_layers: vec![5],
            meta_extra: vec![("materials", standard_grey_material())],
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "A256",
            mode: 3,
            machine_roles: &[Role::Local],
            ..Default::default()
        },
    )
}

/// Encrypted, carrying a reusable print profile.
fn print_profile() -> Built {
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "print-profile",
            description: "Password-mode AES-256-GCM with a sealed PROF chunk: profile identity, a material library, and a settings block reusing META's field names, including the experimental cure curve.",
            features: &[
                "print-profile",
                "prof-chunk",
                "profile-materials",
                "profile-uuid",
                "cure-curve",
                "sealed-content",
                "password-mode",
                "aes-256-gcm",
            ],
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 150, 255)]),
            layers_per_chunk: 2,
            prof: Some(payload::prof(ProfSettings::default(), ProfOverrides::default())),
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "A256",
            mode: 1,
            ..Default::default()
        },
    )
}

/// Plaintext, one override chunk per point.
fn layer_overrides() -> Built {
    // A range is one chunk per layer it covers now: an override set belongs to
    // exactly one (layer, sector), and nothing folds several of them onto a
    // point's timing.
    let ranged = |layers: std::ops::RangeInclusive<u32>, fields: Vec<(&'static str, Value)>| {
        layers
            .map(|layer| Override {
                layer,
                sector_id: 0,
                fields: fields.clone(),
            })
            .collect::<Vec<_>>()
    };
    let mut overrides = vec![Override {
        layer: 2,
        sector_id: 0,
        fields: vec![
            ("normal_exposure_ms", Value::from(2800)),
            ("lift_slow_distance_um", Value::from(6000)),
        ],
    }];
    overrides.extend(ranged(
        3..=5,
        vec![
            ("normal_exposure_ms", Value::from(2200)),
            ("wait_time_before_cure_ms", Value::from(500)),
        ],
    ));
    overrides.extend(ranged(
        6..=8,
        vec![("wait_time_after_lift_ms", Value::from(1000))],
    ));
    // Layer 4 is covered by the range and by a set of its own: one chunk, so the
    // set is written out with the field the single-layer override adds.
    for over in overrides.iter_mut().filter(|over| over.layer == 4) {
        over.fields
            .push(("wait_time_after_lift_ms", Value::from(900)));
    }

    vector::build_vector(&VectorSpec {
        name: "layer-overrides",
        description: "Ten layers of one sector with seven LROV chunks: a single layer, a range of three layers written as one chunk per layer, a second range, and layer 4, which the first range covers too. An override set belongs to exactly one (layer, sector) - the entry that names the chunk is the only thing that places it - so nothing folds: layer 4 resolves to the values of its own set, which keeps the range's exposure and wait while taking the single-layer chunk's wait after the lift.",
        features: &[
            "lrov-chunk",
            "layer-override",
            "layer-range",
            "sector-scoped-override",
        ],
        display: (64, 48),
        layers: vector::repeated(10, &[(0, 120, 255)]),
        layers_per_chunk: 5,
        overrides,
        ..Default::default()
    })
}

/// Encrypted, with one clear and one sealed preview.
fn previews() -> Built {
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "previews",
            description: "Password-mode AES-256-GCM with two PREV chunks: a large preview in the clear and a sealed icon. Preview sealing is optional even when the file is encrypted, so both forms are valid in the same file.",
            features: &[
                "previews",
                "prev-chunk",
                "clear-preview",
                "sealed-preview",
                "preview-role",
                "password-mode",
                "aes-256-gcm",
            ],
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 100, 255)]),
            layers_per_chunk: 2,
            prevs: vec![
                (png::preview(400, 300, [200, 200, 200]), 1, false),
                (png::preview(16, 16, [255, 0, 0]), 3, true),
            ],
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "A256",
            mode: 1,
            ..Default::default()
        },
    )
}

/// Encrypted, with a sealed embedded scene.
fn embedded_scene() -> Built {
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "embedded-scene",
            description: "Password-mode AES-256-GCM with a sealed VOXL chunk: the scene bytes are copied in and must come back out unchanged, while LUMEN itself never parses them.",
            features: &[
                "embedded-scene",
                "voxl-chunk",
                "round-trip-payload",
                "sealed-content",
                "password-mode",
                "aes-256-gcm",
            ],
            display: (64, 48),
            layers: vector::repeated(4, &[(0, 80, 255)]),
            layers_per_chunk: 2,
            voxl: Some(payload::voxl()),
            ..Default::default()
        },
        &CryptoSpec {
            cipher_id: "A256",
            mode: 1,
            ..Default::default()
        },
    )
}

/// Plaintext, with two non-critical extensions.
fn extensions() -> Built {
    // The CMLT body is Python's `json.dumps({"corpus_bytes": 4096, "dict_size":
    // 1024})`, whose default separators are `", "` and `": "`. Every other JSON
    // payload in the corpus is indented; this one is the corpus' only inline
    // document, and serde_json's compact writer would drop the spaces.
    let cmlt = br#"{"corpus_bytes": 4096, "dict_size": 1024}"#;
    let extds = vec![
        payload::extd(Extd {
            ext_type: b"CMLT",
            ext_data: cmlt,
            ..Default::default()
        }),
        payload::extd(Extd {
            ext_type: b"DRNF",
            ext_data: b"\x01\x02\x03\x04\x05",
            vendor_id: 0x1234,
            ..Default::default()
        }),
    ];
    vector::build_vector(&VectorSpec {
        name: "extensions",
        description: "Two non-critical EXTD chunks - one reserved ORA type code and one vendor extension - exercising the frame, the vendor id and critical flag bit, and the rule that readers skip extensions they do not implement.",
        features: &[
            "extd-chunk",
            "extension-frame",
            "vendor-extension",
            "reserved-type-code",
            "skippable-extension",
        ],
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 60, 255)]),
        layers_per_chunk: 2,
        extds,
        ..Default::default()
    })
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

/// One entry of the invalid half of the manifest.
struct Invalid<'a> {
    name: &'a str,
    description: &'a str,
    expected: &'a str,
    raw: Vec<u8>,
    strict_only: bool,
    base: Option<&'a str>,
    crypto: Option<Value>,
}

impl<'a> Invalid<'a> {
    fn new(name: &'a str, description: &'a str, expected: &'a str, raw: Vec<u8>) -> Self {
        Invalid {
            name,
            description,
            expected,
            raw,
            strict_only: false,
            base: None,
            crypto: None,
        }
    }

    fn strict_only(mut self) -> Self {
        self.strict_only = true;
        self
    }

    fn base(mut self, base: &'a str) -> Self {
        self.base = Some(base);
        self
    }

    fn crypto(mut self, crypto: Value) -> Self {
        self.crypto = Some(crypto);
        self
    }
}

/// Write one invalid vector and record it.
fn emit(dir: &Path, manifest: &mut Vec<Value>, invalid: Invalid) {
    let file = format!("invalid/{}.lumen", invalid.name);
    fs::write(dir.join(format!("{}.lumen", invalid.name)), &invalid.raw).expect("vector file");

    let mut entries: Vec<(&str, Value)> = vec![
        ("name", Value::from(invalid.name)),
        ("file", Value::from(file.clone())),
        ("description", Value::from(invalid.description)),
        ("expected_failure", Value::from(invalid.expected)),
        ("strict_only", Value::from(invalid.strict_only)),
        (
            "base_vector",
            invalid.base.map(Value::from).unwrap_or(Value::Null),
        ),
        ("file_size", Value::from(invalid.raw.len())),
        (
            "file_sha256",
            Value::from(container::file_sha256(&invalid.raw)),
        ),
    ];
    if let Some(crypto) = invalid.crypto {
        entries.push(("crypto", crypto));
    }

    println!(
        "wrote {:<28} {:>6} bytes -> expects {}{}",
        file,
        invalid.raw.len(),
        invalid.expected,
        if invalid.strict_only {
            " (strict mode only)"
        } else {
            ""
        }
    );
    manifest.push(json::obj(entries));
}

/// Rewrite one chunk descriptor's flags field.
fn patch_chunk_flags(
    raw: &[u8],
    layout: &container::Layout,
    ctype: &[u8; 4],
    flags: u32,
) -> Vec<u8> {
    let mut out = raw.to_vec();
    for (index, entry) in layout.entries.iter().enumerate() {
        if entry.ctype == *ctype {
            container::write_u32(
                &mut out,
                layout.dir_offset + index * container::DESCRIPTOR_SIZE + 28,
                flags,
            );
            return out;
        }
    }
    panic!("no {:?} chunk", std::str::from_utf8(ctype).expect("ascii"));
}

/// A plaintext file carrying one PROF payload.
fn prof_vector(settings: ProfSettings, overrides: ProfOverrides) -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-prof",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 200, 255)]),
        layers_per_chunk: 2,
        prof: Some(payload::prof(settings, overrides)),
        ..Default::default()
    })
    .raw
}

/// A plaintext file carrying one `LROV` chunk per override set, over ten layers.
fn override_vector(overrides: Vec<Override<'static>>) -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-lrov",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(10, &[(0, 120, 255)]),
        layers_per_chunk: 5,
        overrides,
        ..Default::default()
    })
    .raw
}

/// A plaintext file whose first `LROV` chunk carries `raw` as its payload.
fn lrov_raw_vector(raw: &[u8]) -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-lrov-raw",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(10, &[(0, 120, 255)]),
        layers_per_chunk: 5,
        overrides: vec![Override {
            layer: 2,
            sector_id: 0,
            fields: vec![("normal_exposure_ms", Value::from(2800))],
        }],
        lrov_raw: Some(raw.to_vec()),
        ..Default::default()
    })
    .raw
}

/// A plaintext file carrying an `LROV` chunk that no entry names.
fn orphan_lrov_vector() -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-lrov-orphan",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(10, &[(0, 120, 255)]),
        layers_per_chunk: 5,
        overrides: vec![Override {
            layer: 2,
            sector_id: 0,
            fields: vec![("normal_exposure_ms", Value::from(2800))],
        }],
        orphan_lrov: Some(vec![("normal_exposure_ms", Value::from(2800))]),
        ..Default::default()
    })
    .raw
}

/// A plaintext file whose two layers each carry three sectors.
fn three_sector_source() -> Built {
    let spans = |sector: usize| vec![(sector * 200, sector * 200 + 64, 255u8)];
    let layer: vector::Layer = (0..3).map(spans).collect();
    vector::build_vector(&VectorSpec {
        name: "x-three-sectors",
        description: "source",
        display: (64, 48),
        layers: vec![layer.clone(), layer],
        layers_per_chunk: 1,
        meta_extra: vec![("materials", standard_grey_material())],
        sectors: Some(Value::Array(vec![
            payload::sector_value(1, "Support", 3000),
            payload::sector_value(2, "Second support", 2500),
        ])),
        ..Default::default()
    })
}

/// A plaintext file whose frames do not declare their decompressed size.
fn frame_without_content_size() -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-content-size",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 200, 255)]),
        layers_per_chunk: 2,
        omit_content_size: true,
        ..Default::default()
    })
    .raw
}

/// A plaintext file compressed with a dictionary it does not carry.
fn dictionary_without_zdic() -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-dict-absent",
        description: "source",
        display: (256, 192),
        layers: vector::sparse_layers(16, 256 * 192),
        layers_per_chunk: 8,
        use_dict: true,
        dict_samples_bytes: 1024,
        omit_zdic: true,
        ..Default::default()
    })
    .raw
}

/// A plaintext file carrying a dictionary no frame uses.
fn unused_dictionary() -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-dict-unused",
        description: "source",
        display: (256, 192),
        layers: vector::sparse_layers(16, 256 * 192),
        layers_per_chunk: 8,
        use_dict: true,
        dict_samples_bytes: 1024,
        unused_zdic: true,
        ..Default::default()
    })
    .raw
}

/// A plaintext file whose `META.sectors` names one sector twice.
fn sectors_shape_vector() -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-sectors-shape",
        description: "source",
        display: (64, 48),
        layers: two_sector_layers(),
        layers_per_chunk: 2,
        meta_extra: vec![("materials", standard_grey_material())],
        sectors: Some(Value::Array(vec![
            payload::sector_value(1, "Support", 3000),
            payload::sector_value(1, "Support again", 3000),
        ])),
        ..Default::default()
    })
    .raw
}

/// A plaintext file whose sector names a material the library does not have.
fn sector_material_vector() -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-sector-material",
        description: "source",
        display: (64, 48),
        layers: two_sector_layers(),
        layers_per_chunk: 2,
        meta_extra: vec![("materials", standard_grey_material())],
        sector_extra: vec![("material_index", Value::from(3))],
        ..Default::default()
    })
    .raw
}

/// Four layers that each carry two sectors.
fn two_sector_layers() -> Vec<vector::Layer> {
    (0..4)
        .map(|index| {
            let offset = 16 * index;
            vec![
                vec![(0, 64 + offset, 255u8)],
                vec![(200 + offset, 264 + offset, 255u8)],
            ]
        })
        .collect()
}

/// Where the frame's content-size field sits inside `frame`, read off the frame
/// header, and how wide it is (spec 4.9, zstd's frame format).
///
/// The invalid vectors that lie about the size patch the field in place, so they
/// need its position rather than a hard-coded offset: the header carries an
/// optional window descriptor, an optional dictionary id and a content-size field
/// of one, two, four or eight bytes.
fn content_size_field(frame: &[u8]) -> (usize, usize) {
    let descriptor = frame[4];
    let single_segment = descriptor & 0x20 != 0;
    let dictionary = [0usize, 1, 2, 4][usize::from(descriptor & 0x03)];
    let width = match descriptor >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    (5 + usize::from(!single_segment) + dictionary, width)
}

/// A source whose single frame is wide enough to declare a four-byte size.
///
/// A 64 by 48 display of 32 layers in one group is at most 5 bytes per pixel per
/// slice of decompressed data - a few hundred kilobytes - while the frame's own
/// declaration has four bytes to lie in.
fn allocation_bound_source() -> Built {
    vector::build_vector(&VectorSpec {
        name: "x-allocation",
        description: "source",
        display: (64, 48),
        layers: dense_layers(32, 64 * 48),
        layers_per_chunk: 32,
        ..Default::default()
    })
}

/// `count` layers of alternating one-pixel runs, which REE cannot compress.
fn dense_layers(count: usize, total: usize) -> Vec<vector::Layer> {
    (0..count)
        .map(|start| {
            let mut spans = Vec::new();
            let mut pos = start % 2;
            let mut value = 255u8;
            while pos + 1 < total {
                spans.push((pos, pos + 1, value));
                value = if value == 255 { 128 } else { 255 };
                pos += 2;
            }
            vec![spans]
        })
        .collect()
}

/// A plaintext file carrying the given extensions.
fn extd_vector(extds: &[Extd]) -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-extd",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 50, 255)]),
        layers_per_chunk: 2,
        extds: extds.iter().map(|extd| payload::extd(*extd)).collect(),
        ..Default::default()
    })
    .raw
}

/// The material entry several vectors carry in META.
fn standard_grey_material() -> Value {
    Value::from(vec![obj![
        "name" => "Standard Grey",
        "brand" => "DragonFruit",
        "family" => "standard",
        "density_g_ml" => 1.1,
        "color_rgba" => vec![128, 128, 128, 255],
    ]])
}

/// The layer indices `step, step * 2, ...` below `count`.
fn every(step: usize, count: usize) -> Vec<usize> {
    (0..count).step_by(step).collect()
}

/// The LAYR payload's offset in a built vector.
fn layr_of(built: &Built) -> usize {
    built.layout.offset(b"LAYR")
}
