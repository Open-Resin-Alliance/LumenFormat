//! The corpus: the eleven valid vectors, the deliberate defects, and the manifest.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::container::{self, BLOCK_TABLE_ENTRY_SIZE, LTBL_ENTRY_SIZE};
use crate::json;
use crate::obj;
use crate::payload::{self, Extd, ProfOverrides, ProfSettings};
use crate::png;
use crate::vector::{self, Built, CryptoSpec, Role, VectorSpec};
use crate::{FORMAT_REVISION, ZSTD_LAYER_LEVEL, ZSTD_SMALL_LEVEL};

/// What the manifest says about the bytes an implementer can and cannot rely on.
const NOTE: &str = "Compressed payload bytes depend on the zstd version and level. \
Uncompressed structures (HDR, AUTH, LTBL, LAYR header and block table, LHAS, REE \
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
            "wrote {:<28} {:>6} bytes, {:>2} chunks, {} blocks",
            file,
            built.raw.len(),
            meta["chunk_count"].as_u64().expect("a chunk count"),
            meta["blocks"].as_array().expect("a block table").len()
        );
        manifest_valid.push(meta);
    }

    let mut manifest_invalid: Vec<Value> = Vec::new();

    // The invalid vectors are cut from two of the files above.
    let binary_basic = binary_basic();
    let encrypted_password = encrypted_password();
    let encrypted_crypto = encrypted_password.meta["crypto"].clone();

    // x01: an empty layer (sector_count 0) that claims bytes
    let mut b = binary_basic.raw.clone();
    let ltbl = binary_basic.layout.offset(b"LTBL");
    container::write_u32(&mut b, ltbl + 12 + 12, 2);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "empty-layer-with-bytes",
            "LTBL entry 0 has sector_count 0 but data_size 2.",
            "ltbl.empty_layer_no_bytes",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x02: the non-canonical run_count == 0 all-black form (decodable, not canonical)
    let source = vector::build_vector(&VectorSpec {
        name: "x-source",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 0, 0)]),
        block_size: 2,
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

    // x03: block_index out of range
    let mut b = binary_basic.raw.clone();
    container::write_u32(&mut b, ltbl + 12 + LTBL_ENTRY_SIZE + 8, 99);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "block-index-out-of-range",
            "LTBL entry 1 points at block 99 when the file has three blocks.",
            "ltbl.block_index_in_range",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x04: a gap in the block table
    let mut b = binary_basic.raw.clone();
    let layr = binary_basic.layout.offset(b"LAYR");
    let first_frame_size = container::read_u64(&b, layr + 12 + 8);
    container::write_u64(
        &mut b,
        layr + 12 + BLOCK_TABLE_ENTRY_SIZE,
        first_frame_size + 1,
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "block-table-gap",
            "Block 1 frame_offset leaves a one-byte gap, breaking contiguity.",
            "layr.block_table_contiguous",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x05: merkle root does not match the leaf table
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

    // x06: layer hash does not match the layer bytes (root recomputed to stay consistent)
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

    // x07: layer byte range runs past the end of its block
    let mut b = binary_basic.raw.clone();
    container::write_u32(&mut b, ltbl + 12 + 2 * LTBL_ENTRY_SIZE + 12, 0x00FF_FFFF);
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "layer-range-past-block",
            "LTBL entry 2 claims a data_size far beyond its block's decompressed size.",
            "ltbl.offsets_within_block",
            container::repack(&b, &binary_basic.layout),
        )
        .base("binary-basic"),
    );

    // x08: corrupted trailer CRC (the only failure that is not repacked)
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

    // x09: a fractional duration. Durations are exact whole milliseconds, so a
    // value with a fractional part is not a duration the format can carry; the
    // file is otherwise valid, so the type rule is the only thing wrong with it.
    let fractional = vector::build_vector(&VectorSpec {
        name: "x-meta-fractional",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 255, 255)]),
        block_size: 2,
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
            block_size: 2,
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
            block_size: 2,
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
            block_size: 2,
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

    // e08: a tampered ciphertext byte inside a sealed LAYR block frame
    let mut b = encrypted_password.raw.clone();
    let block_count = encrypted_password.meta["blocks"]
        .as_array()
        .expect("a block table")
        .len();
    let body_off = 12 + block_count * BLOCK_TABLE_ENTRY_SIZE;
    b[layr_of(&encrypted_password) + body_off + 16] ^= 0xFF;
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "crypt-tag-corrupt",
            "One ciphertext byte of LAYR block 0 is flipped, so its AEAD tag must fail; a reader must not decompress or parse a block it cannot authenticate.",
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

    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-entry-form-both",
            "An LROV entry carries both layer and layer_range, which the entry form forbids.",
            "lrov.entry_form",
            lrov_vector(vec![obj![
                "layer" => 2,
                "layer_range" => vec![2, 4],
                "normal_exposure_ms" => 2800,
            ]]),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-layer-out-of-range",
            "An LROV entry overrides layer 40 in a ten-layer file.",
            "lrov.layer_index_range",
            lrov_vector(vec![obj!["layer" => 40, "normal_exposure_ms" => 2800]]),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-range-reversed",
            "An LROV layer_range ends before it begins.",
            "lrov.layer_range_order",
            lrov_vector(vec![obj![
                "layer_range" => vec![8, 3],
                "normal_exposure_ms" => 2800,
            ]]),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-sector-undefined",
            "An LROV entry targets sector 7, which no SECT chunk in this single-sector file defines.",
            "lrov.sector_id_defined",
            lrov_vector(vec![obj![
                "layer_range" => vec![3, 5],
                "sector_id" => 7,
                "normal_exposure_ms" => 2800,
            ]]),
        ),
    );
    emit(
        &invalid_dir,
        &mut manifest_invalid,
        Invalid::new(
            "lrov-wait-fractional",
            "An LROV entry carries wait_time_before_cure_ms = 500.5. A wait time is a whole \
number of milliseconds, so a fractional value is not a duration this format \
can express.",
            "lrov.time_integer",
            lrov_vector(vec![obj![
                "layer" => 2,
                "normal_exposure_ms" => 2800,
                "wait_time_before_cure_ms" => 500.5,
            ]]),
        ),
    );

    let preview = vector::build_vector(&VectorSpec {
        name: "x-prev",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 90, 255)]),
        block_size: 2,
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
        block_size: 2,
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

// --------------------------------------------------------------------------
// valid vectors
// --------------------------------------------------------------------------

/// The eleven valid vectors, in the order the manifest lists them.
pub fn valid_vectors() -> Vec<Built> {
    vec![
        binary_basic(),
        dict_multi_block(),
        multi_sector(),
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

/// 6 layers, three tags, no dictionary, three blocks.
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
        description: "Six layers covering the empty-layer form, binary REE, grayscale REE and split REE, across three blocks with no dictionary, over a bottom range whose motion, wait and PWM values differ from the normal ones: the bottom layers take the bottom-prefixed values verbatim, the transition layer blends them, and light_pwm switches to the normal value at the first non-bottom layer instead of blending.",
        features: &[
            "empty-layer",
            "binary-ree",
            "grayscale-ree",
            "split-ree",
            "multi-block",
            "no-dictionary",
        ],
        display: (64, 48),
        layers,
        block_size: 2,
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

/// 64 layers with a trained dictionary, four blocks.
fn dict_multi_block() -> Built {
    vector::build_vector(&VectorSpec {
        name: "dict-multi-block",
        description: "64 layers with a trained ZDIC dictionary, four blocks of sixteen layers.",
        features: &[
            "dictionary",
            "dictionary-id",
            "multi-block",
            "grayscale-ree",
            "split-ree",
        ],
        display: (256, 192),
        layers: vector::sparse_layers(64, 256 * 192),
        block_size: 16,
        use_dict: true,
        dict_samples_bytes: 1024,
        split_layers: every(2, 64),
        ..Default::default()
    })
}

/// 4 layers, two sectors, partition invariant.
fn multi_sector() -> Built {
    let layers: Vec<vector::Layer> = vec![
        vec![vec![(0, 100, 255)], vec![(200, 300, 255)]],
        vec![vec![(0, 64, 255)]],
        vec![vec![(0, 0, 0)]], // empty layer
        vec![vec![(500, 600, 255)], vec![(1000, 1100, 255)]],
    ];
    vector::build_vector(&VectorSpec {
        name: "multi-sector",
        description: "Four layers with two non-overlapping sectors, exercising the multi-sector varint framing and the sector partition invariant.",
        features: &[
            "multi-sector",
            "sector-framing",
            "empty-layer",
            "binary-ree",
        ],
        display: (64, 48),
        layers,
        block_size: 2,
        meta_extra: vec![("materials", standard_grey_material())],
        ..Default::default()
    })
}

/// Password mode, AES-256-GCM, dictionary, two sealed blocks.
fn encrypted_password() -> Built {
    vector::build_encrypted_vector(
        &VectorSpec {
            name: "encrypted-password",
            description: "Password-mode AES-256-GCM: an Argon2id-wrapped session key, a sealed dictionary and metadata, and two blocks of sealed layer frames.",
            features: &[
                "encryption",
                "password-mode",
                "aes-256-gcm",
                "argon2id",
                "dictionary",
                "sealed-blocks",
                "multi-block",
            ],
            display: (256, 192),
            layers: vector::sparse_layers(32, 256 * 192),
            block_size: 16,
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

/// Machine mode, ChaCha20-Poly1305, one block, three recipient entries.
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
            block_size: 4,
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
            description: "Both wrapping modes set in one AUTH chunk, with multi-sector layer content sealed under a single session key.",
            features: &[
                "encryption",
                "password-mode",
                "machine-binding",
                "multi-sector",
                "sealed-sectors",
                "aes-256-gcm",
            ],
            display: (64, 48),
            layers,
            block_size: 2,
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
            block_size: 2,
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

/// Plaintext, per-layer and per-range overrides.
fn layer_overrides() -> Built {
    let overrides = vec![
        obj![
            "layer" => 2,
            "normal_exposure_ms" => 2800,
            "lift_slow_distance_um" => 6000,
        ],
        obj![
            "layer_range" => vec![3, 5],
            "sector_id" => 0,
            "normal_exposure_ms" => 2200,
            "wait_time_before_cure_ms" => 500,
        ],
        obj![
            "layer_range" => vec![6, 8],
            "wait_time_after_lift_ms" => 1000,
        ],
        obj![
            "layer" => 4,
            "wait_time_after_lift_ms" => 900,
        ],
    ];
    vector::build_vector(&VectorSpec {
        name: "layer-overrides",
        description: "Ten layers with an LROV chunk whose four entries cover a single layer, an inclusive range scoped to sector 0, a range that applies to every sector, and a second entry on layer 4, which the range already matches. The two entries that match layer 4 fold field by field rather than the later one replacing the earlier, so that layer keeps the range's exposure and wait while taking the single-layer entry's wait after the lift.",
        features: &[
            "lrov-chunk",
            "layer-override",
            "layer-range",
            "sector-scoped-override",
        ],
        display: (64, 48),
        layers: vector::repeated(10, &[(0, 120, 255)]),
        block_size: 5,
        lrov: Some(overrides),
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
            block_size: 2,
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
            block_size: 2,
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
        block_size: 2,
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
        block_size: 2,
        prof: Some(payload::prof(settings, overrides)),
        ..Default::default()
    })
    .raw
}

/// A plaintext file carrying one LROV payload.
fn lrov_vector(overrides: Vec<Value>) -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-lrov",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(10, &[(0, 120, 255)]),
        block_size: 5,
        lrov: Some(overrides),
        ..Default::default()
    })
    .raw
}

/// A plaintext file carrying the given extensions.
fn extd_vector(extds: &[Extd]) -> Vec<u8> {
    vector::build_vector(&VectorSpec {
        name: "x-extd",
        description: "source",
        display: (64, 48),
        layers: vector::repeated(4, &[(0, 50, 255)]),
        block_size: 2,
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
