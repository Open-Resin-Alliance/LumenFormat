//! Generate a small `.lumen` file and print what is inside it.
//!
//! The file is written to the directory given as the first argument, or to
//! `target/` when none is given. It exercises the parts of the format that are
//! worth looking at by hand: an empty layer, binary and anti-aliased masks,
//! several `LAYR` chunks, a trained dictionary, the bottom/transition timing
//! blend, a material library, a reusable profile, a preview and an extension.
//!
//! `cargo run --example make_test_file`
//! `cargo run --example make_test_file -- /tmp`

use std::path::PathBuf;

use lumen::chunks::extd::Extension;
use lumen::chunks::head::Head;
use lumen::chunks::preview::PreviewRole;
use lumen::crypto::Cipher;
use lumen::json::{AntiAliasing, Material, Meta, Printer, Profile, Timing};
use lumen::reader::LumenFile;
use lumen::ree::DecodedLayer;
use lumen::validate::Level;
use lumen::writer::{Argon2Params, Encoder, EncryptOptions};
use sha2::{Digest, Sha256};

/// The lower-case hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// The lower-case hex of a SHA-256 digest.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

const WIDTH: u32 = 64;
const HEIGHT: u32 = 48;
const PIXELS: usize = (WIDTH * HEIGHT) as usize;

fn main() {
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    std::fs::create_dir_all(&out_dir).expect("a writable output directory");

    let plaintext = build(None, true);
    let plain_path = out_dir.join("sample.lumen");
    std::fs::write(&plain_path, &plaintext).expect("writable");
    println!("wrote {} ({} bytes)", plain_path.display(), plaintext.len());

    // The same print without the optional integrity tree, so that the
    // optional-mechanism rule of section 10.3 has a file exercising it: a reader
    // must not require LHAS in order to read a file that does not use it.
    let no_hashes = build(None, false);
    let no_hashes_path = out_dir.join("sample-no-lhas.lumen");
    std::fs::write(&no_hashes_path, &no_hashes).expect("writable");
    println!(
        "wrote {} ({} bytes)",
        no_hashes_path.display(),
        no_hashes.len()
    );

    let encrypted = build(
        Some(EncryptOptions {
            cipher: Cipher::Aes256Gcm,
            password: Some("lumen-example".to_string()),
            recipients: Vec::new(),
            argon2: Argon2Params {
                iterations: 2,
                memory_kib: 64,
                parallelism: 1,
            },
        }),
        true,
    );
    let encrypted_path = out_dir.join("sample-encrypted.lumen");
    std::fs::write(&encrypted_path, &encrypted).expect("writable");
    println!(
        "wrote {} ({} bytes)",
        encrypted_path.display(),
        encrypted.len()
    );

    println!("\n=== {} ===", plain_path.display());
    describe(&plaintext, None);

    println!("\n=== {} (no integrity tree) ===", no_hashes_path.display());
    describe(&no_hashes, None);

    println!(
        "\n=== {} (opened with its password) ===",
        encrypted_path.display()
    );
    describe(&encrypted, Some("lumen-example"));
}

/// The print: twelve layers that between them use every encoding the format has.
fn layers() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for index in 0..12 {
        let mut mask = vec![0u8; PIXELS];
        match index {
            0 => {} // empty: the empty-layer form, no bytes at all
            1 => mask.fill(255),
            2 => {
                // Solid base with a rectangular hole: two binary runs per row.
                for (i, pixel) in mask.iter_mut().enumerate() {
                    let x = i % WIDTH as usize;
                    let y = i / WIDTH as usize;
                    *pixel = if (10..40).contains(&x) && (8..24).contains(&y) {
                        0
                    } else {
                        255
                    };
                }
            }
            3 => {
                // A horizontal ramp: every pixel its own grayscale run.
                for (i, pixel) in mask.iter_mut().enumerate() {
                    *pixel = ((i % WIDTH as usize) * 255 / (WIDTH as usize - 1)) as u8;
                }
            }
            4 => {
                // A disc with a one-pixel anti-aliased rim: the split encoding.
                for y in 0..HEIGHT {
                    for x in 0..WIDTH {
                        let dx = x as f64 - WIDTH as f64 / 2.0;
                        let dy = y as f64 - HEIGHT as f64 / 2.0;
                        let d = (dx * dx + dy * dy).sqrt();
                        let r = HEIGHT as f64 / 2.5;
                        let v = if d <= r - 1.0 {
                            255.0
                        } else if d >= r + 1.0 {
                            0.0
                        } else {
                            255.0 * (r + 1.0 - d) / 2.0
                        };
                        mask[y as usize * WIDTH as usize + x as usize] = v.round() as u8;
                    }
                }
            }
            5 => {
                // A checkerboard: the worst case for run-end encoding.
                for (i, pixel) in mask.iter_mut().enumerate() {
                    let x = i % WIDTH as usize;
                    let y = i / WIDTH as usize;
                    *pixel = if (x + y) % 2 == 0 { 255 } else { 0 };
                }
            }
            _ => {
                // Growing bars, so later layers differ from earlier ones.
                let step = (index as usize - 5) * 5;
                for (i, pixel) in mask.iter_mut().enumerate() {
                    if i % (WIDTH as usize) < step.min(WIDTH as usize) {
                        *pixel = 255;
                    }
                }
            }
        }
        out.push(mask);
    }
    out
}

fn head(layer_count: u32) -> Head {
    Head {
        head_version: 1,
        encoder_name: "lumen-format example 0.1".to_string(),
        created_unix_sec: 1_767_000_000,
        display_width_px: WIDTH,
        display_height_px: HEIGHT,
        physical_width_px: WIDTH,
        physical_height_px: HEIGHT,
        build_width_um: 143_000,
        build_depth_um: 89_000,
        build_height_um: 175_000,
        layer_height_um: 50,
        total_layers: layer_count,
    }
}

fn meta() -> Meta {
    Meta {
        meta_version: Some(1),
        timing: Timing {
            layer_height_um: Some(50),
            normal_exposure_ms: Some(2500),
            bottom_exposure_ms: Some(30000),
            bottom_layer_count: Some(2),
            transition_layer_count: Some(3),
            lift_slow_distance_um: Some(5000),
            lift_slow_speed_um_min: Some(65_000),
            lift_fast_distance_um: Some(3000),
            lift_fast_speed_um_min: Some(180_000),
            retract_fast_distance_um: Some(5000),
            retract_fast_speed_um_min: Some(150_000),
            retract_slow_distance_um: Some(3000),
            retract_slow_speed_um_min: Some(180_000),
            wait_time_before_cure_ms: Some(1000),
            wait_time_after_cure_ms: Some(0),
            wait_time_after_lift_ms: Some(500),
            bottom_wait_time_before_cure_ms: Some(1500),
            light_pwm: Some(255),
            chamber_temperature_c: Some(30.0),
            cure_curve: Some(lumen::json::CureCurve {
                dp_um: 120.0,
                ec_mj_cm2: 7.5,
                e0_mj_cm2: 3.0,
            }),
            ..Timing::default()
        },
        materials: Some(vec![Material {
            name: "Standard Grey".to_string(),
            brand: Some("DragonFruit".to_string()),
            family: Some("standard".to_string()),
            density_g_ml: Some(1.1),
            color_rgba: Some([128, 128, 128, 255]),
            bottle_price: None,
            bottle_capacity_ml: None,
            extra: serde_json::Map::new(),
        }]),
        printer: Some(Printer {
            name: Some("Ares 12K".to_string()),
            manufacturer: Some("Open Resin Alliance".to_string()),
            ..Printer::default()
        }),
        anti_aliasing: Some(AntiAliasing {
            enabled: Some(true),
            level: Some(8),
            mode: Some("blur".to_string()),
            ..AntiAliasing::default()
        }),
        estimated_print_time_sec: Some(14_400),
        slicer: Some(lumen::json::Slicer {
            name: Some("lumen-format".to_string()),
            version: Some("0.1.0".to_string()),
            url: Some("https://openresin.org".to_string()),
            ..lumen::json::Slicer::default()
        }),
        ..Meta::default()
    }
}

fn build(encryption: Option<EncryptOptions>, layer_hashes: bool) -> Vec<u8> {
    let masks = layers();
    let mut encoder = Encoder::new(head(masks.len() as u32), meta());
    for mask in &masks {
        encoder.push_layer(mask).expect("a pushable layer");
    }
    encoder.set_layers_per_chunk(4);
    encoder.set_zstd_level(6);
    encoder.set_dictionary(true);
    encoder.set_layer_hashes(layer_hashes);
    encoder.set_profile(Profile {
        profile_name: "Standard Grey - 64x48".to_string(),
        profile_version: "1.0.0".to_string(),
        profile_type: Some("combined".to_string()),
        profile_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
        author: Some("lumen-format example".to_string()),
        description: Some("A profile that travels with the print.".to_string()),
        settings: meta().timing,
        ..Profile::default()
    });
    encoder.set_voxl(b"{\"voxl\":1,\"note\":\"opaque to LUMEN\"}".to_vec());
    encoder.add_preview(PreviewRole::Small, preview_png());
    encoder.add_extension(Extension {
        ext_version: 1,
        ext_type: *b"CMAP",
        vendor_id: 0,
        critical: false,
        encrypted: false,
        data: vec![0, 1, 0, 2],
    });
    if let Some(options) = encryption {
        encoder.set_encryption(options);
    }
    encoder.finish().expect("a writable file")
}

/// A minimal but well-formed PNG: signature and `IHDR`, which is all a LUMEN
/// reader inspects before handing the bytes to a PNG decoder.
fn preview_png() -> Vec<u8> {
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&13u32.to_be_bytes());
    ihdr.extend_from_slice(b"IHDR");
    ihdr.extend_from_slice(&WIDTH.to_be_bytes());
    ihdr.extend_from_slice(&HEIGHT.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    ihdr.extend_from_slice(&lumen::container::crc32c(&ihdr[4..]).to_be_bytes());
    png.extend_from_slice(&ihdr);
    png
}

fn describe(bytes: &[u8], password: Option<&str>) {
    let level = Level::Strict;
    let mut validator = lumen::validate::Validator::new(level);
    if let Some(password) = password {
        let header = lumen::container::FileHeader::parse(bytes).expect("header");
        let directory = lumen::container::parse_directory(bytes, &header).expect("directory");
        let descriptor = directory
            .find(lumen::container::ChunkType::AUTH)
            .expect("AUTH");
        let payload = &bytes[descriptor.offset as usize
            ..descriptor.offset as usize + descriptor.stored_len() as usize];
        let auth = lumen::crypto::parse_auth(payload).expect("AUTH parses");
        validator = validator.with_key(
            lumen::crypto::unwrap_password(&auth, password).expect("the password opens it"),
        );
    }
    validator
        .validate(bytes)
        .expect("the generated file validates strictly");
    println!(
        "validates: strict, {} file",
        if password.is_some() {
            "sealed"
        } else {
            "plaintext"
        }
    );

    let file = match password {
        Some(password) => LumenFile::open_with_password(bytes, level, password),
        None => LumenFile::open(bytes, level),
    }
    .expect("the generated file opens");

    println!(
        "header: version {}, dir_offset {}, chunks {}, flags {:#04x}, total uncompressed {}",
        file.header().version,
        file.header().dir_offset,
        file.header().chunk_count,
        file.header().flags,
        file.header().total_uncompressed_size
    );
    println!(
        "HEAD: encoder {:?}, {}x{} px, physical {}x{}, {} layers of {} um",
        file.head().encoder_name,
        file.head().display_width_px,
        file.head().display_height_px,
        file.head().physical_width_px,
        file.head().physical_height_px,
        file.head().total_layers,
        file.head().layer_height_um
    );

    println!("\nchunks, in file order:");
    println!(
        "  {:<6} {:>8} {:>10} {:>10}  flags",
        "type", "offset", "stored", "plain"
    );
    for d in file.directory().entries() {
        println!(
            "  {:<6} {:>8} {:>10} {:>10}  {:#06x}{}",
            d.chunk_type.tag(),
            d.offset,
            d.stored_len(),
            d.size_uncompressed,
            d.flags,
            if d.is_encrypted() { " sealed" } else { "" }
        );
    }

    if let Some(profile) = file.profile() {
        println!(
            "\nPROF: {:?} {} ({})",
            profile.profile_name,
            profile.profile_version,
            profile.profile_type.as_deref().unwrap_or("?")
        );
    }
    if let Some(voxl) = file.voxl() {
        println!(
            "VOXL: {} bytes, opaque: {:?}",
            voxl.len(),
            String::from_utf8_lossy(voxl)
        );
    }
    for extension in file.extensions() {
        println!(
            "EXTD: {} vendor {:#06x} critical {} data {:?}",
            extension.tag(),
            extension.vendor_id,
            extension.critical,
            extension.data
        );
    }
    for preview in file.previews() {
        println!(
            "PREV: role {:?}, {} bytes of PNG",
            preview.role,
            preview.png.len()
        );
    }
    match file.dictionary() {
        Some(dictionary) => println!(
            "ZDIC: dictionary id {}, {} bytes",
            dictionary.dict_id,
            dictionary.dict_bytes.len()
        ),
        None => println!("ZDIC: none (training was refused for this little data)"),
    }

    println!("\nLAYR: {} chunk(s)", file.layr_chunks().len());
    for chunk in file.layr_chunks() {
        let overlay = file
            .layr_chunk_data(chunk.index)
            .expect("a readable chunk")
            .len();
        println!(
            "  index {:>3}: container {:>7} bytes stored, {:>8} decompressed, flags {:#06x}",
            chunk.index,
            chunk.descriptor.stored_len(),
            overlay,
            chunk.descriptor.flags
        );
    }

    println!("\nlayers, one entry per (layer, sector):");
    println!(
        "  {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>8}  {:>10} {:>8}  leaf",
        "layer", "sector", "chunk", "lrov", "offset", "size", "tag", "exposed", "pixels"
    );
    for index in 0..file.layer_count() {
        let decoded: DecodedLayer = file.layer(index).expect("a decodable layer");
        let exposed = decoded.pixels.iter().filter(|p| **p != 0).count();
        let leaf = file
            .layer_hashes()
            .map(|h| hex(&h.layer_hashes[index as usize])[..12].to_string())
            .unwrap_or_else(|| "-".to_string());
        for entry in file.layer_table().layer_entries(index) {
            println!(
                "  {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>8}  {:>10} {:>8}  {}",
                index,
                entry.sector_id,
                entry.first_layr,
                entry.first_lrov,
                entry.data_offset,
                entry.data_size,
                decoded
                    .tag
                    .map(|t| format!("{t:#04x}"))
                    .unwrap_or_else(|| "empty".to_string()),
                exposed,
                decoded.pixels.len(),
                leaf
            );
        }
    }
    if let Some(hashes) = file.layer_hashes() {
        println!("\nLHAS: Merkle root {}", hex(&hashes.merkle_root));
        println!(
            "      {} leaves of {} bytes, algorithm {:#04x}",
            hashes.layer_count, hashes.hash_size, hashes.hash_algorithm
        );
    }

    println!("\ntiming through the section 8 pipeline:");
    for index in [0, 1, 2, 3, 4, 5, file.layer_count() - 1] {
        let timing = file.timing_for(index, 0).expect("resolvable timing");
        println!(
            "  layer {index:>2}: {:>6} ms exposure, lift {} um at {} um/min, pwm {}{}{}",
            timing.exposure_ms,
            timing.lift_slow_distance_um,
            timing.lift_slow_speed_um_min,
            timing.light_pwm,
            if timing.is_bottom { ", bottom" } else { "" },
            if timing.is_transition {
                ", transition"
            } else {
                ""
            }
        );
    }

    println!(
        "\nfile: {} bytes, SHA-256 {}",
        bytes.len(),
        &sha256_hex(bytes)[..32]
    );
    println!("first 64 bytes: {:02x?}", &bytes[..64.min(bytes.len())]);
    if file.layer_hashes().is_some() {
        file.verify_all().expect("the integrity tree verifies");
        println!("LHAS: every leaf and the root verify");
    } else {
        // Section 10.3: a reader must not require an optional mechanism, so a
        // file without LHAS is readable and there is simply nothing to verify.
        println!("LHAS: absent, which section 4.11 permits; nothing to verify against");
    }
}
