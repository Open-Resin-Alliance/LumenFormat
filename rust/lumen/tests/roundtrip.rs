//! Round trips: encode, then decode, and check the pixels come back.
//!
//! The conformance corpus proves this crate *reads* LUMEN. These tests prove it
//! *writes* LUMEN: a file it produces validates at both levels, and every layer
//! decodes back to the exact bytes that went in - including through the
//! dictionary, through multiple blocks, through the sector framing, and through
//! password encryption.

use lumen::chunks::extd::Extension;
use lumen::chunks::hdr::Hdr;
use lumen::chunks::preview::PreviewRole;
use lumen::crypto::Cipher;
use lumen::json::{Meta, Sect, Timing};
use lumen::reader::LumenFile;
use lumen::ree::EncodeMode;
use lumen::validate::{self, Level};
use lumen::writer::{Argon2Params, Encoder, EncryptOptions};

const WIDTH: u32 = 64;
const HEIGHT: u32 = 48;
const PIXELS: usize = (WIDTH * HEIGHT) as usize;

fn hdr(layers: u32) -> Hdr {
    Hdr {
        hdr_version: 1,
        encoder_name: "lumen-format tests".to_string(),
        created_unix_sec: 1_750_000_000,
        display_width_px: WIDTH,
        display_height_px: HEIGHT,
        physical_width_px: WIDTH,
        physical_height_px: HEIGHT,
        build_width_um: 143_000,
        build_depth_um: 89_000,
        build_height_um: 175_000,
        layer_height_um: 50,
        total_layers: layers,
    }
}

fn meta() -> Meta {
    let mut timing = Timing {
        layer_height_um: Some(50),
        normal_exposure_sec: Some(2.5),
        bottom_exposure_sec: Some(30.0),
        bottom_layer_count: Some(2),
        transition_layer_count: Some(2),
        lift_slow_distance_um: Some(5000),
        lift_slow_speed_um_min: Some(65_000),
        retract_fast_distance_um: Some(5000),
        retract_fast_speed_um_min: Some(150_000),
        lift_fast_distance_um: Some(3000),
        lift_fast_speed_um_min: Some(180_000),
        retract_slow_distance_um: Some(3000),
        retract_slow_speed_um_min: Some(180_000),
        light_pwm: Some(255),
        ..Timing::default()
    };
    timing.extra.clear();
    Meta {
        meta_version: Some(1),
        timing,
        ..Meta::default()
    }
}

/// A corpus of layer masks that between them exercise every encoding and both
/// degenerate cases.
fn masks() -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // Empty: stored as the empty-layer form.
    out.push(vec![0u8; PIXELS]);

    // Solid white: one binary run.
    out.push(vec![255u8; PIXELS]);

    // A left/right split: two binary runs.
    let mut split = vec![0u8; PIXELS];
    for (i, pixel) in split.iter_mut().enumerate() {
        if i % (WIDTH as usize) >= 20 {
            *pixel = 255;
        }
    }
    out.push(split);

    // A horizontal gradient: grayscale or split, whichever is smaller.
    let mut gradient = vec![0u8; PIXELS];
    for (i, pixel) in gradient.iter_mut().enumerate() {
        *pixel = ((i % WIDTH as usize) * 255 / (WIDTH as usize - 1)) as u8;
    }
    out.push(gradient);

    // A disc with a soft anti-aliased edge: mostly solid, few AA pixels.
    let mut disc = vec![0u8; PIXELS];
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let dx = x as f64 - WIDTH as f64 / 2.0;
            let dy = y as f64 - HEIGHT as f64 / 2.0;
            let distance = (dx * dx + dy * dy).sqrt();
            let radius = HEIGHT as f64 / 2.5;
            let value = if distance <= radius - 1.0 {
                255.0
            } else if distance >= radius + 1.0 {
                0.0
            } else {
                255.0 * (radius + 1.0 - distance) / 2.0
            };
            disc[y as usize * WIDTH as usize + x as usize] = value.round() as u8;
        }
    }
    out.push(disc);

    // A checkerboard: worst case for run-end encoding, and many runs per block.
    let mut checker = vec![0u8; PIXELS];
    for (i, pixel) in checker.iter_mut().enumerate() {
        let x = i % WIDTH as usize;
        let y = i / WIDTH as usize;
        *pixel = if (x + y) % 2 == 0 { 255 } else { 0 };
    }
    out.push(checker);

    out
}

/// Encode the masks and return the file.
fn encode(encrypt: Option<EncryptOptions>, block_layers: u32) -> Vec<u8> {
    let layer_masks = masks();
    let mut encoder = Encoder::new(hdr(layer_masks.len() as u32), meta());
    encoder.set_block_layers(block_layers);
    encoder.set_zstd_level(6);
    encoder.set_dictionary(true);
    encoder.set_layer_hashes(true);
    encoder.add_preview(PreviewRole::Small, fake_png());
    if let Some(options) = encrypt {
        encoder.set_encryption(options);
    }
    for mask in &layer_masks {
        encoder.push_layer(mask).expect("a pushable layer");
    }
    encoder.finish().expect("a writable file")
}

/// A minimal well-formed PNG: signature, IHDR, and an empty IEND.
fn fake_png() -> Vec<u8> {
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

fn assert_layers(file: &LumenFile<'_>) {
    for (index, expected) in masks().iter().enumerate() {
        let decoded = file
            .layer(index as u32)
            .unwrap_or_else(|e| panic!("layer {index} must decode: {e}"));
        assert_eq!(
            decoded.pixels.len(),
            PIXELS,
            "layer {index} must decode to a full mask"
        );
        assert_eq!(
            &decoded.pixels, expected,
            "layer {index} pixels must round trip"
        );
        if expected.iter().all(|p| *p == 0) {
            assert!(
                decoded.is_empty(),
                "layer {index} must use the empty-layer form"
            );
        } else {
            assert!(!decoded.is_empty(), "layer {index} must carry a stream");
        }
    }
}

#[test]
fn plaintext_round_trip_with_a_dictionary_and_multiple_blocks() {
    // Six layers in blocks of two exercises the multi-block path and the
    // dictionary; small prints cannot train a dictionary, so the encoder must
    // fall back to plain zstd without failing.
    let bytes = encode(None, 2);
    validate::validate(&bytes, Level::Strict).expect("an authored file must validate strictly");
    let file = LumenFile::open(&bytes, Level::Strict).expect("an authored file must open");
    assert_eq!(file.layer_count(), masks().len() as u32);
    assert_layers(&file);
    file.verify_all()
        .expect("the authored integrity tree must verify");
    assert_eq!(file.previews().len(), 1, "the preview must round trip");

    // META has bottom_layer_count 2 and transition_layer_count 2, so layer 4 is
    // the first fully normal layer and layers 0-1 use the bottom exposure.
    assert_eq!(file.timing_for(0, 0).expect("layer 0").exposure_sec, 30.0);
    assert_eq!(file.timing_for(1, 0).expect("layer 1").exposure_sec, 30.0);
    assert_eq!(file.timing_for(4, 0).expect("layer 4").exposure_sec, 2.5);
    let transition = file.timing_for(2, 0).expect("layer 2");
    assert!(transition.is_transition);
    assert!(
        transition.exposure_sec < 30.0 && transition.exposure_sec > 2.5,
        "layer 2 interpolates: {}",
        transition.exposure_sec
    );
}

#[test]
fn plaintext_round_trip_in_one_block() {
    let bytes = encode(None, 64);
    let file = LumenFile::open(&bytes, Level::Strict).expect("an authored file must open");
    assert_eq!(file.layr().block_count(), 1, "one block for six layers");
    assert_layers(&file);
    file.verify_all()
        .expect("the authored integrity tree must verify");
}

#[test]
fn encoding_is_deterministic() {
    let first = encode(None, 3);
    let second = encode(None, 3);
    assert_eq!(
        first, second,
        "identical input and settings must produce identical bytes"
    );
}

#[test]
fn password_encryption_round_trips() {
    let bytes = encode(
        Some(EncryptOptions {
            cipher: Cipher::Aes256Gcm,
            password: Some("correct horse".to_string()),
            recipients: Vec::new(),
            argon2: Argon2Params {
                iterations: 1,
                memory_kib: 8,
                parallelism: 1,
            },
        }),
        2,
    );

    // Without a key the sealed content cannot be opened, and the flag rules still
    // hold at both levels.
    validate::validate(&bytes, Level::Strict).expect("an encrypted file validates without a key");
    let err = LumenFile::open(&bytes, Level::Loose).expect_err("sealed content needs a key");
    assert_eq!(err.check_name(), "crypt.no_key");

    let file = LumenFile::open_with_password(&bytes, Level::Strict, "correct horse")
        .expect("the right password must open the file");
    assert_layers(&file);
    file.verify_all()
        .expect("the integrity tree must verify through decryption");

    let wrong = LumenFile::open_with_password(&bytes, Level::Loose, "wrong password")
        .expect_err("a wrong password must not open the file");
    assert_eq!(wrong.check_name(), "crypt.key_unwrap");

    // The session key recovered explicitly is the one the content is sealed with.
    let key = file
        .recover_password("correct horse")
        .expect("key recovery");
    let reopened = LumenFile::open_with_key(&bytes, Level::Strict, key).expect("keyed open");
    assert_layers(&reopened);
}

#[test]
fn machine_binding_round_trips() {
    // A fixed recipient keypair: the X25519 private key is opaque to this test,
    // which only needs a public key the encoder can wrap for.
    let private: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let bytes = encode(
        Some(EncryptOptions {
            cipher: Cipher::ChaCha20Poly1305,
            password: None,
            recipients: vec![public.to_bytes()],
            argon2: Argon2Params::default(),
        }),
        2,
    );

    let file = LumenFile::open_with_machine_key(&bytes, Level::Strict, &private)
        .expect("the recipient key must open the file");
    assert_layers(&file);

    let stranger: [u8; 32] = [0x77; 32];
    let err = LumenFile::open_with_machine_key(&bytes, Level::Loose, &stranger)
        .expect_err("another machine's key must not open the file");
    assert_eq!(err.check_name(), "crypt.no_key");
}

#[test]
fn multi_sector_round_trips_and_reports_its_sectors() {
    let mut encoder = Encoder::new(hdr(2), meta());
    encoder.set_sectors(vec![Sect {
        sector_id: 1,
        name: Some("supports".to_string()),
        material_index: None,
        color_rgba: Some([0, 255, 0, 128]),
        timing: Timing {
            normal_exposure_sec: Some(3.0),
            bottom_exposure_sec: Some(35.0),
            ..Timing::default()
        },
    }]);

    // Layer 0: model in sector 0, supports in sector 1, disjoint.
    let mut model = vec![0u8; PIXELS];
    let mut supports = vec![0u8; PIXELS];
    for (i, pixel) in model.iter_mut().enumerate() {
        if i % (WIDTH as usize) < 32 {
            *pixel = 255;
        }
    }
    for (i, pixel) in supports.iter_mut().enumerate() {
        if i % (WIDTH as usize) >= 48 {
            *pixel = 255;
        }
    }
    encoder
        .push_layer_sectors(&[(0, model.clone()), (1, supports.clone())])
        .expect("a pushable multi-sector layer");
    // Layer 1: empty.
    encoder.push_layer_sectors(&[]).expect("an empty layer");

    let bytes = encoder.finish().expect("a writable file");
    validate::validate(&bytes, Level::Strict).expect("a multi-sector file must validate strictly");

    let file = LumenFile::open(&bytes, Level::Strict).expect("a multi-sector file must open");
    assert!(file.multi_sector());
    let sectors = file.layer_sectors(0).expect("layer 0 must decode");
    assert_eq!(sectors.len(), 2);
    assert_eq!(sectors[0].sector_id, 0);
    assert_eq!(sectors[1].sector_id, 1);
    assert_eq!(sectors[0].layer.pixels, model);
    assert_eq!(sectors[1].layer.pixels, supports);

    // The union is what a single-material reader prints.
    let union = file.layer(0).expect("the union must decode");
    for i in 0..PIXELS {
        assert_eq!(union.pixels[i], model[i].max(supports[i]), "pixel {i}");
    }

    // Sector 1 is non-empty, so a sector-0-only reader would drop content.
    assert!(
        !file
            .is_single_material_compatible()
            .expect("a checkable file"),
        "a print with content outside sector 0 is not single-material compatible"
    );

    // Per-sector timing resolves, and sector 1's override wins for sector 1.
    // Layer 0 is inside the bottom range, so it uses the bottom exposure.
    let sector_0 = file.timing_for(0, 0).expect("sector 0 timing");
    let sector_1 = file.timing_for(0, 1).expect("sector 1 timing");
    assert!(sector_0.is_bottom, "layer 0 is a bottom layer");
    assert_eq!(
        sector_0.exposure_sec, 30.0,
        "sector 0 takes META's bottom exposure"
    );
    assert_eq!(
        sector_1.exposure_sec, 35.0,
        "sector 1 overrides the bottom exposure"
    );
}

#[test]
fn extensions_and_embedded_scene_round_trip() {
    let mut encoder = Encoder::new(hdr(1), meta());
    encoder.set_voxl(b"{\"voxl\":1}".to_vec());
    encoder.add_extension(Extension {
        ext_version: 1,
        ext_type: *b"TEST",
        vendor_id: 0x1234,
        critical: false,
        encrypted: false,
        data: vec![1, 2, 3, 4],
    });
    encoder
        .push_layer(&vec![255u8; PIXELS])
        .expect("a pushable layer");
    let bytes = encoder.finish().expect("a writable file");

    validate::validate(&bytes, Level::Strict).expect("the file must validate strictly");
    let file = LumenFile::open(&bytes, Level::Strict).expect("the file must open");
    assert_eq!(
        file.voxl(),
        Some(&b"{\"voxl\":1}"[..]),
        "the scene is opaque"
    );
    let extensions = file.extensions();
    assert_eq!(extensions.len(), 1);
    assert_eq!(extensions[0].tag(), "TEST");
    assert_eq!(extensions[0].vendor_id, 0x1234);
    assert_eq!(extensions[0].data, vec![1, 2, 3, 4]);
}

/// A file whose layer table claims more bytes than the layer's stream uses.
///
/// This is the corpus' own invalid-vector style: introduce one defect, recompute
/// the trailer CRC, and assert that the advertised check is the first to fail -
/// at both levels, since padding is not a strict-only defect.
#[test]
fn padding_after_a_layer_stream_is_rejected() {
    let bytes = encode_without_hashes();
    validate::validate(&bytes, Level::Strict).expect("the unmodified file is valid");

    let mutated = pad_layer_one(&bytes);
    for level in [Level::Loose, Level::Strict] {
        let error = validate::validate(&mutated, level)
            .err()
            .unwrap_or_else(|| panic!("{level:?}: padding must be rejected"));
        assert_eq!(error.check_name(), "ree.no_trailing_bytes", "{level:?}");
    }

    // The reader refuses it as well: `open` validates first, so a layer whose
    // stored range exceeds its stream is rejected rather than decoded with the
    // surplus bytes quietly ignored.
    let refused = LumenFile::open(&mutated, Level::Loose).expect_err("the reader must refuse it");
    assert_eq!(refused.check_name(), "ree.no_trailing_bytes");
}

/// Encode the masks with the integrity tree omitted, so a mutation to the layer
/// table cannot also trip the leaf hashes.
fn encode_without_hashes() -> Vec<u8> {
    let layer_masks = masks();
    let mut encoder = Encoder::new(hdr(layer_masks.len() as u32), meta());
    encoder.set_dictionary(false);
    encoder.set_layer_hashes(false);
    for mask in &layer_masks {
        encoder.push_layer(mask).expect("a pushable layer");
    }
    encoder.finish().expect("a writable file")
}

/// Grow layer 1's `data_size` by one byte and rebuild the file around it.
fn pad_layer_one(bytes: &[u8]) -> Vec<u8> {
    use lumen::chunks::ltbl::LayerTable;
    use lumen::container::{self, ChunkType};

    let header = container::FileHeader::parse(bytes).unwrap();
    let directory = container::parse_directory(bytes, &header).unwrap();
    let descriptor = directory.find(ChunkType::LTBL).unwrap();
    let start = descriptor.offset as usize;
    let end = start + descriptor.stored_len() as usize;
    let mut table = LayerTable::parse(&bytes[start..end]).unwrap();
    table.entries[1].data_size += 1;

    let mut mutated = Vec::from(&bytes[..start]);
    mutated.extend_from_slice(&table.to_bytes());
    mutated.extend_from_slice(&bytes[end..bytes.len() - 8]);
    let crc = container::crc32c(&mutated);
    mutated.extend_from_slice(&container::TRAILER_MAGIC);
    mutated.extend_from_slice(&crc.to_le_bytes());
    mutated
}

#[test]
fn explicit_encoding_modes_round_trip() {
    for mode in [
        EncodeMode::Auto,
        EncodeMode::Binary,
        EncodeMode::Grayscale,
        EncodeMode::Split,
    ] {
        let mut selected: Vec<Vec<u8>> = Vec::new();
        for (index, mask) in masks().iter().enumerate() {
            let binary = mask.iter().all(|p| *p == 0 || *p == 255);
            match mode {
                EncodeMode::Binary if !binary => {
                    // Binary REE cannot represent an anti-aliased mask: the
                    // encoder must refuse it rather than re-quantise the pixels.
                    let mut probe = Encoder::new(hdr(1), meta());
                    let err = probe
                        .push_layer_with_mode(mask, mode)
                        .expect_err("binary REE must reject an anti-aliased mask");
                    assert_eq!(err.check_name(), "ree.first_value", "layer {index}");
                    continue;
                }
                // Section 5.6: a mask whose pixels are all 0x00/0xFF MUST use tag
                // 0x00, and section 11.3 makes a strict validator reject one
                // stored as grayscale. Forcing another tag on such a mask
                // therefore builds a stream no strict reader accepts, which is
                // not a property worth asserting.
                EncodeMode::Grayscale | EncodeMode::Split if binary => continue,
                _ => {}
            }
            selected.push(mask.clone());
        }
        if mode == EncodeMode::Binary {
            continue;
        }
        assert!(!selected.is_empty(), "each mode has masks to encode");

        let mut encoder = Encoder::new(hdr(selected.len() as u32), meta());
        for mask in &selected {
            encoder
                .push_layer_with_mode(mask, mode)
                .unwrap_or_else(|e| panic!("a pushable layer in mode {mode:?}: {e}"));
        }
        let bytes = encoder.finish().expect("a writable file");
        validate::validate(&bytes, Level::Strict)
            .unwrap_or_else(|e| panic!("a {} file must validate strictly: {e}", mode_name(mode)));
        let file = LumenFile::open(&bytes, Level::Strict).expect("the file must open");
        for (index, mask) in selected.iter().enumerate() {
            let decoded = file.layer(index as u32).expect("a decodable layer");
            assert_eq!(
                &decoded.pixels,
                mask,
                "layer {index} in mode {}",
                mode_name(mode)
            );
        }
    }
}

fn mode_name(mode: EncodeMode) -> &'static str {
    match mode {
        EncodeMode::Auto => "Auto",
        EncodeMode::Binary => "Binary",
        EncodeMode::Grayscale => "Grayscale",
        EncodeMode::Split => "Split",
    }
}
