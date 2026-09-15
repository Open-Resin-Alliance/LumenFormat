//! Vector construction: layer encoding, the chunk list, the manifest's golden data
//! and the two builders the vectors go through.

use serde_json::Value;

use crate::container::{self, Chunk, Layout, FLAG_ENCRYPTED, FLAG_MULTI_SECTOR};
use crate::crypto;
use crate::hash;
use crate::json;
use crate::obj;
use crate::payload::{self, LayerEntry};
use crate::ree;
use crate::timing;
use crate::ZSTD_LAYER_LEVEL;

/// The encoder name every HDR payload carries.
const ENCODER_NAME: &str = "LumenFormat test vectors 1.0";

/// One span of a sector: start, end (exclusive) and the value its pixels carry.
pub type Span = ree::Span;

/// One layer: its sectors, each a list of spans.
pub type Layer = Vec<Vec<Span>>;

/// `count` layers that all carry the same single sector.
pub fn repeated(count: usize, spans: &[Span]) -> Vec<Layer> {
    (0..count).map(|_| vec![spans.to_vec()]).collect()
}

/// Everything one vector's layer data is made of, before it is stored.
pub struct Layers {
    pub multi_sector: bool,
    pub layer_bytes: Vec<Vec<u8>>,
    pub sector_counts: Vec<u32>,
    pub tags: Vec<Option<u8>>,
    pub sector_tags: Vec<Vec<u8>>,
    pub frames: Vec<Vec<u8>>,
    pub uncompressed_sizes: Vec<usize>,
    pub entries: Vec<LayerEntry>,
    pub leaves: Vec<[u8; 32]>,
    pub use_dict: bool,
    pub dict_bytes: Vec<u8>,
    pub dict_id: u32,
}

/// The knobs [`encode_layers`] takes.
pub struct LayerOptions<'a> {
    pub block_size: usize,
    pub use_dict: bool,
    pub dict_samples_bytes: usize,
    pub split_layers: &'a [usize],
    pub force_run_count_zero: &'a [usize],
}

/// Everything about one vector's layer data, before it is stored.
///
/// Shared by the plaintext and encrypted builders: encryption changes how the block
/// frames and content chunks are stored, never what they decode to.
pub fn encode_layers(display: (usize, usize), layers: &[Layer], options: &LayerOptions) -> Layers {
    let total = display.0 * display.1;
    let multi_sector = layers.iter().any(|sectors| sectors.len() > 1);

    let mut layer_bytes: Vec<Vec<u8>> = Vec::with_capacity(layers.len());
    let mut sector_counts: Vec<u32> = Vec::with_capacity(layers.len());
    let mut tags: Vec<Option<u8>> = Vec::with_capacity(layers.len());
    let mut sector_tags: Vec<Vec<u8>> = Vec::with_capacity(layers.len());

    for (index, sectors) in layers.iter().enumerate() {
        let prefer_split = options.split_layers.contains(&index);
        let encoded: Vec<(usize, Vec<u8>)> = sectors
            .iter()
            .enumerate()
            .filter_map(|(sector_id, spans)| {
                ree::encode_sector(&ree::runs_from_spans(total, spans), prefer_split)
                    .map(|body| (sector_id, body))
            })
            .collect();

        if options.force_run_count_zero.contains(&index) {
            // Non-canonical all-black form: tag 0x00, first_value 0x00, run_count 0.
            let mut bytes = vec![ree::TAG_BINARY, 0x00];
            bytes.extend(ree::varint(0));
            layer_bytes.push(bytes);
            sector_counts.push(1);
            tags.push(Some(ree::TAG_BINARY));
            sector_tags.push(vec![ree::TAG_BINARY]);
            continue;
        }

        if encoded.is_empty() {
            layer_bytes.push(Vec::new());
            sector_counts.push(0);
            tags.push(None);
            sector_tags.push(Vec::new());
            continue;
        }

        let data = if multi_sector {
            // Every layer in a multi-sector file carries the sector_count varint,
            // including layers with a single active sector.
            let mut data = ree::varint(encoded.len() as u64);
            for (sector_id, body) in &encoded {
                data.extend(ree::varint(*sector_id as u64));
                data.extend(ree::varint(body.len() as u64));
                data.extend_from_slice(body);
            }
            data
        } else {
            encoded[0].1.clone()
        };

        tags.push(if multi_sector { None } else { Some(data[0]) });
        sector_tags.push(encoded.iter().map(|(_, body)| body[0]).collect());
        sector_counts.push(encoded.len() as u32);
        layer_bytes.push(data);
    }

    let mut dict_bytes = Vec::new();
    let mut dict_id = 0;
    if options.use_dict {
        let samples: Vec<&[u8]> = layer_bytes
            .iter()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| bytes.as_slice())
            .collect();
        let dict = zstd::dict::from_samples(&samples, options.dict_samples_bytes)
            .expect("dictionary training");
        dict_id = zstd::zstd_safe::get_dict_id_from_dict(&dict)
            .map(|id| id.get())
            .unwrap_or(0);
        dict_bytes = dict;
    }

    let mut compressor = if options.use_dict {
        zstd::bulk::Compressor::with_dictionary(ZSTD_LAYER_LEVEL, &dict_bytes)
    } else {
        zstd::bulk::Compressor::new(ZSTD_LAYER_LEVEL)
    }
    .expect("zstd compressor");

    let mut frames = Vec::new();
    let mut uncompressed_sizes = Vec::new();
    let mut entries = Vec::with_capacity(layer_bytes.len());
    for start in (0..layer_bytes.len()).step_by(options.block_size) {
        let block_index = (start / options.block_size) as u32;
        let group = start..(start + options.block_size).min(layer_bytes.len());
        let payload: Vec<u8> = group
            .clone()
            .flat_map(|i| layer_bytes[i].iter().copied())
            .collect();
        let frame = compressor
            .compress(&payload)
            .expect("layer block compression");
        frames.push(frame);
        uncompressed_sizes.push(payload.len());

        let mut offset = 0u64;
        for i in group {
            entries.push(LayerEntry {
                block_index,
                data_offset: offset,
                data_size: layer_bytes[i].len() as u64,
                sector_count: sector_counts[i],
            });
            offset += layer_bytes[i].len() as u64;
        }
    }

    let leaves = layer_bytes
        .iter()
        .map(|bytes| hash::leaf_hash(bytes))
        .collect();

    Layers {
        multi_sector,
        layer_bytes,
        sector_counts,
        tags,
        sector_tags,
        frames,
        uncompressed_sizes,
        entries,
        leaves,
        use_dict: options.use_dict,
        dict_bytes,
        dict_id,
    }
}

/// `count` layers of scattered runs, for vectors that need dictionary samples.
pub fn sparse_layers(count: usize, total: usize) -> Vec<Layer> {
    let mut layers = Vec::with_capacity(count);
    for i in 0..count {
        let mut spans: Vec<Span> = Vec::new();
        let mut pos = 0;
        for k in 0..60 {
            let gap = 40 + ((i * 7 + k * 13) % 60);
            let length = 20 + ((i + k) % 40);
            let start = pos + gap;
            if start + length >= total {
                break;
            }
            let value = if (i + k) % 3 != 0 {
                255
            } else {
                128 + ((i * k) % 100) as u8
            };
            spans.push((start, start + length, value));
            pos = start + length;
        }
        layers.push(vec![spans]);
    }
    layers
}

/// Everything one vector needs, from its layers to the words the manifest uses.
pub struct VectorSpec<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub features: &'a [&'a str],
    pub display: (usize, usize),
    pub layer_height_um: u32,
    pub layers: Vec<Layer>,
    pub block_size: usize,
    pub use_dict: bool,
    pub dict_samples_bytes: usize,
    pub split_layers: Vec<usize>,
    pub force_run_count_zero: Vec<usize>,
    pub meta_extra: Vec<(&'a str, Value)>,
    pub prof: Option<Vec<u8>>,
    pub lrov: Option<Vec<Value>>,
    pub prevs: Vec<(Vec<u8>, u32, bool)>,
    pub voxl: Option<Vec<u8>>,
    pub extds: Vec<(Vec<u8>, u32)>,
}

impl VectorSpec<'_> {
    /// The `META` payload's object (spec 4.2), which the manifest's timing
    /// resolves from the way the file's own reader would.
    pub fn meta_value(&self) -> Value {
        payload::meta_value(&self.meta_extra)
    }

    /// The `SECT` definitions the file carries (spec 4.5), in chunk order.
    ///
    /// The corpus has one support sector, and it is present exactly when the
    /// layer data is multi-sector.
    pub fn sectors(&self, multi_sector: bool) -> Vec<Value> {
        if multi_sector {
            vec![payload::sect_value(1, "Support", 3000)]
        } else {
            Vec::new()
        }
    }

    /// The `LROV` entries the file carries (spec 4.6), in file order.
    pub fn overrides(&self) -> &[Value] {
        self.lrov.as_deref().unwrap_or(&[])
    }
}

impl<'a> Default for VectorSpec<'a> {
    fn default() -> Self {
        VectorSpec {
            name: "",
            description: "",
            features: &[],
            display: (0, 0),
            layer_height_um: 50,
            layers: Vec::new(),
            block_size: 0,
            use_dict: false,
            dict_samples_bytes: 2048,
            split_layers: Vec::new(),
            force_run_count_zero: Vec::new(),
            meta_extra: Vec::new(),
            prof: None,
            lrov: None,
            prevs: Vec::new(),
            voxl: None,
            extds: Vec::new(),
        }
    }
}

/// A file and the manifest entry that describes it.
pub struct Built {
    pub raw: Vec<u8>,
    pub meta: Value,
    pub layout: Layout,
}

/// The chunk list before any encryption, in the order section 3 recommends.
pub fn content_chunks(spec: &VectorSpec, enc: &Layers) -> Vec<Chunk> {
    let (w, h) = spec.display;
    let mut chunks = vec![
        Chunk::new(
            b"HDR\0",
            payload::hdr(&payload::Header {
                encoder_name: ENCODER_NAME,
                display_w: w as u32,
                display_h: h as u32,
                layer_height_um: spec.layer_height_um,
                total_layers: spec.layers.len() as u32,
                ..Default::default()
            }),
        ),
        Chunk::new(b"META", json::dumps(&spec.meta_value())).compressed(),
    ];
    if let Some(prof) = &spec.prof {
        chunks.push(Chunk::new(b"PROF", prof.clone()).compressed());
    }
    for definition in spec.sectors(enc.multi_sector) {
        chunks.push(Chunk::new(b"SECT", json::dumps(&definition)).compressed());
    }
    if let Some(lrov) = &spec.lrov {
        chunks.push(Chunk::new(b"LROV", payload::lrov(lrov)).compressed());
    }
    if enc.use_dict {
        chunks.push(Chunk::new(
            b"ZDIC",
            payload::zdic(&enc.dict_bytes, enc.dict_id),
        ));
    }
    for (payload, role, seal) in &spec.prevs {
        let mut chunk = Chunk::new(b"PREV", payload.clone()).flags(*role);
        if *seal {
            chunk = chunk.sealable();
        }
        chunks.push(chunk);
    }
    if let Some(voxl) = &spec.voxl {
        chunks.push(Chunk::new(b"VOXL", voxl.clone()).compressed());
    }
    for (payload, flags) in &spec.extds {
        chunks.push(
            Chunk::new(b"EXTD", payload.clone())
                .compressed()
                .flags(*flags),
        );
    }
    chunks.push(Chunk::new(b"LTBL", payload::ltbl(&enc.entries)));
    chunks.push(Chunk::new(b"LHAS", payload::lhas(&enc.leaves)));
    chunks.push(Chunk::new(
        b"LAYR",
        payload::layr(&enc.frames, &enc.uncompressed_sizes),
    ));
    chunks
}

/// The manifest entry's golden data for one vector.
///
/// The entry pins the bytes, and `resolved_timing` additionally pins what a
/// conforming reader must resolve from the file's META, `SECT` and `LROV`
/// payloads for a sample of `(layer, sector)` points ([`crate::timing`]), so a
/// third-party implementation has numbers to agree with and not only bytes to
/// re-derive. The sample is the product of a set of layers and a set of sectors,
/// chosen to touch every branch of the pipeline rather than every layer: the two
/// ends of the bottom range and its first transition step, the first fully-normal
/// layer and the last layer, each of them beside every layer an `LROV` entry
/// names and that layer's neighbours - which is what puts an override boundary and
/// the layers on either side of it in the same table - against sector 0, every
/// sector a `SECT` chunk defines and every sector an override targets. Pinning
/// every layer would add no branch the pipeline does not already show here: a
/// reader that agrees at these points and disagrees between them has a boundary
/// error, not a sampling gap.
pub fn vector_meta(
    spec: &VectorSpec,
    enc: &Layers,
    chunks: &[Chunk],
    raw: &[u8],
    layout: &Layout,
    crypto_value: Option<Value>,
    chunk_hashes: Option<Value>,
) -> Value {
    let (w, h) = spec.display;
    let layer_entries: Vec<Value> = (0..enc.layer_bytes.len())
        .map(|i| {
            obj![
                "index" => i,
                "block_index" => enc.entries[i].block_index,
                "data_offset" => enc.entries[i].data_offset,
                "data_size" => enc.entries[i].data_size,
                "sector_count" => enc.sector_counts[i],
                "tag" => enc.tags[i],
                "sector_tags" => enc.sector_tags[i].clone(),
                "decompressed_sha256" => hash::sha256_hex(&enc.layer_bytes[i]),
                "lhas_leaf" => hash::hex(&enc.leaves[i]),
            ]
        })
        .collect();

    let features: Vec<Value> = spec.features.iter().map(|f| Value::from(*f)).collect();
    // The timing pipeline reads the very payloads the chunks carry, not a second
    // copy of them: META as `content_chunks` wrote it, the `SECT` definitions it
    // wrote, and the LROV entries in file order.
    let meta = spec.meta_value();
    let sectors = spec.sectors(enc.multi_sector);
    let timing = timing::Pipeline::new(
        &meta,
        &sectors,
        spec.overrides(),
        enc.layer_bytes.len() as u32,
    );
    let mut entries: Vec<(&str, Value)> = vec![
        ("name", Value::from(spec.name)),
        ("description", Value::from(spec.description)),
        ("features", Value::from(features)),
        ("display_width_px", Value::from(w)),
        ("display_height_px", Value::from(h)),
        ("total_layers", Value::from(enc.layer_bytes.len())),
        ("layer_height_um", Value::from(spec.layer_height_um)),
        ("block_size_layers", Value::from(spec.block_size)),
        ("header_flags", Value::from(container::read_u32(raw, 20))),
        ("multi_sector", Value::from(enc.multi_sector)),
        ("chunk_count", Value::from(chunks.len())),
        ("dir_offset", Value::from(layout.dir_offset)),
        (
            "total_uncompressed_size",
            Value::from(container::read_u64(raw, 24)),
        ),
        (
            "trailer_crc32c",
            Value::from(format!("0x{:08X}", container::trailer_crc(raw, layout))),
        ),
        ("file_size", Value::from(raw.len())),
        ("file_sha256", Value::from(container::file_sha256(raw))),
        (
            "dict",
            obj![
                "present" => enc.use_dict,
                "dict_id" => enc.dict_id,
                "dict_size" => enc.dict_bytes.len(),
            ],
        ),
        (
            "blocks",
            Value::Array(container::stored_block_table(raw, layout)),
        ),
        (
            "merkle_root",
            Value::from(hash::hex(&hash::merkle_root(&enc.leaves))),
        ),
        ("layers", Value::Array(layer_entries)),
        ("resolved_timing", timing.manifest()),
    ];
    if let Some(crypto_value) = crypto_value {
        entries.push(("crypto", crypto_value));
    }
    // Python's `if chunk_hashes:` is a truthiness test, so a file with none of
    // those chunks carries no such key at all.
    if let Some(chunk_hashes) = chunk_hashes {
        if chunk_hashes.as_object().is_some_and(|map| !map.is_empty()) {
            entries.push(("chunk_payload_sha256", chunk_hashes));
        }
    }
    json::obj(entries)
}

/// One plaintext vector.
pub fn build_vector(spec: &VectorSpec) -> Built {
    let enc = encode_layers(
        spec.display,
        &spec.layers,
        &LayerOptions {
            block_size: spec.block_size,
            use_dict: spec.use_dict,
            dict_samples_bytes: spec.dict_samples_bytes,
            split_layers: &spec.split_layers,
            force_run_count_zero: &spec.force_run_count_zero,
        },
    );
    let chunks = content_chunks(spec, &enc);
    let header_flags = if enc.multi_sector {
        FLAG_MULTI_SECTOR
    } else {
        0
    };
    let (raw, layout) = container::build_file(&chunks, header_flags);
    let meta = vector_meta(
        spec,
        &enc,
        &chunks,
        &raw,
        &layout,
        None,
        Some(payload::payload_hashes(&chunks)),
    );
    Built { raw, meta, layout }
}

/// One entry of the machine section, in file order.
pub enum Role {
    /// The entry whose private key the manifest publishes.
    Local,
    /// A machine that is not this one.
    Foreign,
    /// An entry for our own fingerprint whose ephemeral key is the low-order point.
    Decoy,
}

/// The AUTH chunk's own knobs.
pub struct CryptoSpec<'a> {
    pub cipher_id: &'a str,
    pub mode: u32,
    pub argon2_params: (u32, u32, u32),
    pub password_trim: usize,
    pub machine_roles: &'a [Role],
    pub session_key: Option<[u8; 32]>,
}

impl<'a> Default for CryptoSpec<'a> {
    fn default() -> Self {
        CryptoSpec {
            cipher_id: "A256",
            mode: 1,
            argon2_params: crypto::DEFAULT_ARGON2,
            password_trim: 0,
            machine_roles: &[],
            session_key: None,
        }
    }
}

/// An encrypted file: the same content chunks, sealed, plus an AUTH chunk.
///
/// The non-canonical all-black form is never forced here, because an encrypted
/// vector has no need of it - the Python producer passes the empty set too.
pub fn build_encrypted_vector(spec: &VectorSpec, crypto_spec: &CryptoSpec) -> Built {
    let enc = encode_layers(
        spec.display,
        &spec.layers,
        &LayerOptions {
            block_size: spec.block_size,
            use_dict: spec.use_dict,
            dict_samples_bytes: spec.dict_samples_bytes,
            split_layers: &spec.split_layers,
            force_run_count_zero: &[],
        },
    );

    let session_key = crypto_spec.session_key.unwrap_or_else(|| {
        crypto::det(&labelled(b"session-key|", spec.name.as_bytes()), 32)
            .try_into()
            .expect("32 bytes")
    });
    let salt = crypto::det(&labelled(b"argon2-salt|", spec.name.as_bytes()), 16);
    let (iterations, memory_kib, parallelism) = crypto_spec.argon2_params;

    let mut password_sec = Vec::new();
    if crypto_spec.mode & 1 != 0 {
        password_sec = crypto::password_section(
            &session_key,
            crypto::TEST_PASSWORD,
            &salt,
            iterations,
            memory_kib,
            parallelism,
        );
        if crypto_spec.password_trim > 0 {
            password_sec.truncate(password_sec.len() - crypto_spec.password_trim);
        } else {
            // The published password must really recover the session key.
            let kek = crypto::argon2_kek(
                crypto::TEST_PASSWORD,
                &salt,
                iterations,
                memory_kib,
                parallelism,
            );
            assert_eq!(
                crypto::aes_key_unwrap(&kek, &password_sec[25..]),
                session_key,
                "password section self-check failed"
            );
        }
    }

    let local_private: [u8; 32] =
        crypto::det(&labelled(b"machine-private|", spec.name.as_bytes()), 32)
            .try_into()
            .expect("32 bytes");
    let mut machine_sec = Vec::new();
    let mut local_index = None;
    for role in crypto_spec.machine_roles {
        match role {
            Role::Local => {
                local_index = Some(machine_sec.len() / 104);
                machine_sec.extend(crypto::machine_entry(
                    &session_key,
                    &local_private,
                    spec.name.as_bytes(),
                ));
            }
            Role::Foreign => {
                let foreign: [u8; 32] =
                    crypto::det(&labelled(b"foreign-private|", spec.name.as_bytes()), 32)
                        .try_into()
                        .expect("32 bytes");
                machine_sec.extend(crypto::machine_entry(
                    &session_key,
                    &foreign,
                    &labelled(spec.name.as_bytes(), b"|foreign"),
                ));
            }
            Role::Decoy => machine_sec.extend(crypto::decoy_entry(
                &crypto::public_of(&local_private),
                spec.name.as_bytes(),
            )),
        }
    }

    let chunks = content_chunks(spec, &enc);
    let sealed = crypto::seal_content_chunks(
        chunks.clone(),
        &enc.frames,
        &enc.uncompressed_sizes,
        &session_key,
        crypto_spec.cipher_id,
    );
    let auth = Chunk::new(
        b"AUTH",
        crypto::auth_payload(
            crypto_spec.cipher_id,
            crypto_spec.mode,
            &password_sec,
            &machine_sec,
        ),
    );

    // Section 3 lists PROF before AUTH.
    let after = if spec.prof.is_some() { 3 } else { 2 };
    let mut ordered = sealed;
    ordered.insert(after, auth);

    let header_flags = FLAG_ENCRYPTED
        | if enc.multi_sector {
            FLAG_MULTI_SECTOR
        } else {
            0
        };
    let (raw, layout) = container::build_file(&ordered, header_flags);

    let mode_names: Vec<Value> = [(1, "password"), (2, "machine-binding")]
        .into_iter()
        .filter(|(bit, _)| crypto_spec.mode & bit != 0)
        .map(|(_, name)| Value::from(name))
        .collect();
    let mut crypto_entries: Vec<(&str, Value)> = vec![
        ("cipher_id", Value::from(crypto_spec.cipher_id)),
        ("auth_version", Value::from(1)),
        ("mode", Value::from(crypto_spec.mode)),
        ("mode_names", Value::from(mode_names)),
    ];
    if crypto_spec.mode & 1 != 0 {
        crypto_entries.push(("password_utf8", Value::from(crypto::TEST_PASSWORD)));
        crypto_entries.push((
            "argon2",
            obj![
                "salt" => hash::hex(&salt),
                "iterations" => iterations,
                "memory_kib" => memory_kib,
                "parallelism" => parallelism,
            ],
        ));
    }
    if crypto_spec.mode & 2 != 0 {
        if let Some(index) = local_index {
            crypto_entries.push(("local_recipient_index", Value::from(index)));
            crypto_entries.push((
                "local_recipient_private_key",
                Value::from(hash::hex(&local_private)),
            ));
        }
    }

    let meta = vector_meta(
        spec,
        &enc,
        &ordered,
        &raw,
        &layout,
        Some(json::obj(crypto_entries)),
        Some(payload::payload_hashes(&chunks)),
    );
    Built { raw, meta, layout }
}

/// `prefix` and `suffix` back to back.
fn labelled(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + suffix.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(suffix);
    out
}
