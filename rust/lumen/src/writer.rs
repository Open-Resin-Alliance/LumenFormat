//! Writing a file: [`Encoder`], which assembles a conforming `.lumen` container.
//!
//! The encoder owns the choices the specification leaves to it (section 5.6): it
//! picks a tag per layer, picks a block size, and decides whether to train a
//! dictionary. Layer masks are encoded as they are pushed, so the encoder never
//! holds the pixel data of the whole print - only its run-end encoded form.
//!
//! `finish` produces the container in the order section 3 recommends: `HDR`,
//! `META`, the optional chunks, `LTBL`, `LAYR`, and the directory at the end, so
//! a streaming writer could append as it goes. Payloads are 8-byte aligned, as
//! section 3.2 prefers, and the trailer's CRC-32C covers every preceding byte.
//!
//! Encryption follows section 9.1 exactly: `HDR`, `AUTH`, `LTBL`, `LHAS` and the
//! `LAYR` header and block table stay plaintext; `META`, `PROF`, `SECT`, `LROV`,
//! `VOXL` and `ZDIC` are sealed as single units; each `LAYR` block frame is its
//! own unit. `PREV` and `EXTD` are written in the clear, which section 9.1
//! permits and which keeps a thumbnail usable without a key.

use crate::check::Check;
use crate::chunks::extd::Extension;
use crate::chunks::hdr::Hdr;
use crate::chunks::layr::{BlockEntry, Layr};
use crate::chunks::lhas::{self, LayerHashes};
use crate::chunks::ltbl::{LayerEntry, LayerTable};
use crate::chunks::preview::PreviewRole;
use crate::chunks::zdic::ZstdDictionary;
use crate::chunks::{self, json_chunks};
use crate::container::{
    self, ChunkDescriptor, ChunkType, Directory, FileHeader, CHUNK_FLAG_ENCRYPTED, FLAG_ENCRYPTED,
    FLAG_MULTI_SECTOR,
};
use crate::crypto::{self, Auth, Cipher, RecipientEntry, SessionKey};
use crate::error::{Error, Result};
use crate::io::Writer;
use crate::json::{Lrov, Meta, Profile, Sect};
use crate::ree::{self, EncodeMode};
use crate::sectors::{self, SectorLayer};

/// Argon2id parameters for password-mode encryption.
///
/// The defaults sit well inside the ceilings a reader is required to enforce
/// (§11.4: iterations <= 10, memory <= 4 GiB, lanes <= 16), so a file this crate
/// writes is one every conforming reader must be willing to open. The encoder
/// does not police the values it is handed: a caller who deliberately asks for
/// more is writing a file that readers MUST refuse rather than attempt, and the
/// conformance corpus contains exactly such a file on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Time cost.
    pub iterations: u32,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Lanes.
    pub parallelism: u8,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // Print-file decryption happens on printer hardware, so the cost has to
        // land between "a weak password is cheap to attack" and "the printer
        // takes a minute to start". A caller who wants more can say so.
        Argon2Params {
            iterations: 3,
            memory_kib: 65_536,
            parallelism: 1,
        }
    }
}

/// How to encrypt the file being written.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// The AEAD cipher.
    pub cipher: Cipher,
    /// Wrap the session key under this password.
    pub password: Option<String>,
    /// Wrap the session key for each of these X25519 public keys.
    pub recipients: Vec<[u8; 32]>,
    /// Argon2id parameters, used when a password is set.
    pub argon2: Argon2Params,
}

impl EncryptOptions {
    /// Password-mode encryption with default Argon2id parameters.
    pub fn password(password: impl Into<String>) -> EncryptOptions {
        EncryptOptions {
            cipher: Cipher::Aes256Gcm,
            password: Some(password.into()),
            recipients: Vec::new(),
            argon2: Argon2Params::default(),
        }
    }
}

/// The block size a fresh encoder starts with (section 4.10 recommends 32-64).
pub const DEFAULT_BLOCK_LAYERS: u32 = 64;
/// The zstd level a fresh encoder starts with.
pub const DEFAULT_ZSTD_LEVEL: i32 = 6;
/// The zstd level for the small JSON chunks (section 6.3).
pub const JSON_ZSTD_LEVEL: i32 = 3;
/// How many layers may be sampled for dictionary training (section 6.2).
pub const DICTIONARY_SAMPLE_LAYERS: usize = 256;

/// One layer, already run-end encoded.
#[derive(Debug, Clone)]
enum LayerRecord {
    /// The empty-layer form: no bytes, `sector_count == 0`.
    Empty,
    /// Single-sector mask data: the tag followed by the REE stream.
    Single(Vec<u8>),
    /// Multi-sector mask data, before framing: `(sector_id, tag plus stream)`.
    Sectors(Vec<(u32, Vec<u8>)>),
}

/// A chunk ready to be laid out.
#[derive(Debug)]
struct Pending {
    chunk_type: ChunkType,
    /// The bytes as they will sit on disk.
    stored: Vec<u8>,
    /// The payload's size once any framing and compression are undone.
    size_uncompressed: u64,
    /// The stored length when it differs from the raw payload, else zero.
    size_compressed: u64,
    flags: u32,
}

/// Builds a `.lumen` file.
#[derive(Debug)]
pub struct Encoder {
    hdr: Hdr,
    meta: Meta,
    profile: Option<Profile>,
    sectors: Vec<Sect>,
    lrov: Option<Lrov>,
    previews: Vec<(PreviewRole, Vec<u8>)>,
    extensions: Vec<Extension>,
    voxl: Option<Vec<u8>>,
    block_layers: u32,
    zstd_level: i32,
    dictionary: bool,
    layer_hashes: bool,
    encryption: Option<EncryptOptions>,
    session: Option<SessionKey>,
    layers: Vec<LayerRecord>,
    multi_sector: bool,
}

impl Encoder {
    /// Start a file with the given `HDR` and `META`.
    ///
    /// `hdr.total_layers` must equal the number of layers pushed.
    pub fn new(hdr: Hdr, meta: Meta) -> Encoder {
        Encoder {
            hdr,
            meta,
            profile: None,
            sectors: Vec::new(),
            lrov: None,
            previews: Vec::new(),
            extensions: Vec::new(),
            voxl: None,
            block_layers: DEFAULT_BLOCK_LAYERS,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            dictionary: true,
            layer_hashes: true,
            encryption: None,
            session: None,
            layers: Vec::new(),
            multi_sector: false,
        }
    }

    /// Attach a reusable print profile.
    pub fn set_profile(&mut self, profile: Profile) {
        self.profile = Some(profile);
    }

    /// Declare the sectors this print uses; switches the file to multi-sector.
    pub fn set_sectors(&mut self, sectors: Vec<Sect>) {
        self.multi_sector = true;
        self.sectors = sectors;
    }

    /// Attach per-layer overrides.
    pub fn set_lrov(&mut self, lrov: Lrov) {
        self.lrov = Some(lrov);
    }

    /// Add a PNG preview.
    pub fn add_preview(&mut self, role: PreviewRole, png: Vec<u8>) {
        self.previews.push((role, png));
    }

    /// Add a vendor or standard extension.
    pub fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }

    /// Embed the scene that produced this print, verbatim.
    pub fn set_voxl(&mut self, voxl: Vec<u8>) {
        self.voxl = Some(voxl);
    }

    /// Layers per zstd block frame.
    pub fn set_block_layers(&mut self, layers: u32) {
        self.block_layers = layers.max(1);
    }

    /// zstd compression level for the layer blocks.
    pub fn set_zstd_level(&mut self, level: i32) {
        self.zstd_level = level;
    }

    /// Whether to train and emit a `ZDIC` dictionary (section 6.2).
    pub fn set_dictionary(&mut self, enabled: bool) {
        self.dictionary = enabled;
    }

    /// Whether to emit an `LHAS` integrity tree.
    pub fn set_layer_hashes(&mut self, enabled: bool) {
        self.layer_hashes = enabled;
    }

    /// Encrypt the file.
    pub fn set_encryption(&mut self, options: EncryptOptions) {
        self.session = Some(SessionKey::generate());
        self.encryption = Some(options);
    }

    /// The session key this encoder uses, for a caller that wants to keep it.
    pub fn session_key(&self) -> Option<SessionKey> {
        self.session
    }

    /// Push one layer's mask, choosing its encoding per [`EncodeMode::Auto`].
    pub fn push_layer(&mut self, pixels: &[u8]) -> Result<()> {
        self.push_layer_with_mode(pixels, EncodeMode::Auto)
    }

    /// Push one layer's mask with an explicit encoding.
    pub fn push_layer_with_mode(&mut self, pixels: &[u8], mode: EncodeMode) -> Result<()> {
        let total_pixels = self.total_pixels();
        if pixels.len() != total_pixels as usize {
            return Err(Error::new(
                Check::ReeDataSize,
                format!(
                    "pixels has {} entries but the display holds {total_pixels}",
                    pixels.len()
                ),
            ));
        }
        let record = match ree::encode(pixels, total_pixels, mode)? {
            None => LayerRecord::Empty,
            // `ree::encode` returns the mask data with its tag already in front,
            // which is exactly what a layer stores; the tag is repeated here only
            // to be dropped.
            Some((_tag, mask)) => {
                if self.multi_sector {
                    LayerRecord::Sectors(vec![(0, mask)])
                } else {
                    LayerRecord::Single(mask)
                }
            }
        };
        self.layers.push(record);
        Ok(())
    }

    /// Push one multi-sector layer: each entry is a sector id and its mask.
    ///
    /// Sector 0 is implicit, so a layer whose only content is sector 0 is pushed
    /// with [`Encoder::push_layer`] instead. A sector with no exposed pixel is
    /// omitted, and a layer whose every sector is empty is stored as the
    /// empty-layer form.
    pub fn push_layer_sectors(&mut self, sectors: &[(u32, Vec<u8>)]) -> Result<()> {
        let total_pixels = self.total_pixels();
        let mut masks: Vec<(u32, Vec<u8>)> = Vec::new();
        for (sector_id, pixels) in sectors {
            if pixels.len() != total_pixels as usize {
                return Err(Error::new(
                    Check::ReeDataSize,
                    format!(
                        "sector {sector_id} has {} pixels but the display holds {total_pixels}",
                        pixels.len()
                    ),
                ));
            }
            if masks.iter().any(|(id, _)| id == sector_id) {
                return Err(Error::new(
                    Check::SectorTags,
                    format!("sector {sector_id} appears twice in one layer"),
                ));
            }
            if let Some((_tag, mask)) = ree::encode(pixels, total_pixels, EncodeMode::Auto)? {
                masks.push((*sector_id, mask));
            }
        }
        if masks.is_empty() {
            self.layers.push(LayerRecord::Empty);
        } else {
            self.multi_sector = true;
            self.layers.push(LayerRecord::Sectors(masks));
        }
        Ok(())
    }

    fn total_pixels(&self) -> u32 {
        self.hdr.total_pixels()
    }

    /// Assemble the container.
    ///
    /// Fails if the number of pushed layers disagrees with `hdr.total_layers`.
    pub fn finish(self) -> Result<Vec<u8>> {
        let pushed = self.layers.len() as u32;
        if pushed != self.hdr.total_layers {
            return Err(Error::new(
                Check::HdrTotalLayers,
                format!(
                    "HDR declares {} layers but {pushed} were pushed",
                    self.hdr.total_layers
                ),
            ));
        }

        let multi_sector = self.multi_sector || !self.sectors.is_empty();

        // 1. Layers to mask data, then blocks.
        let masks: Vec<Vec<u8>> = self
            .layers
            .iter()
            .map(|layer| match layer {
                LayerRecord::Empty => Ok(Vec::new()),
                LayerRecord::Single(mask) => Ok(mask.clone()),
                LayerRecord::Sectors(list) => {
                    let framed: Vec<SectorLayer> = list
                        .iter()
                        .map(|(sector_id, mask)| SectorLayer {
                            sector_id: *sector_id,
                            mask: mask.clone(),
                        })
                        .collect();
                    Ok(sectors::encode(&framed))
                }
            })
            .collect::<Result<_>>()?;

        let block_layers = self.block_layers.max(1) as usize;
        let mut entries = Vec::with_capacity(masks.len());
        let mut blocks: Vec<(BlockEntry, Vec<u8>)> = Vec::new();
        for chunk in masks.chunks(block_layers) {
            let block_index = blocks.len() as u32;
            let mut plaintext = Vec::new();
            for mask in chunk {
                entries.push((block_index, plaintext.len() as u64, mask.len() as u32));
                plaintext.extend_from_slice(mask);
            }
            blocks.push((
                BlockEntry {
                    frame_offset: 0,
                    frame_size: 0,
                    uncompressed_size: plaintext.len() as u64,
                },
                plaintext,
            ));
        }

        // 2. The dictionary, trained on the first layers (section 6.2).
        let dictionary = if self.dictionary {
            let samples: Vec<&[u8]> = blocks
                .iter()
                .flat_map(|(_, plaintext)| split_samples(plaintext))
                .take(DICTIONARY_SAMPLE_LAYERS)
                .collect();
            match chunks::train_dictionary(&samples, 112_640) {
                Ok(bytes) if !bytes.is_empty() && chunks::dictionary_id(&bytes) != 0 => {
                    Some(ZstdDictionary {
                        zdic_version: 1,
                        dict_id: chunks::dictionary_id(&bytes),
                        dict_bytes: bytes,
                    })
                }
                // Training fails on a degenerate print - too little or too
                // uniform data. The specification's answer is to omit ZDIC and
                // compress without a dictionary.
                _ => None,
            }
        } else {
            None
        };
        let dict_bytes = dictionary.as_ref().map(|d| d.dict_bytes.as_slice());

        // 3. Compress the blocks, sealing each frame when encrypting.
        let sealed_layr = self.session.is_some() && self.encryption.is_some();
        let mut block_region = Vec::new();
        for (index, (entry, plaintext)) in blocks.iter_mut().enumerate() {
            let frame = chunks::compress(plaintext, self.zstd_level, dict_bytes)?;
            let frame = if sealed_layr {
                crypto::seal(
                    self.cipher()?,
                    &self.session.expect("set with encryption"),
                    ChunkType::LAYR,
                    index as u32,
                    &frame,
                )?
            } else {
                frame
            };
            entry.frame_offset = block_region.len() as u64;
            entry.frame_size = frame.len() as u64;
            block_region.extend_from_slice(&frame);
        }
        let block_entries: Vec<BlockEntry> = blocks.iter().map(|(entry, _)| *entry).collect();
        let layr_header = Layr::header_to_bytes(&block_entries);
        let mut layr_stored = Vec::with_capacity(layr_header.len() + block_region.len());
        layr_stored.extend_from_slice(&layr_header);
        layr_stored.extend_from_slice(&block_region);

        // 4. LHAS, over the layer byte ranges as they sit in the blocks.
        let hashes = if self.layer_hashes {
            let mut leaves = Vec::with_capacity(masks.len());
            for (index, mask) in masks.iter().enumerate() {
                let (block, offset, size) = entries[index];
                let block = &blocks[block as usize].1;
                let start = offset as usize;
                let end = start + size as usize;
                debug_assert!(end <= block.len());
                debug_assert_eq!(&block[start..end], mask.as_slice());
                leaves.push(lhas::leaf_hash(&block[start..end]));
            }
            Some(LayerHashes {
                hash_algorithm: lhas::HASH_ALGORITHM_SHA256,
                hash_size: lhas::HASH_SIZE_SHA256,
                layer_count: leaves.len() as u32,
                merkle_root: lhas::merkle_root(&leaves),
                layer_hashes: leaves,
            })
        } else {
            None
        };

        // 5. The layer table.
        let table = LayerTable {
            table_version: 1,
            entry_size: crate::chunks::ltbl::LTBL_ENTRY_SIZE_V1,
            entries: entries
                .iter()
                .zip(self.layers.iter())
                .map(|((block_index, offset, size), layer)| LayerEntry {
                    data_offset: *offset,
                    block_index: *block_index,
                    data_size: *size,
                    sector_count: match layer {
                        LayerRecord::Empty => 0,
                        LayerRecord::Single(_) => 1,
                        LayerRecord::Sectors(list) => list.len() as u32,
                    },
                })
                .collect(),
        };

        // 6. Everything else, then the layout.
        let mut flags = 0u32;
        if multi_sector {
            flags |= FLAG_MULTI_SECTOR;
        }
        if self.encryption.is_some() {
            flags |= FLAG_ENCRYPTED;
        }

        let mut pending = Vec::new();
        pending.push(Pending::raw(ChunkType::HDR, self.hdr.to_bytes()));
        pending.push(self.seal_if_needed(
            ChunkType::META,
            json_chunks::meta_to_bytes(&self.meta)?,
            true,
        )?);
        if let Some(profile) = self.profile.as_ref() {
            pending.push(self.seal_if_needed(
                ChunkType::PROF,
                json_chunks::profile_to_bytes(profile)?,
                true,
            )?);
        }
        if let Some(auth) = self.build_auth()? {
            pending.push(Pending::raw(ChunkType::AUTH, crypto::encode_auth(&auth)));
        }
        for sect in &self.sectors {
            pending.push(self.seal_if_needed(
                ChunkType::SECT,
                json_chunks::sect_to_bytes(sect)?,
                true,
            )?);
        }
        if let Some(lrov) = self.lrov.as_ref() {
            pending.push(self.seal_if_needed(
                ChunkType::LROV,
                json_chunks::lrov_to_bytes(lrov)?,
                true,
            )?);
        }
        if let Some(dictionary) = dictionary.as_ref() {
            pending.push(self.seal_if_needed(ChunkType::ZDIC, dictionary.to_bytes(), false)?);
        }
        for (role, png) in &self.previews {
            pending.push(Pending::raw_with_flags(
                ChunkType::PREV,
                png.clone(),
                role.to_flags(),
            ));
        }
        if let Some(voxl) = self.voxl.as_ref() {
            pending.push(self.seal_if_needed(ChunkType::VOXL, voxl.clone(), true)?);
        }
        pending.push(Pending::raw(ChunkType::LTBL, table.to_bytes()));
        if let Some(hashes) = hashes.as_ref() {
            pending.push(Pending::raw(ChunkType::LHAS, hashes.to_bytes()));
        }
        pending.push(Pending {
            chunk_type: ChunkType::LAYR,
            stored: layr_stored.clone(),
            size_uncompressed: layr_stored.len() as u64,
            size_compressed: if sealed_layr {
                layr_stored.len() as u64
            } else {
                0
            },
            flags: if sealed_layr { CHUNK_FLAG_ENCRYPTED } else { 0 },
        });
        for extension in &self.extensions {
            pending.push(Pending::raw_with_flags(
                ChunkType::EXTD,
                extension.to_bytes(),
                extension.to_flags(),
            ));
        }

        // 7. Lay out: header, payloads at 8-byte alignment, directory, trailer.
        let mut out = Writer::with_capacity(
            pending.iter().map(|p| p.stored.len() + 8).sum::<usize>() + 64 + pending.len() * 32,
        );
        out.bytes(&[0u8; 32]);
        let mut directory = Directory::new();
        let mut total_uncompressed = 0u64;
        for chunk in &pending {
            out.pad_to(8);
            let offset = out.len() as u64;
            out.bytes(&chunk.stored);
            total_uncompressed += chunk.size_uncompressed;
            directory.push(ChunkDescriptor {
                chunk_type: chunk.chunk_type,
                offset,
                size_uncompressed: chunk.size_uncompressed,
                size_compressed: chunk.size_compressed,
                flags: chunk.flags,
            });
        }
        out.pad_to(8);
        let dir_offset = out.len() as u64;
        out.bytes(&directory.to_bytes());
        let header = FileHeader {
            version: 1,
            dir_offset,
            chunk_count: directory.descriptors.len() as u32,
            flags,
            total_uncompressed_size: total_uncompressed,
        };
        out.patch_bytes(0, &header.to_bytes());
        let crc = container::crc32c(out.as_slice());
        out.bytes(&container::TRAILER_MAGIC);
        out.u32(crc);
        Ok(out.into_vec())
    }

    fn cipher(&self) -> Result<Cipher> {
        Ok(self
            .encryption
            .as_ref()
            .expect("cipher asked for without encryption")
            .cipher)
    }

    /// Compress and seal a content chunk when the file is encrypted.
    fn seal_if_needed(
        &self,
        chunk_type: ChunkType,
        plaintext: Vec<u8>,
        compress: bool,
    ) -> Result<Pending> {
        let payload = if compress {
            chunks::compress(&plaintext, JSON_ZSTD_LEVEL, None)?
        } else {
            plaintext.clone()
        };
        let compressed_len = if compress { payload.len() as u64 } else { 0 };
        match self.session.as_ref() {
            None => Ok(Pending {
                chunk_type,
                stored: payload,
                size_uncompressed: plaintext.len() as u64,
                size_compressed: compressed_len,
                flags: 0,
            }),
            Some(key) => {
                let sealed = crypto::seal(self.cipher()?, key, chunk_type, 0, &payload)?;
                Ok(Pending {
                    chunk_type,
                    size_uncompressed: plaintext.len() as u64,
                    stored: sealed,
                    size_compressed: payload.len() as u64 + crypto::UNIT_OVERHEAD as u64,
                    flags: CHUNK_FLAG_ENCRYPTED,
                })
            }
        }
    }

    /// Build the `AUTH` chunk, when the file is encrypted.
    fn build_auth(&self) -> Result<Option<Auth>> {
        let Some(options) = self.encryption.as_ref() else {
            return Ok(None);
        };
        let session = self.session.as_ref().expect("set with encryption");
        let mut mode = 0u32;
        let mut password = None;
        let mut recipients: Vec<RecipientEntry> = Vec::new();
        if let Some(secret) = options.password.as_deref() {
            mode |= crypto::MODE_PASSWORD;
            let params = options.argon2;
            password = Some(crypto::wrap_password(
                session,
                secret,
                params.iterations,
                params.memory_kib,
                params.parallelism,
            )?);
        }
        for public in &options.recipients {
            mode |= crypto::MODE_MACHINE;
            recipients.push(crypto::wrap_machine(session, public)?);
        }
        if mode == 0 {
            return Err(Error::new(
                Check::CryptModeEmpty,
                "encryption was requested with neither a password nor a recipient",
            ));
        }
        Ok(Some(Auth {
            cipher: options.cipher,
            auth_version: 1,
            mode,
            password: password.map(Option::Some).unwrap_or(None),
            recipients,
        }))
    }
}

impl Pending {
    fn raw(chunk_type: ChunkType, payload: Vec<u8>) -> Pending {
        let len = payload.len() as u64;
        Pending {
            chunk_type,
            stored: payload,
            size_uncompressed: len,
            size_compressed: 0,
            flags: 0,
        }
    }

    fn raw_with_flags(chunk_type: ChunkType, payload: Vec<u8>, flags: u32) -> Pending {
        let mut pending = Pending::raw(chunk_type, payload);
        pending.flags = flags;
        pending
    }
}

/// Split a block's plaintext into per-layer samples for dictionary training.
///
/// The boundaries are not recoverable from the concatenation alone, so this
/// yields the whole block as one sample per fixed stride, which is what
/// `ZDICT_trainFromBuffer` wants: many samples of similar data. Layer data is
/// already highly redundant, so a sample per 1 KiB window trains well and costs
/// nothing to compute.
fn split_samples(plaintext: &[u8]) -> Vec<&[u8]> {
    const WINDOW: usize = 1024;
    if plaintext.is_empty() {
        return Vec::new();
    }
    plaintext.chunks(WINDOW).collect()
}
