//! Writing a file: [`Encoder`], which assembles a conforming `.lumen` container.
//!
//! The encoder owns the choices the specification leaves to it (section 5.6): it
//! picks a tag per layer, picks how many layers a `LAYR` chunk spans, and decides
//! whether to train a dictionary. Layer masks are encoded as they are pushed, so
//! the encoder never holds the pixel data of the whole print - only its run-end
//! encoded form.
//!
//! The layer axis is cut into groups of [`DEFAULT_LAYERS_PER_CHUNK`] layers (or
//! whatever [`Encoder::set_layers_per_chunk`] asks for), and each (sector,
//! layer-group) becomes one `LAYR` chunk holding that sector's masks for the
//! group as a single zstd frame. `LTBL` then records, per (layer, sector), which
//! chunk holds the layer's run, where in that chunk's decompressed output the
//! run sits, and which `LROV` chunk carries the (layer, sector)'s overrides.
//!
//! `finish` produces the container in the order section 3 recommends: `HDR`,
//! `META`, the optional chunks, `LTBL`, `LAYR`, and the directory at the end.
//! Payloads are 8-byte aligned, as section 3.2 prefers, and the trailer's
//! CRC-32C covers every preceding byte.
//!
//! Encryption follows section 9.1 exactly: `HDR`, `AUTH`, `LTBL`, `LHAS` and the
//! `LAYR` version fields stay plaintext; `META`, `PROF`, `LROV`, `VOXL` and
//! `ZDIC` are sealed as single units; each `LAYR` frame is its own unit, bound by
//! its associated data to the chunk's directory index. `PREV` and `EXTD` are
//! written in the clear, which section 9.1 permits and which keeps a thumbnail
//! usable without a key.

use crate::check::Check;
use crate::chunks::extd::Extension;
use crate::chunks::hdr::Hdr;
use crate::chunks::lhas::{self, LayerHashes};
use crate::chunks::ltbl::{LayerEntry, LayerTable};
use crate::chunks::preview::PreviewRole;
use crate::chunks::zdic::ZstdDictionary;
use crate::chunks::{self, json_chunks, layr};
use crate::container::{
    self, ChunkDescriptor, ChunkType, Directory, FileHeader, CHUNK_FLAG_ENCRYPTED, FLAG_ENCRYPTED,
    FLAG_MULTI_SECTOR,
};
use crate::crypto::{self, Auth, Cipher, RecipientEntry, SessionKey};
use crate::error::{Error, Result};
use crate::io::Writer;
use crate::json::{Meta, Profile, Sector, Timing};
use crate::ree::{self, EncodeMode};
use std::collections::HashMap;

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

/// The layers one `LAYR` chunk spans, which a fresh encoder starts with
/// (section 4.10 recommends 32-64).
pub const DEFAULT_LAYERS_PER_CHUNK: u32 = 64;
/// The zstd level a fresh encoder starts with.
pub const DEFAULT_ZSTD_LEVEL: i32 = 6;
/// The zstd level for the small JSON chunks (section 6.3).
pub const JSON_ZSTD_LEVEL: i32 = 3;
/// How many chunks may be sampled for dictionary training (section 6.2).
pub const DICTIONARY_SAMPLE_LAYERS: usize = 256;

/// One `(layer, sector)`'s timing delta, written as its own `LROV` chunk.
///
/// A delta replaces only the fields it carries; every field it leaves out keeps
/// the value the pipeline resolved for that (layer, sector) from `META`, the
/// sector's `META.sectors` entry and the bottom/transition blend.
#[derive(Debug, Clone, PartialEq)]
pub struct Override {
    /// The layer the delta applies to.
    pub layer: u32,
    /// The sector it applies to. `0` is the primary sector.
    pub sector_id: u32,
    /// The fields the delta replaces, in META's names and units.
    pub timing: Timing,
}

/// One layer, already run-end encoded.
#[derive(Debug, Clone)]
enum LayerRecord {
    /// The empty layer: no sector carries bytes.
    Empty,
    /// `(sector_id, tag plus REE stream)`, ascending by `sector_id`, with the
    /// empty sectors omitted.
    Sectors(Vec<(u32, Vec<u8>)>),
}

impl LayerRecord {
    /// The pushed mask for one sector, when this layer has data for it.
    fn mask(&self, sector_id: u32) -> Option<&[u8]> {
        match self {
            LayerRecord::Empty => None,
            LayerRecord::Sectors(list) => list
                .iter()
                .find(|(id, _)| *id == sector_id)
                .map(|(_, mask)| mask.as_slice()),
        }
    }
}

/// A chunk ready to be laid out.
#[derive(Debug)]
struct Pending {
    chunk_type: ChunkType,
    /// The bytes as they will sit on disk.
    stored: Vec<u8>,
    /// What the descriptor's `size_uncompressed` field reports.
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
    overrides: Vec<Override>,
    previews: Vec<(PreviewRole, Vec<u8>)>,
    extensions: Vec<Extension>,
    voxl: Option<Vec<u8>>,
    layers_per_chunk: u32,
    zstd_level: i32,
    dictionary: bool,
    layer_hashes: bool,
    encryption: Option<EncryptOptions>,
    session: Option<SessionKey>,
    layers: Vec<LayerRecord>,
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
            overrides: Vec::new(),
            previews: Vec::new(),
            extensions: Vec::new(),
            voxl: None,
            layers_per_chunk: DEFAULT_LAYERS_PER_CHUNK,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            dictionary: true,
            layer_hashes: true,
            encryption: None,
            session: None,
            layers: Vec::new(),
        }
    }

    /// Attach a reusable print profile.
    pub fn set_profile(&mut self, profile: Profile) {
        self.profile = Some(profile);
    }

    /// Declare the non-zero sectors this print uses, as `META.sectors`.
    ///
    /// Sector 0 is implicit and must not appear; a sector carries no material
    /// until its entry names one.
    pub fn set_sectors(&mut self, sectors: Vec<Sector>) {
        self.meta.sectors = Some(sectors);
    }

    /// Attach the per-(layer, sector) timing deltas.
    ///
    /// Each becomes its own `LROV` chunk, and the matching `LTBL` entry points at
    /// it. A layer emitted here also gets a table entry for that sector even when
    /// the layer holds no data for it, which is how an override reaches a sector
    /// a layer does not print.
    pub fn set_overrides(&mut self, overrides: Vec<Override>) -> Result<()> {
        let mut overrides = overrides;
        overrides.sort_by_key(|over| (over.layer, over.sector_id));
        for pair in overrides.windows(2) {
            if pair[0].layer == pair[1].layer && pair[0].sector_id == pair[1].sector_id {
                return Err(Error::new(
                    Check::LrovOrphan,
                    format!(
                        "layer {} sector {} carries two override sets; a (layer, sector) has one \
                         or none",
                        pair[0].layer, pair[0].sector_id
                    ),
                ));
            }
        }
        self.overrides = overrides;
        Ok(())
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

    /// How many layers one `LAYR` chunk spans.
    pub fn set_layers_per_chunk(&mut self, layers: u32) {
        self.layers_per_chunk = layers.max(1);
    }

    /// zstd compression level for the layer chunks.
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
    ///
    /// The mask is sector 0's: it is what a single-material reader prints.
    pub fn push_layer(&mut self, pixels: &[u8]) -> Result<()> {
        self.push_layer_with_mode(pixels, EncodeMode::Auto)
    }

    /// Push one layer's mask with an explicit encoding.
    pub fn push_layer_with_mode(&mut self, pixels: &[u8], mode: EncodeMode) -> Result<()> {
        let total_pixels = self.total_pixels();
        check_mask(pixels, total_pixels, "the layer")?;
        let record = match ree::encode(pixels, total_pixels, mode)? {
            None => LayerRecord::Empty,
            // `ree::encode` returns the mask data with its tag already in front,
            // which is exactly what a layer stores; the tag is repeated here only
            // to be dropped.
            Some((_tag, mask)) => LayerRecord::Sectors(vec![(0, mask)]),
        };
        self.layers.push(record);
        Ok(())
    }

    /// Push one layer as a set of sectors, each with its own mask.
    ///
    /// Sector 0 is implicit, so a layer whose only content is sector 0 is pushed
    /// with [`Encoder::push_layer`] instead. A sector with no exposed pixel is
    /// omitted, and a layer whose every sector is empty is stored as the
    /// empty-layer form. The pairs are sorted by sector, which is the order the
    /// layer table requires.
    pub fn push_layer_sectors(&mut self, sectors: &[(u32, Vec<u8>)]) -> Result<()> {
        let total_pixels = self.total_pixels();
        let mut masks: Vec<(u32, Vec<u8>)> = Vec::new();
        for (sector_id, pixels) in sectors {
            check_mask(
                pixels,
                total_pixels,
                &format!("sector {sector_id} of the layer"),
            )?;
            if sectors.iter().filter(|(id, _)| id == sector_id).count() > 1 {
                return Err(Error::new(
                    Check::LtblSectorIdUnique,
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
            masks.sort_by_key(|(sector_id, _)| *sector_id);
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

        // 1. META's own shape rules, so the encoder cannot write a file its own
        //    validator would reject.
        if let Some(sectors) = self.meta.sectors.as_deref() {
            let mut seen: Vec<u32> = Vec::with_capacity(sectors.len());
            for (i, sector) in sectors.iter().enumerate() {
                if sector.sector_id == 0 {
                    return Err(Error::new(
                        Check::MetaSectorsShape,
                        format!(
                            "META.sectors[{i}] uses sector_id 0, which names the implicit primary \
                             sector"
                        ),
                    ));
                }
                if seen.contains(&sector.sector_id) {
                    return Err(Error::new(
                        Check::MetaSectorsShape,
                        format!("sector_id {} appears twice", sector.sector_id),
                    ));
                }
                seen.push(sector.sector_id);
            }
        }

        // 2. Which sectors each layer's table entry set covers: sector 0, every
        //    sector it holds data for, and every sector an override targets.
        let sector_sets = self.sector_sets()?;

        // 3. One LAYR chunk per (sector, layer-group): the group's masks for that
        //    sector, concatenated in ascending layer order. The placement of each
        //    layer's run inside its chunk is what LTBL records.
        let group_size = self.layers_per_chunk.max(1) as usize;
        let mut chunk_plaintexts: Vec<Vec<u8>> = Vec::new();
        let mut placement: HashMap<(u32, u32), (u32, u64, u32)> = HashMap::new();
        for group_start in (0..pushed as usize).step_by(group_size) {
            let group_end = (group_start + group_size).min(pushed as usize);
            let mut sectors: Vec<u32> = sector_sets[group_start..group_end]
                .iter()
                .flatten()
                .copied()
                .collect();
            sectors.sort_unstable();
            sectors.dedup();
            for sector in sectors {
                let mut plaintext = Vec::new();
                let mut placed: Vec<(u32, u64, u32)> = Vec::new();
                for (index, record) in self
                    .layers
                    .iter()
                    .enumerate()
                    .take(group_end)
                    .skip(group_start)
                {
                    if let Some(mask) = record.mask(sector) {
                        placed.push((index as u32, plaintext.len() as u64, mask.len() as u32));
                        plaintext.extend_from_slice(mask);
                    }
                }
                // A sector enters a layer's entries for other reasons too - an
                // override with no data behind it - so a group may name a sector
                // that holds nothing here. It gets no chunk.
                if plaintext.is_empty() {
                    continue;
                }
                let ordinal = chunk_plaintexts.len() as u32;
                for (layer, offset, size) in placed {
                    placement.insert((layer, sector), (ordinal, offset, size));
                }
                chunk_plaintexts.push(plaintext);
            }
        }
        // A file carries at least one LAYR chunk even when every layer is empty
        // (section 3's presence rule).
        if chunk_plaintexts.is_empty() {
            chunk_plaintexts.push(Vec::new());
        }

        // 4. The dictionary, trained on the first chunks (section 6.2).
        let dictionary = if self.dictionary {
            let samples: Vec<&[u8]> = chunk_plaintexts
                .iter()
                .flat_map(|plaintext| split_samples(plaintext))
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

        // 5. Compress each chunk's plaintext into its frame.
        let frames: Vec<Vec<u8>> = chunk_plaintexts
            .iter()
            .map(|plaintext| {
                let frame = chunks::compress(plaintext, self.zstd_level, dict_bytes)?;
                // A reader sizes the frame's output from the frame's own header,
                // so a writer must set its content size; refusing here keeps the
                // guarantee in the writer rather than in a comment.
                chunks::frame_content_size(&frame)?;
                Ok(frame)
            })
            .collect::<Result<_>>()?;

        // 6. LHAS, over each layer's slices concatenated in ascending sector_id -
        //    read back out of the chunk plaintexts, so the leaves are over the
        //    very bytes a reader will reconstruct.
        let hashes = if self.layer_hashes {
            let mut leaves = Vec::with_capacity(pushed as usize);
            for index in 0..pushed {
                let mut data = Vec::new();
                for sector in &sector_sets[index as usize] {
                    if let Some(&(ordinal, offset, size)) = placement.get(&(index, *sector)) {
                        let start = offset as usize;
                        data.extend_from_slice(
                            &chunk_plaintexts[ordinal as usize][start..start + size as usize],
                        );
                    }
                }
                leaves.push(lhas::leaf_hash(&data));
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

        // 7. Everything before LTBL, then LTBL, then everything after: the LAYR
        //    chunks need their directory indices, and LTBL needs them too, so the
        //    one slot LTBL occupies and the optional LHAS slot are what the LAYR
        //    indices are computed from.
        let mut flags = 0u32;
        if self
            .layers
            .iter()
            .any(|record| matches!(record, LayerRecord::Sectors(list) if list.len() > 1))
        {
            flags |= FLAG_MULTI_SECTOR;
        }
        let sealed = self.session.is_some() && self.encryption.is_some();
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
        // The overrides are already sorted by (layer, sector), so their chunks
        // are too, and each (layer, sector) remembers which index it landed at.
        let mut lrov_index: HashMap<(u32, u32), u32> = HashMap::new();
        for over in &self.overrides {
            lrov_index.insert((over.layer, over.sector_id), pending.len() as u32);
            pending.push(self.seal_if_needed(
                ChunkType::LROV,
                json_chunks::lrov_to_bytes(&over.timing)?,
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

        let layr_base = pending.len() as u32 + 1 + u32::from(hashes.is_some());
        let entries =
            self.table_entries(pushed, &sector_sets, &placement, layr_base, &lrov_index)?;
        let table = LayerTable::new(entries, pushed)?;
        pending.push(Pending::raw(ChunkType::LTBL, table.to_bytes()));
        if let Some(hashes) = hashes.as_ref() {
            pending.push(Pending::raw(ChunkType::LHAS, hashes.to_bytes()));
        }
        debug_assert_eq!(
            pending.len() as u32,
            layr_base,
            "the LAYR chunks start where their indices say they do"
        );

        for (ordinal, frame) in frames.iter().enumerate() {
            let directory_index = layr_base + ordinal as u32;
            let container = if sealed {
                let sealed_frame = crypto::seal(
                    self.cipher()?,
                    self.session.as_ref().expect("set with encryption"),
                    ChunkType::LAYR,
                    directory_index,
                    frame,
                )?;
                layr::to_bytes(&sealed_frame)
            } else {
                layr::to_bytes(frame)
            };
            pending.push(Pending {
                chunk_type: ChunkType::LAYR,
                stored: container,
                size_uncompressed: layr::container_len(frame.len()),
                size_compressed: if sealed {
                    // The container's stored length: the version field, the
                    // frame, and the one sealed unit's nonce and tag.
                    layr::container_len(frame.len()) + crypto::UNIT_OVERHEAD as u64
                } else {
                    0
                },
                flags: if sealed { CHUNK_FLAG_ENCRYPTED } else { 0 },
            });
        }
        for extension in &self.extensions {
            pending.push(Pending::raw_with_flags(
                ChunkType::EXTD,
                extension.to_bytes(),
                extension.to_flags(),
            ));
        }

        // 8. Lay out: header, payloads at 8-byte alignment, directory, trailer.
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

    /// The sectors each layer's entries cover, ascending, sector 0 first.
    fn sector_sets(&self) -> Result<Vec<Vec<u32>>> {
        let mut sets: Vec<Vec<u32>> = self
            .layers
            .iter()
            .map(|record| match record {
                LayerRecord::Empty => Vec::new(),
                LayerRecord::Sectors(list) => list.iter().map(|(id, _)| *id).collect(),
            })
            .collect();
        for over in &self.overrides {
            let index = over.layer as usize;
            let Some(ids) = sets.get_mut(index) else {
                return Err(Error::new(
                    Check::LtblLayerIndexRange,
                    format!(
                        "an override names layer {} of {}",
                        over.layer,
                        self.layers.len()
                    ),
                ));
            };
            if !ids.contains(&over.sector_id) {
                ids.push(over.sector_id);
            }
        }
        for ids in &mut sets {
            if !ids.contains(&0) {
                ids.push(0);
            }
            ids.sort_unstable();
            ids.dedup();
        }
        Ok(sets)
    }

    /// The layer table's entries, one per (layer, sector), in table order.
    fn table_entries(
        &self,
        pushed: u32,
        sector_sets: &[Vec<u32>],
        placement: &HashMap<(u32, u32), (u32, u64, u32)>,
        layr_base: u32,
        lrov_index: &HashMap<(u32, u32), u32>,
    ) -> Result<Vec<LayerEntry>> {
        let mut entries = Vec::new();
        for index in 0..pushed {
            let ids = &sector_sets[index as usize];
            let additional = (ids.len() - 1) as u32;
            // Every entry names a `LAYR` chunk, as section 4.10 requires, even
            // when the (layer, sector) holds no bytes: an entry with no run of
            // its own takes the chunk of the layer's first run, or the file's
            // first chunk when the layer has none at all.
            let home = ids
                .iter()
                .find_map(|sector| placement.get(&(index, *sector)))
                .map_or(layr_base, |(ordinal, _, _)| layr_base + *ordinal);
            for (position, sector) in ids.iter().enumerate() {
                let run = placement.get(&(index, *sector));
                entries.push(LayerEntry {
                    data_size: run.map_or(0, |(_, _, size)| *size),
                    first_lrov: lrov_index.get(&(index, *sector)).copied().unwrap_or(0),
                    first_layr: run.map_or(home, |(ordinal, _, _)| layr_base + *ordinal),
                    additional_sector_count: if position == 0 { additional } else { 0 },
                    data_offset: run.map_or(0, |(_, offset, _)| *offset),
                    sector_id: *sector,
                });
            }
        }
        Ok(entries)
    }

    fn cipher(&self) -> Result<Cipher> {
        Ok(self
            .encryption
            .as_ref()
            .expect("cipher asked for without encryption")
            .cipher)
    }

    /// Compress and seal a content chunk when the file is encrypted.
    ///
    /// These are one-unit chunks, so their associated data names slot zero; a
    /// `LAYR` frame is sealed by the layout step instead, bound to the chunk's
    /// directory index.
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

/// Reject a mask whose pixel count disagrees with the display.
fn check_mask(pixels: &[u8], total_pixels: u32, what: &str) -> Result<()> {
    if pixels.len() != total_pixels as usize {
        return Err(Error::new(
            Check::ReeDataSize,
            format!(
                "{what} has {} pixels but the display holds {total_pixels}",
                pixels.len()
            ),
        ));
    }
    Ok(())
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

/// Split a chunk's plaintext into samples for dictionary training.
///
/// The boundaries between layers are not recoverable from the concatenation
/// alone, so this yields the whole chunk as one sample per fixed stride, which is
/// what `ZDICT_trainFromBuffer` wants: many samples of similar data. Layer data is
/// already highly redundant, so a sample per 1 KiB window trains well and costs
/// nothing to compute.
fn split_samples(plaintext: &[u8]) -> Vec<&[u8]> {
    const WINDOW: usize = 1024;
    if plaintext.is_empty() {
        return Vec::new();
    }
    plaintext.chunks(WINDOW).collect()
}
