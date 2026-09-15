//! Reading a file: [`LumenFile`], including random access to a single layer.
//!
//! Opening validates, then parses only what is needed: the fixed header, the
//! directory, and the chunks that describe the print. Layer masks are decoded on
//! demand, one block at a time, so reading layer 1 of a 2,000-layer print
//! decompresses one block rather than the whole file. For a firmware reader that
//! pulls layers through a fixed buffer, that is the whole point of the block
//! design ([`spec/09-compression.md`] section 6.2), and the cache here holds
//! exactly one decompressed block at a time - the layer's own block, or the one
//! last asked for.
//!
//! Opening validates and then parses, so a caller that also runs
//! [`crate::validate`] separately pays for the container walk twice. Callers
//! that want only a verdict should not open the file.

use crate::check::Check;
use crate::chunkio;
use crate::chunks::extd::Extension;
use crate::chunks::hdr::Hdr;
use crate::chunks::layr::Layr;
use crate::chunks::lhas::{self, LayerHashes};
use crate::chunks::ltbl::LayerTable;
use crate::chunks::preview::Preview;
use crate::chunks::zdic::ZstdDictionary;
use crate::chunks::{self, json_chunks};
use crate::container::{self, ChunkDescriptor, ChunkType, Directory, FileHeader};
use crate::crypto::{self, Auth, Cipher, SessionKey};
use crate::error::{Error, Result};
use crate::json::{Lrov, Meta, Profile, Sect};
use crate::ree::{self, DecodedLayer};
use crate::sectors;
use crate::timing::{self, Resolved};
use crate::validate::{Level, Validator};
use std::cell::RefCell;

/// One sector's decoded mask on one layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSector {
    /// The sector this mask belongs to.
    pub sector_id: u32,
    /// The decoded mask.
    pub layer: DecodedLayer,
}

/// An open LUMEN file.
#[derive(Debug)]
pub struct LumenFile<'a> {
    buf: &'a [u8],
    header: FileHeader,
    directory: Directory,
    hdr: Hdr,
    meta: Meta,
    profile: Option<Profile>,
    sectors: Vec<Sect>,
    lrov: Option<Lrov>,
    previews: Vec<Preview>,
    extensions: Vec<Extension>,
    dictionary: Option<ZstdDictionary>,
    layer_hashes: Option<LayerHashes>,
    layer_table: LayerTable,
    layr: Layr,
    layr_chunk: ChunkDescriptor,
    layr_bytes: &'a [u8],
    voxl: Option<Vec<u8>>,
    auth: Option<Auth>,
    cipher: Option<Cipher>,
    key: Option<SessionKey>,
    level: Level,
    cache: RefCell<Option<(u32, Vec<u8>)>>,
}

impl<'a> LumenFile<'a> {
    /// Open a plaintext file.
    pub fn open(buf: &'a [u8], level: Level) -> Result<LumenFile<'a>> {
        LumenFile::assemble(buf, level, None)
    }

    /// Open a file whose session key is already known.
    pub fn open_with_key(buf: &'a [u8], level: Level, key: SessionKey) -> Result<LumenFile<'a>> {
        LumenFile::assemble(buf, level, Some(key))
    }

    /// Open a password-protected file.
    pub fn open_with_password(
        buf: &'a [u8],
        level: Level,
        password: &str,
    ) -> Result<LumenFile<'a>> {
        let auth = auth_of(buf)?;
        let key = crypto::unwrap_password(&auth, password)?;
        LumenFile::assemble(buf, level, Some(key))
    }

    /// Open a machine-bound file with the recipient's X25519 private key.
    pub fn open_with_machine_key(
        buf: &'a [u8],
        level: Level,
        private_key: &[u8; 32],
    ) -> Result<LumenFile<'a>> {
        let auth = auth_of(buf)?;
        let key = crypto::unwrap_machine(&auth, private_key)?;
        LumenFile::assemble(buf, level, Some(key))
    }

    fn assemble(buf: &'a [u8], level: Level, key: Option<SessionKey>) -> Result<LumenFile<'a>> {
        let mut validator = Validator::new(level);
        if let Some(key) = key {
            validator = validator.with_key(key);
        }
        validator.validate(buf)?;

        let header = FileHeader::parse(buf)?;
        let directory = container::parse_directory(buf, &header)?;
        let auth = match directory.find(ChunkType::AUTH) {
            None => None,
            Some(d) => Some(crypto::parse_auth(chunkio::stored(buf, d)?)?),
        };
        let cipher = auth.as_ref().map(|a| a.cipher);
        let parts = Parts {
            buf,
            dir: &directory,
            cipher,
            key: key.as_ref(),
        };

        let hdr = Hdr::parse(&parts.required(ChunkType::HDR)?)?;
        let meta = json_chunks::parse_meta(&parts.required(ChunkType::META)?)?;
        let profile = match parts.optional_required(ChunkType::PROF)? {
            None => None,
            Some(bytes) => Some(json_chunks::parse_profile(&bytes)?),
        };
        let mut sectors = Vec::new();
        for d in directory.find_all(ChunkType::SECT).collect::<Vec<_>>() {
            let stored = chunkio::stored(buf, d)?;
            if let Some(bytes) = chunkio::payload(d, stored, cipher, key.as_ref())? {
                sectors.push(json_chunks::parse_sect(&bytes)?);
            }
        }
        let lrov = match parts.optional_required(ChunkType::LROV)? {
            None => None,
            Some(bytes) => Some(json_chunks::parse_lrov(&bytes)?),
        };
        let mut previews = Vec::new();
        for d in directory.find_all(ChunkType::PREV).collect::<Vec<_>>() {
            let stored = chunkio::stored(buf, d)?;
            let Some(bytes) = chunkio::payload(d, stored, cipher, key.as_ref())? else {
                continue;
            };
            previews.push(Preview {
                role: crate::chunks::preview::PreviewRole::from_flags(d.flags)?,
                png: bytes,
            });
        }
        let mut extensions = Vec::new();
        for d in directory.find_all(ChunkType::EXTD).collect::<Vec<_>>() {
            let stored = chunkio::stored(buf, d)?;
            let Some(frame) = chunkio::payload(d, stored, cipher, key.as_ref())? else {
                continue;
            };
            // Validation has already rejected a malformed frame on a payload it
            // could read, so a failure here means the descriptor did not say the
            // payload was a frame - an extension we do not implement, whose bytes
            // are opaque to us.
            if let Ok(ext) = Extension::parse(&frame, d.flags) {
                extensions.push(ext);
            }
        }
        let dictionary = match parts.optional_required(ChunkType::ZDIC)? {
            None => None,
            Some(bytes) => Some(ZstdDictionary::parse(&bytes)?),
        };
        let layer_hashes = match directory.find(ChunkType::LHAS) {
            None => None,
            Some(d) => Some(LayerHashes::parse(chunkio::stored(buf, d)?)?),
        };
        let layer_table = LayerTable::parse(&parts.required(ChunkType::LTBL)?)?;
        let layr_chunk = *directory
            .find(ChunkType::LAYR)
            .ok_or_else(|| Error::new(Check::PresenceLayr, "no LAYR chunk"))?;
        let layr_bytes = chunkio::stored(buf, &layr_chunk)?;
        let layr = Layr::parse(layr_bytes)?;
        let voxl = parts.optional_required(ChunkType::VOXL)?;

        Ok(LumenFile {
            buf,
            header,
            directory,
            hdr,
            meta,
            profile,
            sectors,
            lrov,
            previews,
            extensions,
            dictionary,
            layer_hashes,
            layer_table,
            layr,
            layr_chunk,
            layr_bytes,
            voxl,
            auth,
            cipher,
            key,
            level,
            cache: RefCell::new(None),
        })
    }

    /// Recover the session key from a password, without reopening.
    pub fn recover_password(&self, password: &str) -> Result<SessionKey> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| Error::new(Check::CryptNoKey, "the file has no AUTH chunk"))?;
        crypto::unwrap_password(auth, password)
    }

    /// Recover the session key from a recipient private key, without reopening.
    pub fn recover_machine_key(&self, private_key: &[u8; 32]) -> Result<SessionKey> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| Error::new(Check::CryptNoKey, "the file has no AUTH chunk"))?;
        crypto::unwrap_machine(auth, private_key)
    }

    /// The file's bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The fixed file header.
    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// The chunk directory.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// The `HDR` chunk.
    pub fn hdr(&self) -> &Hdr {
        &self.hdr
    }

    /// The `META` chunk.
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// The `PROF` chunk, if present. A file carries at most one.
    pub fn profile(&self) -> Option<&Profile> {
        self.profile.as_ref()
    }

    /// Every `SECT` chunk, in file order.
    pub fn sectors(&self) -> &[Sect] {
        &self.sectors
    }

    /// The `LROV` chunk, if present. A file carries at most one.
    pub fn lrov(&self) -> Option<&Lrov> {
        self.lrov.as_ref()
    }

    /// Every `PREV` chunk, in file order.
    pub fn previews(&self) -> &[Preview] {
        &self.previews
    }

    /// Every `EXTD` chunk whose frame could be read, in file order.
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// The `ZDIC` chunk, if present.
    pub fn dictionary(&self) -> Option<&ZstdDictionary> {
        self.dictionary.as_ref()
    }

    /// The `LHAS` chunk, if present.
    pub fn layer_hashes(&self) -> Option<&LayerHashes> {
        self.layer_hashes.as_ref()
    }

    /// The `LTBL` chunk.
    pub fn layer_table(&self) -> &LayerTable {
        &self.layer_table
    }

    /// The `LAYR` header and block table.
    pub fn layr(&self) -> &Layr {
        &self.layr
    }

    /// The `VOXL` payload, if present, verbatim.
    pub fn voxl(&self) -> Option<&[u8]> {
        self.voxl.as_deref()
    }

    /// The `AUTH` chunk, if present.
    pub fn auth(&self) -> Option<&Auth> {
        self.auth.as_ref()
    }

    /// The layer count.
    pub fn layer_count(&self) -> u32 {
        self.hdr.total_layers
    }

    /// Pixels in one layer mask.
    pub fn total_pixels(&self) -> u32 {
        self.hdr.total_pixels()
    }

    /// Whether the file uses sector-based layer encoding.
    pub fn multi_sector(&self) -> bool {
        self.header.multi_sector()
    }

    /// Whether the validation level this file was opened at is strict.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Whether the file has a session key available.
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// The decompressed, decrypted bytes of block `index`.
    pub fn block(&self, index: u32) -> Result<Vec<u8>> {
        self.with_block(index, |data| Ok(data.to_vec()))
    }

    /// Run `f` over the decompressed bytes of block `index`, decompressing it
    /// first if it is not the cached one.
    ///
    /// The cache holds one block, so fetching layers out of a single block is
    /// free after the first, and walking layers in order costs one decompression
    /// per block.
    fn with_block<T>(&self, index: u32, f: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        if self.cache.borrow().as_ref().map(|(k, _)| *k) != Some(index) {
            let data = self.decompress_block(index)?;
            *self.cache.borrow_mut() = Some((index, data));
        }
        let guard = self.cache.borrow();
        let (_, data) = guard.as_ref().expect("filled immediately above");
        f(data)
    }

    fn decompress_block(&self, index: u32) -> Result<Vec<u8>> {
        let block = self.layr.blocks.get(index as usize).ok_or_else(|| {
            Error::new(
                Check::LtblBlockIndexInRange,
                format!("block {index} does not exist"),
            )
        })?;
        let frame = chunkio::block_frame(
            &self.layr,
            self.layr_bytes,
            &self.layr_chunk,
            index as usize,
            self.cipher,
            self.key.as_ref(),
        )?
        .ok_or_else(|| {
            Error::new(
                Check::CryptNoKey,
                "the block is sealed and no session key is available",
            )
        })?;
        let dict = self.dictionary.as_ref().map(|d| d.dict_bytes.as_slice());
        chunks::decompress(&frame, block.uncompressed_size, dict)
    }

    /// The stored bytes of layer `index` within its block.
    fn layer_bytes(&self, index: u32) -> Result<Vec<u8>> {
        let entry = self
            .layer_table
            .entries
            .get(index as usize)
            .ok_or_else(|| {
                Error::new(
                    Check::LtblLayerIndexRange,
                    format!("layer {index} does not exist"),
                )
            })?;
        if entry.is_empty() {
            return Ok(Vec::new());
        }
        let start = entry.data_offset as usize;
        let len = entry.data_size as usize;
        self.with_block(entry.block_index, |block| {
            block
                .get(start..start + len)
                .map(|s| s.to_vec())
                .ok_or_else(|| {
                    Error::new(
                        Check::LtblOffsetsWithinBlock,
                        format!("layer {index} lies outside its block"),
                    )
                })
        })
    }

    /// The decoded mask of layer `index`.
    ///
    /// In a multi-sector file this is the union of every sector's mask, which is
    /// what a single-material reader prints; [`LumenFile::layer_sectors`] gives
    /// the sectors separately.
    pub fn layer(&self, index: u32) -> Result<DecodedLayer> {
        let total_pixels = self.total_pixels();
        if self.multi_sector() {
            let entry = self
                .layer_table
                .entries
                .get(index as usize)
                .ok_or_else(|| {
                    Error::new(
                        Check::LtblLayerIndexRange,
                        format!("layer {index} does not exist"),
                    )
                })?;
            if entry.is_empty() {
                return Ok(DecodedLayer::empty(total_pixels));
            }
            let mut pixels = vec![0u8; total_pixels as usize];
            let mut first_tag = None;
            for sector in self.layer_sectors(index)? {
                if first_tag.is_none() {
                    first_tag = sector.layer.tag;
                }
                for (out, pixel) in pixels.iter_mut().zip(sector.layer.pixels.iter()) {
                    if *pixel > *out {
                        *out = *pixel;
                    }
                }
            }
            // The union has no single stream of its own: `tag` reports the first
            // sector's, which is what a caller reading the layer sequentially
            // would see first, and `is_empty` is already answered above.
            return Ok(DecodedLayer {
                pixels,
                tag: first_tag.or(Some(ree::TAG_BINARY)),
            });
        }
        let data = self.layer_bytes(index)?;
        if data.is_empty() {
            return Ok(DecodedLayer::empty(total_pixels));
        }
        ree::decode(&data, total_pixels, self.level.is_strict())
    }

    /// Every sector's decoded mask on layer `index`, in the order stored.
    pub fn layer_sectors(&self, index: u32) -> Result<Vec<DecodedSector>> {
        let entry = self
            .layer_table
            .entries
            .get(index as usize)
            .ok_or_else(|| {
                Error::new(
                    Check::LtblLayerIndexRange,
                    format!("layer {index} does not exist"),
                )
            })?;
        if entry.is_empty() {
            return Ok(Vec::new());
        }
        let data = self.layer_bytes(index)?;
        let total_pixels = self.total_pixels();
        let mut out = Vec::new();
        for sector in sectors::decode(&data, entry.sector_count)? {
            let layer = ree::decode(&sector.mask, total_pixels, self.level.is_strict())?;
            out.push(DecodedSector {
                sector_id: sector.sector_id,
                layer,
            });
        }
        Ok(out)
    }

    /// Whether a single-material reader can print this file faithfully.
    ///
    /// False when any layer carries a non-empty sector other than 0, which a
    /// reader that decodes only sector 0 would silently drop (section 7.2).
    pub fn is_single_material_compatible(&self) -> Result<bool> {
        if !self.multi_sector() {
            return Ok(true);
        }
        for index in 0..self.layer_count() {
            for sector in self.layer_sectors(index)? {
                if sector.sector_id != 0 && sector.layer.pixels.iter().any(|p| *p != 0) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Resolve one layer's timing, optionally for one sector.
    ///
    /// The returned values already carry the sector definition, the bottom and
    /// transition blend, and every matching `LROV` entry. Overrides are not opt-in
    /// ([`spec/05-print-control.md`] section 4.6): a reader that does not apply them
    /// must refuse a file that carries an `LROV` chunk, because printing the layer
    /// at META's exposure instead of its override fails quietly. This method is
    /// therefore the only supported way to read a layer's timing.
    pub fn timing_for(&self, layer: u32, sector_id: u32) -> Result<Resolved> {
        let sector = self.sectors.iter().find(|s| s.sector_id == sector_id);
        timing::resolve(&self.meta, sector, self.lrov.as_ref(), layer, sector_id)
    }

    /// Verify layer `index` against the `LHAS` leaf table and Merkle path.
    pub fn verify_layer(&self, index: u32) -> Result<()> {
        let hashes = self
            .layer_hashes
            .as_ref()
            .ok_or_else(|| Error::new(Check::LhasFrame, "the file carries no LHAS chunk"))?;
        let stored_leaf = *hashes.layer_hashes.get(index as usize).ok_or_else(|| {
            Error::new(
                Check::LhasLayerCount,
                format!("layer {index} is outside the hash table"),
            )
        })?;
        let data = self.layer_bytes(index)?;
        let leaf = lhas::leaf_hash(&data);
        if leaf != stored_leaf {
            return Err(Error::new(
                Check::LhasLeafMatch,
                format!("layer {index} does not hash to its stored leaf"),
            ));
        }
        let path = lhas::merkle_path(&hashes.layer_hashes, index as usize);
        if !lhas::verify_leaf(&leaf, &path, index as usize, &hashes.merkle_root) {
            return Err(Error::new(
                Check::LhasRootRecompute,
                format!("layer {index}'s Merkle path does not reach the stored root"),
            ));
        }
        Ok(())
    }

    /// Verify every layer and the Merkle root.
    pub fn verify_all(&self) -> Result<()> {
        let hashes = self
            .layer_hashes
            .as_ref()
            .ok_or_else(|| Error::new(Check::LhasFrame, "the file carries no LHAS chunk"))?;
        for index in 0..self.layer_count() {
            let data = self.layer_bytes(index)?;
            let leaf = lhas::leaf_hash(&data);
            match hashes.layer_hashes.get(index as usize) {
                Some(stored) if *stored == leaf => {}
                Some(_) => {
                    return Err(Error::new(
                        Check::LhasLeafMatch,
                        format!("layer {index} does not hash to its stored leaf"),
                    ))
                }
                None => {
                    return Err(Error::new(
                        Check::LhasLayerCount,
                        format!("the hash table holds no layer {index}"),
                    ))
                }
            }
        }
        if lhas::merkle_root(&hashes.layer_hashes) != hashes.merkle_root {
            return Err(Error::new(
                Check::LhasRootRecompute,
                "the stored Merkle root is not the root of the stored leaf hashes",
            ));
        }
        Ok(())
    }
}

/// The chunk-payload reader for one container walk.
struct Parts<'a> {
    buf: &'a [u8],
    dir: &'a Directory,
    cipher: Option<Cipher>,
    key: Option<&'a SessionKey>,
}

impl Parts<'_> {
    /// A chunk's payload, or `None` when the chunk is absent or unreadable.
    fn payload(&self, chunk_type: ChunkType) -> Result<Option<Vec<u8>>> {
        let Some(d) = self.dir.find(chunk_type) else {
            return Ok(None);
        };
        let stored = chunkio::stored(self.buf, d)?;
        chunkio::payload(d, stored, self.cipher, self.key)
    }

    /// A required chunk's payload, distinguishing "missing" from "sealed".
    fn required(&self, chunk_type: ChunkType) -> Result<Vec<u8>> {
        let Some(bytes) = self.payload(chunk_type)? else {
            return Err(self.unreadable(chunk_type));
        };
        Ok(bytes)
    }

    /// An optional chunk's payload: `None` when absent, an error when the chunk
    /// is present but cannot be opened.
    fn optional_required(&self, chunk_type: ChunkType) -> Result<Option<Vec<u8>>> {
        if self.dir.find(chunk_type).is_none() {
            return Ok(None);
        }
        match self.payload(chunk_type)? {
            Some(bytes) => Ok(Some(bytes)),
            None => Err(self.unreadable(chunk_type)),
        }
    }

    /// The error for a chunk that is present but sealed with no key.
    fn unreadable(&self, chunk_type: ChunkType) -> Error {
        Error::new(
            Check::CryptNoKey,
            format!(
                "{chunk_type} is sealed and no session key is available; open the file with a password or a recipient key"
            ),
        )
    }
}

/// Parse the `AUTH` chunk without a key.
fn auth_of(buf: &[u8]) -> Result<Auth> {
    let header = FileHeader::parse(buf)?;
    let directory = container::parse_directory(buf, &header)?;
    let d = directory
        .find(ChunkType::AUTH)
        .ok_or_else(|| Error::new(Check::CryptNoKey, "the file carries no AUTH chunk"))?;
    crypto::parse_auth(chunkio::stored(buf, d)?)
}
