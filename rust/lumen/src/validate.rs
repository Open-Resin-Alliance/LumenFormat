//! The checks of [`spec/14-validation.md`] section 11.
//!
//! Validation returns the **first** failure, in the order the specification
//! presents the checks: file framing, then presence, then each chunk's semantic
//! rules, then layer data, then the integrity tree, then encryption.
//!
//! That ordering is load-bearing. The conformance corpus asserts that each
//! invalid vector fails its advertised check *first*, so a check that runs
//! earlier than the specification's order can mask the one a vector pins. Two
//! orderings are chosen against the tempting alternative:
//!
//! - `presence.auth` runs before `crypt.chunk_flags`. A file whose header sets
//!   `ENCRYPTED` with no `AUTH` chunk fails both, and the corpus pins the
//!   presence check for that vector.
//! - Every check over a chunk payload runs *after* `crypt.chunk_flags`. A
//!   descriptor that claims a payload is sealed while the file has no key would
//!   otherwise be read as plaintext and reported as a JSON error rather than a
//!   flag inconsistency.
//!
//! A sealed file validated without a key is checked as far as its plaintext
//! allows. The directory, `HDR`, `AUTH`, `LTBL`, the `LAYR` header and block
//! table, and `LHAS` are plaintext by construction (section 9.1), so those
//! checks all run; the ones that need decrypted content are skipped rather than
//! guessed at. Supply the key with [`Validator::with_key`] to run them.

use crate::check::Check;
use crate::chunkio;
use crate::chunks::extd::{Extension, CRITICAL_BIT, EXTD_RESERVED_MASK};
use crate::chunks::hdr::Hdr;
use crate::chunks::layr::Layr;
use crate::chunks::lhas::{self, LayerHashes};
use crate::chunks::ltbl::{LayerEntry, LayerTable};
use crate::chunks::preview::{self, PreviewRole};
use crate::chunks::voxl;
use crate::chunks::zdic::ZstdDictionary;
use crate::chunks::{self};
use crate::container::{
    self, ChunkDescriptor, ChunkType as Tag, Directory, FileHeader, CHUNK_FLAG_ENCRYPTED,
    FILE_HEADER_SIZE,
};
use crate::crypto::{self, Cipher, SessionKey};
use crate::error::{Error, Result};
use crate::json::{Material, Meta, Profile, Sect, Timing, REQUIRED_META_FIELDS};
use crate::{ree, sectors};
use serde_json::Value;

/// Header flag bits 0, 2 and 4: reserved, and required to be zero.
///
/// Bits 5-31 are reserved for future use and a reader must ignore them
/// (section 3.1), so they are outside this mask.
const HEADER_MUST_BE_ZERO: u32 = (1 << 0) | (1 << 2) | (1 << 4);

/// The chunk types that carry content and must therefore be sealed whenever the
/// file is (section 9.1).
const CONTENT_CHUNKS: &[Tag] = &[
    Tag::META,
    Tag::PROF,
    Tag::SECT,
    Tag::LROV,
    Tag::VOXL,
    Tag::ZDIC,
    Tag::LAYR,
];

/// The chunk types that must never be sealed, because a reader needs them
/// before it has a key.
const CLEARTEXT_CHUNKS: &[Tag] = &[Tag::HDR, Tag::AUTH, Tag::LTBL, Tag::LHAS];

/// How thoroughly to validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// Default for printing: accept structurally valid files, skip what is
    /// unknown, and do not enforce canonical encodings.
    #[default]
    Loose,
    /// For verification tools: enforce every rule, including the strict-mode
    /// ones marked in section 11.
    Strict,
}

impl Level {
    /// Whether this level enforces the strict-mode checks.
    pub fn is_strict(self) -> bool {
        matches!(self, Level::Strict)
    }
}

/// A configured validator.
#[derive(Debug, Clone, Default)]
pub struct Validator {
    level: Level,
    key: Option<SessionKey>,
}

impl Validator {
    /// A validator at `level`, with no key.
    pub fn new(level: Level) -> Validator {
        Validator { level, key: None }
    }

    /// A loose validator.
    pub fn loose() -> Validator {
        Validator::new(Level::Loose)
    }

    /// A strict validator.
    pub fn strict() -> Validator {
        Validator::new(Level::Strict)
    }

    /// Supply the session key, which enables the checks that need to open
    /// sealed units: `crypt.tag_verify`, and every check over decrypted content.
    pub fn with_key(mut self, key: SessionKey) -> Validator {
        self.key = Some(key);
        self
    }

    /// The configured level.
    pub fn level(&self) -> Level {
        self.level
    }

    /// The configured key, if any.
    pub fn key(&self) -> Option<&SessionKey> {
        self.key.as_ref()
    }

    /// Validate, returning the first failure.
    pub fn validate(&self, buf: &[u8]) -> Result<()> {
        let mut ctx = Ctx::new(buf, self.level, self.key)?;
        ctx.check_framing()?;
        ctx.check_chunk_flags()?;

        let hdr = ctx.read_hdr()?;
        check_hdr(&hdr)?;

        let auth = ctx.read_auth()?;
        ctx.cipher = auth.as_ref().map(|a| a.cipher);

        let meta = ctx.read_meta()?;
        if let Some(meta) = meta.as_ref() {
            check_meta(meta)?;
        }
        let profile = ctx.read_profile()?;
        if let Some(profile) = profile.as_ref() {
            check_profile(profile)?;
        }

        let sects = ctx.read_sects()?;
        check_sects(
            &sects,
            meta.as_ref().and_then(|m| m.materials.as_deref()),
            profile.as_ref().and_then(|p| p.materials.as_deref()),
        )?;

        if let Some(lrov) = ctx.read_lrov()? {
            check_lrov(&lrov, hdr.total_layers, &sects)?;
        }

        ctx.check_previews()?;
        ctx.check_extensions()?;
        ctx.check_voxl()?;

        let layr = ctx.read_layr()?;
        let ltbl = ctx.read_ltbl()?;
        let zdic = ctx.read_zdic()?;
        ctx.check_layer_data(&hdr, &layr, &ltbl, &zdic)?;
        let hashes = ctx.check_hashes(&hdr)?;
        if let Some(hashes) = hashes.as_ref() {
            ctx.check_leaves(&layr, &ltbl, &zdic, hashes)?;
        }

        if let (Some(key), Some(cipher)) = (ctx.key.as_ref(), ctx.cipher) {
            ctx.check_sealed_units(&layr, key, cipher)?;
        }
        Ok(())
    }
}

/// Validate `buf` at `level`, returning the first failure.
pub fn validate(buf: &[u8], level: Level) -> Result<()> {
    Validator::new(level).validate(buf)
}

/// Validate an encrypted file, opening sealed units with `key`.
pub fn validate_with_key(buf: &[u8], level: Level, key: SessionKey) -> Result<()> {
    Validator::new(level).with_key(key).validate(buf)
}

/// A validator's parse of the container, shared by every check.
struct Ctx<'a> {
    buf: &'a [u8],
    header: FileHeader,
    dir: Directory,
    level: Level,
    key: Option<SessionKey>,
    cipher: Option<Cipher>,
}

impl<'a> Ctx<'a> {
    fn new(buf: &'a [u8], level: Level, key: Option<SessionKey>) -> Result<Ctx<'a>> {
        container::verify_trailer_crc(buf)?;
        let header = FileHeader::parse(buf)?;
        let dir = container::parse_directory(buf, &header)?;
        Ok(Ctx {
            buf,
            header,
            dir,
            level,
            key,
            cipher: None,
        })
    }

    /// The stored bytes of a chunk, sealed or not.
    fn stored(&self, d: &ChunkDescriptor) -> Result<&'a [u8]> {
        chunkio::stored(self.buf, d)
    }

    /// The plaintext bytes of a chunk, or `None` when it is sealed and no key is
    /// available.
    fn plaintext(&self, d: &ChunkDescriptor) -> Result<Option<Vec<u8>>> {
        let stored = self.stored(d)?;
        chunkio::plaintext(d, stored, self.cipher, self.key.as_ref())
    }

    /// The decrypted, decompressed payload of a chunk, or `None` when it cannot
    /// be read.
    fn payload(&self, d: &ChunkDescriptor) -> Result<Option<Vec<u8>>> {
        let stored = self.stored(d)?;
        chunkio::payload(d, stored, self.cipher, self.key.as_ref())
    }

    // -- phase 1: framing ---------------------------------------------------

    fn check_framing(&mut self) -> Result<()> {
        if self.header.flags & HEADER_MUST_BE_ZERO != 0 {
            return Err(Error::new(
                Check::HeaderFlagsReserved,
                format!(
                    "header.flags {:#010x} sets a reserved bit",
                    self.header.flags
                ),
            ));
        }

        let dir_start = self.header.dir_offset;
        let mut ranges: Vec<(u64, u64, Tag)> = Vec::new();
        for d in self.dir.entries() {
            let (start, end) = d.extent();
            if start < FILE_HEADER_SIZE as u64 || end > dir_start {
                return Err(Error::new(
                    Check::DirChunkExtent,
                    format!(
                        "chunk {} occupies {start}..{end}, outside the {}..{dir_start} payload region",
                        d.chunk_type, FILE_HEADER_SIZE
                    ),
                ));
            }
            ranges.push((start, end, d.chunk_type));
        }
        ranges.sort_by_key(|r| r.0);
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(Error::new(
                    Check::DirOverlap,
                    format!(
                        "chunk {} at {}..{} overlaps chunk {} at {}..{}",
                        pair[0].2, pair[0].0, pair[0].1, pair[1].2, pair[1].0, pair[1].1
                    ),
                ));
            }
        }

        if self.header.total_uncompressed_size != 0 {
            let sum = self.dir.total_uncompressed_size();
            if sum != self.header.total_uncompressed_size {
                return Err(Error::new(
                    Check::HeaderTotalUncompressedSize,
                    format!(
                        "header declares {} uncompressed bytes, the directory sums to {sum}",
                        self.header.total_uncompressed_size
                    ),
                ));
            }
        }

        if self.dir.find(Tag::HDR).is_none() {
            return Err(Error::new(Check::PresenceHdr, "no HDR chunk"));
        }
        match self.dir.first_entry_index() {
            Some(i) if self.dir.descriptors[i].chunk_type == Tag::HDR => {}
            _ => return Err(Error::new(Check::DirHdrFirst, "the first chunk is not HDR")),
        }
        if self.dir.find(Tag::META).is_none() {
            return Err(Error::new(Check::PresenceMeta, "no META chunk"));
        }
        if self.dir.find(Tag::LTBL).is_none() {
            return Err(Error::new(Check::PresenceLtbl, "no LTBL chunk"));
        }
        if self.dir.find(Tag::LAYR).is_none() {
            return Err(Error::new(Check::PresenceLayr, "no LAYR chunk"));
        }
        if self.header.encrypted() && self.dir.find(Tag::AUTH).is_none() {
            return Err(Error::new(
                Check::PresenceAuth,
                "the header sets ENCRYPTED but the file carries no AUTH chunk",
            ));
        }
        if self.header.multi_sector() && !self.dir.contains(Tag::SECT) {
            return Err(Error::new(
                Check::PresenceSect,
                "MULTI_SECTOR is set but no SECT chunk defines a sector",
            ));
        }
        Ok(())
    }

    /// Section 11.4: the sealed bit on each descriptor agrees with the header.
    fn check_chunk_flags(&self) -> Result<()> {
        let encrypted_file = self.header.encrypted();
        for d in self.dir.entries() {
            let sealed = d.flags & CHUNK_FLAG_ENCRYPTED != 0;
            if !encrypted_file {
                if sealed {
                    return Err(Error::new(
                        Check::CryptChunkFlags,
                        format!(
                            "{} sets the sealed bit, but the file is not encrypted and no key could open it",
                            d.chunk_type
                        ),
                    ));
                }
                continue;
            }
            if CLEARTEXT_CHUNKS.contains(&d.chunk_type) {
                if sealed {
                    return Err(Error::new(
                        Check::CryptChunkFlags,
                        format!("{} must stay plaintext", d.chunk_type),
                    ));
                }
            } else if CONTENT_CHUNKS.contains(&d.chunk_type) && !sealed {
                return Err(Error::new(
                    Check::CryptChunkFlags,
                    format!(
                        "{} is content and must be sealed in an encrypted file",
                        d.chunk_type
                    ),
                ));
            }
        }
        Ok(())
    }

    // -- phase 2: the plaintext chunks -------------------------------------

    fn read_hdr(&self) -> Result<Hdr> {
        let d = self.dir.find(Tag::HDR).expect("presence checked");
        let payload = self
            .plaintext(d)?
            .expect("HDR is never sealed, so it is always readable");
        Hdr::parse(&payload)
    }

    fn read_auth(&self) -> Result<Option<crypto::Auth>> {
        let Some(d) = self.dir.find(Tag::AUTH) else {
            return Ok(None);
        };
        let payload = self
            .plaintext(d)?
            .expect("AUTH is never sealed, so it is always readable");
        let auth = crypto::parse_auth(&payload)?;
        if let Some(password) = auth.password.as_ref() {
            // The budget is checked here, before any caller can derive a key
            // from these parameters.
            crypto::check_argon2_budget(password)?;
        }
        Ok(Some(auth))
    }

    fn read_layr(&self) -> Result<Option<Layr>> {
        match self.dir.find(Tag::LAYR) {
            None => Ok(None),
            // Parsed straight from the file: the container is the largest chunk
            // in a print, and a copy of it to read a twelve-byte header would be
            // file-sized. Its header and block table are plaintext either way
            // (section 9.1), so nothing needs decrypting to read them.
            Some(d) => Ok(Some(Layr::parse(self.stored(d)?)?)),
        }
    }

    fn read_ltbl(&self) -> Result<Option<LayerTable>> {
        match self.dir.find(Tag::LTBL) {
            None => Ok(None),
            Some(d) => {
                let payload = self
                    .plaintext(d)?
                    .expect("LTBL is never sealed, so it is always readable");
                Ok(Some(LayerTable::parse(&payload)?))
            }
        }
    }

    fn read_zdic(&self) -> Result<Option<ZstdDictionary>> {
        let mut found = self.dir.find_all(Tag::ZDIC);
        let Some(d) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() {
            return Err(Error::new(
                Check::ZdicSingle,
                "more than one ZDIC chunk is present",
            ));
        }
        match self.plaintext(d)? {
            None => Ok(None),
            Some(raw) => Ok(Some(ZstdDictionary::parse(&raw)?)),
        }
    }

    // -- phase 3: the JSON chunks ------------------------------------------

    /// Parse a `META` payload while keeping its raw object, which is the only
    /// way to tell an absent required field from one that is `null`.
    fn read_meta(&self) -> Result<Option<Meta>> {
        let Some(d) = self.dir.find(Tag::META) else {
            return Ok(None);
        };
        let Some(bytes) = self.payload(d)? else {
            return Ok(None);
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(json_error)?;
        let object = value
            .as_object()
            .ok_or_else(|| Error::new(Check::MetaJson, "META is not a JSON object"))?;
        let missing = Timing::missing_from(object, &REQUIRED_META_FIELDS);
        if !missing.is_empty() {
            return Err(Error::new(
                Check::MetaRequiredFields,
                format!("META is missing {}", missing.join(", ")),
            ));
        }
        let meta: Meta = serde_json::from_value(value).map_err(json_error)?;
        Ok(Some(meta))
    }

    fn read_profile(&self) -> Result<Option<Profile>> {
        let Some(d) = self.dir.find(Tag::PROF) else {
            return Ok(None);
        };
        match self.payload(d)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(json_error)?)),
        }
    }

    fn read_sects(&self) -> Result<Vec<Sect>> {
        let mut out = Vec::new();
        for d in self.dir.find_all(Tag::SECT).collect::<Vec<_>>() {
            if let Some(bytes) = self.payload(d)? {
                out.push(serde_json::from_slice(&bytes).map_err(json_error)?);
            }
        }
        Ok(out)
    }

    fn read_lrov(&self) -> Result<Option<crate::json::Lrov>> {
        let Some(d) = self.dir.find(Tag::LROV) else {
            return Ok(None);
        };
        match self.payload(d)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(json_error)?)),
        }
    }

    fn check_previews(&self) -> Result<()> {
        for d in self.dir.find_all(Tag::PREV).collect::<Vec<_>>() {
            PreviewRole::from_flags(d.flags)?;
            if self.level.is_strict() {
                if let Some(bytes) = self.payload(d)? {
                    preview::check_png(&bytes)?;
                }
            }
        }
        Ok(())
    }

    /// `EXTD` frame checks.
    ///
    /// A sealed extension is checked only for its flag rules: the specification
    /// leaves its compression to the extension, and no extension is implemented,
    /// so its payload is opaque - which is how a reader treats any extension it
    /// does not implement. The `critical` rule binds either way.
    fn check_extensions(&self) -> Result<()> {
        for d in self.dir.find_all(Tag::EXTD).collect::<Vec<_>>() {
            if d.is_encrypted() {
                check_opaque_extension(d.flags)?;
                continue;
            }
            let Some(frame) = self.payload(d)? else {
                continue;
            };
            let ext = Extension::parse(&frame, d.flags)?;
            check_extension(&ext)?;
        }
        Ok(())
    }

    fn check_voxl(&self) -> Result<()> {
        if !self.level.is_strict() {
            return Ok(());
        }
        for d in self.dir.find_all(Tag::VOXL).collect::<Vec<_>>() {
            if let Some(bytes) = self.payload(d)? {
                voxl::require_voxl(&bytes)?;
            }
        }
        Ok(())
    }

    // -- phase 4: layer data -----------------------------------------------

    /// The `LAYR` block table, `LTBL`, and every layer's REE stream.
    ///
    /// Returns each layer's decompressed bytes so the `LHAS` checks that follow
    /// do not decompress a second time; `None` means the layer could not be read,
    /// which happens only when it is sealed and no key was supplied.
    fn check_layer_data(
        &self,
        hdr: &Hdr,
        layr: &Option<Layr>,
        ltbl: &Option<LayerTable>,
        zdic: &Option<ZstdDictionary>,
    ) -> Result<()> {
        let total_layers = hdr.total_layers;
        let (Some(layr), Some(ltbl)) = (layr.as_ref(), ltbl.as_ref()) else {
            return Ok(());
        };
        let desc = self.dir.find(Tag::LAYR).expect("presence checked");
        let stored = self.stored(desc)?;

        if layr.block_count() == 0 || layr.block_count() > total_layers {
            return Err(Error::new(
                Check::LayrBlockCount,
                format!(
                    "block_count {} is not within 1..={total_layers}",
                    layr.block_count()
                ),
            ));
        }

        // Contiguous, ordered block frames inside the payload.
        let mut expected = 0u64;
        for (k, block) in layr.blocks.iter().enumerate() {
            if block.frame_offset != expected {
                return Err(Error::new(
                    Check::LayrBlockTableContiguous,
                    format!(
                        "block {k} starts at {}, but block {} ended at {expected}",
                        block.frame_offset,
                        k.wrapping_sub(1)
                    ),
                ));
            }
            expected = block.frame_offset + block.frame_size;
            if (layr.block_region_offset as u64).saturating_add(expected) > stored.len() as u64 {
                return Err(Error::new(
                    Check::LayrBlockRegionBounds,
                    format!("block {k} reaches past the LAYR chunk payload"),
                ));
            }
        }

        // Section 11.4: a sealed block frame is at least one AEAD unit.
        if desc.flags & CHUNK_FLAG_ENCRYPTED != 0 {
            for (k, block) in layr.blocks.iter().enumerate() {
                if block.frame_size < crypto::UNIT_OVERHEAD as u64 {
                    return Err(Error::new(
                        Check::CryptChunkFlags,
                        format!(
                            "block {k} is {} bytes, smaller than one sealed unit",
                            block.frame_size
                        ),
                    ));
                }
            }
        }

        let mut referenced = vec![false; layr.blocks.len()];
        for entry in &ltbl.entries {
            if let Some(slot) = referenced.get_mut(entry.block_index as usize) {
                *slot = true;
            }
        }
        if let Some(missing) = referenced.iter().position(|r| !r) {
            return Err(Error::new(
                Check::LayrBlockReferenced,
                format!("block {missing} is referenced by no layer"),
            ));
        }

        // `LTBL` semantics. These use the block table's declared sizes, so they
        // hold whether or not the blocks can be decrypted.
        if ltbl.layer_count() != total_layers {
            return Err(Error::new(
                Check::LtblLayerCount,
                format!(
                    "LTBL describes {} layers, HDR says {total_layers}",
                    ltbl.layer_count()
                ),
            ));
        }
        let mut previous = 0u32;
        for (i, entry) in ltbl.entries.iter().enumerate() {
            if entry.block_index >= layr.block_count() {
                return Err(Error::new(
                    Check::LtblBlockIndexInRange,
                    format!(
                        "layer {i} names block {} of {}",
                        entry.block_index,
                        layr.block_count()
                    ),
                ));
            }
            if i > 0 && entry.block_index < previous {
                return Err(Error::new(
                    Check::LtblBlockIndexOrdered,
                    format!(
                        "layer {i} names block {} after block {previous}",
                        entry.block_index
                    ),
                ));
            }
            previous = entry.block_index;
            let block = &layr.blocks[entry.block_index as usize];
            if entry.data_offset.saturating_add(u64::from(entry.data_size))
                > block.uncompressed_size
            {
                return Err(Error::new(
                    Check::LtblOffsetsWithinBlock,
                    format!(
                        "layer {i} claims {} bytes at offset {}, past block {}'s {} bytes",
                        entry.data_size,
                        entry.data_offset,
                        entry.block_index,
                        block.uncompressed_size
                    ),
                ));
            }
            if entry.is_empty() && entry.data_size != 0 {
                return Err(Error::new(
                    Check::LtblEmptyLayerNoBytes,
                    format!("layer {i} is empty but carries {} bytes", entry.data_size),
                ));
            }
            if !entry.is_empty() && !self.header.multi_sector() && entry.sector_count != 1 {
                return Err(Error::new(
                    Check::SectorTags,
                    format!(
                        "layer {i} is non-empty but declares {} sectors in single-sector mode",
                        entry.sector_count
                    ),
                ));
            }
        }

        // Unsealed frames: the dictionary agreement rules need to see them.
        let mut dictionary_used = false;
        for (k, _) in layr.blocks.iter().enumerate() {
            let Some(frame) = self.block_frame(layr, stored, desc, k)? else {
                continue;
            };
            let id = chunks::frame_dict_id(&frame)?;
            match (id, zdic.as_ref()) {
                (0, None) => {}
                (0, Some(z)) => {
                    return Err(Error::new(
                        Check::LayrDictIdMatch,
                        format!(
                            "block {k} reports no dictionary, but ZDIC declares {}",
                            z.dict_id
                        ),
                    ))
                }
                (id, Some(z)) if id == z.dict_id => dictionary_used = true,
                (id, None) => {
                    return Err(Error::new(
                        Check::PresenceZdic,
                        format!("block {k} reports dictionary {id} but the file has no ZDIC"),
                    ))
                }
                (id, Some(z)) => {
                    return Err(Error::new(
                        Check::LayrDictIdMatch,
                        format!(
                            "block {k} reports dictionary {id}, ZDIC declares {}",
                            z.dict_id
                        ),
                    ))
                }
            }
        }
        let blocks_readable = !desc.is_encrypted() || self.key.is_some();
        if blocks_readable && zdic.is_some() && !dictionary_used {
            return Err(Error::new(
                Check::PresenceZdic,
                "ZDIC is present but no block frame uses a dictionary",
            ));
        }

        // Decompress and check one block at a time, releasing it before the
        // next: peak memory is one block plus the leaf table, never the whole
        // layer stream (section 4.11's design note for memory-constrained
        // readers). The sector-partition rule is the one check that needs a
        // per-pixel scratch buffer, so it uses a bitmap rather than a byte per
        // pixel and is reused across layers.
        let dict_bytes = zdic.as_ref().map(|z| z.dict_bytes.as_slice());
        let mut covered: Vec<u64> = Vec::new();
        for (k, block) in layr.blocks.iter().enumerate() {
            let layers_here = ltbl
                .entries
                .iter()
                .filter(|e| e.block_index as usize == k)
                .count()
                .max(1) as u64;
            let bound = chunks::allocation_bound(layers_here, hdr.total_pixels());
            if block.uncompressed_size > bound {
                return Err(Error::new(
                    Check::LayrAllocationBound,
                    format!(
                        "block {k} declares {} bytes; {layers_here} layers of {} pixels bound it at {bound}",
                        block.uncompressed_size,
                        hdr.total_pixels()
                    ),
                ));
            }
            let Some(frame) = self.block_frame(layr, stored, desc, k)? else {
                continue;
            };
            let plain = chunks::decompress(&frame, block.uncompressed_size, dict_bytes)?;
            for (i, entry) in ltbl.entries.iter().enumerate() {
                if entry.block_index as usize != k || entry.is_empty() {
                    continue;
                }
                let start = entry.data_offset as usize;
                let end = start.checked_add(entry.data_size as usize).ok_or_else(|| {
                    Error::new(Check::LtblOffsetsWithinBlock, "layer range overflows")
                })?;
                let data = &plain[start..end.min(plain.len())];
                if data.len() != entry.data_size as usize {
                    return Err(Error::new(
                        Check::LtblOffsetsWithinBlock,
                        format!("layer {i} runs past its block's decompressed output"),
                    ));
                }
                self.check_layer_stream(i, data, entry, hdr, &mut covered)?;
            }
        }
        Ok(())
    }

    /// The REE rules for one non-empty layer's stored bytes.
    fn check_layer_stream(
        &self,
        i: usize,
        data: &[u8],
        entry: &LayerEntry,
        hdr: &Hdr,
        covered: &mut Vec<u64>,
    ) -> Result<()> {
        let total_pixels = hdr.total_pixels();
        if self.header.multi_sector() {
            let decoded = sectors::decode(data, entry.sector_count)?;
            for sector in &decoded {
                // `ree` takes the tag and the stream together, and a
                // `SectorLayer.mask` is exactly that.
                let used =
                    ree::validate_stream(&sector.mask, total_pixels, self.level.is_strict())?;
                if used != sector.mask.len() {
                    return Err(Error::new(
                        Check::ReeNoTrailingBytes,
                        format!(
                            "layer {i}: sector {} stores {} bytes but its stream uses {used}",
                            sector.sector_id,
                            sector.mask.len()
                        ),
                    ));
                }
            }
            if self.level.is_strict() {
                // Section 7.3: the sector masks are pairwise non-overlapping.
                // The other half of that rule - that they cover every pixel - is
                // what "their union is exactly the layer's exposed image" means,
                // and the layer's exposed image need not be every pixel, so
                // coverage is not enforced here.
                covered.clear();
                covered.resize((total_pixels as usize).div_ceil(64), 0);
                for sector in &decoded {
                    let mask = ree::decode(&sector.mask, total_pixels, true)?;
                    for (index, pixel) in mask.pixels.iter().enumerate() {
                        if *pixel == 0 {
                            continue;
                        }
                        let (word, bit) = (index / 64, index % 64);
                        if covered[word] & (1 << bit) != 0 {
                            return Err(Error::new(
                                Check::SectorPartition,
                                format!(
                                    "layer {i}: sector {} exposes a pixel another sector already exposes",
                                    sector.sector_id
                                ),
                            ));
                        }
                        covered[word] |= 1 << bit;
                    }
                }
            }
        } else {
            let used = ree::validate_stream(data, total_pixels, self.level.is_strict())?;
            if used != data.len() {
                return Err(Error::new(
                    Check::ReeNoTrailingBytes,
                    format!(
                        "layer {i} stores {} bytes but its stream uses {used}",
                        data.len()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The unsealed bytes of block `k`, or `None` when it is sealed and no key is
    /// available.
    fn block_frame(
        &self,
        layr: &Layr,
        stored: &[u8],
        desc: &ChunkDescriptor,
        k: usize,
    ) -> Result<Option<Vec<u8>>> {
        chunkio::block_frame(layr, stored, desc, k, self.cipher, self.key.as_ref())
    }

    /// `LHAS`: the Merkle root always, and every leaf in strict mode.
    fn check_hashes(&self, hdr: &Hdr) -> Result<Option<LayerHashes>> {
        let Some(d) = self.dir.find(Tag::LHAS) else {
            return Ok(None);
        };
        let payload = self
            .plaintext(d)?
            .expect("LHAS is never sealed, so it is always readable");
        let hashes = LayerHashes::parse(&payload)?;
        if hashes.layer_count != hdr.total_layers {
            return Err(Error::new(
                Check::LhasLayerCount,
                format!(
                    "LHAS covers {} layers, HDR says {}",
                    hashes.layer_count, hdr.total_layers
                ),
            ));
        }
        let recomputed = lhas::merkle_root(&hashes.layer_hashes);
        if recomputed != hashes.merkle_root {
            return Err(Error::new(
                Check::LhasRootRecompute,
                "the stored Merkle root is not the root of the stored leaf hashes",
            ));
        }
        Ok(Some(hashes))
    }

    /// Section 11.3's strict rule that each layer hashes to its stored leaf.
    ///
    /// This is a second pass over the blocks, so that the REE checks keep their
    /// place in the check order while memory stays at one block: a layer's bytes
    /// are hashed as its block is decompressed and then released.
    fn check_leaves(
        &self,
        layr: &Option<Layr>,
        ltbl: &Option<LayerTable>,
        zdic: &Option<ZstdDictionary>,
        hashes: &LayerHashes,
    ) -> Result<()> {
        if !self.level.is_strict() {
            return Ok(());
        }
        let (Some(layr), Some(ltbl)) = (layr.as_ref(), ltbl.as_ref()) else {
            return Ok(());
        };
        let desc = self.dir.find(Tag::LAYR).expect("presence checked");
        let stored = self.stored(desc)?;
        let dict_bytes = zdic.as_ref().map(|z| z.dict_bytes.as_slice());

        for (k, block) in layr.blocks.iter().enumerate() {
            let Some(frame) = self.block_frame(layr, stored, desc, k)? else {
                continue;
            };
            let plain = chunks::decompress(&frame, block.uncompressed_size, dict_bytes)?;
            for (i, entry) in ltbl.entries.iter().enumerate() {
                if entry.block_index as usize != k {
                    continue;
                }
                let Some(stored_leaf) = hashes.layer_hashes.get(i) else {
                    continue;
                };
                // An empty layer stores no bytes, so it hashes the empty slice.
                // The range is already proven to lie inside the block by
                // `check_layer_data`; `get` keeps that an explicit dependency
                // rather than an unchecked slice.
                let data: &[u8] = if entry.is_empty() {
                    &[]
                } else {
                    let start = entry.data_offset as usize;
                    plain
                        .get(start..start + entry.data_size as usize)
                        .ok_or_else(|| {
                            Error::new(
                                Check::LtblOffsetsWithinBlock,
                                format!("layer {i} runs past its block's decompressed output"),
                            )
                        })?
                };
                if lhas::leaf_hash(data) != *stored_leaf {
                    return Err(Error::new(
                        Check::LhasLeafMatch,
                        format!("layer {i} does not hash to its stored leaf"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Section 11.4's final row: every sealed unit's tag must verify.
    fn check_sealed_units(
        &self,
        layr: &Option<Layr>,
        key: &SessionKey,
        cipher: Cipher,
    ) -> Result<()> {
        for d in self.dir.entries() {
            if d.chunk_type == Tag::LAYR || d.flags & CHUNK_FLAG_ENCRYPTED == 0 {
                continue;
            }
            crypto::open(cipher, key, d.chunk_type, 0, self.stored(d)?)?;
        }
        if let (Some(layr), Some(d)) = (layr.as_ref(), self.dir.find(Tag::LAYR)) {
            if d.flags & CHUNK_FLAG_ENCRYPTED != 0 {
                let stored = self.stored(d)?;
                for k in 0..layr.blocks.len() {
                    crypto::open(cipher, key, Tag::LAYR, k as u32, layr.frame(stored, k)?)?;
                }
            }
        }
        Ok(())
    }
}

fn json_error(err: serde_json::Error) -> Error {
    Error::new(Check::MetaJson, err.to_string())
}

/// `HDR` rules from sections 11.1 and 11.2.
fn check_hdr(hdr: &Hdr) -> Result<()> {
    if hdr.total_layers == 0 {
        return Err(Error::new(Check::HdrTotalLayers, "HDR declares no layers"));
    }
    if hdr.layer_height_um == 0 {
        return Err(Error::new(Check::HdrLayerHeight, "layer_height_um is zero"));
    }
    if hdr.build_width_um == 0 || hdr.build_depth_um == 0 || hdr.build_height_um == 0 {
        return Err(Error::new(Check::HdrBuildDims, "a build dimension is zero"));
    }
    if hdr.total_pixels() == 0 {
        return Err(Error::new(
            Check::HdrDisplayPixels,
            "the display has no pixels",
        ));
    }
    if hdr.display_width_px != 0 && hdr.physical_width_px % hdr.display_width_px != 0 {
        return Err(Error::new(
            Check::HdrPhysicalMultiple,
            "physical_width_px is not a multiple of display_width_px",
        ));
    }
    if hdr.display_height_px != 0 && hdr.physical_height_px % hdr.display_height_px != 0 {
        return Err(Error::new(
            Check::HdrPhysicalMultiple,
            "physical_height_px is not a multiple of display_height_px",
        ));
    }
    Ok(())
}

/// `META` rules from section 11.2.
fn check_meta(meta: &Meta) -> Result<()> {
    match meta.meta_version {
        Some(1) => {}
        Some(other) => {
            return Err(Error::new(
                Check::MetaVersion,
                format!("unsupported meta_version {other}"),
            ))
        }
        None => return Err(Error::new(Check::MetaVersion, "no meta_version")),
    }
    let timing = &meta.timing;
    if timing.normal_exposure_sec.unwrap_or(0.0) <= 0.0 {
        return Err(Error::new(
            Check::MetaExposure,
            "normal_exposure_sec is not positive",
        ));
    }
    if timing.bottom_exposure_sec.unwrap_or(0.0) <= 0.0 {
        return Err(Error::new(
            Check::MetaExposure,
            "bottom_exposure_sec is not positive",
        ));
    }
    if timing.layer_height_um.unwrap_or(0) == 0 {
        return Err(Error::new(
            Check::MetaLayerHeight,
            "layer_height_um is not positive",
        ));
    }
    if let Some(materials) = meta.materials.as_ref() {
        check_materials(materials, Check::MetaMaterialsShape)?;
    }
    if let Some(curve) = timing.cure_curve.as_ref() {
        check_cure_curve(curve, Check::MetaCureCurve)?;
    }
    for temperature in [timing.chamber_temperature_c, timing.vat_temperature_c]
        .into_iter()
        .flatten()
    {
        if !(0.0..=120.0).contains(&temperature) {
            return Err(Error::new(
                Check::MetaTemperatureRange,
                format!("temperature {temperature} is outside 0..=120 degrees Celsius"),
            ));
        }
    }
    Ok(())
}

/// `PROF` rules from section 11.2.
fn check_profile(profile: &Profile) -> Result<()> {
    match profile.profile_type.as_deref() {
        Some("material") | Some("printer") | Some("combined") => {}
        Some(other) => {
            return Err(Error::new(
                Check::ProfProfileType,
                format!("unknown profile_type {other:?}"),
            ))
        }
        None => return Err(Error::new(Check::ProfProfileType, "no profile_type")),
    }
    if profile.profile_name.is_empty() || profile.profile_version.is_empty() {
        return Err(Error::new(
            Check::ProfProfileIdentity,
            "profile_name and profile_version must be non-empty",
        ));
    }
    if profile.settings.normal_exposure_sec.unwrap_or(0.0) <= 0.0
        || profile.settings.bottom_exposure_sec.unwrap_or(0.0) <= 0.0
    {
        return Err(Error::new(
            Check::ProfSettingsExposure,
            "a profile exposure time is not positive",
        ));
    }
    if profile.settings.layer_height_um.unwrap_or(0) == 0 {
        return Err(Error::new(
            Check::ProfSettingsLayerHeight,
            "the profile's layer_height_um is not positive",
        ));
    }
    if let Some(curve) = profile.settings.cure_curve.as_ref() {
        check_cure_curve(curve, Check::ProfCureCurve)?;
    }
    if let Some(uuid) = profile.profile_uuid.as_deref() {
        if !is_uuid(uuid) {
            return Err(Error::new(
                Check::ProfProfileUuid,
                format!("{uuid:?} is not a UUID"),
            ));
        }
    }
    if let Some(materials) = profile.materials.as_ref() {
        check_materials(materials, Check::ProfMaterialsShape)?;
    }
    Ok(())
}

/// A materials array must be non-empty and every entry must be named.
fn check_materials(materials: &[Material], check: Check) -> Result<()> {
    if materials.is_empty() {
        return Err(Error::new(check, "the array is empty"));
    }
    if let Some(index) = materials.iter().position(|m| m.name.is_empty()) {
        return Err(Error::new(check, format!("material {index} has no name")));
    }
    Ok(())
}

/// A cure curve must be physically meaningful, and a NaN is not a number the
/// Beer-Lambert model can use, so each bound rejects it explicitly rather than
/// relying on how a negated comparison treats an incomparable value.
fn check_cure_curve(curve: &crate::json::CureCurve, check: Check) -> Result<()> {
    if curve.dp_um.is_nan() || curve.dp_um <= 0.0 {
        return Err(Error::new(check, "dp_um is not positive"));
    }
    if curve.ec_mj_cm2.is_nan() || curve.ec_mj_cm2 <= 0.0 {
        return Err(Error::new(check, "ec_mj_cm2 is not positive"));
    }
    if curve.e0_mj_cm2.is_nan() || curve.e0_mj_cm2 < 0.0 {
        return Err(Error::new(check, "e0_mj_cm2 is negative"));
    }
    Ok(())
}

fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let dashed = matches!(i, 8 | 13 | 18 | 23);
        if dashed {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// `SECT` rules from section 11.2.
fn check_sects(
    sects: &[Sect],
    meta_materials: Option<&[Material]>,
    profile_materials: Option<&[Material]>,
) -> Result<()> {
    for (i, sect) in sects.iter().enumerate() {
        if sect.sector_id == 0 {
            return Err(Error::new(
                Check::SectSectorIdReserved,
                "SECT uses sector_id 0, which is reserved for the implicit sector",
            ));
        }
        if sects[..i].iter().any(|s| s.sector_id == sect.sector_id) {
            return Err(Error::new(
                Check::SectSectorIdUnique,
                format!("sector_id {} appears twice", sect.sector_id),
            ));
        }
    }
    for sect in sects {
        if let Some(index) = sect.material_index {
            let known = [meta_materials, profile_materials]
                .into_iter()
                .flatten()
                .any(|library| index < library.len());
            if !known {
                return Err(Error::new(
                    Check::SectMaterialIndex,
                    format!(
                        "sector {} names material {index}, which no library contains",
                        sect.sector_id
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// `LROV` rules from section 11.2.
fn check_lrov(lrov: &crate::json::Lrov, total_layers: u32, sects: &[Sect]) -> Result<()> {
    for (i, entry) in lrov.overrides.iter().enumerate() {
        if entry.layer.is_some() == entry.layer_range.is_some() {
            return Err(Error::new(
                Check::LrovEntryForm,
                format!("override {i} must carry exactly one of layer or layer_range"),
            ));
        }
        if let Some(range) = entry.layer_range {
            if range[1] < range[0] {
                return Err(Error::new(
                    Check::LrovLayerRangeOrder,
                    format!("override {i} has layer_range [{}, {}]", range[0], range[1]),
                ));
            }
            if range[1] >= total_layers {
                return Err(Error::new(
                    Check::LrovLayerIndexRange,
                    format!("override {i} covers layer {} of {total_layers}", range[1]),
                ));
            }
        }
        if let Some(layer) = entry.layer {
            if layer >= total_layers {
                return Err(Error::new(
                    Check::LrovLayerIndexRange,
                    format!("override {i} names layer {layer} of {total_layers}"),
                ));
            }
        }
        if let Some(sector_id) = entry.sector_id {
            if sector_id != 0 && !sects.iter().any(|s| s.sector_id == sector_id) {
                return Err(Error::new(
                    Check::LrovSectorIdDefined,
                    format!("override {i} names undefined sector {sector_id}"),
                ));
            }
        }
    }
    Ok(())
}

/// `EXTD` rules from sections 11.2 and 4.13.
fn check_extension(ext: &Extension) -> Result<()> {
    if ext.critical && !ext.is_implemented() {
        return Err(Error::new(
            Check::ExtdCritical,
            format!(
                "extension {}{:?} is critical and unimplemented",
                ext.tag(),
                ext.vendor_id
            ),
        ));
    }
    Ok(())
}

/// The reserved-flag and critical rules, for an extension whose payload cannot
/// be read.
fn check_opaque_extension(flags: u32) -> Result<()> {
    if flags & EXTD_RESERVED_MASK != 0 {
        return Err(Error::new(
            Check::ExtdFlags,
            format!("EXTD flags {flags:#010x} set a reserved bit"),
        ));
    }
    if flags & CRITICAL_BIT != 0 {
        return Err(Error::new(
            Check::ExtdCritical,
            "a critical extension is unimplemented",
        ));
    }
    Ok(())
}
