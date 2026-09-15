//! The named conformance checks.
//!
//! Every check carries the `<group>.<rule>` name the specification's conformance
//! corpus uses in `expected_failure` ([`test-vectors/README.md`]), so a failure
//! reported by this crate can be compared verbatim against the corpus. Names are
//! stable: see `spec/14-validation.md` section 11, which groups them.

/// A named conformance check, mirroring the corpus convention `<group>.<rule>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Check {
    // -- group: trailer (section 3.3) --------------------------------------
    /// `LEND` magic is absent from the last 8 bytes.
    TrailerMagic,
    /// Trailer CRC-32C does not match `bytes[0 .. file_len-8]`.
    TrailerCrc32c,

    // -- group: header (section 3.1) ---------------------------------------
    /// `LUMN` magic is absent at offset 0.
    HeaderMagic,
    /// `header.version` is not recognized.
    HeaderVersion,
    /// `header.dir_offset` is outside the file, or the directory does not fit.
    HeaderDirOffset,
    /// `header.chunk_count` does not match the directory.
    HeaderChunkCount,
    /// `header.flags` sets a reserved bit (0, 2 or 4).
    HeaderFlagsReserved,
    /// `header.total_uncompressed_size` is non-zero and wrong.
    HeaderTotalUncompressedSize,

    // -- group: dir (section 3.2) ------------------------------------------
    /// A chunk descriptor could not be read.
    DirDescriptor,
    /// Two chunks overlap.
    DirOverlap,
    /// A chunk's stored extent lies outside the file, or inside the directory.
    DirChunkExtent,
    /// The first chunk is not `HDR`.
    DirHdrFirst,

    // -- group: presence (section 3, section 4) ----------------------------
    /// A required chunk is missing.
    PresenceHdr,
    /// `META` is missing.
    PresenceMeta,
    /// `LTBL` is missing.
    PresenceLtbl,
    /// `LAYR` is missing.
    PresenceLayr,
    /// The `ENCRYPTED` flag is set but `AUTH` is absent, or vice versa.
    PresenceAuth,
    /// Exactly one `ZDIC` is required (or forbidden) by the block frames.
    PresenceZdic,
    /// `MULTI_SECTOR` is set but no `SECT` chunk is present.
    PresenceSect,

    // -- group: hdr (section 4.1) ------------------------------------------
    /// `hdr_version` is not recognized.
    HdrVersion,
    /// `encoder_name_len` exceeds 256, or the chunk is too short for its fields.
    HdrFrame,
    /// `total_layers == 0`, or disagrees with `LTBL.layer_count`.
    HdrTotalLayers,
    /// `layer_height_um == 0`.
    HdrLayerHeight,
    /// A build dimension is zero.
    HdrBuildDims,
    /// `display_width_px * display_height_px == 0`.
    HdrDisplayPixels,
    /// A physical dimension is not an integer multiple of the display dimension.
    HdrPhysicalMultiple,

    // -- group: auth (section 4.4) -----------------------------------------
    /// `auth_version` is not recognized.
    AuthVersion,
    /// `cipher_id` is not `A256` or `C20P`.
    AuthCipherKnown,
    /// The AUTH payload is too short for its declared sections.
    AuthFrame,

    // -- group: meta (section 4.2) -----------------------------------------
    /// The META payload is not a JSON object.
    MetaJson,
    /// `meta_version` is absent or unrecognized.
    MetaVersion,
    /// A required META field is absent.
    MetaRequiredFields,
    /// A META duration is not an integer number of milliseconds.
    MetaTimeInteger,
    /// An exposure time is not `> 0`.
    MetaExposure,
    /// `layer_height_um` is not `> 0`.
    MetaLayerHeight,
    /// `materials`, when present, is not a non-empty array of named entries.
    MetaMaterialsShape,
    /// A cure curve has a non-positive `dp_um`/`ec_mj_cm2` or a negative `e0_mj_cm2`.
    MetaCureCurve,
    /// A temperature is outside `[0.0, 120.0]`.
    MetaTemperatureRange,

    // -- group: sect (section 4.5) -----------------------------------------
    /// A SECT duration is not an integer number of milliseconds.
    SectTimeInteger,
    /// A SECT chunk uses `sector_id < 1`.
    SectSectorIdReserved,
    /// Two SECT chunks carry the same `sector_id`.
    SectSectorIdUnique,
    /// `material_index` does not address an existing, non-empty materials array.
    SectMaterialIndex,

    // -- group: prof (section 4.3) -----------------------------------------
    /// `profile_type` is not one of `material`, `printer`, `combined`.
    ProfProfileType,
    /// `profile_name` or `profile_version` is empty.
    ProfProfileIdentity,
    /// A profile duration is not an integer number of milliseconds.
    ProfSettingsTimeInteger,
    /// A profile exposure time is not `> 0`.
    ProfSettingsExposure,
    /// A profile `layer_height_um` is not `> 0`.
    ProfSettingsLayerHeight,
    /// A profile cure curve is out of range.
    ProfCureCurve,
    /// `profile_uuid` is not a well-formed UUID string.
    ProfProfileUuid,
    /// Profile materials are malformed.
    ProfMaterialsShape,

    // -- group: lrov (section 4.6) -----------------------------------------
    /// An entry's duration is not an integer number of milliseconds.
    LrovTimeInteger,
    /// An entry carries both `layer` and `layer_range`, or neither.
    LrovEntryForm,
    /// A layer index is outside `[0, total_layers)`.
    LrovLayerIndexRange,
    /// A `layer_range` ends before it begins.
    LrovLayerRangeOrder,
    /// `sector_id` is neither 0 nor a defined sector.
    LrovSectorIdDefined,

    // -- group: prev (section 4.7) -----------------------------------------
    /// A reserved flag bit is set, or the role is outside 0-3.
    PrevFlags,
    /// The payload does not begin with the PNG signature (strict mode).
    PrevPngSignature,

    // -- group: voxl (section 4.12) ----------------------------------------
    /// The payload is neither VOXL V2 nor a VOXL V1 document (strict mode).
    VoxlSignature,

    // -- group: extd (section 4.13) ----------------------------------------
    /// The payload is shorter than the 8-byte frame.
    ExtdFrame,
    /// `ext_type` is not four ASCII characters.
    ExtdExtType,
    /// A reserved flag bit is set.
    ExtdFlags,
    /// An unimplemented extension carries `critical = 1`.
    ExtdCritical,

    // -- group: ltbl (section 4.8) -----------------------------------------
    /// `table_version` is not recognized.
    LtblVersion,
    /// `layer_count` disagrees with `HDR.total_layers`.
    LtblLayerCount,
    /// `entry_size < 20`, or the entries do not fit the chunk.
    LtblEntrySize,
    /// `block_index >= LAYR.block_count` (or no LAYR was parsed).
    LtblBlockIndexInRange,
    /// A read or an override names a layer the table does not describe.
    LtblLayerIndexRange,
    /// `block_index` is not non-decreasing across layers.
    LtblBlockIndexOrdered,
    /// `data_offset + data_size` exceeds the block's decompressed size.
    LtblOffsetsWithinBlock,
    /// An empty layer carries a non-zero `data_size`.
    LtblEmptyLayerNoBytes,
    /// The in-band `sector_count` disagrees with the `LTBL` entry.
    LtblSectorCountMatch,

    // -- group: layr (section 4.10) ----------------------------------------
    /// `layr_version` is not recognized.
    LayrVersion,
    /// `block_count` is 0 or exceeds `HDR.total_layers`.
    LayrBlockCount,
    /// `block_table_entry_size < 24`, or the table does not fit.
    LayrBlockTableEntrySize,
    /// Block frames are not contiguous and ordered.
    LayrBlockTableContiguous,
    /// The last block frame reaches past the chunk payload.
    LayrBlockRegionBounds,
    /// A block index in `0..block_count` is referenced by no layer.
    LayrBlockReferenced,
    /// A block did not decompress to exactly its `uncompressed_size`.
    LayrBlockDecompressedSize,
    /// A block's `uncompressed_size` exceeds the bound derived from its layers.
    LayrAllocationBound,
    /// A block frame's dictionary ID disagrees with `ZDIC`.
    LayrDictIdMatch,

    // -- group: zdic (section 4.9) -----------------------------------------
    /// `zdic_version` is not recognized.
    ZdicVersion,
    /// `dict_size` exceeds `ZDIC_DICTSIZE_MAX`, or the bytes are missing.
    ZdicDictSize,
    /// `dict_id` disagrees with the block frames.
    ZdicDictIdMatch,
    /// More than one non-null `ZDIC` chunk is present.
    ZdicSingle,

    // -- group: lhas (section 4.11) ----------------------------------------
    /// The payload is too short for its header and hashes.
    LhasFrame,
    /// `hash_algorithm` is not `0x01` (SHA-256).
    LhasHashAlgorithm,
    /// `layer_count` disagrees with `HDR.total_layers`.
    LhasLayerCount,
    /// The recomputed Merkle root differs from the stored one.
    LhasRootRecompute,
    /// A layer's recomputed leaf hash differs from the stored one (strict mode).
    LhasLeafMatch,

    // -- group: ree (section 5) --------------------------------------------
    /// A layer carries an encoding tag other than `0x00`-`0x02`.
    ReeTag,
    /// A varint is overlong, truncated, or longer than 10 bytes.
    ReeVarint,
    /// A binary REE `first_value` is neither `0x00` nor `0xFF`.
    ReeFirstValue,
    /// The non-canonical `run_count == 0` form (strict mode).
    ReeNoRunCountZero,
    /// A stored run length is zero, or the lengths do not sum to `total_pixels` (strict).
    ReeRunLengths,
    /// Adjacent grayscale runs carry the same value, or a run is empty (strict).
    ReeGrayscaleRuns,
    /// An all-`0x00`/`0xFF` layer is stored as grayscale REE (strict).
    ReeGrayscaleAllBinary,
    /// The split binary component does not threshold at `v >= 128` (strict).
    ReeSplitThreshold,
    /// Split overlay positions are not strictly increasing, or out of range.
    ReeSplitPositions,
    /// The decoded stream does not end exactly at `total_pixels`.
    ReeEndPositions,
    /// Bytes follow the end of a layer's REE stream.
    ReeNoTrailingBytes,
    /// A layer's `data_size` does not match its decoded stream.
    ReeDataSize,

    // -- group: sector (section 7) -----------------------------------------
    /// The in-band sector framing disagrees with `LTBL.sector_count`.
    SectorCountMatch,
    /// A sector tag is malformed or a sector repeats.
    SectorTags,
    /// Sector masks overlap or do not sum to `total_pixels` (strict mode).
    SectorPartition,

    // -- group: crypt (section 9) ------------------------------------------
    /// `AUTH.mode` has no bit set.
    CryptModeEmpty,
    /// The password section is shorter than its fixed 65 bytes.
    CryptPasswordSectionLen,
    /// The machine section holds no complete recipient entry.
    CryptMachineSectionLen,
    /// Argon2id parameters exceed the reader's budget.
    CryptArgon2Budget,
    /// A chunk's encrypted flag disagrees with the file's `ENCRYPTED` flag.
    CryptChunkFlags,
    /// An AEAD tag did not verify.
    CryptTagVerify,
    /// A wrapped session key did not unwrap.
    CryptKeyUnwrap,
    /// A machine recipient entry is malformed.
    CryptRecipientEntry,
    /// An X25519 exchange produced the all-zero shared secret.
    CryptLowOrderPoint,
    /// No key could be recovered: wrong password, or no matching recipient.
    CryptNoKey,
}

impl Check {
    /// The `<group>.<rule>` name, verbatim as the conformance corpus spells it.
    pub fn name(self) -> &'static str {
        use Check::*;
        match self {
            TrailerMagic => "trailer.magic",
            TrailerCrc32c => "trailer.crc32c",
            HeaderMagic => "header.magic",
            HeaderVersion => "header.version",
            HeaderDirOffset => "header.dir_offset",
            HeaderChunkCount => "header.chunk_count",
            HeaderFlagsReserved => "header.flags_reserved",
            HeaderTotalUncompressedSize => "header.total_uncompressed_size",
            DirDescriptor => "dir.descriptor",
            DirOverlap => "dir.overlap",
            DirChunkExtent => "dir.chunk_extent",
            DirHdrFirst => "dir.hdr_first",
            PresenceHdr => "presence.hdr",
            PresenceMeta => "presence.meta",
            PresenceLtbl => "presence.ltbl",
            PresenceLayr => "presence.layr",
            PresenceAuth => "presence.auth",
            PresenceZdic => "presence.zdic",
            PresenceSect => "presence.sect",
            HdrVersion => "hdr.version",
            HdrFrame => "hdr.frame",
            HdrTotalLayers => "hdr.total_layers",
            HdrLayerHeight => "hdr.layer_height",
            HdrBuildDims => "hdr.build_dims",
            HdrDisplayPixels => "hdr.display_pixels",
            HdrPhysicalMultiple => "hdr.physical_multiple",
            AuthVersion => "auth.version",
            AuthCipherKnown => "auth.cipher_known",
            AuthFrame => "auth.frame",
            MetaJson => "meta.json",
            MetaVersion => "meta.version",
            MetaRequiredFields => "meta.required_fields",
            MetaTimeInteger => "meta.time_integer",
            MetaExposure => "meta.exposure",
            MetaLayerHeight => "meta.layer_height",
            MetaMaterialsShape => "meta.materials_shape",
            MetaCureCurve => "meta.cure_curve",
            MetaTemperatureRange => "meta.temperature_range",
            SectSectorIdReserved => "sect.sector_id_reserved",
            SectTimeInteger => "sect.time_integer",
            SectSectorIdUnique => "sect.sector_id_unique",
            SectMaterialIndex => "sect.material_index",
            ProfProfileType => "prof.profile_type",
            ProfProfileIdentity => "prof.profile_identity",
            ProfSettingsTimeInteger => "prof.settings_time_integer",
            ProfSettingsExposure => "prof.settings_exposure",
            ProfSettingsLayerHeight => "prof.settings_layer_height",
            ProfCureCurve => "prof.cure_curve",
            ProfProfileUuid => "prof.profile_uuid",
            ProfMaterialsShape => "prof.materials_shape",
            LrovEntryForm => "lrov.entry_form",
            LrovTimeInteger => "lrov.time_integer",
            LrovLayerIndexRange => "lrov.layer_index_range",
            LrovLayerRangeOrder => "lrov.layer_range_order",
            LrovSectorIdDefined => "lrov.sector_id_defined",
            PrevFlags => "prev.flags",
            PrevPngSignature => "prev.png_signature",
            VoxlSignature => "voxl.signature",
            ExtdFrame => "extd.frame",
            ExtdExtType => "extd.ext_type",
            ExtdFlags => "extd.flags",
            ExtdCritical => "extd.critical",
            LtblVersion => "ltbl.version",
            LtblLayerCount => "ltbl.layer_count",
            LtblEntrySize => "ltbl.entry_size",
            LtblBlockIndexInRange => "ltbl.block_index_in_range",
            LtblLayerIndexRange => "ltbl.layer_index_range",
            LtblBlockIndexOrdered => "ltbl.block_index_ordered",
            LtblOffsetsWithinBlock => "ltbl.offsets_within_block",
            LtblEmptyLayerNoBytes => "ltbl.empty_layer_no_bytes",
            LtblSectorCountMatch => "ltbl.sector_count_match",
            LayrVersion => "layr.version",
            LayrBlockCount => "layr.block_count",
            LayrBlockTableEntrySize => "layr.block_table_entry_size",
            LayrBlockTableContiguous => "layr.block_table_contiguous",
            LayrBlockRegionBounds => "layr.block_region_bounds",
            LayrBlockReferenced => "layr.block_referenced",
            LayrBlockDecompressedSize => "layr.block_decompressed_size",
            LayrAllocationBound => "layr.allocation_bound",
            LayrDictIdMatch => "layr.dict_id_match",
            ZdicVersion => "zdic.version",
            ZdicDictSize => "zdic.dict_size",
            ZdicDictIdMatch => "zdic.dict_id_match",
            ZdicSingle => "zdic.single",
            LhasFrame => "lhas.frame",
            LhasHashAlgorithm => "lhas.hash_algorithm",
            LhasLayerCount => "lhas.layer_count",
            LhasRootRecompute => "lhas.root_recompute",
            LhasLeafMatch => "lhas.leaf_match",
            ReeTag => "ree.tag",
            ReeVarint => "ree.varint",
            ReeFirstValue => "ree.first_value",
            ReeNoRunCountZero => "ree.no_run_count_zero",
            ReeRunLengths => "ree.run_lengths",
            ReeGrayscaleRuns => "ree.grayscale_runs",
            ReeGrayscaleAllBinary => "ree.grayscale_all_binary",
            ReeSplitThreshold => "ree.split_threshold",
            ReeSplitPositions => "ree.split_positions",
            ReeEndPositions => "ree.end_positions",
            ReeNoTrailingBytes => "ree.no_trailing_bytes",
            ReeDataSize => "ree.data_size",
            SectorCountMatch => "sector.count_match",
            SectorTags => "sector.tags",
            SectorPartition => "sector.partition",
            CryptModeEmpty => "crypt.mode_empty",
            CryptPasswordSectionLen => "crypt.password_section_len",
            CryptMachineSectionLen => "crypt.machine_section_len",
            CryptArgon2Budget => "crypt.argon2_budget",
            CryptChunkFlags => "crypt.chunk_flags",
            CryptTagVerify => "crypt.tag_verify",
            CryptKeyUnwrap => "crypt.key_unwrap",
            CryptRecipientEntry => "crypt.recipient_entry",
            CryptLowOrderPoint => "crypt.low_order_point",
            CryptNoKey => "crypt.no_key",
        }
    }

    /// Whether the specification marks this check strict-mode only ([section 11.5]).
    ///
    /// A loose-mode read must not fail these; a strict validator must.
    pub fn is_strict_only(self) -> bool {
        use Check::*;
        matches!(
            self,
            ReeNoRunCountZero
                | ReeRunLengths
                | ReeGrayscaleRuns
                | ReeGrayscaleAllBinary
                | ReeSplitThreshold
                | SectorPartition
                | LhasLeafMatch
                | PrevPngSignature
                | VoxlSignature
        )
    }
}

impl core::fmt::Display for Check {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}
