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

/// The encoder name every HEAD payload carries.
const ENCODER_NAME: &str = "LumenFormat test vectors 1.0";

/// One span of a sector: start, end (exclusive) and the value its pixels carry.
pub type Span = ree::Span;

/// One layer: its sectors, each a list of spans. A sector's position is its id,
/// so sector 0 is primary and the rest are `sector_id >= 1`.
pub type Layer = Vec<Vec<Span>>;

/// `count` layers that all carry the same single sector.
pub fn repeated(count: usize, spans: &[Span]) -> Vec<Layer> {
    (0..count).map(|_| vec![spans.to_vec()]).collect()
}

/// One `(layer, sector)`'s encoded mask data.
pub struct Slice {
    pub sector_id: u32,
    pub bytes: Vec<u8>,
}

/// One `LAYR` chunk's frame: the sector it carries, the layers it covers, and the
/// frame itself (spec 4.9).
pub struct Frame {
    pub sector_id: u32,
    pub first_layer: u32,
    pub layer_count: u32,
    pub bytes: Vec<u8>,
    /// The frame's decompressed length, which its header declares.
    pub uncompressed_size: usize,
}

/// Everything one vector's layer data is made of, before it is stored.
pub struct Layers {
    pub multi_sector: bool,
    /// Per layer: its slices, ascending `sector_id`.
    pub slices: Vec<Vec<Slice>>,
    /// Per layer: its slices concatenated in ascending `sector_id`, the bytes the
    /// `LHAS` leaf covers.
    pub layer_bytes: Vec<Vec<u8>>,
    /// The sectors the file carries `LAYR` chunks for, ascending.
    pub sectors: Vec<u32>,
    /// The `LAYR` chunks' frames, in directory order: sector by sector, layer
    /// group by layer group.
    pub frames: Vec<Frame>,
    pub leaves: Vec<[u8; 32]>,
    pub use_dict: bool,
    pub dict_bytes: Vec<u8>,
    pub dict_id: u32,
}

/// The knobs [`encode_layers`] takes.
pub struct LayerOptions<'a> {
    pub layers_per_chunk: usize,
    pub use_dict: bool,
    pub dict_samples_bytes: usize,
    pub split_layers: &'a [usize],
    pub force_run_count_zero: &'a [usize],
    /// Layers stored under tag 0x02 whatever their mask holds, for the one stream
    /// shape the canonical tag choice cannot reach: an all-`0x00`/`0xFF` mask
    /// whose split overlay is empty (spec 5.5, 5.7).
    pub force_split: &'a [usize],
    /// Layers stored under tag 0x03 whatever their mask holds, the attached form
    /// the canonical tag choice never reaches (spec 5.6).
    pub force_attached: &'a [usize],
    /// Layers whose primary sector is stored under tag 0x03 with one deliberate
    /// defect, which is how a vector pins a rule the canonical encoder never
    /// breaks: the layer index, and the shape written in its place.
    pub attached_defects: &'a [(usize, ree::AttachedDefect)],
    /// Compress the frames without declaring their content size, which
    /// `layr.content_size_present` refuses (spec 4.9).
    pub omit_content_size: bool,
    /// Train and publish a dictionary but compress the frames without it, so the
    /// file carries a `ZDIC` chunk no frame uses (`presence.zdic`).
    pub unused_zdic: bool,
}

/// A compressor that turns one group's concatenated layer data into one `LAYR`
/// frame.
enum Compressor {
    /// The bulk compressor, which declares each frame's decompressed size in its
    /// header, as a writer MUST (spec 4.9).
    Declared(zstd::bulk::Compressor<'static>),
    /// A raw context with the content size flag cleared, for the one vector that
    /// pins what a reader does with a frame that declares nothing.
    Undeclared(zstd::zstd_safe::CCtx<'static>),
}

impl Compressor {
    fn new(level: i32, dict: &[u8], declared: bool) -> Self {
        if declared {
            return Compressor::Declared(
                zstd::bulk::Compressor::with_dictionary(level, dict).expect("zstd compressor"),
            );
        }
        let mut context = zstd::zstd_safe::CCtx::create();
        context
            .set_parameter(zstd::zstd_safe::CParameter::CompressionLevel(level))
            .expect("compression level");
        context
            .set_parameter(zstd::zstd_safe::CParameter::ContentSizeFlag(false))
            .expect("content size flag");
        context.load_dictionary(dict).expect("dictionary");
        Compressor::Undeclared(context)
    }

    fn frame(&mut self, payload: &[u8]) -> Vec<u8> {
        match self {
            Compressor::Declared(compressor) => compressor
                .compress(payload)
                .expect("layer frame compression"),
            Compressor::Undeclared(context) => {
                let mut out = Vec::with_capacity(zstd::zstd_safe::compress_bound(payload.len()));
                context
                    .compress2(&mut out, payload)
                    .expect("layer frame compression");
                out
            }
        }
    }
}

/// Everything about one vector's layer data, before it is stored.
///
/// Shared by the plaintext and encrypted builders: encryption changes how the
/// frames are stored, never what they decode to.
///
/// The layer data is grouped twice. A slice is one `(layer, sector)`'s bytes, and
/// the `LTBL` entry indexes it; a frame is one sector's data for one group of
/// layers, and the `LAYR` chunk carries it (spec 4.8, 4.9). Sector 0 is primary
/// and implicitly present on every layer with data, so a layer that carries
/// nothing anywhere still has one entry, for sector 0, with `data_size` 0.
pub fn encode_layers(display: (usize, usize), layers: &[Layer], options: &LayerOptions) -> Layers {
    let total = display.0 * display.1;

    let mut slices: Vec<Vec<Slice>> = Vec::with_capacity(layers.len());
    for (layer, sectors) in layers.iter().enumerate() {
        if options.force_run_count_zero.contains(&layer) {
            // Non-canonical all-black form: tag 0x00, first_value 0x00, run_count 0.
            let mut bytes = vec![ree::TAG_BINARY, 0x00];
            bytes.extend(ree::varint(0));
            slices.push(vec![Slice {
                sector_id: 0,
                bytes,
            }]);
            continue;
        }

        let prefer_split = options.split_layers.contains(&layer);
        let force_split = options.force_split.contains(&layer);
        // At most one defect per layer, and it lands on the layer's primary
        // sector: a second defect stream in one file would change which rule the
        // stream breaks first, and the vector names the rule it is for.
        let defect = options
            .attached_defects
            .iter()
            .find_map(|&(index, defect)| (index == layer).then_some(defect));
        let force_attached = defect.is_some() || options.force_attached.contains(&layer);
        let encoded: Vec<Slice> = sectors
            .iter()
            .enumerate()
            .filter_map(|(sector_id, spans)| {
                let runs = ree::runs_from_spans(total, spans);
                let bytes = match (sector_id, defect) {
                    (0, Some(defect)) => ree::encode_sector_attached_defect(&runs, defect),
                    _ if force_attached => ree::encode_sector_attached(&runs),
                    _ if force_split => ree::encode_sector_split(&runs),
                    _ => ree::encode_sector(&runs, prefer_split),
                }?;
                Some(Slice {
                    sector_id: sector_id as u32,
                    bytes,
                })
            })
            .collect();
        slices.push(encoded);
    }

    // At least one layer carries more than one sector, which is what the header's
    // MULTI_SECTOR flag says (spec 3.1, 7.1).
    let multi_sector = slices.iter().any(|layer| layer.len() > 1);

    let layer_bytes: Vec<Vec<u8>> = slices
        .iter()
        .map(|layer| {
            layer
                .iter()
                .flat_map(|slice| slice.bytes.iter().copied())
                .collect()
        })
        .collect();

    // Sector 0 even in a file no layer carries anything in, so that every entry
    // has a `LAYR` chunk to name.
    let mut sectors: Vec<u32> = Vec::new();
    for layer in &slices {
        for slice in layer {
            if !sectors.contains(&slice.sector_id) {
                sectors.push(slice.sector_id);
            }
        }
    }
    if sectors.is_empty() {
        sectors.push(0);
    }
    sectors.sort_unstable();

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

    // A vector may publish a dictionary the frames do not use, so that the file
    // carries a `ZDIC` chunk nothing refers to (`presence.zdic`).
    let frame_dict: &[u8] = if options.unused_zdic {
        &[]
    } else {
        &dict_bytes
    };
    let mut compressor = Compressor::new(ZSTD_LAYER_LEVEL, frame_dict, !options.omit_content_size);

    let mut frames = Vec::new();
    for sector_id in &sectors {
        for start in (0..slices.len()).step_by(options.layers_per_chunk) {
            let group = start..(start + options.layers_per_chunk).min(slices.len());
            let payload: Vec<u8> = group
                .clone()
                .flat_map(|layer| slice_bytes(&slices[layer], *sector_id))
                .copied()
                .collect();
            frames.push(Frame {
                sector_id: *sector_id,
                first_layer: start as u32,
                layer_count: (group.end - group.start) as u32,
                uncompressed_size: payload.len(),
                bytes: compressor.frame(&payload),
            });
        }
    }

    // A writer MUST NOT suppress the dictionary id (spec 4.8), so each frame's
    // header records what it was compressed with: check the vector's intent
    // against the frames rather than trusting the knobs.
    let wanted = if options.use_dict && !options.unused_zdic {
        dict_id
    } else {
        0
    };
    for frame in &frames {
        let declared =
            zstd::zstd_safe::get_dict_id_from_frame(&frame.bytes).map_or(0, |id| id.get());
        assert_eq!(
            declared, wanted,
            "a frame carries the dictionary id of the dictionary it was compressed with"
        );
    }

    let leaves = layer_bytes
        .iter()
        .map(|bytes| hash::leaf_hash(bytes))
        .collect();

    Layers {
        multi_sector,
        slices,
        layer_bytes,
        sectors,
        frames,
        leaves,
        use_dict: options.use_dict,
        dict_bytes,
        dict_id,
    }
}

/// The bytes `layer` carries for `sector`, empty when it carries none.
fn slice_bytes(layer: &[Slice], sector: u32) -> &[u8] {
    layer
        .iter()
        .find(|slice| slice.sector_id == sector)
        .map_or(&[], |slice| slice.bytes.as_slice())
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

/// One `LROV` chunk (spec 4.5): the timing deltas one `(layer, sector)` carries.
///
/// The deltas are META's names in META's units, and the point they apply to is
/// not in the payload at all - the entry that names the chunk places it, so a
/// range is written as one chunk per layer it covers.
pub struct Override<'a> {
    pub layer: u32,
    pub sector_id: u32,
    pub fields: Vec<(&'a str, Value)>,
}

impl Override<'_> {
    /// The JSON object the chunk carries.
    fn value(&self) -> Value {
        json::obj(self.fields.clone())
    }
}

/// Everything one vector needs, from its layers to the words the manifest uses.
pub struct VectorSpec<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub features: &'a [&'a str],
    pub display: (usize, usize),
    pub layer_height_um: u32,
    pub layers: Vec<Layer>,
    pub layers_per_chunk: usize,
    pub use_dict: bool,
    pub dict_samples_bytes: usize,
    pub split_layers: Vec<usize>,
    pub force_run_count_zero: Vec<usize>,
    /// Layers stored under tag 0x02 whatever their mask holds
    /// ([`LayerOptions::force_split`]).
    pub force_split: Vec<usize>,
    /// Layers stored under tag 0x03 whatever their mask holds
    /// ([`LayerOptions::force_attached`]).
    pub force_attached: Vec<usize>,
    /// Layers whose primary sector is stored under tag 0x03 with one deliberate
    /// defect ([`LayerOptions::attached_defects`]).
    pub attached_defects: Vec<(usize, ree::AttachedDefect)>,
    pub meta_extra: Vec<(&'a str, Value)>,
    /// Fields a vector adds to the corpus' support entry in `META.sectors`, on
    /// top of the exposure [`sectors_value`](VectorSpec::sectors_value) starts
    /// from. This is how a vector pins a sector that carries a layer count of its
    /// own: a sector's entry resolves the bottom and transition ranges for that
    /// sector, so a sector carrying `bottom_layer_count` is blended over a
    /// different range than META's (spec 4.2, 8).
    pub sector_extra: Vec<(&'a str, Value)>,
    /// The whole `META.sectors` array, for the vectors that pin what a malformed
    /// one does. `None` writes the corpus' support sector when the layer data is
    /// multi-sector, and nothing otherwise.
    pub sectors: Option<Value>,
    pub prof: Option<Vec<u8>>,
    pub overrides: Vec<Override<'a>>,
    /// Write the frames with a dictionary but without the `ZDIC` chunk that
    /// carries it, so a frame's dictionary id has nothing to agree with.
    pub omit_zdic: bool,
    /// Write the `ZDIC` chunk but compress the frames without it, so the file
    /// carries a dictionary no frame uses.
    pub unused_zdic: bool,
    /// Compress the frames without declaring their decompressed size.
    pub omit_content_size: bool,
    pub prevs: Vec<(Vec<u8>, u32, bool)>,
    pub voxl: Option<Vec<u8>>,
    /// A raw `LROV` payload, for the vector that pins a malformed one.
    pub lrov_raw: Option<Vec<u8>>,
    /// An extra `LROV` chunk, after the ones an entry names, that no entry
    /// references: a chunk whose overrides can never be attributed.
    pub orphan_lrov: Option<Vec<(&'a str, Value)>>,
    pub extds: Vec<(Vec<u8>, u32)>,
    /// Whether overrides whose deltas are equal share one `LROV` chunk, as the
    /// reference encoder writes them (`true`, the default). `false` writes one
    /// chunk per pair, which section 4.5 also permits - sharing is the encoder's
    /// choice - and is what `lrov-per-pair` pins.
    pub share_identical_overrides: bool,
    /// Zero bytes appended to the `HEAD` payload, so the chunk is longer than the
    /// fields this revision defines - the layout `HEAD` had while it still carried
    /// `physical_width_px` and `physical_height_px`. Section 11.2 makes the frame
    /// exact (`head.frame`), so the corpus needs a way to write one that is not.
    pub head_padding: usize,
    /// Write a second, identical `LTBL` chunk. Section 11.1 requires exactly one
    /// layer table, so this is the malformed shape that pins `presence.ltbl`.
    pub duplicate_ltbl: bool,
}

impl VectorSpec<'_> {
    /// The `META` payload's object (spec 4.2), which the manifest's timing
    /// resolves from the way the file's own reader would.
    ///
    /// The sectors a file defines live here, next to the material library they
    /// index, so a sector's identity and the timing it resolves with are never
    /// stored twice.
    pub fn meta_value(&self, multi_sector: bool) -> Value {
        let meta = payload::meta_value(&self.meta_extra);
        if let Some(sectors) = &self.sectors {
            return json::merge(meta, &[("sectors", sectors.clone())]);
        }
        if multi_sector {
            let support = json::merge(
                payload::sector_value(1, "Support", 3000),
                &self.sector_extra,
            );
            return json::merge(meta, &[("sectors", Value::Array(vec![support]))]);
        }
        meta
    }

    /// The overrides the file carries, ascending by `(layer, sector)`.
    pub fn overrides(&self) -> &[Override<'_>] {
        &self.overrides
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
            layers_per_chunk: 0,
            use_dict: false,
            dict_samples_bytes: 2048,
            split_layers: Vec::new(),
            force_run_count_zero: Vec::new(),
            force_split: Vec::new(),
            force_attached: Vec::new(),
            attached_defects: Vec::new(),
            meta_extra: Vec::new(),
            sector_extra: Vec::new(),
            sectors: None,
            prof: None,
            overrides: Vec::new(),
            omit_zdic: false,
            unused_zdic: false,
            omit_content_size: false,
            prevs: Vec::new(),
            voxl: None,
            lrov_raw: None,
            orphan_lrov: None,
            extds: Vec::new(),
            share_identical_overrides: true,
            head_padding: 0,
            duplicate_ltbl: false,
        }
    }
}

/// A file and the manifest entry that describes it.
pub struct Built {
    pub raw: Vec<u8>,
    pub meta: Value,
    pub layout: Layout,
}

/// One file's content chunks and the layer table that indexes them.
pub struct Content {
    pub chunks: Vec<Chunk>,
    pub entries: Vec<LayerEntry>,
}

/// The chunk list before any encryption, in the order section 3 recommends.
///
/// `auth` is the one chunk encryption adds; it is placed here, ahead of the
/// table, so that the directory indices the table and the sealed frames name are
/// the indices the chunk finally lands on.
pub fn content_chunks(spec: &VectorSpec, enc: &Layers, auth: Option<Chunk>) -> Content {
    let (w, h) = spec.display;
    let mut head = payload::head(&payload::Header {
        encoder_name: ENCODER_NAME,
        display_w: w as u32,
        display_h: h as u32,
        layer_height_um: spec.layer_height_um,
        total_layers: spec.layers.len() as u32,
        ..Default::default()
    });
    // See [`VectorSpec::head_padding`]: the one vector that writes a `HEAD` longer
    // than this revision's fields, which section 11.2 refuses.
    head.resize(head.len() + spec.head_padding, 0);
    let mut chunks = vec![
        Chunk::new(b"HEAD", head),
        Chunk::new(b"META", json::dumps(&spec.meta_value(enc.multi_sector))).compressed(),
    ];
    if let Some(prof) = &spec.prof {
        chunks.push(Chunk::new(b"PROF", prof.clone()).compressed());
    }
    // Section 3 lists PROF before AUTH, and AUTH before the rest.
    if let Some(auth) = auth {
        chunks.push(auth);
    }

    // One LROV chunk per distinct delta, ascending, so an entry can name its own
    // chunk by directory index (spec 4.5). Deltas that are equal share one chunk -
    // that is how a range, or any set of pairs, is written - unless the vector asks
    // for the one-chunk-per-pair form, which is equally conforming.
    let mut shared: std::collections::HashMap<Vec<u8>, u32> = std::collections::HashMap::new();
    let mut points: Vec<(u32, u32, u32)> = Vec::with_capacity(spec.overrides().len());
    for (index, over) in spec.overrides().iter().enumerate() {
        let point = (over.layer, over.sector_id);
        assert!(
            over.layer < spec.layers.len() as u32,
            "an override names a layer the file has"
        );
        assert!(
            points
                .last()
                .is_none_or(|(layer, sector, _)| (*layer, *sector) < point),
            "the overrides ascend by (layer, sector)"
        );
        // The first chunk's payload stands in for the malformed one.
        let bytes = match spec.lrov_raw.as_ref().filter(|_| index == 0) {
            Some(raw) => raw.clone(),
            None => payload::lrov(&over.fields),
        };
        let reused = spec
            .share_identical_overrides
            .then(|| shared.get(&bytes).copied())
            .flatten();
        let chunk_index = match reused {
            Some(chunk_index) => chunk_index,
            None => {
                let chunk_index = chunks.len() as u32;
                chunks.push(Chunk::new(b"LROV", bytes.clone()).compressed());
                shared.insert(bytes, chunk_index);
                chunk_index
            }
        };
        points.push((point.0, point.1, chunk_index));
    }
    if let Some(fields) = &spec.orphan_lrov {
        chunks.push(Chunk::new(b"LROV", payload::lrov(fields)).compressed());
    }

    if enc.use_dict && !spec.omit_zdic {
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

    // LTBL and LHAS, then the frames, so the table can name the LAYR chunks by
    // directory index. A duplicate table (the malformed vector) takes a slot of
    // its own, which the arithmetic here has to account for like any other chunk.
    let layr_start = chunks.len() + 2 + usize::from(spec.duplicate_ltbl);
    let entries = layer_entries(enc, layr_start, &points);
    chunks.push(Chunk::new(
        b"LTBL",
        payload::ltbl(&entries, spec.layers.len() as u32),
    ));
    if spec.duplicate_ltbl {
        // A second layer table, byte-identical to the first, so the file says
        // which chunk holds a layer's data twice over (section 11.1).
        chunks.push(Chunk::new(
            b"LTBL",
            payload::ltbl(&entries, spec.layers.len() as u32),
        ));
    }
    chunks.push(Chunk::new(b"LHAS", payload::lhas(&enc.leaves)));
    for frame in &enc.frames {
        chunks.push(Chunk::new(b"LAYR", payload::layr(&frame.bytes)));
    }
    Content { chunks, entries }
}

/// The layer table (spec 4.8): one 28-byte entry per `(layer, sector)`.
///
/// The entries of a layer are adjacent and ascending by `sector_id`, with the
/// layer's first entry naming sector 0, which every layer with data carries.
/// `points` maps a `(layer, sector)` to its `LROV` chunk's directory index.
fn layer_entries(enc: &Layers, layr_start: usize, points: &[(u32, u32, u32)]) -> Vec<LayerEntry> {
    let mut entries = Vec::with_capacity(enc.slices.len() + 2);
    for (layer, slices) in enc.slices.iter().enumerate() {
        let layer = layer as u32;
        let mut ids: Vec<u32> = Vec::with_capacity(slices.len() + 1);
        ids.push(0);
        ids.extend(
            slices
                .iter()
                .map(|slice| slice.sector_id)
                .filter(|sector_id| *sector_id != 0),
        );

        for (position, sector_id) in ids.iter().enumerate() {
            let bytes = slice_bytes(slices, *sector_id);
            let group = enc
                .frames
                .iter()
                .position(|frame| {
                    frame.sector_id == *sector_id
                        && frame.first_layer <= layer
                        && layer < frame.first_layer + frame.layer_count
                })
                .expect("every sector the layer carries has a LAYR chunk");
            let frame = &enc.frames[group];
            let offset: u64 = (frame.first_layer..layer)
                .map(|earlier| slice_bytes(&enc.slices[earlier as usize], *sector_id).len() as u64)
                .sum();
            entries.push(LayerEntry {
                layer,
                sector_id: *sector_id,
                data_size: bytes.len() as u32,
                first_lrov: points
                    .iter()
                    .find(|(point_layer, point_sector, _)| {
                        (*point_layer, *point_sector) == (layer, *sector_id)
                    })
                    .map_or(0, |(_, _, index)| *index),
                first_layr: (layr_start + group) as u32,
                additional_sector_count: if position == 0 {
                    (ids.len() - 1) as u32
                } else {
                    0
                },
                data_offset: offset,
            });
        }
    }
    entries
}

/// The manifest entry's golden data for one vector.
///
/// The entry pins the bytes, and `resolved_timing` additionally pins what a
/// conforming reader must resolve from the file's META and its `LROV` payloads
/// for a sample of `(layer, sector)` points ([`crate::timing`]), so a
/// third-party implementation has numbers to agree with and not only bytes to
/// re-derive. The sample is chosen to touch every branch of the pipeline rather
/// than every layer, and it is a sample of each sector's own pipeline: a sector
/// resolves `bottom_layer_count` and `transition_layer_count` per field for
/// itself, its `META.sectors` entry's counts replacing META's, so the layers one
/// sector branches at are not necessarily the layers another does. Each sector is
/// sampled at the two ends of its bottom range and its first transition step, the
/// first fully-normal layer and the last layer, each of them beside every layer
/// an `LROV` chunk that belongs to that sector overrides and that layer's
/// neighbours - which is what puts an override boundary and the layers on either
/// side of it in the same table - against sector 0, every sector the file carries
/// and every sector `META.sectors` defines. Pinning every layer would add no
/// branch the pipeline does not already show here: a reader that agrees at these
/// points and disagrees between them has a boundary error, not a sampling gap.
pub fn vector_meta(
    spec: &VectorSpec,
    enc: &Layers,
    content: &Content,
    raw: &[u8],
    layout: &Layout,
    crypto_value: Option<Value>,
    chunk_hashes: Option<Value>,
) -> Value {
    let entries = &content.entries;
    let chunks = &content.chunks;
    let (w, h) = spec.display;
    let layer_records: Vec<Value> = enc
        .slices
        .iter()
        .enumerate()
        .map(|(index, slices)| {
            let layer = entries
                .iter()
                .filter(|entry| entry.layer as usize == index)
                .collect::<Vec<_>>();
            let tags: Vec<Value> = layer
                .iter()
                .map(|entry| match slice_bytes(slices, entry.sector_id).first() {
                    Some(tag) => Value::from(*tag),
                    None => Value::Null,
                })
                .collect();
            obj![
                "index" => index,
                "empty" => layer.iter().all(|entry| entry.data_size == 0),
                "sector_count" => layer.len(),
                "tag" => tags.first().cloned().unwrap_or(Value::Null),
                "sector_tags" => Value::Array(tags),
                "decompressed_sha256" => hash::sha256_hex(&enc.layer_bytes[index]),
                "lhas_leaf" => hash::hex(&enc.leaves[index]),
            ]
        })
        .collect();

    let features: Vec<Value> = spec.features.iter().map(|f| Value::from(*f)).collect();
    // The timing pipeline reads the very payloads the chunks carry, not a second
    // copy of them: META as `content_chunks` wrote it, the sectors it defines,
    // and the `LROV` payloads it wrote, each against the entry that places it.
    let meta = spec.meta_value(enc.multi_sector);
    let overrides: Vec<timing::Override> = spec
        .overrides()
        .iter()
        .map(|over| timing::Override {
            layer: over.layer,
            sector: over.sector_id,
            fields: match over.value() {
                Value::Object(fields) => fields,
                _ => unreachable!("an override is an object"),
            },
        })
        .collect();
    let timing = timing::Pipeline::new(
        &meta,
        &enc.sectors,
        &overrides,
        enc.layer_bytes.len() as u32,
    );
    let mut records: Vec<(&str, Value)> = vec![
        ("name", Value::from(spec.name)),
        ("description", Value::from(spec.description)),
        ("features", Value::from(features)),
        ("display_width_px", Value::from(w)),
        ("display_height_px", Value::from(h)),
        ("total_layers", Value::from(enc.layer_bytes.len())),
        ("layer_height_um", Value::from(spec.layer_height_um)),
        ("layers_per_chunk", Value::from(spec.layers_per_chunk)),
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
            "ltbl",
            Value::Array(container::stored_layer_table(raw, layout)),
        ),
        ("layr_chunks", Value::Array(layr_chunks(enc, raw, layout))),
        (
            "merkle_root",
            Value::from(hash::hex(&hash::merkle_root(&enc.leaves))),
        ),
        ("layers", Value::Array(layer_records)),
        ("resolved_timing", timing.manifest()),
    ];
    if let Some(crypto_value) = crypto_value {
        records.push(("crypto", crypto_value));
    }
    // Python's `if chunk_hashes:` is a truthiness test, so a file with none of
    // those chunks carries no such key at all.
    if let Some(chunk_hashes) = chunk_hashes {
        if chunk_hashes.as_object().is_some_and(|map| !map.is_empty()) {
            records.push(("chunk_payload_sha256", chunk_hashes));
        }
    }
    json::obj(records)
}

/// The `LAYR` chunks exactly as stored (spec 4.9), in directory order.
///
/// The sizes come from the descriptor, so a sealed frame is described by the
/// bytes that are actually there; the frame's own decompressed size and
/// dictionary id come from the frame the vector built, which is the same frame a
/// reader recovers after decrypting.
fn layr_chunks(enc: &Layers, raw: &[u8], layout: &Layout) -> Vec<Value> {
    let stored: Vec<(usize, &container::Entry)> = layout
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.ctype == *b"LAYR")
        .collect();
    assert_eq!(stored.len(), enc.frames.len(), "one chunk per frame");
    stored
        .into_iter()
        .zip(&enc.frames)
        .map(|((index, entry), frame)| {
            let version = container::read_u32(raw, entry.offset);
            let sealed = entry.size_compressed != 0;
            let container_len = if sealed {
                entry.size_compressed
            } else {
                entry.size_uncompressed
            };
            assert_eq!(
                entry.size_uncompressed, container_len,
                "a sealed LAYR container's stored length is its uncompressed length"
            );
            let bytes = &raw[entry.offset + 4..entry.offset + container_len];
            if !sealed {
                // The writer's own check: what the file holds is the frame the
                // vector built, content size included.
                assert_eq!(bytes, frame.bytes.as_slice(), "the stored frame");
            }
            obj![
                "index" => index,
                "sector_id" => frame.sector_id,
                "first_layer" => frame.first_layer,
                "layer_count" => frame.layer_count,
                "version" => version,
                "dict_id" => zstd::zstd_safe::get_dict_id_from_frame(&frame.bytes)
                    .map_or(0, |id| id.get()),
                "content_size" => zstd::zstd_safe::get_frame_content_size(&frame.bytes)
                    .ok()
                    .flatten()
                    .map_or(Value::Null, Value::from),
                "frame_size" => container_len - 4,
                "stored_len" => container_len,
                "sealed" => sealed,
            ]
        })
        .collect()
}

/// One plaintext vector.
pub fn build_vector(spec: &VectorSpec) -> Built {
    let enc = encode_layers(
        spec.display,
        &spec.layers,
        &LayerOptions {
            layers_per_chunk: spec.layers_per_chunk,
            use_dict: spec.use_dict,
            dict_samples_bytes: spec.dict_samples_bytes,
            split_layers: &spec.split_layers,
            force_run_count_zero: &spec.force_run_count_zero,
            force_split: &spec.force_split,
            force_attached: &spec.force_attached,
            attached_defects: &spec.attached_defects,
            omit_content_size: spec.omit_content_size,
            unused_zdic: spec.unused_zdic,
        },
    );
    let content = content_chunks(spec, &enc, None);
    let header_flags = if enc.multi_sector {
        FLAG_MULTI_SECTOR
    } else {
        0
    };
    let (raw, layout) = container::build_file(&content.chunks, header_flags);
    let meta = vector_meta(
        spec,
        &enc,
        &content,
        &raw,
        &layout,
        None,
        Some(payload::payload_hashes(&content.chunks)),
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
    /// Seal every `LAYR` frame under unit index 0 instead of the directory index
    /// of the chunk that carries it (spec 9.3).
    pub bad_unit_index: bool,
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
            bad_unit_index: false,
        }
    }
}

/// An encrypted file: the same content chunks, sealed, plus an AUTH chunk.
///
/// Neither non-canonical form is forced here, because an encrypted vector has no
/// need of one - the Python producer passes the empty sets too.
pub fn build_encrypted_vector(spec: &VectorSpec, crypto_spec: &CryptoSpec) -> Built {
    let enc = encode_layers(
        spec.display,
        &spec.layers,
        &LayerOptions {
            layers_per_chunk: spec.layers_per_chunk,
            use_dict: spec.use_dict,
            dict_samples_bytes: spec.dict_samples_bytes,
            split_layers: &spec.split_layers,
            force_run_count_zero: &[],
            force_split: &[],
            force_attached: &[],
            attached_defects: &[],
            omit_content_size: spec.omit_content_size,
            unused_zdic: false,
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

    let auth = Chunk::new(
        b"AUTH",
        crypto::auth_payload(
            crypto_spec.cipher_id,
            crypto_spec.mode,
            &password_sec,
            &machine_sec,
        ),
    );
    let content = content_chunks(spec, &enc, Some(auth));

    // The chunks are sealed once the AUTH chunk is in place, because a sealed
    // LAYR frame's AAD is its chunk's directory index (spec 9.3).
    let ordered = crypto::seal_content_chunks(content.chunks.clone(), &session_key, crypto_spec);

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
        &content,
        &raw,
        &layout,
        Some(json::obj(crypto_entries)),
        Some(payload::payload_hashes(&content.chunks)),
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
