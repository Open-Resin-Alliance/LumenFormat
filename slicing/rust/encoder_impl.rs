//! DragonFruit's `.lumen` encoder: the LUMEN print format.
//!
//! LUMEN is run-end encoded (section 5) and compressed in blocks, so a layer's cost
//! is set by its run count, not by the plate's pixel count. This encoder therefore
//! takes the engine's RLE streaming path (`requires_png_layers() == false` plus a
//! `RleStreamEncoder`): the rasterizer hands over `RleRun`s and nothing ever
//! materializes a full 94 M-pixel 16K frame, which is the difference between tens of
//! microseconds and a tenth of a second per layer.
//!
//! The container itself - HEAD, META, LTBL, LAYR, ZDIC, LHAS, the chunk directory,
//! the CRC-32C trailer - is written by the `lumen` reference crate rather than
//! reimplemented here, so a file this plugin produces is a file the reference
//! encoder would have produced. That is why this plugin has no `lumen_layout.rs` and no
//! `lumen_crypto.rs`: those modules would be a second implementation of sections 3 to 9,
//! and the whole point of a reference encoder is that there is one (Appendix B).
//!
//! Registration is by folder convention: this repository is imported into DragonFruit
//! as the submodule at `plugins/lumen`, where `scripts/generate-plugin-registry.mjs`
//! finds `pluginDefinition.ts`, `#[path]`-includes this file into the engine crate,
//! and merges the crate this module needs - declared beside this file in
//! `slicing/rust/requiredCrates.toml` as a path into the same checkout - into the
//! engine's manifest, the same route every other plugin's crates take.

mod lumen_metadata;
mod lumen_preview;
mod lumen_types;

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use lumen::chunks::preview::PreviewRole;
use lumen::reader::LumenFile;
use lumen::ree::{encode_runs, EncodeMode, Run};
use lumen::writer::{EncodedLayer, Encoder};

use crate::encoders::FormatEncoder;
use crate::encoders::RleStreamEncoder;
use crate::engine::SlicerV3Error;
use crate::rle::RleRun;
use crate::types::{LayerAreaStatsV3, RenderedLayersV3, SliceJobV3};

use self::lumen_metadata::LumenMetadata;

/// One layer's place in the print, as the streaming sink accumulates it.
enum LayerSlot {
    /// Not delivered yet.
    Missing,
    /// Delivered and empty: LUMEN's empty-layer form, which stores no stream at all.
    Empty,
    /// A REE stream, tag byte first.
    Stream(Vec<u8>),
}

/// The engine's RLE sink for one print.
struct LumenRleStreamEncoder {
    metadata: LumenMetadata,
    /// `HEAD.display_width_px * HEAD.display_height_px`: the frame every layer's runs
    /// cover, and the value LUMEN's run ends are relative to.
    total_pixels: u32,
    /// The export capture, already fitted into the large preview role, or `None`
    /// when the job had none to offer.
    preview_png: Option<Vec<u8>>,
    layers: Vec<LayerSlot>,
}

impl LumenRleStreamEncoder {
    fn new(metadata: LumenMetadata, total_pixels: u32, preview_png: Option<Vec<u8>>) -> Self {
        Self {
            metadata,
            total_pixels,
            preview_png,
            layers: Vec::new(),
        }
    }

    /// Record one layer's encoded form at its index.
    ///
    /// Layers may arrive out of order on the parallel path, so this grows the list to
    /// the index and leaves the gaps marked missing: a gap at finalize time means the
    /// rasterizer never delivered a layer, which is a job error, not an empty layer.
    fn store(&mut self, layer_index: u32, bytes: Vec<u8>) {
        let index = layer_index as usize;
        if self.layers.len() <= index {
            self.layers
                .resize_with(index + 1, || LayerSlot::Missing);
        }
        self.layers[index] = if bytes.is_empty() {
            LayerSlot::Empty
        } else {
            LayerSlot::Stream(bytes)
        };
    }
}

/// One layer's runs as its REE stream.
///
/// An empty layer comes back as an empty vector: `encode_runs` reports the empty
/// layer form as `None` because LUMEN stores no stream for it, and no real stream is
/// ever empty, so the empty vector is an unambiguous marker rather than a special
/// case in the encoding.
fn encode_layer(runs: &[RleRun], total_pixels: u32) -> Result<Vec<u8>, SlicerV3Error> {
    // The rasterizer does not emit zero-length runs, but one would be rejected by the
    // reference encoder's canonical rules; dropping it changes no pixel.
    let runs: Vec<Run> = runs
        .iter()
        .filter(|run| run.length > 0)
        .map(|run| Run::new(run.length, run.value))
        .collect();
    if runs.is_empty() {
        return Ok(Vec::new());
    }
    let encoded = encode_runs(&runs, total_pixels, EncodeMode::Auto).map_err(|error| {
        SlicerV3Error::UnsupportedOutput(format!("lumen layer encoding failed: {error}"))
    })?;
    Ok(encoded.map(|(_tag, stream)| stream).unwrap_or_default())
}

/// The scene the profile asked to embed, decoded and checked, or `None` when it did
/// not ask for one.
///
/// With `lumen.embedVoxlScene` off, a payload the job happens to carry is ignored.
/// On with nothing under `lumen.voxlSceneBase64` is an error naming that key rather
/// than a file quietly missing the scene the profile promised, and a payload that is
/// not VOXL is refused by the reference crate's own validator, so a stray blob never
/// ends up in a chunk that claims to be a scene. Both callers reach this before the
/// encoder writes anything, so a refusal leaves no output file behind.
fn embedded_scene(metadata: &LumenMetadata) -> Result<Option<Vec<u8>>, SlicerV3Error> {
    if !metadata.embed_voxl_scene {
        return Ok(None);
    }
    let encoded = metadata
        .voxl_scene_base64
        .as_deref()
        .map(str::trim)
        .filter(|encoded| !encoded.is_empty())
        .ok_or_else(|| {
            SlicerV3Error::UnsupportedOutput(format!(
                "{} is on, but the job carries no {} scene payload to embed",
                lumen_metadata::EMBED_VOXL_SCENE_PATH,
                lumen_metadata::VOXL_SCENE_PATH
            ))
        })?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            SlicerV3Error::UnsupportedOutput(format!(
                "{} is not valid base64: {error}",
                lumen_metadata::VOXL_SCENE_PATH
            ))
        })?;
    lumen::chunks::voxl::require_voxl(&payload).map_err(|error| {
        SlicerV3Error::UnsupportedOutput(format!(
            "{} does not carry a VOXL scene: {error}",
            lumen_metadata::VOXL_SCENE_PATH
        ))
    })?;
    Ok(Some(payload))
}

/// A writer configured the way this print asked for.
fn open_encoder(
    metadata: &LumenMetadata,
    preview_png: Option<&[u8]>,
) -> Result<Encoder, SlicerV3Error> {
    let mut encoder = Encoder::new(metadata.head.clone(), metadata.meta.clone());
    encoder.set_layers_per_chunk(metadata.layers_per_chunk);
    encoder.set_zstd_level(metadata.zstd_level);
    // The writer samples the print, trains a dictionary and writes it only when the
    // print's own data says it pays (section 6.2): an anti-aliased print's greyscale
    // planes are high-entropy enough that a dictionary makes them larger, and a file
    // is better off without one than with one that does not fit.
    encoder.set_dictionary(true);
    encoder.set_layer_hashes(true);
    // `VOXL` is opaque to LUMEN and optional everywhere, so it is only ever the
    // profile's flag that puts one in the file.
    if let Some(scene) = embedded_scene(metadata)? {
        encoder.set_voxl(scene);
    }
    // The preview the file browser will show. The reference writer stores `PREV`
    // payloads as they are, sealed or not, so it stays readable in an encrypted file.
    if let Some(png) = preview_png {
        encoder.add_preview(PreviewRole::Large, png.to_vec());
    }
    Ok(encoder)
}

/// The reference crate's refusals, reported as this engine's errors.
fn lumen_error(error: impl std::fmt::Display) -> SlicerV3Error {
    SlicerV3Error::UnsupportedOutput(format!("lumen encoder refused the print: {error}"))
}

impl RleStreamEncoder for LumenRleStreamEncoder {
    fn consume_rle_layer(
        &mut self,
        layer_index: u32,
        runs: Vec<RleRun>,
    ) -> Result<(), SlicerV3Error> {
        let bytes = encode_layer(&runs, self.total_pixels)?;
        self.store(layer_index, bytes);
        Ok(())
    }

    /// Runs to REE in the engine's rayon workers.
    ///
    /// These layers are independent - each one becomes its own stream, and grouping
    /// and compression happen later in `finalize_to_bytes` - so this is the whole
    /// reason a 16K print is not bottlenecked on one core.
    fn parallel_encode_fn(
        &self,
    ) -> Option<Arc<dyn Fn(u32, &[RleRun]) -> Result<Vec<u8>, SlicerV3Error> + Send + Sync>> {
        let total_pixels = self.total_pixels;
        Some(Arc::new(move |_layer_index, runs| {
            encode_layer(runs, total_pixels)
        }))
    }

    fn store_encoded_layer(&mut self, layer_index: u32, bytes: Vec<u8>) {
        self.store(layer_index, bytes);
    }

    fn finalize_to_bytes(mut self: Box<Self>) -> Result<Vec<u8>, SlicerV3Error> {
        if self.layers.is_empty() {
            return Err(SlicerV3Error::MissingRenderedLayerPayload(
                "no rendered layers were provided for LUMEN encoding".to_string(),
            ));
        }
        let mut encoder = open_encoder(&self.metadata, self.preview_png.as_deref())?;
        for (index, slot) in std::mem::take(&mut self.layers).into_iter().enumerate() {
            let layer = match slot {
                LayerSlot::Empty => EncodedLayer::Empty,
                LayerSlot::Stream(bytes) => EncodedLayer::single(bytes).map_err(|error| {
                    SlicerV3Error::UnsupportedOutput(format!("lumen layer {index}: {error}"))
                })?,
                LayerSlot::Missing => {
                    return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                        "no mask was delivered for layer {index}"
                    )))
                }
            };
            encoder.push_encoded_layer(layer).map_err(lumen_error)?;
        }
        encoder.finish().map_err(lumen_error)
    }
}

/// The `.lumen` encoder, as the engine's registry sees it.
pub struct LumenPluginEncoder;

impl FormatEncoder for LumenPluginEncoder {
    fn output_format(&self) -> &'static str {
        ".lumen"
    }

    /// The engine rasterizes straight to runs, so this encoder never asks for PNG
    /// layers and never asks for raw masks either: nothing in the LUMEN path needs a
    /// full-frame pixel buffer.
    fn requires_png_layers(&self) -> bool {
        false
    }

    fn create_rle_stream_encoder(
        &self,
        job: &SliceJobV3,
    ) -> Result<Option<Box<dyn RleStreamEncoder>>, SlicerV3Error> {
        let metadata = lumen_metadata::build(job)?;
        let total_pixels = u64::from(job.source_width_px) * u64::from(job.source_height_px);
        let total_pixels = u32::try_from(total_pixels).map_err(|_| {
            SlicerV3Error::InvalidDimensions {
                width: job.source_width_px,
                height: job.source_height_px,
            }
        })?;
        Ok(Some(Box::new(LumenRleStreamEncoder::new(
            metadata,
            total_pixels,
            lumen_preview::export_preview_png(job),
        ))))
    }

    /// Decode one layer of an already-written `.lumen` artifact as a grayscale PNG.
    ///
    /// This is how the app inspects a file it has already sliced: it opens the
    /// artifact the way a printer would - container only, no key, no dictionary of
    /// its own - and renders the layer's stored 8-bit mask, which is the pixel data
    /// itself rather than a re-slice. Validation is skipped here for a narrower
    /// reason than it once was: the reader now checks a stream by walking it, so
    /// this file validates in 23 ms, but the app calls this per layer while
    /// scrubbing and re-validating one file eight hundred times is work nobody asked
    /// for. A malformed stream still fails when the layer is decoded. Encrypted
    /// artifacts need their key and are refused with that stated, rather than
    /// reported as corrupt.
    fn read_layer_preview_png(
        &self,
        path: &Path,
        layer_number: u32,
    ) -> Result<Vec<u8>, SlicerV3Error> {
        let bytes = std::fs::read(path)
            .map_err(|error| SlicerV3Error::LayerPreview(format!("{}: {error}", path.display())))?;
        let file = LumenFile::open_unvalidated(&bytes).map_err(|error| {
            SlicerV3Error::LayerPreview(format!(
                "{} could not be read as a LUMEN file, which an encrypted artifact needs its key for: {error}",
                path.display()
            ))
        })?;

        let count = file.layer_count();
        // Layer numbers are 1-based wherever the engine asks for a preview.
        let index = layer_number
            .checked_sub(1)
            .filter(|index| *index < count)
            .ok_or_else(|| {
                SlicerV3Error::LayerPreview(format!(
                    "layer {layer_number} is outside this file's 1..={count} layers"
                ))
            })?;

        let layer = file
            .layer(index)
            .map_err(|error| SlicerV3Error::LayerPreview(format!("layer {layer_number}: {error}")))?;
        let head = file.head();
        grayscale_png(
            &layer.pixels,
            head.display_width_px,
            head.display_height_px,
        )
    }

    /// The path for a caller that already holds rendered masks instead of runs.
    ///
    /// The engine prefers the streaming sink above, so this exists for the
    /// capability-aware entrypoints and produces the same file at a higher cost per
    /// layer: `push_layer` scans the whole frame where the run path does not.
    fn encode_container_from_rendered_layers(
        &self,
        job: &SliceJobV3,
        rendered_layers: &RenderedLayersV3,
        _layer_area_stats: &[LayerAreaStatsV3],
    ) -> Result<Vec<u8>, SlicerV3Error> {
        let masks = rendered_layers.raw_mask_layers.as_ref().ok_or_else(|| {
            SlicerV3Error::MissingRenderedLayerPayload(
                "the LUMEN encoder encodes raster masks or runs".to_string(),
            )
        })?;
        let metadata = lumen_metadata::build(job)?;
        let preview_png = lumen_preview::export_preview_png(job);
        let mut encoder = open_encoder(&metadata, preview_png.as_deref())?;
        for mask in masks {
            encoder.push_layer(mask).map_err(lumen_error)?;
        }
        encoder.finish().map_err(lumen_error)
    }
}

/// One layer's 8-bit grayscale mask as a PNG, the form the app's layer previews use.
fn grayscale_png(pixels: &[u8], width: u32, height: u32) -> Result<Vec<u8>, SlicerV3Error> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        // A 16K layer is 94 M pixels, and the default search for the best filter per
        // row costs about a second on that while buying nothing on a mask that is
        // mostly flat: measured, this pair encodes in 11 ms instead of 1.5 s at the
        // same output size.
        encoder.set_filter(png::FilterType::Sub);
        encoder.set_compression(png::Compression::Fast);
        let mut writer = encoder
            .write_header()
            .map_err(|error| SlicerV3Error::Png(error.to_string()))?;
        writer
            .write_image_data(pixels)
            .map_err(|error| SlicerV3Error::Png(error.to_string()))?;
        writer
            .finish()
            .map_err(|error| SlicerV3Error::Png(error.to_string()))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SliceJobV3;

    /// The capture DragonFruit hands the encoder: the app renders the export
    /// thumbnail at 1600x960.
    fn capture_png() -> Vec<u8> {
        let (w, h) = (1600u32, 960u32);
        let pixels = vec![200u8; (w * h) as usize];
        let mut out = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut out, w, h);
            encoder.set_color(png::ColorType::Grayscale);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&pixels).unwrap();
        }
        out
    }

    fn test_job(thumbnail: Option<Vec<u8>>) -> SliceJobV3 {
        SliceJobV3 {
            output_format: ".lumen".to_string(),
            source_width_px: 64,
            source_height_px: 48,
            width_px: 64,
            height_px: 48,
            build_width_mm: 100.0,
            build_depth_mm: 60.0,
            layer_height_mm: 0.05,
            total_layers: 1,
            anti_aliasing_level: "Off".to_string(),
            // The default for this field is the empty string; LUMEN stores masks on
            // the display grid, so the job has to say the raster is unpacked.
            x_packing_mode: "none".to_string(),
            metadata_json: "{}".to_string(),
            export_thumbnail_png_base64: thumbnail
                .map(|png| base64::engine::general_purpose::STANDARD.encode(png)),
            ..Default::default()
        }
    }

    /// One fully-lit layer through the streaming sink, which is the path a real
    /// slice takes.
    fn slice_one_layer(job: &SliceJobV3) -> Vec<u8> {
        let encoder = LumenPluginEncoder;
        let mut sink = encoder.create_rle_stream_encoder(job).unwrap().unwrap();
        sink.consume_rle_layer(
            0,
            vec![RleRun {
                length: 64 * 48,
                value: 255,
            }],
        )
        .unwrap();
        sink.finalize_to_bytes().unwrap()
    }

    /// Width and height from the IHDR every PNG starts with.
    fn png_dimensions(png_bytes: &[u8]) -> (u32, u32) {
        (
            u32::from_be_bytes(png_bytes[16..20].try_into().unwrap()),
            u32::from_be_bytes(png_bytes[20..24].try_into().unwrap()),
        )
    }

    #[test]
    fn the_captured_thumbnail_reaches_the_file_as_a_large_preview() {
        let bytes = slice_one_layer(&test_job(Some(capture_png())));
        let file = LumenFile::open_unvalidated(&bytes).unwrap();

        let previews = file.previews();
        assert_eq!(previews.len(), 1, "one PREV chunk");
        assert_eq!(previews[0].role, PreviewRole::Large);
        // Fitted into the role's 400x300 box without distortion: 400x240.
        assert_eq!(png_dimensions(&previews[0].png), (400, 240));
    }

    #[test]
    fn a_job_without_a_usable_capture_writes_no_preview() {
        // No thumbnail at all.
        let bytes = slice_one_layer(&test_job(None));
        assert!(LumenFile::open_unvalidated(&bytes)
            .unwrap()
            .previews()
            .is_empty());

        // A thumbnail that is not a PNG costs the file its preview and nothing else.
        let bytes = slice_one_layer(&test_job(Some(b"not a png".to_vec())));
        assert!(LumenFile::open_unvalidated(&bytes)
            .unwrap()
            .previews()
            .is_empty());
    }
}

pub fn create_plugin_encoder() -> Vec<Box<dyn FormatEncoder>> {
    vec![Box::new(LumenPluginEncoder)]
}
