//! The `PREV` preview a `.lumen` file carries.
//!
//! LUMEN keeps previews in `PREV` chunks — PNG payloads whose descriptor flags name
//! a role (spec §4.6) — and they are what a file browser shows for a `.lumen` file,
//! through the same thumbnail provider the `.voxl` scene format already uses.
//!
//! DragonFruit captures the export thumbnail at 1600×960, which is four times the
//! role-1 recommendation of 400×300. Writing it verbatim would cost a print file a
//! megabyte for a picture every reader scales down anyway, so it is fitted to the
//! role's box here.
//!
//! Nothing in this module fails a print: a thumbnail is decoration, and the
//! reference crate is what decides whether the file itself is well formed. An
//! unusable capture leaves the file with no `PREV` chunk, which the format makes
//! optional on purpose.

use base64::Engine;

use crate::types::SliceJobV3;

/// The role-1 (large) preview box, from the LUMEN spec's recommendation.
const LARGE_W: u32 = 400;
const LARGE_H: u32 = 300;

/// The scene thumbnail the export captured, fitted into the large preview box.
///
/// `None` when the job carries no thumbnail, or carries one that cannot be decoded
/// into a PNG this encoder would stand behind.
pub(super) fn export_preview_png(job: &SliceJobV3) -> Option<Vec<u8>> {
    let encoded = job.export_thumbnail_png_base64.as_deref()?.trim();
    if encoded.is_empty() {
        return None;
    }

    let png_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let (src_w, src_h, rgba) = decode_rgba(&png_bytes)?;
    let (dst_w, dst_h) = fit(src_w, src_h, LARGE_W, LARGE_H);
    let resized = resize_nearest(&rgba, src_w, src_h, dst_w, dst_h);
    encode_png(dst_w, dst_h, &resized).ok()
}

/// Fit `src_w × src_h` inside `box_w × box_h`, keeping the aspect ratio and never
/// upscaling: a thumbnail larger than its source is not a thumbnail.
fn fit(src_w: u32, src_h: u32, box_w: u32, box_h: u32) -> (u32, u32) {
    if src_w == 0 || src_h == 0 {
        return (1, 1);
    }
    if src_w <= box_w && src_h <= box_h {
        return (src_w, src_h);
    }

    let by_width = (u64::from(box_w) * u64::from(src_h)) / u64::from(src_w);
    if by_width <= u64::from(box_h) {
        (box_w, by_width.max(1) as u32)
    } else {
        let by_height = (u64::from(box_h) * u64::from(src_w)) / u64::from(src_h);
        (by_height.max(1) as u32, box_h)
    }
}

/// Decode a PNG to 8-bit RGBA, whatever colour type the capture used.
///
/// `EXPAND` handles bit depths and palettes, `STRIP_16` drops 16-bit channels to
/// their high byte, so what comes out is always one of the four 8-bit layouts below.
fn decode_rgba(png_bytes: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let raw = &buf[..info.buffer_size()];

    let (w, h) = (info.width, info.height);
    let pixels = (w as usize) * (h as usize);
    let mut rgba = vec![0u8; pixels * 4];

    match info.color_type {
        png::ColorType::Rgba => rgba.copy_from_slice(&raw[..pixels * 4]),
        png::ColorType::Rgb => {
            for (px, chunk) in rgba.chunks_exact_mut(4).zip(raw.chunks_exact(3)) {
                px[0] = chunk[0];
                px[1] = chunk[1];
                px[2] = chunk[2];
                px[3] = 255;
            }
        }
        png::ColorType::GrayscaleAlpha => {
            for (px, chunk) in rgba.chunks_exact_mut(4).zip(raw.chunks_exact(2)) {
                let value = chunk[0];
                px[0] = value;
                px[1] = value;
                px[2] = value;
                px[3] = chunk[1];
            }
        }
        png::ColorType::Grayscale => {
            for (px, chunk) in rgba.chunks_exact_mut(4).zip(raw.chunks_exact(1)) {
                let value = chunk[0];
                px[0] = value;
                px[1] = value;
                px[2] = value;
                px[3] = 255;
            }
        }
        // `EXPAND` resolves palettes before this point, so an indexed frame here
        // means the decoder did not transform it: better no preview than invented
        // colours.
        png::ColorType::Indexed => return None,
    }

    Some((w, h, rgba))
}

/// Nearest-neighbour resample, sampling each destination pixel at its centre.
///
/// Nearest is what the other preview builders in this tree use, and the source is a
/// smooth 3D render being reduced by four, so the cheaper filter is also the one
/// that keeps the thumbnail faithful.
fn resize_nearest(src: &[u8], src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Vec<u8> {
    let mut out = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
    if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
        return out;
    }

    for y in 0..dst_h {
        // Centre of the destination row, mapped into the source.
        let sy = (((u64::from(y) * 2 + 1) * u64::from(src_h)) / (u64::from(dst_h) * 2))
            .min(u64::from(src_h - 1)) as usize;
        for x in 0..dst_w {
            let sx = (((u64::from(x) * 2 + 1) * u64::from(src_w)) / (u64::from(dst_w) * 2))
                .min(u64::from(src_w - 1)) as usize;

            let from = (sy * src_w as usize + sx) * 4;
            let to = (y as usize * dst_w as usize + x as usize) * 4;
            out[to..to + 4].copy_from_slice(&src[from..from + 4]);
        }
    }

    out
}

fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, png::EncodingError> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(rgba)?;
        writer.finish()?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PNG of the given size through the same encoder the preview uses.
    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut rgba = Vec::with_capacity((width as usize) * (height as usize) * 4);
        for _ in 0..(width * height) {
            rgba.extend_from_slice(&[128, 128, 128, 255]);
        }
        encode_png(width, height, &rgba).unwrap()
    }

    #[test]
    fn fit_keeps_the_aspect_ratio_and_never_upscales() {
        // 1600×960 (the capture) into the role box: width-bound.
        assert_eq!(fit(1600, 960, 400, 300), (400, 240));
        // Tall sources are height-bound.
        assert_eq!(fit(960, 1600, 400, 300), (180, 300));
        // Already inside the box: untouched.
        assert_eq!(fit(320, 240, 400, 300), (320, 240));
    }

    #[test]
    fn resized_preview_round_trips_through_the_decoder() {
        let source = png(1600, 960);
        let (w, h, rgba) = decode_rgba(&source).unwrap();
        assert_eq!((w, h), (1600, 960));

        let (dst_w, dst_h) = fit(w, h, LARGE_W, LARGE_H);
        let resized = resize_nearest(&rgba, w, h, dst_w, dst_h);
        let encoded = encode_png(dst_w, dst_h, &resized).unwrap();

        let (out_w, out_h, out_rgba) = decode_rgba(&encoded).unwrap();
        assert_eq!((out_w, out_h), (400, 240));
        assert_eq!(out_rgba.len(), 400 * 240 * 4);
        // Every pixel survives the round trip with its value.
        assert!(out_rgba.chunks_exact(4).all(|px| px == [128, 128, 128, 255]));
    }
}
