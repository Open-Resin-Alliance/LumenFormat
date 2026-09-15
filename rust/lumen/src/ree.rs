//! Run-end encoded layer masks ([`spec/08-layer-encoding.md`] section 5).
//!
//! Three tags are defined: binary REE (`0x00`), grayscale REE (`0x01`) and split
//! REE (`0x02`). A layer whose pixels are all zero has no stream at all - the
//! empty-layer form lives in the `LTBL` entry, not in the layer data.

use crate::check::Check;
use crate::error::{Error, Result};
use crate::io::{Reader, Writer};

/// Tag for binary REE, used when every pixel is `0x00` or `0xFF`.
pub const TAG_BINARY: u8 = 0x00;
/// Tag for grayscale REE, used when pixels may hold any 8-bit value.
pub const TAG_GRAYSCALE: u8 = 0x01;
/// Tag for binary REE plus a sparse anti-aliasing overlay.
pub const TAG_SPLIT: u8 = 0x02;

/// Which encoding an encoder should use for a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncodeMode {
    /// Smallest of the applicable encodings; ties go to grayscale (section 5.6).
    #[default]
    Auto,
    /// Binary REE. Requires every pixel to be `0x00` or `0xFF`.
    Binary,
    /// Grayscale REE.
    Grayscale,
    /// Split REE. The thresholded mask thresholds at `v >= 128`.
    Split,
}

/// A decoded layer mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLayer {
    /// One byte per pixel, in row-major order, `total_pixels` long.
    pub pixels: Vec<u8>,
    /// The tag the stream carried, or `None` for the empty-layer form.
    pub tag: Option<u8>,
}

impl DecodedLayer {
    /// All-black layer, carrying no stream: `LTBL.sector_count == 0`.
    pub fn empty(total_pixels: u32) -> DecodedLayer {
        DecodedLayer {
            pixels: vec![0u8; total_pixels as usize],
            tag: None,
        }
    }

    /// Whether this is the empty-layer form.
    pub fn is_empty(&self) -> bool {
        self.tag.is_none()
    }

    /// Whether every pixel is `0x00` or `0xFF`.
    pub fn is_binary(&self) -> bool {
        self.pixels.iter().all(|p| *p == 0 || *p == 255)
    }
}

/// The binary threshold of section 5.5: `255 if v >= 128 else 0`.
pub fn threshold(pixel: u8) -> u8 {
    if pixel >= 128 {
        255
    } else {
        0
    }
}

/// Decode a layer's mask data, exclusive of any sector framing.
///
/// `data` is the one-byte encoding tag followed by the stream, so it is never
/// empty: the empty-layer form carries no bytes at all. Bytes past the end of
/// the stream are not part of the mask and are ignored.
///
/// In `strict` mode the canonical-form rules of section 5.6 are enforced.
/// A loose read accepts any stream that satisfies sections 5.3-5.5. A stream
/// that ends before its structure is complete reports [`Check::ReeVarint`], the
/// check the varint decoder already uses for a truncated stream.
pub fn decode(data: &[u8], total_pixels: u32, strict: bool) -> Result<DecodedLayer> {
    decode_counted(data, total_pixels, strict).map(|(layer, _)| layer)
}

/// Decode a layer mask and report how many bytes the stream used.
///
/// The length is what lets a caller notice bytes after the end of the stream:
/// the mask data a layer stores is exactly `[tag][stream]`, so any surplus is
/// padding the encoder did not intend and a reader must not silently accept
/// (`ree` rule, section 11.3).
pub fn decode_counted(
    data: &[u8],
    total_pixels: u32,
    strict: bool,
) -> Result<(DecodedLayer, usize)> {
    let Some((&tag, stream)) = data.split_first() else {
        return Err(Error::new(
            Check::ReeTag,
            "layer mask data is empty: the empty-layer form carries no bytes",
        ));
    };
    let mut reader = Reader::checked(stream, Check::ReeVarint);
    let pixels = match tag {
        TAG_BINARY => decode_binary(&mut reader, total_pixels, strict)?,
        TAG_GRAYSCALE => decode_grayscale(&mut reader, total_pixels, strict)?,
        TAG_SPLIT => decode_split(&mut reader, total_pixels, strict)?,
        other => {
            return Err(Error::new(
                Check::ReeTag,
                format!("unknown layer encoding tag 0x{other:02X}"),
            ))
        }
    };
    Ok((
        DecodedLayer {
            pixels,
            tag: Some(tag),
        },
        1 + reader.pos(),
    ))
}

/// Read a run count and reject one above the section 5.2 bound before any buffer
/// is sized from it: a run covers at least one pixel, so a stream cannot hold
/// more than `total_pixels + 1` runs.
fn read_run_count(reader: &mut Reader<'_>, total_pixels: u64) -> Result<u64> {
    let bound = total_pixels + 1;
    let run_count = reader.varint()?;
    if run_count > bound {
        return Err(Error::new(
            Check::ReeRunLengths,
            format!("run_count {run_count} exceeds total_pixels + 1 ({bound})"),
        ));
    }
    Ok(run_count)
}

/// Fill `mask[start .. end]` with `value`. Both bounds are validated by callers.
fn fill(mask: &mut [u8], start: u64, end: u64, value: u8) {
    mask[start as usize..end as usize].fill(value);
}

/// Decode the binary REE stream of section 5.3. The helper is shared with the
/// split tag, whose binary component is a tagless binary stream.
fn decode_binary(reader: &mut Reader<'_>, total_pixels: u32, strict: bool) -> Result<Vec<u8>> {
    let total = u64::from(total_pixels);
    let first_value = reader.u8()?;
    if first_value != 0x00 && first_value != 0xFF {
        return Err(Error::new(
            Check::ReeFirstValue,
            format!("binary REE first_value is 0x{first_value:02X}, not 0x00 or 0xFF"),
        ));
    }
    let run_count = read_run_count(reader, total)?;
    if run_count == 0 {
        if strict {
            return Err(Error::new(
                Check::ReeNoRunCountZero,
                "binary REE uses the non-canonical run_count == 0 form",
            ));
        }
        return Ok(vec![0u8; total_pixels as usize]);
    }
    if run_count == 1 {
        return Ok(vec![first_value; total_pixels as usize]);
    }

    let mut mask = vec![0u8; total_pixels as usize];
    let mut value = first_value;
    let mut start = 0u64;
    let mut cumulative = 0u64;
    let mut empty_run = false;
    for i in 0..run_count {
        let end = if i + 1 == run_count {
            // The last run's length is implicit: it ends at total_pixels.
            total
        } else {
            let delta = reader.varint()?;
            cumulative = cumulative.checked_add(delta).ok_or_else(|| {
                Error::new(Check::ReeEndPositions, "binary REE run lengths overflow")
            })?;
            cumulative
        };
        if end > total {
            return Err(Error::new(
                Check::ReeEndPositions,
                format!("binary REE run {i} ends at {end}, past total_pixels {total}"),
            ));
        }
        empty_run |= end == start;
        fill(&mut mask, start, end, value);
        value = 255 - value;
        start = end;
    }
    if strict && empty_run {
        return Err(Error::new(
            Check::ReeRunLengths,
            "binary REE stores an empty run",
        ));
    }
    Ok(mask)
}

/// Decode the grayscale REE stream of section 5.4.
fn decode_grayscale(reader: &mut Reader<'_>, total_pixels: u32, strict: bool) -> Result<Vec<u8>> {
    let total = u64::from(total_pixels);
    let run_count = read_run_count(reader, total)?;
    if run_count == 0 {
        if strict {
            return Err(Error::new(
                Check::ReeNoRunCountZero,
                "grayscale REE uses the non-canonical run_count == 0 form",
            ));
        }
        return Ok(vec![0u8; total_pixels as usize]);
    }

    let mut mask = vec![0u8; total_pixels as usize];
    let mut start = 0u64;
    let mut previous: Option<u8> = None;
    for _ in 0..run_count {
        let value = reader.u8()?;
        let end = reader.varint()?;
        if end > total {
            return Err(Error::new(
                Check::ReeEndPositions,
                format!("grayscale REE end position {end} is past total_pixels {total}"),
            ));
        }
        if end < start {
            // Out of order: loose mode still requires non-decreasing positions.
            return Err(Error::new(
                if strict {
                    Check::ReeGrayscaleRuns
                } else {
                    Check::ReeEndPositions
                },
                format!("grayscale REE end position {end} follows {start}"),
            ));
        }
        if strict && end == start {
            return Err(Error::new(
                Check::ReeGrayscaleRuns,
                "grayscale REE stores a zero-length run",
            ));
        }
        if strict && previous == Some(value) {
            return Err(Error::new(
                Check::ReeGrayscaleRuns,
                format!("grayscale REE repeats value 0x{value:02X} in adjacent runs"),
            ));
        }
        fill(&mut mask, start, end, value);
        previous = Some(value);
        start = end;
    }
    if start != total {
        return Err(Error::new(
            Check::ReeEndPositions,
            format!("grayscale REE ends at {start}, not total_pixels {total}"),
        ));
    }
    if strict && mask.iter().all(|p| *p == 0x00 || *p == 0xFF) {
        return Err(Error::new(
            Check::ReeGrayscaleAllBinary,
            "grayscale REE holds only 0x00/0xFF pixels; such a layer must use tag 0x00",
        ));
    }
    Ok(mask)
}

/// Decode the split stream of section 5.5: a binary REE component followed by a
/// delta-encoded sparse overlay of anti-aliasing pixels.
fn decode_split(reader: &mut Reader<'_>, total_pixels: u32, strict: bool) -> Result<Vec<u8>> {
    let total = u64::from(total_pixels);
    let mut mask = decode_binary(reader, total_pixels, strict)?;

    let aa_count = reader.varint()?;
    let bound = total + 1;
    if aa_count > bound {
        return Err(Error::new(
            Check::ReeSplitPositions,
            format!("aa_pixel_count {aa_count} exceeds total_pixels + 1 ({bound})"),
        ));
    }
    if aa_count == 0 {
        return Ok(mask);
    }

    let count = aa_count as usize;
    let mut positions: Vec<u32> = Vec::with_capacity(count);
    let mut position = 0u64;
    for i in 0..count {
        let delta = reader.varint()?;
        position = position.checked_add(delta).ok_or_else(|| {
            Error::new(Check::ReeSplitPositions, "split overlay positions overflow")
        })?;
        if i > 0 && delta == 0 {
            return Err(Error::new(
                Check::ReeSplitPositions,
                format!("split overlay position {position} repeats its predecessor"),
            ));
        }
        if position >= total {
            return Err(Error::new(
                Check::ReeSplitPositions,
                format!("split overlay position {position} is not below total_pixels {total}"),
            ));
        }
        positions.push(position as u32);
    }

    let values = reader.bytes(count)?;
    if strict {
        for (i, &pixel) in positions.iter().enumerate() {
            let value = values[i];
            let binary = mask[pixel as usize];
            if value == 0x00 || value == 0xFF || threshold(value) != binary {
                return Err(Error::new(
                    Check::ReeSplitThreshold,
                    format!(
                        "split overlay pixel {pixel} holds 0x{value:02X} over binary 0x{binary:02X}"
                    ),
                ));
            }
        }
    }
    for (i, &pixel) in positions.iter().enumerate() {
        mask[pixel as usize] = values[i];
    }
    Ok(mask)
}

/// Reject a mask whose length is not the layer's pixel count.
fn check_mask(pixels: &[u8], total_pixels: u32) -> Result<()> {
    if pixels.len() != total_pixels as usize {
        return Err(Error::new(
            Check::ReeDataSize,
            format!(
                "mask holds {} pixels, total_pixels is {total_pixels}",
                pixels.len()
            ),
        ));
    }
    Ok(())
}

/// A zero-pixel layer is the empty-layer form: it has no encodable stream.
fn require_pixels(pixels: &[u8]) -> Result<()> {
    if pixels.is_empty() {
        return Err(Error::new(
            Check::ReeDataSize,
            "a zero-pixel layer has no encodable stream: it is the empty-layer form",
        ));
    }
    Ok(())
}

/// Write the tagless binary REE stream of section 5.3 for `pixels`, mapping each
/// pixel through `value_of` so the split encoder can threshold without
/// materializing a second mask.
fn write_binary_stream(
    writer: &mut Writer,
    pixels: &[u8],
    value_of: impl Fn(u8) -> u8,
) -> Result<()> {
    let Some(&first) = pixels.first() else {
        return Err(Error::new(
            Check::ReeDataSize,
            "a binary stream needs at least one pixel",
        ));
    };
    let first_value = value_of(first);
    if first_value != 0x00 && first_value != 0xFF {
        return Err(Error::new(
            Check::ReeFirstValue,
            format!("binary REE first_value is 0x{first_value:02X}, not 0x00 or 0xFF"),
        ));
    }

    // Runs alternate strictly, so the value after the first is determined.
    let mut run_count = 1u64;
    let mut value = first_value;
    for &pixel in pixels {
        let mapped = value_of(pixel);
        if mapped == value {
            continue;
        }
        if mapped != 255 - value {
            return Err(Error::new(
                Check::ReeFirstValue,
                format!("binary REE cannot hold pixel 0x{mapped:02X}"),
            ));
        }
        run_count += 1;
        value = mapped;
    }

    writer.u8(first_value);
    writer.varint(run_count);
    // Every run length except the last, whose end is implicitly total_pixels.
    let mut value = first_value;
    let mut length = 0u64;
    for &pixel in pixels {
        if value_of(pixel) == value {
            length += 1;
        } else {
            writer.varint(length);
            value = value_of(pixel);
            length = 1;
        }
    }
    Ok(())
}

/// Encode a layer mask, choosing the tag per `mode`.
///
/// Returns `None` for an all-black layer, which is stored as the empty-layer
/// form with no bytes at all.
///
/// The returned bytes are the mask data a layer stores: the tag, then the
/// stream. The tag is returned alongside them so a caller can log or branch on
/// the choice, not so it can be re-prepended.
pub fn encode(pixels: &[u8], total_pixels: u32, mode: EncodeMode) -> Result<Option<(u8, Vec<u8>)>> {
    check_mask(pixels, total_pixels)?;
    if pixels.iter().all(|pixel| *pixel == 0) {
        return Ok(None);
    }
    let encoded = match mode {
        EncodeMode::Binary => (TAG_BINARY, encode_binary(pixels, total_pixels)?),
        EncodeMode::Grayscale => (TAG_GRAYSCALE, encode_grayscale(pixels, total_pixels)?),
        EncodeMode::Split => (TAG_SPLIT, encode_split(pixels, total_pixels)?),
        EncodeMode::Auto => {
            if pixels.iter().all(|pixel| *pixel == 0 || *pixel == 255) {
                (TAG_BINARY, encode_binary(pixels, total_pixels)?)
            } else {
                // Section 5.6: the encoder picks the smaller of the two, and a
                // tie goes to grayscale.
                let grayscale = encode_grayscale(pixels, total_pixels)?;
                let split = encode_split(pixels, total_pixels)?;
                if split.len() < grayscale.len() {
                    (TAG_SPLIT, split)
                } else {
                    (TAG_GRAYSCALE, grayscale)
                }
            }
        }
    };
    Ok(Some(encoded))
}

/// Encode with tag `0x00`; the returned bytes include the tag.
pub fn encode_binary(pixels: &[u8], total_pixels: u32) -> Result<Vec<u8>> {
    check_mask(pixels, total_pixels)?;
    require_pixels(pixels)?;
    let mut writer = Writer::new();
    writer.u8(TAG_BINARY);
    write_binary_stream(&mut writer, pixels, |pixel| pixel)?;
    Ok(writer.into_vec())
}

/// Encode with tag `0x01`; the returned bytes include the tag.
pub fn encode_grayscale(pixels: &[u8], total_pixels: u32) -> Result<Vec<u8>> {
    check_mask(pixels, total_pixels)?;
    require_pixels(pixels)?;
    let mut writer = Writer::new();
    writer.u8(TAG_GRAYSCALE);

    // One run per maximal stretch of equal pixels.
    let mut run_count = 0u64;
    let mut previous: Option<u8> = None;
    for &pixel in pixels {
        if previous != Some(pixel) {
            run_count += 1;
            previous = Some(pixel);
        }
    }
    writer.varint(run_count);

    // Every run's value and its absolute end position; the last ends at
    // total_pixels.
    let mut end = 0u64;
    let mut previous: Option<u8> = None;
    for &pixel in pixels {
        end += 1;
        if previous != Some(pixel) {
            if let Some(value) = previous {
                writer.u8(value);
                writer.varint(end - 1);
            }
            previous = Some(pixel);
        }
    }
    if let Some(value) = previous {
        writer.u8(value);
        writer.varint(end);
    }
    Ok(writer.into_vec())
}

/// Encode with tag `0x02`; the returned bytes include the tag.
pub fn encode_split(pixels: &[u8], total_pixels: u32) -> Result<Vec<u8>> {
    check_mask(pixels, total_pixels)?;
    require_pixels(pixels)?;
    let mut writer = Writer::new();
    writer.u8(TAG_SPLIT);
    write_binary_stream(&mut writer, pixels, threshold)?;

    // The overlay is exactly the pixels whose value is neither 0x00 nor 0xFF.
    let mut count = 0u64;
    for &pixel in pixels {
        if pixel != 0x00 && pixel != 0xFF {
            count += 1;
        }
    }
    writer.varint(count);

    // Positions are absolute then delta-encoded, and strictly increasing, so
    // every delta after the first is at least 1.
    let mut previous = 0u64;
    for (index, &pixel) in pixels.iter().enumerate() {
        if pixel == 0x00 || pixel == 0xFF {
            continue;
        }
        let position = index as u64;
        writer.varint(position - previous);
        previous = position;
    }
    for &pixel in pixels {
        if pixel != 0x00 && pixel != 0xFF {
            writer.u8(pixel);
        }
    }
    Ok(writer.into_vec())
}

/// Re-check a stream against the canonical rules and report the bytes it used.
///
/// `data` is the same one-byte tag plus stream that [`decode`] takes - the
/// canonical rules of section 5.6 depend on the tag - and the decoded mask is
/// discarded. The returned length is the stream's exact extent, so a caller
/// holding the layer's stored range can reject padding after it.
pub fn validate_stream(data: &[u8], total_pixels: u32, strict: bool) -> Result<usize> {
    decode_counted(data, total_pixels, strict).map(|(_, len)| len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 64 x 48 pixel masks of `test-vectors/valid/binary-basic.lumen`, one
    /// per tag, exactly as the corpus stores them.
    const LAYER_BINARY: &str = "00000364c801";
    const LAYER_GRAYSCALE: &str = "01050064807800dc01ffc002008018";
    const LAYER_SPLIT: &str = "020005641e14321e640101010101010101010101010101010101010101010101010101010101c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8";
    /// `HDR.display_width_px * HDR.display_height_px` for that file.
    const TOTAL: u32 = 64 * 48;

    /// Expand `(value, length)` runs into a mask.
    fn mask(runs: &[(u8, usize)]) -> Vec<u8> {
        let mut pixels = Vec::new();
        for (value, length) in runs {
            pixels.extend(std::iter::repeat_n(*value, *length));
        }
        pixels
    }

    /// The `(value, length)` runs of a mask.
    fn runs(pixels: &[u8]) -> Vec<(u8, usize)> {
        let mut runs: Vec<(u8, usize)> = Vec::new();
        for &pixel in pixels {
            if let Some(last) = runs.last_mut() {
                if last.0 == pixel {
                    last.1 += 1;
                    continue;
                }
            }
            runs.push((pixel, 1));
        }
        runs
    }

    fn bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    fn check_of(data: &[u8], total: u32, strict: bool) -> Check {
        decode(data, total, strict).unwrap_err().check()
    }

    #[test]
    fn spec_varint_examples() {
        // Section 5.2's table and its three worked examples.
        assert_eq!(crate::varint::to_vec(0), vec![0x00]);
        assert_eq!(crate::varint::to_vec(128), vec![0x80, 0x01]);
        assert_eq!(crate::varint::encoded_len(127), 1);
        assert_eq!(crate::varint::encoded_len(128), 2);
        assert_eq!(crate::varint::encoded_len(16_383), 2);
        assert_eq!(crate::varint::encoded_len(16_384), 3);
        assert_eq!(crate::varint::encoded_len(2_097_151), 3);
        assert_eq!(crate::varint::encoded_len(268_435_455), 4);
        assert_eq!(
            crate::varint::to_vec(1920 * 1080),
            vec![0x80, 0xC8, 0x7E],
            "2 073 600 is 3 bytes"
        );
        assert_eq!(crate::varint::encoded_len(11_520 * 6_480), 4);
        let twelve_k = crate::varint::to_vec(11_520 * 6_480);
        let mut reader = Reader::new(&twelve_k);
        assert_eq!(reader.varint().unwrap(), 11_520 * 6_480);
        assert!(reader.is_empty());
    }

    #[test]
    fn binary_layer_of_the_corpus_round_trips() {
        let data = bytes(LAYER_BINARY);
        let expected = mask(&[(0, 100), (255, 200), (0, 2772)]);
        for strict in [false, true] {
            let layer = decode(&data, TOTAL, strict).unwrap();
            assert_eq!(layer.tag, Some(TAG_BINARY));
            assert_eq!(layer.pixels, expected);
            assert!(layer.is_binary());
        }
        assert_eq!(encode_binary(&expected, TOTAL).unwrap(), data);
        assert_eq!(
            encode(&expected, TOTAL, EncodeMode::Auto).unwrap(),
            Some((TAG_BINARY, data))
        );
    }

    #[test]
    fn grayscale_layer_of_the_corpus_round_trips() {
        let data = bytes(LAYER_GRAYSCALE);
        let expected = mask(&[(0, 100), (128, 20), (0, 100), (255, 100), (0, 2752)]);
        for strict in [false, true] {
            let layer = decode(&data, TOTAL, strict).unwrap();
            assert_eq!(layer.tag, Some(TAG_GRAYSCALE));
            assert_eq!(layer.pixels, expected);
        }
        assert_eq!(encode_grayscale(&expected, TOTAL).unwrap(), data);
        // Grayscale is 15 bytes here; the split stream is far larger.
        assert_eq!(
            encode(&expected, TOTAL, EncodeMode::Auto).unwrap(),
            Some((TAG_GRAYSCALE, data))
        );
    }

    #[test]
    fn split_layer_of_the_corpus_round_trips() {
        let data = bytes(LAYER_SPLIT);
        assert_eq!(data.len(), 68, "the corpus split stream is 68 bytes");
        // A binary core with thirty 200-valued edge pixels at 100..130.
        let expected = mask(&[(0, 100), (200, 30), (0, 20), (255, 50), (0, 2872)]);
        for strict in [false, true] {
            let layer = decode(&data, TOTAL, strict).unwrap();
            assert_eq!(layer.tag, Some(TAG_SPLIT));
            assert_eq!(layer.pixels, expected);
        }
        // Byte equality pins the delta encoding: the first position is absolute
        // (0x64 = 100), the twenty-nine that follow are 1 apart, and exactly
        // thirty value bytes close the stream.
        assert_eq!(data[8], 0x64);
        assert!(data[9..38].iter().all(|b| *b == 0x01));
        assert!(data[38..].iter().all(|b| *b == 0xC8));
        assert_eq!(encode_split(&expected, TOTAL).unwrap(), data);
        assert_eq!(
            encode(&expected, TOTAL, EncodeMode::Split).unwrap(),
            Some((TAG_SPLIT, data))
        );
    }

    #[test]
    fn all_black_is_the_empty_layer_form() {
        assert_eq!(encode(&[0u8; 16], 16, EncodeMode::Auto).unwrap(), None);
        assert_eq!(encode(&[0u8; 16], 16, EncodeMode::Binary).unwrap(), None);
        assert_eq!(encode(&[0u8; 16], 16, EncodeMode::Split).unwrap(), None);
        assert!(DecodedLayer::empty(16).is_empty());
        // A zero-pixel layer is the empty-layer form too, and the per-tag
        // encoders refuse to invent a stream for it.
        assert_eq!(encode(&[], 0, EncodeMode::Auto).unwrap(), None);
        assert_eq!(
            encode_binary(&[], 0).unwrap_err().check(),
            Check::ReeDataSize
        );
        assert_eq!(
            encode_grayscale(&[], 0).unwrap_err().check(),
            Check::ReeDataSize
        );
        assert_eq!(
            encode_split(&[], 0).unwrap_err().check(),
            Check::ReeDataSize
        );
    }

    #[test]
    fn all_white_is_one_run() {
        let (tag, data) = encode(&[255u8; 16], 16, EncodeMode::Auto).unwrap().unwrap();
        assert_eq!(tag, TAG_BINARY);
        // tag, first_value 0xFF, run_count 1, no stored lengths.
        assert_eq!(data, vec![TAG_BINARY, 0xFF, 0x01]);
        assert_eq!(decode(&data, 16, true).unwrap().pixels, vec![255u8; 16]);
    }

    #[test]
    fn auto_picks_the_smaller_stream_and_breaks_ties_towards_grayscale() {
        // A tie on a three-pixel mask: both streams are eight bytes.
        let tie = [0u8, 128, 0];
        assert_eq!(encode_grayscale(&tie, 3).unwrap().len(), 8);
        assert_eq!(encode_split(&tie, 3).unwrap().len(), 8);
        assert_eq!(
            encode(&tie, 3, EncodeMode::Auto).unwrap().unwrap().0,
            TAG_GRAYSCALE
        );

        // A long run of distinct values: every one is a grayscale run (626
        // bytes), while the split overlay pays one delta plus one value each.
        let gradient: Vec<u8> = (1..=250u16).map(|v| v as u8).collect();
        let grayscale = encode_grayscale(&gradient, 250).unwrap();
        let split = encode_split(&gradient, 250).unwrap();
        assert!(split.len() < grayscale.len(), "{split:?} {grayscale:?}");
        let (tag, data) = encode(&gradient, 250, EncodeMode::Auto).unwrap().unwrap();
        assert_eq!(tag, TAG_SPLIT);
        assert_eq!(data, split);
        assert_eq!(decode(&data, 250, false).unwrap().pixels, gradient);

        // A hand-built gradient that is not all-binary still round-trips. The
        // two streams are 12 and 11 bytes: grayscale is tag + run_count +
        // 5 x (value + end_pos) = 1 + 1 + 10; split is tag + a three-byte
        // binary core + aa_count + 3 positions + 3 values = 1 + 3 + 1 + 3 + 3.
        let ramp = [0u8, 64, 128, 192, 255];
        assert_eq!(encode_grayscale(&ramp, 5).unwrap().len(), 12);
        assert_eq!(encode_split(&ramp, 5).unwrap().len(), 11);
        let (tag, data) = encode(&ramp, 5, EncodeMode::Auto).unwrap().unwrap();
        assert_eq!(tag, TAG_SPLIT, "split is strictly smaller here");
        assert_eq!(decode(&data, 5, false).unwrap().pixels, ramp);
    }

    #[test]
    fn binary_stripes_round_trip_all_modes() {
        let pixels = mask(&[(0, 3), (255, 2), (0, 4), (255, 1)]);
        let data = encode_binary(&pixels, 10).unwrap();
        // first_value 0, run_count 4, three stored lengths.
        assert_eq!(data, vec![TAG_BINARY, 0x00, 0x04, 3, 2, 4]);
        for strict in [false, true] {
            assert_eq!(decode(&data, 10, strict).unwrap().pixels, pixels);
        }
        assert_eq!(runs(&pixels).len(), 4);
    }

    #[test]
    fn encode_rejects_a_mask_of_the_wrong_size() {
        assert_eq!(
            encode(&[0u8; 4], 5, EncodeMode::Auto).unwrap_err().check(),
            Check::ReeDataSize
        );
        assert_eq!(
            encode_binary(&[0u8; 4], 5).unwrap_err().check(),
            Check::ReeDataSize
        );
        assert_eq!(
            encode_grayscale(&[0u8; 4], 5).unwrap_err().check(),
            Check::ReeDataSize
        );
        assert_eq!(
            encode_split(&[0u8; 4], 5).unwrap_err().check(),
            Check::ReeDataSize
        );
    }

    #[test]
    fn binary_mode_refuses_a_non_binary_mask() {
        let pixels = [0u8, 7, 255, 0];
        assert_eq!(
            encode(&pixels, 4, EncodeMode::Binary).unwrap_err().check(),
            Check::ReeFirstValue
        );
        assert_eq!(
            encode_binary(&pixels, 4).unwrap_err().check(),
            Check::ReeFirstValue
        );
        // A non-binary first pixel is the same rule.
        assert_eq!(
            encode_binary(&[7u8, 0], 2).unwrap_err().check(),
            Check::ReeFirstValue
        );
    }

    #[test]
    fn unknown_or_missing_tags_are_rejected() {
        assert_eq!(check_of(&[], 4, false), Check::ReeTag);
        assert_eq!(check_of(&[0x03, 0x00], 4, false), Check::ReeTag);
        assert_eq!(check_of(&[0xFF, 0x00], 4, true), Check::ReeTag);
        assert_eq!(check_of(&[TAG_BINARY], 4, false), Check::ReeVarint);
        assert_eq!(check_of(&[TAG_GRAYSCALE], 4, false), Check::ReeVarint);
        assert_eq!(
            check_of(&[TAG_SPLIT, TAG_BINARY, 0x01], 4, false),
            Check::ReeVarint
        );
    }

    #[test]
    fn binary_first_value_must_be_black_or_white() {
        assert_eq!(
            check_of(&[TAG_BINARY, 0x7F, 0x01], 4, false),
            Check::ReeFirstValue
        );
        assert_eq!(
            check_of(&[TAG_BINARY, 0x01, 0x01], 4, true),
            Check::ReeFirstValue
        );
    }

    #[test]
    fn run_count_zero_is_loose_only() {
        // Binary: first_value 0x00, run_count 0.
        let binary = [TAG_BINARY, 0x00, 0x00];
        assert_eq!(decode(&binary, 4, false).unwrap().pixels, vec![0u8; 4]);
        assert_eq!(check_of(&binary, 4, true), Check::ReeNoRunCountZero);
        // Accepted, and reported as using exactly the three bytes it holds.
        assert_eq!(validate_stream(&binary, 4, false), Ok(binary.len()));
        assert_eq!(
            validate_stream(&binary, 4, true).unwrap_err().check(),
            Check::ReeNoRunCountZero
        );

        // Grayscale: run_count 0.
        let grayscale = [TAG_GRAYSCALE, 0x00];
        assert_eq!(decode(&grayscale, 4, false).unwrap().pixels, vec![0u8; 4]);
        assert_eq!(check_of(&grayscale, 4, true), Check::ReeNoRunCountZero);

        // Encoders never emit it: an all-black layer has no stream at all.
        assert_eq!(encode(&[0u8; 4], 4, EncodeMode::Binary).unwrap(), None);
    }

    #[test]
    fn binary_run_lengths_split_loose_from_strict() {
        // first_value 0x00, run_count 3, stored lengths 0 and 2: the first run
        // is empty but still toggles the value.
        let empty_first = [TAG_BINARY, 0x00, 0x03, 0x00, 0x02];
        assert_eq!(
            decode(&empty_first, 4, false).unwrap().pixels,
            vec![255, 255, 0, 0]
        );
        assert_eq!(check_of(&empty_first, 4, true), Check::ReeRunLengths);

        // run_count 2 with one stored length of 4: the implicit final run is
        // empty, which loose accepts.
        let implicit_empty = [TAG_BINARY, 0x00, 0x02, 0x04];
        assert_eq!(
            decode(&implicit_empty, 4, false).unwrap().pixels,
            vec![0, 0, 0, 0]
        );
        assert_eq!(check_of(&implicit_empty, 4, true), Check::ReeRunLengths);

        // The stored lengths overshoot total_pixels, so the implicit final run
        // would be negative: both modes reject it.
        let overshoot = [TAG_BINARY, 0x00, 0x02, 0x05];
        assert_eq!(check_of(&overshoot, 4, false), Check::ReeEndPositions);
        assert_eq!(check_of(&overshoot, 4, true), Check::ReeEndPositions);

        // run_count above total_pixels + 1 is refused before anything is sized.
        let too_many = [TAG_BINARY, 0x00, 0x06];
        assert_eq!(check_of(&too_many, 4, false), Check::ReeRunLengths);
        assert_eq!(
            check_of(&[TAG_GRAYSCALE, 0x06], 4, false),
            Check::ReeRunLengths
        );

        // The canonical form is accepted by both modes.
        let canonical = [TAG_BINARY, 0x00, 0x02, 0x02];
        for strict in [false, true] {
            assert_eq!(
                decode(&canonical, 4, strict).unwrap().pixels,
                vec![0, 0, 255, 255]
            );
        }
    }

    #[test]
    fn grayscale_run_rules_split_loose_from_strict() {
        // Two adjacent runs with the same value.
        let repeated = [TAG_GRAYSCALE, 0x02, 0x00, 0x02, 0x00, 0x04];
        assert_eq!(
            decode(&repeated, 4, false).unwrap().pixels,
            vec![0, 0, 0, 0]
        );
        assert_eq!(check_of(&repeated, 4, true), Check::ReeGrayscaleRuns);

        // A zero-length run: end position 0, then 5 up to total_pixels.
        let empty_run = [TAG_GRAYSCALE, 0x02, 0x00, 0x00, 0x05, 0x04];
        assert_eq!(
            decode(&empty_run, 4, false).unwrap().pixels,
            vec![5, 5, 5, 5]
        );
        assert_eq!(check_of(&empty_run, 4, true), Check::ReeGrayscaleRuns);

        // Out of order: 3 then 2 then 4. Strict reports the grayscale rule,
        // loose the end-position rule.
        let backwards = [TAG_GRAYSCALE, 0x03, 0x00, 0x03, 0x05, 0x02, 0x07, 0x04];
        assert_eq!(check_of(&backwards, 4, false), Check::ReeEndPositions);
        assert_eq!(check_of(&backwards, 4, true), Check::ReeGrayscaleRuns);

        // The last end position must be total_pixels, in both modes.
        let short = [TAG_GRAYSCALE, 0x01, 0x00, 0x03];
        assert_eq!(check_of(&short, 4, false), Check::ReeEndPositions);
        assert_eq!(check_of(&short, 4, true), Check::ReeEndPositions);
        let past = [TAG_GRAYSCALE, 0x01, 0x00, 0x05];
        assert_eq!(check_of(&past, 4, false), Check::ReeEndPositions);
        assert_eq!(check_of(&past, 4, true), Check::ReeEndPositions);

        // Only 0x00/0xFF pixels: such a layer must use tag 0x00.
        let binary_values = [TAG_GRAYSCALE, 0x02, 0x00, 0x02, 0xFF, 0x04];
        assert_eq!(
            decode(&binary_values, 4, false).unwrap().pixels,
            vec![0, 0, 255, 255]
        );
        assert_eq!(
            check_of(&binary_values, 4, true),
            Check::ReeGrayscaleAllBinary
        );

        // The corpus grayscale stream is canonical for both modes.
        assert_eq!(
            validate_stream(&bytes(LAYER_GRAYSCALE), TOTAL, true),
            Ok(LAYER_GRAYSCALE.len() / 2)
        );
    }

    /// A canonical split stream: binary 0x0000, 0xFF00, AA 200 at 4 and 5.
    const SPLIT_TOTAL: u32 = 8;
    const SPLIT_CANONICAL: [u8; 10] = [
        TAG_SPLIT, 0x00, 0x03, 0x04, 0x02, 0x02, 0x04, 0x01, 0xC8, 0xC8,
    ];

    #[test]
    fn split_overlay_positions_are_delta_encoded() {
        let expected = [0, 0, 0, 0, 200, 200, 0, 0];
        for strict in [false, true] {
            assert_eq!(
                decode(&SPLIT_CANONICAL, SPLIT_TOTAL, strict)
                    .unwrap()
                    .pixels,
                expected
            );
        }
        assert_eq!(
            encode_split(&expected, SPLIT_TOTAL).unwrap(),
            SPLIT_CANONICAL
        );
        // The first position is absolute (4), the second a delta of 1.
        assert_eq!(&SPLIT_CANONICAL[6..8], &[0x04, 0x01]);
    }

    #[test]
    fn split_overlay_rules_are_enforced() {
        // A repeated position (delta 0) and a position at total_pixels are both
        // refused, in loose mode too.
        let repeated = [
            TAG_SPLIT, 0x00, 0x03, 0x04, 0x02, 0x02, 0x04, 0x00, 0xC8, 0xC8,
        ];
        assert_eq!(
            check_of(&repeated, SPLIT_TOTAL, false),
            Check::ReeSplitPositions
        );
        assert_eq!(
            check_of(&repeated, SPLIT_TOTAL, true),
            Check::ReeSplitPositions
        );

        let out_of_range = [
            TAG_SPLIT, 0x00, 0x03, 0x04, 0x02, 0x02, 0x08, 0x01, 0xC8, 0xC8,
        ];
        assert_eq!(
            check_of(&out_of_range, SPLIT_TOTAL, false),
            Check::ReeSplitPositions
        );

        // An overlay count above total_pixels + 1 is refused before allocating.
        let too_many = [TAG_SPLIT, 0x00, 0x01, 0x06];
        assert_eq!(check_of(&too_many, 4, false), Check::ReeSplitPositions);

        // A truncated value array.
        let short_values = [TAG_SPLIT, 0x00, 0x03, 0x04, 0x02, 0x02, 0x04, 0x01, 0xC8];
        assert_eq!(
            check_of(&short_values, SPLIT_TOTAL, false),
            Check::ReeVarint
        );

        // The overlay must hold exactly the pixels that are neither 0x00 nor
        // 0xFF, and must threshold to the binary component.
        let wrong_threshold = [
            TAG_SPLIT, 0x00, 0x03, 0x04, 0x02, 0x02, 0x04, 0x01, 0x64, 0xC8,
        ];
        assert!(decode(&wrong_threshold, SPLIT_TOTAL, false).is_ok());
        assert_eq!(
            check_of(&wrong_threshold, SPLIT_TOTAL, true),
            Check::ReeSplitThreshold
        );

        let white_overlay = [
            TAG_SPLIT, 0x00, 0x03, 0x04, 0x02, 0x02, 0x04, 0x01, 0xFF, 0xC8,
        ];
        assert_eq!(
            check_of(&white_overlay, SPLIT_TOTAL, true),
            Check::ReeSplitThreshold
        );

        // The binary component's own rules still apply.
        let non_canonical_core = [TAG_SPLIT, 0x00, 0x00, 0x00];
        assert_eq!(
            check_of(&non_canonical_core, SPLIT_TOTAL, true),
            Check::ReeNoRunCountZero
        );
        assert!(decode(&non_canonical_core, SPLIT_TOTAL, false).is_ok());
    }

    #[test]
    fn validate_stream_matches_decode() {
        assert_eq!(
            validate_stream(&bytes(LAYER_BINARY), TOTAL, true),
            Ok(LAYER_BINARY.len() / 2)
        );
        assert_eq!(
            validate_stream(&bytes(LAYER_SPLIT), TOTAL, true),
            Ok(LAYER_SPLIT.len() / 2)
        );
        assert_eq!(
            validate_stream(&[], TOTAL, false),
            Err(Error::new(
                Check::ReeTag,
                "layer mask data is empty: the empty-layer form carries no bytes"
            ))
        );
    }
}
