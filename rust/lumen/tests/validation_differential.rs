//! The differential test for the mask-free stream walk.
//!
//! Section 11.3's per-slice checks used to be a side effect of decoding a slice:
//! the validator called [`lumen::ree::validate_stream`], which was
//! `decode_counted` with the mask thrown away. On a 16K layer that mask is 94 MB
//! per slice, and the checks need none of it - coverage, the first value, the
//! run-value rules, the split threshold, the plane layout and the stream's extent
//! are all properties of the bytes.
//!
//! `old` below is that implementation as it stood, kept as the oracle: the walk
//! must return what it returned, check id, message and byte count included, and
//! the mask [`lumen::ree::decode`] returns must not have moved either. The cases
//! are every slice the corpus stores, and the small masks and one-byte changes
//! that reach the shapes the corpus does not.

use lumen::ree;
use lumen::{EncodeMode, LumenFile};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The validating implementation this rewrite replaced, copied verbatim.
///
/// `Reader` is the crate's bounds-checked cursor and is not part of the rewrite,
/// so the copy borrows it; everything the copy does with the bytes it reads is
/// the code that was removed.
mod old {
    use lumen::io::Reader;
    use lumen::{Check, DecodedLayer, Error, Result};

    const TAG_BINARY: u8 = 0x00;
    const TAG_GRAYSCALE: u8 = 0x01;
    const TAG_SPLIT: u8 = 0x02;
    const PLANES: usize = 4;

    /// The binary threshold of section 5.5: `255 if v >= 128 else 0`.
    fn threshold(pixel: u8) -> u8 {
        if pixel >= 128 {
            255
        } else {
            0
        }
    }

    pub fn decode(data: &[u8], total_pixels: u32, strict: bool) -> Result<DecodedLayer> {
        decode_counted(data, total_pixels, strict).map(|(layer, _)| layer)
    }

    pub fn validate_stream(data: &[u8], total_pixels: u32, strict: bool) -> Result<usize> {
        decode_counted(data, total_pixels, strict).map(|(_, len)| len)
    }

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

    fn fill(mask: &mut [u8], start: u64, end: u64, value: u8) {
        mask[start as usize..end as usize].fill(value);
    }

    struct Planes<'a> {
        planes: [&'a [u8]; PLANES],
        at: [usize; PLANES],
    }

    impl<'a> Planes<'a> {
        fn read(reader: &mut Reader<'a>, strict: bool) -> Result<Planes<'a>> {
            let mut lengths = [0usize; PLANES];
            for (plane, length) in lengths.iter_mut().enumerate() {
                let value = reader.varint()?;
                *length = usize::try_from(value).map_err(|_| {
                    Error::new(
                        Check::ReePlanes,
                        format!("plane {plane} length {value} does not fit in memory"),
                    )
                })?;
            }
            if strict {
                for plane in 1..PLANES {
                    if lengths[plane] > 0 && lengths[plane - 1] == 0 {
                        return Err(Error::new(
                            Check::ReePlanes,
                            format!(
                                "plane {plane} holds {} bytes after empty plane {}: the planes are \
                                 not prefix-closed",
                                lengths[plane],
                                plane - 1
                            ),
                        ));
                    }
                }
            }
            let mut planes = [&[][..]; PLANES];
            for (plane, length) in planes.iter_mut().zip(lengths) {
                *plane = reader.bytes(length)?;
            }
            Ok(Planes {
                planes,
                at: [0; PLANES],
            })
        }

        fn next(&mut self) -> Result<Option<u64>> {
            if self.at[0] == self.planes[0].len() {
                return Ok(None);
            }
            let mut value = 0u64;
            for plane in 0..PLANES {
                let Some(&byte) = self.planes[plane].get(self.at[plane]) else {
                    return Err(Error::new(
                        Check::ReeVarint,
                        format!("a varint continues into plane {plane}, which holds no more bytes"),
                    ));
                };
                self.at[plane] += 1;
                value |= u64::from(byte & 0x7F) << (7 * plane);
                if byte & 0x80 == 0 {
                    if plane > 0 && byte == 0 {
                        return Err(Error::new(
                            Check::ReeVarint,
                            "a varint crossing planes is not minimally encoded",
                        ));
                    }
                    return Ok(Some(value));
                }
            }
            Err(Error::new(
                Check::ReeVarint,
                "a varint continues past plane 3, which is the last plane",
            ))
        }

        fn varint(&mut self) -> Result<u64> {
            self.next()?.ok_or_else(|| {
                Error::new(
                    Check::ReeVarint,
                    "the planes hold fewer varints than the stream's count",
                )
            })
        }

        fn check_consumed(&self) -> Result<()> {
            for plane in 0..PLANES {
                let len = self.planes[plane].len();
                if self.at[plane] != len {
                    return Err(Error::new(
                        Check::ReePlanes,
                        format!(
                            "plane {plane} holds {len} bytes, {} of which describe a varint",
                            self.at[plane]
                        ),
                    ));
                }
            }
            Ok(())
        }
    }

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

        // The first `run_count - 1` run lengths; the last run ends at `total_pixels`.
        let mut planes = Planes::read(reader, strict)?;
        let mut mask = vec![0u8; total_pixels as usize];
        let mut value = first_value;
        let mut start = 0u64;
        let mut empty_run = false;
        for i in 0..run_count - 1 {
            let delta = planes.varint()?;
            let end = start.checked_add(delta).ok_or_else(|| {
                Error::new(Check::ReeEndPositions, "binary REE run lengths overflow")
            })?;
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
        empty_run |= start == total;
        fill(&mut mask, start, total, value);
        if strict {
            if empty_run {
                return Err(Error::new(
                    Check::ReeRunLengths,
                    "binary REE stores an empty run",
                ));
            }
            planes.check_consumed()?;
        }
        Ok(mask)
    }

    fn decode_grayscale(
        reader: &mut Reader<'_>,
        total_pixels: u32,
        strict: bool,
    ) -> Result<Vec<u8>> {
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

        // The values are hoisted out of the run loop, one byte per run.
        let values = reader.bytes(run_count as usize)?;
        // The first `run_count - 1` run lengths; the last run ends at `total_pixels`.
        let mut planes = Planes::read(reader, strict)?;
        let mut mask = vec![0u8; total_pixels as usize];
        let mut start = 0u64;
        let mut previous: Option<u8> = None;
        let mut empty_run = false;
        for (i, &value) in values[..values.len() - 1].iter().enumerate() {
            let length = planes.varint()?;
            empty_run |= length == 0;
            let end = start.checked_add(length).ok_or_else(|| {
                Error::new(Check::ReeEndPositions, "grayscale REE run lengths overflow")
            })?;
            if end > total {
                return Err(Error::new(
                    Check::ReeEndPositions,
                    format!("grayscale REE run {i} ends at {end}, past total_pixels {total}"),
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

        let value = values[values.len() - 1];
        empty_run |= start == total;
        if strict && previous == Some(value) {
            return Err(Error::new(
                Check::ReeGrayscaleRuns,
                format!("grayscale REE repeats value 0x{value:02X} in adjacent runs"),
            ));
        }
        fill(&mut mask, start, total, value);
        if strict {
            if empty_run {
                return Err(Error::new(
                    Check::ReeGrayscaleRuns,
                    "grayscale REE stores a zero-length run",
                ));
            }
            planes.check_consumed()?;
            if mask.iter().all(|p| *p == 0x00 || *p == 0xFF) {
                return Err(Error::new(
                    Check::ReeGrayscaleAllBinary,
                    "grayscale REE holds only 0x00/0xFF pixels; such a layer must use tag 0x00",
                ));
            }
        }
        Ok(mask)
    }

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
        // The positions are stored as planes, then the values as one byte each.
        let mut planes = Planes::read(reader, strict)?;
        let count = aa_count as usize;
        let values = reader.bytes(count)?;

        let mut positions: Vec<u32> = Vec::with_capacity(count);
        let mut position = 0u64;
        for i in 0..count {
            let delta = planes.varint()?;
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
        if strict {
            planes.check_consumed()?;
            for (i, &pixel) in positions.iter().enumerate() {
                let value = values[i];
                let binary = mask[pixel as usize];
                if value == 0x00 || value == 0xFF || threshold(value) != binary {
                    return Err(Error::new(
                        Check::ReeSplitThreshold,
                        format!(
                            "split overlay pixel {pixel} holds 0x{value:02X} over binary \
                             0x{binary:02X}"
                        ),
                    ));
                }
            }
        }
        for (i, &pixel) in positions.iter().enumerate() {
            mask[pixel as usize] = values[i];
        }
        if strict && mask.iter().all(|p| *p == 0x00 || *p == 0xFF) {
            return Err(Error::new(
                Check::ReeSplitAllBinary,
                "split REE holds only 0x00/0xFF pixels: it has no anti-aliasing to overlay, \
                 and such a layer must use tag 0x00",
            ));
        }
        Ok(mask)
    }
}

/// The corpus' own list of the vectors it holds.
#[derive(Deserialize)]
struct Manifest {
    valid: Vec<Entry>,
    invalid: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    file: String,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

/// One stream: what it is called, the bytes it holds, and the layer's pixel
/// count.
struct Base {
    name: String,
    data: Vec<u8>,
    total_pixels: u32,
}

/// A case is a base stream, or one byte of it changed.
///
/// The bytes of a case are built from the base when they are needed - a
/// truncation is a slice of it - so a run that compares a hundred thousand of
/// them allocates almost nothing per case.
#[derive(Clone, Copy, Debug)]
enum Change {
    /// The stream itself.
    Stream,
    /// Its first `n` bytes.
    Truncated(usize),
    /// The stream with byte `at` set to `byte`.
    Replaced(usize, u8),
}

/// The bytes a case names, borrowing `scratch` for the one case that has to
/// build them.
fn case_bytes<'a>(base: &'a Base, change: Change, scratch: &'a mut Vec<u8>) -> &'a [u8] {
    match change {
        Change::Stream => &base.data,
        Change::Truncated(length) => &base.data[..length],
        Change::Replaced(at, byte) => {
            scratch.clear();
            scratch.extend_from_slice(&base.data);
            scratch[at] = byte;
            scratch
        }
    }
}

/// What the run reached, so the test shows the shapes its cases cover rather
/// than assuming they are covered.
#[derive(Default)]
struct Seen {
    /// Streams compared: two per case, one per validation level.
    compared: usize,
    /// Streams both implementations accepted.
    accepted: usize,
    /// Every check the streams failed, and how many streams failed it.
    checks: BTreeMap<&'static str, usize>,
}

/// Compare the walk with the implementation it replaced over one stream, and the
/// mask a decoder returns with the mask it returned.
///
/// The comparison is over the whole `Result`, so a check id, its message and the
/// bytes a stream used all have to match.
fn compare(base: &Base, change: Change, scratch: &mut Vec<u8>, seen: &mut Seen) {
    let data = case_bytes(base, change, scratch);
    let total = base.total_pixels;
    for strict in [false, true] {
        match (
            old::validate_stream(data, total, strict),
            ree::validate_stream(data, total, strict),
        ) {
            (Ok(expected), Ok(got)) => {
                assert_eq!(
                    expected, got,
                    "{} ({change:?}) at strict = {strict}: bytes used",
                    base.name
                );
                seen.accepted += 1;
            }
            (Err(expected), Err(got)) => {
                assert_eq!(
                    expected, got,
                    "{} ({change:?}) at strict = {strict}: the check and its message",
                    base.name
                );
                *seen.checks.entry(expected.check_name()).or_default() += 1;
            }
            (expected, got) => panic!(
                "{} ({change:?}) at strict = {strict}: the walk says {got:?}, the implementation \
                 it replaced said {expected:?}",
                base.name
            ),
        }
        let expected = old::decode(data, total, strict);
        let got = ree::decode(data, total, strict);
        assert!(
            expected == got,
            "{} ({change:?}) at strict = {strict}: the mask {got:?} is not the mask the \
             implementation it replaced returned, {expected:?}",
            base.name
        );
        seen.compared += 1;
    }
}

/// Every slice of every vector the corpus stores.
///
/// A vector whose container does not parse, or whose `LAYR` frame does not
/// open, contributes no slice: there is no stream to compare. The counts say how
/// many did.
fn corpus_streams() -> Corpus {
    let dir = vectors_dir();
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json")).unwrap_or_else(|_| {
            panic!(
                "no conformance corpus at {}.\n\
                 The corpus lives beside the specification, not inside this crate: run this test \
                 from a checkout of https://github.com/Open-Resin-Alliance/LumenFormat.",
                dir.display()
            )
        }),
    )
    .expect("the corpus manifest must parse");

    let mut found = Corpus::default();
    for entry in manifest.valid.iter().chain(manifest.invalid.iter()) {
        found.vectors += 1;
        let bytes = std::fs::read(dir.join(&entry.file)).expect("a readable vector");
        // A vector whose framing is the defect has no readable container, and
        // one whose frames are corrupt has no readable slice: neither has a
        // stream for this walk to be compared on.
        let Ok(opened) = LumenFile::open_unvalidated(&bytes) else {
            found.unreadable += 1;
            continue;
        };
        let total_pixels = opened.total_pixels();
        let mut slices = 0usize;
        for layer in 0..opened.layer_count() {
            for layer_entry in opened.layer_table().layer_entries(layer) {
                if layer_entry.is_empty() {
                    continue;
                }
                let Ok(chunk) = opened.layr_chunk_data(layer_entry.first_layr) else {
                    continue;
                };
                let start = layer_entry.data_offset as usize;
                let end = start + layer_entry.data_size as usize;
                let Some(slice) = chunk.get(start..end) else {
                    continue;
                };
                found.streams.push(Base {
                    name: format!(
                        "{} layer {layer} sector {}",
                        entry.file, layer_entry.sector_id
                    ),
                    data: slice.to_vec(),
                    total_pixels,
                });
                slices += 1;
            }
        }
        if slices == 0 {
            found.unreadable += 1;
        }
        found.slices += slices;
    }
    found
}

/// What the corpus walk found.
#[derive(Default)]
struct Corpus {
    streams: Vec<Base>,
    /// Vectors the manifest lists.
    vectors: usize,
    /// Slices read out of them.
    slices: usize,
    /// Vectors with no readable slice.
    unreadable: usize,
}

/// Every small mask, under every tag that can represent it: the shapes the
/// corpus' handful of masks do not reach - one run, an empty overlay, an
/// anti-aliased pixel at position 0, a value below the threshold, a value that
/// merges with its neighbour, an all-black layer with no stream at all.
fn mask_streams() -> Vec<Base> {
    /// Values either side of the threshold and both binary ends.
    const ALPHABET: [u8; 4] = [0x00, 0x40, 0x80, 0xFF];
    let mut bases = Vec::new();
    for total in 0u32..=4 {
        let mut pixels = vec![0u8; total as usize];
        for index in 0..ALPHABET.len().pow(total) {
            let mut rest = index;
            for pixel in pixels.iter_mut() {
                *pixel = ALPHABET[rest % ALPHABET.len()];
                rest /= ALPHABET.len();
            }
            for mode in [EncodeMode::Binary, EncodeMode::Grayscale, EncodeMode::Split] {
                let Ok(Some((_, data))) = ree::encode(&pixels, total, mode) else {
                    continue;
                };
                bases.push(Base {
                    name: format!("mask {pixels:?} as {mode:?}"),
                    data,
                    total_pixels: total,
                });
            }
        }
    }
    bases
}

/// A stream and every one-byte change to it.
///
/// The corpus is far too small to reach the shapes a malformed stream can take,
/// and a walk that reads a stream differently from a decoder usually differs by
/// one byte. Truncating at every length and putting a value the format gives a
/// meaning to in every position reaches a length that overshoots, a plane that is
/// not prefix-closed, an overlay position at `total_pixels`, a repeated position,
/// a varint that does not terminate and a non-minimal one.
fn variations(data: &[u8]) -> Vec<Change> {
    /// The two tags that need a value to carry them, both binary ends, a value
    /// either side of the threshold, and a continuation bit.
    const BYTES: [u8; 5] = [0x00, 0x01, 0x7F, 0x80, 0xFF];
    let mut changes = vec![Change::Stream];
    changes.extend((0..data.len()).map(Change::Truncated));
    for (at, current) in data.iter().enumerate() {
        for byte in BYTES {
            if byte != *current {
                changes.push(Change::Replaced(at, byte));
            }
        }
    }
    changes
}

#[test]
fn the_walk_matches_the_decoder_it_replaced() {
    let corpus = corpus_streams();
    let masks = mask_streams();
    let mut scratch = Vec::new();
    let mut seen = Seen::default();

    for base in &corpus.streams {
        compare(base, Change::Stream, &mut scratch, &mut seen);
    }

    let mut generated = 0usize;
    for base in &masks {
        for change in variations(&base.data) {
            compare(base, change, &mut scratch, &mut seen);
            generated += 1;
        }
    }

    println!(
        "{} streams compared: {} corpus slices over {} vectors ({} carry no readable slice) and \
         {generated} streams the corpus does not reach, built from {} encoded masks by truncating \
         each and changing every byte. {} accepted, {} refused: {}",
        seen.compared,
        corpus.slices,
        corpus.vectors,
        corpus.unreadable,
        masks.len(),
        seen.accepted,
        seen.compared - seen.accepted,
        seen.checks
            .iter()
            .map(|(check, count)| format!("{check} {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    assert!(
        corpus.slices >= 13,
        "the corpus' valid vectors alone carry more than {} slices",
        corpus.slices
    );
    assert!(
        generated > 10_000,
        "the generated cases are the ones that reach the shapes a corpus cannot"
    );
    // Every rule the walk decides has to be reached by the cases: a stream of
    // mutation cases that never makes `ree.split_threshold` fire would pass this
    // test without testing it.
    for check in [
        "ree.tag",
        "ree.varint",
        "ree.first_value",
        "ree.no_run_count_zero",
        "ree.run_lengths",
        "ree.end_positions",
        "ree.grayscale_runs",
        "ree.grayscale_all_binary",
        "ree.split_positions",
        "ree.split_threshold",
        "ree.split_all_binary",
        "ree.planes",
    ] {
        assert!(
            seen.checks.contains_key(check),
            "no case reached {check}: {:?}",
            seen.checks
        );
    }
}
