//! The run-length encoders the layer sectors use (spec 5.6), canonical forms only.

/// Tag byte for the binary REE form.
pub const TAG_BINARY: u8 = 0x00;
/// Tag byte for the grayscale REE form.
pub const TAG_GRAYSCALE: u8 = 0x01;
/// Tag byte for the split REE form.
pub const TAG_SPLIT: u8 = 0x02;

/// One canonical run: how many pixels, and what value.
pub type Run = (usize, u8);

/// One span: start, end (exclusive) and the value the pixels carry.
pub type Span = (usize, usize, u8);

/// A little-endian base-128 varint.
pub fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        let byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return out;
        }
    }
}

/// `PLANES` (spec 5.3.1): the four plane lengths, then the plane bytes.
///
/// A varint's byte `j` - least-significant seven bits first - is appended to plane
/// `j`, so a `k`-byte varint adds one byte to each of planes `0..k`. The four
/// lengths are written unconditionally, an empty array costing four zero bytes.
pub fn enc_planes(values: &[u64]) -> Vec<u8> {
    let mut planes: [Vec<u8>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for &value in values {
        let mut value = value;
        let mut plane = 0;
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            planes[plane].push(if value != 0 { byte | 0x80 } else { byte });
            if value == 0 {
                break;
            }
            plane += 1;
        }
    }
    let mut out = Vec::new();
    for plane in &planes {
        out.extend(varint(plane.len() as u64));
    }
    for plane in &planes {
        out.extend_from_slice(plane);
    }
    out
}

/// Canonical `(length, value)` runs covering `total` pixels.
///
/// Spans are `(start, end, value)`; pixels no span covers are black. Adjacent
/// equal values are merged, so the result alternates.
pub fn runs_from_spans(total: usize, spans: &[Span]) -> Vec<Run> {
    fn push(out: &mut Vec<Run>, length: usize, value: u8) {
        if length == 0 {
            return;
        }
        if let Some(last) = out.last_mut() {
            if last.1 == value {
                last.0 += length;
                return;
            }
        }
        out.push((length, value));
    }

    let mut events: Vec<Span> = spans.iter().copied().filter(|&(s, e, _)| e > s).collect();
    events.sort_unstable();

    let mut out = Vec::new();
    let mut pos = 0;
    for (start, end, value) in events {
        assert!(start >= pos, "overlapping spans");
        push(&mut out, start - pos, 0);
        push(&mut out, end - start, value);
        pos = end;
    }
    push(&mut out, total - pos, 0);
    out
}

/// Binary REE body: first_value, run_count, PLANES of the K-1 run lengths.
pub fn enc_binary(runs: &[Run]) -> Vec<u8> {
    if runs.is_empty() {
        return Vec::new();
    }
    if runs.len() == 1 {
        let mut out = vec![runs[0].1];
        out.extend(varint(1));
        out.extend(enc_planes(&[]));
        return out;
    }
    let first = runs[0].1;
    assert!(
        first == 0 || first == 255,
        "binary REE values must be 0x00 or 0xFF"
    );
    let mut out = vec![first];
    out.extend(varint(runs.len() as u64));
    let lengths: Vec<u64> = runs[..runs.len() - 1]
        .iter()
        .map(|&(length, _)| {
            assert!(length >= 1);
            length as u64
        })
        .collect();
    out.extend(enc_planes(&lengths));
    out
}

/// Grayscale REE body: run_count, the value of every run, then PLANES of the K-1
/// run lengths. The last run ends at `total_pixels`, which the reader knows.
pub fn enc_grayscale(runs: &[Run]) -> Vec<u8> {
    let mut out = varint(runs.len() as u64);
    for (i, &(length, value)) in runs.iter().enumerate() {
        assert!(length >= 1, "zero-length run");
        assert!(
            !(i > 0 && runs[i - 1].1 == value),
            "adjacent runs share a value"
        );
        out.push(value);
    }
    let lengths: Vec<u64> = runs[..runs.len() - 1]
        .iter()
        .map(|&(length, _)| length as u64)
        .collect();
    out.extend(enc_planes(&lengths));
    out
}

/// Positions and values of the non-0x00/0xFF pixels, in index order.
pub fn split_overlay(runs: &[Run]) -> (Vec<usize>, Vec<u8>) {
    let mut positions = Vec::new();
    let mut values = Vec::new();
    let mut pos = 0;
    for &(length, value) in runs {
        if value != 0 && value != 255 {
            positions.extend(pos..pos + length);
            values.resize(values.len() + length, value);
        }
        pos += length;
    }
    (positions, values)
}

/// Split REE body: binary REE over the thresholded mask, then the AA overlay.
pub fn enc_split(runs: &[Run]) -> Vec<u8> {
    let mut thresholded: Vec<Run> = Vec::new();
    for &(length, value) in runs {
        let bit = if value >= 128 { 255 } else { 0 };
        match thresholded.last_mut() {
            Some(last) if last.1 == bit => last.0 += length,
            _ => thresholded.push((length, bit)),
        }
    }

    let (positions, values) = split_overlay(runs);
    let mut out = enc_binary(&thresholded);
    out.extend(varint(positions.len() as u64));
    let mut prev = 0;
    let mut deltas: Vec<u64> = Vec::with_capacity(positions.len());
    for &position in &positions {
        deltas.push((position - prev) as u64);
        prev = position;
    }
    out.extend(enc_planes(&deltas));
    out.extend_from_slice(&values);
    out
}

/// Canonical tag choice (spec 5.6). `None` means the empty-layer form.
pub fn pick_tag(runs: &[Run], prefer_split: bool) -> Option<u8> {
    if runs.iter().all(|&(_, value)| value == 0) {
        return None;
    }
    if runs.iter().all(|&(_, value)| value == 0 || value == 255) {
        return Some(TAG_BINARY);
    }
    Some(if prefer_split {
        TAG_SPLIT
    } else {
        TAG_GRAYSCALE
    })
}

/// Encoded sector body (tag + mask data), or `None` for an empty sector.
pub fn encode_sector(runs: &[Run], prefer_split: bool) -> Option<Vec<u8>> {
    match pick_tag(runs, prefer_split)? {
        TAG_BINARY => {
            let mut out = vec![TAG_BINARY];
            out.extend(enc_binary(runs));
            Some(out)
        }
        TAG_GRAYSCALE => {
            let mut out = vec![TAG_GRAYSCALE];
            out.extend(enc_grayscale(runs));
            Some(out)
        }
        _ => {
            let mut out = vec![TAG_SPLIT];
            out.extend(enc_split(runs));
            Some(out)
        }
    }
}

/// Encoded sector body under tag 0x02 whatever the mask holds, or `None` for an
/// empty sector.
///
/// [`pick_tag`] gives an all-`0x00`/`0xFF` mask tag 0x00, so this is the only way
/// to write the one stream shape that tag cannot carry: a split whose overlay is
/// empty, whose `aa_positions` are still `PLANES(0)` - four zero lengths. The
/// stream is decodable and no rule refuses it, but spec 5.6's tag choice keeps it
/// out of the canonical form; the vector that uses it says so.
pub fn encode_sector_split(runs: &[Run]) -> Option<Vec<u8>> {
    if runs.iter().all(|&(_, value)| value == 0) {
        return None;
    }
    let mut out = vec![TAG_SPLIT];
    out.extend(enc_split(runs));
    Some(out)
}
