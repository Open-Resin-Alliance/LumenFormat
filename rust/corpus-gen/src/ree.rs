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

/// Binary REE body: first_value, run_count, K-1 run lengths.
pub fn enc_binary(runs: &[Run]) -> Vec<u8> {
    if runs.is_empty() {
        return Vec::new();
    }
    if runs.len() == 1 {
        let mut out = vec![runs[0].1];
        out.extend(varint(1));
        return out;
    }
    let first = runs[0].1;
    assert!(
        first == 0 || first == 255,
        "binary REE values must be 0x00 or 0xFF"
    );
    let mut out = vec![first];
    out.extend(varint(runs.len() as u64));
    for &(length, _) in &runs[..runs.len() - 1] {
        assert!(length >= 1);
        out.extend(varint(length as u64));
    }
    out
}

/// Grayscale REE body: run_count, then (value, end_pos) per run.
pub fn enc_grayscale(runs: &[Run]) -> Vec<u8> {
    let mut out = varint(runs.len() as u64);
    let mut pos = 0;
    for (i, &(length, value)) in runs.iter().enumerate() {
        assert!(length >= 1, "zero-length run");
        assert!(
            !(i > 0 && runs[i - 1].1 == value),
            "adjacent runs share a value"
        );
        pos += length;
        out.push(value);
        out.extend(varint(pos as u64));
    }
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
    for &position in &positions {
        out.extend(varint((position - prev) as u64));
        prev = position;
    }
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
