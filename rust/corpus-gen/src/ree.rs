//! The run-length encoders the layer sectors use (spec 5.7), canonical forms only.

/// Tag byte for the binary REE form.
pub const TAG_BINARY: u8 = 0x00;
/// Tag byte for the grayscale REE form.
pub const TAG_GRAYSCALE: u8 = 0x01;
/// Tag byte for the split REE form.
pub const TAG_SPLIT: u8 = 0x02;
/// Tag byte for the attached REE form.
pub const TAG_ATTACHED: u8 = 0x03;

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

/// The thresholded core of `runs`: one run per stretch whose pixels threshold
/// the same way, so its runs alternate in value (spec 5.5, 5.6).
///
/// A pixel belongs to the core for the value it thresholds to - `0xFF` at 128 and
/// above - and mask runs the threshold cannot tell apart merge into one core run.
/// The core is therefore a lossy reading of the mask, and the overlay is what
/// describes the difference.
fn core_runs(runs: &[Run]) -> Vec<Run> {
    let mut core: Vec<Run> = Vec::new();
    for &(length, value) in runs {
        let bit = if value >= 128 { 255 } else { 0 };
        match core.last_mut() {
            Some(last) if last.1 == bit => last.0 += length,
            _ => core.push((length, bit)),
        }
    }
    core
}

/// Split REE body: binary REE over the thresholded mask, then the AA overlay.
pub fn enc_split(runs: &[Run]) -> Vec<u8> {
    let thresholded = core_runs(runs);

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

/// One attached stream's fields, before they are laid out (spec 5.6).
///
/// Three of them are stored and the fourth is not. The core is a run array whose
/// lengths are stored parity by parity; the attachment bits describe the two
/// pixels at each of its runs' ends, because a run's end pixel is the one pixel
/// no other run can describe; the escapes carry the positions of the anti-aliased
/// pixels the bits cannot, which is what costs an entry each. The walk is the
/// order the reader visits those pixels in and needs no storing at all: run by
/// run it is the bit's pixel, then the escapes inside that run, then the bit's
/// other pixel, which is pixel order - so the only thing left to write down is
/// each of their values.
struct Attached {
    core: Vec<Run>,
    /// Per core run: whether its first and whether its last pixel is anti-aliased.
    first: Vec<bool>,
    last: Vec<bool>,
    /// The escapes: absolute positions of anti-aliased pixels no attachment bit
    /// expresses, strictly increasing and each strictly inside its run.
    escapes: Vec<usize>,
    /// The walk: every anti-aliased pixel's position and value, in pixel order.
    walk: Vec<(usize, u8)>,
}

/// Read `runs` into the fields an attached stream stores.
///
/// A run's end pixel is the one a bit describes, and every other anti-aliased
/// pixel of the run has to be positioned instead. A run of one pixel is both of
/// its ends at once, so it takes the first bit and leaves the second clear: one
/// pixel is described once.
fn plan_attached(runs: &[Run]) -> Attached {
    let core = core_runs(runs);
    assert!(!core.is_empty(), "an attached stream carries a core");

    let (positions, values) = split_overlay(runs);
    let walk: Vec<(usize, u8)> = positions.into_iter().zip(values).collect();

    let mut first = vec![false; core.len()];
    let mut last = vec![false; core.len()];
    let mut escapes = Vec::new();
    let mut run = 0;
    let mut start = 0;
    for &(index, _) in &walk {
        while index >= start + core[run].0 {
            start += core[run].0;
            run += 1;
        }
        if index == start {
            first[run] = true;
        } else if index == start + core[run].0 - 1 {
            last[run] = true;
        } else {
            escapes.push(index);
        }
    }

    Attached {
        core,
        first,
        last,
        escapes,
        walk,
    }
}

/// The pixel core run `run` starts at.
fn run_start(core: &[Run], run: usize) -> usize {
    core[..run].iter().map(|&(length, _)| length).sum()
}

/// The core run the pixel at `position` belongs to.
fn run_of(core: &[Run], position: usize) -> usize {
    let mut start = 0;
    for (run, &(length, _)) in core.iter().enumerate() {
        if position < start + length {
            return run;
        }
        start += length;
    }
    unreachable!("a walk pixel lies inside the core")
}

/// Where the pixel at `position` sits in the walk.
fn walk_at(walk: &[(usize, u8)], position: usize) -> usize {
    walk.iter()
        .position(|&(index, _)| index == position)
        .expect("the walk holds every anti-aliased pixel once")
}

/// The attachment bits: two per core run, run `r` in byte `r >> 2`, its first
/// pixel's bit below its last pixel's.
///
/// The array is a whole byte at a time, so a mask with one run still carries one
/// byte, and the bits no run reaches stay clear. A stream that sets one of them
/// names a run the core does not have.
fn attach_bits(first: &[bool], last: &[bool]) -> Vec<u8> {
    let mut bits = vec![0u8; first.len().div_ceil(4)];
    for (run, (&first, &last)) in first.iter().zip(last).enumerate() {
        let shift = (run & 3) * 2;
        bits[run >> 2] |= u8::from(first) << shift | u8::from(last) << (shift + 1);
    }
    bits
}

/// `zigzag` (spec 5.2): a signed difference as one non-negative integer, small
/// magnitudes first, so a difference of -1 and one of +1 both stay inside one
/// byte's seven bits. Both of the attached form's differences - a run length
/// against the run of its own parity two earlier, an overlay value against its
/// neighbour - are signed as often as not, and a reader undoes this with the
/// `unzigzag` that pairs with it.
fn zigzag(value: i64) -> u64 {
    ((value as u64) << 1) ^ ((value >> 63) as u64)
}

/// Lay an attached stream's fields out, the tag byte aside.
///
/// `first_entry` overrides the first entry of `aa_values`, which is the one
/// shape [`AttachedDefect::ValueNotByte`] needs: an entry stored as a value and
/// wider than a byte.
fn write_attached(attached: &Attached, first_entry: Option<u64>) -> Vec<u8> {
    let core = &attached.core;
    let mut out = vec![core[0].1];
    out.extend(varint(core.len() as u64));

    // The lengths are stored without the last run's, which ends at total_pixels,
    // and each parity differences against itself: a run's length sits close to
    // the length of the run carrying its own value two along, and far from the
    // run in between, which is the run of the other value.
    let mut even: Vec<u64> = Vec::new();
    let mut odd: Vec<u64> = Vec::new();
    for index in 0..core.len() - 1 {
        let length = core[index].0 as i64;
        let stored = if index < 2 {
            length as u64
        } else {
            zigzag(length - core[index - 2].0 as i64)
        };
        if index % 2 == 0 {
            even.push(stored);
        } else {
            odd.push(stored);
        }
    }
    out.extend(enc_planes(&even));
    out.extend(enc_planes(&odd));

    out.extend(varint(attached.walk.len() as u64));
    out.extend(attach_bits(&attached.first, &attached.last));

    let mut previous = 0;
    let mut deltas = Vec::with_capacity(attached.escapes.len());
    for &escape in &attached.escapes {
        deltas.push((escape - previous) as u64);
        previous = escape;
    }
    out.extend(varint(attached.escapes.len() as u64));
    out.extend(enc_planes(&deltas));

    // The values are first differences too, and a walk is a ramp per edge - the
    // same value along a band, then one step - so they are small. The first is
    // stored as itself: a value is a byte, and a difference from nothing is not.
    let mut previous = 0u8;
    let mut values = Vec::with_capacity(attached.walk.len());
    for (index, &(_, value)) in attached.walk.iter().enumerate() {
        values.push(if index == 0 {
            first_entry.unwrap_or(value as u64)
        } else {
            zigzag(value as i64 - previous as i64)
        });
        previous = value;
    }
    out.extend(enc_planes(&values));

    out
}

/// Attached REE body: the parity-split core's lengths, its attachment bits, the
/// escape positions and the overlay values in walk order.
pub fn enc_attached(runs: &[Run]) -> Vec<u8> {
    write_attached(&plan_attached(runs), None)
}

/// The one defect an attached stream can deliberately carry.
///
/// Each of them is a shape the canonical encoder never writes, so a vector asks
/// for one here and writes a mask whose first suitable core run is where the
/// defect lands. The one that does not find its shape is a loud failure rather
/// than a vector that pins nothing.
#[derive(Clone, Copy)]
pub enum AttachedDefect {
    /// The anti-aliased pixel a core run opens on is written as an escape at that
    /// run's first pixel, where an escape has to be strictly inside its run.
    EscapeAtRunStart,
    /// One escape repeats the position before it, so the escapes do not strictly
    /// increase.
    EscapeRepeat,
    /// The stream counts one pixel fewer than its attachment bits and escapes
    /// place.
    CountShort,
    /// The first overlay value is stored in two bytes, where an overlay value is
    /// a byte.
    ValueNotByte,
    /// A core run of one pixel, whose only pixel is anti-aliased, sets both of its
    /// attachment bits, so both describe that single pixel.
    SinglePixelBothBits,
    /// The first overlay value is 0x00, which is not an anti-aliased value.
    ValueBinary,
    /// The first overlay value thresholds to the other value than the core run it
    /// sits in.
    ValueOtherSide,
}

/// Attached REE body with `defect` written into it.
pub fn enc_attached_defect(runs: &[Run], defect: AttachedDefect) -> Vec<u8> {
    let mut attached = plan_attached(runs);
    let mut first_entry = None;
    match defect {
        AttachedDefect::EscapeAtRunStart => {
            // A run of one pixel has no second pixel to be its last, so the pixel
            // this moves off the bits needs a run that is longer than one.
            let run = (0..attached.core.len())
                .find(|&run| attached.first[run] && attached.core[run].0 > 1)
                .expect("a core run that opens on an anti-aliased pixel");
            let start = run_start(&attached.core, run);
            attached.first[run] = false;
            let at = attached.escapes.partition_point(|&escape| escape < start);
            attached.escapes.insert(at, start);
        }
        AttachedDefect::EscapeRepeat => {
            // The repeated position is still strictly inside its run, and the walk
            // grows with the escape list: a stream that failed the count instead
            // would pin the wrong rule.
            let escape = attached
                .escapes
                .first()
                .copied()
                .expect("an escape strictly inside a run");
            attached.escapes.insert(1, escape);
            let at = walk_at(&attached.walk, escape);
            let pixel = attached.walk[at];
            attached.walk.insert(at + 1, pixel);
        }
        AttachedDefect::CountShort => {
            // One pixel the bits and escapes place goes uncounted, so the count
            // and the walk disagree and nothing else does.
            attached
                .walk
                .pop()
                .expect("an anti-aliased pixel to leave out");
        }
        AttachedDefect::ValueNotByte => {
            // Only the first entry is stored as a value; every later one is a
            // difference, which the planes may spread over several bytes.
            first_entry = Some(0x100);
        }
        AttachedDefect::SinglePixelBothBits => {
            let run = (0..attached.core.len())
                .find(|&run| attached.core[run].0 == 1 && attached.first[run])
                .expect("a core run of one anti-aliased pixel");
            let start = run_start(&attached.core, run);
            attached.last[run] = true;
            // Both bits place that pixel, so the walk gains it a second time.
            let at = walk_at(&attached.walk, start);
            let pixel = attached.walk[at];
            attached.walk.insert(at + 1, pixel);
        }
        AttachedDefect::ValueBinary => {
            // The value has to be wrong for one reason only, so the run the pixel
            // sits in has to be black: 0x00 thresholds to it.
            let run = run_of(&attached.core, attached.walk[0].0);
            assert_eq!(
                attached.core[run].1, 0,
                "the first overlay pixel sits in a black core run"
            );
            attached.walk[0].1 = 0x00;
        }
        AttachedDefect::ValueOtherSide => {
            // 0x40 thresholds to 0x00, so the run the pixel sits in has to be
            // white for the value to threshold to the other value.
            let run = run_of(&attached.core, attached.walk[0].0);
            assert_eq!(
                attached.core[run].1, 255,
                "the first overlay pixel sits in a white core run"
            );
            attached.walk[0].1 = 0x40;
        }
    }
    write_attached(&attached, first_entry)
}

/// Canonical tag choice (spec 5.7). `None` means the empty-layer form.
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
/// stream is decodable and no rule refuses it, but spec 5.7's tag choice keeps it
/// out of the canonical form; the vector that uses it says so.
pub fn encode_sector_split(runs: &[Run]) -> Option<Vec<u8>> {
    if runs.iter().all(|&(_, value)| value == 0) {
        return None;
    }
    let mut out = vec![TAG_SPLIT];
    out.extend(enc_split(runs));
    Some(out)
}

/// Encoded sector body under tag 0x03 whatever the mask holds, or `None` for an
/// empty sector.
///
/// Which of tags 0x00, 0x01, 0x02 and 0x03 a mask is written under is the
/// encoder's to pick (spec 5.7), and [`pick_tag`] picks the first three only: a
/// mask whose pixels are all `0x00`/`0xFF` takes tag 0x00, and any other mask
/// takes 0x01 or 0x02. Both are canonical, so a vector that pins the attached
/// form has to ask for it rather than expect the choice to fall on it.
pub fn encode_sector_attached(runs: &[Run]) -> Option<Vec<u8>> {
    if runs.iter().all(|&(_, value)| value == 0) {
        return None;
    }
    let mut out = vec![TAG_ATTACHED];
    out.extend(enc_attached(runs));
    Some(out)
}

/// Encoded sector body under tag 0x03 with `defect` written into it, or `None`
/// for an empty sector.
pub fn encode_sector_attached_defect(runs: &[Run], defect: AttachedDefect) -> Option<Vec<u8>> {
    if runs.iter().all(|&(_, value)| value == 0) {
        return None;
    }
    let mut out = vec![TAG_ATTACHED];
    out.extend(enc_attached_defect(runs, defect));
    Some(out)
}
