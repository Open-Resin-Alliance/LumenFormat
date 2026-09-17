//! The four run-length encodings of §5, and the violations each can carry.
//!
//! A decoder either produces a mask plus the list of violations it found, or
//! fails outright - and the two are different verdicts. A violation is reported
//! under its own check name; a failure means the stream could not be read at
//! all, and names the rule the stream ran out against - `ree.data_size` when
//! the slice was too short, `ree.varint` when a varint is not well formed,
//! `ree.end_positions`, `ree.split_positions` or `ree.attach_positions` when a
//! position it decoded lands outside the layer, and `ree.attach_count` when the
//! attached form's overlay describes a number of pixels other than the one it
//! declares, or a value no mask byte can carry. Keeping the two apart is what
//! lets the corpus assert that one specific rule was broken rather than that
//! the layer merely failed to decode.
//!
//! Every stored varint array - binary and grayscale run lengths, split overlay
//! positions, and the attached form's parity-split core lengths, escapes and
//! overlay values - is written as significance planes (§5.3.1) rather than as
//! interleaved varints: four plane lengths, then the planes. See [`Planes`] for
//! the walk and [`read_planes`] for the framing.
//!
//! Each violation carries the specification's own wording as well as its check
//! name, because the verbose report prints that wording.

use crate::primitives::{read_varint, VarintError};

/// A rule the stream breaks, and what to call it.
///
/// `message` is the specification's wording for the failure, printed after the
/// check name. `None` where the reader records the verdict without saying why -
/// an unknown tag is its own explanation.
pub struct Violation {
    pub code: &'static str,
    pub message: Option<&'static str>,
}

/// A stream that cannot be read: bad framing, a truncated run, or a position
/// outside the layer, and the check name the failure belongs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    /// The §11.3 rule the stream broke, reported as the failing check.
    pub name: &'static str,
    /// The reader's own wording for the failure, printed after the check name.
    pub message: &'static str,
}

impl DecodeError {
    /// A varint that is not well formed: unterminated, or longer than the ten
    /// bytes a 64-bit value can need (§11.3).
    pub fn varint(error: VarintError) -> Self {
        DecodeError {
            name: "ree.varint",
            message: error.0,
        }
    }
}

/// The slice holds fewer bytes than the stream it starts describes.
const SHORT_STREAM: DecodeError = DecodeError {
    name: "ree.data_size",
    message: "empty binary REE stream",
};
const RUN_END_RANGE: DecodeError = DecodeError {
    name: "ree.end_positions",
    message: "run end out of range",
};
const END_PAST_TOTAL: DecodeError = DecodeError {
    name: "ree.end_positions",
    message: "end position past total_pixels",
};
const OVERLAY_PAST_TOTAL: DecodeError = DecodeError {
    name: "ree.split_positions",
    message: "overlay position past total_pixels",
};
/// The run values - grayscale's array, or the split overlay's - are cut short.
const MISSING_VALUES: DecodeError = DecodeError {
    name: "ree.data_size",
    message: "the slice ends inside a run's values",
};
/// The slice ends where the array's four plane lengths begin. §5.3.1 writes
/// them for every array, empty ones included, so a stream that stops here is
/// short of the bytes it says it has.
const PLANES_MISSING: DecodeError = DecodeError {
    name: "ree.data_size",
    message: "the slice ends before the four plane lengths",
};
const PLANES_PAST_END: DecodeError = DecodeError {
    name: "ree.data_size",
    message: "a plane runs past the end of the slice",
};
/// The slice ends inside the attachment bits the attached form starts its
/// overlay with. They are written for the run count the stream declares - one
/// byte per four runs - so a stream that stops before them is short of the
/// bytes it says it has.
const ATTACH_BITS_SHORT: DecodeError = DecodeError {
    name: "ree.data_size",
    message: "the slice ends inside the attachment bits",
};
/// `aa_pixel_count` disagrees with the pixels the attachment bits and the
/// escapes describe: a pixel is named twice over, or a value has no pixel to
/// attach to.
const ATTACH_COUNT: DecodeError = DecodeError {
    name: "ree.attach_count",
    message: "aa_pixel_count disagrees with the attachment bits and escapes",
};
/// An overlay value the stream cannot express as a mask byte. The first entry of
/// the value array is stored as it is and every later one is a step from the
/// pixel before it, so either can leave `0..=255`.
const NOT_A_BYTE: DecodeError = DecodeError {
    name: "ree.attach_count",
    message: "an overlay value is not a byte",
};

fn violation(code: &'static str, message: &'static str) -> Violation {
    Violation {
        code,
        message: Some(message),
    }
}

/// The four significance planes of one varint array, and the cursors that walk
/// them in step (§5.3.1).
///
/// Byte `j` of a varint - least significant seven bits first - is in plane `j`,
/// so a varint is read by taking the next byte of plane 0, then the next byte
/// of plane 1 while the continuation bit is set, and so on until a byte without
/// it terminates the value. A plane's cursor therefore counts the varints that
/// reached it rather than the varints read: a one-byte varint consumes a byte of
/// plane 0 only, and the plane-1 cursor moves for the two-byte ones alone.
///
/// No count of varints is needed to find the end of a plane, and a varint's
/// length is implied by its own bytes - which is what the arrangement buys the
/// compressor: a high byte is no longer sandwiched between two noisy low ones.
struct Planes<'a> {
    planes: [&'a [u8]; 4],
    cursors: [usize; 4],
}

impl<'a> Planes<'a> {
    /// No planes at all, for the streams §5.3 ends before writing them.
    fn empty() -> Self {
        Planes {
            planes: [&[]; 4],
            cursors: [0; 4],
        }
    }

    /// The next varint, in the walk §5.3.1 describes.
    ///
    /// A plane that runs out while its byte is wanted means the varint is not
    /// terminated inside the array, and a byte that continues past the fourth
    /// plane needs a fifth that the layout does not have. Both are malformed
    /// varints rather than violations: there is no value to carry on with.
    fn next(&mut self) -> Result<u128, VarintError> {
        let mut value = 0u128;
        let mut shift = 0u32;
        for (index, plane) in self.planes.iter().enumerate() {
            let Some(&byte) = plane.get(self.cursors[index]) else {
                return Err(VarintError("a varint is not terminated inside its planes"));
            };
            self.cursors[index] += 1;
            value |= u128::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(VarintError("a varint reaches past the fourth plane"))
    }

    /// Whether any plane holds a byte no varint consumed.
    fn leftover(&self) -> bool {
        self.planes
            .iter()
            .enumerate()
            .any(|(index, plane)| self.cursors[index] < plane.len())
    }
}

/// PLANES(n): four varint plane lengths, then the plane bytes (§5.3.1).
///
/// The lengths are the *byte* lengths of planes 0..3, zero when a plane is
/// empty, and they always number four - a PLANES(0) is four zero lengths and
/// costs four bytes - so a decoder knows the layout without first knowing how
/// many varints the array holds.
///
/// The prefix-closure rule is checked here: a varint that reaches plane `j`
/// occupies planes `0..j-1` as well, so a non-empty plane may not follow an
/// empty one.
fn read_planes<'a>(
    body: &'a [u8],
    pos: usize,
) -> Result<(Planes<'a>, usize, Vec<Violation>), DecodeError> {
    if pos >= body.len() {
        return Err(PLANES_MISSING);
    }
    let mut violations = Vec::new();
    let mut pos = pos;
    let mut lengths = [0usize; 4];
    for slot in &mut lengths {
        let (length, next) = read_varint(body, pos).map_err(DecodeError::varint)?;
        *slot = usize::try_from(length).map_err(|_| PLANES_PAST_END)?;
        pos = next;
    }

    let mut planes: [&[u8]; 4] = [&[]; 4];
    for (plane, length) in planes.iter_mut().zip(lengths) {
        let end = pos.checked_add(length).ok_or(PLANES_PAST_END)?;
        *plane = body.get(pos..end).ok_or(PLANES_PAST_END)?;
        pos = end;
    }

    for index in 1..planes.len() {
        if !planes[index].is_empty() && planes[index - 1].is_empty() {
            violations.push(violation(
                "ree.planes",
                "a non-empty plane follows an empty one",
            ));
        }
    }

    Ok((
        Planes {
            planes,
            cursors: [0; 4],
        },
        pos,
        violations,
    ))
}

/// The PLANES section of an array that stores `count` varints, unless the
/// stream is one of the §5.3/§5.4/§5.5 forms that ends before it.
///
/// §5.3.1 says the four lengths are always written, so an array with nothing in
/// it still carries four zero bytes and the reader always knows the layout.
/// The one stream that stops earlier is `run_count == 0`, which §5.3 and §5.4
/// end at the run count ("decodes to all black"; "fill 0; return") and which
/// strict mode rejects as non-canonical either way - so a stream that ends
/// there is read as the all-black layer it declares rather than refused for
/// four bytes that carry no information about it.
fn planes_section<'a>(
    body: &'a [u8],
    pos: usize,
    count: u128,
) -> Result<(Planes<'a>, usize, Vec<Violation>), DecodeError> {
    if count == 0 && pos >= body.len() {
        return Ok((Planes::empty(), pos, Vec::new()));
    }
    read_planes(body, pos)
}

/// The next `count` varints of an array, in order.
fn read_array(planes: &mut Planes<'_>, count: u128) -> Result<Vec<u128>, DecodeError> {
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(planes.next().map_err(DecodeError::varint)?);
    }
    Ok(values)
}

/// §11.3: the plane lengths and the planes account for exactly `data_size`, so
/// a plane byte no varint consumed is a byte the stream does not use.
fn check_leftover(planes: &Planes<'_>, violations: &mut Vec<Violation>) {
    if planes.leftover() {
        violations.push(violation(
            "ree.no_trailing_bytes",
            "a plane byte is not part of any varint",
        ));
    }
}

/// Binary REE: `body[0]` is `first_value`.
///
/// Returns the mask, the position just past the stream, and the violations.
pub fn binary(body: &[u8], total: usize) -> Result<(Vec<u8>, usize, Vec<Violation>), DecodeError> {
    let mut violations = Vec::new();
    let Some((&first_value, _)) = body.split_first() else {
        return Err(SHORT_STREAM);
    };
    let mut pos = 1;
    if first_value != 0x00 && first_value != 0xFF {
        violations.push(violation(
            "ree.first_value",
            "first_value is neither 0x00 nor 0xFF",
        ));
    }

    let (run_count, after) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after;
    if run_count == 0 {
        violations.push(violation(
            "ree.no_run_count_zero",
            "run_count == 0 is not canonical",
        ));
    }

    // The stored lengths are run_count - 1 of them: the last run ends at
    // total_pixels and carries no length of its own.
    let (mut planes, after, plane_violations) = planes_section(body, pos, run_count)?;
    pos = after;
    violations.extend(plane_violations);
    let lengths = read_array(&mut planes, run_count.saturating_sub(1))?;
    check_leftover(&planes, &mut violations);

    if lengths.iter().any(|&length| length < 1) {
        violations.push(violation("ree.run_lengths", "a stored run length is < 1"));
    }
    let stored: u128 = lengths.iter().fold(0u128, |sum, &l| sum.saturating_add(l));
    if (total as u128) < stored.saturating_add(1) {
        violations.push(violation(
            "ree.run_lengths",
            "the implicit final run length is < 1",
        ));
    }

    let mut mask = vec![0u8; total];
    let mut value = first_value;
    let mut start = 0usize;
    // Reading `run_count - 1` lengths consumed at least a byte each, so a run
    // count the stream cannot describe has already failed above: `lengths`
    // holds every stored run and the last one is implicit.
    for &length in &lengths {
        let end = start as u128 + length;
        if end > total as u128 || end < start as u128 {
            return Err(RUN_END_RANGE);
        }
        let end = end as usize;
        mask[start..end].fill(value);
        value = 255 - value;
        start = end;
    }
    if run_count > 0 {
        // The implicit final run: it reaches the end of the layer.
        if (start as u128) > total as u128 {
            return Err(RUN_END_RANGE);
        }
        mask[start..].fill(value);
    }
    Ok((mask, pos, violations))
}

/// Grayscale REE: every run's value, then the lengths of all but the last.
pub fn grayscale(
    body: &[u8],
    total: usize,
) -> Result<(Vec<u8>, usize, Vec<Violation>), DecodeError> {
    let mut violations = Vec::new();
    let (run_count, mut pos) = read_varint(body, 0).map_err(DecodeError::varint)?;
    if run_count == 0 {
        violations.push(violation(
            "ree.no_run_count_zero",
            "run_count == 0 is not canonical",
        ));
    }

    // §5.4: the values are hoisted out of the run loop into one array, which
    // also leaves the length stream smooth for the planes to exploit.
    let value_count = usize::try_from(run_count).map_err(|_| MISSING_VALUES)?;
    let values_end = pos.checked_add(value_count).ok_or(MISSING_VALUES)?;
    let values = body.get(pos..values_end).ok_or(MISSING_VALUES)?;
    pos = values_end;

    let (mut planes, after, plane_violations) = planes_section(body, pos, run_count)?;
    pos = after;
    violations.extend(plane_violations);
    let lengths = read_array(&mut planes, run_count.saturating_sub(1))?;
    check_leftover(&planes, &mut violations);

    let mut mask = vec![0u8; total];
    let mut previous: Option<u8> = None;
    let mut start = 0usize;
    let last = values.len().checked_sub(1);
    for (index, &value) in values.iter().enumerate() {
        // §5.4: the final run's length is implicit - it ends at total_pixels,
        // which the reader knows already.
        let end = if Some(index) == last {
            total as u128
        } else {
            start as u128 + lengths[index]
        };
        if end <= start as u128 {
            violations.push(violation(
                "ree.end_positions",
                "end positions are not strictly increasing",
            ));
        }
        if end > total as u128 {
            return Err(END_PAST_TOTAL);
        }
        if previous == Some(value) {
            violations.push(violation(
                "ree.grayscale_runs",
                "adjacent runs share a value",
            ));
        }
        let end = end as usize;
        if end > start {
            mask[start..end].fill(value);
        }
        start = end;
        previous = Some(value);
    }
    Ok((mask, pos, violations))
}

/// Split REE: a binary base plus the non-binary pixels listed by hand.
pub fn split(body: &[u8], total: usize) -> Result<(Vec<u8>, usize, Vec<Violation>), DecodeError> {
    let (mut mask, mut pos, base) = binary(body, total)?;
    let mut violations = base;

    let (count, after) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after;

    let (mut planes, after, plane_violations) = planes_section(body, pos, count)?;
    pos = after;
    violations.extend(plane_violations);

    // §5.5: positions[0] is the absolute index of the first AA pixel (a delta
    // from 0), so only later deltas have to be >= 1 for the indices to
    // increase.
    let deltas = read_array(&mut planes, count)?;
    let mut positions = Vec::new();
    let mut position = 0u128;
    for (index, delta) in deltas.iter().enumerate() {
        if index != 0 && *delta < 1 {
            violations.push(violation(
                "ree.split_positions",
                "overlay positions are not strictly increasing",
            ));
        }
        position += delta;
        positions.push(position);
    }
    check_leftover(&planes, &mut violations);

    // §5.5: the overlay is every position, then every value.
    let value_count = usize::try_from(count).map_err(|_| MISSING_VALUES)?;
    let values_end = pos.checked_add(value_count).ok_or(MISSING_VALUES)?;
    let values = body.get(pos..values_end).ok_or(MISSING_VALUES)?;
    pos = values_end;

    for (&position, &value) in positions.iter().zip(values) {
        if position >= total as u128 {
            return Err(OVERLAY_PAST_TOTAL);
        }
        mask[position as usize] = value;
    }

    // Canonical: the overlay must be exactly the non-0x00/0xFF pixels.
    let expected: Vec<(usize, u8)> = mask
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, value)| *value != 0 && *value != 255)
        .collect();
    let indices_match = expected
        .iter()
        .map(|(index, _)| *index)
        .eq(positions.iter().map(|p| *p as usize));
    let values_match = expected.iter().map(|(_, v)| *v).eq(values.iter().copied());
    if !indices_match || !values_match {
        violations.push(violation(
            "ree.split_threshold",
            "overlay is not exactly the set of non-binary pixels",
        ));
    }
    Ok((mask, pos, violations))
}

/// Unzigzag: the inverse of the map that stores a signed step as a varint the
/// planes can carry - `0, -1, 1, -2` are stored as `0, 1, 2, 3` - so the sign of
/// a step costs one bit rather than a whole byte, and a step towards either
/// value stays cheap.
fn unzigzag(value: u128) -> i128 {
    let magnitude = (value >> 1) as i128;
    if value & 1 == 0 {
        magnitude
    } else {
        -magnitude - 1
    }
}

/// Bit `index` of the packed attachment bits, least significant bit first, and
/// zero past the end.
///
/// Two bits per core run are one byte per four runs, so only the last byte is
/// partial. Reading past the end is what sizes the bits for the non-canonical
/// `run_count == 0` form, whose core has one run and no bits at all.
fn attach_bit(bits: &[u8], index: usize) -> bool {
    bits.get(index >> 3)
        .is_some_and(|byte| ((*byte >> (index & 7)) & 1) == 1)
}

/// Attached split REE (tag `0x03`): a thresholded binary core whose AA pixels
/// are attached to the core's run boundaries (§5.6).
///
/// The core is binary REE with its stored lengths split by parity, and each of
/// those a step from the length two runs back, so the two parities never mix and
/// a run's length is a difference of like values rather than an absolute end
/// position. The AA pixels of an edge are then the first and last pixel of the
/// run their thresholded value lands in, which two bits per run express - a
/// quarter of a byte a run instead of a delta-coded position each - and only the
/// pixels strictly inside a run are listed by hand. The overlay's values are in
/// pixel order and first differenced, so a band of similar coverage costs the
/// step between its pixels rather than a byte each.
///
/// Returns the mask, the position just past the stream, and the violations.
pub fn attached(
    body: &[u8],
    total: usize,
) -> Result<(Vec<u8>, usize, Vec<Violation>), DecodeError> {
    let mut violations = Vec::new();
    let Some((&first_value, _)) = body.split_first() else {
        return Err(SHORT_STREAM);
    };
    let mut pos = 1;
    if first_value != 0x00 && first_value != 0xFF {
        violations.push(violation(
            "ree.first_value",
            "first_value is neither 0x00 nor 0xFF",
        ));
    }

    let (run_count, after) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after;
    if run_count == 0 {
        violations.push(violation(
            "ree.no_run_count_zero",
            "run_count == 0 is not canonical",
        ));
    }

    // Stored index j of the core's lengths is run j's own length for j < 2 and
    // zigzag(length[j] - length[j-2]) beyond, and the two parities go to their
    // own arrays - so a step is always measured against the run two back, which
    // shares this run's parity.
    let core = run_count.saturating_sub(1);
    let (mut even_planes, after, plane_violations) = read_planes(body, pos)?;
    pos = after;
    violations.extend(plane_violations);
    let even = read_array(&mut even_planes, core.div_ceil(2))?;
    check_leftover(&even_planes, &mut violations);
    let (mut odd_planes, after, plane_violations) = read_planes(body, pos)?;
    pos = after;
    violations.extend(plane_violations);
    let odd = read_array(&mut odd_planes, core / 2)?;
    check_leftover(&odd_planes, &mut violations);

    let mut lengths: Vec<i128> = Vec::with_capacity(even.len() + odd.len());
    for index in 0..even.len() + odd.len() {
        let stored = if index % 2 == 0 {
            even[index / 2]
        } else {
            odd[index / 2]
        };
        let length = if index < 2 {
            i128::try_from(stored).unwrap_or(i128::MAX)
        } else {
            lengths[index - 2].saturating_add(unzigzag(stored))
        };
        lengths.push(length);
    }
    if lengths.iter().any(|&length| length < 1) {
        violations.push(violation("ree.run_lengths", "a stored run length is < 1"));
    }

    // The core, run by run: run i carries first_value when i is even, and the
    // last run reaches total_pixels with no length of its own.
    let mut mask = vec![0u8; total];
    let mut runs: Vec<(usize, usize, u8)> = Vec::with_capacity(lengths.len() + 1);
    let mut value = first_value;
    let mut start = 0u128;
    for &length in &lengths {
        // A length the stream declares as zero or less describes no pixels; the
        // run is empty, and the value still alternates.
        let end = start.saturating_add(u128::try_from(length.max(0)).unwrap_or(u128::MAX));
        if end > total as u128 {
            return Err(RUN_END_RANGE);
        }
        mask[start as usize..end as usize].fill(value);
        runs.push((start as usize, end as usize, value));
        value = 255 - value;
        start = end;
    }
    if run_count > 0 {
        // The implicit final run reaches the end of the layer.
        if start > total as u128 {
            return Err(RUN_END_RANGE);
        }
        mask[start as usize..].fill(value);
        runs.push((start as usize, total, value));
    }
    if (total as u128) < start.saturating_add(1) {
        violations.push(violation(
            "ree.run_lengths",
            "the implicit final run length is < 1",
        ));
    }

    // The run count the attachment bits are sized by, taken before the run list
    // grows its one entry for §5.3's non-canonical all-black form. That form
    // declares no run at all, and the overlay which follows it sits over one
    // black run covering the layer - a run no bit addresses.
    let declared = runs.len();
    if run_count == 0 {
        runs.push((0, total, 0x00));
    }

    let (aa_pixel_count, after) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after;

    // Two bits per declared run - its first pixel, then its last - packed into
    // ceil(K/4) bytes, least significant bit first. The bits past the last run
    // are padding, and a set one addresses a run the stream does not have.
    let bit_bytes = declared.div_ceil(4);
    let bits_end = pos.checked_add(bit_bytes).ok_or(ATTACH_BITS_SHORT)?;
    let bits = body.get(pos..bits_end).ok_or(ATTACH_BITS_SHORT)?;
    pos = bits_end;
    for index in declared * 2..bits.len() * 8 {
        if attach_bit(bits, index) {
            violations.push(violation(
                "ree.attach_bits",
                "an attachment bit addresses a run past run_count",
            ));
        }
    }

    let (escape_count, after) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after;
    let (mut escape_planes, after, plane_violations) = read_planes(body, pos)?;
    pos = after;
    violations.extend(plane_violations);
    let escape_deltas = read_array(&mut escape_planes, escape_count)?;
    check_leftover(&escape_planes, &mut violations);

    // An escape is an AA pixel no attachment bit expresses: an absolute index,
    // delta-coded, and strictly inside its core run - at its first or last pixel
    // it would be a bit's business.
    let mut positions: Vec<u128> = Vec::with_capacity(escape_deltas.len());
    let mut position = 0u128;
    for (index, &delta) in escape_deltas.iter().enumerate() {
        if index != 0 && delta < 1 {
            violations.push(violation(
                "ree.attach_positions",
                "escape positions are not strictly increasing",
            ));
        }
        position += delta;
        positions.push(position);
    }

    // Which run each escape sits in: the last run that starts at or before it. A
    // run of no pixels holds none, so a stream that declares one leaves its
    // escapes with no run to be inside of.
    let mut interior: Vec<Vec<usize>> = vec![Vec::new(); runs.len()];
    let mut outside: Vec<usize> = Vec::new();
    for (index, &escape) in positions.iter().enumerate() {
        if escape >= total as u128 {
            violations.push(violation(
                "ree.attach_positions",
                "an escape position is not below total_pixels",
            ));
            outside.push(index);
            continue;
        }
        let Some(run) = runs
            .partition_point(|&(run_start, _, _)| run_start <= escape as usize)
            .checked_sub(1)
        else {
            violations.push(violation(
                "ree.attach_positions",
                "an escape position is not strictly inside its core run",
            ));
            outside.push(index);
            continue;
        };
        let (run_start, run_end, _) = runs[run];
        if escape as usize == run_start || escape as usize + 1 == run_end {
            violations.push(violation(
                "ree.attach_positions",
                "an escape position is not strictly inside its core run",
            ));
        }
        interior[run].push(index);
    }

    // The AA pixels in the order their values are stored: for each core run, the
    // first pixel when its bit is set, then the escapes inside it, then the last
    // pixel when its bit is set. A pixel the stream names but no run holds keeps
    // its place and its value, and is written nowhere.
    let mut walk: Vec<Option<(usize, u8)>> = Vec::new();
    for (run, &(run_start, run_end, run_value)) in runs.iter().enumerate() {
        let first = attach_bit(bits, run * 2);
        let last = attach_bit(bits, run * 2 + 1);
        // A run of one pixel expresses that pixel with the first bit alone; both
        // bits would name it twice.
        if first && last && run_end - run_start == 1 {
            violations.push(violation(
                "ree.attach_bits",
                "a run of one pixel sets both of its bits",
            ));
        }
        if first {
            walk.push((run_end > run_start).then_some((run_start, run_value)));
        }
        for &escape in &interior[run] {
            walk.push(Some((positions[escape] as usize, run_value)));
        }
        if last {
            walk.push((run_end > run_start).then_some((run_end - 1, run_value)));
        }
    }
    walk.extend(outside.iter().map(|_| None));
    if walk.len() as u128 != aa_pixel_count {
        return Err(ATTACH_COUNT);
    }

    // §5.6: the overlay's values are one plane array - the first as it is, every
    // later one the step from the pixel before it in the walk.
    let (mut value_planes, after, plane_violations) = read_planes(body, pos)?;
    pos = after;
    violations.extend(plane_violations);
    let stored = read_array(&mut value_planes, aa_pixel_count)?;
    check_leftover(&value_planes, &mut violations);

    let mut values: Vec<u8> = Vec::with_capacity(stored.len());
    let mut value = 0i128;
    for (index, &entry) in stored.iter().enumerate() {
        value = if index == 0 {
            i128::try_from(entry).map_err(|_| NOT_A_BYTE)?
        } else {
            value + unzigzag(entry)
        };
        values.push(u8::try_from(value).map_err(|_| NOT_A_BYTE)?);
    }

    // The overlay, written over the core.
    for (&named, &value) in walk.iter().zip(&values) {
        if let Some((pixel, _)) = named {
            mask[pixel] = value;
        }
    }

    // Strict canonical form: an AA pixel is a coverage byte, so it is neither
    // 0x00 nor 0xFF, and it thresholds to the value of the run it sits in -
    // otherwise the core would not be the threshold of its own mask.
    if values.iter().any(|&value| value == 0x00 || value == 0xFF) {
        violations.push(violation(
            "ree.attach_threshold",
            "an overlay value is 0x00 or 0xFF",
        ));
    }
    let mismatched = walk.iter().zip(&values).any(|(&named, &value)| {
        named.is_some_and(|(_, run_value)| (if value >= 128 { 0xFF } else { 0x00 }) != run_value)
    });
    if mismatched {
        violations.push(violation(
            "ree.attach_threshold",
            "an overlay value does not threshold to the value of the run it sits in",
        ));
    }
    Ok((mask, pos, violations))
}
