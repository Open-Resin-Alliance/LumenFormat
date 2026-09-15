//! The three run-length encodings of §5, and the violations each can carry.
//!
//! A decoder either produces a mask plus the list of violations it found, or
//! fails outright - and the two are different verdicts. A violation is reported
//! under its own check name; a failure means the stream could not be read at
//! all, and names the rule the stream ran out against - `ree.data_size` when
//! the slice was too short, `ree.varint` when a varint is not well formed,
//! `ree.end_positions` or `ree.split_positions` when a position it decoded
//! lands outside the layer. Keeping the two apart is what lets the corpus
//! assert that one specific rule was broken rather than that the layer merely
//! failed to decode.
//!
//! Every stored varint array - binary and grayscale run lengths, split overlay
//! positions - is written as significance planes (§5.3.1) rather than as
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
