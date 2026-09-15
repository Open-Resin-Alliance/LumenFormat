//! The three run-length encodings of §4.3, and the violations each can carry.
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
//! Each violation carries the specification's own wording as well as its check
//! name, because the verbose report prints that wording.

use crate::bytes::at;
use crate::primitives::read_varint;

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
    pub fn varint(error: crate::primitives::VarintError) -> Self {
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
const MISSING_VALUE: DecodeError = DecodeError {
    name: "ree.data_size",
    message: "the stream ends inside a run",
};

fn violation(code: &'static str, message: &'static str) -> Violation {
    Violation {
        code,
        message: Some(message),
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

    let (run_count, after_count) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after_count;
    let mut lengths = Vec::new();
    for _ in 0..run_count.saturating_sub(1) {
        let (length, next) = read_varint(body, pos).map_err(DecodeError::varint)?;
        pos = next;
        lengths.push(length);
    }
    if run_count == 0 {
        violations.push(violation(
            "ree.no_run_count_zero",
            "run_count == 0 is not canonical",
        ));
    }
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

/// Grayscale REE: a value and an end position per run.
pub fn grayscale(
    body: &[u8],
    total: usize,
) -> Result<(Vec<u8>, usize, Vec<Violation>), DecodeError> {
    let mut violations = Vec::new();
    let (run_count, mut pos) = read_varint(body, 0).map_err(DecodeError::varint)?;

    let mut mask = vec![0u8; total];
    let mut previous: Option<u8> = None;
    let mut start = 0usize;
    for _ in 0..run_count {
        let value = *body.get(pos).ok_or(MISSING_VALUE)?;
        pos += 1;
        let (end, next) = read_varint(body, pos).map_err(DecodeError::varint)?;
        pos = next;
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
    if start != total {
        violations.push(violation(
            "ree.end_positions",
            "the final end position is not total_pixels",
        ));
    }
    if run_count == 0 {
        violations.push(violation(
            "ree.no_run_count_zero",
            "run_count == 0 is not canonical",
        ));
    }
    Ok((mask, pos, violations))
}

/// Split REE: a binary base plus the non-binary pixels listed by hand.
pub fn split(body: &[u8], total: usize) -> Result<(Vec<u8>, usize, Vec<Violation>), DecodeError> {
    let (mut mask, mut pos, base) = binary(body, total)?;
    let mut violations = base;

    let (count, after_count) = read_varint(body, pos).map_err(DecodeError::varint)?;
    pos = after_count;
    let mut positions = Vec::new();
    let mut position = 0u128;
    for index in 0..count {
        let (delta, next) = read_varint(body, pos).map_err(DecodeError::varint)?;
        pos = next;
        // positions[0] is the absolute index of the first AA pixel (a delta from
        // 0), so only later deltas have to be >= 1 for the indices to increase.
        if index != 0 && delta < 1 {
            violations.push(violation(
                "ree.split_positions",
                "overlay positions are not strictly increasing",
            ));
        }
        position += delta;
        positions.push(position);
    }

    let values = at(body, pos as u128, count);
    pos = pos.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
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
