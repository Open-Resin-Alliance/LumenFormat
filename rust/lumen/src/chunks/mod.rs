//! One codec per chunk type ([`spec/03-chunks.md`], [`spec/06-layer-data.md`],
//! [`spec/07-scene-chunks.md`]).
//!
//! Each codec deals in *plaintext payload bytes*: decryption and the zstd layer
//! are the caller's business, because whether a chunk carries a zstd frame is a
//! property of its type (section 6.3) while whether it is sealed is a property
//! of its descriptor.

pub mod extd;
pub mod hdr;
pub mod json_chunks;
pub mod layr;
pub mod lhas;
pub mod ltbl;
pub mod preview;
pub mod voxl;
pub mod zdic;

pub use extd::Extension;
pub use hdr::Hdr;
pub use lhas::LayerHashes;
pub use ltbl::{LayerEntry, LayerTable};
pub use preview::{Preview, PreviewRole};
pub use zdic::ZstdDictionary;

use crate::check::Check;
use crate::error::{Error, Result};
use zstd::bulk::{Compressor, Decompressor};

/// Compress a chunk payload into a zstd frame, optionally against a dictionary.
pub fn compress(payload: &[u8], level: i32, dictionary: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut compressor = match dictionary {
        Some(dictionary) => Compressor::with_dictionary(level, dictionary),
        None => Compressor::new(level),
    }
    .map_err(|e| {
        Error::new(
            Check::LayrFrameDecompressedSize,
            format!("could not start the zstd compressor: {e}"),
        )
    })?;
    compressor.compress(payload).map_err(|e| {
        Error::new(
            Check::LayrFrameDecompressedSize,
            format!("zstd compression failed: {e}"),
        )
    })
}

/// Decompress a zstd frame, checking the result is exactly `uncompressed_size`.
pub fn decompress(
    frame: &[u8],
    uncompressed_size: u64,
    dictionary: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Refuse to reserve memory a frame's own bytes cannot justify before the
    // decompressor allocates for the declared size (section 11.3).
    check_allocation(frame.len(), uncompressed_size)?;
    let capacity = usize::try_from(uncompressed_size).map_err(|_| {
        Error::new(
            Check::LayrFrameDecompressedSize,
            format!("declared uncompressed size {uncompressed_size} is not addressable"),
        )
    })?;
    let mut decompressor = match dictionary {
        Some(dictionary) => Decompressor::with_dictionary(dictionary),
        None => Decompressor::new(),
    }
    .map_err(|e| {
        Error::new(
            Check::LayrFrameDecompressedSize,
            format!("could not start the zstd decompressor: {e}"),
        )
    })?;
    let decoded = decompressor.decompress(frame, capacity).map_err(|e| {
        Error::new(
            Check::LayrFrameDecompressedSize,
            format!("zstd decompression failed: {e}"),
        )
    })?;
    if decoded.len() as u64 != uncompressed_size {
        return Err(Error::new(
            Check::LayrFrameDecompressedSize,
            format!(
                "the frame expands to {} bytes, not the declared {uncompressed_size}",
                decoded.len()
            ),
        ));
    }
    Ok(decoded)
}

/// The dictionary ID a frame reports, or `0` when the frame used no dictionary.
pub fn frame_dict_id(frame: &[u8]) -> Result<u32> {
    Ok(zstd::zstd_safe::get_dict_id_from_frame(frame)
        .map(|id| id.get())
        .unwrap_or(0))
}

/// The decompressed length a frame's own header declares.
///
/// A `LAYR` frame MUST carry its content size: the chunk descriptor describes
/// the container, not the frame's output, so this header field is the only place
/// a reader can learn how large that output is before it allocates.
pub fn frame_content_size(frame: &[u8]) -> Result<u64> {
    match zstd::zstd_safe::get_frame_content_size(frame) {
        Ok(Some(size)) => Ok(size),
        Ok(None) => Err(Error::new(
            Check::LayrContentSizePresent,
            "the frame carries no content size, so its output cannot be sized",
        )),
        Err(e) => Err(Error::new(
            Check::LayrContentSizePresent,
            format!("the frame's content size is unreadable: {e}"),
        )),
    }
}

/// Decompress a `LAYR` frame, sizing its output from the frame's own header.
pub fn decompress_frame(frame: &[u8], dictionary: Option<&[u8]>) -> Result<Vec<u8>> {
    let size = frame_content_size(frame)?;
    check_allocation(frame.len(), size)?;
    decompress(frame, size, dictionary)
}

/// The dictionary ID a raw dictionary reports.
pub fn dictionary_id(dictionary: &[u8]) -> u32 {
    zstd::zstd_safe::get_dict_id_from_dict(dictionary)
        .map(|id| id.get())
        .unwrap_or(0)
}

/// Train a zstd dictionary from layer samples (section 6.2).
pub fn train_dictionary(samples: &[&[u8]], max_size: usize) -> Result<Vec<u8>> {
    zstd::dict::from_samples(samples, max_size).map_err(|e| {
        Error::new(
            Check::ZdicDictSize,
            format!("zstd dictionary training failed: {e}"),
        )
    })
}

/// The decompressed-size bound a `LAYR` chunk's frame may not exceed.
///
/// Grayscale REE costs at most about 5 bytes per pixel plus framing, which is
/// what a reader checks a frame's declared content size against before
/// allocating, over the layers whose slices the chunk holds (section 11.3).
pub fn allocation_bound(layers: u64, total_pixels: u32) -> u64 {
    layers.saturating_mul(u64::from(total_pixels).saturating_mul(5).saturating_add(64))
}

/// Reject a payload that would need more memory than its own bytes can justify.
pub fn check_allocation(payload_len: usize, uncompressed_size: u64) -> Result<()> {
    if uncompressed_size > (payload_len as u64).saturating_mul(MAX_ZSTD_RATIO as u64) {
        return Err(Error::new(
            Check::LayrAllocationBound,
            format!(
                "declared uncompressed size {uncompressed_size} is implausible for {payload_len} stored bytes"
            ),
        ));
    }
    Ok(())
}

/// The largest expansion zstd can produce for a chunk payload, used as a coarse
/// guard before a bound specific to the chunk is available.
pub const MAX_ZSTD_RATIO: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn zstd_round_trips_with_and_without_a_dictionary() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 17) as u8).collect();

        let framed = compress(&payload, 3, None).unwrap();
        assert_eq!(frame_dict_id(&framed).unwrap(), 0);
        assert_eq!(
            decompress(&framed, payload.len() as u64, None).unwrap(),
            payload
        );

        // Training needs a corpus of similar samples.
        let samples: Vec<Vec<u8>> = (0..256u32)
            .map(|s| (0..256u32).map(|i| ((i + s) % 23) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = samples.iter().map(|s| s.as_slice()).collect();
        let dictionary = train_dictionary(&refs, 512).unwrap();
        let dict_id = dictionary_id(&dictionary);
        assert_ne!(dict_id, 0, "a trained dictionary reports its ID");

        let framed = compress(&payload, 3, Some(&dictionary)).unwrap();
        assert_eq!(frame_dict_id(&framed).unwrap(), dict_id);
        assert_eq!(
            decompress(&framed, payload.len() as u64, Some(&dictionary)).unwrap(),
            payload
        );

        // A frame that does not expand to the declared size is rejected.
        let err = decompress(&framed, payload.len() as u64 + 1, Some(&dictionary)).unwrap_err();
        assert_eq!(err.check(), Check::LayrFrameDecompressedSize);
    }

    #[test]
    fn a_writer_frame_declares_the_size_it_expands_to() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 17) as u8).collect();
        let framed = compress(&payload, 3, None).unwrap();
        assert_eq!(frame_content_size(&framed).unwrap(), payload.len() as u64);
        assert_eq!(decompress_frame(&framed, None).unwrap(), payload);

        // A `LAYR` frame is sized from its own header, because the chunk
        // descriptor describes the container and not the frame's output. A frame
        // written by a streaming encoder declares no content size, and a reader
        // refuses one rather than guessing what to allocate.
        let streamed = {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap()
        };
        assert_eq!(
            frame_content_size(&streamed).unwrap_err().check(),
            Check::LayrContentSizePresent
        );
    }

    #[test]
    fn check_allocation_bounds_the_declared_size() {
        assert!(check_allocation(1, (MAX_ZSTD_RATIO - 1) as u64).is_ok());
        assert_eq!(
            check_allocation(1, MAX_ZSTD_RATIO as u64 + 1)
                .unwrap_err()
                .check(),
            Check::LayrAllocationBound
        );
        assert!(allocation_bound(2, 1000) > 0);
    }
}
