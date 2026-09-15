//! zstd decoding with the semantics the oracle's `ZstdDecompressor.decompress`
//! has, which are not quite the obvious ones.
//!
//! Three of them matter to the corpus, so they are reproduced deliberately
//! rather than approximated:
//!
//! * A frame that declares its content size is decoded into a buffer of exactly
//!   that size, and `max_output_size` is ignored - it is a hint for the frames
//!   that do *not* declare one, not a cap.
//! * A frame that declares an empty payload is answered without decoding.
//! * Data after the first frame is ignored, not treated as an error.
//!
//! And one is structural: a `ZSTD_DCtx` carries an unfinished frame into the
//! next call, so a decoder reused across a file's frames behaves differently
//! from a fresh one per frame. [`Decoder`] is reused exactly where the oracle
//! reuses its `ZstdDecompressor`: across the `LAYR` frames of one file, and not
//! across the payloads of two chunks.

use std::num::NonZeroU32;

use zstd::zstd_safe;

/// The frame is not a frame, or it does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZstdError;

/// One decoder context, reused across calls.
pub struct Decoder {
    dctx: zstd_safe::DCtx<'static>,
}

impl Decoder {
    /// A decoder that reads frames written with `dictionary`, or without one
    /// when `dictionary` is empty.
    pub fn new(dictionary: &[u8]) -> Result<Self, ZstdError> {
        let mut dctx = zstd_safe::DCtx::create();
        dctx.load_dictionary(dictionary).map_err(|_| ZstdError)?;
        Ok(Self { dctx })
    }

    /// Decompress one frame, the way `ZstdDecompressor.decompress` does.
    pub fn decompress(
        &mut self,
        data: &[u8],
        max_output_size: usize,
    ) -> Result<Vec<u8>, ZstdError> {
        // The frame header decides the buffer; `max_output_size` only fills in
        // when the header does not carry a content size.
        let (size, exact) = match zstd_safe::get_frame_content_size(data) {
            // Not a frame header at all.
            Err(_) => return Err(ZstdError),
            // A frame with an empty payload is answered without decoding.
            Ok(Some(0)) => return Ok(Vec::new()),
            Ok(Some(size)) => (usize::try_from(size).map_err(|_| ZstdError)?, true),
            Ok(None) => {
                if max_output_size == 0 {
                    return Err(ZstdError);
                }
                (max_output_size, false)
            }
        };

        let mut buffer = Vec::new();
        buffer.try_reserve_exact(size).map_err(|_| ZstdError)?;
        buffer.resize(size, 0);
        let mut output = zstd_safe::OutBuffer::around(&mut buffer[..]);
        let mut input = zstd_safe::InBuffer::around(data);
        match self.dctx.decompress_stream(&mut output, &mut input) {
            // 0 is only returned once the frame is decoded *and* flushed.
            Ok(0) => {
                let written = output.pos();
                if exact && written != size {
                    return Err(ZstdError);
                }
                buffer.truncate(written);
                Ok(buffer)
            }
            Ok(_) => Err(ZstdError),
            Err(_) => Err(ZstdError),
        }
    }
}

/// The dictionary ID a frame header declares, or `None` when the bytes are not
/// a frame header - the oracle's `get_frame_parameters` raising.
pub fn frame_dict_id(frame: &[u8]) -> Option<u32> {
    zstd_safe::get_frame_content_size(frame).ok()?;
    Some(zstd_safe::get_dict_id_from_frame(frame).map_or(0, NonZeroU32::get))
}

/// What a frame header says about its output size (§4.9).
///
/// The outer `None` is "these bytes are not a frame header at all"; the inner
/// one is "the frame leaves its content size implicit", which a writer is not
/// allowed to do and a reader cannot allocate for. The two are different
/// defects, so they are not folded together.
pub fn frame_content_size(frame: &[u8]) -> Option<Option<u64>> {
    zstd_safe::get_frame_content_size(frame).ok()
}
