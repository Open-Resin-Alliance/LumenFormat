//! The preview payloads (spec 4.6): minimal deterministic 8-bit RGB PNGs.

use crate::deflate;

/// A minimal deterministic 8-bit RGB PNG, one filter byte per row and no ancillary
/// chunks, so the bytes depend only on the arguments.
pub fn preview(width: usize, height: usize, rgb: [u8; 3]) -> Vec<u8> {
    // One filter byte per row, then the pixels: RGB triples, byte for byte.
    let row_len = 1 + 3 * width;
    let mut rows = vec![0u8; row_len * height];
    for line in rows.chunks_exact_mut(row_len) {
        for pixel in line[1..].as_chunks_mut::<3>().0 {
            pixel.copy_from_slice(&rgb);
        }
    }

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);

    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    out.extend(chunk(b"IHDR", &ihdr));
    out.extend(chunk(b"IDAT", &deflate::zlib_compress(&rows)));
    out.extend(chunk(b"IEND", &[]));
    out
}

/// One PNG chunk: length, tag, data, CRC-32 of tag and data.
fn chunk(tag: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 12);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(tag);
    crc.update(data);
    out.extend_from_slice(&crc.finish().to_be_bytes());
    out
}

/// CRC-32 as PNG defines it (IEEE 802.3, reflected).
struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Crc32(0xFFFF_FFFF)
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.0 ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (self.0 & 1).wrapping_neg();
                self.0 = (self.0 >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.0
    }
}
