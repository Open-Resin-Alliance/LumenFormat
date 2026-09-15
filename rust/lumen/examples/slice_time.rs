//! Throwaway: where does the encode time go on a real model?
//!
//! Decodes a `.lumen` file's own layers once, then re-encodes them through the writer at
//! several zstd levels and with the dictionary on and off, timing the per-layer push and
//! the finalize separately, so the slice-time difference against CTB can be attributed.
//! Deleted after the measurement.

use lumen::reader::LumenFile;
use lumen::ree::{encode_runs, EncodeMode, Run};
use lumen::writer::Encoder;

const CHUNK: u32 = 64;

fn runs_of(pixels: &[u8]) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    let mut value = pixels[0];
    let mut length = 0u32;
    for pixel in pixels {
        if *pixel == value {
            length += 1;
            continue;
        }
        runs.push(Run::new(length, value));
        value = *pixel;
        length = 1;
    }
    runs.push(Run::new(length, value));
    runs
}

fn main() {
    let path = std::env::args().nth(1).expect("a .lumen path");
    let bytes = std::fs::read(&path).expect("readable");
    let file = LumenFile::open_unvalidated(&bytes).expect("openable");
    let head = file.head().clone();
    let meta = file.meta().clone();
    let count = file.layer_count();
    let total_pixels = file.total_pixels();

    let started = std::time::Instant::now();
    let mut layers: Vec<Vec<Run>> = Vec::with_capacity(count as usize);
    for index in 0..count {
        layers.push(runs_of(&file.layer(index).expect("decodable").pixels));
    }
    let decode = started.elapsed().as_secs_f64();
    let runs: usize = layers.iter().map(|l| l.len()).sum();
    let stored: u64 = file
        .layer_table()
        .entries
        .iter()
        .map(|e| u64::from(e.data_size))
        .sum();
    println!(
        "file {} B, {} layers x {} um, {} M lit pixels per layer\n  decoding {} layers took {:.1} s; {} runs ({:.0}/layer), {:.2} MB of REE",
        bytes.len(),
        count,
        head.layer_height_um,
        total_pixels / 1_000_000,
        count,
        decode,
        runs,
        runs as f64 / count as f64,
        stored as f64 / 1e6
    );
    let zstd_input_mb = stored as f64 / 1e6;

    println!("\n  {:<26} {:>10} {:>12} {:>10}", "config", "push", "finish", "total");
    for (level, dict) in [(3, false), (6, false), (19, false), (3, true), (6, true), (19, true)] {
        let mut encoder = Encoder::new(head.clone(), meta.clone());
        encoder.set_layers_per_chunk(CHUNK);
        encoder.set_zstd_level(level);
        encoder.set_dictionary(dict);
        encoder.set_layer_hashes(true);

        let started = std::time::Instant::now();
        for runs in &layers {
            encoder
                .push_layer_runs(runs, EncodeMode::Auto)
                .expect("pushable");
        }
        let push = started.elapsed().as_secs_f64();

        let started = std::time::Instant::now();
        let size = encoder.finish().expect("writable").len();
        let finish = started.elapsed().as_secs_f64();
        println!(
            "  {:<26} {:>9.2} s {:>11.2} s {:>9.2} s   -> {} B ({:.2} MB of zstd input, {} MB/s)",
            format!("level {level}, dictionary {dict}"),
            push,
            finish,
            push + finish,
            size,
            zstd_input_mb,
            zstd_input_mb / finish.max(0.001)
        );
    }
}
