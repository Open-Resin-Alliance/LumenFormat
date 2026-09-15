//! Throwaway: how should a planar LAYR layout be shaped?
//!
//! Three serializations of the same print, all compressed the same way (level 19,
//! 64-layer groups, no dictionary), plus the per-plane breakdown of the middle one,
//! so the format change can be designed around where the win actually is.
//! Deleted after the measurement.

use lumen::chunks::compress;
use lumen::reader::LumenFile;
use lumen::ree::{encode_runs, EncodeMode, Run};
use lumen::Level;

const CHUNK: usize = 64;
const LEVEL: i32 = 19;

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

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A varint's bytes split by significance.
fn push_planes(planes: &mut [Vec<u8>; 4], mut value: u64) {
    let mut plane = 0;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            planes[plane].push(byte);
            return;
        }
        planes[plane].push(byte | 0x80);
        plane += 1;
    }
}

/// One layer's binary runs, as the three candidate serializations.
struct Layer {
    stored: Vec<u8>,
    tag: u8,
    first: u8,
    count: u64,
    lengths: Vec<u32>,
}

fn compressed(blocks: &[Vec<u8>]) -> usize {
    blocks
        .iter()
        .map(|block| {
            compress(block, LEVEL, None)
                .map(|f| f.len())
                .unwrap_or(block.len())
        })
        .sum()
}

fn main() {
    let path = std::env::args().nth(1).expect("a .lumen path");
    let bytes = std::fs::read(&path).expect("readable");
    let file = LumenFile::open(&bytes, Level::Loose).expect("openable");
    let total_pixels = file.total_pixels();

    let mut layers: Vec<Layer> = Vec::new();
    for index in 0..file.layer_count() {
        let layer = file.layer(index).expect("decodable");
        let runs = runs_of(&layer.pixels);
        let encoded = encode_runs(&runs, total_pixels, EncodeMode::Auto).expect("encodable");
        match encoded {
            Some((tag, stream)) => layers.push(Layer {
                stored: stream,
                tag,
                first: runs[0].value,
                count: runs.len() as u64,
                lengths: runs[..runs.len() - 1]
                    .iter()
                    .map(|run| run.length)
                    .collect(),
            }),
            None => layers.push(Layer {
                stored: Vec::new(),
                tag: 0,
                first: 0,
                count: 0,
                lengths: Vec::new(),
            }),
        }
    }

    // A: what the format stores today.
    let stored_total: usize = layers.iter().map(|l| l.stored.len()).sum();
    let stored_blocks: Vec<Vec<u8>> = layers
        .iter()
        .map(|l| l.stored.clone())
        .collect::<Vec<_>>()
        .chunks(CHUNK)
        .map(|group| group.concat())
        .collect();

    // B: per chunk, every plane of the whole group, so like bytes sit together.
    let mut chunk_planes: Vec<Vec<u8>> = Vec::new();
    let mut plane_raw = [0usize; 10];
    for group in layers.chunks(CHUNK) {
        let mut tags = Vec::new();
        let mut firsts = Vec::new();
        let mut counts: [Vec<u8>; 4] = Default::default();
        let mut lengths: [Vec<u8>; 4] = Default::default();
        for layer in group {
            if layer.count == 0 {
                continue;
            }
            tags.push(layer.tag);
            firsts.push(layer.first);
            push_planes(&mut counts, layer.count);
            for length in &layer.lengths {
                push_planes(&mut lengths, u64::from(*length));
            }
        }
        let mut block = Vec::new();
        let parts: Vec<&Vec<u8>> = [&tags, &firsts]
            .into_iter()
            .chain(counts.iter())
            .chain(lengths.iter())
            .collect();
        for part in parts {
            block.extend_from_slice(part);
        }
        plane_raw[0] += tags.len();
        plane_raw[1] += firsts.len();
        for (i, plane) in counts.iter().enumerate() {
            plane_raw[2 + i] += plane.len();
        }
        for (i, plane) in lengths.iter().enumerate() {
            plane_raw[6 + i] += plane.len();
        }
        chunk_planes.push(block);
    }

    // C: per layer, its own planes behind a three-varint length header.
    let mut per_layer: Vec<Vec<u8>> = Vec::new();
    for layer in &layers {
        if layer.count == 0 {
            per_layer.push(Vec::new());
            continue;
        }
        let mut counts: [Vec<u8>; 4] = Default::default();
        let mut lengths: [Vec<u8>; 4] = Default::default();
        push_planes(&mut counts, layer.count);
        for length in &layer.lengths {
            push_planes(&mut lengths, u64::from(*length));
        }
        let mut block = vec![layer.tag, layer.first];
        for plane in &lengths {
            push_varint(&mut block, plane.len() as u64);
        }
        for plane in counts.iter().chain(lengths.iter()) {
            block.extend_from_slice(plane);
        }
        per_layer.push(block);
    }
    let per_layer_blocks: Vec<Vec<u8>> = per_layer
        .chunks(CHUNK)
        .map(|group| group.concat())
        .collect();

    let a = compressed(&stored_blocks);
    let b = compressed(&chunk_planes);
    let c = compressed(&per_layer_blocks);
    println!("801-layer print, level {LEVEL}, {CHUNK}-layer groups, no dictionary");
    println!("  raw stored stream          {stored_total:>9} B");
    println!("  A stored layout            {:>8.1} KB", a as f64 / 1e3);
    println!(
        "  B chunk-level planes       {:>8.1} KB  {:.3}x vs A",
        b as f64 / 1e3,
        a as f64 / b as f64
    );
    println!(
        "  C per-layer planes         {:>8.1} KB  {:.3}x vs A",
        c as f64 / 1e3,
        a as f64 / c as f64
    );
    println!(
        "\n  plane raw bytes (B): tags {} firsts {} count planes {:?} length planes {:?}",
        plane_raw[0],
        plane_raw[1],
        &plane_raw[2..6],
        &plane_raw[6..10]
    );

    // Where the win lives: each plane of B compressed on its own.
    let mut tags = Vec::new();
    let mut firsts = Vec::new();
    let mut counts: [Vec<u8>; 4] = Default::default();
    let mut lengths: [Vec<u8>; 4] = Default::default();
    for layer in &layers {
        if layer.count == 0 {
            continue;
        }
        tags.push(layer.tag);
        firsts.push(layer.first);
        push_planes(&mut counts, layer.count);
        for length in &layer.lengths {
            push_planes(&mut lengths, u64::from(*length));
        }
    }
    print!(
        "  per-plane compressed: tags {} firsts {}",
        compressed(&vec![tags; 1]),
        compressed(&vec![firsts; 1])
    );
    for plane in counts.iter() {
        print!(" c{}", compressed(std::slice::from_ref(plane)));
    }
    for plane in lengths.iter() {
        print!(" l{}", compressed(std::slice::from_ref(plane)));
    }
    println!();
}
