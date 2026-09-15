//! Peak memory of validating a file, measured rather than reasoned about.
//!
//! Section 4.11 asks a memory-constrained reader to verify one block at a time -
//! "peak memory is one block plus the leaf hash table, never the whole layer
//! stream". That is a property of *this* implementation too, and an easy one to
//! lose: collecting every decompressed block before checking any of them gives
//! the same answer only while the file is small.
//!
//! So this measures. It installs a counting allocator and compares three peaks:
//! one block decompressed, every block decompressed one after another, and a
//! full validation pass. Validation must cost about what the sequential walk
//! costs, because that is what "one block at a time" means in practice; if the
//! blocks are accumulated instead, the third number grows with the file while the
//! second does not.
//!
//! It lives in its own test binary with a single test, so the high-water mark it
//! reads is not polluted by anything else running concurrently.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use lumen::chunks::hdr::Hdr;
use lumen::container::{self, ChunkType};
use lumen::json::{Meta, Timing};
use lumen::reader::LumenFile;
use lumen::validate::{self, Level};
use lumen::writer::Encoder;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards to the system allocator; the counters are
// bookkeeping around it and never change what is allocated or freed.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        System.dealloc(pointer, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const WIDTH: u32 = 512;
const HEIGHT: u32 = 512;
const PIXELS: usize = (WIDTH * HEIGHT) as usize;
/// Each layer is a ramp, which grayscale REE cannot fold into shared runs: every
/// pixel becomes its own run, so a layer is about two bytes per pixel before zstd.
const LAYERS: u32 = 16;
/// Two layers per block: eight blocks, each eight times smaller than the stream.
const BLOCK_LAYERS: u32 = 2;

/// Run `body` and report the highest number of live bytes it reached.
fn peak_of(body: impl FnOnce()) -> u64 {
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    body();
    PEAK.load(Ordering::SeqCst).saturating_sub(before) as u64
}

#[test]
fn validation_peak_memory_does_not_grow_with_the_file() {
    let bytes = build();
    let file = LumenFile::open(&bytes, Level::Loose).expect("a readable file");

    let total: u64 = file
        .layr()
        .blocks
        .iter()
        .map(|block| block.uncompressed_size)
        .sum();
    let largest = file
        .layr()
        .blocks
        .iter()
        .map(|block| block.uncompressed_size)
        .max()
        .unwrap_or(0);
    let block_count = file.layr().block_count();
    let layr_container = container::parse_directory(&bytes, {
        &container::FileHeader::parse(&bytes).expect("header")
    })
    .expect("directory")
    .find(ChunkType::LAYR)
    .expect("LAYR")
    .stored_len();

    assert_eq!(block_count, LAYERS / BLOCK_LAYERS);
    assert!(
        block_count >= 4 && total >= 3 * largest,
        "the file needs several comparably sized blocks for this to mean \
         anything: {block_count} blocks, total {total}, largest {largest}"
    );

    let one_block = peak_of(|| {
        let block = file.block(0).expect("a readable block");
        assert_eq!(block.len() as u64, largest);
    });
    let sequential = peak_of(|| {
        for index in 0..block_count {
            let block = file.block(index).expect("a readable block");
            assert!(!block.is_empty());
        }
    });
    drop(file);
    let validated = peak_of(|| {
        validate::validate(&bytes, Level::Loose).expect("the file is valid");
    });

    println!(
        "file {} bytes; LAYR container {layr_container}; {block_count} blocks, \
         {total} bytes decompressed, {largest} each",
        bytes.len()
    );
    println!("peak: one block {one_block}, all blocks sequentially {sequential}, full validation {validated}");

    assert!(
        validated <= sequential + largest,
        "validation peaked at {validated} but walking the blocks one at a time \
         peaked at {sequential}: the pass costs more than the walk, so it is \
         holding on to something. One block is {largest}, all {block_count} \
         total {total}."
    );
}

fn build() -> Vec<u8> {
    let mut encoder = Encoder::new(hdr(), meta());
    encoder.set_block_layers(BLOCK_LAYERS);
    encoder.set_dictionary(false);
    encoder.set_layer_hashes(true);
    for index in 0..LAYERS {
        let shift = index as usize;
        let mask: Vec<u8> = (0..PIXELS)
            .map(|i| (((i + shift) % (WIDTH as usize)) * 255 / (WIDTH as usize - 1)) as u8)
            .collect();
        encoder.push_layer(&mask).expect("a pushable layer");
    }
    encoder.finish().expect("a writable file")
}

fn hdr() -> Hdr {
    Hdr {
        hdr_version: 1,
        encoder_name: "peak-memory".to_string(),
        created_unix_sec: 0,
        display_width_px: WIDTH,
        display_height_px: HEIGHT,
        physical_width_px: WIDTH,
        physical_height_px: HEIGHT,
        build_width_um: 1,
        build_depth_um: 1,
        build_height_um: 1,
        layer_height_um: 50,
        total_layers: LAYERS,
    }
}

fn meta() -> Meta {
    Meta {
        meta_version: Some(1),
        timing: Timing {
            layer_height_um: Some(50),
            normal_exposure_ms: Some(2500),
            bottom_exposure_ms: Some(30000),
            bottom_layer_count: Some(1),
            transition_layer_count: Some(1),
            lift_slow_distance_um: Some(5000),
            lift_slow_speed_um_min: Some(65_000),
            retract_fast_distance_um: Some(5000),
            retract_fast_speed_um_min: Some(150_000),
            ..Timing::default()
        },
        ..Meta::default()
    }
}
