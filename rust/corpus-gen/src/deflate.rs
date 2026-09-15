//! A dependency-free port of zlib 1.3.1's level-9 deflate path.
//!
//! [`zlib_compress`] reproduces, byte for byte, what zlib 1.3.1's `deflate()`
//! emits for `level = 9`, `windowBits = 15`, `memLevel = 8`,
//! `strategy = Z_DEFAULT_STRATEGY` and a single `Z_FINISH` call on all of the
//! input: one RFC 1950 stream, i.e. a two-byte header, the DEFLATE data and
//! the big-endian Adler-32 of the uncompressed input.
//!
//! This is a faithful port of the following upstream sources:
//!
//! * <https://raw.githubusercontent.com/madler/zlib/v1.3.1/deflate.c>
//!   (`configuration_table[9]`, `lm_init`, `longest_match`, `fill_window`,
//!   `deflate_slow`, `INSERT_STRING`, the zlib header of `deflate()`)
//! * <https://raw.githubusercontent.com/madler/zlib/v1.3.1/trees.c>
//!   (the whole Huffman machinery: `_tr_init`, `init_block`, `pqdownheap`,
//!   `gen_bitlen`, `build_tree`, `scan_tree`, `send_tree`, `build_bl_tree`,
//!   `send_all_trees`, `compress_block`, `_tr_stored_block`,
//!   `_tr_flush_block`, `_tr_tally`, `bi_reverse`, `bi_windup`,
//!   `tr_static_init`)
//! * <https://raw.githubusercontent.com/madler/zlib/v1.3.1/deflate.h>
//!   (`deflate_state`, `MAX_DIST`, `MIN_LOOKAHEAD`, `d_code`, the LIT_MEM-less
//!   variants of `_tr_tally_lit`/`_tr_tally_dist`)
//! * <https://raw.githubusercontent.com/madler/zlib/v1.3.1/zutil.h>
//!   (`ulg` is `unsigned long`, i.e. 32 bits on the reference builds; the
//!   `opt_len`/`static_len` accumulators below therefore wrap at 32 bits)
//!
//! Only the one-shot `Z_FINISH` path is ported. The whole input is handed to
//! the encoder at once, so the sliding window, the `insert` bookkeeping used
//! when input arrives over several `deflate()` calls, and the
//! `need_more`/`finish_started` block states are unobservable here:
//! `fill_window` degenerates to a no-op because every input byte is already in
//! the window (which is zero padded past the end of the data, exactly like the
//! `high_water` zeroing in the C does for `WIN_INIT` bytes).
//!
//! The window never slides, so positions are absolute. That is equivalent to
//! the C: `head[]`/`prev[]` are indexed modulo `w_size` and chain traversal
//! stops as soon as a candidate is `<= limit` (`strstart - MAX_DIST`), which is
//! precisely where the C's chain ends after `slide_hash()` has rewritten the
//! links that fell out of the window to `NIL`.
//!
//! Pure `std`, no `unsafe`.

/* ===========================================================================
 * This file is an altered version of zlib 1.3.1 - a Rust reimplementation of its
 * one-shot level-9 deflate path, not the original software. zlib is
 * Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler, and the upstream
 * sources this is ported from are named in the module documentation above.
 *
 *   This software is provided 'as-is', without any express or implied warranty.
 *   In no event will the authors be held liable for any damages arising from the
 *   use of this software.
 *
 *   Permission is granted to anyone to use this software for any purpose,
 *   including commercial applications, and to alter it and redistribute it
 *   freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must not claim
 *      that you wrote the original software. If you use this software in a
 *      product, an acknowledgment in the product documentation would be
 *      appreciated but is not required.
 *   2. Altered source versions must be plainly marked as such, and must not be
 *      misrepresented as being the original software.
 *   3. This notice may not be removed or altered from any source distribution.
 * ===========================================================================
 */

use std::sync::LazyLock;

/* ===========================================================================
 * Constants (deflate.h, trees.c, deflate.c)
 */

/// `MIN_MATCH`: the shortest match the encoder looks for.
const MIN_MATCH: usize = 3;
/// `MAX_MATCH`: the longest match the DEFLATE format allows.
const MAX_MATCH: usize = 258;
/// `MIN_LOOKAHEAD` = `MAX_MATCH + MIN_MATCH + 1`.
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
/// `w_size` for `windowBits = 15`.
const W_SIZE: usize = 32768;
/// `w_mask` = `w_size - 1`: `prev[]` is indexed modulo `w_size`.
const W_MASK: usize = W_SIZE - 1;
/// `MAX_DIST` = `w_size - MIN_LOOKAHEAD`: the longest allowed match distance.
const MAX_DIST: usize = W_SIZE - MIN_LOOKAHEAD;
/// `TOO_FAR`: matches of length 3 are discarded beyond this distance.
const TOO_FAR: usize = 4096;
/// `NIL`: tail of the hash chains.
const NIL: u32 = 0;
/// `hash_bits` = `memLevel + 7` for `memLevel = 8`.
const HASH_BITS: u32 = 15;
/// `hash_size` = `1 << hash_bits`.
const HASH_SIZE: usize = 1 << HASH_BITS;
/// `hash_mask` = `hash_size - 1`.
const HASH_MASK: u32 = (HASH_SIZE - 1) as u32;
/// `hash_shift` = `(hash_bits + MIN_MATCH - 1) / MIN_MATCH`.
const HASH_SHIFT: u32 = HASH_BITS.div_ceil(MIN_MATCH as u32);

/// `configuration_table[9]` = `{good_length, max_lazy, nice_length, max_chain}`.
const GOOD_MATCH: usize = 32;
const MAX_LAZY_MATCH: usize = 258;
const NICE_MATCH: usize = 258;
const MAX_CHAIN_LENGTH: usize = 4096;

/// `lit_bufsize` = `1 << (memLevel + 6)` for `memLevel = 8`.
const LIT_BUFSIZE: usize = 1 << 14;
/// `sym_end` = `(lit_bufsize - 1) * 3`: a block flushes when the symbol buffer
/// is full.
const SYM_END: usize = (LIT_BUFSIZE - 1) * 3;
/// Size of the symbol buffer (`lit_bufsize * 3` bytes in the C).
const SYM_BUF_SIZE: usize = LIT_BUFSIZE * 3;

/// `LENGTH_CODES`.
const LENGTH_CODES: usize = 29;
/// `LITERALS`.
const LITERALS: usize = 256;
/// `L_CODES` = `LITERALS + 1 + LENGTH_CODES`.
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
/// `D_CODES`.
const D_CODES: usize = 30;
/// `BL_CODES`.
const BL_CODES: usize = 19;
/// `HEAP_SIZE` = `2 * L_CODES + 1`.
const HEAP_SIZE: usize = 2 * L_CODES + 1;
/// `MAX_BITS`.
const MAX_BITS: usize = 15;
/// `MAX_BL_BITS`.
const MAX_BL_BITS: usize = 7;
/// `END_BLOCK`.
const END_BLOCK: usize = 256;
/// `REP_3_6`: repeat previous bit length 3-6 times.
const REP_3_6: usize = 16;
/// `REPZ_3_10`: repeat a zero length 3-10 times.
const REPZ_3_10: usize = 17;
/// `REPZ_11_138`: repeat a zero length 11-138 times.
const REPZ_11_138: usize = 18;

/// `STORED_BLOCK`, `STATIC_TREES`, `DYN_TREES` (block type codes).
const STORED_BLOCK: u32 = 0;
const STATIC_TREES: u32 = 1;
const DYN_TREES: u32 = 2;

/// `SMALLEST`: index within the heap of the least frequent node.
const SMALLEST: i32 = 1;

/// `extra_lbits`.
const EXTRA_LBITS: [i32; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// `extra_dbits`.
const EXTRA_DBITS: [i32; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// `extra_blbits`.
const EXTRA_BLBITS: [i32; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
/// `bl_order`.
const BL_ORDER: [usize; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Zero padding kept past the end of the input so `longest_match` may scan up
/// to `strstart + MAX_MATCH`, like the C reads into its equal `WIN_INIT`
/// region.
const WINDOW_PAD: usize = MAX_MATCH + 16;

/* ===========================================================================
 * Static tables (trees.c: tr_static_init)
 */

/// One `ct_data` node: `fc.freq`/`fc.code` and `dl.dad`/`dl.len` are unions in
/// the C; all four are kept here.
#[derive(Clone, Copy, Default)]
struct Ct {
    freq: u16,
    code: u16,
    dad: u16,
    len: u16,
}

/// The tables `tr_static_init()` builds once: the static literal and distance
/// trees, and the length/distance code mappings.
struct StaticTables {
    static_ltree: [Ct; L_CODES + 2],
    static_dtree: [Ct; D_CODES],
    dist_code: [u8; 512],
    length_code: [u8; MAX_MATCH - MIN_MATCH + 1],
    base_length: [i32; LENGTH_CODES],
    base_dist: [i32; D_CODES],
}

/// The static tables, built once per process by [`StaticTables::new`].
static STATIC_TABLES: LazyLock<StaticTables> = LazyLock::new(StaticTables::new);

/// The static tables.
fn static_tables() -> &'static StaticTables {
    &STATIC_TABLES
}

/// `bi_reverse`: reverse the first `len` bits of `code`.
fn bi_reverse(mut code: u32, mut len: i32) -> u32 {
    let mut res: u32 = 0;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len <= 0 {
            break;
        }
    }
    res >> 1
}

/// `gen_codes`: turn bit lengths into canonical (bit reversed) codes.
fn gen_codes(tree: &mut [Ct], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code: u32 = 0;
    for bits in 1..=MAX_BITS {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code as u16;
    }
    for node in tree.iter_mut().take(max_code + 1) {
        let len = node.len;
        if len == 0 {
            continue;
        }
        node.code = bi_reverse(next_code[len as usize] as u32, len as i32) as u16;
        next_code[len as usize] += 1;
    }
}

impl StaticTables {
    /// Port of `tr_static_init()`.
    fn new() -> Self {
        let mut length_code = [0u8; MAX_MATCH - MIN_MATCH + 1];
        let mut base_length = [0i32; LENGTH_CODES];
        let mut length = 0usize;
        let mut code = 0usize;
        while code < LENGTH_CODES - 1 {
            base_length[code] = length as i32;
            for _ in 0..(1 << EXTRA_LBITS[code]) {
                length_code[length] = code as u8;
                length += 1;
            }
            code += 1;
        }
        // Match length 258 can be encoded two ways; the last entry is
        // overwritten to use the best encoding (code 285).
        length_code[length - 1] = code as u8;

        let mut dist_code = [0u8; 512];
        let mut base_dist = [0i32; D_CODES];
        let mut dist = 0usize;
        for code in 0..16 {
            base_dist[code] = dist as i32;
            for _ in 0..(1 << EXTRA_DBITS[code]) {
                dist_code[dist] = code as u8;
                dist += 1;
            }
        }
        dist >>= 7; // from now on, all distances are divided by 128
        for code in 16..D_CODES {
            base_dist[code] = (dist << 7) as i32;
            for _ in 0..(1 << (EXTRA_DBITS[code] - 7)) {
                dist_code[256 + dist] = code as u8;
                dist += 1;
            }
        }

        let mut static_ltree = [Ct::default(); L_CODES + 2];
        let mut bl_count = [0u16; MAX_BITS + 1];
        let mut n = 0usize;
        while n <= 143 {
            static_ltree[n].len = 8;
            bl_count[8] += 1;
            n += 1;
        }
        while n <= 255 {
            static_ltree[n].len = 9;
            bl_count[9] += 1;
            n += 1;
        }
        while n <= 279 {
            static_ltree[n].len = 7;
            bl_count[7] += 1;
            n += 1;
        }
        while n <= 287 {
            static_ltree[n].len = 8;
            bl_count[8] += 1;
            n += 1;
        }
        gen_codes(&mut static_ltree, L_CODES + 1, &bl_count);

        let mut static_dtree = [Ct::default(); D_CODES];
        for (n, node) in static_dtree.iter_mut().enumerate() {
            node.len = 5;
            node.code = bi_reverse(n as u32, 5) as u16;
        }

        Self {
            static_ltree,
            static_dtree,
            dist_code,
            length_code,
            base_length,
            base_dist,
        }
    }
}

/// `d_code(dist)`: map a distance-1 to its distance code.
fn d_code(dist: usize) -> usize {
    let t = static_tables();
    if dist < 256 {
        t.dist_code[dist] as usize
    } else {
        t.dist_code[256 + (dist >> 7)] as usize
    }
}

/// Adler-32 (RFC 1950), the checksum zlib appends to a `wrap == 1` stream.
fn adler32(data: &[u8]) -> u32 {
    const BASE: u32 = 65521;
    const NMAX: usize = 5552; // largest n with 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= BASE;
        b %= BASE;
    }
    (b << 16) | a
}

/* ===========================================================================
 * Bit output (trees.c: send_bits, put_short, bi_flush, bi_windup)
 */

/// The bit/window half of `deflate_state`: `pending_buf` plus the bit buffer.
struct BitWriter {
    out: Vec<u8>,
    bi_buf: u16,
    bi_valid: i32,
}

impl BitWriter {
    fn new(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
            bi_buf: 0,
            bi_valid: 0,
        }
    }

    /// `put_byte`.
    fn put_byte(&mut self, c: u8) {
        self.out.push(c);
    }

    /// `put_short`: output a short LSB first.
    fn put_short(&mut self, w: u16) {
        self.put_byte((w & 0xff) as u8);
        self.put_byte((w >> 8) as u8);
    }

    /// `putShortMSB`: output a short MSB first (used by the zlib wrapper).
    fn put_short_msb(&mut self, w: u16) {
        self.put_byte((w >> 8) as u8);
        self.put_byte((w & 0xff) as u8);
    }

    /// `send_bits`: send `value` on `length` bits, LSB first.
    fn send_bits(&mut self, value: u32, length: i32) {
        if self.bi_valid > 16 - length {
            self.bi_buf |= (((value & 0xffff) << self.bi_valid) & 0xffff) as u16;
            self.put_short(self.bi_buf);
            self.bi_buf = ((value & 0xffff) >> (16 - self.bi_valid)) as u16;
            self.bi_valid += length - 16;
        } else {
            self.bi_buf |= (((value & 0xffff) << self.bi_valid) & 0xffff) as u16;
            self.bi_valid += length;
        }
    }

    /// `send_code`.
    fn send_code(&mut self, c: Ct) {
        self.send_bits(c.code as u32, c.len as i32);
    }

    /// `bi_windup`: flush the bit buffer and align on a byte boundary.
    fn bi_windup(&mut self) {
        if self.bi_valid > 8 {
            let buf = self.bi_buf;
            self.put_short(buf);
        } else if self.bi_valid > 0 {
            let byte = self.bi_buf as u8;
            self.put_byte(byte);
        }
        self.bi_buf = 0;
        self.bi_valid = 0;
    }
}

/* ===========================================================================
 * Huffman coding (trees.c)
 */

/// Which of the three trees of a block a routine works on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TreeKind {
    /// `dyn_ltree` (`l_desc`).
    Lit,
    /// `dyn_dtree` (`d_desc`).
    Dist,
    /// `bl_tree` (`bl_desc`).
    Bl,
}

impl TreeKind {
    fn idx(self) -> usize {
        match self {
            TreeKind::Lit => 0,
            TreeKind::Dist => 1,
            TreeKind::Bl => 2,
        }
    }
}

/// The `trees.c` half of `deflate_state`.
struct Trees {
    dyn_ltree: [Ct; HEAP_SIZE],
    dyn_dtree: [Ct; 2 * D_CODES + 1],
    bl_tree: [Ct; 2 * BL_CODES + 1],
    /// `sym_buf`, the `(dist, len)` symbol buffer.
    sym_buf: Vec<u8>,
    /// `sym_next`.
    sym_next: usize,
    /// `max_code` of each tree, set by `build_tree`.
    max_code: [i32; 3],
    heap: [i32; HEAP_SIZE],
    heap_len: i32,
    heap_max: i32,
    depth: [u8; HEAP_SIZE],
    bl_count: [u16; MAX_BITS + 1],
    opt_len: u32,
    static_len: u32,
}

impl Trees {
    fn new() -> Self {
        let mut trees = Self {
            dyn_ltree: [Ct::default(); HEAP_SIZE],
            dyn_dtree: [Ct::default(); 2 * D_CODES + 1],
            bl_tree: [Ct::default(); 2 * BL_CODES + 1],
            sym_buf: vec![0u8; SYM_BUF_SIZE],
            sym_next: 0,
            max_code: [-1; 3],
            heap: [0; HEAP_SIZE],
            heap_len: 0,
            heap_max: 0,
            depth: [0; HEAP_SIZE],
            bl_count: [0; MAX_BITS + 1],
            opt_len: 0,
            static_len: 0,
        };
        trees.init_block();
        trees
    }

    fn tree(&self, kind: TreeKind) -> &[Ct] {
        match kind {
            TreeKind::Lit => &self.dyn_ltree,
            TreeKind::Dist => &self.dyn_dtree,
            TreeKind::Bl => &self.bl_tree,
        }
    }

    fn tree_mut(&mut self, kind: TreeKind) -> &mut [Ct] {
        match kind {
            TreeKind::Lit => &mut self.dyn_ltree,
            TreeKind::Dist => &mut self.dyn_dtree,
            TreeKind::Bl => &mut self.bl_tree,
        }
    }

    /// `init_block`: start a new block.
    fn init_block(&mut self) {
        for n in 0..L_CODES {
            self.dyn_ltree[n].freq = 0;
        }
        for n in 0..D_CODES {
            self.dyn_dtree[n].freq = 0;
        }
        for n in 0..BL_CODES {
            self.bl_tree[n].freq = 0;
        }
        self.dyn_ltree[END_BLOCK].freq = 1;
        self.opt_len = 0;
        self.static_len = 0;
        self.sym_next = 0;
    }

    /// `_tr_tally_lit`: save an unmatched byte and tally its frequency.
    /// Returns `true` if the current block must be flushed.
    fn tally_lit(&mut self, c: u8) -> bool {
        self.sym_buf[self.sym_next] = 0;
        self.sym_buf[self.sym_next + 1] = 0;
        self.sym_buf[self.sym_next + 2] = c;
        self.sym_next += 3;
        self.dyn_ltree[c as usize].freq += 1;
        self.sym_next == SYM_END
    }

    /// `_tr_tally_dist`: save a match and tally the length/distance codes.
    /// Returns `true` if the current block must be flushed.
    fn tally_dist(&mut self, distance: usize, length: usize) -> bool {
        let dist = distance as u16;
        self.sym_buf[self.sym_next] = (dist & 0xff) as u8;
        self.sym_buf[self.sym_next + 1] = (dist >> 8) as u8;
        self.sym_buf[self.sym_next + 2] = length as u8;
        self.sym_next += 3;
        let dist = (dist - 1) as usize;
        self.dyn_ltree[static_tables().length_code[length] as usize + LITERALS + 1].freq += 1;
        self.dyn_dtree[d_code(dist)].freq += 1;
        self.sym_next == SYM_END
    }

    /// `smaller`: compare two subtrees, using the tree depth as tie breaker.
    fn smaller(&self, kind: TreeKind, n: i32, m: i32) -> bool {
        let tree = self.tree(kind);
        let (n, m) = (n as usize, m as usize);
        tree[n].freq < tree[m].freq
            || (tree[n].freq == tree[m].freq && self.depth[n] <= self.depth[m])
    }

    /// `pqdownheap`: restore the heap property below node `k`.
    fn pqdownheap(&mut self, kind: TreeKind, k: i32) {
        let v = self.heap[k as usize];
        let mut k = k;
        let mut j = k << 1;
        while j <= self.heap_len {
            if j < self.heap_len {
                let right = self.heap[(j + 1) as usize];
                let left = self.heap[j as usize];
                if self.smaller(kind, right, left) {
                    j += 1;
                }
            }
            let jnode = self.heap[j as usize];
            if self.smaller(kind, v, jnode) {
                break;
            }
            self.heap[k as usize] = jnode;
            k = j;
            j <<= 1;
        }
        self.heap[k as usize] = v;
    }

    /// `gen_bitlen`: compute the optimal bit lengths of a tree and add to the
    /// block's `opt_len`/`static_len`.
    fn gen_bitlen(&mut self, kind: TreeKind, max_code: usize) {
        let t = static_tables();
        let (stree, extra): (Option<&[Ct]>, &[i32]) = match kind {
            TreeKind::Lit => (Some(&t.static_ltree), &EXTRA_LBITS),
            TreeKind::Dist => (Some(&t.static_dtree), &EXTRA_DBITS),
            TreeKind::Bl => (None, &EXTRA_BLBITS),
        };
        let max_length = match kind {
            TreeKind::Bl => MAX_BL_BITS as i32,
            _ => MAX_BITS as i32,
        };
        let base = match kind {
            TreeKind::Lit => LITERALS + 1,
            _ => 0,
        };

        for b in self.bl_count.iter_mut() {
            *b = 0;
        }
        let root = self.heap[self.heap_max as usize] as usize;
        self.tree_mut(kind)[root].len = 0; // root of the heap

        let mut overflow = 0i32;
        let mut h = self.heap_max + 1;
        while h < HEAP_SIZE as i32 {
            let n = self.heap[h as usize];
            h += 1;
            let dad = self.tree(kind)[n as usize].dad as usize;
            let mut bits = self.tree(kind)[dad].len as i32 + 1;
            if bits > max_length {
                bits = max_length;
                overflow += 1;
            }
            self.tree_mut(kind)[n as usize].len = bits as u16;
            // tree[n].Dad is overwritten above and no longer needed.
            if n as usize > max_code {
                continue;
            }
            self.bl_count[bits as usize] += 1;
            let xbits = if n as usize >= base {
                extra[n as usize - base]
            } else {
                0
            };
            let f = self.tree(kind)[n as usize].freq as u32;
            self.opt_len = self
                .opt_len
                .wrapping_add(f.wrapping_mul(bits as u32 + xbits as u32));
            if let Some(stree) = stree {
                self.static_len = self
                    .static_len
                    .wrapping_add(f.wrapping_mul(stree[n as usize].len as u32 + xbits as u32));
            }
        }
        if overflow == 0 {
            return;
        }

        // Find the first bit length which could increase, and rebalance.
        loop {
            let mut bits = max_length - 1;
            while self.bl_count[bits as usize] == 0 {
                bits -= 1;
            }
            self.bl_count[bits as usize] -= 1; // move one leaf down the tree
            self.bl_count[(bits + 1) as usize] += 2; // move one overflow item as its brother
            self.bl_count[max_length as usize] -= 1;
            overflow -= 2;
            if overflow <= 0 {
                break;
            }
        }

        // Recompute all bit lengths, scanning in increasing frequency.
        let mut h = HEAP_SIZE as i32;
        let mut bits = max_length;
        while bits != 0 {
            let mut n = self.bl_count[bits as usize];
            while n != 0 {
                h -= 1;
                let m = self.heap[h as usize];
                if m as usize > max_code {
                    continue;
                }
                if self.tree(kind)[m as usize].len as i32 != bits {
                    let delta = (bits as u32).wrapping_sub(self.tree(kind)[m as usize].len as u32);
                    self.opt_len = self
                        .opt_len
                        .wrapping_add(delta.wrapping_mul(self.tree(kind)[m as usize].freq as u32));
                    self.tree_mut(kind)[m as usize].len = bits as u16;
                }
                n -= 1;
            }
            bits -= 1;
        }
    }

    /// `build_tree`: build one Huffman tree and assign the code bit strings.
    fn build_tree(&mut self, kind: TreeKind) {
        let elems = match kind {
            TreeKind::Lit => L_CODES,
            TreeKind::Dist => D_CODES,
            TreeKind::Bl => BL_CODES,
        };
        let mut max_code: i32 = -1;
        self.heap_len = 0;
        self.heap_max = HEAP_SIZE as i32;

        for n in 0..elems {
            if self.tree(kind)[n].freq != 0 {
                self.heap_len += 1;
                self.heap[self.heap_len as usize] = n as i32;
                max_code = n as i32;
                self.depth[n] = 0;
            } else {
                self.tree_mut(kind)[n].len = 0;
            }
        }

        // The pkzip format requires at least one distance code, and at least
        // one bit sent even if there is only one possible code, so force at
        // least two codes of non zero frequency.
        while self.heap_len < 2 {
            self.heap_len += 1;
            let node = if max_code < 2 {
                max_code += 1;
                max_code
            } else {
                0
            };
            self.heap[self.heap_len as usize] = node;
            self.tree_mut(kind)[node as usize].freq = 1;
            self.depth[node as usize] = 0;
            // The forced node is not a real code: undo its contribution. The
            // C does this with plain (wrapping) `ulg` arithmetic, and the
            // matching addition in gen_bitlen cancels it out.
            self.opt_len = self.opt_len.wrapping_sub(1);
            if kind != TreeKind::Bl {
                self.static_len = self
                    .static_len
                    .wrapping_sub(static_tree(kind)[node as usize].len as u32);
            }
        }
        self.max_code[kind.idx()] = max_code;

        // Establish sub-heaps of increasing lengths.
        for n in (1..=(self.heap_len / 2)).rev() {
            self.pqdownheap(kind, n);
        }

        // Construct the Huffman tree by combining the least two frequent nodes.
        let mut node = elems as i32;
        loop {
            // pqremove: n = node of least frequency.
            let n = self.heap[SMALLEST as usize];
            let last = self.heap[self.heap_len as usize];
            self.heap_len -= 1;
            self.heap[SMALLEST as usize] = last;
            self.pqdownheap(kind, SMALLEST);
            let m = self.heap[SMALLEST as usize];

            self.heap_max -= 1;
            self.heap[self.heap_max as usize] = n; // keep the nodes sorted by frequency
            self.heap_max -= 1;
            self.heap[self.heap_max as usize] = m;

            let f = self.tree(kind)[n as usize].freq + self.tree(kind)[m as usize].freq;
            self.tree_mut(kind)[node as usize].freq = f;
            let dn = self.depth[n as usize];
            let dm = self.depth[m as usize];
            self.depth[node as usize] = (if dn >= dm { dn } else { dm }) + 1;
            self.tree_mut(kind)[n as usize].dad = node as u16;
            self.tree_mut(kind)[m as usize].dad = node as u16;

            // and insert the new node in the heap
            self.heap[SMALLEST as usize] = node;
            node += 1;
            self.pqdownheap(kind, SMALLEST);

            if self.heap_len < 2 {
                break;
            }
        }

        self.heap_max -= 1;
        let root = self.heap[SMALLEST as usize];
        self.heap[self.heap_max as usize] = root;

        self.gen_bitlen(kind, max_code as usize);
        let bl_count = self.bl_count;
        gen_codes(self.tree_mut(kind), max_code as usize, &bl_count);
    }

    /// `scan_tree`: tally the frequencies of the codes in the bit length tree.
    fn scan_tree(&mut self, kind: TreeKind, max_code: usize) {
        let mut prevlen: i32 = -1;
        let mut count: i32 = 0;
        let mut max_count: i32 = 7;
        let mut min_count: i32 = 4;
        let mut nextlen = self.tree(kind)[0].len as i32;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }
        self.tree_mut(kind)[max_code + 1].len = 0xffff; // guard

        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = self.tree(kind)[n + 1].len as i32;
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                self.bl_tree[curlen as usize].freq += count as u16;
            } else if curlen != 0 {
                if curlen != prevlen {
                    self.bl_tree[curlen as usize].freq += 1;
                }
                self.bl_tree[REP_3_6].freq += 1;
            } else if count <= 10 {
                self.bl_tree[REPZ_3_10].freq += 1;
            } else {
                self.bl_tree[REPZ_11_138].freq += 1;
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }
    }

    /// `send_tree`: send a literal or distance tree in compressed form.
    fn send_tree(&mut self, w: &mut BitWriter, kind: TreeKind, max_code: usize) {
        let mut prevlen: i32 = -1;
        let mut count: i32 = 0;
        let mut max_count: i32 = 7;
        let mut min_count: i32 = 4;
        let mut nextlen = self.tree(kind)[0].len as i32;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }

        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = self.tree(kind)[n + 1].len as i32;
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                loop {
                    w.send_code(self.bl_tree[curlen as usize]);
                    count -= 1;
                    if count == 0 {
                        break;
                    }
                }
            } else if curlen != 0 {
                if curlen != prevlen {
                    w.send_code(self.bl_tree[curlen as usize]);
                    count -= 1;
                }
                w.send_code(self.bl_tree[REP_3_6]);
                w.send_bits((count - 3) as u32, 2);
            } else if count <= 10 {
                w.send_code(self.bl_tree[REPZ_3_10]);
                w.send_bits((count - 3) as u32, 3);
            } else {
                w.send_code(self.bl_tree[REPZ_11_138]);
                w.send_bits((count - 11) as u32, 7);
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }
    }

    /// `build_bl_tree`: build the bit length tree, returning the index in
    /// `bl_order` of the last bit length code to send.
    fn build_bl_tree(&mut self) -> usize {
        let l_max = self.max_code[TreeKind::Lit.idx()] as usize;
        let d_max = self.max_code[TreeKind::Dist.idx()] as usize;
        self.scan_tree(TreeKind::Lit, l_max);
        self.scan_tree(TreeKind::Dist, d_max);

        self.build_tree(TreeKind::Bl);

        // The pkzip format requires that at least 4 bit length codes be sent.
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 {
            if self.bl_tree[BL_ORDER[max_blindex]].len != 0 {
                break;
            }
            max_blindex -= 1;
        }
        // Update opt_len to include the bit length tree and counts.
        self.opt_len = self
            .opt_len
            .wrapping_add(3 * (max_blindex as u32 + 1) + 5 + 5 + 4);
        max_blindex
    }

    /// `send_all_trees`: send the header of a dynamic block.
    fn send_all_trees(&mut self, w: &mut BitWriter, lcodes: usize, dcodes: usize, blcodes: usize) {
        w.send_bits((lcodes - 257) as u32, 5);
        w.send_bits((dcodes - 1) as u32, 5);
        w.send_bits((blcodes - 4) as u32, 4);
        for &code in BL_ORDER.iter().take(blcodes) {
            w.send_bits(self.bl_tree[code].len as u32, 3);
        }
        self.send_tree(w, TreeKind::Lit, lcodes - 1);
        self.send_tree(w, TreeKind::Dist, dcodes - 1);
    }

    /// `compress_block`: send the block data using the given trees.
    fn compress_block(&mut self, w: &mut BitWriter, use_static: bool) {
        let t = static_tables();
        let (ltree, dtree): (&[Ct], &[Ct]) = if use_static {
            (&t.static_ltree, &t.static_dtree)
        } else {
            (&self.dyn_ltree, &self.dyn_dtree)
        };

        let mut sx = 0usize;
        if self.sym_next != 0 {
            loop {
                let dist = self.sym_buf[sx] as u32 + ((self.sym_buf[sx + 1] as u32) << 8);
                let lc = self.sym_buf[sx + 2] as usize;
                sx += 3;
                if dist == 0 {
                    w.send_code(ltree[lc]); // send a literal byte
                } else {
                    // Here, lc is the match length - MIN_MATCH.
                    let code = t.length_code[lc] as usize;
                    w.send_code(ltree[code + LITERALS + 1]); // send length code
                    let extra = EXTRA_LBITS[code];
                    if extra != 0 {
                        w.send_bits(lc as u32 - t.base_length[code] as u32, extra);
                    }
                    let dist = dist - 1; // dist is now the match distance - 1
                    let code = d_code(dist as usize);
                    w.send_code(dtree[code]); // send the distance code
                    let extra = EXTRA_DBITS[code];
                    if extra != 0 {
                        w.send_bits(dist - t.base_dist[code] as u32, extra);
                    }
                }
                if sx >= self.sym_next {
                    break;
                }
            }
        }
        w.send_code(ltree[END_BLOCK]);
    }

    /// `_tr_stored_block`: send a stored block.
    fn tr_stored_block(&mut self, w: &mut BitWriter, buf: &[u8], stored_len: usize, last: bool) {
        w.send_bits(STORED_BLOCK << 1 | last as u32, 3); // send block type
        w.bi_windup(); // align on byte boundary
        w.put_short(stored_len as u16);
        w.put_short(!(stored_len as u16));
        w.out.extend_from_slice(buf);
    }

    /// `_tr_flush_block`: choose the best encoding for the current block
    /// (stored, static or dynamic) and write it out.
    fn flush_block(&mut self, w: &mut BitWriter, buf: &[u8], stored_len: usize, last: bool) {
        // level 9 > 0: always build the Huffman trees.
        self.build_tree(TreeKind::Lit);
        self.build_tree(TreeKind::Dist);
        let max_blindex = self.build_bl_tree();

        // Determine the best encoding; compute the block lengths in bytes.
        let mut opt_lenb = self.opt_len.wrapping_add(3 + 7) >> 3;
        let static_lenb = self.static_len.wrapping_add(3 + 7) >> 3;
        // Z_FIXED is not used, so only the plain length comparison applies.
        if static_lenb <= opt_lenb {
            opt_lenb = static_lenb;
        }

        if stored_len as u32 + 4 <= opt_lenb {
            // 4: two words for the lengths
            self.tr_stored_block(w, buf, stored_len, last);
        } else if static_lenb == opt_lenb {
            w.send_bits(STATIC_TREES << 1 | last as u32, 3);
            self.compress_block(w, true);
        } else {
            w.send_bits(DYN_TREES << 1 | last as u32, 3);
            self.send_all_trees(
                w,
                self.max_code[TreeKind::Lit.idx()] as usize + 1,
                self.max_code[TreeKind::Dist.idx()] as usize + 1,
                max_blindex + 1,
            );
            self.compress_block(w, false);
        }
        self.init_block();

        if last {
            w.bi_windup();
        }
    }
}

/// The static tree of a kind, used by `build_tree`'s forced node handling.
fn static_tree(kind: TreeKind) -> &'static [Ct] {
    let t = static_tables();
    match kind {
        TreeKind::Lit => &t.static_ltree,
        TreeKind::Dist => &t.static_dtree,
        TreeKind::Bl => &[],
    }
}

/* ===========================================================================
 * LZ77 (deflate.c)
 */

/// The `deflate.c` half of `deflate_state`, for the one-shot `Z_FINISH` path.
struct Deflater {
    /// The C's sliding window, held as an absolute-positioned flat window with
    /// zero padding past the end of the data.
    window: Vec<u8>,
    /// Heads of the hash chains (`NIL` when empty).
    head: Vec<u32>,
    /// Links to older strings with the same hash index, indexed by position
    /// modulo `w_size`.
    prev: Vec<u32>,
    /// `ins_h`: running hash index.
    ins_h: u32,
    /// `strstart`: start of the string being matched.
    strstart: usize,
    /// `lookahead`: number of valid bytes ahead of `strstart`.
    lookahead: usize,
    /// `block_start`: window position at the beginning of the current block.
    block_start: usize,
    /// `match_start`: start of the matching string.
    match_start: usize,
    /// `match_length`: length of the best match at the current position.
    match_length: usize,
    /// `prev_match`: previous match position.
    prev_match: usize,
    /// `prev_length`: length of the best match at the previous step.
    prev_length: usize,
    /// `match_available`: set if a previous match exists.
    match_available: bool,
    trees: Trees,
}

impl Deflater {
    /// `deflateInit2` + `deflateReset` + `lm_init` for level 9, then the first
    /// (and only) `fill_window`, which loads the whole input.
    fn new(data: &[u8]) -> Self {
        let mut window = Vec::with_capacity(data.len() + WINDOW_PAD);
        window.extend_from_slice(data);
        window.resize(data.len() + WINDOW_PAD, 0); // WIN_INIT zeroing

        // fill_window() folds the first MIN_MATCH-1 bytes into the running
        // hash value as soon as MIN_MATCH bytes are available. `insert` is 0
        // on this first call, so only those seed bytes are mixed in here; the
        // third one is folded in by the first INSERT_STRING.
        let ins_h = if data.len() >= MIN_MATCH {
            (((window[0] as u32) << HASH_SHIFT) ^ (window[1] as u32)) & HASH_MASK
        } else {
            0
        };

        Self {
            window,
            head: vec![NIL; HASH_SIZE], // CLEAR_HASH
            prev: vec![NIL; W_SIZE],    // initialized on the fly in the C
            ins_h,
            strstart: 0,
            lookahead: data.len(),
            block_start: 0,
            match_start: 0,
            // lm_init: match_length = prev_length = MIN_MATCH-1
            match_length: MIN_MATCH - 1,
            prev_match: 0,
            prev_length: MIN_MATCH - 1,
            match_available: false,
            trees: Trees::new(),
        }
    }

    /// `INSERT_STRING`: insert `s` into the dictionary and return the previous
    /// head of its hash chain.
    fn insert_string(&mut self, s: usize) -> usize {
        self.ins_h =
            ((self.ins_h << HASH_SHIFT) ^ (self.window[s + MIN_MATCH - 1] as u32)) & HASH_MASK;
        let hash_head = self.head[self.ins_h as usize];
        self.prev[s & W_MASK] = hash_head;
        self.head[self.ins_h as usize] = s as u32;
        hash_head as usize
    }

    /// `longest_match`: set `match_start` to the longest match at `strstart`
    /// and return its length. Matches shorter or equal to `prev_length` are
    /// discarded, in which case the result is `prev_length`.
    fn longest_match(&mut self, cur_match: usize) -> usize {
        let mut chain_length = MAX_CHAIN_LENGTH;
        let mut best_len = self.prev_length;
        let mut nice_match = NICE_MATCH;
        let limit = if self.strstart > MAX_DIST {
            self.strstart - MAX_DIST
        } else {
            NIL as usize
        };
        // Stop when cur_match becomes <= limit; string 0 never matches.
        let strend = self.strstart + MAX_MATCH;
        let mut scan_end1 = self.window[self.strstart + best_len - 1];
        let mut scan_end = self.window[self.strstart + best_len];

        // Do not waste too much time if we already have a good match.
        if self.prev_length >= GOOD_MATCH {
            chain_length >>= 2;
        }
        // Do not look for matches beyond the end of the input.
        if nice_match > self.lookahead {
            nice_match = self.lookahead;
        }

        let mut cur_match = cur_match;
        loop {
            let mut scan = self.strstart;
            let mut m = cur_match;
            if self.window[m + best_len] != scan_end
                || self.window[m + best_len - 1] != scan_end1
                || self.window[m] != self.window[scan]
                || self.window[m + 1] != self.window[scan + 1]
            {
                // Not a longer match: try the next string in the chain.
            } else {
                scan += 2;
                m += 2;
                loop {
                    let mut failed = false;
                    for _ in 0..8 {
                        scan += 1;
                        m += 1;
                        if self.window[scan] != self.window[m] {
                            failed = true;
                            break;
                        }
                    }
                    if failed || scan >= strend {
                        break;
                    }
                }
                let len = MAX_MATCH - (strend - scan);
                if len > best_len {
                    self.match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                    scan_end1 = self.window[self.strstart + best_len - 1];
                    scan_end = self.window[self.strstart + best_len];
                }
            }

            let next = self.prev[cur_match & W_MASK] as usize;
            if next > limit {
                chain_length -= 1;
                if chain_length != 0 {
                    cur_match = next;
                    continue;
                }
            }
            break;
        }

        if best_len <= self.lookahead {
            best_len
        } else {
            self.lookahead
        }
    }

    /// The `FLUSH_BLOCK_ONLY` macro: flush the current block (giving it the
    /// given end-of-file flag) and start the next one at `strstart`.
    fn flush_block(&mut self, w: &mut BitWriter, last: bool) {
        let stored_len = self.strstart - self.block_start;
        let start = self.block_start;
        let end = self.strstart;
        let buf = &self.window[start..end];
        self.trees.flush_block(w, buf, stored_len, last);
        self.block_start = self.strstart;
    }

    /// `deflate_slow` with `flush == Z_FINISH` and unbounded output space: the
    /// lazy match loop, then the final end-of-file block.
    fn deflate_slow(&mut self, w: &mut BitWriter) {
        loop {
            // Make sure that we always have enough lookahead, except at the
            // end of the input file. The C calls fill_window() here, which
            // reads more input and slides the window; neither is observable in
            // this port because every byte of the input is already in the
            // window (see the module documentation). What is left is the C's
            // `if (s->lookahead == 0) break;`.
            if self.lookahead == 0 {
                break; // flush the current block
            }

            // Insert the string window[strstart .. strstart + 2] in the
            // dictionary, and set hash_head to the head of its hash chain.
            let mut hash_head = NIL as usize;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }

            // Find the longest match, discarding those <= prev_length.
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;

            if hash_head != NIL as usize
                && self.prev_length < MAX_LAZY_MATCH
                && self.strstart - hash_head <= MAX_DIST
            {
                self.match_length = self.longest_match(hash_head);

                // Z_DEFAULT_STRATEGY (not Z_FILTERED): only the TOO_FAR rule
                // can discard a short match.
                if self.match_length == MIN_MATCH && self.strstart - self.match_start > TOO_FAR {
                    self.match_length = MIN_MATCH - 1;
                }
            }

            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                // Output the previous match: it is at least as good as the
                // current one.
                let max_insert = self.strstart + self.lookahead - MIN_MATCH;
                let bflush = self.trees.tally_dist(
                    self.strstart - 1 - self.prev_match,
                    self.prev_length - MIN_MATCH,
                );

                // Insert in the hash table all strings up to the end of the
                // match. strstart - 1 and strstart are already inserted, and
                // if there is not enough lookahead the last two strings are
                // not inserted at all.
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;

                if bflush {
                    self.flush_block(w, false);
                }
            } else if self.match_available {
                // If there was no match at the previous position, output a
                // single literal. If there was a match but the current match
                // is longer, truncate the previous match to a single literal.
                let bflush = self.trees.tally_lit(self.window[self.strstart - 1]);
                if bflush {
                    self.flush_block(w, false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
            } else {
                // There is no previous match to compare with, wait for the
                // next step to decide.
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }

        if self.match_available {
            self.trees.tally_lit(self.window[self.strstart - 1]);
            self.match_available = false;
        }
        // The C sets `s->insert = strstart < MIN_MATCH-1 ? strstart :
        // MIN_MATCH-1` here. That only tells a later deflate() call which
        // strings fill_window() still has to insert, so it cannot affect the
        // output of this one-shot encoder.

        self.flush_block(w, true);
    }
}

/* ===========================================================================
 * Public entry point
 */

/// zlib (RFC 1950) stream of `data` at level 9, byte-identical to zlib 1.3.1's
/// `deflate()` with windowBits=15, memLevel=8, strategy=Z_DEFAULT_STRATEGY,
/// Z_FINISH.
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new(data.len() / 2 + 64);

    // zlib header (the INIT_STATE branch of deflate()): Z_DEFLATED, 15-bit
    // window, and level_flags = 3 because level 9 >= 7. No preset dictionary,
    // so no FDICT bit; the two low bits are the FCHECK that makes the header
    // a multiple of 31.
    let mut header: u32 = (8 + ((15 - 8) << 4)) << 8; // Z_DEFLATED = 8
    header |= 3 << 6;
    header += 31 - (header % 31);
    w.put_short_msb(header as u16);

    Deflater::new(data).deflate_slow(&mut w);

    // Adler-32 of the uncompressed input, high half first.
    let adler = adler32(data);
    w.put_short_msb((adler >> 16) as u16);
    w.put_short_msb((adler & 0xffff) as u16);

    w.out
}
