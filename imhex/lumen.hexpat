// =============================================================================
// LUMEN (.lumen) - ImHex pattern
//
// Parses the Open Resin Alliance print container described by the LUMEN
// specification (magic "LUMN"): the fixed 32-byte header, the chunk directory
// at the end of the file, the 8-byte "LEND" trailer, and one typed body per
// chunk type. On top of the parse it builds a decoded virtual file tree under
// /lumen/, so the parts of a file that are not directly readable - zstd'd
// metadata, the layer table, per-layer masks - show up as files you can open
// in their own tab.
//
// Sections referenced below are the LUMEN specification's, published in
// spec/ of the repository this pattern ships with.
//
// How to use it
// -------------
// Open a .lumen file in ImHex, then Patterns -> Open pattern -> lumen.hexpat
// and run it. The pattern view shows the container itself; the Virtual File
// System view (File -> Virtual File System) shows the decoded tree the pattern
// builds under /lumen/, and opening an entry there inspects it in its own tab.
//
// Everything the tree holds is generated in memory: nothing is written to the
// .lumen file, and no part of it is modified.
//
// Knobs. The defaults live at the top of this file: edit them, or set them in
// a wrapper pattern of your own and include this one, which is what keeps this
// file the same as the one in the repository:
//
//     #define LUMEN_MAX_MASKS   64
//     #define LUMEN_MASK_BUDGET 268435456
//     #include "lumen.hexpat"
//
//   LUMEN_LAYER_DATA     1  decompress LAYR frames and decode layer masks
//   LUMEN_MASK_BUDGET   33554432  bytes of layer mask to decode, in total
//   LUMEN_MAX_MASKS      8  decoded mask files at most
//   LUMEN_CHUNK_COPY_MAX 16777216  copy a chunk's stored bytes up to this size
//   LUMEN_DECODE_MAX     67108864  decompress a frame up to this declared size
//
// A 12K print holds 74 MB per layer, so decoding masks is bounded on purpose:
// with the defaults a large print gets its tables, metadata and hashes and no
// mask files, and a small one gets its first eight layers. Raise the two mask
// knobs to see more, or set LUMEN_LAYER_DATA 0 to skip masks entirely.
//
// Headless use (`imhex --pl run|format`, e.g. for a corpus sweep) works, but
// the editor-only builtins the virtual file tree needs - and the zstd builtin
// the decoder needs - are absent there: no files are created and compressed
// payloads are not decompressed. Both calls are guarded, so the parse, the
// tables and the exports are all that a headless run reports.
// =============================================================================

#pragma endian little
#pragma description "LUMEN print container: header, chunk directory, every chunk body, and a decoded virtual file tree"
#pragma MIME application/vnd.openresin.lumen
#pragma loop_limit 4000000000

import std.mem;
import std.core;
import std.string;
import std.io;

// The editor-only builtins are called through these wrappers: headless runs
// (imhex --pl ...) have neither, and a caught error leaves the virtual file
// tree empty instead of failing the parse.
fn vfs_add_file(str path, auto pattern) {
    try {
        builtin::hex::core::add_virtual_file(path, pattern);
    } catch { }
};

fn zstd_try(ref auto pattern, std::mem::Section section) {
    try {
        return u64(builtin::hex::dec::zstd_decompress(pattern, section));
    } catch {
        return u64(0);
    }
};

#ifndef LUMEN_LAYER_DATA
    #define LUMEN_LAYER_DATA 1
#endif
#ifndef LUMEN_MASK_BUDGET
    #define LUMEN_MASK_BUDGET 33554432
#endif
#ifndef LUMEN_MAX_MASKS
    #define LUMEN_MAX_MASKS 8
#endif
#ifndef LUMEN_CHUNK_COPY_MAX
    #define LUMEN_CHUNK_COPY_MAX 16777216
#endif
#ifndef LUMEN_DECODE_MAX
    #define LUMEN_DECODE_MAX 67108864
#endif

// =============================================================================
// Constants
// =============================================================================

// Chunk type tags, as the little-endian u32 a descriptor's first four bytes are.
const u32 TAG_HEAD = 0x44414548; // "HEAD"
const u32 TAG_META = 0x4154454D; // "META"
const u32 TAG_PROF = 0x464F5250; // "PROF"
const u32 TAG_AUTH = 0x48545541; // "AUTH"
const u32 TAG_LROV = 0x564F524C; // "LROV"
const u32 TAG_PREV = 0x56455250; // "PREV"
const u32 TAG_LTBL = 0x4C42544C; // "LTBL"
const u32 TAG_ZDIC = 0x4349445A; // "ZDIC"
const u32 TAG_LAYR = 0x5259414C; // "LAYR"
const u32 TAG_LHAS = 0x5341484C; // "LHAS"
const u32 TAG_VOXL = 0x4C584F56; // "VOXL"
const u32 TAG_EXTD = 0x44545845; // "EXTD"

const u32 CHUNK_SEALED = 0x10;       // chunk descriptor flag bit 4 (§3.2)
const u32 HDR_MULTI_SECTOR = 0x02;   // file header flag bit 1 (§3.1)
const u32 HDR_ENCRYPTED = 0x08;      // file header flag bit 3 (§3.1)
const u32 HDR_RETIRED = 0x15;        // file header flag bits 0, 2 and 4

const u64 NO_CHUNK = 0xFFFFFFFF;
const u32 ZSTD_MAGIC = 0xFD2FB528;

// =============================================================================
// Raw reads and small helpers
// =============================================================================

fn fourcc(auto a, auto b, auto c, auto d) {
    return u32(a) | (u32(b) << 8) | (u32(c) << 16) | (u32(d) << 24);
};

// A malformed length field must not walk a view off the end of the file, so
// every length that comes out of the data is bounded by what is left of it.
fn file_remaining(u64 addr) {
    u64 size = u64(std::mem::size());
    return size > addr ? size - addr : 0;
};

fn clamp_len(u64 want, u64 addr) {
    u64 available = file_remaining(addr);
    return want < available ? want : available;
};

fn clamp_count(u64 want, u64 addr, u64 stride) {
    if (stride == 0) return u64(0);
    u64 available = file_remaining(addr) / stride;
    return want < available ? want : available;
};

fn rd_u8(u64 addr)  { return u8(std::mem::read_unsigned(addr, 1)); };
fn rd_u16(u64 addr) { return u16(std::mem::read_unsigned(addr, 2)); };
fn rd_u32(u64 addr) { return u32(std::mem::read_unsigned(addr, 4)); };
fn rd_u64(u64 addr) { return u64(std::mem::read_unsigned(addr, 8)); };

fn file_size()      { return u64(std::mem::size()); };
fn trailer_addr()   { return file_size() - 8; };

// File header, §3.1
fn header_magic_ok()       { return rd_u32(0x00) == 0x4E4D554C; };  // "LUMN"
fn header_version()        { return rd_u32(0x04); };
fn header_dir_offset()     { return rd_u64(0x08); };
fn header_chunk_count()    { return rd_u32(0x10); };
fn header_flags()          { return rd_u32(0x14); };
fn header_total_uncompressed() { return rd_u64(0x18); };
fn trailer_magic_ok()      { return rd_u32(trailer_addr()) == 0x444E454C; };  // "LEND"

// Chunk descriptor, §3.2 (32 bytes, in directory order)
fn desc_addr(u64 i)        { return header_dir_offset() + i * 32; };
fn desc_type(u64 i)        { return rd_u32(desc_addr(i)); };
fn desc_offset(u64 i)      { return rd_u64(desc_addr(i) + 4); };
fn desc_size_u(u64 i)      { return rd_u64(desc_addr(i) + 12); };
fn desc_size_c(u64 i)      { return rd_u64(desc_addr(i) + 20); };
fn desc_flags(u64 i)       { return rd_u32(desc_addr(i) + 28); };
fn desc_null(u64 i)            { return desc_offset(i) == 0; };
fn desc_sealed(u64 i)          { return (desc_flags(i) & CHUNK_SEALED) != 0; };
fn desc_stored(u64 i)          { return desc_size_c(i) == 0 ? desc_size_u(i) : desc_size_c(i); };

fn find_chunk(u32 tag) {
    for (u64 i = 0, i < header_chunk_count(), i += 1) {
        if (!desc_null(i) && desc_type(i) == tag)
            return i;
    }
    return NO_CHUNK;
};

fn kind_of(u32 tag) {
    if (tag == TAG_HEAD) return "HEAD";
    if (tag == TAG_META) return "META";
    if (tag == TAG_PROF) return "PROF";
    if (tag == TAG_AUTH) return "AUTH";
    if (tag == TAG_LROV) return "LROV";
    if (tag == TAG_PREV) return "PREV";
    if (tag == TAG_LTBL) return "LTBL";
    if (tag == TAG_ZDIC) return "ZDIC";
    if (tag == TAG_LAYR) return "LAYR";
    if (tag == TAG_LHAS) return "LHAS";
    if (tag == TAG_VOXL) return "VOXL";
    if (tag == TAG_EXTD) return "EXTD";
    return std::format("{}", tag);
};

// §6.3: which chunk payloads are wrapped in a zstd frame. EXTD decides per
// extension, and the descriptor is what says which way it went.
fn is_framed(u32 tag, u32 flags, u64 size_c) {
    if ((flags & CHUNK_SEALED) != 0) return false;
    if (tag == TAG_META) return true;
    if (tag == TAG_PROF) return true;
    if (tag == TAG_LROV) return true;
    if (tag == TAG_VOXL) return true;
    if (tag == TAG_LAYR) return true;
    if (tag == TAG_EXTD) return size_c != 0;
    return false;
};

fn preview_role(u32 flags) {
    u32 r = flags & 0x0F;
    if (r == 0) return "unspecified";
    if (r == 1) return "large";
    if (r == 2) return "small";
    if (r == 3) return "icon";
    return std::format("reserved({})", r);
};

// =============================================================================
// HEAD chunk (§4.1)
// =============================================================================

fn head_addr()      { u64 i = find_chunk(TAG_HEAD); return i == NO_CHUNK ? 0 : desc_offset(i); };
fn head_ok()        { return find_chunk(TAG_HEAD) != NO_CHUNK; };
fn head_namelen()   { return u32(clamp_len(u64(rd_u32(head_addr() + 4)), head_addr() + 8)); };
fn head_encoder()   { return std::mem::read_string(head_addr() + 8, head_namelen()); };
fn head_created()   { return rd_u64(head_addr() + 8 + head_namelen()); };
fn head_w()         { return rd_u32(head_addr() + 16 + head_namelen()); };
fn head_h()         { return rd_u32(head_addr() + 20 + head_namelen()); };
fn head_build_w()   { return rd_u32(head_addr() + 24 + head_namelen()); };
fn head_build_d()   { return rd_u32(head_addr() + 28 + head_namelen()); };
fn head_build_h()   { return rd_u32(head_addr() + 32 + head_namelen()); };
fn head_layer_um()  { return rd_u32(head_addr() + 36 + head_namelen()); };
fn head_layers()    { return rd_u32(head_addr() + 40 + head_namelen()); };

// =============================================================================
// LTBL chunk (§4.7)
// =============================================================================

fn ltbl_addr()          { u64 i = find_chunk(TAG_LTBL); return i == NO_CHUNK ? 0 : desc_offset(i); };
fn ltbl_ok()            { return find_chunk(TAG_LTBL) != NO_CHUNK; };
fn ltbl_version()       { return rd_u32(ltbl_addr()); };
fn ltbl_layers()        { return rd_u32(ltbl_addr() + 4); };
fn ltbl_entry_size()    { return rd_u32(ltbl_addr() + 8); };
fn ltbl_entry_count()   { return u32(clamp_count(u64(rd_u32(ltbl_addr() + 12)), ltbl_addr() + 16, 28)); };
fn ltbl_entry_addr(u64 i)   { return ltbl_addr() + 16 + i * 28; };
fn ltbl_data_size(u64 i)    { return rd_u32(ltbl_entry_addr(i)); };
fn ltbl_first_lrov(u64 i)   { return rd_u32(ltbl_entry_addr(i) + 4); };
fn ltbl_first_layr(u64 i)   { return rd_u32(ltbl_entry_addr(i) + 8); };
fn ltbl_additional(u64 i)   { return rd_u32(ltbl_entry_addr(i) + 12); };
fn ltbl_data_offset(u64 i)  { return rd_u64(ltbl_entry_addr(i) + 16); };
fn ltbl_sector(u64 i)       { return rd_u32(ltbl_entry_addr(i) + 24); };
fn ltbl_max_sectors() {
    u64 m = 0;
    for (u64 i = 0, i < ltbl_entry_count(), i += 1) {
        u64 s = 1 + u64(ltbl_additional(i));
        if (s > m) m = s;
    }
    return m;
};

// =============================================================================
// LHAS chunk (§4.10)
// =============================================================================

fn lhas_addr()     { u64 i = find_chunk(TAG_LHAS); return i == NO_CHUNK ? 0 : desc_offset(i); };
fn lhas_ok()       { return find_chunk(TAG_LHAS) != NO_CHUNK; };
fn lhas_algo()     { return rd_u8(lhas_addr()); };
fn lhas_size()     { return rd_u8(lhas_addr() + 1); };
fn lhas_layers()   { return u32(clamp_count(u64(rd_u32(lhas_addr() + 2)), lhas_addr() + 38, u64(lhas_size()))); };
fn lhas_hash(u64 i)    { return std::mem::read_string(lhas_addr() + 38 + i * u64(lhas_size()), u64(lhas_size())); };

// =============================================================================
// ZDIC / AUTH / EXTD headers
// =============================================================================

fn zdic_addr()     { u64 i = find_chunk(TAG_ZDIC); return i == NO_CHUNK ? 0 : desc_offset(i); };
fn zdic_ok()       { return find_chunk(TAG_ZDIC) != NO_CHUNK; };
fn zdic_sealed()   { u64 i = find_chunk(TAG_ZDIC); return i != NO_CHUNK && desc_sealed(i); };
// A sealed dictionary is ciphertext: its id and length are only readable with
// the session key, so they are reported as zero rather than as noise.
fn zdic_dict_id()  { return zdic_sealed() ? u32(0) : rd_u32(zdic_addr() + 4); };
fn zdic_dict_size() { return zdic_sealed() ? u32(0) : rd_u32(zdic_addr() + 8); };

fn auth_addr()       { u64 i = find_chunk(TAG_AUTH); return i == NO_CHUNK ? 0 : desc_offset(i); };
fn auth_ok()         { return find_chunk(TAG_AUTH) != NO_CHUNK; };
fn auth_cipher()     { return std::mem::read_string(auth_addr(), 4); };
fn auth_version()    { return rd_u32(auth_addr() + 4); };
fn auth_mode()       { return rd_u32(auth_addr() + 8); };
fn auth_pw_len()     { return u32(clamp_len(u64(rd_u32(auth_addr() + 12)), auth_addr() + 20)); };
fn auth_machine_len() { return u32(clamp_len(u64(rd_u32(auth_addr() + 16)), auth_addr() + 20 + u64(auth_pw_len()))); };
fn auth_recipients() { return auth_machine_len() / 104; };

// =============================================================================
// zstd frame headers (§6, RFC 8878)
//
// LUMEN requires every frame to declare its content size, so a frame and its
// payload length can both be read without decompressing anything.
// =============================================================================

fn zstd_fcs_len(u32 flag, bool single_segment) {
    if (flag == 0) return single_segment ? 1 : 0;
    if (flag == 1) return 2;
    if (flag == 2) return 4;
    return 8;
};

fn zstd_dict_len(u32 flag) {
    if (flag == 0) return 0;
    if (flag == 1) return 1;
    if (flag == 2) return 2;
    return 4;
};

fn zstd_base_ok(u64 frame_addr) {
    return rd_u32(frame_addr) == ZSTD_MAGIC;
};

fn zstd_content_size(u64 frame_addr) {
    if (!zstd_base_ok(frame_addr)) return 0;

    u8 fhd = rd_u8(frame_addr + 4);
    bool single_segment = (fhd & 0x20) != 0;
    u32 fcs_flag = (fhd >> 6) & 0x03;
    u32 dict_flag = fhd & 0x03;

    u64 off = frame_addr + 5;
    if (!single_segment) off += 1;               // window descriptor
    off += zstd_dict_len(dict_flag);             // dictionary id

    u32 n = zstd_fcs_len(fcs_flag, single_segment);
    if (n == 0) return 0;
    if (n == 1) return u64(rd_u8(off));
    if (n == 2) return u64(rd_u16(off)) + 256;
    if (n == 4) return u64(rd_u32(off));
    return rd_u64(off);
};

fn zstd_dict_id(u64 frame_addr) {
    if (!zstd_base_ok(frame_addr)) return u64(0);

    u8 fhd = rd_u8(frame_addr + 4);
    bool single_segment = (fhd & 0x20) != 0;
    u32 dict_flag = fhd & 0x03;

    u64 off = frame_addr + 5;
    if (!single_segment) off += 1;

    if (dict_flag == 0) return u64(0);
    if (dict_flag == 1) return u64(rd_u8(off));
    if (dict_flag == 2) return u64(rd_u16(off));
    return u64(rd_u32(off));
};

fn zstd_header_len(u64 frame_addr) {
    u8 fhd = rd_u8(frame_addr + 4);
    bool single_segment = (fhd & 0x20) != 0;
    return 5 + (single_segment ? 0 : 1)
             + zstd_dict_len(fhd & 0x03)
             + zstd_fcs_len((fhd >> 6) & 0x03, single_segment);
};

fn zstd_info(u64 frame_addr) {
    if (!zstd_base_ok(frame_addr))
        return "not a zstd frame (bad magic)";

    u8 fhd = rd_u8(frame_addr + 4);
    bool single_segment = (fhd & 0x20) != 0;
    u32 dict_flag = fhd & 0x03;
    u32 fcs_flag = (fhd >> 6) & 0x03;

    str s = std::format("zstd frame: header={} B content_size=", zstd_header_len(frame_addr));
    if (zstd_fcs_len(fcs_flag, single_segment) == 0)
        s += "unknown (stream)";
    else
        s += std::format("{}", zstd_content_size(frame_addr));
    s += std::format(" dict_id={} checksum={} single_segment={}",
                     zstd_dict_id(frame_addr),
                     (fhd & 0x04) != 0 ? "yes" : "no",
                     single_segment ? "yes" : "no");
    return s;
};

// =============================================================================
// Run-end decoding (§5)
//
// The stream is walked with a cursor over a placed byte array, and the run
// lengths live in four significance planes rather than interleaved (§5.3.1).
// =============================================================================

u64 g_pos;
u64 g_dlen;                 // the slice the decode walks
bool g_read_ok;             // false once a read would pass that slice
u64 g_plane_start[4];
u64 g_plane_len[4];
u64 g_plane_pos[4];

// Every read is bounded by the slice: a stream that lies about a length or ends
// in the middle of a field makes the decode refuse, it never walks off the view.
fn ree_read_varint(ref auto d) {
    u64 value = 0;
    u32 shift = 0;
    while (true) {
        if (g_pos >= g_dlen) {
            g_read_ok = false;
            return u64(0);
        }
        u8 b = d[g_pos];
        g_pos += 1;
        value |= u64(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 63) break;
    }
    return value;
};

fn ree_read_planes(ref auto d) {
    for (u64 j = 0, j < 4, j += 1) {
        g_plane_len[j] = ree_read_varint(d);
        g_plane_pos[j] = 0;
    }
    for (u64 j = 0, j < 4, j += 1) {
        if (j == 0)
            g_plane_start[0] = g_pos;
        else
            g_plane_start[j] = g_plane_start[j - 1] + g_plane_len[j - 1];
    }
    // The starts ascend, so the last plane's end is the furthest of them.
    if (g_plane_start[3] + g_plane_len[3] > g_dlen) {
        g_read_ok = false;
        return;
    }
    g_pos = g_plane_start[3] + g_plane_len[3];
};

fn ree_planes_reset() {
    for (u64 j = 0, j < 4, j += 1)
        g_plane_pos[j] = 0;
};

fn ree_planes_next(ref auto d) {
    u64 value = 0;
    u32 shift = 0;
    for (u64 j = 0, j < 4, j += 1) {
        if (g_plane_pos[j] >= g_plane_len[j]) break;
        u8 b = d[g_plane_start[j] + g_plane_pos[j]];
        g_plane_pos[j] = g_plane_pos[j] + 1;
        value |= u64(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return value;
};

// The plane state above holds one array at a time, but tag 0x03 reads three in
// step: the core's even lengths, the core's odd lengths, and the escape list. A
// kept array is the same four lengths and bytes, parked under a slot number so
// the next plane block can take over the primary state.
u64 g_keep_start[12];
u64 g_keep_len[12];
u64 g_keep_pos[12];

fn ree_planes_keep(u64 slot) {
    for (u64 j = 0, j < 4, j += 1) {
        g_keep_start[slot * 4 + j] = g_plane_start[j];
        g_keep_len[slot * 4 + j] = g_plane_len[j];
        g_keep_pos[slot * 4 + j] = 0;
    }
};

fn ree_planes_kept_next(ref auto d, u64 slot) {
    u64 value = 0;
    u32 shift = 0;
    for (u64 j = 0, j < 4, j += 1) {
        u64 p = slot * 4 + j;
        if (g_keep_pos[p] >= g_keep_len[p]) break;
        u8 b = d[g_keep_start[p] + g_keep_pos[p]];
        g_keep_pos[p] = g_keep_pos[p] + 1;
        value |= u64(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return value;
};

// zigzag (§5.2): even values carry the non-negative half, odd the negative one.
fn ree_unzigzag(u64 v) {
    return (v & 1) == 0 ? s64(v >> 1) : s64(-1) - s64(v >> 1);
};

fn ree_fill(ref auto mask, u64 first, u64 last, u32 value) {
    for (u64 i = first, i < last, i += 1)
        mask[i] = u8(value & 0xFF);
};

// tag 0x00 (§5.3)
fn ree_binary(ref auto d, u64 dlen, ref auto mask, u64 total) {
    if (g_pos >= dlen) return false;
    u32 first = u64(d[g_pos]);
    g_pos += 1;

    u64 run_count = ree_read_varint(d);
    if (!g_read_ok) return false;
    if (run_count == 0) { ree_fill(mask, 0, total, 0); return true; }

    ree_read_planes(d);
    if (!g_read_ok) return false;
    if (run_count == 1) { ree_fill(mask, 0, total, first); return true; }

    u32 value = first;
    u64 cumulative = 0;
    u64 start = 0;
    for (u64 i = 0, i < run_count, i += 1) {
        u64 end = total;
        if (i + 1 < run_count) {
            cumulative += ree_planes_next(d);
            end = cumulative;
        }
        if (end > total) end = total;
        ree_fill(mask, start, end, value);
        value = 255 - value;
        start = end;
    }
    return true;
};

// tag 0x01 (§5.4)
fn ree_grayscale(ref auto d, u64 dlen, ref auto mask, u64 total) {
    u64 run_count = ree_read_varint(d);
    if (!g_read_ok) return false;
    if (run_count == 0) { ree_fill(mask, 0, total, 0); return true; }
    if (g_pos + run_count > dlen) return false;

    u64 values = g_pos;
    g_pos += run_count;

    ree_read_planes(d);
    if (!g_read_ok) return false;

    u64 start = 0;
    for (u64 i = 0, i < run_count, i += 1) {
        u64 len = total - start;
        if (i + 1 < run_count)
            len = ree_planes_next(d);

        u64 end = start + len;
        if (end > total) end = total;
        ree_fill(mask, start, end, u64(d[values + i]));
        start = end;
    }
    return start == total;
};

// tag 0x02 (§5.5): binary REE, then a sparse (position, value) overlay
fn ree_split(ref auto d, u64 dlen, ref auto mask, u64 total) {
    if (!ree_binary(d, dlen, mask, total)) return false;

    u64 aa_count = ree_read_varint(d);
    if (!g_read_ok) return false;
    if (aa_count == 0) return true;

    ree_read_planes(d);
    if (!g_read_ok) return false;
    ree_planes_reset();

    u64 values = g_pos;
    u64 pos = 0;
    for (u64 i = 0, i < aa_count, i += 1) {
        pos += ree_planes_next(d);
        if (pos >= total) return false;
        if (values + i >= dlen) return false;
        mask[pos] = d[values + i];
    }
    return true;
};

// tag 0x03 (§5.6), attached REE: a thresholded core whose run lengths are split
// by parity and delta coded against the run two back, plus an overlay of AA
// pixels that the core's run ends carry - two bits per run - and that an escape
// list completes.
u64 g_aa_value;    // the overlay value the walk has reached
bool g_aa_ok;      // whether the last one read was a byte

// The next overlay value: the first is stored as it is, every later one is the
// running value plus a first difference, and each is a byte of the mask.
fn ree_aa_next(ref auto d, u64 placed, u64 aa_count) {
    if (placed >= aa_count) {
        g_aa_ok = false;
        return u64(0);
    }

    u64 stored = ree_planes_next(d);
    if (placed == 0) {
        if (stored > 255) {
            g_aa_ok = false;
            return u64(0);
        }
        g_aa_value = stored;
    } else {
        s64 v = s64(g_aa_value) + ree_unzigzag(stored);
        if (v < 0 || v > 255) {
            g_aa_ok = false;
            return u64(0);
        }
        g_aa_value = u64(v);
    }
    g_aa_ok = true;
    return g_aa_value;
};

fn ree_attached(ref auto d, u64 dlen, ref auto mask, u64 total) {
    if (g_pos >= dlen) return false;
    u32 declared = u64(d[g_pos]);
    g_pos += 1;
    if (declared != 0x00 && declared != 0xFF) return false;

    u64 run_count = ree_read_varint(d);
    if (!g_read_ok) return false;
    if (run_count > total + 1) return false;

    // run_count == 0 is the non-canonical one-black-run form, exactly as tag
    // 0x00 reads it: the overlay fields that follow then describe pixels over a
    // core that is black everywhere, and the empty bit array claims none.
    u32 first = run_count == 0 ? 0x00 : declared;
    u64 runs = run_count == 0 ? 1 : run_count;

    // even_lengths then odd_lengths, parked before the next block overwrites the
    // plane state; the walk reads the two in step with the run order.
    ree_read_planes(d);
    if (!g_read_ok) return false;
    ree_planes_keep(0);
    ree_read_planes(d);
    if (!g_read_ok) return false;
    ree_planes_keep(1);

    if (g_pos >= dlen) return false;
    u64 aa_count = ree_read_varint(d);
    if (!g_read_ok) return false;
    if (aa_count > total + 1) return false;

    // Two bits per core run: bit 2r is "the run's first pixel is an AA pixel",
    // bit 2r+1 its last. Runs past run_count have no bits of their own.
    u64 bit_bytes = (run_count + 3) / 4;
    if (g_pos + bit_bytes > dlen) return false;
    u64 bits_at = g_pos;
    g_pos += bit_bytes;

    u64 escape_count = ree_read_varint(d);
    if (!g_read_ok) return false;
    if (escape_count > aa_count) return false;
    ree_read_planes(d);
    if (!g_read_ok) return false;
    ree_planes_keep(2);        // escape_positions: delta coded absolute indices

    ree_read_planes(d);        // aa_values: the first value, then first differences
    if (!g_read_ok) return false;

    u64 prev[2];    // the length two runs back, one lane per parity
    prev[0] = 0;
    prev[1] = 0;

    u64 placed = 0;
    u64 escapes_used = 0;
    u64 escape_pos = 0;
    bool escape_held = false;
    u64 start = 0;

    for (u64 r = 0, r < runs, r += 1) {
        // Run K-1 is implicit: it runs to the end of the mask.
        u64 len = total - start;
        if (r + 1 < runs) {
            u64 stored = (r & 1) == 0 ? ree_planes_kept_next(d, 0) : ree_planes_kept_next(d, 1);
            if (r < 2)
                len = stored;
            else
                len = u64(s64(prev[r & 1]) + ree_unzigzag(stored));
            prev[r & 1] = len;
        }
        if (len > total - start) return false;    // a run may not pass the layer
        u64 end = start + len;

        ree_fill(mask, start, end, (r & 1) == 0 ? first : 255 - first);

        bool first_aa = false;
        bool last_aa = false;
        if (bit_bytes > 0) {
            u8 attach = d[bits_at + (r >> 2)];
            first_aa = ((attach >> ((r & 3) * 2)) & 1) != 0;
            last_aa  = ((attach >> ((r & 3) * 2 + 1)) & 1) != 0;
        }

        // The walk is run by run: the run's first pixel, then the escapes inside
        // it in ascending order, then its last pixel - the order the overlay
        // values are stored in.
        if (first_aa && end > start) {
            u64 value = ree_aa_next(d, placed, aa_count);
            if (!g_aa_ok) return false;
            mask[start] = u8(value);
            placed += 1;
        }

        // An escape is strictly inside the run that holds it, so a position at
        // or past this run's end belongs to a later one and is held over; a held
        // position is placed even when the list holds nothing more to read.
        while (true) {
            if (!escape_held) {
                if (escapes_used == escape_count) break;
                u64 delta = ree_planes_kept_next(d, 2);
                if (escapes_used > 0 && delta == 0) return false;   // strictly increasing
                escape_pos += delta;
                if (escape_pos >= total) return false;
                escapes_used += 1;
                escape_held = true;
            }
            if (escape_pos >= end) break;
            if (escape_pos <= start || escape_pos + 1 >= end) return false;  // not strictly inside
            u64 value = ree_aa_next(d, placed, aa_count);
            if (!g_aa_ok) return false;
            mask[escape_pos] = u8(value);
            placed += 1;
            escape_held = false;
        }

        if (last_aa && end > start) {
            u64 value = ree_aa_next(d, placed, aa_count);
            if (!g_aa_ok) return false;
            mask[end - 1] = u8(value);
            placed += 1;
        }

        start = end;
    }

    // The walk yields exactly the pixels the attachment bits and the escapes
    // describe, and no escape is left over past the last run.
    return placed == aa_count && !escape_held;
};

fn ree_decode(u8 tag, ref auto d, u64 dlen, ref auto mask, u64 total) {
    g_pos = 1;    // d is the whole slice: the tag byte comes first (spec 4.9)
    g_dlen = dlen;
    g_read_ok = true;
    if (tag == 0x00) return ree_binary(d, dlen, mask, total);
    if (tag == 0x01) return ree_grayscale(d, dlen, mask, total);
    if (tag == 0x02) return ree_split(d, dlen, mask, total);
    if (tag == 0x03) return ree_attached(d, dlen, mask, total);
    return false;
};

// =============================================================================
// Virtual file tree
// =============================================================================

str g_manifest = "";
str g_notes = "";
u64 g_files = 0;
u64 g_decoded = 0;
u64 g_decode_failed = 0;
u64 g_masks = 0;
u64 g_mask_pixels = 0;
u64 g_files_failed = 0;

fn note(str text) {
    g_notes += text;
    g_notes += "\n";
};

fn manifest_add(str path, u64 size) {
    g_files += 1;
    g_manifest += std::format("{}\t{}\n", path, size);
};

fn vfs_bytes(str path, auto pattern) {
    u64 n = u64(sizeof(pattern));
    manifest_add(path, n);
    try {
        vfs_add_file(path, pattern);
    } catch {
        g_files_failed += 1;
    }
};

fn vfs_text(str path, str text, bool record = true) {
    u64 n = std::string::length(text);
    if (n == 0) return u64(0);

    char buf[n];
    for (u64 i = 0, i < n, i += 1)
        buf[i] = std::string::at(text, i);

    auto sec = std::mem::create_section("lumen " + path);
    std::mem::set_section_size(sec, n);
    std::mem::copy_value_to_section(buf, sec, 0);

    char data[n] @ 0x00 in sec;
    if (record) manifest_add(path, n);
    try {
        vfs_add_file(path, data);
    } catch {
        g_files_failed += 1;
    }
    return n;
};

// Decompresses one frame into a new section and writes it out. The section is
// returned (empty when the frame could not be decoded) so a caller can slice
// the decompressed bytes further.
fn vfs_decompress(str path, auto frame) {
    auto sec = std::mem::create_section("lumen " + path);

    u64 consumed = 0;
    try {
        consumed = zstd_try(frame, sec);
    } catch {
        consumed = 0;
    }

    if (consumed == 0 || std::mem::get_section_size(sec) == 0) {
        g_decode_failed += 1;
        return sec;
    }

    u64 n = u64(std::mem::get_section_size(sec));
    u8 data[n] @ 0x00 in sec;
    g_decoded += 1;
    manifest_add(path, n);
    try {
        vfs_add_file(path, data);
    } catch {
        g_files_failed += 1;
    }
    return sec;
};

fn pgm_header(u64 w, u64 h) {
    return std::format("P5\n{} {}\n255\n", w, h);
};

fn mask_files(str base, ref auto mask, u64 w, u64 h) {
    u64 n = w * h;

    // The mask as it sits in the file: one byte per pixel, 0x00 black.
    auto raw_sec = std::mem::create_section("lumen " + base + " raw");
    std::mem::set_section_size(raw_sec, n);
    std::mem::copy_value_to_section(mask, raw_sec, 0);
    u8 raw[n] @ 0x00 in raw_sec;
    manifest_add(base + ".raw", n);
    try {
        vfs_add_file(base + ".raw", raw);
    } catch {
        g_files_failed += 1;
    }

    // The same bytes as a binary PGM (P5), which is what draws the layer.
    str head = pgm_header(w, h);
    u64 hl = std::string::length(head);
    char hb[hl];
    for (u64 i = 0, i < hl, i += 1)
        hb[i] = std::string::at(head, i);

    auto pgm_sec = std::mem::create_section("lumen " + base + " pgm");
    std::mem::set_section_size(pgm_sec, hl + n);
    std::mem::copy_value_to_section(hb, pgm_sec, 0);
    std::mem::copy_section_to_section(raw_sec, 0, pgm_sec, hl, n);
    u8 pgm[hl + n] @ 0x00 in pgm_sec;
    manifest_add(base + ".pgm", hl + n);
    try {
        vfs_add_file(base + ".pgm", pgm);
    } catch {
        g_files_failed += 1;
    }
};

// Decodes every (layer, sector) slice a LAYR chunk holds (§4.9). The table is
// walked in order, so a layer's index falls out of the walk rather than out of
// a lookup per entry.
fn emit_layr_masks(u64 chunk_index, std::mem::Section sec, u64 w, u64 h) {
    if (!ltbl_ok() || w == 0 || h == 0) return;

    u64 total = w * h;
    if (total > LUMEN_MASK_BUDGET) {
        note(std::format("masks are {} bytes each, above LUMEN_MASK_BUDGET ({}); raise it or set LUMEN_MAX_MASKS 0",
                         total, LUMEN_MASK_BUDGET));
        return;
    }

    u64 entry_count = ltbl_entry_count();
    u64 layer = 0;
    u64 i = 0;
    while (i < entry_count) {
        u64 additional = ltbl_additional(i);
        u64 group = 1 + additional;

        for (u64 k = 0, k < group, k += 1) {
            u64 e = i + k;
            if (e >= entry_count) break;
            if (ltbl_first_layr(e) != chunk_index) continue;

            u64 size = ltbl_data_size(e);
            if (size == 0) continue;    // nothing exposed: the empty slice, §4.9

            if (g_masks >= LUMEN_MAX_MASKS || g_mask_pixels + total > LUMEN_MASK_BUDGET) {
                note(std::format("stopped decoding masks at layer {} (LUMEN_MAX_MASKS {}, LUMEN_MASK_BUDGET {})",
                                 layer, LUMEN_MAX_MASKS, LUMEN_MASK_BUDGET));
                return;
            }

            u64 off = ltbl_data_offset(e);
            u8 slice[size] @ off in sec;

            u8 tag = u64(slice[0]);
            u8 mask[total];
            if (!ree_decode(tag, slice, size, mask, total)) {
                note(std::format("layer {} sector {}: encoding tag {:#04x} could not be decoded", layer, ltbl_sector(e), tag));
                continue;
            }

            str base = std::format("/lumen/layers/L{:05d}-S{:02d}", layer, ltbl_sector(e));
            mask_files(base, mask, w, h);
            g_masks += 1;
            g_mask_pixels += total;
        }

        i += group;
        layer += 1;
    }
};

// One chunk: the stored bytes, the decoded payload when there is a frame, and
// the layer masks when it is a LAYR chunk.
fn emit_chunk(ref auto desc, auto raw, auto layr_frame, auto zdic_dict) {
    if (desc.null_descriptor) return "";

    str base = std::format("/lumen/chunks/{:03d}-{}", desc.index, desc.kind);

    if (desc.stored_len <= LUMEN_CHUNK_COPY_MAX) {
        vfs_bytes(base + ".bin", raw);
    } else {
        note(std::format("{}: {} stored bytes at {:#x}, not copied (raise LUMEN_CHUNK_COPY_MAX to copy it)",
                         base, desc.stored_len, desc.offset));
    }

    if (desc.sealed) {
        note(std::format("{}: sealed (12-byte nonce, ciphertext, 16-byte tag); only the framing is readable - see /lumen/tables/crypto.json",
                         base));
        return base;
    }

    if (desc.tag == TAG_PREV) {
        str png = std::format("/lumen/previews/{:03d}-PREV-{}.png", desc.index, preview_role(desc.flags));
        if (desc.stored_len <= LUMEN_CHUNK_COPY_MAX)
            vfs_bytes(png, raw);
        return png;
    }

    if (desc.tag == TAG_ZDIC && desc.stored_len > 12) {
        vfs_bytes("/lumen/zdic/dictionary.zdict", zdic_dict);
        return base;
    }

    if (!desc.framed) return base;

    u64 content = zstd_content_size(desc.frame_addr);
    if (content > LUMEN_DECODE_MAX) {
        note(std::format("{}: frame declares {} bytes, above LUMEN_DECODE_MAX ({}); not decompressed",
                         base, content, LUMEN_DECODE_MAX));
        return base;
    }

    str suffix = ".dec";
    if (desc.tag == TAG_META || desc.tag == TAG_PROF || desc.tag == TAG_LROV) suffix = ".json";
    if (desc.tag == TAG_VOXL) suffix = ".voxl";

    if (desc.tag == TAG_LAYR) {
        auto sec = vfs_decompress(base + ".frames.bin", layr_frame);
        if (u64(std::mem::get_section_size(sec)) == 0) {
            note_dict_required(desc, base);
            return base;
        }
        if (LUMEN_LAYER_DATA != 0)
            emit_layr_masks(desc.index, sec, head_w(), head_h());
        return base;
    }

    auto sec = vfs_decompress(base + suffix, raw);
    if (u64(std::mem::get_section_size(sec)) == 0) {
        note_dict_required(desc, base);
        return base;
    }

    return base;
};

fn note_dict_required(ref auto desc, str base) {
    if (desc.frame_dict_id != 0) {
        note(std::format("{}: frame needs the ZDIC dictionary (id {}); ImHex's zstd decompressor takes no dictionary, so the stored frame is the only view",
                         base, desc.frame_dict_id));
    } else {
        note(std::format("{}: frame could not be decompressed", base));
    }
};

// =============================================================================
// Text views
// =============================================================================

fn header_json() {
    str s = "{\n";
    s += std::format("  \"magic\": \"{}\",\n", std::mem::read_string(0x00, 4));
    s += std::format("  \"magic_ok\": {},\n", header_magic_ok());
    s += std::format("  \"version\": {},\n", header_version());
    s += std::format("  \"dir_offset\": {},\n", header_dir_offset());
    s += std::format("  \"chunk_count\": {},\n", header_chunk_count());
    s += std::format("  \"flags\": {},\n", header_flags());
    s += std::format("  \"multi_sector\": {},\n", (header_flags() & HDR_MULTI_SECTOR) != 0);
    s += std::format("  \"encrypted\": {},\n", (header_flags() & HDR_ENCRYPTED) != 0);
    s += std::format("  \"retired_flag_bits\": {},\n", header_flags() & HDR_RETIRED);
    s += std::format("  \"total_uncompressed_size\": {},\n", header_total_uncompressed());
    s += std::format("  \"file_size\": {},\n", file_size());
    s += std::format("  \"trailer\": \"{}\",\n", std::mem::read_string(trailer_addr(), 4));
    s += std::format("  \"trailer_magic_ok\": {},\n", trailer_magic_ok());
    s += std::format("  \"trailer_crc32c\": \"{:08x}\"\n", rd_u32(trailer_addr() + 4));
    s += "}\n";
    return s;
};

fn head_json() {
    if (!head_ok()) return "{\n  \"present\": false\n}\n";

    str s = "{\n";
    s += "  \"present\": true,\n";
    s += std::format("  \"head_version\": {},\n", rd_u32(head_addr()));
    s += std::format("  \"encoder_name\": \"{}\",\n", head_encoder());
    s += std::format("  \"created_unix_sec\": {},\n", head_created());
    s += std::format("  \"display_width_px\": {},\n", head_w());
    s += std::format("  \"display_height_px\": {},\n", head_h());
    s += std::format("  \"build_width_um\": {},\n", head_build_w());
    s += std::format("  \"build_depth_um\": {},\n", head_build_d());
    s += std::format("  \"build_height_um\": {},\n", head_build_h());
    s += std::format("  \"layer_height_um\": {},\n", head_layer_um());
    s += std::format("  \"total_layers\": {},\n", head_layers());
    s += std::format("  \"total_pixels\": {}\n", u64(head_w()) * u64(head_h()));
    s += "}\n";
    return s;
};

fn directory_csv() {
    str s = "index,type,kind,offset,size_uncompressed,size_compressed,size_stored,flags,sealed,framed,null,detail\n";
    for (u64 i = 0, i < header_chunk_count(), i += 1) {
        u32 tag = desc_type(i);
        u32 flags = desc_flags(i);
        str detail = "";
        if (tag == TAG_PREV) detail = std::format("role={}", preview_role(flags));
        if (tag == TAG_EXTD) detail = std::format("vendor=0x{:04x} critical={}",
                                                  (u32(flags) >> 8) & 0xFFFF, (flags & (1 << 24)) != 0);

        s += std::format("{},{},{},{},{},{},{},{:#010x},{},{},{},{}\n",
                         i,
                         std::mem::read_string(desc_addr(i), 4),
                         kind_of(tag),
                         desc_offset(i),
                         desc_size_u(i),
                         desc_size_c(i),
                         desc_stored(i),
                         flags,
                         desc_sealed(i),
                         is_framed(tag, flags, desc_size_c(i)),
                         desc_null(i),
                         detail);
    }
    return s;
};

fn layers_csv() {
    str s = "layer,entry,sector,sector_count,data_size,data_offset,first_layr,first_lrov,empty\n";
    if (!ltbl_ok()) return s;

    u64 entry_count = ltbl_entry_count();
    u64 layer = 0;
    u64 i = 0;
    while (i < entry_count) {
        u64 group = 1 + u64(ltbl_additional(i));
        for (u64 k = 0, k < group, k += 1) {
            u64 e = i + k;
            if (e >= entry_count) break;
            s += std::format("{},{},{},{},{},{},{},{},{}\n",
                             layer, e, ltbl_sector(e), group,
                             ltbl_data_size(e), ltbl_data_offset(e),
                             ltbl_first_layr(e), ltbl_first_lrov(e),
                             ltbl_data_size(e) == 0);
        }
        i += group;
        layer += 1;
    }
    return s;
};

fn hashes_txt() {
    str s = "LUMEN LHAS - SHA-256 Merkle tree over decompressed layer data (spec 4.10)\n";
    if (!lhas_ok()) {
        s += "no LHAS chunk in this file\n";
        return s;
    }

    s += std::format("hash_algorithm={} hash_size={} layer_count={}\n", lhas_algo(), lhas_size(), lhas_layers());
    s += std::format("merkle_root={}\n", hex_of_hash(std::mem::read_string(lhas_addr() + 6, 32)));
    for (u64 i = 0, i < u64(lhas_layers()), i += 1)
        s += std::format("leaf[{:05d}]={}\n", i, hex_of_hash(lhas_hash(i)));
    return s;
};

// A 32-byte hash read as a string is the byte string; express it as hex.
fn hex_of_hash(str raw) {
    str s = "";
    for (u64 i = 0, i < std::string::length(raw), i += 1)
        s += std::format("{:02x}", u8(std::string::at(raw, i)));
    return s;
};

fn crypto_json() {
    if (!auth_ok())
        return "{\n  \"present\": false,\n  \"note\": \"no AUTH chunk: this container is plaintext\"\n}\n";

    str s = "{\n";
    s += "  \"present\": true,\n";
    s += std::format("  \"cipher_id\": \"{}\",\n", auth_cipher());
    s += std::format("  \"auth_version\": {},\n", auth_version());
    s += std::format("  \"mode\": {},\n", auth_mode());
    s += std::format("  \"password_mode\": {},\n", (auth_mode() & 0x01) != 0);
    s += std::format("  \"machine_binding\": {},\n", (auth_mode() & 0x02) != 0);
    s += std::format("  \"password_section_len\": {},\n", auth_pw_len());
    s += std::format("  \"machine_section_len\": {},\n", auth_machine_len());
    s += std::format("  \"recipients\": {},\n", auth_recipients());

    if (auth_pw_len() == 65) {
        s += std::format("  \"argon2id\": {{ \"salt\": \"{}\", \"iterations\": {}, \"memory_kib\": {}, \"parallelism\": {} }},\n",
                         hex_of_hash(std::mem::read_string(auth_addr() + 20, 16)),
                         rd_u32(auth_addr() + 36),
                         rd_u32(auth_addr() + 40),
                         rd_u8(auth_addr() + 44));
    }

    s += "  \"note\": \"content chunks are sealed with AEAD framing (nonce, ciphertext, tag); ";
    s += "this pattern shows the framing but cannot open it\"\n";
    s += "}\n";
    return s;
};

fn summary_txt() {
    str s = "LUMEN container summary\n";
    s += "======================\n";
    s += std::format("file size            : {} bytes\n", file_size());
    s += std::format("header version       : {} (magic {})\n", header_version(), header_magic_ok() ? "ok" : "BAD");
    s += std::format("chunk directory      : {} entries at offset {}\n", header_chunk_count(), header_dir_offset());
    s += std::format("trailer              : magic {} crc32c {:#010x}\n",
                     trailer_magic_ok() ? "LEND ok" : "BAD", rd_u32(trailer_addr() + 4));
    s += std::format("declared uncompressed: {} bytes\n", header_total_uncompressed());
    s += std::format("header flags         : {:#010x} multi_sector={} encrypted={} retired_bits={:#x}\n",
                     header_flags(),
                     (header_flags() & HDR_MULTI_SECTOR) != 0,
                     (header_flags() & HDR_ENCRYPTED) != 0,
                     header_flags() & HDR_RETIRED);

    if (head_ok()) {
        s += "\nHEAD\n";
        s += std::format("  encoder        : {}\n", head_encoder());
        s += std::format("  created        : {} (unix seconds)\n", head_created());
        s += std::format("  display        : {} x {} px ({} pixels per layer)\n", head_w(), head_h(), u64(head_w()) * u64(head_h()));
        s += std::format("  build volume   : {} x {} x {} um\n", head_build_w(), head_build_d(), head_build_h());
        s += std::format("  layer height   : {} um over {} layers\n", head_layer_um(), head_layers());
    } else {
        s += "\nHEAD is missing\n";
    }

    if (ltbl_ok()) {
        s += "\nLTBL\n";
        s += std::format("  table version  : {}\n", ltbl_version());
        s += std::format("  layers         : {} (HEAD says {})\n", ltbl_layers(), head_ok() ? head_layers() : 0);
        s += std::format("  entry size     : {} bytes, {} entries\n", ltbl_entry_size(), ltbl_entry_count());
        s += std::format("  sectors/layer  : at most {}\n", ltbl_max_sectors());
    } else {
        s += "\nLTBL is missing\n";
    }

    if (zdic_ok() && zdic_sealed())
        s += "\nZDIC             : present, sealed (dictionary is ciphertext)\n";
    else if (zdic_ok())
        s += std::format("\nZDIC             : dictionary id {} of {} bytes ({} frames name it)\n",
                         zdic_dict_id(), zdic_dict_size(), count_dict_frames(zdic_dict_id()));
    else
        s += "\nZDIC             : absent\n";

    if (lhas_ok())
        s += std::format("LHAS             : SHA-256, {} leaves, root {}\n", lhas_layers(),
                         hex_of_hash(std::mem::read_string(lhas_addr() + 6, 32)));
    else
        s += "LHAS             : absent\n";

    if (auth_ok())
        s += std::format("AUTH             : {} v{}, mode {}, {} recipients, password section {}\n",
                         auth_cipher(), auth_version(), auth_mode(), auth_recipients(), auth_pw_len());
    else
        s += "AUTH             : absent (plaintext container)\n";

    s += "\nchunks\n";
    for (u64 i = 0, i < header_chunk_count(), i += 1) {
        if (desc_null(i)) {
            s += std::format("  [{:03d}] null descriptor\n", i);
            continue;
        }
        str extra = "";
        if (desc_type(i) == TAG_LAYR && !desc_sealed(i))
            extra = std::format("  {}", zstd_info(desc_offset(i) + 4));
        else if (is_framed(desc_type(i), desc_flags(i), desc_size_c(i)))
            extra = std::format("  {}", zstd_info(desc_offset(i)));

        s += std::format("  [{:03d}] {} at {:#x} stored {} bytes{} \n",
                         i, std::mem::read_string(desc_addr(i), 4), desc_offset(i), desc_stored(i), extra);
    }

    s += "\nvirtual file tree\n";
    s += std::format("  decoded chunks : {}\n", g_decoded);
    s += std::format("  failed to open : {} (a trained ZDIC dictionary is beyond ImHex's zstd builtin)\n", g_decode_failed);
    s += std::format("  mask files     : {} ({} pixels)\n", g_masks, g_mask_pixels);
    s += std::format("  files listed   : {} ({} not accepted by the editor)\n", g_files, g_files_failed);

    if (std::string::length(g_notes) > 0) {
        s += "\nnotes\n";
        s += g_notes;
    }
    return s;
};

fn count_dict_frames(u32 dict_id) {
    u64 n = 0;
    for (u64 i = 0, i < header_chunk_count(), i += 1) {
        if (desc_type(i) != TAG_LAYR || desc_null(i) || desc_sealed(i)) continue;
        if (u64(zstd_dict_id(desc_offset(i) + 4)) == u64(dict_id)) n += 1;
    }
    return n;
};

fn readme_txt() {
    str s = "LUMEN virtual file tree\n";
    s += "======================\n\n";
    s += "Everything in /lumen is generated by the LUMEN pattern from the loaded\n";
    s += "file. Open an entry to inspect it in its own tab; nothing here is written\n";
    s += "back to the .lumen file.\n\n";
    s += "lumen/summary.txt       decoded container summary, chunk list, notes\n";
    s += "lumen/header.json       32-byte file header and the LEND trailer\n";
    s += "lumen/directory.csv     every chunk descriptor as the directory holds it\n";
    s += "lumen/manifest.txt      every file in this tree, with its byte length\n";
    s += "lumen/head.json         the HEAD chunk: display, build volume, layers\n";
    s += "lumen/tables/layers.csv the layer table: one line per (layer, sector)\n";
    s += "lumen/tables/hashes.txt LHAS Merkle root and per-layer leaf hashes\n";
    s += "lumen/tables/crypto.json AUTH: cipher, mode, Argon2id parameters, recipients\n";
    s += "lumen/zdic/dictionary.zdict the ZDIC dictionary when the file trains one\n";
    s += "lumen/chunks/NNN-TYPE.bin   the chunk payload as stored\n";
    s += "lumen/chunks/NNN-TYPE.json  a decompressed META, PROF or LROV payload\n";
    s += "lumen/chunks/NNN-TYPE.voxl  a decompressed embedded scene\n";
    s += "lumen/chunks/NNN-LAYR.frames.bin  a LAYR frame, decompressed\n";
    s += "lumen/previews/NNN-PREV-*.png     a preview image\n";
    s += "lumen/layers/Lnnnnn-Snn.raw       one (layer, sector) mask, 8 bits per pixel\n";
    s += "lumen/layers/Lnnnnn-Snn.pgm       the same mask as a binary PGM\n\n";
    s += "Masks are written exactly over the HEAD grid, row major from the first\n";
    s += "pixel, 0x00 black and 0xFF full exposure (spec 4.1). Encoding tags are\n";
    s += "0x00 binary REE, 0x01 grayscale REE, 0x02 split REE and 0x03 attached\n";
    s += "REE (spec 5).\n\n";
    s += "Decoding a LAYR frame needs zstd without a dictionary: where the file's\n";
    s += "frames were compressed with the ZDIC dictionary, ImHex's builtin zstd\n";
    s += "decompressor cannot read them and only the stored frame is offered.\n\n";
    s += "Knobs: LUMEN_LAYER_DATA, LUMEN_MASK_BUDGET, LUMEN_MAX_MASKS,\n";
    s += "LUMEN_CHUNK_COPY_MAX, LUMEN_DECODE_MAX (see the pattern's header).\n";
    return s;
};

// =============================================================================
// Chunk bodies
// =============================================================================

bitfield ZstdFrameHeaderDescriptor {
    frame_content_size_flag : 2;   // bits 7-6
    single_segment_flag     : 1;   // bit 5
    unused_bit              : 1;   // bit 4
    reserved_bit            : 1;   // bit 3
    content_checksum_flag   : 1;   // bit 2
    dictionary_id_flag      : 2;   // bits 1-0
} [[bitfield_order(std::core::BitfieldOrder::MostToLeastSignificant, 8)]];

struct ZstdFrame {
    u32 magic;
    ZstdFrameHeaderDescriptor descriptor;

    // The frame header's optional fields follow the descriptor byte, so they are
    // read off the cursor rather than placed: their sizes depend on it.
    u64 base            = $ - 5;
    bool magic_ok       = (magic == ZSTD_MAGIC) [[export]];
    u32 header_len      = zstd_header_len(base) [[export]];
    u64 content_size    = zstd_content_size(base) [[export]];
    u64 dict_id         = zstd_dict_id(base) [[export]];
    bool checksum       = descriptor.content_checksum_flag != 0 [[export]];
    str info            = zstd_info(base) [[export]];
};

struct HeadChunk {
    u32 head_version;
    u32 encoder_name_len;
    char encoder_name[clamp_len(u64(encoder_name_len), $)];
    u64 created_unix_sec;
    u32 display_width_px;
    u32 display_height_px;
    u32 build_width_um;
    u32 build_depth_um;
    u32 build_height_um;
    u32 layer_height_um;
    u32 total_layers;

    u64 pixels_per_layer = u64(display_width_px) * u64(display_height_px) [[export]];
};

struct LtblEntry {
    u32 data_size;
    u32 first_lrov;
    u32 first_layr;
    u32 additional_sector_count;
    u64 data_offset;
    u32 sector_id;

    u32 entry_index = std::core::array_index() [[export]];
    bool empty      = (data_size == 0) [[export]];
};

struct LtblChunk {
    u32 table_version;
    u32 layer_count;
    u32 entry_size;
    u32 entry_count;
    LtblEntry entries[clamp_count(u64(entry_count), $, 28)];
};

struct LhasChunk {
    u8 hash_algorithm;
    u8 hash_size;
    u32 layer_count;
    char merkle_root[32];
    u8 layer_hashes[clamp_len(u64(layer_count) * u64(hash_size), $)];

    str merkle_root_hex = hex_of_hash(merkle_root) [[export]];
    str algorithm        = hash_algorithm == 0x01 ? "SHA-256" : std::format("unknown({})", hash_algorithm) [[export]];
};

struct ZdicChunk {
    u32 zdic_version;
    u32 dict_id;
    u32 dict_size;
    u8 dict_bytes[clamp_len(u64(dict_size), $)];
};

struct AuthPasswordSection {
    char salt[16];
    u32 iterations;
    u32 memory_kib;
    u8 parallelism;
    char wrapped_key[40];
};

struct AuthMachineEntry {
    char machine_fp[32];
    char ephemeral_pk[32];
    char wrapped_key[40];
};

struct AuthChunk {
    char cipher_id[4];
    u32 auth_version;
    u32 mode;
    u32 password_section_len;
    u32 machine_section_len;
    AuthPasswordSection password[clamp_count(u64(password_section_len), $, 65)];
    AuthMachineEntry machines[clamp_count(u64(machine_section_len), $, 104)];
};

struct LayrChunk {
    u32 layr_version;
    ZstdFrame frame;
};

struct ExtdHeader {
    u32 ext_version;
    char ext_type[4];
};

struct ChunkDescriptor {
    char chunk_type[4];
    u64 offset;
    u64 size_uncompressed;
    u64 size_compressed;
    u32 flags;

    u32 index            = std::core::array_index() [[export]];
    u32 tag              = fourcc(chunk_type[0], chunk_type[1], chunk_type[2], chunk_type[3]) [[export]];
    str kind             = kind_of(tag) [[export]];
    bool null_descriptor = (offset == 0) [[export]];
    bool sealed          = (flags & CHUNK_SEALED) != 0 [[export]];
    u64 stored_len       = clamp_len(size_compressed == 0 ? size_uncompressed : size_compressed, offset) [[export]];
    bool framed          = is_framed(tag, flags, size_compressed) [[export]];
    u64 frame_offset     = tag == TAG_LAYR ? 4 : 0;
    u64 frame_addr       = offset + frame_offset;
    u64 frame_len        = (tag == TAG_LAYR && stored_len >= 4) ? stored_len - 4 : (tag == TAG_LAYR ? 0 : stored_len);
    u64 frame_dict_id    = (framed && stored_len > 4) ? zstd_dict_id(frame_addr) : 0 [[export]];
    u64 frame_content    = (framed && stored_len > 4) ? zstd_content_size(frame_addr) : 0 [[export]];
    str detail           = tag == TAG_PREV ? std::format("role={}", preview_role(flags)) : "" [[export]];
};

// The dispatcher: one slot per entry, so a chunk type that needs a second view
// (a LAYR frame, a ZDIC dictionary) can have one.
u32 g_entry_tag;
u8 g_entry_slot[8];
bool g_entry_null;
bool g_entry_sealed;
u64 g_slice_len;      // bytes a secondary view shows, set by entry_arm
u64 g_sealed_len;     // ciphertext length of a sealed unit, set by entry_arm
u64 g_sealed_off;     // where that unit starts, set by entry_arm

// The two secondary views a chunk can carry: a LAYR frame without its version
// field, and a ZDIC dictionary without its 12-byte header. Their lengths are
// only known once the entry's descriptor has been read, so they come from here.
struct LayrFrameSlice {
    u8 bytes[g_slice_len];
};

struct DictSlice {
    u8 bytes[g_slice_len];
};

// A sealed payload is nonce, ciphertext and tag (spec 9.3). The contents need
// the key, the framing does not.
struct SealedUnit {
    char nonce[12];
    u8 ciphertext[g_sealed_len];
    char tag[16];
};

fn entry_arm(ref auto desc) {
    g_entry_tag = desc.tag;
    g_entry_null = desc.null_descriptor;
    g_entry_sealed = desc.sealed;
    for (u64 i = 0, i < 8, i += 1)
        g_entry_slot[i] = 0;

    if (desc.tag == TAG_ZDIC)
        g_slice_len = desc.stored_len > 12 ? desc.stored_len - 12 : 0;
    else
        g_slice_len = desc.frame_len;

    // A LAYR chunk keeps its 4-byte version field outside the sealed unit.
    u64 overhead = 28;
    g_sealed_off = desc.tag == TAG_LAYR ? 4 : 0;
    g_sealed_len = desc.stored_len > g_sealed_off + overhead
                 ? desc.stored_len - g_sealed_off - overhead
                 : 0;

    return kind_of(desc.tag);
};

fn entry_want(u32 tag, u64 slot) {
    if (g_entry_null) return false;
    if (g_entry_sealed) return false;   // the payload is ciphertext, not a body
    if (g_entry_slot[slot] != 0) return false;
    if (g_entry_tag != tag) return false;
    g_entry_slot[slot] = 1;
    return true;
};

fn entry_want_sealed(u64 slot) {
    if (g_entry_null) return false;
    if (!g_entry_sealed) return false;
    if (g_entry_slot[slot] != 0) return false;
    g_entry_slot[slot] = 1;
    return true;
};

struct ChunkEntry {
    ChunkDescriptor desc;

    // Arms the dispatcher below and names the entry in the pattern tree.
    str kind = entry_arm(desc) [[export]];

    HeadChunk   head[while(entry_want(TAG_HEAD, 0))] @ desc.offset;
    ZstdFrame   meta[while(entry_want(TAG_META, 0))] @ desc.offset;
    ZstdFrame   prof[while(entry_want(TAG_PROF, 0))] @ desc.offset;
    AuthChunk   auth[while(entry_want(TAG_AUTH, 0))] @ desc.offset;
    ZstdFrame   lrov[while(entry_want(TAG_LROV, 0))] @ desc.offset;
    LtblChunk   ltbl[while(entry_want(TAG_LTBL, 0))] @ desc.offset;
    ZdicChunk   zdic[while(entry_want(TAG_ZDIC, 0))] @ desc.offset;
    LayrChunk   layr[while(entry_want(TAG_LAYR, 0))] @ desc.offset;
    LhasChunk   lhas[while(entry_want(TAG_LHAS, 0))] @ desc.offset;
    ZstdFrame   voxl[while(entry_want(TAG_VOXL, 0))] @ desc.offset;
    ExtdHeader  extd[while(entry_want(TAG_EXTD, 0))] @ desc.offset;

    // Second view: the bytes a decoder or a reader wants on their own.
    LayrFrameSlice layr_frame[while(entry_want(TAG_LAYR, 1))] @ desc.frame_addr;
    DictSlice zdic_dict[while(entry_want(TAG_ZDIC, 1))] @ desc.offset + 12;

    // What a reader without the key can still see of a sealed chunk.
    SealedUnit sealed_unit[while(entry_want_sealed(1))] @ desc.offset + desc.frame_offset;

    u8 raw[desc.stored_len] @ desc.offset;

    str emitted = emit_chunk(desc, raw, layr_frame, zdic_dict) [[export]];
};

struct DirectoryTrailer {
    char magic[4];
    u32 crc32c;
};

struct FileHeader {
    char magic[4];
    u32 version;
    u64 dir_offset;
    u32 chunk_count;
    u32 flags;
    u64 total_uncompressed_size;

    bool magic_ok        = (magic[0] == 'L') && (magic[1] == 'U') && (magic[2] == 'M') && (magic[3] == 'N') [[export]];
    bool multi_sector    = (flags & HDR_MULTI_SECTOR) != 0 [[export]];
    bool encrypted       = (flags & HDR_ENCRYPTED) != 0 [[export]];
    u32 retired_flag_bits = flags & HDR_RETIRED [[export]];
};

// =============================================================================
// The container, and the report that follows the walk
// =============================================================================

struct Report {
    u64 file_size               = file_size() [[export]];
    bool magic_ok               = header_magic_ok() [[export]];
    bool trailer_magic_ok       = trailer_magic_ok() [[export]];
    u64 chunk_count             = header_chunk_count() [[export]];
    u64 layers                  = head_ok() ? head_layers() : 0 [[export]];
    u64 display_w               = head_ok() ? head_w() : 0 [[export]];
    u64 display_h               = head_ok() ? head_h() : 0 [[export]];
    u64 ltbl_entries            = ltbl_ok() ? ltbl_entry_count() : 0 [[export]];
    u64 ltbl_max_sectors        = ltbl_ok() ? ltbl_max_sectors() : 0 [[export]];
    u64 dict_id                 = zdic_ok() ? zdic_dict_id() : 0 [[export]];
    bool has_dictionary         = zdic_ok() [[export]];
    u64 merkle_leaves           = lhas_ok() ? lhas_layers() : 0 [[export]];
    bool encrypted              = auth_ok() [[export]];
    u64 decoded_chunks          = g_decoded [[export]];
    u64 decode_failed           = g_decode_failed [[export]];
    u64 masks_emitted           = g_masks [[export]];
    u64 vfs_files               = g_files [[export]];

    // Written last, so the manifest holds everything the walk produced.
    u64 readme_bytes            = vfs_text("/lumen/README.txt", readme_txt()) [[export]];
    u64 summary_bytes           = vfs_text("/lumen/summary.txt", summary_txt()) [[export]];
    u64 header_bytes            = vfs_text("/lumen/header.json", header_json()) [[export]];
    u64 head_bytes              = vfs_text("/lumen/head.json", head_json()) [[export]];
    u64 directory_bytes         = vfs_text("/lumen/directory.csv", directory_csv()) [[export]];
    u64 layers_bytes            = vfs_text("/lumen/tables/layers.csv", layers_csv()) [[export]];
    u64 hashes_bytes            = vfs_text("/lumen/tables/hashes.txt", hashes_txt()) [[export]];
    u64 crypto_bytes            = vfs_text("/lumen/tables/crypto.json", crypto_json()) [[export]];
    u64 manifest_bytes          = vfs_text("/lumen/manifest.txt", g_manifest, false) [[export]];

    str notes                   = g_notes [[export]];
    str manifest                = g_manifest [[export]];
};

struct Lumen {
    FileHeader header @ 0x00;
    ChunkEntry entries[header.chunk_count] @ header.dir_offset;
    DirectoryTrailer trailer @ trailer_addr();
    Report report @ 0x00;
};

Lumen lumen @ 0x00;
