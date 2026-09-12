#!/usr/bin/env python3
"""Independent validator for the .lumen test vectors.

This deliberately shares no code with make_vectors.py: the primitives and the
reader logic are reimplemented from the specification, so agreement between the
two is evidence that the spec is unambiguous rather than that one module is
self-consistent.

Usage:
    python verify_vectors.py            # validate the committed corpus
    python verify_vectors.py -v         # list every individual check

Exit code 0 only if every valid vector passes and every invalid vector fails
exactly the check it advertises.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

import zstandard as zstd

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "manifest.json")

# ---------------------------------------------------------------- primitives

_P = 0x82F63B78
_T = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_P if _c & 1 else 0)
    _T.append(_c)


def crc32c(data: bytes) -> int:
    c = 0xFFFFFFFF
    for b in data:
        c = _T[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    val = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise ValueError("varint runs past the end of its buffer")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return val, pos
        if pos - start > 10:
            raise ValueError("varint longer than 10 bytes")


def merkle_root(leaves: list[bytes]) -> bytes:
    level = list(leaves)
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


# ------------------------------------------------------------ REE decoders

def dec_binary(body: bytes, total: int):
    """body[0] is first_value. Returns (mask, end, violations)."""
    v = []
    if not body:
        raise ValueError("empty binary REE stream")
    fv = body[0]
    if fv not in (0, 255):
        v.append("first_value is neither 0x00 nor 0xFF")
    k, pos = read_varint(body, 1)
    lengths = []
    for _ in range(max(k - 1, 0)):
        d, pos = read_varint(body, pos)
        lengths.append(d)
    if k == 0:
        v.append("run_count == 0 is not canonical")
    if any(l < 1 for l in lengths):
        v.append("a stored run length is < 1")
    if total - sum(lengths) < 1:
        v.append("the implicit final run length is < 1")
    mask = bytearray(total)
    value = fv
    start = 0
    for i in range(k):
        end = total if i == k - 1 else start + lengths[i]
        if end > total or end < start:
            raise ValueError("run end out of range")
        mask[start:end] = bytes([value]) * (end - start)
        value = 255 - value
        start = end
    return mask, pos, v


def dec_grayscale(body: bytes, total: int, strict: bool):
    v = []
    k, pos = read_varint(body, 0)
    mask = bytearray(total)
    prev_value = None
    start = 0
    for _ in range(k):
        value = body[pos]
        pos += 1
        end, pos = read_varint(body, pos)
        if end <= start:
            v.append("end positions are not strictly increasing")
        if end > total:
            raise ValueError("end position past total_pixels")
        if value == prev_value:
            v.append("adjacent runs share a value")
        mask[start:end] = bytes([value]) * (end - start)
        start = end
        prev_value = value
    if start != total:
        v.append("the final end position is not total_pixels")
    if k == 0:
        v.append("run_count == 0 is not canonical")
    return mask, pos, v


def dec_split(body: bytes, total: int):
    v = []
    mask, pos, bv = dec_binary(body, total)
    v += bv
    n, pos = read_varint(body, pos)
    positions = []
    prev = 0
    for _ in range(n):
        d, pos = read_varint(body, pos)
        if d < 1:
            v.append("overlay positions are not strictly increasing")
        prev += d
        positions.append(prev)
    values = list(body[pos:pos + n])
    pos += n
    for p, val in zip(positions, values):
        if p >= total:
            raise ValueError("overlay position past total_pixels")
        mask[p] = val
    # canonical: the overlay must be exactly the non-0x00/0xFF pixels
    expect = [(i, mask[i]) for i in range(total) if mask[i] not in (0, 255)]
    if [p for p, _ in expect] != positions or [x for _, x in expect] != values:
        v.append("overlay is not exactly the set of non-binary pixels")
    return mask, pos, v


# ------------------------------------------------------------- file reader

class Checks:
    def __init__(self, verbose: bool):
        self.items: list[tuple[str, bool]] = []
        self.verbose = verbose

    def __call__(self, name: str, ok: bool, detail: str = "") -> bool:
        self.items.append((name, bool(ok)))
        if self.verbose:
            print("      %-32s %s%s" % (name, "PASS" if ok else "FAIL",
                                        ("  " + detail) if detail and not ok else ""))
        return bool(ok)

    def failed(self) -> list[str]:
        return [n for n, ok in self.items if not ok]


def validate(path: str, strict: bool, verbose: bool = False):
    chk = Checks(verbose)
    raw = open(path, "rb").read()

    # ---- structural ----------------------------------------------------
    if not chk("trailer.magic", len(raw) >= 8 and raw[-8:-4] == b"LEND"):
        return chk
    stored_crc = struct.unpack_from("<I", raw, len(raw) - 4)[0]
    chk("trailer.crc32c", crc32c(raw[:-8]) == stored_crc)
    if not chk("header.magic", raw[:4] == b"LUMN"):
        return chk
    chk("header.version", struct.unpack_from("<I", raw, 4)[0] == 1)
    dir_off, chunk_count = struct.unpack_from("<QI", raw, 8)
    flags = struct.unpack_from("<I", raw, 20)[0]
    total_uncompressed = struct.unpack_from("<Q", raw, 24)[0]
    if not chk("dir.bounds", 32 <= dir_off and dir_off + chunk_count * 32 <= len(raw) - 8):
        return chk

    entries = []
    for i in range(chunk_count):
        base = dir_off + i * 32
        ctype = raw[base:base + 4]
        off, usz, csz, cflags = struct.unpack_from("<QQQI", raw, base + 4)
        entries.append({"type": ctype, "offset": off, "usz": usz, "csz": csz, "flags": cflags})

    real = [e for e in entries if e["offset"] != 0]
    chk("chunk.hdr_first", bool(real) and real[0]["type"] == b"HDR\0" and real[0]["offset"] == 32)
    extents = sorted((e["offset"], e["offset"] + (e["csz"] or e["usz"])) for e in real)
    chk("chunk.overlap", all(extents[i][1] <= extents[i + 1][0] for i in range(len(extents) - 1)))
    chk("chunk.bounds", all(e["offset"] + (e["csz"] or e["usz"]) <= len(raw) - 8 for e in real))

    def find(ctype):
        hits = [e for e in real if e["type"] == ctype]
        return hits

    def payload(e):
        n = e["csz"] or e["usz"]
        blob = raw[e["offset"]:e["offset"] + n]
        if e["csz"]:
            blob = zstd.ZstdDecompressor().decompress(blob, max_output_size=e["usz"])
        return blob

    chk("presence.meta", len(find(b"META")) == 1)
    chk("presence.ltbl", len(find(b"LTBL")) == 1)
    chk("presence.layr", len(find(b"LAYR")) == 1)
    if flags & 0x02:
        chk("presence.sect", len(find(b"SECT")) >= 1)
    chk("presence.lhas", len(find(b"LHAS")) == 1)

    # ---- HDR -----------------------------------------------------------
    hdr = payload(find(b"HDR\0")[0])
    hdr_version, name_len = struct.unpack_from("<II", hdr, 0)
    chk("hdr.version", hdr_version == 1)
    chk("hdr.encoder_name_fits", len(hdr) >= 52 + name_len and name_len <= 256)
    (created, disp_w, disp_h, phys_w, phys_h) = struct.unpack_from("<QIIII", hdr, 8 + name_len)
    (build_w, build_d, build_h, layer_h, total_layers) = struct.unpack_from("<ffffI", hdr, 32 + name_len)
    chk("hdr.total_layers", total_layers > 0)
    chk("hdr.physical_ratio", phys_w % disp_w == 0 and phys_h % disp_h == 0)
    total_pixels = disp_w * disp_h

    # ---- META / SECT ---------------------------------------------------
    meta = json.loads(payload(find(b"META")[0]))
    mats = meta.get("materials")
    chk("meta.required_fields", all(k in meta for k in (
        "meta_version", "normal_exposure_sec", "bottom_exposure_sec", "bottom_layer_count",
        "transition_layer_count", "layer_height_mm", "lift_distance_mm", "lift_speed_mm_min",
        "retract_distance_mm", "retract_speed_mm_min")))
    chk("meta.materials_shape", mats is None or (
        isinstance(mats, list) and len(mats) > 0
        and all(isinstance(m, dict) and m.get("name") for m in mats)))
    sects = [json.loads(payload(e)) for e in find(b"SECT")]
    chk("sect.sector_id_nonzero", all(s.get("sector_id", 0) >= 1 for s in sects))
    chk("sect.ids_unique", len({s["sector_id"] for s in sects}) == len(sects))
    chk("sect.material_index_bounds", all(
        "material_index" not in s or (mats is not None and 0 <= s["material_index"] < len(mats))
        for s in sects))

    # ---- LTBL ----------------------------------------------------------
    ltbl = payload(find(b"LTBL")[0])
    table_version, layer_count, entry_size = struct.unpack_from("<III", ltbl, 0)
    chk("ltbl.table_version", table_version == 1)
    chk("ltbl.entry_size", entry_size >= 20)
    chk("hdr.total_layers_matches_ltbl", layer_count == total_layers)
    entries_l = []
    for i in range(layer_count):
        o = 12 + i * entry_size
        data_offset, block_index, data_size, sector_count = struct.unpack_from("<QIII", ltbl, o)
        entries_l.append({"data_offset": data_offset, "block_index": block_index,
                          "data_size": data_size, "sector_count": sector_count})

    # ---- LAYR ----------------------------------------------------------
    layr = payload(find(b"LAYR")[0])
    layr_version, block_count, bt_entry = struct.unpack_from("<III", layr, 0)
    chk("layr.version", layr_version == 1)
    chk("layr.block_count", 1 <= block_count <= total_layers)
    blocks = []
    for k in range(block_count):
        o = 12 + k * bt_entry
        fo, fs, us = struct.unpack_from("<QQQ", layr, o)
        blocks.append({"frame_offset": fo, "frame_size": fs, "uncompressed_size": us})
    body_off = 12 + block_count * bt_entry
    chk("layr.block_table_contiguous",
        blocks[0]["frame_offset"] == 0 and
        all(blocks[k + 1]["frame_offset"] == blocks[k]["frame_offset"] + blocks[k]["frame_size"]
            for k in range(block_count - 1)))
    chk("layr.block_end_within_payload",
        blocks[-1]["frame_offset"] + blocks[-1]["frame_size"] <= len(layr) - body_off)
    chk("ltbl.block_index_in_range", all(e["block_index"] < block_count for e in entries_l))
    chk("ltbl.block_index_monotonic",
        all(entries_l[i]["block_index"] <= entries_l[i + 1]["block_index"] for i in range(layer_count - 1)))
    chk("layr.blocks_referenced", {e["block_index"] for e in entries_l} == set(range(block_count)))
    chk("ltbl.empty_layer_no_bytes", all(e["data_size"] == 0 for e in entries_l if e["sector_count"] == 0))
    chk("ltbl.offsets_within_block", all(
        e["block_index"] < block_count
        and e["data_offset"] + e["data_size"] <= blocks[e["block_index"]]["uncompressed_size"]
        for e in entries_l))

    # dictionary
    zdic = find(b"ZDIC")
    dict_bytes = b""
    dict_id = 0
    if zdic:
        zd = payload(zdic[0])
        zver, dict_id, dsize = struct.unpack_from("<III", zd, 0)
        dict_bytes = zd[12:12 + dsize]
        chk("zdic.version", zver == 1)
        chk("zdic.present_for_dict", dsize > 0)
    zctx = zstd.ZstdCompressionDict(dict_bytes) if dict_bytes else None
    dctx = zstd.ZstdDecompressor(dict_data=zctx) if zctx else zstd.ZstdDecompressor()

    dict_ids = []
    outputs = []
    ok_sizes = True
    decompress_ok = True
    for k, blk in enumerate(blocks):
        try:
            frame = layr[body_off + blk["frame_offset"]: body_off + blk["frame_offset"] + blk["frame_size"]]
            dict_ids.append(zstd.get_frame_parameters(frame).dict_id)
            out = dctx.decompress(frame, max_output_size=blk["uncompressed_size"])
        except Exception:
            decompress_ok = False
            dict_ids.append(None)
            outputs.append(b"")
            continue
        ok_sizes &= len(out) == blk["uncompressed_size"]
        outputs.append(out)
    chk("layr.block_decompress", decompress_ok)
    chk("layr.block_sizes_exact", ok_sizes and decompress_ok)
    if zdic:
        chk("layr.dict_id_match", all(d == dict_id for d in dict_ids))
    else:
        chk("layr.dict_id_absent", all(d == 0 for d in dict_ids))

    # ---- LHAS + layer decode -------------------------------------------
    lhas = payload(find(b"LHAS")[0])
    alg, hsize, lhas_count = struct.unpack_from("<BBI", lhas, 0)
    root = lhas[6:38]
    leaves = [lhas[38 + 32 * i: 38 + 32 * (i + 1)] for i in range(lhas_count)]
    chk("lhas.hash_algorithm", alg == 1 and hsize == 32)
    chk("lhas.layer_count", lhas_count == total_layers)
    chk("lhas.root_recompute", merkle_root(leaves) == root)

    layer_data = []
    for i, e in enumerate(entries_l):
        if e["block_index"] >= block_count:
            layer_data.append(b"")
            continue
        blob = outputs[e["block_index"]][e["data_offset"]: e["data_offset"] + e["data_size"]]
        layer_data.append(blob)
    if strict:
        chk("lhas.leaf_match",
            all(hashlib.sha256(b"\x00" + layer_data[i]).digest() == leaves[i] for i in range(layer_count)))

    # ---- REE / sector decode -------------------------------------------
    CODE_OF = {
        "run_count == 0 is not canonical": "ree.no_run_count_zero",
        "a stored run length is < 1": "ree.binary_lengths",
        "the implicit final run length is < 1": "ree.binary_lengths",
        "binary REE produced a non-binary pixel": "ree.binary_lengths",
        "first_value is neither 0x00 nor 0xFF": "ree.binary_first_value",
        "end positions are not strictly increasing": "ree.grayscale_ends",
        "the final end position is not total_pixels": "ree.grayscale_ends",
        "adjacent runs share a value": "ree.grayscale_adjacent",
        "overlay is not exactly the set of non-binary pixels": "ree.split_overlay",
        "overlay positions are not strictly increasing": "ree.split_overlay",
        "binary content encoded as grayscale REE": "ree.canonical_tag_choice",
        "trailing bytes after the REE stream": "ree.no_trailing_bytes",
    }
    STRICT_ONLY = {"ree.no_run_count_zero", "ree.binary_lengths", "ree.grayscale_adjacent",
                   "ree.split_overlay", "ree.canonical_tag_choice"}
    REE_ORDER = ["ree.tag_known", "ree.binary_first_value", "ree.binary_lengths",
                 "ree.grayscale_ends", "ree.grayscale_adjacent", "ree.no_run_count_zero",
                 "ree.split_overlay", "ree.canonical_tag_choice", "ree.no_trailing_bytes",
                 "ree.truncated_sector"]
    hits: set[str] = set()
    detail: dict[str, str] = {}
    sector_match = True
    ids_unique = True
    partition_ok = True

    for i, e in enumerate(entries_l):
        blob = layer_data[i]
        if e["sector_count"] == 0:
            continue
        try:
            if flags & 0x02:
                n, pos = read_varint(blob, 0)
                if n != e["sector_count"]:
                    sector_match = False
                sectors = []
                ids = []
                for _ in range(n):
                    sid, pos = read_varint(blob, pos)
                    size, pos = read_varint(blob, pos)
                    sectors.append(blob[pos:pos + size])
                    pos += size
                    ids.append(sid)
                if len(set(ids)) != len(ids):
                    ids_unique = False
            else:
                sectors = [blob]
            masks = []
            for sub in sectors:
                if not sub:
                    hits.add("ree.truncated_sector")
                    detail.setdefault("ree.truncated_sector", "layer %d: empty sector data" % i)
                    continue
                tag, body = sub[0], sub[1:]
                if tag not in (0x00, 0x01, 0x02):
                    hits.add("ree.tag_known")
                    continue
                if tag == 0x00:
                    mask, end, v = dec_binary(body, total_pixels)
                elif tag == 0x01:
                    mask, end, v = dec_grayscale(body, total_pixels, strict)
                    if strict and all(x in (0, 255) for x in mask):
                        v.append("binary content encoded as grayscale REE")
                else:
                    mask, end, v = dec_split(body, total_pixels)
                if end != len(body):
                    v.append("trailing bytes after the REE stream")
                masks.append(mask)
                for msg in v:
                    code = CODE_OF.get(msg)
                    if code:
                        hits.add(code)
                        detail.setdefault(code, "layer %d: %s" % (i, msg))
            for a in range(len(masks)):
                for b_ in range(a + 1, len(masks)):
                    if any(x and y for x, y in zip(masks[a], masks[b_])):
                        partition_ok = False
        except Exception as exc:
            hits.add("ree.truncated_sector")
            detail.setdefault("ree.truncated_sector", "layer %d: %s" % (i, exc))

    chk("sector.count_match", sector_match)
    chk("sector.ids_unique", ids_unique)
    for name in REE_ORDER:
        if name in STRICT_ONLY and not strict:
            continue
        chk(name, name not in hits, detail.get(name, ""))
    if strict:
        chk("sector.partition", partition_ok)

    # ---- manifest agreement --------------------------------------------
    chk("__checks_complete", True)
    return chk


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if crc32c(b"123456789") != 0xE3069283:
        print("FATAL: CRC-32C self-test failed")
        return 2

    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    failures = 0

    print("valid vectors")
    for v in manifest["valid"]:
        path = os.path.join(HERE, v["file"])
        chk = validate(path, strict=True, verbose=args.verbose)
        bad = chk.failed()
        ref = check_manifest(v, path)
        if ref:
            bad += ref
        status = "PASS" if not bad else "FAIL"
        print("  %-4s %-24s %d checks%s" % (status, v["name"], len(chk.items),
                                            "" if not bad else "  -> " + ", ".join(bad)))
        failures += bool(bad)

    print("invalid vectors")
    for v in manifest["invalid"]:
        path = os.path.join(HERE, v["file"])
        strict = not v.get("strict_only")
        chk = validate(path, strict=True, verbose=args.verbose)
        loose = validate(path, strict=False) if v.get("strict_only") else None
        expect = v["expected_failure"]
        names = [n for n, _ in chk.items]
        hit = [n for n, ok in chk.items if not ok]
        ok = expect in hit and hit[0] == expect
        extra = ""
        if v.get("strict_only"):
            ok = ok and not loose.failed()
            extra = " (accepted in loose mode: %s)" % ("yes" if not loose.failed() else "NO")
        status = "PASS" if ok else "FAIL"
        print("  %-4s %-28s expects %-28s got %s%s"
              % (status, v["name"], expect, hit[0] if hit else "(nothing failed)", extra))
        failures += not ok

    print()
    print("corpus:", "OK" if not failures else "%d FAILURES" % failures)
    return 1 if failures else 0


def check_manifest(v: dict, path: str) -> list[str]:
    """Compare the committed bytes against the recorded golden values."""
    bad = []
    raw = open(path, "rb").read()
    if len(raw) != v["file_size"]:
        bad.append("manifest.file_size")
    if hashlib.sha256(raw).hexdigest() != v["file_sha256"]:
        bad.append("manifest.file_sha256")
    dir_off, chunk_count = struct.unpack_from("<QI", raw, 8)
    if dir_off != v["dir_offset"] or chunk_count != v["chunk_count"]:
        bad.append("manifest.directory")
    if struct.unpack_from("<Q", raw, 24)[0] != v["total_uncompressed_size"]:
        bad.append("manifest.total_uncompressed_size")
    if struct.unpack_from("<I", raw, 20)[0] != v["header_flags"]:
        bad.append("manifest.header_flags")
    if ("0x%08X" % struct.unpack_from("<I", raw, len(raw) - 4)[0]) != v["trailer_crc32c"]:
        bad.append("manifest.trailer_crc32c")

    # structural comparison against the recorded layout
    entries = []
    for i in range(chunk_count):
        base = dir_off + i * 32
        off, usz, csz, _f = struct.unpack_from("<QQQI", raw, base + 4)
        entries.append((raw[base:base + 4], off, usz, csz))
    by_type = {e[0]: e for e in entries}
    layr_off = by_type[b"LAYR"][1]
    _v, block_count, bt = struct.unpack_from("<III", raw, layr_off)
    if block_count != len(v["blocks"]):
        bad.append("manifest.block_count")
    else:
        for k, blk in enumerate(v["blocks"]):
            fo, fs, us = struct.unpack_from("<QQQ", raw, layr_off + 12 + k * bt)
            if (fo, fs, us) != (blk["frame_offset"], blk["frame_size"], blk["uncompressed_size"]):
                bad.append("manifest.block[%d]" % k)
                break
    lhas_off = by_type[b"LHAS"][1]
    if raw[lhas_off + 6: lhas_off + 38].hex() != v["merkle_root"]:
        bad.append("manifest.merkle_root")
    ltbl_off = by_type[b"LTBL"][1]
    _tv, n, es = struct.unpack_from("<III", raw, ltbl_off)
    for i, rec in enumerate(v["layers"]):
        o = ltbl_off + 12 + i * es
        do, bi, ds, sc = struct.unpack_from("<QIII", raw, o)
        if (bi, ds, sc) != (rec["block_index"], rec["data_size"], rec["sector_count"]):
            bad.append("manifest.layer[%d]" % i)
            break
        leaf = raw[lhas_off + 38 + 32 * i: lhas_off + 38 + 32 * (i + 1)].hex()
        if leaf != rec["lhas_leaf"]:
            bad.append("manifest.layer[%d].lhas_leaf" % i)
            break
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
