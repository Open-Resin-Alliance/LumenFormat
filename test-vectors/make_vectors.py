#!/usr/bin/env python3
"""Reference encoder for the .lumen test vectors in this directory.

This is spec tooling, not the production encoder. It exists so the corpus is
reproducible and auditable: every byte of the valid vectors is produced here,
from the rules in the specification. It implements the subset the vectors
exercise - HDR, META, SECT, ZDIC, LTBL, LAYR, LHAS, the chunk directory and the
trailer.

Usage:
    python make_vectors.py

Requires: zstandard (pip install zstandard)
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

import zstandard as zstd

HERE = os.path.dirname(os.path.abspath(__file__))
VALID_DIR = os.path.join(HERE, "valid")
INVALID_DIR = os.path.join(HERE, "invalid")

MAGIC = b"LUMN"
TRAILER_MAGIC = b"LEND"
HEADER_SIZE = 32
DESCRIPTOR_SIZE = 32
CHUNK_ALIGN = 8
LTBL_ENTRY_SIZE = 20
BLOCK_TABLE_ENTRY_SIZE = 24
ZSTD_LAYER_LEVEL = 6
ZSTD_SMALL_LEVEL = 3
CREATED_UNIX_SEC = 1757000000

FLAG_MULTI_SECTOR = 0x02
FLAG_ENCRYPTED = 0x08

TAG_BINARY = 0x00
TAG_GRAYSCALE = 0x01
TAG_SPLIT = 0x02


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

_CRC32C_POLY = 0x82F63B78
_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_CRC32C_POLY if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli). Self-test vector: b"123456789" -> 0xE3069283."""
    c = 0xFFFFFFFF
    for b in data:
        c = _CRC32C_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint is unsigned")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def runs_from_spans(total: int, spans) -> list[tuple[int, int]]:
    """Build canonical (length, value) runs covering `total` pixels.

    `spans` is an iterable of (start, end, value); pixels not covered are black.
    Adjacent equal values are merged, so the result alternates.
    """
    events = sorted((s, e, v) for s, e, v in spans if e > s)
    out: list[tuple[int, int]] = []

    def push(length: int, value: int) -> None:
        if length <= 0:
            return
        if out and out[-1][1] == value:
            out[-1] = (out[-1][0] + length, value)
        else:
            out.append((length, value))

    pos = 0
    for s, e, v in events:
        if s < pos:
            raise ValueError("overlapping spans")
        push(s - pos, 0)
        push(e - s, v)
        pos = e
    push(total - pos, 0)
    return out


# --------------------------------------------------------------------------
# REE encoders (canonical forms only - see spec section 5.6)
# --------------------------------------------------------------------------

def enc_binary(runs: list[tuple[int, int]]) -> bytes:
    """Binary REE body: first_value, run_count, K-1 run lengths."""
    if not runs:
        return b""
    if len(runs) == 1:
        return bytes([runs[0][1]]) + varint(1)
    fv = runs[0][1]
    if fv not in (0, 255):
        raise ValueError("binary REE values must be 0x00 or 0xFF")
    out = bytearray([fv, *varint(len(runs))])
    for length, _ in runs[:-1]:
        assert length >= 1
        out += varint(length)
    return bytes(out)


def enc_grayscale(runs: list[tuple[int, int]]) -> bytes:
    """Grayscale REE body: run_count, then (value, end_pos) per run."""
    out = bytearray(varint(len(runs)))
    pos = 0
    for i, (length, value) in enumerate(runs):
        if length < 1:
            raise ValueError("zero-length run")
        if i and runs[i - 1][1] == value:
            raise ValueError("adjacent runs share a value")
        pos += length
        out.append(value)
        out += varint(pos)
    return bytes(out)


def split_overlay(runs: list[tuple[int, int]]) -> tuple[list[int], list[int]]:
    """Positions and values of the non-0x00/0xFF pixels, in index order."""
    positions: list[int] = []
    values: list[int] = []
    pos = 0
    for length, value in runs:
        if value not in (0, 255):
            positions.extend(range(pos, pos + length))
            values.extend([value] * length)
        pos += length
    return positions, values


def enc_split(runs: list[tuple[int, int]]) -> bytes:
    """Split REE body: binary REE over the thresholded mask, then the AA overlay."""
    thresholded: list[tuple[int, int]] = []
    for length, value in runs:
        b = 255 if value >= 128 else 0
        if thresholded and thresholded[-1][1] == b:
            thresholded[-1] = (thresholded[-1][0] + length, b)
        else:
            thresholded.append((length, b))
    positions, values = split_overlay(runs)
    out = bytearray(enc_binary(thresholded))
    out += varint(len(positions))
    prev = 0
    for p in positions:
        out += varint(p - prev)
        prev = p
    out += bytes(values)
    return bytes(out)


def pick_tag(runs: list[tuple[int, int]], prefer_split: bool) -> int | None:
    """Canonical tag choice (spec 5.6). None means the empty-layer form."""
    if all(v == 0 for _, v in runs):
        return None
    if all(v in (0, 255) for _, v in runs):
        return TAG_BINARY
    return TAG_SPLIT if prefer_split else TAG_GRAYSCALE


def encode_sector(runs: list[tuple[int, int]], prefer_split: bool) -> bytes | None:
    """Encoded sector body (tag + mask data), or None for an empty sector."""
    tag = pick_tag(runs, prefer_split)
    if tag is None:
        return None
    if tag == TAG_BINARY:
        return bytes([TAG_BINARY]) + enc_binary(runs)
    if tag == TAG_GRAYSCALE:
        return bytes([TAG_GRAYSCALE]) + enc_grayscale(runs)
    return bytes([TAG_SPLIT]) + enc_split(runs)


# --------------------------------------------------------------------------
# Merkle tree (spec 4.11: domain-separated leaves, promote the odd node)
# --------------------------------------------------------------------------

def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError("no leaves")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def leaf_hash(layer_bytes: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + layer_bytes).digest()


# --------------------------------------------------------------------------
# chunk payload builders
# --------------------------------------------------------------------------

def hdr_payload(encoder_name: str, display_w: int, display_h: int, build_w: float,
                build_d: float, build_h: float, layer_height: float,
                total_layers: int) -> bytes:
    name = encoder_name.encode()
    return (
        struct.pack("<II", 1, len(name))
        + name
        + struct.pack("<QIIII", CREATED_UNIX_SEC, display_w, display_h, display_w, display_h)
        + struct.pack("<ffffI", build_w, build_d, build_h, layer_height, total_layers)
    )


def meta_payload(**overrides) -> bytes:
    meta = {
        "meta_version": 1,
        "normal_exposure_sec": 2.5,
        "bottom_exposure_sec": 30.0,
        "bottom_layer_count": 2,
        "transition_layer_count": 1,
        "layer_height_mm": 0.05,
        "lift_distance_mm": 5.0,
        "lift_speed_mm_min": 65.0,
        "retract_distance_mm": 5.0,
        "retract_speed_mm_min": 150.0,
    }
    meta.update(overrides)
    return json.dumps(meta, indent=2, sort_keys=True).encode()


def sect_payload(sector_id: int, name: str, exposure: float) -> bytes:
    return json.dumps({
        "sector_id": sector_id,
        "name": name,
        "material_index": 0,
        "normal_exposure_sec": exposure,
    }, indent=2, sort_keys=True).encode()


def ltbl_payload(entries) -> bytes:
    out = bytearray(struct.pack("<III", 1, len(entries), LTBL_ENTRY_SIZE))
    for e in entries:
        out += struct.pack("<QIII", e["data_offset"], e["block_index"],
                           e["data_size"], e["sector_count"])
    return bytes(out)


def lhas_payload(leaves: list[bytes]) -> bytes:
    root = merkle_root(leaves)
    out = bytearray(struct.pack("<BBI", 0x01, 32, len(leaves)))
    out += root
    for leaf in leaves:
        out += leaf
    return bytes(out)


def zdic_payload(dict_bytes: bytes, dict_id: int) -> bytes:
    return struct.pack("<III", 1, dict_id, len(dict_bytes)) + dict_bytes


def layr_payload(frames: list[bytes], uncompressed_sizes: list[int]) -> bytes:
    table = bytearray()
    offset = 0
    for frame, usize in zip(frames, uncompressed_sizes):
        table += struct.pack("<QQQ", offset, len(frame), usize)
        offset += len(frame)
    return struct.pack("<III", 1, len(frames), BLOCK_TABLE_ENTRY_SIZE) + bytes(table) + b"".join(frames)


# --------------------------------------------------------------------------
# container assembly
# --------------------------------------------------------------------------

def build_file(chunks: list[dict], header_flags: int) -> tuple[bytes, dict]:
    """chunks: list of {type, payload, compressed, flags} in file order.

    HDR must be first, which places its payload at offset 32. Payloads are
    aligned to CHUNK_ALIGN (spec 3.2 recommends 8); the gaps are free because
    the directory carries explicit offsets.
    """
    body = bytearray()
    pos = HEADER_SIZE
    entries = []
    layout = {}
    total_uncompressed = 0

    for ch in chunks:
        pad = (-pos) % CHUNK_ALIGN
        body += b"\x00" * pad
        pos += pad
        payload = ch["payload"]
        if ch.get("compressed"):
            stored = zstd.ZstdCompressor(level=ZSTD_SMALL_LEVEL).compress(payload)
            size_uncompressed, size_compressed = len(payload), len(stored)
        else:
            stored = payload
            size_uncompressed, size_compressed = len(payload), 0
        layout[ch["type"].decode().rstrip("\0") + "_off"] = pos
        entries.append({
            "type": ch["type"],
            "offset": pos,
            "size_uncompressed": size_uncompressed,
            "size_compressed": size_compressed,
            "flags": ch.get("flags", 0),
        })
        body += stored
        pos += len(stored)
        total_uncompressed += size_uncompressed

    dir_offset = pos
    directory = bytearray()
    for e in entries:
        directory += e["type"] + struct.pack("<QQQI", e["offset"], e["size_uncompressed"],
                                              e["size_compressed"], e["flags"])
    pos += len(directory)

    header = MAGIC + struct.pack("<IQII", 1, dir_offset, len(entries), header_flags)
    header += struct.pack("<Q", total_uncompressed)
    assert len(header) == HEADER_SIZE

    file_bytes = bytearray(header + body + directory)
    crc = crc32c(bytes(file_bytes))
    file_bytes += TRAILER_MAGIC + struct.pack("<I", crc)

    layout["dir_offset"] = dir_offset
    layout["trailer_offset"] = len(file_bytes) - 8
    layout["entries"] = entries
    return bytes(file_bytes), layout


# --------------------------------------------------------------------------
# vector construction
# --------------------------------------------------------------------------

def build_vector(name: str, description: str, features: list[str], display: tuple[int, int],
                 layer_height: float, layers, block_size: int, use_dict: bool,
                 dict_samples_bytes: int = 2048, split_layers=(), force_run_count_zero=(),
                 meta_extra: dict | None = None):
    """layers: list of (list of sector spans). One sector per layer => single-sector."""
    w, h = display
    total = w * h

    multi_sector = any(len(s) > 1 for s in layers)
    layer_bytes: list[bytes] = []
    sector_counts: list[int] = []
    tags: list[int | None] = []
    sector_tags: list[list[int]] = []

    for idx, sectors in enumerate(layers):
        encoded = [(sid, encode_sector(runs_from_spans(total, spans), idx in split_layers))
                   for sid, spans in enumerate(sectors)]
        encoded = [(sid, body) for sid, body in encoded if body is not None]
        if idx in force_run_count_zero:
            # Non-canonical all-black form: tag 0x00, first_value 0x00, run_count 0.
            layer_bytes.append(bytes([TAG_BINARY, 0x00]) + varint(0))
            sector_counts.append(1)
            tags.append(TAG_BINARY)
            sector_tags.append([TAG_BINARY])
            continue
        if not encoded:
            layer_bytes.append(b"")
            sector_counts.append(0)
            tags.append(None)
            sector_tags.append([])
            continue
        if not multi_sector:
            data = encoded[0][1]
        else:
            # Every layer in a multi-sector file carries the sector_count varint,
            # including layers with a single active sector.
            data = bytearray(varint(len(encoded)))
            for sid, body in encoded:
                data += varint(sid)
                data += varint(len(body))
                data += body
            data = bytes(data)
        layer_bytes.append(data)
        sector_counts.append(len(encoded))
        tags.append(data[0] if not multi_sector else None)
        sector_tags.append([body[0] for _, body in encoded])

    # dictionary
    dict_bytes = b""
    dict_id = 0
    if use_dict:
        samples = [b for b in layer_bytes if b]
        d = zstd.train_dictionary(dict_samples_bytes, samples)
        dict_bytes = d.as_bytes()
        dict_id = d.dict_id()
    cctx = zstd.ZstdCompressor(level=ZSTD_LAYER_LEVEL,
                               dict_data=zstd.ZstdCompressionDict(dict_bytes)) if use_dict else \
           zstd.ZstdCompressor(level=ZSTD_LAYER_LEVEL)

    # blocks
    frames, uncompressed_sizes, entries = [], [], []
    for start in range(0, len(layer_bytes), block_size):
        block_index = start // block_size
        group = list(range(start, min(start + block_size, len(layer_bytes))))
        payload = b"".join(layer_bytes[i] for i in group)
        frame = cctx.compress(payload)
        frames.append(frame)
        uncompressed_sizes.append(len(payload))
        offset = 0
        for i in group:
            entries.append({"block_index": block_index, "data_offset": offset,
                            "data_size": len(layer_bytes[i]), "sector_count": sector_counts[i]})
            offset += len(layer_bytes[i])

    leaves = [leaf_hash(b) for b in layer_bytes]

    chunks = [
        {"type": b"HDR\0", "payload": hdr_payload(
            "LumenFormat test vectors 1.0", w, h, 218.0, 123.0, 250.0, layer_height, len(layers))},
        {"type": b"META", "payload": meta_payload(**(meta_extra or {})), "compressed": True},
    ]
    if multi_sector:
        chunks.append({"type": b"SECT", "payload": sect_payload(1, "Support", 3.0),
                       "compressed": True})
    if use_dict:
        chunks.append({"type": b"ZDIC", "payload": zdic_payload(dict_bytes, dict_id)})
    chunks += [
        {"type": b"LTBL", "payload": ltbl_payload(entries)},
        {"type": b"LHAS", "payload": lhas_payload(leaves)},
        {"type": b"LAYR", "payload": layr_payload(frames, uncompressed_sizes)},
    ]

    raw, layout = build_file(chunks, FLAG_MULTI_SECTOR if multi_sector else 0)

    meta = {
        "name": name,
        "description": description,
        "features": features,
        "display_width_px": w,
        "display_height_px": h,
        "total_layers": len(layers),
        "layer_height_mm": layer_height,
        "block_size_layers": block_size,
        "header_flags": FLAG_MULTI_SECTOR if multi_sector else 0,
        "multi_sector": multi_sector,
        "chunk_count": len(chunks),
        "dir_offset": layout["dir_offset"],
        "total_uncompressed_size": struct.unpack_from("<Q", raw, 24)[0],
        "trailer_crc32c": "0x%08X" % struct.unpack_from("<I", raw, layout["trailer_offset"] + 4)[0],
        "file_size": len(raw),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "dict": {"present": bool(use_dict), "dict_id": dict_id, "dict_size": len(dict_bytes)},
        "blocks": [{"frame_offset": sum(len(f) for f in frames[:k]),
                    "frame_size": len(frames[k]),
                    "uncompressed_size": uncompressed_sizes[k]}
                   for k in range(len(frames))],
        "merkle_root": merkle_root(leaves).hex(),
        "layers": [{"index": i, "block_index": entries[i]["block_index"],
                    "data_offset": entries[i]["data_offset"],
                    "data_size": entries[i]["data_size"],
                    "sector_count": sector_counts[i],
                    "tag": tags[i],
                    "sector_tags": sector_tags[i],
                    "decompressed_sha256": hashlib.sha256(layer_bytes[i]).hexdigest(),
                    "lhas_leaf": leaves[i].hex()} for i in range(len(layers))],
    }
    return raw, meta, layout


# --------------------------------------------------------------------------
# vectors
# --------------------------------------------------------------------------

T = 64 * 48
T2 = 256 * 192


def vector_binary_basic():
    """6 layers, three tags, no dictionary, three blocks."""
    layers = [
        [((0, 0, 0),)],                                            # all black -> empty form
        [((100, 300, 255),)],
        [((50, 60, 255), (100, 110, 255))],
        [((100, 120, 128), (220, 320, 255))],                      # grayscale
        [((100, 130, 200), (150, 200, 255))],                      # split (prefer_split)
        [((3000, 3072, 255),)],
    ]
    return build_vector(
        "binary-basic", "Six layers covering the empty-layer form, binary REE, grayscale REE and split REE, across three blocks with no dictionary.",
        ["empty-layer", "binary-ree", "grayscale-ree", "split-ree", "multi-block", "no-dictionary"],
        (64, 48), 0.05, layers, block_size=2, use_dict=False, split_layers={4})


def vector_dict():
    """64 layers with a trained dictionary, four blocks."""
    layers = []
    for i in range(64):
        spans = []
        pos = 0
        for k in range(60):
            gap = 40 + ((i * 7 + k * 13) % 60)
            length = 20 + ((i + k) % 40)
            start = pos + gap
            if start + length >= T2:
                break
            value = 255 if (i + k) % 3 else 128 + ((i * k) % 100)
            spans.append((start, start + length, value))
            pos = start + length
        layers.append([tuple(spans)])
    return build_vector(
        "dict-multi-block", "64 layers with a trained ZDIC dictionary, four blocks of sixteen layers.",
        ["dictionary", "dictionary-id", "multi-block", "grayscale-ree", "split-ree"],
        (256, 192), 0.05, layers, block_size=16, use_dict=True, dict_samples_bytes=1024,
        split_layers=set(range(0, 64, 2)))


def vector_multisector():
    """4 layers, two sectors, partition invariant."""
    layers = [
        [((0, 100, 255),), ((200, 300, 255),)],
        [((0, 64, 255),)],
        [((0, 0, 0),)],                                            # empty layer
        [((500, 600, 255),), ((1000, 1100, 255),)],
    ]
    return build_vector(
        "multi-sector", "Four layers with two non-overlapping sectors, exercising the multi-sector varint framing and the sector partition invariant.",
        ["multi-sector", "sector-framing", "empty-layer", "binary-ree"],
        (64, 48), 0.05, layers, block_size=2, use_dict=False,
        meta_extra={"materials": [{"name": "Standard Grey", "brand": "DragonFruit",
                                   "family": "standard", "density_g_ml": 1.1,
                                   "color_rgba": [128, 128, 128, 255]}]})


def main() -> int:
    assert crc32c(b"123456789") == 0xE3069283, "CRC-32C self-test failed"
    os.makedirs(VALID_DIR, exist_ok=True)
    os.makedirs(INVALID_DIR, exist_ok=True)

    manifest = {"valid": [], "invalid": [], "generator": {
        "python": sys.version.split()[0],
        "zstandard": zstd.__version__,
        "zstd_layer_level": ZSTD_LAYER_LEVEL,
        "zstd_small_level": ZSTD_SMALL_LEVEL,
        "note": "Compressed payload bytes depend on the zstd version and level. "
                "Uncompressed structures (HDR, LTBL, LAYR header and block table, "
                "LHAS, REE streams, directory, trailer) are exact.",
    }}

    for builder in (vector_binary_basic, vector_dict, vector_multisector):
        raw, meta, layout = builder()
        path = os.path.join(VALID_DIR, meta["name"] + ".lumen")
        with open(path, "wb") as fh:
            fh.write(raw)
        meta["file"] = "valid/" + meta["name"] + ".lumen"
        manifest["valid"].append(meta)
        print("wrote %-28s %6d bytes, %2d chunks, %d blocks"
              % (meta["file"], len(raw), meta["chunk_count"], len(meta["blocks"])))

    # ---------------- invalid vectors ----------------
    def emit_invalid(name, description, expected, raw, strict_only=False, base=None):
        path = os.path.join(INVALID_DIR, name + ".lumen")
        with open(path, "wb") as fh:
            fh.write(raw)
        manifest["invalid"].append({
            "name": name, "file": "invalid/" + name + ".lumen",
            "description": description, "expected_failure": expected,
            "strict_only": strict_only, "base_vector": base,
            "file_size": len(raw), "file_sha256": hashlib.sha256(raw).hexdigest(),
        })
        print("wrote %-28s %6d bytes -> expects %s%s"
              % ("invalid/" + name + ".lumen", len(raw), expected,
                 " (strict mode only)" if strict_only else ""))

    def repack(raw, layout):
        """Recompute the trailer CRC-32C after a mutation."""
        b = bytearray(raw)
        b[layout["trailer_offset"] + 4:layout["trailer_offset"] + 8] = \
            struct.pack("<I", crc32c(bytes(b[:layout["trailer_offset"]])))
        return bytes(b)

    raw, meta, layout = vector_binary_basic()

    # x01: an empty layer (sector_count 0) that claims bytes
    b = bytearray(raw)
    struct.pack_into("<I", b, layout["LTBL_off"] + 12 + 0 * LTBL_ENTRY_SIZE + 12, 2)
    emit_invalid("empty-layer-with-bytes",
                 "LTBL entry 0 has sector_count 0 but data_size 2.", "ltbl.empty_layer_no_bytes",
                 repack(b, layout), base="binary-basic")

    # x02: the non-canonical run_count == 0 all-black form (decodable, not canonical)
    raw2, meta2, _ = build_vector(
        "x-source", "source", [], (64, 48), 0.05,
        [[((0, 0, 0),)] for _ in range(4)], block_size=2, use_dict=False,
        force_run_count_zero={0})
    emit_invalid("run-count-zero-all-black",
                 "Layer 0 stores all-black as tag 0x00 with run_count 0 instead of the empty-layer form.",
                 "ree.no_run_count_zero", raw2, strict_only=True, base=None)

    # x03: block_index out of range
    b = bytearray(raw)
    struct.pack_into("<I", b, layout["LTBL_off"] + 12 + 1 * LTBL_ENTRY_SIZE + 8, 99)
    emit_invalid("block-index-out-of-range",
                 "LTBL entry 1 points at block 99 when the file has three blocks.",
                 "ltbl.block_index_in_range", repack(b, layout), base="binary-basic")

    # x04: a gap in the block table
    b = bytearray(raw)
    first_frame_size = struct.unpack_from("<Q", b, layout["LAYR_off"] + 12 + 8)[0]
    struct.pack_into("<Q", b, layout["LAYR_off"] + 12 + BLOCK_TABLE_ENTRY_SIZE, first_frame_size + 1)
    emit_invalid("block-table-gap",
                 "Block 1 frame_offset leaves a one-byte gap, breaking contiguity.",
                 "layr.block_table_contiguous", repack(b, layout), base="binary-basic")

    # x05: merkle root does not match the leaf table
    b = bytearray(raw)
    b[layout["LHAS_off"] + 6] ^= 0xFF
    emit_invalid("merkle-root-mismatch",
                 "One byte of merkle_root is flipped, so recomputation from layer_hashes disagrees.",
                 "lhas.root_recompute", repack(b, layout), base="binary-basic")

    # x06: layer hash does not match the layer bytes (root recomputed to stay consistent)
    b = bytearray(raw)
    leaves_off = layout["LHAS_off"] + 38
    n_layers = struct.unpack_from("<I", b, layout["LHAS_off"] + 2)[0]
    leaves = [bytes(b[leaves_off + 32 * i: leaves_off + 32 * (i + 1)]) for i in range(n_layers)]
    leaves[0] = bytes([leaves[0][0] ^ 0xFF]) + leaves[0][1:]
    for i, leaf in enumerate(leaves):
        b[leaves_off + 32 * i: leaves_off + 32 * (i + 1)] = leaf
    b[layout["LHAS_off"] + 6: layout["LHAS_off"] + 38] = merkle_root(leaves)
    emit_invalid("layer-hash-mismatch",
                 "Layer 0's stored leaf hash is altered and merkle_root recomputed to match, so only hashing the actual bytes catches it.",
                 "lhas.leaf_match", repack(b, layout), strict_only=True, base="binary-basic")

    # x07: layer byte range runs past the end of its block
    b = bytearray(raw)
    struct.pack_into("<I", b, layout["LTBL_off"] + 12 + 2 * LTBL_ENTRY_SIZE + 12, 0xFFFFFF)
    emit_invalid("layer-range-past-block",
                 "LTBL entry 2 claims a data_size far beyond its block's decompressed size.",
                 "ltbl.offsets_within_block", repack(b, layout), base="binary-basic")

    # x08: corrupted trailer CRC (the only failure that is not repacked)
    b = bytearray(raw)
    b[layout["trailer_offset"] + 4] ^= 0xFF
    emit_invalid("trailer-crc-mismatch",
                 "The trailer CRC-32C does not match the file bytes.", "trailer.crc32c",
                 bytes(b), base="binary-basic")

    with open(os.path.join(HERE, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("\nmanifest.json: %d valid, %d invalid"
          % (len(manifest["valid"]), len(manifest["invalid"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
