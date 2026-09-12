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
import zlib
from importlib.metadata import version as package_version

import zstandard as zstd
from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

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
FLAG_CHUNK_ENCRYPTED = 0x10

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


def prof_payload(settings_extra: dict | None = None, **overrides) -> bytes:
    """A reusable print profile (spec 4.3), with META's field names under `settings`."""
    prof = {
        "profile_name": "LumenFormat test profile",
        "profile_version": "1.0.0",
        "profile_type": "combined",
        "profile_uuid": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        "settings": {
            "normal_exposure_sec": 2.5,
            "bottom_exposure_sec": 32.0,
            "bottom_layer_count": 5,
            "transition_layer_count": 8,
            "layer_height_mm": 0.05,
            "lift_distance_mm": 5.0,
            "lift_speed_mm_min": 65.0,
            "lift_distance2_mm": 3.0,
            "lift_speed2_mm_min": 200.0,
            "retract_distance_mm": 4.0,
            "retract_speed_mm_min": 150.0,
            "retract_distance2_mm": 2.0,
            "retract_speed2_mm_min": 180.0,
            "bottom_lift_distance_mm": 6.0,
            "bottom_lift_speed_mm_min": 50.0,
            "bottom_retract_distance_mm": 6.0,
            "bottom_retract_speed_mm_min": 100.0,
            "wait_time_before_cure_sec": 1.0,
            "wait_time_after_cure_sec": 0.0,
            "wait_time_after_lift_sec": 0.5,
            "delay_mode": "light_off",
            "light_off_delay_sec": 1.0,
            "light_pwm": 255,
            "chamber_temperature_c": 30.0,
            "vat_temperature_c": 28.0,
            "cure_curve": {"dp_um": 120.0, "ec_mj_cm2": 7.5, "e0_mj_cm2": 3.0},
        },
        "materials": [
            {"name": "ABS-Like Grey", "brand": "DragonFruit", "family": "abs-like",
             "density_g_ml": 1.1, "color_rgba": [128, 128, 128, 255],
             "bottle_price": 29.99, "bottle_capacity_ml": 1000},
        ],
        "scale_compensation_pct": {"x": 0.5, "y": 0.5, "z": 0.0},
        "extra": {},
    }
    if settings_extra:
        prof["settings"].update(settings_extra)
    prof.update(overrides)
    return json.dumps(prof, indent=2, sort_keys=True).encode()


def lrov_payload(overrides: list) -> bytes:
    """Layer overrides (spec 4.6)."""
    return json.dumps({"overrides": overrides}, indent=2, sort_keys=True).encode()


def png_preview(width: int, height: int, rgb=(200, 200, 200)) -> bytes:
    """A minimal deterministic 8-bit RGB PNG for PREV vectors (spec 4.7)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))
    rows = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def extd_payload(ext_type: bytes, ext_data: bytes, ext_version: int = 1, vendor_id: int = 0,
                 critical: bool = False, flags_extra: int = 0) -> tuple[bytes, int]:
    """An EXTD chunk payload and its descriptor flags (spec 4.13).

    The frame is `ext_version || ext_type || ext_data`. The descriptor's flags carry
    the vendor id in bits 8-23 and the critical bit at 24; `flags_extra` is for the
    invalid vectors that set a reserved bit on purpose.
    """
    flags = ((vendor_id & 0xFFFF) << 8) | (0x01000000 if critical else 0) | flags_extra
    return struct.pack("<I", ext_version) + ext_type + ext_data, flags


def voxl_payload(**overrides) -> bytes:
    """A minimal V1 VOXL scene document (spec 4.12).

    Synthetic, not a real slice: a LUMEN file embeds a scene so it can be handed
    back unchanged, and never parses it - which is exactly what the VOXL vectors
    pin. A V1 document starts with `{`, which is how a reader recognizes the
    generation without knowing anything else about VOXL.
    """
    doc = {
        "magic": "VOXL",
        "version": 1,
        "meta": {"generator": "LumenFormat test vectors", "printer": "Test printer"},
        "scene": {"name": "embedded-scene", "units": "mm"},
        "models": [],
        "supports": [],
    }
    doc.update(overrides)
    return json.dumps(doc, indent=2, sort_keys=True).encode()


def payload_hashes(chunks: list[dict]) -> dict:
    """SHA-256 of each PROF/LROV/PREV plaintext payload, as the manifest records it."""
    out: dict = {}
    for ch in chunks:
        name = ch["type"].decode("ascii").rstrip("\x00")
        if name not in ("PROF", "LROV", "PREV", "VOXL", "EXTD"):
            continue
        digest = hashlib.sha256(ch["payload"]).hexdigest()
        if name in ("PREV", "EXTD"):
            out.setdefault(name, []).append(digest)
        else:
            out[name] = digest
    return out


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
        if "sealed" in ch:
            # A framed, encrypted unit: size_uncompressed is the plaintext length it
            # yields after decrypt + decompress, size_compressed the on-disk length
            # including the 28-byte AEAD framing (spec 3.2, 9.3).
            stored = ch["sealed"]
            size_uncompressed, size_compressed = ch["size_uncompressed"], len(stored)
        elif ch.get("compressed"):
            size_uncompressed = len(ch["payload"])
            stored = zstd.ZstdCompressor(level=ZSTD_SMALL_LEVEL).compress(ch["payload"])
            size_compressed = len(stored)
        else:
            stored = ch["payload"]
            size_uncompressed, size_compressed = len(stored), 0
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

def encode_layers(display: tuple[int, int], layers, block_size: int, use_dict: bool,
                  dict_samples_bytes: int, split_layers, force_run_count_zero) -> dict:
    """Everything about one vector's layer data, before it is stored.

    Shared by the plaintext and encrypted builders: encryption changes how the
    block frames and content chunks are stored, never what they decode to.
    """
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

    return {"multi_sector": multi_sector, "layer_bytes": layer_bytes,
            "sector_counts": sector_counts, "tags": tags, "sector_tags": sector_tags,
            "frames": frames, "uncompressed_sizes": uncompressed_sizes, "entries": entries,
            "leaves": leaves, "use_dict": use_dict, "dict_bytes": dict_bytes, "dict_id": dict_id}


def sparse_layers(count: int, total: int) -> list:
    """`count` layers of scattered runs, for vectors that need dictionary samples."""
    layers = []
    for i in range(count):
        spans = []
        pos = 0
        for k in range(60):
            gap = 40 + ((i * 7 + k * 13) % 60)
            length = 20 + ((i + k) % 40)
            start = pos + gap
            if start + length >= total:
                break
            value = 255 if (i + k) % 3 else 128 + ((i * k) % 100)
            spans.append((start, start + length, value))
            pos = start + length
        layers.append([tuple(spans)])
    return layers


def content_chunks(enc: dict, encoder_name: str, display: tuple[int, int], layer_height: float,
                   layer_count: int, meta_extra, prof: bytes | None = None,
                   lrov: bytes | None = None, prevs=(), voxl: bytes | None = None,
                   extds=()) -> list[dict]:
    """The chunk list before any encryption, in the order section 3 recommends.

    `prevs` is a list of (payload, role, seal) triples: a PREV's role lives in its
    chunk descriptor flags, and its sealing is optional even in an encrypted file
    (spec 4.7, 9.1).
    """
    w, h = display
    chunks = [
        {"type": b"HDR\0", "payload": hdr_payload(
            encoder_name, w, h, 218.0, 123.0, 250.0, layer_height, layer_count)},
        {"type": b"META", "payload": meta_payload(**(meta_extra or {})), "compressed": True},
    ]
    if prof is not None:
        chunks.append({"type": b"PROF", "payload": prof, "compressed": True})
    if enc["multi_sector"]:
        chunks.append({"type": b"SECT", "payload": sect_payload(1, "Support", 3.0),
                       "compressed": True})
    if lrov is not None:
        chunks.append({"type": b"LROV", "payload": lrov, "compressed": True})
    if enc["use_dict"]:
        chunks.append({"type": b"ZDIC", "payload": zdic_payload(enc["dict_bytes"], enc["dict_id"])})
    for payload, role, seal_prev in prevs:
        chunks.append({"type": b"PREV", "payload": payload, "flags": role, "seal": seal_prev})
    if voxl is not None:
        chunks.append({"type": b"VOXL", "payload": voxl, "compressed": True})
    for payload, flags in extds:
        chunks.append({"type": b"EXTD", "payload": payload, "compressed": True, "flags": flags})
    chunks += [
        {"type": b"LTBL", "payload": ltbl_payload(enc["entries"])},
        {"type": b"LHAS", "payload": lhas_payload(enc["leaves"])},
        {"type": b"LAYR", "payload": layr_payload(enc["frames"], enc["uncompressed_sizes"])},
    ]
    return chunks


def stored_block_table(raw: bytes, layout: dict) -> list[dict]:
    """The LAYR block table exactly as written to the file.

    Read back rather than recomputed: an encrypted vector's frames are sealed, so
    their frame_size includes the 28-byte AEAD overhead (spec 4.10, 9.3), and the
    manifest must describe the bytes that are actually there.
    """
    off = layout["LAYR_off"]
    _version, block_count, entry_size = struct.unpack_from("<III", raw, off)
    return [dict(zip(("frame_offset", "frame_size", "uncompressed_size"),
                     struct.unpack_from("<QQQ", raw, off + 12 + k * entry_size)))
            for k in range(block_count)]


def vector_meta(name: str, description: str, features: list[str], display: tuple[int, int],
                layer_height: float, block_size: int, enc: dict, chunks: list[dict],
                raw: bytes, layout: dict, crypto: dict | None = None,
                chunk_hashes: dict | None = None) -> dict:
    """The manifest entry's golden data for one vector."""
    w, h = display
    meta = {
        "name": name,
        "description": description,
        "features": features,
        "display_width_px": w,
        "display_height_px": h,
        "total_layers": len(enc["layer_bytes"]),
        "layer_height_mm": layer_height,
        "block_size_layers": block_size,
        "header_flags": struct.unpack_from("<I", raw, 20)[0],
        "multi_sector": enc["multi_sector"],
        "chunk_count": len(chunks),
        "dir_offset": layout["dir_offset"],
        "total_uncompressed_size": struct.unpack_from("<Q", raw, 24)[0],
        "trailer_crc32c": "0x%08X" % struct.unpack_from("<I", raw, layout["trailer_offset"] + 4)[0],
        "file_size": len(raw),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "dict": {"present": enc["use_dict"], "dict_id": enc["dict_id"],
                 "dict_size": len(enc["dict_bytes"])},
        "blocks": stored_block_table(raw, layout),
        "merkle_root": merkle_root(enc["leaves"]).hex(),
        "layers": [{"index": i, "block_index": enc["entries"][i]["block_index"],
                    "data_offset": enc["entries"][i]["data_offset"],
                    "data_size": enc["entries"][i]["data_size"],
                    "sector_count": enc["sector_counts"][i],
                    "tag": enc["tags"][i],
                    "sector_tags": enc["sector_tags"][i],
                    "decompressed_sha256": hashlib.sha256(enc["layer_bytes"][i]).hexdigest(),
                    "lhas_leaf": enc["leaves"][i].hex()} for i in range(len(enc["layer_bytes"]))],
    }
    if crypto is not None:
        meta["crypto"] = crypto
    if chunk_hashes:
        meta["chunk_payload_sha256"] = chunk_hashes
    return meta


def build_vector(name: str, description: str, features: list[str], display: tuple[int, int],
                 layer_height: float, layers, block_size: int, use_dict: bool,
                 dict_samples_bytes: int = 2048, split_layers=(), force_run_count_zero=(),
                 meta_extra: dict | None = None, prof: bytes | None = None,
                 lrov: bytes | None = None, prevs=(), voxl: bytes | None = None, extds=()):
    """layers: list of (list of sector spans). One sector per layer => single-sector."""
    enc = encode_layers(display, layers, block_size, use_dict, dict_samples_bytes,
                        split_layers, force_run_count_zero)
    chunks = content_chunks(enc, "LumenFormat test vectors 1.0", display, layer_height,
                            len(layers), meta_extra, prof, lrov, prevs, voxl, extds)
    raw, layout = build_file(chunks, FLAG_MULTI_SECTOR if enc["multi_sector"] else 0)
    meta = vector_meta(name, description, features, display, layer_height, block_size, enc,
                       chunks, raw, layout, chunk_hashes=payload_hashes(chunks))
    return raw, meta, layout


# --------------------------------------------------------------------------
# encryption (spec 4.4, 9)
# --------------------------------------------------------------------------

SEED = b"LUMEN test vectors v1.0"
TEST_PASSWORD = "lumen-test-vector"
MACHINE_INFO = b"LUMEN machine-binding v1\x00"
DEFAULT_ARGON2 = (1, 8, 1)          # iterations, memory_kib, parallelism
ENC_CONTENT_TYPES = (b"LAYR", b"META", b"PROF", b"SECT", b"LROV", b"VOXL", b"ZDIC")


def det(label: bytes, length: int) -> bytes:
    """Deterministic test material, so the corpus regenerates byte for byte.

    Real encoders MUST draw every nonce, salt and key from a CSPRNG (spec 9.3);
    these values are public test data and demonstrate nothing about production
    randomness.
    """
    return hashlib.shake_256(SEED + b"|" + label).digest(length)


def unit_aad(chunk_type: bytes, unit_index: int) -> bytes:
    """AAD binds a sealed unit to its identity in the file (spec 9.3)."""
    return chunk_type + b"\x00" + struct.pack("<I", unit_index)


def seal(key: bytes, cipher_id: str, chunk_type: bytes, unit_index: int, plaintext: bytes) -> bytes:
    """One sealed unit: nonce || ciphertext || tag (spec 9.3)."""
    nonce = det(b"nonce|" + chunk_type + b"|%d" % unit_index, 12)
    aead = AESGCM(key) if cipher_id == "A256" else ChaCha20Poly1305(key)
    return nonce + aead.encrypt(nonce, plaintext, unit_aad(chunk_type, unit_index))


def argon2_kek(password: str, salt: bytes, iterations: int, memory_kib: int,
               parallelism: int) -> bytes:
    """Argon2id per RFC 9106: version 0x13, 32-byte output, UTF-8 password."""
    return hash_secret_raw(secret=password.encode(), salt=salt, time_cost=iterations,
                           memory_cost=memory_kib, parallelism=parallelism, hash_len=32,
                           type=Argon2Type.ID)


def password_section(session_key: bytes, password: str, salt: bytes, iterations: int,
                     memory_kib: int, parallelism: int) -> bytes:
    kek = argon2_kek(password, salt, iterations, memory_kib, parallelism)
    return (salt + struct.pack("<IIB", iterations, memory_kib, parallelism)
            + aes_key_wrap(kek, session_key))


def public_of(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def fingerprint(public: bytes) -> bytes:
    return hashlib.sha256(public).digest()


def machine_kek(ss: bytes, ephemeral_pk: bytes, fp: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=fp,
                info=MACHINE_INFO + ephemeral_pk + fp).derive(ss)


def machine_entry(session_key: bytes, recipient_private: bytes, label: bytes) -> bytes:
    """One recipient entry: machine_fp || ephemeral_pk || wrapped_key (spec 4.4.2)."""
    recipient_public = public_of(recipient_private)
    fp = fingerprint(recipient_public)
    eph = X25519PrivateKey.from_private_bytes(det(b"ephemeral|" + label, 32))
    ephemeral_pk = eph.public_key().public_bytes_raw()
    ss = eph.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    return fp + ephemeral_pk + aes_key_wrap(machine_kek(ss, ephemeral_pk, fp), session_key)


def decoy_entry(recipient_public: bytes, label: bytes) -> bytes:
    """An entry for our own fingerprint whose ephemeral key is the low-order point.

    X25519 against it yields the all-zero shared secret, which a reader MUST
    reject (spec 4.4.2 step 1). It carries a *different* session key, so a reader
    that unwraps it without checking cannot decrypt the file at all.
    """
    fp = fingerprint(recipient_public)
    ephemeral_pk = bytes(32)
    return (fp + ephemeral_pk
            + aes_key_wrap(machine_kek(bytes(32), ephemeral_pk, fp),
                           det(b"decoy-session-key|" + label, 32)))


def auth_payload(cipher_id: str, mode: int, password_sec: bytes = b"",
                 machine_sec: bytes = b"") -> bytes:
    return (cipher_id.encode()
            + struct.pack("<IIII", 1, mode, len(password_sec), len(machine_sec))
            + password_sec + machine_sec)


def seal_content_chunks(chunks: list[dict], enc: dict, key: bytes, cipher_id: str) -> list[dict]:
    """Seal every content chunk (spec 9.1).

    LAYR keeps its header and block table plaintext and seals each block frame
    separately, so per-block random access still works (spec 9.3).
    """
    out = []
    for ch in chunks:
        ctype = ch["type"]
        if ctype == b"LAYR":
            sealed_frames = [seal(key, cipher_id, b"LAYR", k, frame)
                             for k, frame in enumerate(enc["frames"])]
            out.append({"type": b"LAYR",
                        "payload": layr_payload(sealed_frames, enc["uncompressed_sizes"]),
                        "flags": FLAG_CHUNK_ENCRYPTED})
        elif ctype in ENC_CONTENT_TYPES or ch.get("seal"):
            plain = ch["payload"]
            stored = (zstd.ZstdCompressor(level=ZSTD_SMALL_LEVEL).compress(plain)
                      if ch.get("compressed") else plain)
            # Keep any chunk-specific flag bits (a PREV carries its role in bits 0-3)
            # and add the sealed bit.
            out.append({"type": ctype, "sealed": seal(key, cipher_id, ctype, 0, stored),
                        "size_uncompressed": len(plain),
                        "flags": ch.get("flags", 0) | FLAG_CHUNK_ENCRYPTED})
        else:
            out.append(ch)
    return out


def build_encrypted_vector(name: str, description: str, features: list[str],
                           display: tuple[int, int], layer_height: float, layers,
                           block_size: int, cipher_id: str, mode: int, use_dict: bool = False,
                           dict_samples_bytes: int = 1024, split_layers=(), meta_extra=None,
                           argon2_params=None, password_trim: int = 0, machine_roles=(),
                           session_key: bytes | None = None, prof: bytes | None = None,
                           lrov: bytes | None = None, prevs=(), voxl: bytes | None = None,
                           extds=()):
    """An encrypted file: the same content chunks, sealed, plus an AUTH chunk.

    `machine_roles` lists the recipient entries in file order; the role "local"
    marks the entry whose private key the manifest publishes.
    """
    enc = encode_layers(display, layers, block_size, use_dict, dict_samples_bytes,
                        split_layers, ())
    session_key = session_key or det(b"session-key|" + name.encode(), 32)
    salt = det(b"argon2-salt|" + name.encode(), 16)
    iterations, memory_kib, parallelism = argon2_params or DEFAULT_ARGON2

    password_sec = b""
    if mode & 1:
        password_sec = password_section(session_key, TEST_PASSWORD, salt, iterations,
                                        memory_kib, parallelism)
        if password_trim:
            password_sec = password_sec[:-password_trim]
        else:
            # The published password must really recover the session key.
            kek = argon2_kek(TEST_PASSWORD, salt, iterations, memory_kib, parallelism)
            assert aes_key_unwrap(kek, password_sec[25:]) == session_key, \
                "password section self-check failed"

    machine_sec = b""
    local_index = None
    local_private = det(b"machine-private|" + name.encode(), 32)
    for role in machine_roles:
        if role == "local":
            local_index = len(machine_sec) // 104
            machine_sec += machine_entry(session_key, local_private, name.encode())
        elif role == "foreign":
            machine_sec += machine_entry(session_key, det(b"foreign-private|" + name.encode(), 32),
                                         name.encode() + b"|foreign")
        elif role == "decoy":
            machine_sec += decoy_entry(public_of(local_private), name.encode())
        else:
            raise ValueError("unknown recipient role %r" % (role,))

    chunks = content_chunks(enc, "LumenFormat test vectors 1.0", display, layer_height,
                            len(layers), meta_extra, prof, lrov, prevs, voxl, extds)
    sealed = seal_content_chunks(chunks, enc, session_key, cipher_id)
    auth = {"type": b"AUTH", "payload": auth_payload(cipher_id, mode, password_sec, machine_sec)}
    after = 3 if prof is not None else 2      # section 3 lists PROF before AUTH
    ordered = sealed[:after] + [auth] + sealed[after:]

    header_flags = FLAG_ENCRYPTED | (FLAG_MULTI_SECTOR if enc["multi_sector"] else 0)
    raw, layout = build_file(ordered, header_flags)

    crypto = {
        "cipher_id": cipher_id,
        "auth_version": 1,
        "mode": mode,
        "mode_names": [n for bit, n in ((1, "password"), (2, "machine-binding")) if mode & bit],
    }
    if mode & 1:
        crypto["password_utf8"] = TEST_PASSWORD
        crypto["argon2"] = {"salt": salt.hex(), "iterations": iterations,
                            "memory_kib": memory_kib, "parallelism": parallelism}
    if mode & 2 and local_index is not None:
        crypto["local_recipient_index"] = local_index
        crypto["local_recipient_private_key"] = local_private.hex()

    meta = vector_meta(name, description, features, display, layer_height, block_size, enc,
                       ordered, raw, layout, crypto=crypto, chunk_hashes=payload_hashes(chunks))
    return raw, meta, layout


def vector_encrypted_password():
    """Password mode, AES-256-GCM, dictionary, two sealed blocks."""
    return build_encrypted_vector(
        "encrypted-password",
        "Password-mode AES-256-GCM: an Argon2id-wrapped session key, a sealed dictionary and metadata, and two blocks of sealed layer frames.",
        ["encryption", "password-mode", "aes-256-gcm", "argon2id", "dictionary",
         "sealed-blocks", "multi-block"],
        (256, 192), 0.05, sparse_layers(32, T2), block_size=16, cipher_id="A256", mode=1,
        use_dict=True, dict_samples_bytes=1024, split_layers=set(range(0, 32, 2)))


def vector_encrypted_machine():
    """Machine mode, ChaCha20-Poly1305, one block, three recipient entries."""
    layers = [
        [((0, 120, 255),)],
        [((0, 200, 128), (300, 460, 255),)],
        [((0, 0, 0),)],
        [((600, 700, 255),)],
    ]
    return build_encrypted_vector(
        "encrypted-machine",
        "Machine-mode ChaCha20-Poly1305 with three recipient entries: a foreign machine, a decoy entry for our own fingerprint whose ephemeral key is the low-order point, and the real entry. A reader that unwraps the decoy without rejecting the all-zero shared secret recovers a different session key and cannot decrypt the file.",
        ["encryption", "machine-binding", "chacha20-poly1305", "x25519", "hkdf",
         "multiple-recipients", "low-order-point"],
        (64, 48), 0.05, layers, block_size=4, cipher_id="C20P", mode=2,
        split_layers={1}, machine_roles=("foreign", "decoy", "local"))


def vector_encrypted_both():
    """Both wrapping modes in one AUTH, multi-sector content."""
    layers = [
        [((0, 100, 255),), ((200, 300, 255),)],
        [((0, 64, 255),)],
        [((0, 0, 0),)],
        [((500, 600, 255),), ((1000, 1100, 255),)],
        [((0, 900, 255),)],
        [((70, 90, 200), (150, 200, 255),)],
    ]
    return build_encrypted_vector(
        "encrypted-both",
        "Both wrapping modes set in one AUTH chunk, with multi-sector layer content sealed under a single session key.",
        ["encryption", "password-mode", "machine-binding", "multi-sector", "sealed-sectors",
         "aes-256-gcm"],
        (64, 48), 0.05, layers, block_size=2, cipher_id="A256", mode=3,
        split_layers={5}, machine_roles=("local",),
        meta_extra={"materials": [{"name": "Standard Grey", "brand": "DragonFruit",
                                   "family": "standard", "density_g_ml": 1.1,
                                   "color_rgba": [128, 128, 128, 255]}]})


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
    return build_vector(
        "dict-multi-block", "64 layers with a trained ZDIC dictionary, four blocks of sixteen layers.",
        ["dictionary", "dictionary-id", "multi-block", "grayscale-ree", "split-ree"],
        (256, 192), 0.05, sparse_layers(64, T2), block_size=16, use_dict=True,
        dict_samples_bytes=1024, split_layers=set(range(0, 64, 2)))


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


def vector_print_profile():
    """Encrypted, carrying a reusable print profile."""
    return build_encrypted_vector(
        "print-profile",
        "Password-mode AES-256-GCM with a sealed PROF chunk: profile identity, a material library, and a settings block reusing META's field names, including the experimental cure curve.",
        ["print-profile", "prof-chunk", "profile-materials", "profile-uuid", "cure-curve",
         "sealed-content", "password-mode", "aes-256-gcm"],
        (64, 48), 0.05, [[((0, 150, 255),)] for _ in range(4)], block_size=2,
        cipher_id="A256", mode=1, prof=prof_payload())


def vector_layer_overrides():
    """Plaintext, per-layer and per-range overrides."""
    overrides = [
        {"layer": 2, "normal_exposure_sec": 2.8, "lift_distance_mm": 6.0},
        {"layer_range": [3, 5], "sector_id": 0, "normal_exposure_sec": 2.2,
         "wait_time_before_cure_sec": 0.5},
        {"layer_range": [6, 8], "wait_time_after_lift_sec": 1.0},
    ]
    return build_vector(
        "layer-overrides",
        "Ten layers with an LROV chunk covering a single layer, an inclusive layer range scoped to sector 0, and a range that applies to every sector.",
        ["lrov-chunk", "layer-override", "layer-range", "sector-scoped-override"],
        (64, 48), 0.05, [[((0, 120, 255),)] for _ in range(10)], block_size=5,
        use_dict=False, lrov=lrov_payload(overrides))


def vector_previews():
    """Encrypted, with one clear and one sealed preview."""
    return build_encrypted_vector(
        "previews",
        "Password-mode AES-256-GCM with two PREV chunks: a large preview in the clear and a sealed icon. Preview sealing is optional even when the file is encrypted, so both forms are valid in the same file.",
        ["previews", "prev-chunk", "clear-preview", "sealed-preview", "preview-role",
         "password-mode", "aes-256-gcm"],
        (64, 48), 0.05, [[((0, 100, 255),)] for _ in range(4)], block_size=2,
        cipher_id="A256", mode=1,
        prevs=[(png_preview(400, 300), 1, False), (png_preview(16, 16, (255, 0, 0)), 3, True)])


def vector_embedded_scene():
    """Encrypted, with a sealed embedded scene."""
    return build_encrypted_vector(
        "embedded-scene",
        "Password-mode AES-256-GCM with a sealed VOXL chunk: the scene bytes are copied in and must come back out unchanged, while LUMEN itself never parses them.",
        ["embedded-scene", "voxl-chunk", "round-trip-payload", "sealed-content",
         "password-mode", "aes-256-gcm"],
        (64, 48), 0.05, [[((0, 80, 255),)] for _ in range(4)], block_size=2,
        cipher_id="A256", mode=1, voxl=voxl_payload())


def vector_extensions():
    """Plaintext, with two non-critical extensions."""
    extds = [
        extd_payload(b"CMLT", json.dumps({"corpus_bytes": 4096, "dict_size": 1024}).encode()),
        extd_payload(b"DRNF", b"\x01\x02\x03\x04\x05", vendor_id=0x1234),
    ]
    return build_vector(
        "extensions",
        "Two non-critical EXTD chunks - one reserved ORA type code and one vendor extension - exercising the frame, the vendor id and critical flag bit, and the rule that readers skip extensions they do not implement.",
        ["extd-chunk", "extension-frame", "vendor-extension", "reserved-type-code",
         "skippable-extension"],
        (64, 48), 0.05, [[((0, 60, 255),)] for _ in range(4)], block_size=2,
        use_dict=False, extds=extds)


def main() -> int:
    assert crc32c(b"123456789") == 0xE3069283, "CRC-32C self-test failed"
    os.makedirs(VALID_DIR, exist_ok=True)
    os.makedirs(INVALID_DIR, exist_ok=True)

    manifest = {"valid": [], "invalid": [], "generator": {
        "python": sys.version.split()[0],
        "zstandard": zstd.__version__,
        "zstd_layer_level": ZSTD_LAYER_LEVEL,
        "zstd_small_level": ZSTD_SMALL_LEVEL,
        "cryptography": package_version("cryptography"),
        "argon2_cffi": package_version("argon2-cffi"),
        "note": "Compressed payload bytes depend on the zstd version and level. "
                "Uncompressed structures (HDR, AUTH, LTBL, LAYR header and block table, "
                "LHAS, REE streams, directory, trailer) are exact. Sealed units are exact "
                "too: every nonce, salt and key is derived from a fixed SHAKE-256 seed, so "
                "regeneration is deterministic. Those values are public test data; real "
                "encoders must draw them from a CSPRNG.",
    }}

    for builder in (vector_binary_basic, vector_dict, vector_multisector,
                    vector_encrypted_password, vector_encrypted_machine,
                    vector_encrypted_both, vector_print_profile, vector_layer_overrides,
                    vector_previews, vector_embedded_scene, vector_extensions):
        raw, meta, layout = builder()
        path = os.path.join(VALID_DIR, meta["name"] + ".lumen")
        with open(path, "wb") as fh:
            fh.write(raw)
        meta["file"] = "valid/" + meta["name"] + ".lumen"
        manifest["valid"].append(meta)
        print("wrote %-28s %6d bytes, %2d chunks, %d blocks"
              % (meta["file"], len(raw), meta["chunk_count"], len(meta["blocks"])))

    # ---------------- invalid vectors ----------------
    def emit_invalid(name, description, expected, raw, strict_only=False, base=None,
                     crypto=None):
        path = os.path.join(INVALID_DIR, name + ".lumen")
        with open(path, "wb") as fh:
            fh.write(raw)
        entry = {
            "name": name, "file": "invalid/" + name + ".lumen",
            "description": description, "expected_failure": expected,
            "strict_only": strict_only, "base_vector": base,
            "file_size": len(raw), "file_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if crypto is not None:
            entry["crypto"] = crypto
        manifest["invalid"].append(entry)
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

    # ---------------- encrypted invalid vectors ----------------

    def patch_chunk_flags(raw_in, layout_in, ctype, flags):
        """Rewrite one chunk descriptor's flags field."""
        b = bytearray(raw_in)
        for i, e in enumerate(layout_in["entries"]):
            if e["type"] == ctype:
                struct.pack_into("<I", b, layout_in["dir_offset"] + i * DESCRIPTOR_SIZE + 28, flags)
                return bytes(b)
        raise AssertionError("no %r chunk" % (ctype,))

    enc_raw, enc_meta, enc_layout = vector_encrypted_password()

    # e01: the ENCRYPTED header flag with no AUTH chunk at all
    b = bytearray(raw)
    struct.pack_into("<I", b, 20, struct.unpack_from("<I", b, 20)[0] | FLAG_ENCRYPTED)
    emit_invalid("encrypted-flag-without-auth",
                 "The file header sets ENCRYPTED but there is no AUTH chunk, so no session key can ever be derived.",
                 "presence.auth", repack(b, layout), base="binary-basic")

    # e02: an unrecognized cipher
    b = bytearray(enc_raw)
    b[enc_layout["AUTH_off"]:enc_layout["AUTH_off"] + 4] = b"XXXX"
    emit_invalid("auth-cipher-unknown",
                 "AUTH.cipher_id is XXXX, which names no algorithm.",
                 "auth.cipher_known", repack(b, enc_layout), base="encrypted-password",
                 crypto=enc_meta["crypto"])

    # e03: neither wrapping mode declared
    b = bytearray(enc_raw)
    struct.pack_into("<I", b, enc_layout["AUTH_off"] + 8, 0)
    emit_invalid("crypt-mode-empty",
                 "AUTH.mode is 0: neither a password nor a machine binding is declared, so the session key is unreachable.",
                 "crypt.mode_empty", repack(b, enc_layout), base="encrypted-password",
                 crypto={**enc_meta["crypto"], "mode": 0, "mode_names": []})

    # e04: Argon2id cost above the recommended ceiling. The section is coherent, so
    # only the cost rule can refuse it.
    raw4, meta4, _ = build_encrypted_vector(
        "x-argon2-budget", "source", [], (64, 48), 0.05,
        [[((0, 300, 255),)] for _ in range(4)], block_size=2, cipher_id="A256", mode=1,
        argon2_params=(99, 8, 1))
    emit_invalid("crypt-argon2-budget",
                 "The password section declares Argon2id iterations = 99, above the recommended ceiling of 10; it is otherwise coherent, so only the cost rule refuses it.",
                 "crypt.argon2_budget", raw4, base=None, crypto=meta4["crypto"])

    # e05: password section shorter than the fixed 65 bytes
    raw5, meta5, _ = build_encrypted_vector(
        "x-password-short", "source", [], (64, 48), 0.05,
        [[((0, 300, 255),)] for _ in range(4)], block_size=2, cipher_id="A256", mode=1,
        password_trim=1)
    emit_invalid("crypt-password-len-short",
                 "AUTH declares a 64-byte password section, one byte short of the fixed section size.",
                 "crypt.password_section_len", raw5, base=None, crypto=meta5["crypto"])

    # e06: machine mode with an empty machine section
    raw6, meta6, _ = build_encrypted_vector(
        "x-machine-empty", "source", [], (64, 48), 0.05,
        [[((0, 300, 255),)] for _ in range(4)], block_size=2, cipher_id="C20P", mode=2,
        machine_roles=())
    emit_invalid("crypt-machine-len-empty",
                 "AUTH.mode sets machine-binding but the machine section is empty: no recipient can ever unwrap the session key.",
                 "crypt.machine_section_len", raw6, base=None, crypto=meta6["crypto"])

    # e07: a content chunk whose descriptor says plaintext while the file is encrypted
    b = patch_chunk_flags(enc_raw, enc_layout, b"ZDIC", 0)
    emit_invalid("crypt-plaintext-content",
                 "ZDIC's descriptor does not set the encrypted flag although the file is encrypted; its bytes are sealed regardless, so the flag is the only disagreement.",
                 "crypt.chunk_flags", repack(b, enc_layout), base="encrypted-password",
                 crypto=enc_meta["crypto"])

    # e08: a tampered ciphertext byte inside a sealed LAYR block frame
    b = bytearray(enc_raw)
    body_off = 12 + len(enc_meta["blocks"]) * BLOCK_TABLE_ENTRY_SIZE
    b[enc_layout["LAYR_off"] + body_off + 16] ^= 0xFF   # past the nonce, inside the ciphertext
    emit_invalid("crypt-tag-corrupt",
                 "One ciphertext byte of LAYR block 0 is flipped, so its AEAD tag must fail; a reader must not decompress or parse a block it cannot authenticate.",
                 "crypt.tag_verify", repack(b, enc_layout), base="encrypted-password",
                 crypto=enc_meta["crypto"])

    # ---------------- PROF / LROV / PREV invalid vectors ----------------

    def emit_prof_invalid(name, expected, description, **prof_kwargs):
        raw_p, _, _ = build_vector("x-prof", "source", [], (64, 48), 0.05,
                                   [[((0, 200, 255),)] for _ in range(4)], block_size=2,
                                   use_dict=False, prof=prof_payload(**prof_kwargs))
        emit_invalid(name, description, expected, raw_p, base=None)

    emit_prof_invalid("prof-type-unknown", "prof.profile_type",
                      "PROF.profile_type is \"resin\", which is not one of the three defined types.",
                      profile_type="resin")
    emit_prof_invalid("prof-identity-empty", "prof.profile_identity",
                      "PROF.profile_name is an empty string.",
                      profile_name="")
    emit_prof_invalid("prof-settings-exposure", "prof.settings_exposure",
                      "PROF settings carry a zero normal exposure.",
                      settings_extra={"normal_exposure_sec": 0.0})
    emit_prof_invalid("prof-settings-layer-height", "prof.settings_layer_height",
                      "PROF settings carry a zero layer height.",
                      settings_extra={"layer_height_mm": 0.0})
    emit_prof_invalid("prof-cure-curve", "prof.cure_curve",
                      "PROF cure curve has dp_um = 0.0, which no resin can have.",
                      settings_extra={"cure_curve": {"dp_um": 0.0, "ec_mj_cm2": 7.5,
                                                     "e0_mj_cm2": 3.0}})
    emit_prof_invalid("prof-uuid-malformed", "prof.profile_uuid",
                      "PROF.profile_uuid is not a UUID.",
                      profile_uuid="not-a-uuid")
    emit_prof_invalid("prof-materials-shape", "prof.materials_shape",
                      "PROF.materials is an empty array, which the META.materials shape rules forbid.",
                      materials=[])

    def emit_lrov_invalid(name, expected, description, overrides):
        raw_l, _, _ = build_vector("x-lrov", "source", [], (64, 48), 0.05,
                                   [[((0, 120, 255),)] for _ in range(10)], block_size=5,
                                   use_dict=False, lrov=lrov_payload(overrides))
        emit_invalid(name, description, expected, raw_l, base=None)

    emit_lrov_invalid("lrov-entry-form-both", "lrov.entry_form",
                      "An LROV entry carries both layer and layer_range, which the entry form forbids.",
                      [{"layer": 2, "layer_range": [2, 4], "normal_exposure_sec": 2.8}])
    emit_lrov_invalid("lrov-layer-out-of-range", "lrov.layer_index_range",
                      "An LROV entry overrides layer 40 in a ten-layer file.",
                      [{"layer": 40, "normal_exposure_sec": 2.8}])
    emit_lrov_invalid("lrov-range-reversed", "lrov.layer_range_order",
                      "An LROV layer_range ends before it begins.",
                      [{"layer_range": [8, 3], "normal_exposure_sec": 2.8}])
    emit_lrov_invalid("lrov-sector-undefined", "lrov.sector_id_defined",
                      "An LROV entry targets sector 7, which no SECT chunk in this single-sector file defines.",
                      [{"layer_range": [3, 5], "sector_id": 7, "normal_exposure_sec": 2.8}])

    raw_pv, _, layout_pv = build_vector(
        "x-prev", "source", [], (64, 48), 0.05, [[((0, 90, 255),)] for _ in range(4)],
        block_size=2, use_dict=False, prevs=[(png_preview(24, 18), 1, False)])

    b = patch_chunk_flags(raw_pv, layout_pv, b"PREV", 0x21)
    emit_invalid("prev-flags",
                 "A PREV chunk sets reserved flag bit 5 alongside role 1; only bits 0-3 carry the role.",
                 "prev.flags", repack(b, layout_pv), base=None)

    b = bytearray(raw_pv)
    prev_off = layout_pv["PREV_off"]
    b[prev_off:prev_off + 4] = b"NOTP"
    emit_invalid("prev-not-png",
                 "A PREV payload does not begin with the PNG signature. A loose reader ignores previews and must still accept the file; a strict validator rejects it.",
                 "prev.png_signature", repack(b, layout_pv), strict_only=True, base=None)

    # a VOXL payload that is neither the V2 magic nor a V1 JSON document
    raw_vx, _, _ = build_vector(
        "x-voxl", "source", [], (64, 48), 0.05, [[((0, 70, 255),)] for _ in range(4)],
        block_size=2, use_dict=False, voxl=b'[{"magic": "VOXL", "version": 1}]')
    emit_invalid("voxl-not-voxl",
                 "The embedded scene is a JSON array rather than a VOXL document: the payload begins with neither the V2 magic nor the V1 document marker. A loose reader never looks inside the chunk and must still accept the file; a strict validator rejects it.",
                 "voxl.signature", raw_vx, strict_only=True, base=None)

    def emit_extd_invalid(name, expected, description, extds):
        raw_x, _, _ = build_vector("x-extd", "source", [], (64, 48), 0.05,
                                   [[((0, 50, 255),)] for _ in range(4)], block_size=2,
                                   use_dict=False, extds=extds)
        emit_invalid(name, description, expected, raw_x, base=None)

    emit_extd_invalid("extd-critical", "extd.critical",
                      "An extension sets the critical bit, so a reader that does not implement it must refuse the file rather than print an approximation.",
                      [extd_payload(b"DRNF", b"\x00", vendor_id=0x1234, critical=True)])
    emit_extd_invalid("extd-truncated", "extd.frame",
                      "An EXTD payload is four bytes, too short to carry ext_version and ext_type.",
                      [extd_payload(b"", b"")])
    emit_extd_invalid("extd-reserved-flags", "extd.flags",
                      "An EXTD chunk sets reserved flag bit 0, which must be 0.",
                      [extd_payload(b"CMLT", b"x", flags_extra=0x01)])
    emit_extd_invalid("extd-type-nonascii", "extd.ext_type",
                      "An EXTD ext_type is four non-ASCII bytes, so no reader can name the extension.",
                      [extd_payload(b"\x80\x81\x82\x83", b"x")])

    # a chunk that claims to be sealed in a file that carries no AUTH at all
    b = patch_chunk_flags(raw, layout, b"META", 0x10)
    emit_invalid("sealed-without-auth",
                 "META's descriptor sets the encrypted bit while the file header does not, so the file carries no AUTH chunk and no key could open it.",
                 "crypt.chunk_flags", repack(b, layout), base="binary-basic")

    with open(os.path.join(HERE, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("\nmanifest.json: %d valid, %d invalid"
          % (len(manifest["valid"]), len(manifest["invalid"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
