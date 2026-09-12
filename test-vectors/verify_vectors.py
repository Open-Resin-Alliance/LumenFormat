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
import re
import struct
import sys

import zstandard as zstd

# The crypto libraries are optional: a plaintext corpus validates without them.
# Guarded at import time so an encrypted vector is the only thing that needs
# `cryptography` and `argon2-cffi` to be installed.
try:
    import argon2.low_level as _argon2
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey as _X25519PrivateKey,
        X25519PublicKey as _X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM as _AESGCM,
        ChaCha20Poly1305 as _ChaCha20Poly1305,
    )
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap as _aes_key_unwrap
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Encoding,
        PublicFormat as _PublicFormat,
    )

    CRYPTO_AVAILABLE = True
except Exception:  # ImportError, or a broken install
    CRYPTO_AVAILABLE = False

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
    # positions[0] is the absolute index of the first AA pixel (delta from 0), so
    # only subsequent deltas have to be >= 1 for the indices to be increasing.
    for idx in range(n):
        d, pos = read_varint(body, pos)
        if idx and d < 1:
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


# ------------------------------------------------------------ crypto helpers
#
# Reimplemented from spec 04-chunk-auth.md (§4.4), 06-layer-data.md (§4.10) and
# 12-encryption.md (§9), independently of the generator.  Every helper assumes
# CRYPTO_AVAILABLE; callers only enter the encrypted path when it holds.

ENCRYPTED_FLAG = 0x08       # file header: AUTH chunk present, content sealed
SEALED_FLAG = 0x10          # chunk descriptor: this chunk's payload is sealed
AEAD_OVERHEAD = 28          # nonce[12] + tag[16]
SEALED_CHUNK_TYPES = (b"LAYR", b"META", b"PROF", b"SECT", b"LROV", b"VOXL", b"ZDIC")
CLEAR_CHUNK_TYPES = (b"HDR\0", b"AUTH", b"LTBL")
# PREV's sealing is optional (§4.7), so it is deliberately absent from
# SEALED_CHUNK_TYPES: a clear PREV beside a sealed one is not a defect.  Its
# ENCRYPTED bit still has to be honoured when it is set, so the decrypt phase
# covers it too.
SEALABLE_CHUNK_TYPES = SEALED_CHUNK_TYPES + (b"PREV",)
COMPRESSED_TYPES = frozenset((b"META", b"PROF", b"SECT", b"LROV", b"VOXL"))


def unit_aad(chunk_type: bytes, unit_index: int) -> bytes:
    """§9.3: chunk_type || 0x00 || unit_index_le_u32."""
    return chunk_type + b"\x00" + struct.pack("<I", unit_index)


def open_unit(key: bytes, cipher_id: bytes, chunk_type: bytes, unit_index: int,
              blob: bytes) -> bytes:
    """Open one sealed unit (nonce || ciphertext || tag); raises on tag failure."""
    if len(blob) < AEAD_OVERHEAD:
        raise ValueError("sealed unit shorter than the 28-byte framing")
    aad = unit_aad(chunk_type, unit_index)
    if cipher_id == b"A256":
        return _AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    if cipher_id == b"C20P":
        return _ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
    raise ValueError("unknown cipher_id %r" % (cipher_id,))


def argon2_params(auth: bytes, pw_len: int):
    """(iterations, memory_kib, parallelism) from the password section, or None.

    Only the 25 bytes that hold salt + the three cost parameters are needed, so
    a section whose declared length is short of the fixed 65 still exposes its
    declared budget (the length defect is reported by its own check).
    """
    if pw_len < 25 or len(auth) < 20 + 25:
        return None
    return (struct.unpack_from("<I", auth, 36)[0],
            struct.unpack_from("<I", auth, 40)[0],
            auth[44])


def recover_session_key(auth: bytes, crypto, cipher_id: bytes, mode: int,
                        pw_len: int, mc_len: int):
    """Unwrap the session key per §4.4; None when no credential works.

    Password mode is tried first, then every machine-binding entry whose
    fingerprint matches ours (§4.4.2 step 1: an all-zero shared secret — the
    low-order-point result — rejects the entry).
    """
    if not CRYPTO_AVAILABLE or not isinstance(crypto, dict):
        return None
    if mode & 0x01:
        password = crypto.get("password_utf8")
        params = crypto.get("argon2")
        if isinstance(password, str) and isinstance(params, dict) and pw_len >= 65:
            try:
                kek = _argon2.hash_secret_raw(
                    secret=password.encode("utf-8"),
                    salt=bytes.fromhex(params["salt"]),
                    time_cost=int(params["iterations"]),
                    memory_cost=int(params["memory_kib"]),
                    parallelism=int(params["parallelism"]),
                    hash_len=32,
                    type=_argon2.Type.ID,
                    version=0x13,  # RFC 9106
                )
                key = _aes_key_unwrap(kek, auth[45:85])
            except Exception:
                key = None
            if key is not None and len(key) == 32:
                return key
    if mode & 0x02:
        priv_hex = crypto.get("local_recipient_private_key")
        if not isinstance(priv_hex, str):
            return None
        try:
            priv = _X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
            local_pub = priv.public_key().public_bytes(_Encoding.Raw, _PublicFormat.Raw)
        except Exception:
            return None
        machine_fp = hashlib.sha256(local_pub).digest()
        base = 20 + pw_len
        for i in range(mc_len // 104):
            off = base + i * 104
            if off + 104 > len(auth):
                break
            entry = auth[off:off + 104]
            if entry[:32] != machine_fp:
                continue
            ephemeral_pk = entry[32:64]
            try:
                shared = priv.exchange(_X25519PublicKey.from_public_bytes(ephemeral_pk))
            except Exception:
                continue  # library rejected the point
            if not any(shared):
                continue  # low-order point: the all-zero shared secret
            try:
                kek = _HKDF(algorithm=_hashes.SHA256(), length=32, salt=machine_fp,
                            info=b"LUMEN machine-binding v1\0" + ephemeral_pk + machine_fp
                            ).derive(shared)
                key = _aes_key_unwrap(kek, entry[64:104])
            except Exception:
                continue
            if len(key) == 32:
                return key
    return None


def chunk_flag_report(real, blocks, encrypted_flag: bool, sealed_layr: bool):
    """(ok, detail) for crypt.chunk_flags — §11.4 / §9.1."""
    if not encrypted_flag:
        return True, ""
    bad = []
    for e in real:
        name = e["type"].rstrip(b"\x00").decode("ascii", "replace")
        if e["type"] in SEALED_CHUNK_TYPES and not (e["flags"] & SEALED_FLAG):
            bad.append("%s not sealed" % name)
        if e["type"] in CLEAR_CHUNK_TYPES and (e["flags"] & SEALED_FLAG):
            bad.append("%s sealed" % name)
    if sealed_layr and any(b["frame_size"] < AEAD_OVERHEAD for b in blocks):
        bad.append("LAYR block frame shorter than 28 bytes")
    return (not bad), ", ".join(bad)


# ------------------------------------------------- content chunk helpers
#
# §4.3 / §4.6 / §4.7, shared by the PROF, LROV and PREV checks.

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                     r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def is_number(v) -> bool:
    """A JSON number, as opposed to a bool (which is an int in Python)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def materials_shape_ok(mats) -> bool:
    """§11.2: absent, or a non-empty array of objects each with a non-empty name."""
    return mats is None or (
        isinstance(mats, list) and len(mats) > 0
        and all(isinstance(m, dict) and m.get("name") for m in mats))


def lrov_indices_ok(entry, total_layers: int) -> bool:
    """§11.2: layer, and both layer_range bounds, in [0, total_layers-1]."""
    def in_range(v):
        return is_number(v) and 0 <= v <= total_layers - 1

    if "layer" in entry:
        return in_range(entry["layer"])
    rng = entry.get("layer_range")
    return isinstance(rng, list) and len(rng) == 2 and all(in_range(v) for v in rng)


def lrov_range_ordered(entry) -> bool:
    """§11.2: layer_range is inclusive and end >= start."""
    rng = entry.get("layer_range")
    if rng is None:
        return True
    return isinstance(rng, list) and len(rng) == 2 and rng[1] >= rng[0]


def png_header_ok(blob: bytes) -> bool:
    """§4.7 / §11.2 (strict): PNG signature followed by a well-formed IHDR.

    Only the leading IHDR is inspected: the signature must be present, its
    declared length must be at least the 13 bytes of the fixed IHDR layout, and
    its width and height must both be non-zero.
    """
    if len(blob) < 24 or blob[:8] != PNG_SIGNATURE:
        return False
    if struct.unpack_from(">I", blob, 8)[0] < 13 or blob[12:16] != b"IHDR":
        return False
    width, height = struct.unpack_from(">II", blob, 16)
    return width > 0 and height > 0


# ------------------------------------------------------------- file reader

class Checks:
    def __init__(self, verbose: bool):
        self.items: list[tuple[str, bool]] = []
        self.verbose = verbose
        # Plaintext payloads of the content chunks, keyed by type tag; filled in
        # by validate() so check_manifest() can pin them without re-deriving the
        # session key.
        self.payloads: dict = {}

    def __call__(self, name: str, ok: bool, detail: str = "") -> bool:
        self.items.append((name, bool(ok)))
        if self.verbose:
            print("      %-32s %s%s" % (name, "PASS" if ok else "FAIL",
                                        ("  " + detail) if detail and not ok else ""))
        return bool(ok)

    def failed(self) -> list[str]:
        return [n for n, ok in self.items if not ok]


def validate(path: str, strict: bool, verbose: bool = False, crypto: dict | None = None):
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

    def stored(e):
        """Stored payload bytes; for LAYR this is the plaintext container."""
        n = e["csz"] or e["usz"]
        return raw[e["offset"]:e["offset"] + n]

    def payload_plain(e):
        """Stored payload with chunk-level compression undone."""
        blob = stored(e)
        if e["csz"]:
            blob = zstd.ZstdDecompressor().decompress(blob, max_output_size=e["usz"])
        return blob

    chk("presence.meta", len(find(b"META")) == 1)
    chk("presence.ltbl", len(find(b"LTBL")) == 1)
    chk("presence.layr", len(find(b"LAYR")) == 1)
    if flags & 0x02:
        chk("presence.sect", len(find(b"SECT")) >= 1)
    chk("presence.lhas", len(find(b"LHAS")) == 1)

    auth_entries = find(b"AUTH")
    encrypted_flag = bool(flags & ENCRYPTED_FLAG)
    crypto_engaged = encrypted_flag or bool(auth_entries) or (crypto is not None)

    # ---- HDR -----------------------------------------------------------
    hdr = stored(find(b"HDR\0")[0])
    hdr_version, name_len = struct.unpack_from("<II", hdr, 0)
    chk("hdr.version", hdr_version == 1)
    chk("hdr.encoder_name_fits", len(hdr) >= 52 + name_len and name_len <= 256)
    (created, disp_w, disp_h, phys_w, phys_h) = struct.unpack_from("<QIIII", hdr, 8 + name_len)
    (build_w, build_d, build_h, layer_h, total_layers) = struct.unpack_from("<ffffI", hdr, 32 + name_len)
    chk("hdr.total_layers", total_layers > 0)
    chk("hdr.physical_ratio", phys_w % disp_w == 0 and phys_h % disp_h == 0)
    total_pixels = disp_w * disp_h

    # ---- META / SECT are content-derived: parsed in phase 6 -------------

    # ---- LTBL ----------------------------------------------------------
    ltbl = stored(find(b"LTBL")[0])
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
    layr = stored(find(b"LAYR")[0])
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

    # ============================================================ phase 1 (c)
    # LHAS header.  The leaf table and its root are plaintext even when the
    # layer data is sealed, so the root can be recomputed without a key.
    lhas = stored(find(b"LHAS")[0])
    alg, hsize, lhas_count = struct.unpack_from("<BBI", lhas, 0)
    root = lhas[6:38]
    leaves = [lhas[38 + 32 * i: 38 + 32 * (i + 1)] for i in range(lhas_count)]
    chk("lhas.hash_algorithm", alg == 1 and hsize == 32)
    chk("lhas.layer_count", lhas_count == total_layers)
    chk("lhas.root_recompute", merkle_root(leaves) == root)

    # ============================================================== phase 2
    # AUTH structure.  If any of this fails the session key cannot be obtained,
    # so every later crypto and content-derived check is skipped rather than
    # recorded as failed.
    session_key = None
    cipher_id = b""
    decrypted: dict[int, bytes] = {}
    block_frames = None
    tag_ok = True
    halt_crypto = False
    halt_content = False

    auth_e = auth_entries[0] if len(auth_entries) == 1 else None
    if crypto_engaged:
        chk("presence.auth", (not encrypted_flag) or len(auth_entries) == 1)
        if auth_e is None:
            halt_crypto = halt_content = True
        else:
            auth = stored(auth_e)
            head = len(auth) >= 20
            auth_version = struct.unpack_from("<I", auth, 4)[0] if head else 0
            cipher_id = auth[:4] if head else b""
            mode = struct.unpack_from("<I", auth, 8)[0] if head else 0
            pw_len = struct.unpack_from("<I", auth, 12)[0] if head else 0
            mc_len = struct.unpack_from("<I", auth, 16)[0] if head else 0
            ok_version = chk("auth.version", auth_version == 1)
            ok_cipher = chk("auth.cipher_known", cipher_id in (b"A256", b"C20P"))
            ok_mode = chk("crypt.mode_empty", mode != 0)
            ok_pw = True
            if mode & 0x01:
                ok_pw = chk("crypt.password_section_len", pw_len >= 65)
            ok_mc = True
            if mode & 0x02:
                ok_mc = chk("crypt.machine_section_len", mc_len >= 104 and mc_len % 104 == 0)
            ok_budget = True
            if mode & 0x01:
                params = argon2_params(auth, pw_len)
                ok_budget = chk("crypt.argon2_budget",
                                params is not None
                                and params[0] <= 10 and params[1] <= 4194304 and params[2] <= 16)
            if ok_version and ok_cipher and ok_mode and ok_pw and ok_mc and ok_budget:
                session_key = recover_session_key(auth, crypto, cipher_id, mode, pw_len, mc_len)
                if session_key is None:
                    halt_crypto = halt_content = True
            else:
                halt_crypto = halt_content = True

    # ============================================================== phase 3
    # Chunk flags are directory metadata: checked before any decryption.
    sealed_layr = bool(find(b"LAYR")[0]["flags"] & SEALED_FLAG)
    if crypto_engaged and not halt_crypto:
        ok_flags, flag_detail = chunk_flag_report(real, blocks, encrypted_flag, sealed_layr)
        chk("crypt.chunk_flags", ok_flags, flag_detail)
        if not ok_flags:
            halt_crypto = halt_content = True

    # ============================================================== phase 4
    # Decrypt every sealed unit.  The key itself was unwrapped in phase 2,
    # because its success decides whether the content checks can run at all.
    if crypto_engaged and not halt_crypto:
        chk("crypt.key_unwrap", session_key is not None)
        if session_key is None:
            halt_crypto = halt_content = True
        else:
            for e in real:
                if (e["type"] in SEALABLE_CHUNK_TYPES and e["type"] != b"LAYR"
                        and (e["flags"] & SEALED_FLAG)):
                    try:
                        decrypted[e["offset"]] = open_unit(
                            session_key, cipher_id, e["type"], 0, stored(e))
                    except Exception:
                        tag_ok = False
            if sealed_layr:
                block_frames = []
                for k, blk in enumerate(blocks):
                    blob = layr[body_off + blk["frame_offset"]:
                                body_off + blk["frame_offset"] + blk["frame_size"]]
                    try:
                        block_frames.append(open_unit(session_key, cipher_id, b"LAYR", k, blob))
                    except Exception:
                        tag_ok = False
                        block_frames.append(None)

    # ============================================================== phase 5
    # §9.3: every tag must verify before content is parsed or decompressed.
    if crypto_engaged and not halt_crypto:
        if not chk("crypt.tag_verify", tag_ok):
            halt_content = True

    # ============================================================== phase 6
    # Content-derived checks.  A file whose key or tags did not check out is
    # still validated structurally, but its content is never parsed.
    def content_entry(e):
        if e["flags"] & SEALED_FLAG:
            blob = decrypted.get(e["offset"])
            if blob is None:
                raise ValueError("%r unit was not decrypted" % (e["type"],))
            if e["type"] in COMPRESSED_TYPES:
                blob = zstd.ZstdDecompressor().decompress(blob, max_output_size=e["usz"])
            return blob
        return payload_plain(e)

    def content(ctype):
        return content_entry(find(ctype)[0])

    # Plaintext payloads of the optional content chunks, for check_manifest().
    payloads: dict = {}

    if halt_content:
        chk("__checks_complete", True)
        return chk

    # ---- META / SECT ---------------------------------------------------
    meta = json.loads(content(b"META"))
    mats = meta.get("materials")
    chk("meta.required_fields", all(k in meta for k in (
        "meta_version", "normal_exposure_sec", "bottom_exposure_sec", "bottom_layer_count",
        "transition_layer_count", "layer_height_mm", "lift_distance_mm", "lift_speed_mm_min",
        "retract_distance_mm", "retract_speed_mm_min")))
    chk("meta.materials_shape", materials_shape_ok(mats))
    sects = [json.loads(content_entry(e)) for e in find(b"SECT")]
    chk("sect.sector_id_nonzero", all(s.get("sector_id", 0) >= 1 for s in sects))
    chk("sect.ids_unique", len({s["sector_id"] for s in sects}) == len(sects))
    chk("sect.material_index_bounds", all(
        "material_index" not in s or (mats is not None and 0 <= s["material_index"] < len(mats))
        for s in sects))
    sect_ids = {s.get("sector_id") for s in sects if "sector_id" in s}

    # ---- PROF / LROV / PREV --------------------------------------------
    # Optional content chunks.  PROF and LROV go through the same
    # sealed/compressed path as META/SECT; PREV is uncompressed but may carry
    # its own ENCRYPTED bit (§4.7), independent of the file-level flag.
    if find(b"PROF"):
        prof_plain = content(b"PROF")
        prof = json.loads(prof_plain)
        if not isinstance(prof, dict):
            prof = {}
        settings = prof.get("settings")
        chk("prof.profile_identity",
            isinstance(prof.get("profile_name"), str) and prof["profile_name"] != ""
            and isinstance(prof.get("profile_version"), str) and prof["profile_version"] != "")
        chk("prof.profile_type", prof.get("profile_type") in ("material", "printer", "combined"))
        chk("prof.settings_exposure",
            isinstance(settings, dict)
            and is_number(settings.get("normal_exposure_sec"))
            and settings["normal_exposure_sec"] > 0.0
            and is_number(settings.get("bottom_exposure_sec"))
            and settings["bottom_exposure_sec"] > 0.0)
        chk("prof.settings_layer_height",
            isinstance(settings, dict)
            and is_number(settings.get("layer_height_mm"))
            and settings["layer_height_mm"] > 0.0)
        curve = settings.get("cure_curve") if isinstance(settings, dict) else None
        chk("prof.cure_curve", curve is None or (
            isinstance(curve, dict)
            and is_number(curve.get("dp_um")) and curve["dp_um"] > 0.0
            and is_number(curve.get("ec_mj_cm2")) and curve["ec_mj_cm2"] > 0.0
            and is_number(curve.get("e0_mj_cm2")) and curve["e0_mj_cm2"] >= 0.0))
        puuid = prof.get("profile_uuid")
        chk("prof.profile_uuid", puuid is None or (
            isinstance(puuid, str) and UUID_RE.fullmatch(puuid) is not None))
        chk("prof.materials_shape", materials_shape_ok(prof.get("materials")))
        payloads[b"PROF"] = prof_plain

    if find(b"LROV"):
        lrov_plain = content(b"LROV")
        lrov = json.loads(lrov_plain)
        overrides = lrov.get("overrides") if isinstance(lrov, dict) else None
        entries = overrides if isinstance(overrides, list) else None
        chk("lrov.entry_form", entries is not None and all(
            isinstance(x, dict) and (("layer" in x) != ("layer_range" in x)) for x in entries))
        chk("lrov.layer_index_range", entries is not None and all(
            lrov_indices_ok(x, total_layers) for x in entries))
        chk("lrov.layer_range_order", entries is not None and all(
            lrov_range_ordered(x) for x in entries))
        chk("lrov.sector_id_defined", entries is not None and all(
            "sector_id" not in x or x["sector_id"] == 0 or x["sector_id"] in sect_ids
            for x in entries))
        payloads[b"LROV"] = lrov_plain

    prev_e = find(b"PREV")
    if prev_e:
        chk("prev.flags", all(
            (e["flags"] & 0x0F) <= 3 and (e["flags"] >> 5) == 0 for e in prev_e))
        if strict:
            chk("prev.png_signature", all(png_header_ok(content_entry(e)) for e in prev_e))
        payloads[b"PREV"] = [content_entry(e) for e in prev_e]

    # ---- VOXL ----------------------------------------------------------
    # §4.12: the embedded scene is opaque to LUMEN, so §11.2 only asks a strict
    # reader to recognize which generation of VOXL it is holding.  Whether the
    # scene is *valid* is VOXL's business: a print reader must never reject a
    # file over its embedded scene, so loose mode records nothing here.
    voxl_e = find(b"VOXL")
    if voxl_e:
        voxl_plain = content_entry(voxl_e[0])
        if strict:
            chk("voxl.signature",
                voxl_plain[:4] == b"VOXL" or voxl_plain[:1] == b"{")
        payloads[b"VOXL"] = voxl_plain

    # dictionary
    zdic = find(b"ZDIC")
    dict_bytes = b""
    dict_id = 0
    if zdic:
        zd = content(b"ZDIC")
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
    frames = []
    for k, blk in enumerate(blocks):
        if block_frames is not None:
            frames.append(block_frames[k])
        else:
            frames.append(layr[body_off + blk["frame_offset"]:
                               body_off + blk["frame_offset"] + blk["frame_size"]])
    for k, blk in enumerate(blocks):
        try:
            frame = frames[k]
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

    # ---- layer data / leaf hashes --------------------------------------
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
    chk.payloads = payloads
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
    skipped = 0

    def missing_crypto(v):
        return bool(v.get("crypto")) and not CRYPTO_AVAILABLE

    def report_skip(v):
        print("  %-4s %-24s (needs cryptography + argon2-cffi)" % ("SKIP", v["name"]))

    print("valid vectors")
    for v in manifest["valid"]:
        if missing_crypto(v):
            report_skip(v)
            skipped += 1
            continue
        path = os.path.join(HERE, v["file"])
        chk = validate(path, strict=True, verbose=args.verbose, crypto=v.get("crypto"))
        bad = chk.failed()
        ref = check_manifest(v, path, chk.payloads)
        if ref:
            bad += ref
        status = "PASS" if not bad else "FAIL"
        print("  %-4s %-24s %d checks%s" % (status, v["name"], len(chk.items),
                                            "" if not bad else "  -> " + ", ".join(bad)))
        failures += bool(bad)

    print("invalid vectors")
    for v in manifest["invalid"]:
        if missing_crypto(v):
            report_skip(v)
            skipped += 1
            continue
        path = os.path.join(HERE, v["file"])
        strict = not v.get("strict_only")
        chk = validate(path, strict=True, verbose=args.verbose, crypto=v.get("crypto"))
        loose = validate(path, strict=False, crypto=v.get("crypto")) if v.get("strict_only") else None
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
    if failures:
        print("corpus: %d FAILURES" % failures)
    if skipped:
        print("corpus: INCOMPLETE (%d encrypted vectors skipped; "
              "pip install cryptography argon2-cffi)" % skipped)
    if not failures and not skipped:
        print("corpus: OK")
    return 1 if failures else (3 if skipped else 0)


def check_manifest(v: dict, path: str, payloads: dict | None = None) -> list[str]:
    """Compare the committed bytes against the recorded golden values.

    `payloads` carries the plaintext payload of each optional content chunk as
    the validator decoded it, keyed by type tag (a list for PREV, in file
    order), so the recorded `chunk_payload_sha256` pins can be compared without
    re-deriving the session key here.  An absent payload has no pin to check.
    """
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

    # plaintext payload pins for the optional content chunks (§11.6)
    available = payloads or {}
    for ctype, want in sorted((v.get("chunk_payload_sha256") or {}).items()):
        got = available.get(ctype.encode("ascii"))
        if got is None:
            continue
        if isinstance(want, list):
            actual = ([hashlib.sha256(b).hexdigest() for b in got]
                      if isinstance(got, list) else [])
            mismatch = actual != want
        else:
            mismatch = (not isinstance(got, (bytes, bytearray))
                        or hashlib.sha256(got).hexdigest() != want)
        if mismatch:
            bad.append("manifest.chunk_payload_sha256")
            break
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
