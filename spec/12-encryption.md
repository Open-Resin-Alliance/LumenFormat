# Encryption model

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 9. Encryption Model

### 9.1 Design Principles

- **User-initiated, not mandatory.** Files are plaintext by default.
- **AEAD only.** Authenticated encryption prevents undetected tampering.
- **Compress-then-encrypt.** zstd compression is applied first, then the compressed
  frame is encrypted.
- **Content-scoped encryption.** The directory, HDR, AUTH, LTBL, and the LAYR header
  and block table remain plaintext. Everything that carries content or content-derived
  data (LAYR block frames, ZDIC, META, PROF, SECT, LROV, VOXL) is encrypted. PREV and
  EXTD are optionally encrypted: a file may carry either sealed or in the clear, and a
  reader that skips them never needs the key. When `AUTH` is present every content chunk
  MUST be encrypted; v1 has no partial-encryption mode, so the `ENCRYPTED` flag is set on
  all of them. Conversely the chunk-level `ENCRYPTED` flag requires `AUTH` in the same
  file: a chunk MUST NOT set it when the file header does not, because no key exists to
  open it.
- **Confidentiality and per-chunk integrity, not authenticity.** Encryption hides
  content and detects modification of each sealed unit, and the AAD binds a unit to its
  chunk type and index ([§9.3](#93-encryption-format)). It does **not** authenticate the file: the fixed header,
  the chunk directory, `LTBL`, `LHAS`, and the LAYR header and block table are plaintext
  and unauthenticated, so an attacker can still add, remove, reorder or repoint chunks.
  A file-level signature (`EXTD`/`SIGN`) is the only mechanism that proves origin, and
  it is optional in v1.

### 9.2 Encryption Algorithm

Two options, identified in the AUTH chunk:

| `cipher_id` | Algorithm | Nonce size | Tag size | Notes |
|-------------|-----------|------------|----------|-------|
| `A256` | AES-256-GCM | 12 bytes | 16 bytes | Hardware-accelerated on x86 (AES-NI) and ARM (AES extensions). |
| `C20P` | ChaCha20-Poly1305 | 12 bytes | 16 bytes | Faster in software; constant-time on all platforms. |

### 9.3 Encryption Format

When chunk flags bit 4 (`ENCRYPTED`) is set, each **encrypted unit** in the chunk
payload is sealed independently:

```
nonce        : [u8; 12]     - Random, unique per unit.
ciphertext   : [u8; N]      - Encrypted payload bytes.
tag          : [u8; 16]     - AEAD authentication tag.
```

`AEAD-Open(key, nonce, ciphertext, associated_data)` MUST verify the tag before any
parsing or decompression. `associated_data` binds the unit to its identity in the
file: `chunk_type || 0x00 || unit_index_le_u32`. For a single-unit chunk,
`unit_index` is `0`.

For every chunk except `LAYR`, the chunk payload is exactly one unit, and the chunk
descriptor's `size_compressed` includes the 28-byte framing overhead.

For `LAYR`, the `layr_header` and `block_table` stay plaintext and each block frame
is its own unit (`unit_index` = block index, [§4.10](06-layer-data.md#410-layr---layer-data-chunk)). This keeps per-block random
access working on encrypted files: a reader can seek to a block, decrypt just that
block, and decompress it instead of streaming the whole ciphertext. The block
table's `frame_size` includes the 28-byte overhead for its unit.

### 9.4 Session Key Lifecycle

1. Generate 256-bit random session key at encode time.
2. Encrypt each sensitive unit with the session key (unique random nonce per unit; [§9.3](#93-encryption-format)).
3. Wrap the session key:
   - **Password mode:** Derive KEK from password via Argon2id, wrap with AES-256-KW.
   - **Machine mode:** For each authorized machine, derive KEK via X25519 ECDH +
     HKDF-SHA-256, wrap with AES-256-KW.
4. Store wrapping metadata in AUTH chunk.

The session key is the same for all chunks in the file. Multiple wrapping entries
enable multiple authorized machines without re-encrypting the entire payload.
