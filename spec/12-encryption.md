# Encryption model

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

## 9. Encryption Model

### 9.1 Design Principles

- **User-initiated, not mandatory.** Files are plaintext by default.
- **AEAD only.** Authenticated encryption prevents undetected tampering.
- **Compress-then-encrypt.** zstd compression is applied first, then the compressed
  frame is encrypted.
- **Content-scoped encryption.** The directory, HEAD, AUTH, LTBL, and the `LAYR` version
  field remain plaintext. Everything that carries content or content-derived
  data (the `LAYR` frames, ZDIC, META, PROF, LROV, VOXL) is encrypted. PREV and
  EXTD are optionally encrypted: a file may carry either sealed or in the clear, and a
  reader that skips them never needs the key. When `AUTH` is present every content chunk
  MUST be encrypted; v1 has no partial-encryption mode, so the `ENCRYPTED` flag is set on
  all of them. Conversely the chunk-level `ENCRYPTED` flag requires `AUTH` in the same
  file: a chunk MUST NOT set it when the file header does not, because no key exists to
  open it.
- **Confidentiality and per-chunk integrity, not authenticity.** Encryption hides
  content and detects modification of each sealed unit, and the AAD binds a unit to its
  chunk type and index ([§9.3](#93-encryption-format)). It does **not** authenticate the file: the fixed header,
  the chunk directory, `LTBL`, `LHAS`, and the `LAYR` version fields are plaintext
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
file: `chunk_type || 0x00 || unit_index_le_u32`, with `unit_index` little-endian and

- `0` for a chunk stored as one unit - every chunk except `LAYR`;
- **the chunk's directory index** for a `LAYR` chunk, whose payload is its version field
  followed by one sealed frame.

The index is what keeps two `LAYR` chunks apart. A file has as many of them as it has
`(sector, layer group)` pairs, all with the same `chunk_type` and one unit each; with
`unit_index` fixed at `0`, a sealed frame lifted out of one `LAYR` chunk and written into
another would authenticate exactly as it did before, because nothing in the AAD or in the
ciphertext would differ. Binding each frame to the directory position of the chunk it
belongs to denies that, which is the whole purpose of an index in the AAD. A reader
therefore computes the index of the chunk it is opening - its position in the chunk
directory, counted from `0` over all descriptors including `HEAD` - and passes it as
`unit_index`; an implementation that leaves it at `0` accepts files a conforming reader
rejects.

For every chunk except `LAYR`, the chunk payload is exactly one unit, and the chunk
descriptor's `size_compressed` includes the 28-byte framing overhead.

For `LAYR`, the 4-byte version field stays plaintext and the frame that follows it is the
sealed unit ([§4.10](06-layer-data.md#410-layr---layer-data-chunk)). One frame is one unit,
decrypted whole, and no sealed unit spans two frames, so the version can be read before the
key is used without a decompression pass. The container's `size_compressed` includes the
28-byte overhead and `size_uncompressed` does not, so the frame's stored length is
`size_compressed - 32`.

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
