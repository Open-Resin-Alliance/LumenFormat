# Authentication chunk

<!-- Part of the LUMEN Format Specification. Section numbers (`§3.1`) are stable anchors across the parts. -->

### 4.4 AUTH - Authentication & Encryption Chunk

**Type tag:** `AUTH` (`0x41 0x55 0x54 0x48`). Optional.

**Flags:** uncompressed, unencrypted.

Present only when the `ENCRYPTED` flag is set in the file header. Carries the
metadata needed to derive or unwrap the session key.

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | `[u8; 4]` | `cipher_id` | ASCII. `A256` = AES-256-GCM, `C20P` = ChaCha20-Poly1305. |
| 4 | 4 | `u32` | `auth_version` | Layout version. `1` for this spec. |
| 8 | 4 | `u32` | `mode` | Bitfield: bit 0 = password, bit 1 = machine-binding. |
| 12 | 4 | `u32` | `password_section_len` | Byte length of password section. 0 if not used. |
| 16 | 4 | `u32` | `machine_section_len` | Byte length of machine-binding section. 0 if not used. |
| 20 | N | - | `password_section` | See [§4.4.1](#441-password-section). |
| 20+N | M | - | `machine_section` | See [§4.4.2](#442-machine-binding-section). |

#### 4.4.1 Password Section

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 16 | `[u8; 16]` | `salt` | Random salt for Argon2id. |
| 16 | 4 | `u32` | `iterations` | Argon2id time cost. |
| 20 | 4 | `u32` | `memory_kib` | Argon2id memory cost in KiB. |
| 24 | 1 | `u8` | `parallelism` | Argon2id lanes. |
| 25 | 40 | `[u8; 40]` | `wrapped_key` | Session key wrapped with the Argon2id-derived KEK (AES-256-KW, RFC 3394). |

Password section size: 65 bytes. AES-256-KW is deterministic and takes no nonce, so
none is stored; per-file uniqueness comes from the salt.

To decrypt: derive a 256-bit KEK from the password + salt + Argon2id parameters,
then unwrap `wrapped_key` with AES-256-KW to recover the session key.

#### 4.4.2 Machine-Binding Section

Contains one or more recipient entries. Each entry:

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 32 | `[u8; 32]` | `machine_fp` | SHA-256 fingerprint of the machine's public key. |
| 32 | 32 | `[u8; 32]` | `ephemeral_pk` | Sender's ephemeral X25519 public key. |
| 64 | 40 | `[u8; 40]` | `wrapped_key` | Session key wrapped with the ECDH-derived KEK (AES-256-KW). |

Total per entry: 104 bytes. `machine_section_len / 104` gives the recipient count.

The sender must obtain the recipient's X25519 public key out of band (a machine key
registry, or a pairing step). The file carries only its fingerprint, as an index; there
is no way to recover the public key from `machine_fp`.

To decrypt, for each entry whose `machine_fp` matches the local machine:

1. `ss = X25519(recipient_private_key, ephemeral_pk)`. If `ss` is the all-zero value
   (the low-order-point result), reject the entry.
2. Derive the KEK with HKDF-SHA-256:

   ```
   KEK = HKDF-SHA-256(
           IKM  = ss,
           salt = machine_fp,
           info = "LUMEN machine-binding v1\0" || ephemeral_pk || machine_fp,
           L    = 32)
   ```

   `info` is the ASCII label, then a NUL byte, then the two 32-byte values in the order
   shown. All lengths are fixed, so the concatenation is unambiguous.
3. Unwrap `wrapped_key` with AES-256-KW. RFC 3394 unwrapping fails on a wrong KEK, so a
   successful unwrap is what proves possession of the recipient private key.

Binding both values and a protocol label into `info`, and using `machine_fp` as the HKDF
salt, keeps the KEK unique to this recipient entry and to this construction; a bare
`HKDF(ss)` would be reassociable with any other use of the same shared secret.

**Notes:**
- All recipient entries wrap the **same** session key - any authorized machine
  can decrypt.
- A file may use password mode only, machine-binding only, or both (the session
  key is the same; both sections wrap it independently).
