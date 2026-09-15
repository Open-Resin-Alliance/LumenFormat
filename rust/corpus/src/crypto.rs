//! The AUTH chunk and the sealing it describes (§4.4, §9, §11.4).
//!
//! Reimplemented from the specification, independently of the generator, so
//! that an encrypted vector agreeing with this reader is evidence about the
//! text rather than about one implementation.
//!
//! Every helper here is total: a credential that does not work, a tag that does
//! not verify, a budget the reader will not spend - all of them are answers, not
//! errors. The checks that report them are the point, and a reader that panicked
//! on a damaged file could not report anything.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_kw::KekAes256;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::bytes::at;
use crate::container::{type_name, Chunk, AEAD_OVERHEAD, LAYR_HEADER_SIZE, SEALED_FLAG};

/// A sealed unit that does not open: an unknown cipher, a unit too short to
/// hold its framing, or a tag that does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealError;

/// §9.1: chunk types whose payload must be sealed when the file is encrypted.
pub const SEALED_CHUNK_TYPES: [&[u8; 4]; 6] =
    [b"LAYR", b"META", b"PROF", b"LROV", b"VOXL", b"ZDIC"];

/// §9.1: chunk types that must stay in the clear.
pub const CLEAR_CHUNK_TYPES: [&[u8; 4]; 3] = [b"HEAD", b"AUTH", b"LTBL"];

/// PREV's sealing is optional (§4.6), so it is deliberately absent from
/// [`SEALED_CHUNK_TYPES`]: a clear PREV beside a sealed one is not a defect. Its
/// `ENCRYPTED` bit still has to be honoured when it is set, so the decrypt phase
/// covers it too.
pub const SEALABLE_CHUNK_TYPES: [&[u8; 4]; 7] = [
    b"LAYR", b"META", b"PROF", b"LROV", b"VOXL", b"ZDIC", b"PREV",
];

/// The credentials a manifest entry (or a caller) supplies for an AUTH chunk.
///
/// The generator writes this shape into `manifest.json`; [`crate::cross_check`]
/// builds the same one from a file's own AUTH chunk, which is why the fields are
/// public and the type carries no logic.
#[derive(Deserialize, Default, Clone)]
pub struct CryptoBlock {
    #[serde(default)]
    pub password_utf8: Option<String>,
    #[serde(default)]
    pub argon2: Option<Argon2Cost>,
    #[serde(default)]
    pub local_recipient_private_key: Option<String>,
}

/// The Argon2id cost parameters as they appear in a manifest or an AUTH chunk.
#[derive(Deserialize, Default, Clone)]
pub struct Argon2Cost {
    /// Lowercase hex, 16 bytes.
    pub salt: String,
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

/// §9.3: `chunk_type || 0x00 || unit_index_le_u32`.
pub fn unit_aad(ctype: &[u8; 4], unit_index: u32) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..4].copy_from_slice(ctype);
    aad[5..].copy_from_slice(&unit_index.to_le_bytes());
    aad
}

/// Open one sealed unit (`nonce || ciphertext || tag`).
///
/// `Err` is a tag failure or an unknown cipher: §9.3 requires both to stop the
/// content checks rather than be worked around.
pub fn open_unit(
    key: &[u8; 32],
    cipher_id: &[u8; 4],
    ctype: &[u8; 4],
    unit_index: u32,
    blob: &[u8],
) -> Result<Vec<u8>, SealError> {
    if blob.len() < AEAD_OVERHEAD {
        return Err(SealError);
    }
    let aad = unit_aad(ctype, unit_index);
    let nonce = Nonce::from_slice(&blob[..12]);
    let payload = Payload {
        msg: &blob[12..],
        aad: &aad,
    };
    match cipher_id {
        b"A256" => Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
            .decrypt(nonce, payload)
            .map_err(|_| SealError),
        b"C20P" => ChaCha20Poly1305::new(Key::<ChaCha20Poly1305>::from_slice(key))
            .decrypt(nonce, payload)
            .map_err(|_| SealError),
        _ => Err(SealError),
    }
}

/// `(iterations, memory_kib, parallelism)` from the password section, or `None`.
///
/// Only the 25 bytes holding the salt and the three cost parameters are needed,
/// so a section whose declared length falls short of the fixed 65 still exposes
/// its declared budget - the length defect is reported by its own check.
pub fn argon2_params(auth: &[u8], pw_len: u32) -> Option<(u32, u32, u8)> {
    if pw_len < 25 || auth.len() < 20 + 25 {
        return None;
    }
    Some((
        u32::from_le_bytes(auth[36..40].try_into().ok()?),
        u32::from_le_bytes(auth[40..44].try_into().ok()?),
        auth[44],
    ))
}

/// Unwrap the session key per §4.4; `None` when no credential works.
///
/// Password mode is tried first, then every machine-binding entry whose
/// fingerprint matches ours (§4.4.2 step 1: an all-zero shared secret - the
/// low-order-point result - rejects the entry).
pub fn recover_session_key(
    auth: &[u8],
    crypto: Option<&CryptoBlock>,
    mode: u32,
    pw_len: u32,
    mc_len: u32,
) -> Option<[u8; 32]> {
    let crypto = crypto?;
    if mode & 0x01 != 0 {
        if let (Some(password), Some(params)) = (&crypto.password_utf8, &crypto.argon2) {
            if pw_len >= 65 {
                if let Some(key) = password_session_key(password, params, auth) {
                    return Some(key);
                }
            }
        }
    }
    if mode & 0x02 != 0 {
        let private = crypto.local_recipient_private_key.as_deref()?;
        let secret = StaticSecret::from(unhex32(private)?);
        let local_public = PublicKey::from(&secret);
        let machine_fp = Sha256::digest(local_public.as_bytes());
        let base = 20 + pw_len as usize;
        for index in 0..(mc_len / 104) as usize {
            let offset = base + index * 104;
            if offset + 104 > auth.len() {
                break;
            }
            let entry = &auth[offset..offset + 104];
            if entry[..32] != machine_fp[..] {
                continue;
            }
            let ephemeral = &entry[32..64];
            let Ok(ephemeral) = <[u8; 32]>::try_from(ephemeral) else {
                continue;
            };
            let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
            if shared.as_bytes().iter().all(|&b| b == 0) {
                continue;
            }
            let mut info = Vec::with_capacity(23 + 32 + 32);
            info.extend_from_slice(b"LUMEN machine-binding v1\0");
            info.extend_from_slice(&ephemeral);
            info.extend_from_slice(&machine_fp);
            let mut kek = [0u8; 32];
            if Hkdf::<Sha256>::new(Some(&machine_fp), shared.as_bytes())
                .expand(&info, &mut kek)
                .is_err()
            {
                continue;
            }
            if let Some(key) = unwrap_key(&kek, &entry[64..104]) {
                return Some(key);
            }
        }
    }
    None
}

fn password_session_key(password: &str, params: &Argon2Cost, auth: &[u8]) -> Option<[u8; 32]> {
    let salt = crate::bytes::unhex(&params.salt)?;
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .ok()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut kek)
        .ok()?;
    unwrap_key(&kek, at(auth, 45, 40))
}

fn unwrap_key(kek: &[u8; 32], wrapped: &[u8]) -> Option<[u8; 32]> {
    let length = wrapped.len().checked_sub(8)?;
    let mut key = vec![0u8; length];
    KekAes256::from(*kek).unwrap(wrapped, &mut key).ok()?;
    <[u8; 32]>::try_from(key.as_slice()).ok()
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(crate::bytes::unhex(text)?.as_slice()).ok()
}

/// `(ok, detail)` for `crypt.chunk_flags` - §11.4 / §9.1.
///
/// `real` is the directory's live records. A `LAYR` chunk's frame is the sealed
/// unit and its 4-byte version field stays in the clear, so a sealed LAYR chunk
/// whose container cannot even hold its framing is reported here rather than
/// left for the seam to notice.
pub fn chunk_flag_report(real: &[Chunk], encrypted_flag: bool) -> (bool, String) {
    if !encrypted_flag {
        // §9.1: the chunk-level flag requires AUTH in the same file. Without it
        // there is no key, so a sealed unit is unreadable rather than merely
        // unchecked.
        let sealed: Vec<String> = real
            .iter()
            .filter(|chunk| chunk.entry.flags & SEALED_FLAG != 0)
            .map(|chunk| type_name(&chunk.entry.ctype))
            .collect();
        if sealed.is_empty() {
            return (true, String::new());
        }
        return (false, format!("{} sealed without AUTH", sealed.join(", ")));
    }
    let mut bad = Vec::new();
    for chunk in real {
        let name = type_name(&chunk.entry.ctype);
        if SEALED_CHUNK_TYPES.contains(&&chunk.entry.ctype) && chunk.entry.flags & SEALED_FLAG == 0
        {
            bad.push(format!("{name} not sealed"));
        }
        if CLEAR_CHUNK_TYPES.contains(&&chunk.entry.ctype) && chunk.entry.flags & SEALED_FLAG != 0 {
            bad.push(format!("{name} sealed"));
        }
        if chunk.entry.ctype == *b"LAYR"
            && chunk.entry.flags & SEALED_FLAG != 0
            && chunk.entry.size() < LAYR_HEADER_SIZE + AEAD_OVERHEAD as u64
        {
            bad.push("LAYR frame shorter than 28 bytes".to_string());
        }
    }
    (bad.is_empty(), bad.join(", "))
}
