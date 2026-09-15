//! Encryption (spec 4.4 and 9): deterministic test material, the sealed unit form,
//! and the two session-key wrapping modes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_kw::KekAes256;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::container::{Chunk, FLAG_CHUNK_ENCRYPTED};
use crate::hash;
use crate::payload;
use crate::ZSTD_SMALL_LEVEL;

/// The fixed seed every nonce, salt and key is derived from.
pub const SEED: &[u8] = b"LUMEN test vectors v1.0";
/// The password the password-mode vectors publish.
pub const TEST_PASSWORD: &str = "lumen-test-vector";
/// Machine-binding HKDF information prefix.
pub const MACHINE_INFO: &[u8] = b"LUMEN machine-binding v1\x00";
/// Argon2id parameters: iterations, memory in KiB, parallelism.
pub const DEFAULT_ARGON2: (u32, u32, u32) = (1, 8, 1);
/// The chunk types sealed as single units (spec 9.1).
pub const ENC_CONTENT_TYPES: [[u8; 4]; 7] = [
    *b"LAYR", *b"META", *b"PROF", *b"SECT", *b"LROV", *b"VOXL", *b"ZDIC",
];

/// Deterministic test material, so the corpus regenerates byte for byte.
///
/// Real encoders MUST draw every nonce, salt and key from a CSPRNG (spec 9.3);
/// these values are public test data and demonstrate nothing about production
/// randomness.
pub fn det(label: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(SEED);
    hasher.update(b"|");
    hasher.update(label);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; length];
    reader.read(&mut out);
    out
}

/// AAD binding a sealed unit to its identity in the file (spec 9.3).
pub fn unit_aad(chunk_type: &[u8; 4], unit_index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(chunk_type);
    out.push(0x00);
    out.extend_from_slice(&unit_index.to_le_bytes());
    out
}

/// One sealed unit: nonce || ciphertext || tag (spec 9.3).
pub fn seal(
    key: &[u8; 32],
    cipher_id: &str,
    chunk_type: &[u8; 4],
    unit_index: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut label = Vec::with_capacity(16);
    label.extend_from_slice(b"nonce|");
    label.extend_from_slice(chunk_type);
    label.extend_from_slice(b"|");
    label.extend_from_slice(unit_index.to_string().as_bytes());
    let nonce = det(&label, 12);
    let aad = unit_aad(chunk_type, unit_index);

    let ciphertext = match cipher_id {
        "A256" => Aes256Gcm::new_from_slice(key)
            .expect("AES-256-GCM key length")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            ),
        "C20P" => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .expect("ChaCha20-Poly1305 key length")
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            ),
        other => panic!("unknown cipher id {other:?}"),
    }
    .expect("sealing");

    let mut out = nonce;
    out.extend_from_slice(&ciphertext);
    out
}

/// Argon2id per RFC 9106: version 0x13, 32-byte output, UTF-8 password.
pub fn argon2_kek(
    password: &str,
    salt: &[u8],
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
) -> [u8; 32] {
    let params =
        Params::new(memory_kib, iterations, parallelism, Some(32)).expect("Argon2id parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("Argon2id");
    out
}

/// The password section of an AUTH chunk (spec 4.4.1).
pub fn password_section(
    session_key: &[u8; 32],
    password: &str,
    salt: &[u8],
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Vec<u8> {
    let kek = argon2_kek(password, salt, iterations, memory_kib, parallelism);
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(salt);
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&memory_kib.to_le_bytes());
    out.push(parallelism as u8);
    out.extend(aes_key_wrap(&kek, session_key));
    out
}

/// The public key of a private key.
pub fn public_of(private: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// The recipient fingerprint: SHA-256 of the public key.
pub fn fingerprint(public: &[u8; 32]) -> [u8; 32] {
    hash::sha256(public)
}

/// The machine-binding KEK (spec 4.4.2).
pub fn machine_kek(shared: &[u8], ephemeral_pk: &[u8; 32], fp: &[u8; 32]) -> [u8; 32] {
    let mut info = Vec::with_capacity(MACHINE_INFO.len() + 64);
    info.extend_from_slice(MACHINE_INFO);
    info.extend_from_slice(ephemeral_pk);
    info.extend_from_slice(fp);
    let hkdf = Hkdf::<Sha256>::new(Some(fp), shared);
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out).expect("HKDF output length");
    out
}

/// One recipient entry: machine_fp || ephemeral_pk || wrapped_key (spec 4.4.2).
pub fn machine_entry(
    session_key: &[u8; 32],
    recipient_private: &[u8; 32],
    label: &[u8],
) -> Vec<u8> {
    let recipient_public = public_of(recipient_private);
    let fp = fingerprint(&recipient_public);

    let mut ephemeral_label = Vec::with_capacity(10 + label.len());
    ephemeral_label.extend_from_slice(b"ephemeral|");
    ephemeral_label.extend_from_slice(label);
    let ephemeral =
        StaticSecret::from(<[u8; 32]>::try_from(det(&ephemeral_label, 32)).expect("32"));
    let ephemeral_pk = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral
        .diffie_hellman(&PublicKey::from(recipient_public))
        .to_bytes();

    let mut out = Vec::with_capacity(104);
    out.extend_from_slice(&fp);
    out.extend_from_slice(&ephemeral_pk);
    out.extend(aes_key_wrap(
        &machine_kek(&shared, &ephemeral_pk, &fp),
        session_key,
    ));
    out
}

/// An entry for our own fingerprint whose ephemeral key is the low-order point.
///
/// X25519 against it yields the all-zero shared secret, which a reader MUST reject
/// (spec 4.4.2 step 1). It carries a *different* session key, so a reader that
/// unwraps it without checking cannot decrypt the file at all.
pub fn decoy_entry(recipient_public: &[u8; 32], label: &[u8]) -> Vec<u8> {
    let fp = fingerprint(recipient_public);
    let ephemeral_pk = [0u8; 32];

    let mut session_label = Vec::with_capacity(18 + label.len());
    session_label.extend_from_slice(b"decoy-session-key|");
    session_label.extend_from_slice(label);
    let decoy_key = det(&session_label, 32);

    let mut out = Vec::with_capacity(104);
    out.extend_from_slice(&fp);
    out.extend_from_slice(&ephemeral_pk);
    out.extend(aes_key_wrap(
        &machine_kek(&ephemeral_pk, &ephemeral_pk, &fp),
        &<[u8; 32]>::try_from(decoy_key).expect("32"),
    ));
    out
}

/// The AUTH chunk payload (spec 4.4).
pub fn auth_payload(
    cipher_id: &str,
    mode: u32,
    password_sec: &[u8],
    machine_sec: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 16 + password_sec.len() + machine_sec.len());
    out.extend_from_slice(cipher_id.as_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&mode.to_le_bytes());
    out.extend_from_slice(&(password_sec.len() as u32).to_le_bytes());
    out.extend_from_slice(&(machine_sec.len() as u32).to_le_bytes());
    out.extend_from_slice(password_sec);
    out.extend_from_slice(machine_sec);
    out
}

/// Seal every content chunk (spec 9.1).
///
/// LAYR keeps its header and block table plaintext and seals each block frame
/// separately, so per-block random access still works (spec 9.3).
pub fn seal_content_chunks(
    chunks: Vec<Chunk>,
    frames: &[Vec<u8>],
    uncompressed_sizes: &[usize],
    key: &[u8; 32],
    cipher_id: &str,
) -> Vec<Chunk> {
    let mut out = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        if chunk.ctype == *b"LAYR" {
            let sealed: Vec<Vec<u8>> = frames
                .iter()
                .enumerate()
                .map(|(index, frame)| seal(key, cipher_id, b"LAYR", index as u32, frame))
                .collect();
            out.push(
                Chunk::new(b"LAYR", payload::layr(&sealed, uncompressed_sizes))
                    .flags(FLAG_CHUNK_ENCRYPTED),
            );
            continue;
        }

        if ENC_CONTENT_TYPES.contains(&chunk.ctype) || chunk.seal {
            let plaintext_len = chunk.payload.len();
            let stored = if chunk.compressed {
                zstd::bulk::Compressor::new(ZSTD_SMALL_LEVEL)
                    .expect("zstd compressor")
                    .compress(&chunk.payload)
                    .expect("small payload compression")
            } else {
                chunk.payload.clone()
            };
            let sealed = seal(key, cipher_id, &chunk.ctype, 0, &stored);
            let flags = chunk.flags | FLAG_CHUNK_ENCRYPTED;
            out.push(chunk.seal_with(sealed, plaintext_len, flags));
            continue;
        }

        out.push(chunk);
    }
    out
}

/// AES Key Wrap (RFC 3394) with the default initial value.
pub fn aes_key_wrap(kek: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; plaintext.len() + 8];
    KekAes256::from(*kek)
        .wrap(plaintext, &mut out)
        .expect("key wrap");
    out
}

/// AES Key Unwrap, used by the password-section self-check.
pub fn aes_key_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; wrapped.len() - 8];
    KekAes256::from(*kek)
        .unwrap(wrapped, &mut out)
        .expect("key unwrap");
    out
}
