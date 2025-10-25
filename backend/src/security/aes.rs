use aes_gcm::aead::{Aead, KeyInit};   // <-- trait + key init live under `aead`
use aes_gcm::{Aes256Gcm, Key, Nonce}; // cipher + Key alias + Nonce
use rand::{rngs::OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

const TAG_LEN: usize = 16; // AES-GCM tag is 128 bits

#[derive(Debug, thiserror::Error)]
pub enum AesError {
    #[error("invalid key length")]
    BadKey,
    #[error("invalid base64: {0}")]
    B64(String),
    #[error("crypto error")]
    Crypto,
}

pub fn decode_key_32_from_b64(s: &str) -> Result<[u8; 32], AesError> {
    let mut out = [0u8; 32];
    let bytes = B64.decode(s.trim()).map_err(|e| AesError::B64(e.to_string()))?;
    if bytes.len() != 32 { return Err(AesError::BadKey); }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encrypts plaintext; returns (iv_b64, ct_b64, tag_b64)
pub fn encrypt_aes256_gcm(key: &[u8; 32], plaintext: &[u8]) -> Result<(String, String, String), AesError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    // 12-byte nonce (IV)
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let mut out = cipher.encrypt(nonce, plaintext).map_err(|_| AesError::Crypto)?;
    // split ct || tag
    if out.len() < TAG_LEN { return Err(AesError::Crypto); }
    let tag = out.split_off(out.len() - TAG_LEN); // now: out=ct, tag=tag

    Ok((
        B64.encode(&iv),
        B64.encode(&out),
        B64.encode(&tag),
    ))
}

/// Decrypts given (iv, ct, tag) – all b64. Returns plaintext bytes.
pub fn decrypt_aes256_gcm(key: &[u8; 32], iv_b64: &str, ct_b64: &str, tag_b64: &str) -> Result<Vec<u8>, AesError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let iv = B64.decode(iv_b64.trim()).map_err(|e| AesError::B64(e.to_string()))?;
    if iv.len() != 12 { return Err(AesError::Crypto); }
    let nonce = Nonce::from_slice(&iv);

    let mut ct = B64.decode(ct_b64.trim()).map_err(|e| AesError::B64(e.to_string()))?;
    let tag = B64.decode(tag_b64.trim()).map_err(|e| AesError::B64(e.to_string()))?;
    if tag.len() != TAG_LEN { return Err(AesError::Crypto); }
    ct.extend_from_slice(&tag); // combine to ct||tag as expected by aes-gcm

    cipher.decrypt(nonce, ct.as_ref()).map_err(|_| AesError::Crypto)
}
