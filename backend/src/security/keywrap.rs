use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key, OsRng, generic_array::GenericArray}};
use base64::{engine::general_purpose, Engine as _};
use rand_core::RngCore; // <-- required for OsRng.fill_bytes

#[derive(thiserror::Error, Debug)]
pub enum KwError {
    #[error("master key invalid length")]
    MasterKeyLen,
    #[error("base64 error: {0}")]
    B64(#[from] base64::DecodeError),
    #[error("crypto error")]
    Crypto,
}

fn decode_master_key_b64() -> Result<[u8; 32], KwError> {
    let s = std::env::var("MASTER_KEY_B64").map_err(|_| KwError::MasterKeyLen)?;
    let raw = general_purpose::STANDARD.decode(s)?;
    if raw.len() != 32 { return Err(KwError::MasterKeyLen); }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn wrap_key_v1(dk32: &[u8; 32]) -> Result<String, KwError> {
    let mk = decode_master_key_b64()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&mk));

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ct = cipher.encrypt(GenericArray::from_slice(&nonce), dk32.as_slice())
        .map_err(|_| KwError::Crypto)?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(general_purpose::STANDARD.encode(out))
}

pub fn unwrap_key_v1(wrapped_b64: &str) -> Result<[u8; 32], KwError> {
    let mk = decode_master_key_b64()?;
    let blob = general_purpose::STANDARD.decode(wrapped_b64)?;
    if blob.len() < 12 + 16 { return Err(KwError::Crypto); }
    let (nonce, ct) = blob.split_at(12);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&mk));
    let pt = cipher.decrypt(GenericArray::from_slice(nonce), ct)
        .map_err(|_| KwError::Crypto)?;
    if pt.len() != 32 { return Err(KwError::Crypto); }

    let mut dk = [0u8; 32];
    dk.copy_from_slice(&pt);
    Ok(dk)
}
