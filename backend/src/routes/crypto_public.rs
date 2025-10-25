use axum::{Json, http::StatusCode};
use crate::models::dto::{TextIn, ShaOut, ArgonOut, VerifyIn, VerifyOut};

use sha2::{Digest, Sha256};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{PasswordHash, SaltString};
use rand_core::OsRng; // for SaltString::generate
use hex;

pub async fn hash_sha256(Json(input): Json<TextIn>) -> Result<Json<ShaOut>, (StatusCode, String)> {
    if input.text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "text required".into()));
    }

    let mut hasher = Sha256::new();
    hasher.update(input.text.as_bytes());
    let hash = hex::encode(hasher.finalize());

    Ok(Json(ShaOut { hash }))
}

pub async fn hash_argon2(Json(input): Json<TextIn>) -> Result<Json<ArgonOut>, (StatusCode, String)> {
    if input.text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "text required".into()));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();

    let hash = argon
        .hash_password(input.text.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    Ok(Json(ArgonOut { hash }))
}

pub async fn verify_argon2(Json(input): Json<VerifyIn>) -> Result<Json<VerifyOut>, (StatusCode, String)> {
    if input.plaintext.is_empty() || input.hash.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "plaintext and hash required".into()));
    }

    let parsed = PasswordHash::new(&input.hash)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid hash format".into()))?;

    let argon = Argon2::default();
    let ok = argon.verify_password(input.plaintext.as_bytes(), &parsed).is_ok();

    Ok(Json(VerifyOut { valid: ok }))
}
