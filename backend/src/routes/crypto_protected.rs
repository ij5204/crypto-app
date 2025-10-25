use axum::{Json, http::StatusCode, extract::State};
use crate::db::Db;

use crate::models::dto::{TextIn, EncOut, DecIn, DecOut};
use crate::models::claims::Claims;
use crate::security::aes::{encrypt_aes256_gcm, decrypt_aes256_gcm};
use serde_json::json;
use crate::store::operations::insert_operation;
use crate::store::keys::{ensure_active_key, get_key_by_id};

pub async fn encrypt(
    State(pool): State<Db>,
    claims: Claims,
    Json(input): Json<TextIn>,
) -> Result<Json<EncOut>, (StatusCode, String)> {
    if input.text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "text required".into()));
    }
    if input.text.len() > 1_000_000 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "text too large".into()));
    }

    // per-user data key
    let (key_id, dk) = ensure_active_key(&pool, &claims, "DATA")
    .await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let (iv, ct, tag) = encrypt_aes256_gcm(&dk, input.text.as_bytes())
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let meta = json!({ "iv": iv, "ct": ct, "tag": tag, "size": input.text.len(), "key_id": key_id, "version": 1 });
    let _ = insert_operation(&pool, &claims, "ENCRYPT", "AES-256-GCM", &meta, None).await;
    
    Ok(Json(EncOut { scheme: "AES-256-GCM", iv, ct, tag, version: 1, key_id }))
}

pub async fn decrypt(
    State(pool): State<Db>,
    claims: Claims,
    Json(input): Json<DecIn>,
) -> Result<Json<DecOut>, (StatusCode, String)> {
    if input.iv.is_empty() || input.ct.is_empty() || input.tag.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "iv, ct, tag required".into()));
    }

    // use current active key (simple v1). Later: accept key_id/version in request to pick historical key.
    let (_key_id_used, dk) = if let Some(kid) = input.key_id {
    // fetch that key and unwrap it
    use crate::store::keys::get_key_by_id; // add this helper (below)
    let dk = get_key_by_id(&pool, &claims, kid)
        .await.map_err(|e| (StatusCode::BAD_REQUEST, format!("bad key_id: {e}")))?;
    (kid, dk)
    } else {
        ensure_active_key(&pool, &claims, "DATA")
        .await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    let pt = decrypt_aes256_gcm(&dk, &input.iv, &input.ct, &input.tag)
    .map_err(|_| (StatusCode::BAD_REQUEST, "decryption failed".into()))?;
    let plaintext = String::from_utf8(pt).unwrap_or_default();

    // log (sizes only)
    let meta = json!({ "ct_len": input.ct.len(), "tag_len": input.tag.len() });
    let _ = insert_operation(&pool, &claims, "DECRYPT", "AES-256-GCM", &meta, None).await;

    Ok(Json(DecOut { plaintext }))
}
