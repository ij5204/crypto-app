use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;

/* ---------- Public crypto DTOs ---------- */
#[derive(Deserialize)]
pub struct TextIn {
    pub text: String,
}

#[derive(Serialize)]
pub struct ShaOut {
    pub hash: String,
}

#[derive(Serialize)]
pub struct ArgonOut {
    pub hash: String,
}

#[derive(Deserialize)]
pub struct VerifyIn {
    pub plaintext: String,
    pub hash: String,
}

#[derive(Serialize)]
pub struct VerifyOut {
    pub valid: bool,
}

/* ---------- Protected AES DTOs ---------- */
#[derive(Serialize)]
pub struct EncOut {
    pub scheme: &'static str,
    pub iv: String,
    pub ct: String,
    pub tag: String,
    pub version: i16,
    pub key_id: uuid::Uuid,   // NEW
}

#[derive(Deserialize)]
pub struct DecIn {
    pub iv: String,
    pub ct: String,
    pub tag: String,
    pub version: Option<i16>,
    pub key_id: Option<uuid::Uuid>, // NEW (client may supply)
}

#[derive(Serialize)]
pub struct DecOut { pub plaintext: String }

/* ---------- History DTOs ---------- */
#[derive(Serialize, FromRow)]
pub struct HistoryItem {
    pub id: Uuid,
    pub kind: String,
    pub algo: String,
    pub meta_json: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct SaveHistoryIn {
    pub kind: String,
    pub algo: String,
    pub meta_json: Value,
    pub took_ms: Option<i32>,
}
