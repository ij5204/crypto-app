use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::TypedHeader;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use std::env;
use uuid::Uuid;

use crate::models::claims::Claims;

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Bearer token
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, _state)
                .await
                .map_err(|_| (StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;

        // Supabase JWT secret
        let secret = env::var("SUPABASE_JWT_SECRET")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "SUPABASE_JWT_SECRET missing".into()))?;

        // Verify HS256
        let mut v = Validation::new(Algorithm::HS256);
        v.validate_aud = false;

        let data = decode::<Value>(bearer.token(), &DecodingKey::from_secret(secret.as_bytes()), &v)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".into()))?;

        // Extract sub (uuid)
        let sub_str = data
            .claims
            .get("sub")
            .and_then(|s| s.as_str())
            .ok_or((StatusCode::UNAUTHORIZED, "token missing sub".into()))?;
        let sub = Uuid::parse_str(sub_str).map_err(|_| (StatusCode::UNAUTHORIZED, "sub must be uuid".into()))?;

        Ok(Claims { sub, rest: data.claims })
    }
}
