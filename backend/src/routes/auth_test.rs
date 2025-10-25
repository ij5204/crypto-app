use axum::{extract::State, Json};
use serde_json::json;
use axum::http::StatusCode;
use serde::Serialize;
use uuid::Uuid;

use crate::store::keys::create_user_key;
use crate::db::{Db, begin_with_rls};
use crate::models::claims::Claims;

pub async fn whoami(State(pool): State<Db>, claims: Claims) -> Json<serde_json::Value> {
    let claims_json = claims.as_json();

    let rls_ok = if let Ok(mut tx) = begin_with_rls(&pool, &claims_json).await {
        let row: Option<String> = sqlx::query_scalar(
            "select current_setting('request.jwt.claims', true)"
        )
        .persistent(false)
        .fetch_one(&mut *tx)
        .await
        .ok()
        .flatten();
        let _ = tx.rollback().await;
        row.is_some()
    } else {
        false
    };

    Json(json!({ "user_id": claims.sub, "rls_claims_set": rls_ok }))
}

#[derive(Serialize)]
pub struct RotateOut { pub new_key_id: Uuid }

pub async fn rotate_key(
    State(pool): State<Db>,
    claims: Claims,
) -> Result<Json<RotateOut>, (StatusCode, String)> {
    // (A) retire current key in ONE statement with RLS set via CTE (no Transaction in handler)
    sqlx::query(
        r#"
        with _s as (
        select set_config('request.jwt.claims', $1, true)
        )
        update public.keys
        set retired_at = now()
        where user_id = auth.uid()
        and purpose  = 'DATA'
        and retired_at is null
        "#,
    )
    .bind(claims.as_json())
    .persistent(false) 
    .execute(&pool)
    .await
    .map_err(internal)?;

    // (B) mint new envelope key (this helper manages DB internally)
    let kid = create_user_key(&pool, &claims, "DATA")
        .await
        .map_err(internal)?;

    Ok(Json(RotateOut { new_key_id: kid }))
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
