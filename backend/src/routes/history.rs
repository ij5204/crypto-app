use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::Db;
use crate::models::{claims::Claims, dto::{HistoryItem, SaveHistoryIn}};
use crate::store::operations::{insert_operation, list_operations, delete_operation, ListParams};

#[derive(Deserialize)]
pub struct ListQuery {
    pub kind: Option<String>,
    pub algo: Option<String>,
    pub limit: Option<i64>,
}

pub async fn save_history(
    State(pool): State<Db>,
    claims: Claims,
    Json(input): Json<SaveHistoryIn>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let id = insert_operation(
        &pool, &claims, &input.kind, &input.algo, &input.meta_json, input.took_ms,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "id": id })))
}

pub async fn list_history(
    State(pool): State<Db>,
    claims: Claims,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<HistoryItem>>, (StatusCode, String)> {
    let items = list_operations(
        &pool,
        &claims,
        ListParams {
            kind: q.kind.as_deref(),
            algo: q.algo.as_deref(),
            limit: q.limit.unwrap_or(50).clamp(1, 200),
        },
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(items))
}

pub async fn delete_history(
    State(pool): State<Db>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let n = delete_operation(&pool, &claims, id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if n == 0 { return Err((StatusCode::NOT_FOUND, "not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}
