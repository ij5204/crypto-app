use anyhow::Result;
use serde_json::Value;
use sqlx::{QueryBuilder, Postgres};
use uuid::Uuid;

use crate::db::{begin_with_rls, Db};
use crate::models::{claims::Claims, dto::HistoryItem};

pub async fn insert_operation(
    pool: &Db,
    claims: &Claims,
    kind: &str,
    algo: &str,
    meta_json: &Value,
    took_ms: Option<i32>,
) -> Result<Uuid> {
    let claims_json = claims.as_json();
    let mut tx = begin_with_rls(pool, &claims_json).await?;
    let rec: (Uuid,) = sqlx::query_as(
        r#"
        insert into public.operations (user_id, kind, algo, meta_json, took_ms)
        values (auth.uid(), $1, $2, $3, $4)
        returning id
        "#,
    )
    .bind(kind)
    .bind(algo)
    .bind(meta_json)
    .bind(took_ms)
    .persistent(false) 
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rec.0)
}

pub struct ListParams<'a> {
    pub kind: Option<&'a str>,
    pub algo: Option<&'a str>,
    pub limit: i64,
}

pub async fn list_operations(
    pool: &Db,
    claims: &Claims,
    params: ListParams<'_>,
) -> Result<Vec<HistoryItem>> {
    let claims_json = claims.as_json();
    let mut tx = begin_with_rls(pool, &claims_json).await?;

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "select id, kind, algo, meta_json, created_at from public.operations where user_id = auth.uid()",
    );
    if let Some(kind) = params.kind { qb.push(" and kind = ").push_bind(kind); }
    if let Some(algo) = params.algo { qb.push(" and algo = ").push_bind(algo); }
    qb.push(" order by created_at desc limit ").push_bind(params.limit);

    let rows = qb.build_query_as::<HistoryItem>().fetch_all(&mut *tx).await?;
    tx.rollback().await.ok();
    Ok(rows)
}

pub async fn delete_operation(pool: &Db, claims: &Claims, id: Uuid) -> Result<u64> {
    let claims_json = claims.as_json();
    let mut tx = begin_with_rls(pool, &claims_json).await?;
    let res = sqlx::query("delete from public.operations where id = $1 and user_id = auth.uid()")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(res.rows_affected())
}
