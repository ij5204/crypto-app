use anyhow::{Result, anyhow};
use sqlx::{FromRow, query_as};
use sqlx::Row;
use uuid::Uuid;

use crate::db::{Db, begin_with_rls};
use crate::models::claims::Claims;
use rand::rngs::OsRng;
use rand::RngCore;
use crate::security::keywrap::{wrap_key_v1, unwrap_key_v1};

#[derive(Debug, Clone, FromRow)]
pub struct KeyRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub purpose: String,
    pub wrapped_key: String,
    pub algo: String,
}

async fn get_active_key(pool: &Db, claims: &Claims, purpose: &str) -> Result<Option<KeyRow>> {
    let mut tx = begin_with_rls(pool, &claims.as_json()).await?;
    let row = query_as::<_, KeyRow>(
        r#"
        select id, user_id, purpose, wrapped_key, algo
        from public.keys
        where (user_id = auth.uid() or user_id is null)
        and purpose = $1
        and retired_at is null
        order by user_id nulls last, created_at desc
        limit 1
        "#,
    )
    .bind(purpose)
    .persistent(false)
    .fetch_optional(&mut *tx)
    .await?;
    tx.rollback().await.ok();
    Ok(row)
}

pub async fn get_key_by_id(pool: &Db, claims: &Claims, key_id: Uuid) -> Result<[u8;32]> {
    let mut tx = begin_with_rls(pool, &claims.as_json()).await?;
    let wrapped: Option<String> = sqlx::query_scalar::<_, String>(
        r#"select wrapped_key from public.keys
        where id = $1 and (user_id = auth.uid() or user_id is null)"#
    )
    .bind(key_id)
    .persistent(false) 
    .fetch_optional(&mut *tx)
    .await?;
    tx.rollback().await.ok();
    let wrapped = wrapped.ok_or_else(|| anyhow!("key not found"))?;
    let dk = crate::security::keywrap::unwrap_key_v1(&wrapped)?;
    Ok(dk)
}

pub async fn create_user_key(pool: &Db, claims: &Claims, purpose: &str) -> Result<Uuid> {
    use rand::rngs::OsRng;
    use rand_core::RngCore;
    let mut dk = [0u8; 32];
    OsRng.fill_bytes(&mut dk);

    let wrapped = crate::security::keywrap::wrap_key_v1(&dk)?;

    let mut tx = begin_with_rls(pool, &claims.as_json()).await?;
    // runtime query (no `!` macro)
    let id: Uuid = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.keys (user_id, purpose, wrapped_key, algo)
        values (auth.uid(), $1, $2, 'AES-256-GCM')
        returning id
        "#
    )
    .bind(purpose)
    .bind(wrapped)
    .persistent(false) 
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(id)
}

pub async fn ensure_active_key(pool: &Db, claims: &Claims, purpose: &str) -> Result<(Uuid, [u8;32])> {
    // try get active
    let mut tx = begin_with_rls(pool, &claims.as_json()).await?;
    let row: Option<(Uuid, String)> = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        select id, wrapped_key
        from public.keys
        where purpose = $1 and retired_at is null
        and (user_id = auth.uid() or user_id is null)
        order by created_at desc
        limit 1
        "#
    )
    .bind(purpose)
    .persistent(false) 
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((id, wrapped)) = row {
        tx.rollback().await.ok();
        let dk = crate::security::keywrap::unwrap_key_v1(&wrapped)?;
        return Ok((id, dk));
    }

    tx.rollback().await.ok();

    // else create one
    let id = create_user_key(pool, claims, purpose).await?;
    // read it back unwrapped
    let mut tx2 = begin_with_rls(pool, &claims.as_json()).await?;
    let wrapped: String = sqlx::query_scalar::<_, String>(
        "select wrapped_key from public.keys where id = $1"
    )
    .bind(id)
    .persistent(false) 
    .fetch_one(&mut *tx2)
    .await?;
    tx2.rollback().await.ok();

    let dk = crate::security::keywrap::unwrap_key_v1(&wrapped)?;
    Ok((id, dk))
}
