use anyhow::Result;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Pool, Postgres, Transaction,
};
use std::str::FromStr;

pub type Db = Pool<Postgres>;

pub async fn connect_db(url: &str) -> Result<Db> {
    // Disable server-side prepared statements (PgBouncer-safe)
    let opts = PgConnectOptions::from_str(url)?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;
    Ok(pool)
}
// Tie the returned Transaction's lifetime to the pool reference.
pub async fn begin_with_rls<'a>(
    pool: &'a Db,
    claims_json: &str,
) -> Result<Transaction<'a, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("select set_config('request.jwt.claims', $1, true)")
        .bind(claims_json)
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
