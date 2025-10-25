use axum::{
    routing::{get, post},
    Json, Router,
};
use dotenvy::dotenv;
use serde::Serialize;
use std::{env, net::SocketAddr};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use routes::crypto_protected::{encrypt, decrypt};
use routes::auth_test::rotate_key;

// --- modules ---
mod db;
mod middleware;
mod models { pub mod dto; pub mod claims; }
mod routes;
mod security;
mod store;


use db::connect_db;
use routes::auth_test::whoami;
use routes::crypto_public::{hash_argon2, hash_sha256, verify_argon2};
use routes::history::{save_history, list_history, delete_history};

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct RootInfo<'a> {
    service: &'a str,
    health: &'a str,
    public_routes: &'a [&'a str],
    protected_routes: &'a [&'a str],
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv_override().ok();  // load .env

    // logging (RUST_LOG=info in .env)
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4028);

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is required");

    // DB pool
    let pool = connect_db(&db_url).await.expect("db connect");

    // CORS for dev (lock down in prod)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Router
    let app = Router::new()
        // Friendly root
        .route(
            "/",
            get(|| async {
                Json(RootInfo {
                    service: "encryption-api",
                    health: "/health",
                    public_routes: &[
                        "POST /api/hash/sha256",
                        "POST /api/hash/argon2",
                        "POST /api/hash/verify",
                    ],
                    protected_routes: &["GET /api/whoami"],
                })
            }),
        )
        // Health
        .route("/health", get(|| async { Json(Health { status: "ok" }) }))
        // Public crypto
        .route("/api/hash/sha256", post(hash_sha256))
        .route("/api/hash/argon2", post(hash_argon2))
        .route("/api/hash/verify", post(verify_argon2))
        // Protected test endpoint (requires Bearer token)
        .route("/api/whoami", get(whoami))
        .route("/api/encrypt", post(encrypt))   // needs Bearer token
        .route("/api/decrypt", post(decrypt))   // needs Bearer token
        .route("/api/keys/rotate", post(rotate_key))  // needs Bearer token
        // History endpoints
        .route("/api/history/save", axum::routing::post(save_history))
        .route("/api/history", axum::routing::get(list_history))
        .route("/api/history/:id", axum::routing::delete(delete_history))
        // Share DB via state
        .with_state(pool)
        // Middleware layers
        .layer(cors)
        .layer(TraceLayer::new_for_http()); // request/response logs

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Backend listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
