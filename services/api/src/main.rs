//! Sentinel API server binary.
//!
//! Configuration (environment):
//! * `DATABASE_URL`  — required, e.g. `postgres://localhost/sentinel_dev`.
//! * `SENTINEL_BIND` — listen address, default `127.0.0.1:8080`. The dev default binds
//!   loopback only; production terminates TLS 1.3 at the ingress in front of this service
//!   and must configure trusted-proxy client-IP forwarding for rate limiting.
//! * `SENTINEL_RATE_PER_MIN` — per-IP requests/minute on `/v1`, default 60.
//! * `SENTINEL_TRUSTED_IP_HEADER` — optional. When set (e.g. `x-real-client-ip`), the client IP
//!   for rate limiting is read from that header. **Only** set this behind a trusted reverse proxy
//!   that overwrites the header on every request; otherwise clients could forge it (R-306). Unset
//!   ⇒ rate limit by peer socket IP and ignore the header.
//!
//! Logging: tracing with target-level filters. No request/response bodies, tokens, or
//! credentials are ever logged (INV-8).

use std::net::SocketAddr;
use std::sync::Arc;

use auth_core::memstore::SystemClock;
use auth_core::{AuthService, Config};
use sentinel_api::pgstore::PgStores;
use sentinel_api::{build_pool, http, run_migrations};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// Setup (migrations, pool) runs in plain sync `main` BEFORE the tokio runtime exists:
/// the sync `postgres` client hosts its own private runtime and panics if entered from
/// within another runtime. Once the server is async, all store access goes through
/// `spawn_blocking` (see http.rs).
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("DATABASE_URL is required (e.g. postgres://localhost/sentinel_dev)");
            std::process::exit(2);
        }
    };
    let bind: SocketAddr = env_or("SENTINEL_BIND", "127.0.0.1:8080")
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("invalid SENTINEL_BIND: {e}");
            std::process::exit(2);
        });
    let rate_per_min: u32 = env_or("SENTINEL_RATE_PER_MIN", "60").parse().unwrap_or(60);

    if let Err(e) = run_migrations(&database_url) {
        tracing::error!("migration failure: {e}");
        std::process::exit(1);
    }
    tracing::info!("migrations up to date");

    let pool = match build_pool(&database_url, 16) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("db pool failure: {e}");
            std::process::exit(1);
        }
    };
    let stores = Arc::new(PgStores::new(pool));

    let service = Arc::new(AuthService::new(
        stores.clone(),
        stores.clone(),
        stores.clone(),
        stores.clone(),
        stores.clone(),
        Arc::new(SystemClock),
        Config::default(),
    ));

    let relay = Arc::new(sentinel_api::relay::PgRelay::new(stores.pool_clone()));
    let social = Arc::new(sentinel_api::social::PgSocial::new(stores.pool_clone()));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(serve(bind, rate_per_min, stores, service, relay, social));
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    bind: SocketAddr,
    rate_per_min: u32,
    stores: Arc<PgStores>,
    service: Arc<AuthService>,
    relay: Arc<sentinel_api::relay::PgRelay>,
    social: Arc<sentinel_api::social::PgSocial>,
) {
    // Retention hygiene (DATA_RETENTION.md): every minute purge expired challenges/access
    // tokens AND stale envelopes past the 30-day queue TTL. Failure is logged and retried
    // next tick — never fatal.
    {
        let stores = stores.clone();
        let relay = relay.clone();
        tokio::spawn(async move {
            const ENVELOPE_TTL_DAYS: i32 = 30;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                let stores = stores.clone();
                let relay = relay.clone();
                let purged = tokio::task::spawn_blocking(move || {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let auth = stores.purge_expired(now)?;
                    let mail = relay.purge_stale_envelopes(ENVELOPE_TTL_DAYS)?;
                    Ok::<u64, auth_core::store::StoreError>(auth + mail)
                })
                .await;
                match purged {
                    Ok(Ok(n)) if n > 0 => tracing::debug!("purged {n} expired rows"),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::warn!("purge failed: {e}"),
                    Err(e) => tracing::warn!("purge task join error: {e}"),
                }
            }
        });
    }

    // Optional trusted-proxy client-IP header for rate limiting (R-306). Only honored when set;
    // must be overwritten by a trusted proxy on every request or clients could forge it.
    let trusted_ip_header = std::env::var("SENTINEL_TRUSTED_IP_HEADER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| axum::http::HeaderName::from_bytes(s.trim().as_bytes()).ok());
    let app = http::build_router_cfg(service, relay, social, rate_per_min, trusted_ip_header);
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("sentinel-api listening on {bind}");
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}
