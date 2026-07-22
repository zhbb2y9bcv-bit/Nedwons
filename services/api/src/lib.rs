//! PostgreSQL-backed stores and the HTTP API. Security decisions live in `auth-core`; this crate
//! supplies storage (with DB-enforced atomicity, ADR-0006) and transport.

#![forbid(unsafe_code)]

pub mod attest;
pub mod breach_http;
pub mod groups;
pub mod http;
pub mod membership;
pub mod notify;
pub mod pgstore;
pub mod proof;
pub mod push;
pub mod relay;
pub mod social;
pub mod transparency;

use refinery::embed_migrations;

embed_migrations!("migrations");

/// Run embedded migrations against the given database URL.
pub fn run_migrations(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = postgres::Client::connect(database_url, postgres::NoTls)?;
    migrations::runner().run(&mut client)?;
    Ok(())
}

/// Build a connection pool for the given database URL.
///
/// `min_idle(0)` matters: the sync `postgres` client hosts a private tokio runtime, so
/// connections must only ever be created from blocking threads (`spawn_blocking`), never
/// eagerly from an async context — creating a runtime inside a runtime panics. With zero
/// minimum idle, connections are established lazily on first `get()`, which the HTTP
/// handlers always perform inside `spawn_blocking`.
pub fn build_pool(
    database_url: &str,
    max_size: u32,
) -> Result<pgstore::PgPool, Box<dyn std::error::Error>> {
    let mut config: r2d2_postgres::postgres::Config = database_url.parse()?;
    // Overload guards (fail fast instead of wedging):
    // - statement_timeout: a stuck query cannot hold a pooled connection indefinitely. All API
    //   statements are single-row/small-batch and finish in milliseconds; 15s is generous.
    // - idle_in_transaction_session_timeout: an abandoned transaction (leaked connection, killed
    //   thread) cannot pin locks forever.
    // Migrations run through this pool too — a future migration needing longer than 15s (e.g. an
    // index build on a huge table) must SET LOCAL statement_timeout itself.
    config.options("-c statement_timeout=15000 -c idle_in_transaction_session_timeout=30000");
    let manager =
        r2d2_postgres::PostgresConnectionManager::new(config, r2d2_postgres::postgres::NoTls);
    Ok(r2d2::Pool::builder()
        .max_size(max_size)
        .min_idle(Some(0))
        // Fail fast when the pool is exhausted/DB is stalled: each waiting `spawn_blocking`
        // thread is a scarce resource; 30s (the r2d2 default) of queued waiters under load is
        // how a database stall becomes a full-service stall.
        .connection_timeout(std::time::Duration::from_secs(5))
        .build_unchecked(manager))
}
