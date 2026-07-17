//! `sentinel-api` — PostgreSQL-backed stores and the HTTP authentication API for Sentinel.
//! The security decisions live in `auth-core`; this crate supplies storage (with
//! DB-enforced atomicity, ADR-0006) and transport.

#![forbid(unsafe_code)]

pub mod http;
pub mod pgstore;

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
    let manager = r2d2_postgres::PostgresConnectionManager::new(
        database_url.parse()?,
        r2d2_postgres::postgres::NoTls,
    );
    Ok(r2d2::Pool::builder()
        .max_size(max_size)
        .min_idle(Some(0))
        .build_unchecked(manager))
}
