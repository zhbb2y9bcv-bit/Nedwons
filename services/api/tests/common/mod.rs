// Each test binary compiles this module independently, so helpers used by only one binary
// are "dead" in the others — a false positive inherent to shared test modules.
#![allow(dead_code)]

//! Shared helpers for the Postgres-backed integration tests.
//!
//! These tests require a running PostgreSQL with a test database:
//!   `TEST_DATABASE_URL` (default `postgres://localhost/sentinel_test`).
//! They use randomized usernames instead of truncation so parallel tests and repeated
//! runs never collide, and they run real migrations (idempotent via refinery).

use std::sync::Arc;

use auth_core::memstore::SystemClock;
use auth_core::transcript::{Action, Transcript};
use auth_core::{AuthService, Config, RegisterRequest, Session};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use sentinel_api::pgstore::PgStores;

pub const PASSWORD: &str = "battery staple orbit lantern";

pub fn db_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/sentinel_test".to_string())
}

/// Parallel tests must not race refinery's schema-history bootstrap: run migrations
/// exactly once per test process (Once blocks the other callers until done).
pub fn migrate_once(url: &str) {
    static MIGRATE: std::sync::Once = std::sync::Once::new();
    MIGRATE.call_once(|| {
        sentinel_api::run_migrations(url).expect(
            "migrations require a running PostgreSQL with the sentinel_test database \
             (TEST_DATABASE_URL)",
        );
    });
}

/// Process-lifetime shared stores. Never dropped, deliberately: the sync `postgres`
/// client's Drop runs `block_on`, which panics if the last pool handle is released inside
/// an async context (as at the end of a #[tokio::test]). A OnceLock keeps one handle alive
/// for the whole test process, so per-test drops are never the last.
pub fn shared_stores() -> Arc<PgStores> {
    static STORES: std::sync::OnceLock<Arc<PgStores>> = std::sync::OnceLock::new();
    STORES
        .get_or_init(|| {
            let url = db_url();
            migrate_once(&url);
            Arc::new(PgStores::new(
                sentinel_api::build_pool(&url, 24).expect("pool"),
            ))
        })
        .clone()
}

/// Migrated PgStores handle + AuthService over it.
pub fn setup() -> (Arc<PgStores>, AuthService) {
    let stores = shared_stores();
    let service = AuthService::new(
        stores.clone(),
        stores.clone(),
        stores.clone(),
        stores.clone(),
        stores.clone(),
        Arc::new(SystemClock),
        Config::default(),
    );
    (stores, service)
}

/// Random username, unique per call, satisfying the normalization policy.
pub fn unique_username(prefix: &str) -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}{suffix}")
}

/// A test stand-in for a device: holds the private key (Secure Enclave in production).
pub struct TestDevice {
    signing_key: SigningKey,
    pub public_key: Vec<u8>,
}

impl TestDevice {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }
}

/// Register a fresh account through the service; returns the device and its session.
pub fn register(service: &AuthService, username: &str) -> (TestDevice, Session) {
    let device = TestDevice::new();
    let challenge = service.register_begin().expect("register_begin");
    let transcript = Transcript {
        action: Action::Register,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());
    let session = service
        .register_finish(RegisterRequest {
            username: username.to_string(),
            password: PASSWORD.to_string(),
            device_public_key: device.public_key.clone(),
            txn_id: challenge.txn_id,
            signature,
        })
        .expect("registration should succeed");
    (device, session)
}
