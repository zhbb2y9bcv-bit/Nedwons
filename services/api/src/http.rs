//! The HTTP authentication API. Design rules (SECURITY.md, THREAT_MODEL.md):
//!
//! * Strict schemas: `deny_unknown_fields`, exact hex lengths, small body limit.
//! * Generic external errors: security failures are `401 {"error":"denied"}` with no
//!   detail; storage faults are `500 {"error":"internal"}`. Client-correctable input
//!   problems (username shape, weak password) are the only specific messages.
//! * CPU-bound security work (Argon2, ECDSA) runs in `spawn_blocking`.
//! * Per-IP rate limiting (GCRA via `governor`) on all `/v1` routes. Behind a proxy, the
//!   real client IP must come from a *trusted* forwarded header configured at the ingress —
//!   never from a client-controlled header (ABUSE_MODEL.md).
//! * No request/response bodies are logged on any auth endpoint (INV-8).
//! * Transport security: production terminates TLS 1.3 in front of this service; the dev
//!   default binds 127.0.0.1 only. There is no TLS code here to get wrong.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use auth_core::ids::TxnId;
use auth_core::{AuthError, AuthService, RegisterRequest};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Maximum request body accepted on any auth endpoint.
const MAX_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<AuthService>,
    limiter: Arc<IpLimiter>,
}

/// Requests allowed per minute per client IP on `/v1` routes.
pub fn build_router(service: Arc<AuthService>, per_ip_per_minute: u32) -> Router {
    let quota =
        Quota::per_minute(NonZeroU32::new(per_ip_per_minute.max(1)).expect("max(1) is non-zero"));
    let state = AppState {
        service,
        limiter: Arc::new(RateLimiter::keyed(quota)),
    };

    Router::new()
        .route("/v1/register/begin", post(register_begin))
        .route("/v1/register/finish", post(register_finish))
        .route("/v1/login/begin", post(login_begin))
        .route("/v1/login/finish", post(login_finish))
        .route("/v1/session/refresh", post(refresh))
        .route("/v1/session/logout", post(logout))
        .route("/v1/session/whoami", get(whoami))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

// ----- errors -------------------------------------------------------------------------

/// External error shape. Deliberately generic (enumeration resistance / fail closed).
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Denied => ApiError(StatusCode::UNAUTHORIZED, "denied"),
            AuthError::UsernameUnavailable => {
                ApiError(StatusCode::CONFLICT, "username_unavailable")
            }
            AuthError::InvalidInput => ApiError(StatusCode::BAD_REQUEST, "invalid_input"),
            AuthError::WeakPassword => ApiError(StatusCode::BAD_REQUEST, "weak_password"),
            AuthError::Internal => ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

fn bad_request() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_input")
}

fn internal() -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

// ----- rate limiting ------------------------------------------------------------------

async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // ConnectInfo is present when served via into_make_service_with_connect_info (the
    // production path in main.rs). In-process tests without a socket share one bucket.
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    if state.limiter.check_key(&ip).is_err() {
        return ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
    }
    next.run(request).await
}

// ----- hex helpers ---------------------------------------------------------------------

/// Decode a hex field, enforcing the exact expected byte length (size-bounded inputs).
fn hex_exact(input: &str, expected_bytes: usize) -> Result<Vec<u8>, ApiError> {
    if input.len() != expected_bytes * 2 {
        return Err(bad_request());
    }
    hex::decode(input).map_err(|_| bad_request())
}

fn txn_from_hex(input: &str) -> Result<TxnId, ApiError> {
    let bytes = hex_exact(input, 16)?;
    let arr: [u8; 16] = bytes.try_into().map_err(|_| bad_request())?;
    Ok(TxnId(arr))
}

// ----- DTOs ----------------------------------------------------------------------------

#[derive(Serialize)]
struct ChallengeDto {
    account_id: String,
    device_id: String,
    txn_id: String,
    nonce: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct SessionDto {
    account_id: String,
    device_id: String,
    access_token: String,
    access_expires_at: u64,
    refresh_token: String,
    refresh_expires_at: u64,
}

impl From<auth_core::Session> for SessionDto {
    fn from(s: auth_core::Session) -> Self {
        Self {
            account_id: hex::encode(s.account_id.as_bytes()),
            device_id: hex::encode(s.device_id.as_bytes()),
            access_token: hex::encode(&s.access_token),
            access_expires_at: s.access_expires_at,
            refresh_token: hex::encode(&s.refresh_token),
            refresh_expires_at: s.refresh_expires_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinishBody {
    username: String,
    password: String,
    /// SEC1 uncompressed P-256 public key (65 bytes → 130 hex chars).
    device_public_key: String,
    txn_id: String,
    /// Raw 64-byte ECDSA signature (128 hex chars).
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBeginBody {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishBody {
    txn_id: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshBody {
    refresh_token: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutBody {
    refresh_token: String,
}

#[derive(Serialize)]
struct WhoamiDto {
    account_id: String,
    device_id: String,
}

// ----- handlers ------------------------------------------------------------------------

/// Run a blocking closure on the blocking pool, failing closed if the task is cancelled.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, AuthError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| internal())?
        .map_err(ApiError::from)
}

async fn register_begin(State(state): State<AppState>) -> Result<Json<ChallengeDto>, ApiError> {
    let service = state.service.clone();
    let c = blocking(move || service.register_begin()).await?;
    Ok(Json(ChallengeDto {
        account_id: hex::encode(c.account_id.as_bytes()),
        device_id: hex::encode(c.device_id.as_bytes()),
        txn_id: hex::encode(c.txn_id.as_bytes()),
        nonce: hex::encode(c.nonce),
        expires_at: c.expires_at,
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Json(body): Json<RegisterFinishBody>,
) -> Result<Json<SessionDto>, ApiError> {
    // Pre-normalization size caps; detailed policy checks live in auth-core.
    if body.username.len() > 64 || body.password.len() > 1024 {
        return Err(bad_request());
    }
    let device_public_key = hex_exact(&body.device_public_key, 65)?;
    let txn_id = txn_from_hex(&body.txn_id)?;
    let signature = hex_exact(&body.signature, 64)?;

    let service = state.service.clone();
    let session = blocking(move || {
        service.register_finish(RegisterRequest {
            username: body.username,
            password: body.password,
            device_public_key,
            txn_id,
            signature,
        })
    })
    .await?;
    Ok(Json(session.into()))
}

async fn login_begin(
    State(state): State<AppState>,
    Json(body): Json<LoginBeginBody>,
) -> Result<Json<ChallengeDto>, ApiError> {
    if body.username.len() > 64 || body.password.len() > 1024 {
        return Err(bad_request());
    }
    let service = state.service.clone();
    // login_begin is infallible by design: bad credentials still produce a decoy challenge.
    let c =
        tokio::task::spawn_blocking(move || service.login_begin(&body.username, &body.password))
            .await
            .map_err(|_| internal())?;
    Ok(Json(ChallengeDto {
        account_id: hex::encode(c.account_id.as_bytes()),
        device_id: hex::encode(c.device_id.as_bytes()),
        txn_id: hex::encode(c.txn_id.as_bytes()),
        nonce: hex::encode(c.nonce),
        expires_at: c.expires_at,
    }))
}

async fn login_finish(
    State(state): State<AppState>,
    Json(body): Json<LoginFinishBody>,
) -> Result<Json<SessionDto>, ApiError> {
    let txn_id = txn_from_hex(&body.txn_id)?;
    let signature = hex_exact(&body.signature, 64)?;
    let service = state.service.clone();
    let session = blocking(move || service.login_finish(&txn_id, &signature)).await?;
    Ok(Json(session.into()))
}

async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshBody>,
) -> Result<Json<SessionDto>, ApiError> {
    let refresh_token = hex_exact(&body.refresh_token, 32)?;
    let signature = hex_exact(&body.signature, 64)?;
    let service = state.service.clone();
    let session = blocking(move || service.refresh(&refresh_token, &signature)).await?;
    Ok(Json(session.into()))
}

async fn logout(
    State(state): State<AppState>,
    Json(body): Json<LogoutBody>,
) -> Result<StatusCode, ApiError> {
    let refresh_token = hex_exact(&body.refresh_token, 32)?;
    let service = state.service.clone();
    blocking(move || service.logout(&refresh_token)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn whoami(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<WhoamiDto>, ApiError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "denied"))?;
    let access_token =
        hex_exact(bearer, 32).map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "denied"))?;

    let service = state.service.clone();
    let who = blocking(move || service.validate_access(&access_token)).await?;
    Ok(Json(WhoamiDto {
        account_id: hex::encode(who.account_id.as_bytes()),
        device_id: hex::encode(who.device_id.as_bytes()),
    }))
}
