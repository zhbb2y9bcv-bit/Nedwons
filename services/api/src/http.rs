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

use auth_core::ids::{AccountId, DeviceId, TxnId};
use auth_core::store::AccountDevice;
use auth_core::{AuthError, AuthService, RegisterRequest};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;

use crate::notify::DeliveryNotifier;
use crate::relay::{FanoutOutcome, PgRelay};
use crate::social::{FriendRequestOutcome, PgSocial};

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Maximum request body on auth endpoints. Message envelopes may be larger (attachments
/// are chunked separately), so the relay routes get their own higher cap.
const MAX_BODY_BYTES: usize = 8 * 1024;
const MAX_RELAY_BODY_BYTES: usize = 256 * 1024;

/// Upper bound on inbox long-poll wait, so a client cannot hold a request open forever.
const MAX_INBOX_WAIT_SECS: u64 = 30;

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<AuthService>,
    pub relay: Arc<PgRelay>,
    pub social: Arc<PgSocial>,
    notifier: DeliveryNotifier,
    limiter: Arc<IpLimiter>,
}

/// Requests allowed per minute per client IP on `/v1` routes.
pub fn build_router(
    service: Arc<AuthService>,
    relay: Arc<PgRelay>,
    social: Arc<PgSocial>,
    per_ip_per_minute: u32,
) -> Router {
    let quota =
        Quota::per_minute(NonZeroU32::new(per_ip_per_minute.max(1)).expect("max(1) is non-zero"));
    let state = AppState {
        service,
        relay,
        social,
        notifier: DeliveryNotifier::default(),
        limiter: Arc::new(RateLimiter::keyed(quota)),
    };

    // Relay routes accept larger bodies (opaque envelopes) than auth routes.
    let relay_routes = Router::new()
        .route("/v1/keypackages", post(publish_key_package))
        .route("/v1/keypackages/claim", post(claim_key_package))
        .route("/v1/conversations", post(create_conversation))
        .route("/v1/conversations/{id}/members", post(add_member))
        .route("/v1/conversations/{id}/messages", post(send_message))
        .route("/v1/conversations/{id}/welcome", post(send_welcome))
        .route("/v1/inbox", get(fetch_inbox))
        .route("/v1/inbox/ack", post(ack_inbox))
        .route("/v1/stream", get(stream_handler))
        // profiles & social
        .route("/v1/profile", get(get_my_profile).put(update_profile))
        .route("/v1/profile/{account_id}", get(get_profile_by_id))
        .route("/v1/profiles/search", get(search_profiles))
        .route("/v1/friends", get(list_friends))
        .route("/v1/friends/requests", get(list_friend_requests))
        .route("/v1/friends/request", post(friend_request))
        .route("/v1/friends/accept", post(friend_accept))
        .route("/v1/friends/decline", post(friend_decline))
        .route("/v1/friends/remove", post(friend_remove))
        .route("/v1/groups", post(create_group))
        .layer(RequestBodyLimitLayer::new(MAX_RELAY_BODY_BYTES));

    Router::new()
        .route("/v1/register/begin", post(register_begin))
        .route("/v1/register/finish", post(register_finish))
        .route("/v1/login/begin", post(login_begin))
        .route("/v1/login/finish", post(login_finish))
        .route("/v1/session/refresh", post(refresh))
        .route("/v1/session/logout", post(logout))
        .route("/v1/session/whoami", get(whoami))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .merge(relay_routes)
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
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

fn forbidden() -> ApiError {
    // The relay uses a generic 403 for "not a member" so it does not confirm a
    // conversation's existence or membership to non-members.
    ApiError(StatusCode::FORBIDDEN, "forbidden")
}

impl From<auth_core::store::StoreError> for ApiError {
    fn from(_: auth_core::store::StoreError) -> Self {
        internal()
    }
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
    Ok(TxnId(id16_from_hex(input)?))
}

fn id16_from_hex(input: &str) -> Result<[u8; 16], ApiError> {
    let bytes = hex_exact(input, 16)?;
    bytes.try_into().map_err(|_| bad_request())
}

/// Authenticate the caller from the `Authorization: Bearer <access-token hex>` header,
/// returning the bound account/device. Any failure is a generic 401.
async fn authed_device(state: &AppState, headers: &HeaderMap) -> Result<AccountDevice, ApiError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "denied"))?;
    let access_token =
        hex_exact(bearer, 32).map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "denied"))?;
    let service = state.service.clone();
    blocking(move || service.validate_access(&access_token)).await
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
    headers: HeaderMap,
) -> Result<Json<WhoamiDto>, ApiError> {
    let who = authed_device(&state, &headers).await?;
    Ok(Json(WhoamiDto {
        account_id: hex::encode(who.account_id.as_bytes()),
        device_id: hex::encode(who.device_id.as_bytes()),
    }))
}

// ----- relay (E2EE message routing; server never decrypts) ----------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishKeyPackageBody {
    /// TLS-serialized MLS key package (opaque to the server).
    key_package: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimKeyPackageBody {
    account_id: String,
}

#[derive(Serialize)]
struct ClaimedKeyPackageDto {
    device_id: String,
    key_package: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddMemberBody {
    account_id: String,
}

#[derive(Serialize)]
struct ConversationDto {
    conversation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendMessageBody {
    /// Opaque MLS application ciphertext (hex) — ONE ciphertext the whole group decrypts.
    ciphertext: String,
    /// 16-byte client-chosen idempotency key (hex); a retry with the same key is a no-op.
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendWelcomeBody {
    /// The joining member's device (routing target for the MLS Welcome).
    recipient_device: String,
    ciphertext: String,
    idempotency_key: String,
}

#[derive(Serialize)]
struct FanoutReceiptDto {
    /// Number of recipient devices the ciphertext was newly queued for (0 on an idempotent
    /// retry). Delivery to the server, NOT a decryption claim.
    delivered: usize,
}

#[derive(Serialize)]
struct ReceiptDto {
    envelope_id: i64,
}

#[derive(Serialize)]
struct InboxEnvelopeDto {
    id: i64,
    conversation_id: String,
    sender_device: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct InboxQuery {
    /// Long-poll: seconds to wait for new mail before returning empty (0 = return now).
    #[serde(default)]
    wait: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    /// Envelope ids the client has durably persisted and no longer needs served.
    ids: Vec<i64>,
}

/// Publish a key package for the authenticated device.
async fn publish_key_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PublishKeyPackageBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    if body.key_package.is_empty() || body.key_package.len() > MAX_RELAY_BODY_BYTES {
        return Err(bad_request());
    }
    let key_package = hex::decode(&body.key_package).map_err(|_| bad_request())?;
    let relay = state.relay.clone();
    blocking_store(move || relay.publish_key_package(me.account_id, me.device_id, &key_package))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Claim one key package for a target account's device (to add them to a group).
async fn claim_key_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ClaimKeyPackageBody>,
) -> Result<Json<ClaimedKeyPackageDto>, ApiError> {
    let _me = authed_device(&state, &headers).await?;
    let account = AccountId(id16_from_hex(&body.account_id)?);
    let relay = state.relay.clone();
    let claimed = blocking_store(move || relay.claim_key_package(&account))
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no_key_package"))?;
    Ok(Json(ClaimedKeyPackageDto {
        device_id: hex::encode(claimed.device_id),
        key_package: hex::encode(claimed.key_package),
    }))
}

/// Create a conversation with the authenticated device as the first member.
async fn create_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ConversationDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = auth_core::crypto::random_bytes::<16>();
    let relay = state.relay.clone();
    blocking_store(move || relay.create_conversation(conversation_id, me.account_id, me.device_id))
        .await?;
    Ok(Json(ConversationDto {
        conversation_id: hex::encode(conversation_id),
    }))
}

/// Add a target account's active device to a conversation's routing membership. The caller
/// must already be a member.
async fn add_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<AddMemberBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let target_account = AccountId(id16_from_hex(&body.account_id)?);

    let relay = state.relay.clone();
    let service = state.service.clone();
    blocking_store(move || {
        if !relay.is_member(&conversation_id, &me.device_id)? {
            // Non-members cannot learn anything; a store-level error maps to 500, so we
            // signal "not a member" out of band below.
            return Ok(None);
        }
        // Resolve the target's active device (server-side authority, never client-asserted).
        let device = service
            .active_device(&target_account)
            .map_err(|_| auth_core::store::StoreError("device lookup".into()))?;
        match device {
            Some(device_id) => {
                relay.add_member(&conversation_id, target_account, device_id)?;
                Ok(Some(()))
            }
            None => Ok(Some(())), // no active device: nothing to route to (still success)
        }
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Send an MLS application message: ONE ciphertext, fanned out server-side to every other
/// member device in a single round trip (the client uploads once, not once per recipient).
/// Idempotent per `idempotency_key`.
async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<SendMessageBody>,
) -> Result<Json<FanoutReceiptDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let idempotency_key = id16_from_hex(&body.idempotency_key)?;
    let ciphertext = decode_ciphertext(&body.ciphertext)?;

    let relay = state.relay.clone();
    let outcome = blocking_store(move || {
        relay.fanout_message(
            &conversation_id,
            &me.device_id,
            &ciphertext,
            &idempotency_key,
        )
    })
    .await?;
    match outcome {
        FanoutOutcome::Forbidden => Err(forbidden()),
        FanoutOutcome::Delivered { newly_queued } => {
            // Wake any long-poll waiters for the recipients that just got mail.
            for device in &newly_queued {
                state.notifier.wake(device);
            }
            Ok(Json(FanoutReceiptDto {
                delivered: newly_queued.len(),
            }))
        }
    }
}

/// Send a targeted MLS Welcome to a specific joining device. Idempotent.
async fn send_welcome(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<SendWelcomeBody>,
) -> Result<Json<ReceiptDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let recipient = DeviceId(id16_from_hex(&body.recipient_device)?);
    let idempotency_key = id16_from_hex(&body.idempotency_key)?;
    let ciphertext = decode_ciphertext(&body.ciphertext)?;

    let relay = state.relay.clone();
    let recipient_bytes = recipient.0;
    let envelope_id = blocking_store(move || {
        relay.send_targeted(
            &conversation_id,
            &me.device_id,
            &recipient,
            &ciphertext,
            &idempotency_key,
        )
    })
    .await?
    .ok_or_else(forbidden)?;
    state.notifier.wake(&recipient_bytes);
    Ok(Json(ReceiptDto { envelope_id }))
}

/// Peek the authenticated device's queued envelopes (does NOT mark delivered — the client
/// acks via `/v1/inbox/ack` after persisting, giving at-least-once delivery). With `?wait=N`
/// this long-polls: it returns immediately if mail is present, otherwise parks until mail
/// arrives (woken by a send) or `N` seconds elapse — near-zero idle delivery latency without
/// burning a database connection while waiting.
async fn fetch_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<InboxQuery>,
) -> Result<Json<Vec<InboxEnvelopeDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let device = me.device_id.0;

    // Register interest BEFORE the first read to avoid a lost-wakeup window.
    let notified = state.notifier.handle(&device);
    let mut envelopes = read_inbox(&state, me.device_id).await?;

    if envelopes.is_empty() && query.wait > 0 {
        let wait = std::time::Duration::from_secs(query.wait.min(MAX_INBOX_WAIT_SECS));
        tokio::select! {
            _ = notified.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
        envelopes = read_inbox(&state, me.device_id).await?;
    }

    Ok(Json(
        envelopes
            .into_iter()
            .map(|e| InboxEnvelopeDto {
                id: e.id,
                conversation_id: hex::encode(e.conversation_id),
                sender_device: hex::encode(e.sender_device),
                ciphertext: hex::encode(e.ciphertext),
            })
            .collect(),
    ))
}

/// Acknowledge durably-persisted envelopes so the server can purge them. At-least-once: a
/// client peeks, persists locally, then acks; a crash before ack just re-peeks (dedup by id).
async fn ack_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    if body.ids.len() > 1000 {
        return Err(bad_request());
    }
    let relay = state.relay.clone();
    blocking_store(move || relay.ack_envelopes(&me.device_id, &body.ids)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn read_inbox(
    state: &AppState,
    device_id: DeviceId,
) -> Result<Vec<crate::relay::EnvelopeOut>, ApiError> {
    let relay = state.relay.clone();
    // Peek (do NOT mark delivered); the client acks after persisting (at-least-once).
    blocking_store(move || relay.peek_inbox(&device_id, 100)).await
}

// ----- WebSocket streaming delivery ---------------------------------------------------

#[derive(Serialize)]
struct StreamPush {
    envelopes: Vec<InboxEnvelopeDto>,
}

#[derive(Deserialize)]
struct StreamAck {
    #[serde(default)]
    ack: Vec<i64>,
}

/// Authenticated WebSocket push channel: `GET /v1/stream` with `Authorization: Bearer
/// <access-token hex>` on the upgrade request. The server pushes new envelopes the instant
/// they arrive (woken by the same `DeliveryNotifier` as long-poll — sub-100 ms, no polling)
/// and the client acks over the same socket. Same at-least-once semantics as HTTP: unacked
/// envelopes are re-delivered on reconnect.
async fn stream_handler(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // Authenticate BEFORE upgrading, so an unauthenticated client gets a clean 401.
    let me = match authed_device(&state, &headers).await {
        Ok(me) => me,
        Err(e) => return e.into_response(),
    };
    ws.on_upgrade(move |socket| stream_socket(socket, state, me))
}

async fn stream_socket(
    mut socket: axum::extract::ws::WebSocket,
    state: AppState,
    me: AccountDevice,
) {
    use axum::extract::ws::Message;

    let device = me.device_id;
    let notify = state.notifier.handle(&device.0);
    // Only push envelopes newer than what we've already sent this session; unacked ones are
    // re-served from the DB on reconnect (last_sent resets to 0).
    let mut last_sent: i64 = 0;
    let heartbeat = std::time::Duration::from_secs(30);

    loop {
        // Deliver anything pending and not yet pushed this session.
        match read_inbox(&state, device).await {
            Ok(pending) => {
                let fresh: Vec<InboxEnvelopeDto> = pending
                    .into_iter()
                    .filter(|e| e.id > last_sent)
                    .map(|e| InboxEnvelopeDto {
                        id: e.id,
                        conversation_id: hex::encode(e.conversation_id),
                        sender_device: hex::encode(e.sender_device),
                        ciphertext: hex::encode(e.ciphertext),
                    })
                    .collect();
                if let Some(max_id) = fresh.iter().map(|e| e.id).max() {
                    last_sent = max_id;
                    let payload = serde_json::to_string(&StreamPush { envelopes: fresh })
                        .unwrap_or_else(|_| "{\"envelopes\":[]}".to_string());
                    if socket.send(Message::Text(payload.into())).await.is_err() {
                        return; // client gone
                    }
                }
            }
            Err(_) => return, // storage fault: drop the connection, client reconnects
        }

        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(StreamAck { ack }) = serde_json::from_str::<StreamAck>(&text) {
                            if !ack.is_empty() && ack.len() <= 1000 {
                                let relay = state.relay.clone();
                                let _ = blocking_store(move || relay.ack_envelopes(&device, &ack)).await;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                    _ => {}
                }
            }
            _ = notify.notified() => { /* new mail: loop to deliver */ }
            _ = tokio::time::sleep(heartbeat) => {
                // Liveness probe; a dead peer surfaces as a send error next cycle.
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn decode_ciphertext(hex_str: &str) -> Result<Vec<u8>, ApiError> {
    if hex_str.is_empty() || hex_str.len() > MAX_RELAY_BODY_BYTES {
        return Err(bad_request());
    }
    hex::decode(hex_str).map_err(|_| bad_request())
}

// ----- profiles, friends, and clique-gated groups -------------------------------------

const MAX_GROUP_MEMBERS: usize = 256;
const MIN_SEARCH_CHARS: usize = 2;

#[derive(Serialize)]
struct ProfileDto {
    account_id: String,
    username: String,
    display_name: String,
    bio: String,
}

#[derive(Serialize)]
struct ProfileSummaryDto {
    account_id: String,
    username: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateProfileBody {
    display_name: String,
    bio: String,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRefBody {
    account_id: String,
}

#[derive(Serialize)]
struct FriendActionDto {
    status: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGroupBody {
    member_account_ids: Vec<String>,
}

#[derive(Serialize)]
struct GroupDto {
    conversation_id: String,
    member_account_ids: Vec<String>,
}

fn profile_dto(p: crate::social::Profile) -> ProfileDto {
    ProfileDto {
        account_id: hex::encode(p.account_id),
        username: p.username,
        display_name: p.display_name,
        bio: p.bio,
    }
}

fn summary_dto(s: crate::social::ProfileSummary) -> ProfileSummaryDto {
    ProfileSummaryDto {
        account_id: hex::encode(s.account_id),
        username: s.username,
        display_name: s.display_name,
    }
}

async fn get_my_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProfileDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let social = state.social.clone();
    let profile = blocking_store(move || social.get_profile(&me.account_id))
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    Ok(Json(profile_dto(profile)))
}

async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateProfileBody>,
) -> Result<StatusCode, ApiError> {
    if body.display_name.chars().count() > 64 || body.bio.chars().count() > 256 {
        return Err(bad_request());
    }
    let me = authed_device(&state, &headers).await?;
    let social = state.social.clone();
    blocking_store(move || social.upsert_profile(&me.account_id, &body.display_name, &body.bio))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_profile_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_hex): Path<String>,
) -> Result<Json<ProfileDto>, ApiError> {
    let _me = authed_device(&state, &headers).await?;
    let account = AccountId(id16_from_hex(&account_hex)?);
    let social = state.social.clone();
    let profile = blocking_store(move || social.get_profile(&account))
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    Ok(Json(profile_dto(profile)))
}

async fn search_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SearchQuery>,
) -> Result<Json<Vec<ProfileSummaryDto>>, ApiError> {
    let _me = authed_device(&state, &headers).await?;
    // Username search is over the normalized (lowercase) handle; require a minimum length so
    // this is deliberate discovery, not a bulk directory scan (ABUSE_MODEL.md).
    let q = query.q.trim().to_lowercase();
    if q.chars().count() < MIN_SEARCH_CHARS || q.len() > 64 {
        return Err(bad_request());
    }
    let social = state.social.clone();
    let results = blocking_store(move || social.search_profiles(&q, 20)).await?;
    Ok(Json(results.into_iter().map(summary_dto).collect()))
}

async fn list_friends(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileSummaryDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let social = state.social.clone();
    let friends = blocking_store(move || social.list_friends(&me.account_id)).await?;
    Ok(Json(friends.into_iter().map(summary_dto).collect()))
}

async fn list_friend_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileSummaryDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let social = state.social.clone();
    let reqs = blocking_store(move || social.list_incoming_requests(&me.account_id)).await?;
    Ok(Json(reqs.into_iter().map(summary_dto).collect()))
}

async fn friend_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountRefBody>,
) -> Result<Json<FriendActionDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    if target.0 == me.account_id.0 {
        return Err(bad_request());
    }
    let social = state.social.clone();
    let outcome =
        blocking_store(move || social.send_friend_request(&me.account_id, &target)).await?;
    let status = match outcome {
        FriendRequestOutcome::Requested => "requested",
        FriendRequestOutcome::Friended => "friended",
        FriendRequestOutcome::AlreadyFriends => "already_friends",
    };
    Ok(Json(FriendActionDto { status }))
}

async fn friend_accept(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let other = AccountId(id16_from_hex(&body.account_id)?);
    let social = state.social.clone();
    let accepted =
        blocking_store(move || social.accept_friend_request(&me.account_id, &other)).await?;
    if accepted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "no_request"))
    }
}

async fn friend_decline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let other = AccountId(id16_from_hex(&body.account_id)?);
    let social = state.social.clone();
    blocking_store(move || social.cancel_request(&me.account_id, &other)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn friend_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let other = AccountId(id16_from_hex(&body.account_id)?);
    let social = state.social.clone();
    blocking_store(move || social.remove_friend(&me.account_id, &other)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Create a group conversation — allowed ONLY if the creator and every listed member form a
/// complete mutual-friend clique (everyone has added everyone). Adds all members' active
/// devices to routing so the group's messages reach every person.
async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupBody>,
) -> Result<Json<GroupDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;

    // Parse + dedup members, excluding the creator (added automatically).
    let mut others: Vec<AccountId> = Vec::new();
    for id_hex in &body.member_account_ids {
        let account = AccountId(id16_from_hex(id_hex)?);
        if account.0 != me.account_id.0 && !others.iter().any(|a| a.0 == account.0) {
            others.push(account);
        }
    }
    if others.is_empty() || others.len() + 1 > MAX_GROUP_MEMBERS {
        return Err(bad_request());
    }

    // The full clique = creator + others.
    let mut all = vec![me.account_id];
    all.extend(others.iter().copied());

    let social = state.social.clone();
    let relay = state.relay.clone();
    let service = state.service.clone();
    let others_for_task = others.clone();
    let outcome = blocking_store(move || {
        // Gate: everyone must be mutually friends.
        if !social.all_mutually_friends(&all)? {
            return Ok(None);
        }
        let conversation_id = auth_core::crypto::random_bytes::<16>();
        relay.create_conversation(conversation_id, me.account_id, me.device_id)?;
        for member in &others_for_task {
            // Resolve each member's active device server-side (never client-asserted).
            if let Some(device) = service
                .active_device(member)
                .map_err(|_| auth_core::store::StoreError("device lookup".into()))?
            {
                relay.add_member(&conversation_id, *member, device)?;
            }
        }
        Ok(Some(conversation_id))
    })
    .await?;

    match outcome {
        None => Err(ApiError(StatusCode::FORBIDDEN, "not_all_friends")),
        Some(conversation_id) => Ok(Json(GroupDto {
            conversation_id: hex::encode(conversation_id),
            member_account_ids: others.iter().map(|a| hex::encode(a.0)).collect(),
        })),
    }
}

/// Like `blocking`, but for relay store calls that return `StoreResult`.
async fn blocking_store<T: Send + 'static>(
    f: impl FnOnce() -> auth_core::store::StoreResult<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| internal())?
        .map_err(ApiError::from)
}
