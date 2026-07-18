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
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;

use crate::groups::{InviteOutcome, PgGroups};
use crate::membership::{ApplyOutcome, CommitRequest, PgMembership};
use crate::notify::DeliveryNotifier;
use crate::relay::{FanoutOutcome, PgRelay, SelfGroupSendOutcome, SendOutcome};
use crate::social::{FriendRequestOutcome, PgSocial};
use crate::transparency::PgTransparency;

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
/// Per-recipient-device limiter for unauthenticated sealed delivery (ADR-0014): the sender is
/// unknown, so flooding is bounded by the *recipient* device instead.
type DeviceLimiter = RateLimiter<[u8; 16], DefaultKeyedStateStore<[u8; 16]>, DefaultClock>;

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
    pub groups: Arc<PgGroups>,
    pub transparency: Arc<PgTransparency>,
    pub membership: Arc<PgMembership>,
    notifier: DeliveryNotifier,
    limiter: Arc<IpLimiter>,
    /// When `Some(h)`, the client IP for rate limiting is taken from header `h` — which MUST be
    /// set by a trusted reverse proxy. When `None`, the peer socket IP is used and any such header
    /// is ignored, so a client cannot spoof its IP. See [`build_router_cfg`].
    trusted_ip_header: Option<HeaderName>,
    /// When true, every request bearing an `Authorization` token must also carry a valid
    /// DPoP-style device proof (ADR-0011, R-308). Off by default during migration.
    require_proof: bool,
    proof_cache: Arc<crate::proof::ProofReplayCache>,
    /// Sealed-sender **sender-certificate** signing key (ADR-0012, R-204). Loaded from
    /// `SENTINEL_SENDER_CERT_KEY` (hex) or ephemeral (dev). Distinct from the auth/transparency
    /// keys. Its public key is returned with issued certificates; production clients pin it.
    sender_cert_key: Arc<p256::ecdsa::SigningKey>,
    /// Per-recipient-device rate limiter for the unauthenticated sealed-delivery endpoint
    /// (ADR-0014). Bounds flooding when the sender is unknown.
    sealed_limiter: Arc<DeviceLimiter>,
}

/// Load the sender-certificate signing key from `SENTINEL_SENDER_CERT_KEY` (hex), or generate an
/// ephemeral one (dev — a restart rotates it, invalidating in-flight certs, which is fine as they
/// are short-lived).
fn load_or_generate_sender_cert_key() -> p256::ecdsa::SigningKey {
    if let Ok(hex_key) = std::env::var("SENTINEL_SENDER_CERT_KEY") {
        if let Ok(bytes) = hex::decode(hex_key.trim()) {
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&bytes) {
                return key;
            }
        }
        tracing::error!("SENTINEL_SENDER_CERT_KEY is set but invalid; using an ephemeral key");
    }
    p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
}

/// Build the router with per-IP rate limiting keyed on the **peer** socket IP (correct when the
/// service is directly exposed or in tests). Behind a proxy, use [`build_router_cfg`].
#[allow(clippy::too_many_arguments)]
pub fn build_router(
    service: Arc<AuthService>,
    relay: Arc<PgRelay>,
    social: Arc<PgSocial>,
    groups: Arc<PgGroups>,
    transparency: Arc<PgTransparency>,
    membership: Arc<PgMembership>,
    per_ip_per_minute: u32,
) -> Router {
    build_router_cfg(
        service,
        relay,
        social,
        groups,
        transparency,
        membership,
        per_ip_per_minute,
        None,
        false,
    )
}

/// As [`build_router`], but `trusted_ip_header` selects where the client IP comes from for rate
/// limiting.
///
/// - `None` (default): use the peer socket IP; **ignore** any forwarded header (a client cannot
///   spoof its address).
/// - `Some(header)`: read the client IP from `header`, which MUST be overwritten on every request
///   by a trusted reverse proxy that sets it to the single real client IP (e.g. nginx
///   `proxy_set_header X-Real-Client-IP $remote_addr;`, or Cloudflare `CF-Connecting-IP`). The
///   value must be one IP address; a multi-value / malformed header falls back to the peer IP
///   (fail safe — still limited, just by the proxy). **Only enable this behind such a proxy**
///   (ABUSE_MODEL.md, RISK_REGISTER R-306) — otherwise clients could forge the header to evade
///   per-IP limits.
#[allow(clippy::too_many_arguments)]
pub fn build_router_cfg(
    service: Arc<AuthService>,
    relay: Arc<PgRelay>,
    social: Arc<PgSocial>,
    groups: Arc<PgGroups>,
    transparency: Arc<PgTransparency>,
    membership: Arc<PgMembership>,
    per_ip_per_minute: u32,
    trusted_ip_header: Option<HeaderName>,
    require_proof: bool,
) -> Router {
    let quota =
        Quota::per_minute(NonZeroU32::new(per_ip_per_minute.max(1)).expect("max(1) is non-zero"));
    let state = AppState {
        service,
        relay,
        social,
        groups,
        transparency,
        membership,
        notifier: DeliveryNotifier::default(),
        limiter: Arc::new(RateLimiter::keyed(quota)),
        trusted_ip_header,
        require_proof,
        proof_cache: Arc::new(crate::proof::ProofReplayCache::new()),
        sender_cert_key: Arc::new(load_or_generate_sender_cert_key()),
        // Reuse the per-IP quota for the per-recipient sealed-delivery cap.
        sealed_limiter: Arc::new(RateLimiter::keyed(quota)),
    };

    // Relay routes accept larger bodies (opaque envelopes) than auth routes.
    let relay_routes = Router::new()
        .route("/v1/keypackages", post(publish_key_package))
        .route("/v1/keypackages/claim", post(claim_key_package))
        .route("/v1/keypackages/count", get(key_package_count))
        // Device self-group (ADR-0015 option 3): establish + use the account's own-devices MLS group.
        .route("/v1/self-group/register", post(self_group_register))
        .route("/v1/self-group/pending", get(self_group_pending))
        .route(
            "/v1/self-group/keypackage/claim",
            post(self_group_claim_key_package),
        )
        .route("/v1/self-group/deliver", post(self_group_deliver))
        // sealed-sender certificate issuance (ADR-0012, R-204)
        .route("/v1/sender-certificate", get(issue_sender_certificate))
        // sealed-sender delivery access key registration (ADR-0014 Slice 2a, R-204)
        .route("/v1/delivery-access-key", put(set_delivery_access_key))
        .route(
            "/v1/conversations",
            post(create_conversation).get(list_conversations),
        )
        .route("/v1/conversations/{id}/members", post(add_member))
        .route("/v1/conversations/{id}/members/remove", post(remove_member))
        .route("/v1/conversations/{id}/leave", post(leave_conversation))
        // MLS-commit-authoritative membership (ADR-0010): change membership with a signed
        // manifest + opaque commit; the epoch CAS linearizes membership history.
        .route("/v1/conversations/{id}/commit", post(membership_commit))
        .route("/v1/conversations/{id}/epoch", get(conversation_epoch))
        .route(
            "/v1/conversations/{id}/membership/{epoch}",
            get(membership_event),
        )
        // group governance (ADR-0009)
        .route(
            "/v1/conversations/{id}/invites",
            get(list_invites).post(create_invite),
        )
        .route("/v1/conversations/{id}/invites/revoke", post(revoke_invite))
        .route("/v1/invites/accept", post(accept_invite))
        .route("/v1/conversations/{id}/requests", get(list_join_requests))
        .route(
            "/v1/conversations/{id}/requests/approve",
            post(approve_join_request),
        )
        .route(
            "/v1/conversations/{id}/requests/deny",
            post(deny_join_request),
        )
        .route("/v1/conversations/{id}/admins", post(promote_admin))
        .route("/v1/conversations/{id}/admins/demote", post(demote_admin))
        .route("/v1/conversations/{id}/settings", post(update_settings))
        .route("/v1/conversations/{id}/messages", post(send_message))
        .route("/v1/conversations/{id}/welcome", post(send_welcome))
        .route("/v1/inbox", get(fetch_inbox))
        .route("/v1/inbox/ack", post(ack_inbox))
        .route("/v1/stream", get(stream_handler))
        // sealed-sender delivery (ADR-0014 Slice 2b, R-204): UNAUTHENTICATED — gated by the
        // recipient's delivery access key, not by a sender token.
        .route("/v1/sealed/deliver", post(deliver_sealed_handler))
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
        .route("/v1/blocks", get(list_blocked).post(block_user))
        .route("/v1/blocks/remove", post(unblock_user))
        .route("/v1/reports", post(create_report))
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
        // password change (device-signed + current-password): two stages
        .route("/v1/session/password/begin", post(password_change_begin))
        .route("/v1/session/password/finish", post(password_change_finish))
        // controlled multi-device (ADR-0008): enroll a new device via a trusted device, list, revoke
        .route("/v1/devices", get(list_devices_handler))
        .route("/v1/devices/enroll/begin", post(enroll_begin))
        .route("/v1/devices/enroll/finish", post(enroll_finish))
        .route("/v1/devices/revoke", post(revoke_device_handler))
        // account recovery (ADR-0003): set a recovery secret (authed), recover a lost account
        .route("/v1/recovery/set", post(set_recovery))
        .route("/v1/recover/begin", post(recover_begin_handler))
        .route("/v1/recover/finish", post(recover_finish_handler))
        // key transparency (R-201): the log is auditable; reads require a bearer token.
        .route("/v1/transparency/sth", get(transparency_sth))
        .route(
            "/v1/transparency/consistency",
            get(transparency_consistency),
        )
        .route(
            "/v1/transparency/account/{account_id}",
            get(transparency_account),
        )
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .merge(relay_routes)
        .layer(middleware::from_fn_with_state(state.clone(), proof_layer))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .route("/healthz", get(|| async { "ok" }))
        .layer(middleware::from_fn(security_headers))
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

fn idempotency_conflict() -> ApiError {
    // An idempotency key was reused with a different payload/conversation. The client must
    // retry with a fresh key; the original message under this key was not overwritten.
    ApiError(StatusCode::CONFLICT, "idempotency_conflict")
}

impl From<auth_core::store::StoreError> for ApiError {
    fn from(_: auth_core::store::StoreError) -> Self {
        internal()
    }
}

// ----- sender-constrained access tokens (DPoP-style, ADR-0011, R-308) -----------------

/// When enforcement is on, any request carrying an `Authorization` token must ALSO carry a valid
/// device proof binding the method + path + token + timestamp + a single-use nonce, signed by the
/// device's enrolled key. Requests without an `Authorization` header (register/login/refresh/
/// healthz) are untouched — the rule is precisely "a bearer token is only honored with proof of
/// possession of the enrolling key." Off by default during migration.
async fn proof_layer(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if state.require_proof && request.headers().contains_key(header::AUTHORIZATION) {
        // Extract owned inputs synchronously — never hold `&Request` across an `.await`, or the
        // middleware future stops being `Send` (Body is not `Sync`).
        let bearer = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let proof_hdr = request
            .headers()
            .get("x-sentinel-proof")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let method = request.method().as_str().as_bytes().to_vec();
        let path = request.uri().path().as_bytes().to_vec();
        if let Err(e) = verify_request_proof(&state, bearer, proof_hdr, method, path).await {
            return e.into_response();
        }
    }
    next.run(request).await
}

async fn verify_request_proof(
    state: &AppState,
    bearer: Option<String>,
    proof_hdr: Option<String>,
    method: Vec<u8>,
    path: Vec<u8>,
) -> Result<(), ApiError> {
    let denied = || ApiError(StatusCode::UNAUTHORIZED, "denied");
    let bearer = bearer.ok_or_else(denied)?;
    let access_token = hex_exact(&bearer, 32).map_err(|_| denied())?;
    let parsed = proof_hdr
        .as_deref()
        .and_then(crate::proof::parse_proof_header)
        .ok_or_else(denied)?;

    let token_hash = auth_core::crypto::sha256(&access_token);
    let now = now_unix();

    let proof = auth_core::request_proof::RequestProof {
        method: &method,
        path: &path,
        access_token_hash: &token_hash,
        timestamp: parsed.timestamp,
        nonce: &parsed.nonce,
    };
    // Cheap freshness gate before any DB work.
    if !proof.is_fresh(now) {
        return Err(denied());
    }

    // Resolve the token's device and its enrolled key, then verify the proof under that key.
    let service = state.service.clone();
    let token_for_lookup = access_token.clone();
    let account = blocking(move || service.validate_access(&token_for_lookup))
        .await
        .map_err(|_| denied())?;
    let service = state.service.clone();
    let device_id = account.device_id;
    let public_key = blocking(move || service.device_public_key(&device_id))
        .await
        .map_err(|_| denied())?;
    if !proof.verify(&public_key, &parsed.signature) {
        return Err(denied());
    }

    // Single-use within the freshness window (a valid proof cannot be replayed).
    if !state.proof_cache.check_and_record(
        &account.device_id.0,
        &parsed.nonce,
        now + auth_core::request_proof::MAX_SKEW_SECS + 5,
        now,
    ) {
        return Err(denied());
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ----- rate limiting ------------------------------------------------------------------

async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let ip = client_ip(&request, &state);
    if state.limiter.check_key(&ip).is_err() {
        return ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
    }
    next.run(request).await
}

/// The IP used for rate limiting. Prefers a *trusted* proxy header when configured, else the peer
/// socket IP. A client-supplied header is only honored when `trusted_ip_header` is set (operator
/// opt-in), so it can never be used to spoof an address in the default configuration.
fn client_ip(request: &Request, state: &AppState) -> IpAddr {
    if let Some(header) = &state.trusted_ip_header {
        if let Some(ip) = request
            .headers()
            .get(header)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
        // Header trusted but absent/malformed: fall back to the peer IP (still limited).
    }
    // ConnectInfo is present when served via into_make_service_with_connect_info (the production
    // path in main.rs). In-process tests without a socket share one bucket.
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

// ----- security headers ----------------------------------------------------------------

/// Add conservative security headers to every response (defense-in-depth; OWASP ASVS). This is a
/// JSON API, so a strict `default-src 'none'` CSP and `nosniff` prevent a browser from ever
/// interpreting a response as executable/framed content, and `no-store` keeps tokens/profiles out
/// of shared caches. HSTS is intentionally **not** set here — it belongs at the TLS-terminating
/// ingress, since this hop runs behind the proxy.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

// ----- key transparency (R-201) --------------------------------------------------------

#[derive(Serialize)]
struct SthDto {
    tree_size: u64,
    root_hash: String,
    timestamp: u64,
    /// ECDSA-P256 over encode_sth(tree_size, root, timestamp), 64-byte r‖s (hex).
    signature: String,
    /// The log's SEC1 public key (hex). Clients PIN this out of band; it is echoed for convenience.
    log_public_key: String,
}

async fn transparency_sth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SthDto>, ApiError> {
    let _ = authed_device(&state, &headers).await?;
    let transparency = state.transparency.clone();
    let sth = blocking_store(move || transparency.signed_tree_head()).await?;
    Ok(Json(SthDto {
        tree_size: sth.tree_size,
        root_hash: hex::encode(sth.root),
        timestamp: sth.timestamp,
        signature: hex::encode(sth.signature),
        log_public_key: hex::encode(state.transparency.log_public_key_sec1()),
    }))
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    first: u64,
    second: u64,
}

#[derive(Serialize)]
struct ConsistencyDto {
    proof: Vec<String>,
}

async fn transparency_consistency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsistencyQuery>,
) -> Result<Json<ConsistencyDto>, ApiError> {
    let _ = authed_device(&state, &headers).await?;
    let transparency = state.transparency.clone();
    let proof = blocking_store(move || transparency.consistency(q.first, q.second))
        .await?
        .ok_or_else(bad_request)?;
    Ok(Json(ConsistencyDto {
        proof: proof.iter().map(hex::encode).collect(),
    }))
}

#[derive(Serialize)]
struct AccountBindingDto {
    leaf_index: u64,
    device_id: String,
    public_key: String,
    /// The canonical leaf INPUT (hex); leaf hash = H(0x00 || entry).
    entry: String,
    proof: Vec<String>,
    /// Present (unix secs) only when this leaf is a **revocation** of `device_id` (ADR-0013). A
    /// client can flag a revocation of its own device it did not initiate. Omitted for bindings, so
    /// older clients that ignore the field are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<u64>,
}

#[derive(Serialize)]
struct AccountViewDto {
    tree_size: u64,
    bindings: Vec<AccountBindingDto>,
}

#[derive(Deserialize)]
struct AtSizeQuery {
    #[serde(default)]
    tree_size: Option<u64>,
}

async fn transparency_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_hex): Path<String>,
    Query(q): Query<AtSizeQuery>,
) -> Result<Json<AccountViewDto>, ApiError> {
    let _ = authed_device(&state, &headers).await?;
    let account = AccountId(id16_from_hex(&account_hex)?);
    let transparency = state.transparency.clone();
    let view = blocking_store(move || transparency.account_view(&account, q.tree_size)).await?;
    Ok(Json(AccountViewDto {
        tree_size: view.tree_size,
        bindings: view
            .bindings
            .into_iter()
            .map(|b| AccountBindingDto {
                leaf_index: b.leaf_index,
                device_id: hex::encode(b.device_id),
                public_key: hex::encode(b.public_key),
                entry: hex::encode(b.entry),
                proof: b.proof.iter().map(hex::encode).collect(),
                revoked_at: b.revoked_at,
            })
            .collect(),
    }))
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
    let public_key_for_log = device_public_key.clone();
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

    append_binding_best_effort(
        &state,
        session.account_id,
        session.device_id,
        public_key_for_log,
        "registration",
    )
    .await;
    Ok(Json(session.into()))
}

/// Publish an account→device-key binding to the transparency log (R-201). Best-effort: the CLIENT
/// self-monitors and is the real check, so a transient log fault must not block the user. A gap is
/// a monitorable error (production couples this atomically). Used at every point a device is bound
/// to an account — registration, trusted-device enrollment, and recovery — so a self-monitoring
/// client sees EVERY device the server routes for it (a server cannot add a device undetected;
/// ADR-0008).
async fn append_binding_best_effort(
    state: &AppState,
    account: AccountId,
    device: DeviceId,
    public_key: Vec<u8>,
    context: &'static str,
) {
    let transparency = state.transparency.clone();
    if blocking_store(move || transparency.append_binding(&account, &device, &public_key))
        .await
        .is_err()
    {
        tracing::error!("transparency log append failed at {context} (log gap — must reconcile)");
    }
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

// ----- password change (device-signed + current password) -----------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChangeFinishBody {
    txn_id: String,
    /// Device signature over the `PasswordChange` transcript (128 hex chars).
    signature: String,
    current_password: String,
    new_password: String,
}

/// Stage 1: issue a `PasswordChange` challenge for the authenticated device to sign.
async fn password_change_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ChallengeDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let service = state.service.clone();
    let ch = blocking(move || service.password_change_begin(&me)).await?;
    Ok(Json(ChallengeDto {
        account_id: hex::encode(ch.account_id.as_bytes()),
        device_id: hex::encode(ch.device_id.as_bytes()),
        txn_id: hex::encode(ch.txn_id.as_bytes()),
        nonce: hex::encode(ch.nonce),
        expires_at: ch.expires_at,
    }))
}

/// Stage 2: verify the device signature AND the current password, then set the new password
/// (policy + breach checked, rehashed). Requires both factors.
async fn password_change_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeFinishBody>,
) -> Result<StatusCode, ApiError> {
    if body.new_password.len() > 1024 || body.current_password.len() > 1024 {
        return Err(bad_request());
    }
    let me = authed_device(&state, &headers).await?;
    let txn_id = txn_from_hex(&body.txn_id)?;
    let signature = hex_exact(&body.signature, 64)?;
    let service = state.service.clone();
    blocking(move || {
        service.password_change_finish(
            &me,
            &txn_id,
            &signature,
            &body.current_password,
            &body.new_password,
        )
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- controlled multi-device (ADR-0008, R-903) --------------------------------------

#[derive(Serialize)]
struct EnrollChallengeDto {
    /// The reserved id for the NEW device (the trusted device binds this in its signature).
    device_id: String,
    txn_id: String,
    nonce: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollFinishBody {
    txn_id: String,
    /// SEC1 uncompressed P-256 public key of the NEW device (130 hex chars).
    device_public_key: String,
    /// The TRUSTED device's signature over the `DeviceEnroll` transcript (128 hex chars).
    signature: String,
}

#[derive(Serialize)]
struct DeviceDto {
    device_id: String,
    revoked: bool,
    /// True for the device making this request.
    current: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRefBody {
    device_id: String,
}

/// Stage 1 of trusted-device enrollment: the authenticated (trusted) device reserves the new
/// device's id + a nonce to sign.
async fn enroll_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<EnrollChallengeDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let service = state.service.clone();
    let ch = blocking(move || service.enroll_device_begin(&me)).await?;
    Ok(Json(EnrollChallengeDto {
        device_id: hex::encode(ch.device_id.as_bytes()),
        txn_id: hex::encode(ch.txn_id.as_bytes()),
        nonce: hex::encode(ch.nonce),
        expires_at: ch.expires_at,
    }))
}

/// Stage 2: the trusted device submits the new device's public key + its signature authorizing it.
/// Returns a **session for the new device**, relayed to it over the pairing channel.
async fn enroll_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnrollFinishBody>,
) -> Result<Json<SessionDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let txn_id = txn_from_hex(&body.txn_id)?;
    let device_public_key = hex_exact(&body.device_public_key, 65)?;
    let signature = hex_exact(&body.signature, 64)?;
    let service = state.service.clone();
    let public_key_for_log = device_public_key.clone();
    let session = blocking(move || {
        service.enroll_device_finish(
            &me,
            auth_core::EnrollRequest {
                txn_id,
                device_public_key,
                signature,
            },
        )
    })
    .await?;
    append_binding_best_effort(
        &state,
        session.account_id,
        session.device_id,
        public_key_for_log,
        "device enrollment",
    )
    .await;
    Ok(Json(SessionDto::from(session)))
}

/// The account's devices (management list). Members-of-account only (the caller's own account).
async fn list_devices_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let service = state.service.clone();
    let account = me.account_id;
    let current = me.device_id;
    let devices = blocking(move || service.list_devices(&account)).await?;
    Ok(Json(
        devices
            .into_iter()
            .map(|d| DeviceDto {
                current: d.device_id.0 == current.0,
                device_id: hex::encode(d.device_id.as_bytes()),
                revoked: d.revoked,
            })
            .collect(),
    ))
}

/// Revoke one of the caller's own devices (cascades tokens + refresh families + fails closed).
async fn revoke_device_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let target = DeviceId(id16_from_hex(&body.device_id)?);
    let service = state.service.clone();
    let account = me.account_id;
    let revoked = blocking(move || service.revoke_own_device(&account, &target)).await?;
    if !revoked {
        return Err(forbidden());
    }
    // Log the removal in the transparency log so a *revocation* is auditable under the signed root,
    // not just additions (ADR-0013). Best-effort, like binding appends: a log hiccup must not fail
    // the revocation (the device is already revoked in the source-of-truth store).
    let transparency = state.transparency.clone();
    let now = now_unix();
    let _ = blocking_store(move || transparency.append_revocation(&account, &target, now)).await;
    Ok(StatusCode::NO_CONTENT)
}

// ----- account recovery (ADR-0003, R-304) ---------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetRecoveryBody {
    recovery_secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverBeginBody {
    username: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverFinishBody {
    username: String,
    recovery_secret: String,
    txn_id: String,
    /// SEC1 uncompressed P-256 public key of the recovering (new) device.
    device_public_key: String,
    /// The new device's self-signature over the `DeviceEnroll` transcript.
    signature: String,
}

/// Set (or replace) the caller's recovery secret (authed; you set it up while you have a device).
async fn set_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetRecoveryBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let service = state.service.clone();
    blocking(move || service.set_recovery_secret(&me, &body.recovery_secret)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Stage 1 of recovery (unauthenticated): reserve the recovering device's id + a nonce to sign.
/// Enumeration-resistant — always returns a challenge.
async fn recover_begin_handler(
    State(state): State<AppState>,
    Json(body): Json<RecoverBeginBody>,
) -> Result<Json<ChallengeDto>, ApiError> {
    let service = state.service.clone();
    let ch = blocking(move || Ok::<_, AuthError>(service.recover_begin(&body.username))).await?;
    Ok(Json(ChallengeDto {
        account_id: hex::encode(ch.account_id.as_bytes()),
        device_id: hex::encode(ch.device_id.as_bytes()),
        txn_id: hex::encode(ch.txn_id.as_bytes()),
        nonce: hex::encode(ch.nonce),
        expires_at: ch.expires_at,
    }))
}

/// Stage 2 of recovery (unauthenticated): the recovery secret + the new device's proof of
/// possession enroll the new device and return its session.
async fn recover_finish_handler(
    State(state): State<AppState>,
    Json(body): Json<RecoverFinishBody>,
) -> Result<Json<SessionDto>, ApiError> {
    let txn_id = txn_from_hex(&body.txn_id)?;
    let device_public_key = hex_exact(&body.device_public_key, 65)?;
    let signature = hex_exact(&body.signature, 64)?;
    let service = state.service.clone();
    let public_key_for_log = device_public_key.clone();
    let session = blocking(move || {
        service.recover_finish(auth_core::RecoveryRequest {
            username: body.username,
            recovery_secret: body.recovery_secret,
            txn_id,
            new_device_public_key: device_public_key,
            new_device_signature: signature,
        })
    })
    .await?;
    append_binding_best_effort(
        &state,
        session.account_id,
        session.device_id,
        public_key_for_log,
        "recovery",
    )
    .await;
    Ok(Json(SessionDto::from(session)))
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
    /// Absent for a **sealed** envelope (the recipient learns the conversation from the payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
    /// Absent for a **sealed** envelope (the relay never learned the sender — ADR-0014).
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_device: Option<String>,
    ciphertext: String,
    /// True for a sealed envelope. Sealed ids live in a **separate id space** from identified ones,
    /// so a client acks them via `AckBody.sealed_ids`, not `ids`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sealed: bool,
    /// True for a **self-group** envelope (ADR-0015 option 3): a message from one of this account's
    /// OWN devices (linking Welcome/commit, or a `SecretConsumed`), which the client routes to the
    /// self-group inbound path. Its own id space — ack via `AckBody.self_group_ids`. `sender_device`
    /// is present (a sibling device); `conversation_id` is absent (it is not a conversation).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    self_group: bool,
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
    /// Identified envelope ids the client has durably persisted and no longer needs served.
    ids: Vec<i64>,
    /// **Sealed** envelope ids to ack — a separate id space from `ids` (ADR-0014). Optional so
    /// existing clients that only send `ids` are unaffected.
    #[serde(default)]
    sealed_ids: Vec<i64>,
    /// **Self-group** envelope ids to ack — a separate id space again (ADR-0015 option 3). Optional
    /// so existing clients are unaffected.
    #[serde(default)]
    self_group_ids: Vec<i64>,
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
    let claimed = blocking_store(move || {
        relay.claim_key_package(&account, crate::relay::KEY_PACKAGE_TTL_SECS)
    })
    .await?
    .ok_or(ApiError(StatusCode::NOT_FOUND, "no_key_package"))?;
    Ok(Json(ClaimedKeyPackageDto {
        device_id: hex::encode(claimed.device_id),
        key_package: hex::encode(claimed.key_package),
    }))
}

#[derive(Serialize)]
struct KeyPackageCountDto {
    /// Non-expired key packages this device still has published.
    available: u64,
    /// Publish more when `available` is at/below this (offline-add readiness).
    low_watermark: u64,
}

/// The caller's device's available (non-expired) key-package count, so the client knows when to
/// replenish its prekeys (MLS hygiene).
async fn key_package_count(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<KeyPackageCountDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let relay = state.relay.clone();
    let device = me.device_id;
    let available = blocking_store(move || {
        relay.count_available_key_packages(&device, crate::relay::KEY_PACKAGE_TTL_SECS)
    })
    .await?;
    Ok(Json(KeyPackageCountDto {
        available,
        low_watermark: crate::relay::KEY_PACKAGE_LOW_WATERMARK,
    }))
}

/// Sealed-sender certificate lifetime (ADR-0012, R-204). Short so a leaked or rotated
/// sender-certificate key stops being trusted quickly, yet long enough that a device does not
/// re-fetch per message.
const SENDER_CERT_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Serialize)]
struct SenderCertDto {
    account_id: String,
    device_id: String,
    /// SEC1 public key of the sending device (what the recipient checks the MLS sender against).
    sender_public_key: String,
    expires_at: u64,
    /// 64-byte r‖s ECDSA-P256 signature over the canonical certificate encoding.
    signature: String,
    /// SEC1 public key of the server's sender-certificate signing key. Production clients pin this
    /// out of band; it is returned here for bootstrap/discovery and tests (ADR-0012).
    cert_public_key: String,
}

/// Issue a short-lived sealed-sender **certificate** for the authenticated device (ADR-0012,
/// R-204). The device embeds the certificate *inside* the E2EE payload of a sealed-sender message,
/// so the recipient — and only the recipient — verifies who sent it while the relay never learns
/// the sender. The relay itself stays MLS-blind: this endpoint only signs `{account, device,
/// device public key, expiry}` bytes.
async fn issue_sender_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SenderCertDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let service = state.service.clone();
    let device_id = me.device_id;
    let sender_public_key = blocking(move || service.device_public_key(&device_id)).await?;
    let expires_at = now_unix() + SENDER_CERT_TTL_SECS;
    let cert = auth_core::sender_cert::SenderCert {
        account_id: &me.account_id,
        device_id: &me.device_id,
        sender_public_key: &sender_public_key,
        expires_at,
    };
    let signature: p256::ecdsa::Signature = state.sender_cert_key.sign(&cert.encode());
    let cert_public_key = state
        .sender_cert_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    Ok(Json(SenderCertDto {
        account_id: hex::encode(me.account_id.as_bytes()),
        device_id: hex::encode(me.device_id.as_bytes()),
        sender_public_key: hex::encode(&sender_public_key),
        expires_at,
        signature: hex::encode(signature.to_bytes()),
        cert_public_key: hex::encode(cert_public_key),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryVerifierBody {
    /// Hex `SHA-256(K_r)` — the verifier of the caller's sealed-sender delivery access key.
    verifier: String,
}

/// Register (or rotate) the caller account's sealed-sender **delivery access verifier**
/// (ADR-0014 Slice 2a). The recipient computes `V_r = SHA-256(K_r)` on-device and registers it here
/// while authenticated as itself; the relay stores only the 32-byte hash, never `K_r`. This is the
/// gate value only — no sealed-delivery endpoint exists yet (Slice 2b, gated on ADR-0014 review),
/// so registering a verifier changes no delivery behavior today.
async fn set_delivery_access_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeliveryVerifierBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let verifier = hex_exact(&body.verifier, auth_core::delivery_key::VERIFIER_LEN)?;
    if !auth_core::delivery_key::is_valid_verifier(&verifier) {
        return Err(bad_request());
    }
    let relay = state.relay.clone();
    let account = me.account_id;
    blocking_store(move || relay.set_delivery_verifier(&account, &verifier)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedDeliverBody {
    /// Recipient device (hex, 16 bytes) to enqueue for.
    recipient_device: String,
    /// Opaque MLS ciphertext (hex).
    ciphertext: String,
    /// Sender-chosen 128-bit random idempotency key (hex, 16 bytes).
    idempotency_key: String,
}

/// HTTP header carrying the recipient's delivery access key `K_r` (hex). MUST NOT be logged.
const DELIVERY_KEY_HEADER: &str = "x-delivery-key";

/// Deliver a **sealed-sender** message (ADR-0014 Slice 2b, R-204). **Unauthenticated:** the caller
/// proves the right to deliver by presenting the recipient's delivery access key `K_r` (header
/// `X-Delivery-Key`), not by authenticating as a sender — so the relay stores the envelope with **no
/// sender and no conversation**. The DAK is verified against the recipient account's registered
/// verifier `V_r = SHA-256(K_r)`; unknown device, unset verifier, and wrong key all return the SAME
/// generic 403 (no existence oracle), and the constant-time compare runs on every path.
async fn deliver_sealed_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SealedDeliverBody>,
) -> Result<StatusCode, ApiError> {
    let recipient = DeviceId(id16_from_hex(&body.recipient_device)?);
    let ciphertext = decode_ciphertext(&body.ciphertext)?;
    let idem = id16_from_hex(&body.idempotency_key)?;
    // A missing or malformed delivery key is treated exactly like a wrong one — uniform reject.
    let dak = match headers
        .get(DELIVERY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| hex::decode(s).ok())
    {
        Some(k) if k.len() == auth_core::delivery_key::DAK_LEN => k,
        _ => return Err(forbidden()),
    };

    // Verify the DAK off the async thread. Always run the constant-time compare (against a dummy
    // verifier when the device/verifier is absent) so unknown-device and bad-key share one path.
    let relay = state.relay.clone();
    let rec = recipient;
    let authorized = blocking_store(move || {
        let verifier = match relay.account_for_device(&rec)? {
            Some(account) => relay.delivery_verifier(&account)?,
            None => None,
        };
        let dummy = [0u8; auth_core::delivery_key::VERIFIER_LEN];
        let vref = verifier.as_deref().unwrap_or(&dummy);
        Ok(auth_core::delivery_key::verify(&dak, vref))
    })
    .await?;
    if !authorized {
        return Err(forbidden());
    }

    // Rate-limit only AUTHORIZED deliveries, keyed on the recipient device, so a bad-key flood can't
    // exhaust a victim's quota (that path is bounded by the per-IP limiter instead).
    if state.sealed_limiter.check_key(&recipient.0).is_err() {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }

    let relay = state.relay.clone();
    let rec = recipient;
    blocking_store(move || relay.deliver_sealed(&rec, &ciphertext, &idem)).await?;
    // Wake a waiting inbox/long-poll for the recipient.
    state.notifier.wake(&recipient.0);
    Ok(StatusCode::ACCEPTED)
}

// ----- Device self-group (ADR-0015 option 3) ------------------------------------------
//
// Establish + use the account's own-devices MLS group over the relay so a view-once "consumed"
// control message fans out to the account's OTHER devices — without the conversation's other party
// ever being in the channel. Every endpoint is authenticated and account-scoped: a device only ever
// touches its OWN account's self-group (the account boundary IS the authorization; no manifests).

/// Declare the authenticated device a member of its account's self-group (idempotent). Called by the
/// device that creates the self-group and by each device after it `join_self_group`s.
async fn self_group_register(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let relay = state.relay.clone();
    let account = me.account_id;
    let device = me.device_id;
    blocking_store(move || relay.register_self_group_member(&account, &device)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct SelfGroupPendingDto {
    /// Devices of my account that are enrolled but not yet linked into the self-group.
    pending_devices: Vec<String>,
}

/// List the account's devices that are enrolled but NOT yet in its self-group — the candidates the
/// caller links (claim each one's key package, add it, deliver the Welcome).
async fn self_group_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SelfGroupPendingDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let relay = state.relay.clone();
    let account = me.account_id;
    let caller = me.device_id;
    let devices =
        blocking_store(move || relay.pending_self_group_devices(&account, &caller)).await?;
    Ok(Json(SelfGroupPendingDto {
        pending_devices: devices.iter().map(hex::encode).collect(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfGroupClaimBody {
    /// A device of the caller's OWN account to claim a key package for (to add it to the self-group).
    device_id: String,
}

/// Claim one key package for a specific sibling device of the caller's account (to add it to the
/// self-group). Refuses if the target device is not a non-revoked device of the caller's account —
/// this endpoint never claims another account's key package.
async fn self_group_claim_key_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SelfGroupClaimBody>,
) -> Result<Json<ClaimedKeyPackageDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let target = DeviceId(id16_from_hex(&body.device_id)?);
    let relay = state.relay.clone();
    let account = me.account_id;
    let claimed = blocking_store(move || {
        // Authorization: the target must be one of the caller's own account's devices.
        match relay.account_for_device(&target)? {
            Some(a) if a.0 == account.0 => {}
            _ => return Ok(None),
        }
        relay.claim_key_package_for_device(&target, crate::relay::KEY_PACKAGE_TTL_SECS)
    })
    .await?
    .ok_or(ApiError(StatusCode::NOT_FOUND, "no_key_package"))?;
    Ok(Json(ClaimedKeyPackageDto {
        device_id: hex::encode(claimed.device_id),
        key_package: hex::encode(claimed.key_package),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfGroupDeliverBody {
    /// Targeted delivery to one of the caller's own devices (an MLS Welcome/commit during linking).
    /// Omit to **fan out** to every OTHER joined member of the self-group (a `SecretConsumed` control
    /// message).
    #[serde(default)]
    recipient_device: Option<String>,
    /// Opaque MLS ciphertext (hex) — the relay never decrypts it.
    ciphertext: String,
    /// 16-byte client-chosen idempotency key (hex); a retry with the same key is a no-op.
    idempotency_key: String,
}

/// Deliver a self-group envelope. With `recipient_device`: targeted to that sibling device (Welcome
/// or commit). Without: fan out to every OTHER joined member of the caller's self-group (the
/// consumption control message). Relay-blind: opaque ciphertext, account-scoped routing only.
async fn self_group_deliver(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SelfGroupDeliverBody>,
) -> Result<Json<FanoutReceiptDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let ciphertext = decode_ciphertext(&body.ciphertext)?;
    let idem = id16_from_hex(&body.idempotency_key)?;
    let recipient = match &body.recipient_device {
        Some(hex_id) => Some(DeviceId(id16_from_hex(hex_id)?)),
        None => None,
    };

    let relay = state.relay.clone();
    let account = me.account_id;
    let sender = me.device_id;
    let outcome = blocking_store(move || match recipient {
        Some(rec) => relay.deliver_self_group_targeted(&account, &sender, &rec, &ciphertext, &idem),
        None => relay.fanout_self_group(&account, &sender, &ciphertext, &idem),
    })
    .await?;

    let newly_queued = match outcome {
        SelfGroupSendOutcome::Forbidden => return Err(forbidden()),
        SelfGroupSendOutcome::Delivered { newly_queued } => newly_queued,
    };
    for device in &newly_queued {
        state.notifier.wake(device);
    }
    Ok(Json(FanoutReceiptDto {
        delivered: newly_queued.len(),
    }))
}

#[derive(Serialize)]
struct ConversationSummaryDto {
    conversation_id: String,
    member_account_ids: Vec<String>,
}

/// List the conversations the authenticated device belongs to (for the Chats list).
async fn list_conversations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConversationSummaryDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let relay = state.relay.clone();
    let convos = blocking_store(move || relay.list_conversations(&me.device_id)).await?;
    Ok(Json(
        convos
            .into_iter()
            .map(|c| ConversationSummaryDto {
                conversation_id: hex::encode(c.conversation_id),
                member_account_ids: c.member_account_ids.iter().map(hex::encode).collect(),
            })
            .collect(),
    ))
}

/// Optional create-conversation body. `mls_authoritative` opts the conversation into
/// commit-authoritative membership (ADR-0010): afterwards the legacy direct-mutation endpoints
/// refuse and all membership changes go through `/commit`. Absent/`{}` ⇒ legacy (false).
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CreateConversationBody {
    #[serde(default)]
    mls_authoritative: bool,
}

/// Create a conversation with the authenticated device as the first member.
async fn create_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<CreateConversationBody>>,
) -> Result<Json<ConversationDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let mls_authoritative = body.map(|b| b.0.mls_authoritative).unwrap_or(false);
    let conversation_id = auth_core::crypto::random_bytes::<16>();
    let relay = state.relay.clone();
    let groups = state.groups.clone();
    blocking_store(move || {
        relay.create_conversation(
            conversation_id,
            me.account_id,
            me.device_id,
            mls_authoritative,
        )?;
        groups.bootstrap_admin(&conversation_id, &me.account_id)
    })
    .await?;
    Ok(Json(ConversationDto {
        conversation_id: hex::encode(conversation_id),
    }))
}

/// Reject a legacy membership mutation on an MLS-authoritative conversation (ADR-0010): such
/// conversations accept membership changes only through `/commit`. Returns `409 commits_required`.
async fn reject_if_authoritative(
    state: &AppState,
    conversation_id: &[u8; 16],
) -> Result<(), ApiError> {
    let relay = state.relay.clone();
    let cid = *conversation_id;
    if blocking_store(move || relay.is_authoritative(&cid)).await? {
        return Err(ApiError(StatusCode::CONFLICT, "commits_required"));
    }
    Ok(())
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
    reject_if_authoritative(&state, &conversation_id).await?;

    let relay = state.relay.clone();
    let service = state.service.clone();
    let groups = state.groups.clone();
    let social = state.social.clone();
    blocking_store(move || {
        // Direct add is consent-by-proxy, so it is tightly gated (ADR-0009): the caller must be
        // an ADMIN of the group AND friends with the target (friends = implied consent to be
        // added by you; strangers join via invite links = their own consent), and no block may
        // exist between the target and any current member. Non-members/non-admins learn nothing.
        if !relay.is_member(&conversation_id, &me.device_id)?
            || !groups.is_admin(&conversation_id, &me.account_id)?
            || !social.are_friends(&me.account_id, &target_account)?
            || groups.blocked_against_members(&conversation_id, &target_account)?
        {
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

/// Leave a conversation (consent withdrawal, ADR-0009). Removes all of the caller's devices from
/// routing and purges their queued undelivered envelopes for it. Idempotent `204`: leaving a
/// conversation you're not in (or that doesn't exist) is a no-op — ids are opaque random values,
/// so this discloses nothing.
async fn leave_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    reject_if_authoritative(&state, &conversation_id).await?;
    let groups = state.groups.clone();
    blocking_store(move || groups.leave_conversation(&conversation_id, &me.account_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- group governance (ADR-0009): admins, invites, join requests --------------------

/// Invite-link bounds: default 7 days / 100 uses, capped at 30 days / 1000 uses.
const INVITE_DEFAULT_EXPIRES_SECS: i64 = 7 * 24 * 3600;
const INVITE_MAX_EXPIRES_SECS: i64 = 30 * 24 * 3600;
const INVITE_DEFAULT_MAX_USES: i32 = 100;
const INVITE_MAX_MAX_USES: i32 = 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInviteBody {
    #[serde(default)]
    expires_in_secs: Option<i64>,
    #[serde(default)]
    max_uses: Option<i32>,
}

#[derive(Serialize)]
struct InviteDto {
    invite_token: String,
    expires_at: i64,
    max_uses: i32,
    uses: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteTokenBody {
    invite_token: String,
}

#[derive(Serialize)]
struct AcceptInviteDto {
    conversation_id: String,
    status: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsBody {
    join_approval: bool,
}

fn token32_from_hex(input: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex_exact(input, 32)?;
    bytes.try_into().map_err(|_| bad_request())
}

/// Guard: true iff the caller is a routed member AND an admin of the conversation. Handlers treat
/// `false` as a generic forbidden — non-members/non-admins learn nothing. Store errors stay 500.
fn is_conversation_admin(
    state: &AppState,
    conversation_id: &[u8; 16],
    me: &AccountDevice,
) -> auth_core::store::StoreResult<bool> {
    Ok(state.relay.is_member(conversation_id, &me.device_id)?
        && state.groups.is_admin(conversation_id, &me.account_id)?)
}

async fn create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<CreateInviteBody>,
) -> Result<Json<InviteDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    // Authoritative conversations grow only through /commit, so they mint no invite links: this
    // closes the invite/join join-path at its source (no invite ⇒ no accept ⇒ no join request).
    reject_if_authoritative(&state, &conversation_id).await?;
    let expires = body
        .expires_in_secs
        .unwrap_or(INVITE_DEFAULT_EXPIRES_SECS)
        .clamp(60, INVITE_MAX_EXPIRES_SECS);
    let max_uses = body
        .max_uses
        .unwrap_or(INVITE_DEFAULT_MAX_USES)
        .clamp(1, INVITE_MAX_MAX_USES);
    let token = auth_core::crypto::random_bytes::<32>();
    let st = state.clone();
    blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups
            .create_invite(&conversation_id, &me.account_id, token, expires, max_uses)?;
        Ok(Some(()))
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(Json(InviteDto {
        invite_token: hex::encode(token),
        expires_at: now_unix_i64() + expires,
        max_uses,
        uses: 0,
    }))
}

fn now_unix_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn list_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
) -> Result<Json<Vec<InviteDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let st = state.clone();
    let invites = blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.list_invites(&conversation_id).map(Some)
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(Json(
        invites
            .into_iter()
            .map(|i| InviteDto {
                invite_token: hex::encode(i.token),
                expires_at: i.expires_at_unix,
                max_uses: i.max_uses,
                uses: i.uses,
            })
            .collect(),
    ))
}

async fn revoke_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<InviteTokenBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let token = token32_from_hex(&body.invite_token)?;
    let st = state.clone();
    blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.revoke_invite(&conversation_id, &token)?;
        Ok(Some(()))
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Present an invite token: the joiner's own consent. Joins immediately, or files a join request
/// when the group requires approval. One generic 403 on any refusal — a token must not become an
/// oracle for group/block state.
async fn accept_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InviteTokenBody>,
) -> Result<Json<AcceptInviteDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let token = token32_from_hex(&body.invite_token)?;
    let groups = state.groups.clone();
    let relay = state.relay.clone();
    let outcome = blocking_store(move || {
        let outcome = groups.accept_invite(&token, &me.account_id)?;
        if let InviteOutcome::Joined { conversation_id } = &outcome {
            // Routing add after the validated consume; the caller's own device only.
            relay.add_member(conversation_id, me.account_id, me.device_id)?;
        }
        Ok(outcome)
    })
    .await?;
    match outcome {
        InviteOutcome::Joined { conversation_id } => Ok(Json(AcceptInviteDto {
            conversation_id: hex::encode(conversation_id),
            status: "joined",
        })),
        InviteOutcome::Requested { conversation_id } => Ok(Json(AcceptInviteDto {
            conversation_id: hex::encode(conversation_id),
            status: "requested",
        })),
        InviteOutcome::Refused => Err(forbidden()),
    }
}

async fn list_join_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
) -> Result<Json<Vec<String>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let st = state.clone();
    let requests = blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.list_join_requests(&conversation_id).map(Some)
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(Json(requests.into_iter().map(hex::encode).collect()))
}

async fn approve_join_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    reject_if_authoritative(&state, &conversation_id).await?;
    let st = state.clone();
    let approved = blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        // Blocks are re-checked at approval time inside approve_join_request.
        if !st.groups.approve_join_request(&conversation_id, &target)? {
            return Ok(Some(false));
        }
        let device = st
            .service
            .active_device(&target)
            .map_err(|_| auth_core::store::StoreError("device lookup".into()))?;
        if let Some(device_id) = device {
            st.relay.add_member(&conversation_id, target, device_id)?;
        }
        Ok(Some(true))
    })
    .await?
    .ok_or_else(forbidden)?;
    if approved {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "no_request"))
    }
}

async fn deny_join_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    let st = state.clone();
    blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.deny_join_request(&conversation_id, &target)?;
        Ok(Some(()))
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Admin removes a member. Uses the same exit path as leave (routing removal + queued-mail purge +
/// role cleanup). Removing yourself is a `leave`, not a remove.
async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    if target.0 == me.account_id.0 {
        return Err(bad_request());
    }
    reject_if_authoritative(&state, &conversation_id).await?;
    let st = state.clone();
    blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.leave_conversation(&conversation_id, &target)?;
        Ok(Some(()))
    })
    .await?
    .ok_or_else(forbidden)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn promote_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    let st = state.clone();
    let promoted = blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.promote(&conversation_id, &target).map(Some)
    })
    .await?
    .ok_or_else(forbidden)?;
    if promoted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "not_member"))
    }
}

async fn demote_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    let st = state.clone();
    let demoted = blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups.demote(&conversation_id, &target).map(Some)
    })
    .await?
    .ok_or_else(forbidden)?;
    if demoted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        // Refusing to demote the LAST admin keeps the group manageable.
        Err(ApiError(StatusCode::CONFLICT, "last_admin"))
    }
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<SettingsBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let st = state.clone();
    blocking_store(move || {
        if !is_conversation_admin(&st, &conversation_id, &me)? {
            return Ok(None);
        }
        st.groups
            .set_join_approval(&conversation_id, body.join_approval)?;
        Ok(Some(()))
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
        // Key reused for a different payload/conversation: refusing (409) beats silently
        // deduping, which would drop the new message while reporting success.
        FanoutOutcome::IdempotencyMismatch => Err(idempotency_conflict()),
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
    let outcome = blocking_store(move || {
        relay.send_targeted(
            &conversation_id,
            &me.device_id,
            &recipient,
            &ciphertext,
            &idempotency_key,
        )
    })
    .await?;
    let envelope_id = match outcome {
        SendOutcome::Forbidden => return Err(forbidden()),
        SendOutcome::IdempotencyMismatch => return Err(idempotency_conflict()),
        SendOutcome::Queued(id) => id,
    };
    state.notifier.wake(&recipient_bytes);
    Ok(Json(ReceiptDto { envelope_id }))
}

/// One added member in a membership commit: their account and joining device.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitAddDto {
    account_id: String,
    device_id: String,
}

/// A membership change as `(signed manifest fields, opaque commit[, welcomes])` (ADR-0010).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipCommitBody {
    /// 1 = add, 2 = remove, 3 = self-leave.
    control_type: u8,
    prev_epoch: u64,
    next_epoch: u64,
    /// SHA-256 (hex) of `commit` — verified server-side before anything is applied.
    commit_hash: String,
    added: Vec<CommitAddDto>,
    removed: Vec<String>,
    idempotency_key: String,
    expires_at: u64,
    /// ECDSA-P256 signature (hex) over the canonical manifest by the actor's enrolled device key.
    signature: String,
    /// The opaque MLS commit ciphertext (hex).
    commit: String,
    /// One opaque Welcome (hex) per `added` entry, same order.
    welcomes: Vec<String>,
}

#[derive(Serialize)]
struct MembershipCommitReceiptDto {
    /// False on an idempotent retry of an already-applied commit.
    applied: bool,
    next_epoch: u64,
}

#[derive(Serialize)]
struct EpochDto {
    epoch: u64,
}

/// Bounds membership-change fan-in per commit (defense in depth; MLS groups this size need the
/// future attachment path anyway).
const MAX_COMMIT_MEMBER_DELTA: usize = 32;

/// Apply an MLS membership commit (ADR-0010): verify the device-signed manifest, enforce
/// governance and the per-group epoch CAS, and atomically apply routing + fan out the commit and
/// welcomes. The relay never parses the commit — recipients verify correspondence client-side.
async fn membership_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
    Json(body): Json<MembershipCommitBody>,
) -> Result<Json<MembershipCommitReceiptDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;

    // ---- Shape + freshness checks (reject before any lookup). ----
    let control =
        auth_core::membership::ControlType::from_u8(body.control_type).ok_or_else(bad_request)?;
    if body.next_epoch != body.prev_epoch.wrapping_add(1) {
        return Err(bad_request());
    }
    if body.added.len() > MAX_COMMIT_MEMBER_DELTA
        || body.removed.len() > MAX_COMMIT_MEMBER_DELTA
        || body.welcomes.len() != body.added.len()
    {
        return Err(bad_request());
    }
    // Control-consistency: exactly one kind of change per commit (v1).
    let shape_ok = match control {
        auth_core::membership::ControlType::Add => {
            !body.added.is_empty() && body.removed.is_empty()
        }
        auth_core::membership::ControlType::Remove | auth_core::membership::ControlType::Leave => {
            body.added.is_empty() && !body.removed.is_empty()
        }
    };
    if !shape_ok {
        return Err(bad_request());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if body.expires_at <= now {
        return Err(bad_request());
    }

    // ---- Decode + canonical-order checks. ----
    let mut added: Vec<(AccountId, DeviceId)> = Vec::with_capacity(body.added.len());
    for a in &body.added {
        added.push((
            AccountId(id16_from_hex(&a.account_id)?),
            DeviceId(id16_from_hex(&a.device_id)?),
        ));
    }
    let mut removed: Vec<DeviceId> = Vec::with_capacity(body.removed.len());
    for d in &body.removed {
        removed.push(DeviceId(id16_from_hex(d)?));
    }
    // Sorted + duplicate-free lists are part of the canonical form (the encoding is otherwise
    // ambiguous between semantically-equal manifests).
    let sorted_unique_pairs = added
        .windows(2)
        .all(|w| (w[0].0.as_bytes(), w[0].1.as_bytes()) < (w[1].0.as_bytes(), w[1].1.as_bytes()));
    let sorted_unique_removed = removed
        .windows(2)
        .all(|w| w[0].as_bytes() < w[1].as_bytes());
    if !sorted_unique_pairs || !sorted_unique_removed {
        return Err(bad_request());
    }

    let commit_hash: [u8; 32] = hex_exact(&body.commit_hash, 32)?
        .try_into()
        .map_err(|_| bad_request())?;
    let idempotency_key = id16_from_hex(&body.idempotency_key)?;
    let signature = decode_ciphertext(&body.signature)?;
    let commit = decode_ciphertext(&body.commit)?;
    let mut welcomes: Vec<Vec<u8>> = Vec::with_capacity(body.welcomes.len());
    for w in &body.welcomes {
        welcomes.push(decode_ciphertext(w)?);
    }

    // ---- Hash binding: the manifest names exactly these commit bytes. ----
    if auth_core::crypto::sha256(&commit) != commit_hash {
        return Err(bad_request());
    }

    // ---- Manifest signature under the actor's enrolled device key. ----
    let manifest = auth_core::membership::Manifest {
        control,
        group_id: &conversation_id,
        prev_epoch: body.prev_epoch,
        next_epoch: body.next_epoch,
        commit_hash: &commit_hash,
        actor_device: &me.device_id,
        added: &added,
        removed: &removed,
        idempotency_key: &idempotency_key,
        expires_at: body.expires_at,
    };
    let manifest_bytes = manifest.encode();
    let manifest_hash = manifest.hash();
    let service = state.service.clone();
    let actor_device = me.device_id;
    let actor_key = blocking(move || service.device_public_key(&actor_device)).await?;
    if !auth_core::crypto::verify_p256(&actor_key, &manifest_bytes, &signature) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "denied"));
    }

    // ---- Atomic application (governance + idempotency + epoch CAS + delta + fanout + log). ----
    let membership = state.membership.clone();
    let next_epoch = body.next_epoch;
    let outcome = blocking_store(move || {
        membership.apply_commit(&CommitRequest {
            conversation_id: &conversation_id,
            actor_account: &me.account_id,
            actor_device: &me.device_id,
            control_type: body.control_type,
            prev_epoch: body.prev_epoch,
            next_epoch: body.next_epoch,
            commit_hash: &commit_hash,
            manifest_hash: &manifest_hash,
            manifest: &manifest_bytes,
            signature: &signature,
            idempotency_key: &idempotency_key,
            commit: &commit,
            added: &added,
            removed: &removed,
            welcomes: &welcomes,
        })
    })
    .await?;

    match outcome {
        ApplyOutcome::Applied { woken } => {
            for device in &woken {
                state.notifier.wake(device);
            }
            Ok(Json(MembershipCommitReceiptDto {
                applied: true,
                next_epoch,
            }))
        }
        ApplyOutcome::AlreadyApplied => Ok(Json(MembershipCommitReceiptDto {
            applied: false,
            next_epoch,
        })),
        ApplyOutcome::Forbidden => Err(forbidden()),
        ApplyOutcome::StaleEpoch => Err(ApiError(StatusCode::CONFLICT, "stale_epoch")),
        ApplyOutcome::IdempotencyMismatch => Err(idempotency_conflict()),
        ApplyOutcome::Invalid => Err(bad_request()),
    }
}

/// A stored membership event's manifest (decoded) + evidence, for a recipient's correspondence
/// check (ADR-0010). Members only.
#[derive(Serialize)]
struct MembershipEventDto {
    control_type: u8,
    prev_epoch: u64,
    next_epoch: u64,
    commit_hash: String,
    actor_device: String,
    /// The actor's account — where its device key lives in the transparency log, so the recipient
    /// can verify the signature against the LOGGED key rather than a server-asserted one.
    actor_account: String,
    added: Vec<CommitAddDto>,
    removed: Vec<String>,
    idempotency_key: String,
    expires_at: u64,
    /// Canonical manifest bytes (hex) + the actor's device signature (hex).
    manifest: String,
    signature: String,
}

/// Fetch the membership event for an epoch transition (`{epoch}` = its `next_epoch`). A recipient
/// at local epoch N fetches `N+1` to learn the manifest's `added`/`removed` before running the
/// client-side correspondence check. Members only (generic `403` otherwise).
async fn membership_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((conversation_hex, epoch)): Path<(String, u64)>,
) -> Result<Json<MembershipEventDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let membership = state.membership.clone();
    let device = me.device_id;
    let (is_member, row) = blocking_store(move || {
        let is_member = membership
            .epoch_for_member(&conversation_id, &device)?
            .is_some();
        let row = if is_member {
            membership.event_for_epoch(&conversation_id, epoch)?
        } else {
            None
        };
        Ok((is_member, row))
    })
    .await?;
    if !is_member {
        return Err(forbidden());
    }
    // Not-found and not-a-member both surface as a generic 403 (no oracle on which epochs exist).
    let row = row.ok_or_else(forbidden)?;
    let m = auth_core::membership::decode(&row.manifest).ok_or_else(internal)?;
    Ok(Json(MembershipEventDto {
        control_type: m.control as u8,
        prev_epoch: m.prev_epoch,
        next_epoch: m.next_epoch,
        commit_hash: hex::encode(m.commit_hash),
        actor_device: hex::encode(m.actor_device),
        actor_account: hex::encode(row.actor_account),
        added: m
            .added
            .iter()
            .map(|(a, d)| CommitAddDto {
                account_id: hex::encode(a),
                device_id: hex::encode(d),
            })
            .collect(),
        removed: m.removed.iter().map(hex::encode).collect(),
        idempotency_key: hex::encode(m.idempotency_key),
        expires_at: m.expires_at,
        manifest: hex::encode(&row.manifest),
        signature: hex::encode(&row.signature),
    }))
}

/// The conversation's current membership epoch (members only; one generic 403 otherwise). A
/// client rebasing after `stale_epoch` reads this before rebuilding its commit.
async fn conversation_epoch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_hex): Path<String>,
) -> Result<Json<EpochDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let conversation_id = id16_from_hex(&conversation_hex)?;
    let membership = state.membership.clone();
    let epoch =
        blocking_store(move || membership.epoch_for_member(&conversation_id, &me.device_id))
            .await?
            .ok_or_else(forbidden)?;
    Ok(Json(EpochDto { epoch }))
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
    let (mut identified, mut sealed, mut self_group) = read_all_inbox(&state, me.device_id).await?;

    if identified.is_empty() && sealed.is_empty() && self_group.is_empty() && query.wait > 0 {
        let wait = std::time::Duration::from_secs(query.wait.min(MAX_INBOX_WAIT_SECS));
        tokio::select! {
            _ = notified.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
        (identified, sealed, self_group) = read_all_inbox(&state, me.device_id).await?;
    }

    let mut out: Vec<InboxEnvelopeDto> = identified
        .into_iter()
        .map(|e| InboxEnvelopeDto {
            id: e.id,
            conversation_id: Some(hex::encode(e.conversation_id)),
            sender_device: Some(hex::encode(e.sender_device)),
            ciphertext: hex::encode(e.ciphertext),
            sealed: false,
            self_group: false,
        })
        .collect();
    out.extend(sealed.into_iter().map(|e| InboxEnvelopeDto {
        id: e.id,
        conversation_id: None,
        sender_device: None,
        ciphertext: hex::encode(e.ciphertext),
        sealed: true,
        self_group: false,
    }));
    out.extend(self_group.into_iter().map(|e| InboxEnvelopeDto {
        id: e.id,
        conversation_id: None,
        sender_device: Some(hex::encode(e.sender_device)),
        ciphertext: hex::encode(e.ciphertext),
        sealed: false,
        self_group: true,
    }));
    Ok(Json(out))
}

/// Acknowledge durably-persisted envelopes so the server can purge them. At-least-once: a
/// client peeks, persists locally, then acks; a crash before ack just re-peeks (dedup by id).
async fn ack_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    if body.ids.len() > 1000 || body.sealed_ids.len() > 1000 || body.self_group_ids.len() > 1000 {
        return Err(bad_request());
    }
    let relay = state.relay.clone();
    let device = me.device_id;
    blocking_store(move || {
        relay.ack_envelopes(&device, &body.ids)?;
        relay.ack_sealed(&device, &body.sealed_ids)?;
        relay.ack_self_group(&device, &body.self_group_ids)?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Peek identified, sealed (ADR-0014), and self-group (ADR-0015 option 3) envelopes for a device.
/// Each lives in a separate table/id space, so they are returned as separate lists the caller tags
/// distinctly (`sealed` / `self_group` flags), and the client acks each via its own id list.
#[allow(clippy::type_complexity)]
async fn read_all_inbox(
    state: &AppState,
    device_id: DeviceId,
) -> Result<
    (
        Vec<crate::relay::EnvelopeOut>,
        Vec<crate::relay::SealedEnvelopeOut>,
        Vec<crate::relay::SelfGroupEnvelopeOut>,
    ),
    ApiError,
> {
    let relay = state.relay.clone();
    blocking_store(move || {
        let identified = relay.peek_inbox(&device_id, 100)?;
        let sealed = relay.peek_sealed_inbox(&device_id, 100)?;
        let self_group = relay.peek_self_group_inbox(&device_id, 100)?;
        Ok((identified, sealed, self_group))
    })
    .await
}

// ----- WebSocket streaming delivery ---------------------------------------------------

#[derive(Serialize)]
struct StreamPush {
    envelopes: Vec<InboxEnvelopeDto>,
}

/// Client → server ack over the socket. Each channel has its own id space (identified conversation
/// mail, sealed-sender, self-group), so acks are carried in three separate lists — a client acks
/// each envelope in the list matching its `sealed` / `self_group` flag. All optional (a client that
/// only receives identified mail sends `ack` alone).
#[derive(Deserialize)]
struct StreamAck {
    #[serde(default)]
    ack: Vec<i64>,
    #[serde(default)]
    sealed_ack: Vec<i64>,
    #[serde(default)]
    self_group_ack: Vec<i64>,
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
    // re-served from the DB on reconnect (the cursors reset to 0). Each channel has its own
    // BIGSERIAL id space (separate tables), so it needs its own cursor — a single one would let a
    // high id in one channel suppress a lower id in another.
    let mut last_identified: i64 = 0;
    let mut last_sealed: i64 = 0;
    let mut last_self_group: i64 = 0;
    let heartbeat = std::time::Duration::from_secs(30);

    loop {
        // Deliver anything pending and not yet pushed this session, across ALL three channels
        // (identified conversation mail, sealed-sender, self-group) so real-time delivery — e.g. a
        // view-once consumption fan-out — rides the socket, not just the HTTP long-poll.
        match read_all_inbox(&state, device).await {
            Ok((identified, sealed, self_group)) => {
                let mut fresh: Vec<InboxEnvelopeDto> = Vec::new();
                for e in identified {
                    if e.id > last_identified {
                        last_identified = last_identified.max(e.id);
                        fresh.push(InboxEnvelopeDto {
                            id: e.id,
                            conversation_id: Some(hex::encode(e.conversation_id)),
                            sender_device: Some(hex::encode(e.sender_device)),
                            ciphertext: hex::encode(e.ciphertext),
                            sealed: false,
                            self_group: false,
                        });
                    }
                }
                for e in sealed {
                    if e.id > last_sealed {
                        last_sealed = last_sealed.max(e.id);
                        fresh.push(InboxEnvelopeDto {
                            id: e.id,
                            conversation_id: None,
                            sender_device: None,
                            ciphertext: hex::encode(e.ciphertext),
                            sealed: true,
                            self_group: false,
                        });
                    }
                }
                for e in self_group {
                    if e.id > last_self_group {
                        last_self_group = last_self_group.max(e.id);
                        fresh.push(InboxEnvelopeDto {
                            id: e.id,
                            conversation_id: None,
                            sender_device: Some(hex::encode(e.sender_device)),
                            ciphertext: hex::encode(e.ciphertext),
                            sealed: false,
                            self_group: true,
                        });
                    }
                }
                if !fresh.is_empty() {
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
                        if let Ok(StreamAck { ack, sealed_ack, self_group_ack }) =
                            serde_json::from_str::<StreamAck>(&text)
                        {
                            if ack.len() <= 1000 && sealed_ack.len() <= 1000
                                && self_group_ack.len() <= 1000
                                && !(ack.is_empty() && sealed_ack.is_empty() && self_group_ack.is_empty())
                            {
                                let relay = state.relay.clone();
                                let _ = blocking_store(move || {
                                    relay.ack_envelopes(&device, &ack)?;
                                    relay.ack_sealed(&device, &sealed_ack)?;
                                    relay.ack_self_group(&device, &self_group_ack)?;
                                    Ok(())
                                })
                                .await;
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
        FriendRequestOutcome::Blocked => return Err(ApiError(StatusCode::FORBIDDEN, "blocked")),
    };
    Ok(Json(FriendActionDto { status }))
}

async fn block_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    if target.0 == me.account_id.0 {
        return Err(bad_request());
    }
    let social = state.social.clone();
    blocking_store(move || social.block(&me.account_id, &target)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unblock_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountRefBody>,
) -> Result<StatusCode, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    let social = state.social.clone();
    blocking_store(move || social.unblock(&me.account_id, &target)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_blocked(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileSummaryDto>>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let social = state.social.clone();
    let blocked = blocking_store(move || social.list_blocked(&me.account_id)).await?;
    Ok(Json(blocked.into_iter().map(summary_dto).collect()))
}

const MAX_REPORT_REASON_CHARS: usize = 500;
const MAX_REPORT_EVIDENCE_CHARS: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportBody {
    account_id: String,
    reason: String,
    /// Optional reporter-chosen excerpt. The server never derives this from E2EE content.
    #[serde(default)]
    evidence: Option<String>,
}

#[derive(Serialize)]
struct ReportDto {
    report_id: i64,
}

async fn create_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ReportBody>,
) -> Result<Json<ReportDto>, ApiError> {
    let me = authed_device(&state, &headers).await?;
    let target = AccountId(id16_from_hex(&body.account_id)?);
    if target.0 == me.account_id.0 {
        return Err(bad_request());
    }
    let reason = body.reason.trim().to_string();
    if reason.is_empty() || reason.chars().count() > MAX_REPORT_REASON_CHARS {
        return Err(bad_request());
    }
    if let Some(ev) = &body.evidence {
        if ev.chars().count() > MAX_REPORT_EVIDENCE_CHARS {
            return Err(bad_request());
        }
    }
    let social = state.social.clone();
    let evidence = body.evidence.clone();
    let id = blocking_store(move || {
        social.create_report(&me.account_id, &target, &reason, evidence.as_deref())
    })
    .await?;
    Ok(Json(ReportDto { report_id: id }))
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

/// Create a group conversation. Members need not be friends (ADR-0009), but creation is refused
/// if any pair within the group has blocked each other. Adds all members' active devices to
/// routing so the group's messages reach every person.
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
    let groups = state.groups.clone();
    let outcome = blocking_store(move || {
        // Gates (ADR-0009): listing someone is a DIRECT add, so the creator must be friends with
        // each listed member (friends = implied consent to be added by you — strangers join via
        // invite links, which is their own consent; this stops forced-membership spam). Members
        // need NOT be friends with each other. And a group must never force together a pair that
        // has blocked each other.
        for member in &others_for_task {
            if !social.are_friends(&me.account_id, member)? {
                return Ok(Err("not_friends"));
            }
        }
        if social.any_block_within(&all)? {
            return Ok(Err("blocked_member"));
        }
        let conversation_id = auth_core::crypto::random_bytes::<16>();
        // Legacy multi-member group creation stays non-authoritative (it seeds routing directly);
        // authoritative groups are created empty via POST /v1/conversations {mls_authoritative}
        // and grow through /commit.
        relay.create_conversation(conversation_id, me.account_id, me.device_id, false)?;
        groups.bootstrap_admin(&conversation_id, &me.account_id)?;
        for member in &others_for_task {
            // Resolve each member's active device server-side (never client-asserted).
            if let Some(device) = service
                .active_device(member)
                .map_err(|_| auth_core::store::StoreError("device lookup".into()))?
            {
                relay.add_member(&conversation_id, *member, device)?;
            }
        }
        Ok(Ok(conversation_id))
    })
    .await?;

    match outcome {
        Err(reason) => Err(ApiError(StatusCode::FORBIDDEN, reason)),
        Ok(conversation_id) => Ok(Json(GroupDto {
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
