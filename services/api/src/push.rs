//! APNs push, so a backgrounded/killed app is woken to fetch its inbox — the in-process
//! [`crate::notify::DeliveryNotifier`] only reaches a connected client.
//!
//! **Content never leaves the relay (INV-1).** A push carries NO message content, only a
//! contentless "you have mail" signal (`{"aps":{"alert":"New message","mutable-content":1,…}}`);
//! the Notification Service Extension fetches and decrypts locally.
//!
//! **Injected transport (mirrors the HIBP breach provider).** The APNs protocol logic — the ES256
//! provider JWT, the `/3/device/<token>` request, the headers — is built and unit-tested here against
//! a mock [`PushTransport`]. The production HTTP/2 socket to `api.push.apple.com` is a thin adapter
//! supplied at deployment (it needs an HTTP/2 client dependency + Apple credentials: an APNs auth-key
//! scalar, key id, team id, and the app's bundle-id topic). Until one is wired, [`PushService`] is
//! disabled and every dispatch is a no-op — the wake path still works, it just sends nothing.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use auth_core::ids::DeviceId;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use crate::relay::PgRelay;

/// APNs provider configuration (from environment at startup). The signing key is the P-256 private
/// scalar of the operator's APNs auth key (`.p8`); `key_id`/`team_id`/`topic` are Apple identifiers.
pub struct ApnsConfig {
    pub key_id: String,
    pub team_id: String,
    /// The app's bundle id (the `apns-topic`).
    pub topic: String,
    pub signing_key: SigningKey,
}

/// One outbound APNs HTTP/2 request, fully formed — the transport only opens the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsRequest {
    /// `:path` — `/3/device/<device-token>`.
    pub path: String,
    /// `authorization: bearer <jwt>`.
    pub authorization: String,
    /// `apns-topic` (the bundle id).
    pub apns_topic: String,
    /// `apns-push-type` (`alert`).
    pub apns_push_type: String,
    /// JSON payload (contentless).
    pub body: Vec<u8>,
}

/// Injected so the protocol logic is testable without a network. Blocking; called off the async
/// path. Returns the APNs HTTP status (200 = accepted).
pub trait PushTransport: Send + Sync {
    fn post(&self, request: &ApnsRequest) -> Result<u16, String>;
}

/// A transport that sends nothing (kept for tests and for explicitly-disabled deployments).
pub struct NullTransport;
impl PushTransport for NullTransport {
    fn post(&self, _request: &ApnsRequest) -> Result<u16, String> {
        Ok(200)
    }
}

/// The **real** transport (rustls, no OpenSSL). APNs requires HTTP/2, so `https://` uses TLS ALPN
/// and `http://` uses prior knowledge (h2c) for local tests only.
///
/// The client is built lazily **inside** `post`, which always runs on a blocking thread, because
/// constructing a `reqwest::blocking::Client` in an async context panics.
pub struct HttpPushTransport {
    base_url: String,
    client: std::sync::OnceLock<Result<reqwest::blocking::Client, String>>,
}

/// Default APNs production host. Sandbox is `https://api.sandbox.push.apple.com` (set
/// `NEDWONS_APNS_URL` to override).
pub const APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";

impl HttpPushTransport {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: std::sync::OnceLock::new(),
        }
    }

    /// Base URL from `NEDWONS_APNS_URL`, defaulting to production APNs.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("NEDWONS_APNS_URL").unwrap_or_else(|_| APNS_PRODUCTION_URL.to_string()),
        )
    }

    fn client(&self) -> Result<&reqwest::blocking::Client, String> {
        self.client
            .get_or_init(|| {
                let builder = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10));
                // Plain-HTTP base (tests/dev): HTTP/2 prior knowledge, since there is no ALPN.
                let builder = if self.base_url.starts_with("http://") {
                    builder.http2_prior_knowledge()
                } else {
                    builder
                };
                builder.build().map_err(|e| format!("client build: {e}"))
            })
            .as_ref()
            .map_err(|e| e.clone())
    }
}

impl PushTransport for HttpPushTransport {
    fn post(&self, request: &ApnsRequest) -> Result<u16, String> {
        let url = format!("{}{}", self.base_url, request.path);
        let response = self
            .client()?
            .post(&url)
            .header("authorization", &request.authorization)
            .header("apns-topic", &request.apns_topic)
            .header("apns-push-type", &request.apns_push_type)
            .header("content-type", "application/json")
            .body(request.body.clone())
            .send()
            .map_err(|e| format!("apns send: {e}"))?;
        Ok(response.status().as_u16())
    }
}

/// Parse Apple's `.p8` (PKCS#8 PEM) provider key into a P-256 signing key. Accepts literal `\n`
/// escapes (env-file friendliness). `None` on any malformation — never a partial parse.
pub fn signing_key_from_p8(p8: &str) -> Option<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    let pem = p8.replace("\\n", "\n");
    SigningKey::from_pkcs8_pem(pem.trim()).ok()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unpadded base64url (JWT/JWS alphabet), no dependency.
fn b64url(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

/// Build the APNs **provider token** — an ES256 JWT `{alg:ES256, kid} . {iss:team, iat} . sig`.
/// Apple accepts a token for up to ~1h; the caller may cache it, but building per-batch is cheap.
pub fn apns_jwt(cfg: &ApnsConfig, iat: u64) -> String {
    let header = format!(r#"{{"alg":"ES256","kid":"{}"}}"#, cfg.key_id);
    let claims = format!(r#"{{"iss":"{}","iat":{}}}"#, cfg.team_id, iat);
    let signing_input = format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(claims.as_bytes())
    );
    let sig: Signature = cfg.signing_key.sign(signing_input.as_bytes());
    format!("{}.{}", signing_input, b64url(&sig.to_bytes()))
}

/// The contentless "new message" payload. Carries no E2EE content (the relay has none); the app's
/// Notification Service Extension fetches + decrypts and rewrites the alert (`mutable-content`).
fn contentless_payload() -> Vec<u8> {
    br#"{"aps":{"alert":"New message","mutable-content":1,"sound":"default"}}"#.to_vec()
}

/// Build the APNs request that wakes `device_token` (a hex/opaque APNs token).
pub fn build_push(cfg: &ApnsConfig, device_token: &str, iat: u64) -> ApnsRequest {
    ApnsRequest {
        path: format!("/3/device/{device_token}"),
        authorization: format!("bearer {}", apns_jwt(cfg, iat)),
        apns_topic: cfg.topic.clone(),
        apns_push_type: "alert".to_string(),
        body: contentless_payload(),
    }
}

/// Dispatches contentless wake pushes to a device's registered tokens. Disabled (a no-op) unless an
/// [`ApnsConfig`] is configured — so the wake path is always safe to call.
#[derive(Clone)]
pub struct PushService {
    inner: Option<Arc<PushInner>>,
}

struct PushInner {
    cfg: ApnsConfig,
    transport: Arc<dyn PushTransport>,
    relay: Arc<PgRelay>,
}

impl PushService {
    /// A disabled service (no APNs config) — every dispatch is a no-op.
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn new(cfg: ApnsConfig, transport: Arc<dyn PushTransport>, relay: Arc<PgRelay>) -> Self {
        Self {
            inner: Some(Arc::new(PushInner {
                cfg,
                transport,
                relay,
            })),
        }
    }

    /// Build from the environment; returns a disabled service if the identifiers or key are absent
    /// or malformed. `transport` is the deployment's HTTP/2 adapter ([`HttpPushTransport`] in
    /// production; a recording/[`NullTransport`] in tests).
    ///
    /// - `NEDWONS_APNS_KEY_ID`, `NEDWONS_APNS_TEAM_ID`, `NEDWONS_APNS_TOPIC` — Apple identifiers.
    /// - The provider key, either form:
    ///   - `NEDWONS_APNS_KEY_P8` — the **contents of the `.p8` file from Apple, verbatim** (PKCS#8
    ///     PEM; literal `\n` sequences are accepted for env-file friendliness), or
    ///   - `NEDWONS_APNS_KEY_HEX` — the raw P-256 scalar in hex.
    pub fn from_env(relay: Arc<PgRelay>, transport: Arc<dyn PushTransport>) -> Self {
        let (Ok(key_id), Ok(team_id), Ok(topic)) = (
            std::env::var("NEDWONS_APNS_KEY_ID"),
            std::env::var("NEDWONS_APNS_TEAM_ID"),
            std::env::var("NEDWONS_APNS_TOPIC"),
        ) else {
            return Self::disabled();
        };
        let Some(signing_key) = Self::signing_key_from_env() else {
            return Self::disabled();
        };
        Self::new(
            ApnsConfig {
                key_id,
                team_id,
                topic,
                signing_key,
            },
            transport,
            relay,
        )
    }

    /// The provider signing key from `NEDWONS_APNS_KEY_P8` (preferred — Apple's `.p8` verbatim) or
    /// `NEDWONS_APNS_KEY_HEX`. `None` if absent or malformed (the service then stays disabled —
    /// never a half-configured signer).
    fn signing_key_from_env() -> Option<SigningKey> {
        if let Ok(p8) = std::env::var("NEDWONS_APNS_KEY_P8") {
            return signing_key_from_p8(&p8);
        }
        let key_hex = std::env::var("NEDWONS_APNS_KEY_HEX").ok()?;
        let bytes = hex::decode(key_hex.trim()).ok()?;
        SigningKey::from_slice(&bytes).ok()
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Send a contentless wake push to every APNs token registered for `device`. Best-effort: a
    /// token lookup error or a per-token transport failure is swallowed (delivery already happened;
    /// the client also has the long-poll / WebSocket path). Blocking — call from a blocking task.
    pub fn notify_device_blocking(&self, device: &[u8; 16]) {
        let Some(inner) = &self.inner else {
            return;
        };
        let tokens = inner
            .relay
            .push_tokens_for_device(&DeviceId(*device))
            .unwrap_or_default();
        if tokens.is_empty() {
            return;
        }
        let iat = now_secs();
        for (platform, token) in tokens {
            if platform == "apns" {
                let req = build_push(&inner.cfg, &token, iat);
                let _ = inner.transport.post(&req);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> ApnsConfig {
        // A fixed key is unnecessary — we assert structure, not an exact signature.
        ApnsConfig {
            key_id: "ABC1234567".to_string(),
            team_id: "TEAM098765".to_string(),
            topic: "app.nedwons.messenger".to_string(),
            signing_key: SigningKey::from_slice(&[7u8; 32]).unwrap(),
        }
    }

    #[test]
    fn b64url_matches_known_vectors() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        // The '+' / '/' of standard base64 become '-' / '_' and there is no padding.
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn jwt_has_es256_header_and_provider_claims() {
        let cfg = test_cfg();
        let jwt = apns_jwt(&cfg, 1_700_000_000);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "header.claims.signature");
        // The header is a documented, unpadded base64url of the ES256/kid JSON.
        assert_eq!(parts[0], b64url(br#"{"alg":"ES256","kid":"ABC1234567"}"#));
        assert_eq!(
            parts[1],
            b64url(br#"{"iss":"TEAM098765","iat":1700000000}"#)
        );
        // ES256 signature is raw r||s = 64 bytes → 86 unpadded base64url chars.
        assert_eq!(parts[2].len(), 86);
    }

    #[test]
    fn push_request_is_contentless_and_correctly_addressed() {
        let cfg = test_cfg();
        let req = build_push(&cfg, "deadbeefcafe", 1_700_000_000);
        assert_eq!(req.path, "/3/device/deadbeefcafe");
        assert!(req.authorization.starts_with("bearer "));
        assert_eq!(req.apns_topic, "app.nedwons.messenger");
        assert_eq!(req.apns_push_type, "alert");
        let body = String::from_utf8(req.body).unwrap();
        // No E2EE content ever appears — only a generic wake alert.
        assert!(body.contains("mutable-content"));
        assert!(body.contains("New message"));
    }
}
