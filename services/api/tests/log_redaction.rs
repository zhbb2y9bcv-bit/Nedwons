//! INV-8 evidence: nothing secret reaches the logs.
//!
//! THREAT_MODEL lists INV-8 as "**P** — source-side redaction; log-redaction tests in Milestone
//! 1/2", i.e. the tests were promised and never written. Until they exist the invariant is a
//! convention, and a convention only holds until the one `{e}` nobody reviewed. This captures the
//! REAL subscriber output while driving real traffic through the real router, then asserts the
//! secrets are absent.
//!
//! A single test in its own binary, deliberately: `set_global_default` can only be called once per
//! process, and request handling crosses tokio worker threads, so a thread-scoped subscriber would
//! silently capture nothing and the test would pass by observing an empty buffer. The final
//! assertion guards exactly that failure mode by requiring the capture to be non-empty first.

mod common;

use std::io;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::{
    get_auth, http_register, make_app, post_json, post_json_auth, unique_username, PASSWORD,
};
use serde_json::json;

/// A `MakeWriter` that appends every emitted log line to a shared buffer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("capture lock")).to_string()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn logs_contain_no_credentials_tokens_or_search_terms() {
    let capture = Capture::default();
    // DEBUG deliberately: this must hold at the most verbose setting an operator would realistically
    // use while diagnosing an incident, not merely at the production default. The filter is built
    // through the same policy the binary uses, so the test exercises the real configuration rather
    // than a friendlier one.
    tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            nedwons_api::redact::log_filter(Some("debug")),
        ))
        .with_ansi(false)
        .init();

    let app = make_app(1_000_000).await;

    // Distinctive values: if any of these appear anywhere in the captured output, something logged
    // data it should not have. They are chosen to be unmistakable rather than realistic.
    let username = unique_username("redactme");
    let (_device, session) = http_register(&app, &username).await;
    let token = session["access_token"].as_str().unwrap().to_string();
    let account_id = session["account_id"].as_str().unwrap().to_string();
    let device_id = session["device_id"].as_str().unwrap().to_string();
    let refresh = session["refresh_token"].as_str().unwrap().to_string();

    // Traffic across the interesting shapes: an authenticated GET, a search carrying a term in the
    // QUERY STRING, a mutation with a body, and two failures (which is where handlers are most
    // tempted to log detail).
    let (status, _) = get_auth(&app, "/v1/session/whoami", &token).await;
    assert_eq!(status, StatusCode::OK);

    let secret_search_term = "zzsupersecretsearchzz";
    let (_status, _) = get_auth(
        &app,
        &format!("/v1/profiles/search?q={secret_search_term}"),
        &token,
    )
    .await;

    let (_status, _) = post_json_auth(
        &app,
        "/v1/profile",
        &token,
        json!({"display_name": "Redact Me", "bio": "a bio"}),
    )
    .await;

    // A failed login: wrong password, and a bogus signature.
    let (_status, _) = post_json(
        &app,
        "/v1/login/begin",
        json!({"username": username, "password": "WRONGPASSWORD_zz_marker"}),
    )
    .await;
    let (_status, _) = post_json(
        &app,
        "/v1/login/finish",
        json!({"txn_id": "00".repeat(16), "signature": "11".repeat(64)}),
    )
    .await;

    // A request that fails authentication entirely.
    let (_status, _) = get_auth(&app, "/v1/session/whoami", &"ab".repeat(32)).await;

    let logs = capture.contents();

    // Guard the failure mode where this test proves nothing: if the subscriber captured no output,
    // every "absent" assertion below would pass vacuously.
    assert!(
        logs.contains("request"),
        "captured no request logs — the test would pass vacuously; got {} bytes",
        logs.len()
    );

    for (label, needle) in [
        ("the account password", PASSWORD),
        ("a wrong password attempt", "WRONGPASSWORD_zz_marker"),
        ("the access token", token.as_str()),
        ("the refresh token", refresh.as_str()),
        ("the search term from the query string", secret_search_term),
        ("the account id", account_id.as_str()),
        ("the device id", device_id.as_str()),
        ("the username", username.as_str()),
    ] {
        assert!(
            !logs.contains(needle),
            "INV-8 violation: {label} appears in the logs.\n--- captured ---\n{logs}"
        );
    }

    // The route SHAPE is what operations needs and is safe to keep, so its presence is asserted
    // positively — a redaction that also removed the useful signal would be a regression, not a
    // fix.
    assert!(
        logs.contains("/v1/session/whoami"),
        "the route shape should be logged: {logs}"
    );
    assert!(
        logs.contains("/v1/profiles/search"),
        "the search ROUTE is fine; only the term is not: {logs}"
    );
}
