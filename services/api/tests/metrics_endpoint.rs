//! The scrape endpoint is a credential-gated surface, not a public one.
//!
//! Metrics describe the health and volume of the whole service. Exposed publicly they hand an
//! attacker a live feed of how their probing is landing — auth failures climbing, rate limits
//! biting, queue depth growing. So the endpoint is gated, and an unconfigured deployment answers
//! 404 rather than 401: it should not even advertise that the endpoint exists.
//!
//! Its own binary because `NEDWONS_METRICS_TOKEN` is process-global; setting it from one test
//! while another reads it is how a suite becomes flaky.

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::make_app;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn get_metrics(app: &axum::Router, token: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::get("/metrics");
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn metrics_are_gated_and_expose_no_identifiers() {
    // Unconfigured: the endpoint does not exist as far as any caller can tell.
    std::env::remove_var("NEDWONS_METRICS_TOKEN");
    let app = make_app(1_000_000).await;
    let (status, _) = get_metrics(&app, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unconfigured deployment must not advertise the endpoint"
    );

    std::env::set_var("NEDWONS_METRICS_TOKEN", "scrape-token-for-tests");

    // Configured, but no credential — still 404, not 401: a 401 confirms the endpoint is there.
    let (status, _) = get_metrics(&app, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "missing token must not scrape"
    );

    let (status, _) = get_metrics(&app, Some("wrong-token")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "wrong token must not scrape");

    let (status, body) = get_metrics(&app, Some("scrape-token-for-tests")).await;
    assert_eq!(status, StatusCode::OK, "the correct token scrapes");

    // The flows the runbooks alert on must actually be present, or an alert silently never fires.
    for metric in [
        "nedwons_auth_failures_total",
        "nedwons_auth_successes_total",
        "nedwons_proof_replays_rejected_total",
        "nedwons_quota_exhausted_total",
        "nedwons_rate_limited_ip_total",
        "nedwons_db_pool_in_use",
        "nedwons_queue_depth",
        "nedwons_websockets_open",
        "nedwons_kt_append_failures_total",
        "nedwons_accounts_deleted_total",
        "nedwons_attestation_failures_total",
        "nedwons_push_failures_total",
    ] {
        assert!(body.contains(metric), "missing metric {metric}:\n{body}");
    }

    // INV-8 covers metrics too. No labels means no place for an identifier to hide.
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        assert!(!line.contains('{'), "metrics must carry no labels: {line}");
    }

    std::env::remove_var("NEDWONS_METRICS_TOKEN");
}
