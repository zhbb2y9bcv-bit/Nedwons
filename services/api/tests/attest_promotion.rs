//! ADR-0017: a **cryptographically verified** App Attest attestation promotes the submitting device
//! to `Assurance::Hardware`, which is what lets it authorize enrollment of another device.
//!
//! This is a **separate test binary on purpose.** `AttestationConfig::from_env()` reads process-wide
//! environment variables, and Cargo gives each integration-test file its own process — so enabling
//! verification here cannot leak into `app_attest.rs`, which asserts the opposite (bootstrap-mode)
//! behaviour. Everything runs in ONE test for the same reason: the env must be set before the router
//! is built, and tests within a binary share the process.
//!
//! No Apple hardware is needed: a synthetic root → intermediate → credential chain (the same
//! technique `attest_verify.rs` uses on the verifier directly) is pinned via
//! `NEDWONS_APP_ATTEST_ROOT_PEM`, so the real verification code path executes against a root we
//! control.

mod common;

use axum::http::StatusCode;
use ciborium::value::Value;
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};

use auth_core::ids::DeviceId;
use auth_core::store::{Assurance, DeviceStore};
use auth_core::transcript::{Action, Transcript};
use common::{
    get_auth, http_register, make_app_requiring_hardware_approver, post_json_auth, shared_stores,
    unique_username, TestDevice,
};

const APP_ID: &str = "TEAM123.app.nedwons.demo";
const AAGUID_PROD: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";

/// Apple's nonce extension content: SEQUENCE { [1] { OCTET STRING(32) } }.
fn nonce_extension_der(nonce: &[u8; 32]) -> Vec<u8> {
    let mut inner = vec![0x04, 0x20];
    inner.extend_from_slice(nonce);
    let mut ctx = vec![0xA1, inner.len() as u8];
    ctx.extend_from_slice(&inner);
    let mut seq = vec![0x30, ctx.len() as u8];
    seq.extend_from_slice(&ctx);
    seq
}

/// WebAuthn-style authData: rpIdHash ‖ flags ‖ counter ‖ aaguid ‖ credIdLen ‖ credId.
fn auth_data(cred_id: &[u8]) -> Vec<u8> {
    let mut out = Sha256::digest(APP_ID.as_bytes()).to_vec();
    out.push(0x40); // AT flag
    out.extend_from_slice(&0u32.to_be_bytes()); // counter MUST be 0 at attestation
    out.extend_from_slice(&AAGUID_PROD);
    out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    out.extend_from_slice(cred_id);
    out
}

fn attestation_cbor(x5c: Vec<Vec<u8>>, auth_data: &[u8]) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("fmt".into()),
            Value::Text("apple-appattest".into()),
        ),
        (
            Value::Text("attStmt".into()),
            Value::Map(vec![
                (
                    Value::Text("x5c".into()),
                    Value::Array(x5c.into_iter().map(Value::Bytes).collect()),
                ),
                (Value::Text("receipt".into()), Value::Bytes(vec![])),
            ]),
        ),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).expect("cbor encode");
    out
}

/// The synthetic trust root, generated once so it can be pinned via env before the app is built.
struct Root {
    pem: String,
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_root() -> Root {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    Root {
        pem: cert.pem(),
        cert,
        key,
    }
}

/// Build an attestation bound to `challenge` — the server's own random challenge, hashed exactly as
/// the handler does (`clientDataHash = SHA-256(challenge)`), so the nonce check passes.
fn attestation_for_challenge(root: &Root, challenge: &[u8]) -> (Vec<u8>, String) {
    let inter_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut inter_params = CertificateParams::new(vec![]).unwrap();
    inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let inter_cert = inter_params
        .signed_by(&inter_key, &root.cert, &root.key)
        .unwrap();

    // key id = SHA-256(uncompressed credential public key); it is also the credential id.
    let cred_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let key_id = Sha256::digest(cred_key.public_key_raw()).to_vec();

    let ad = auth_data(&key_id);
    let client_data_hash: [u8; 32] = Sha256::digest(challenge).into();
    let mut h = Sha256::new();
    h.update(&ad);
    h.update(client_data_hash);
    let nonce: [u8; 32] = h.finalize().into();

    let mut cred_params = CertificateParams::new(vec![]).unwrap();
    cred_params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 2, 840, 113635, 100, 8, 2],
        nonce_extension_der(&nonce),
    )];
    let cred_cert = cred_params
        .signed_by(&cred_key, &inter_cert, &inter_key)
        .unwrap();

    let cbor = attestation_cbor(
        vec![cred_cert.der().to_vec(), inter_cert.der().to_vec()],
        &ad,
    );
    // The handler expects the key id in the same encoding `attest::decode_key_id` accepts.
    (cbor, hex::encode(&key_id))
}

fn id16(hex_str: &str) -> [u8; 16] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// Drive the two-stage ADR-0008 enrollment ceremony over HTTP, returning the `finish` status.
async fn try_enroll(
    app: &axum::Router,
    trusted_token: &str,
    trusted_account_hex: &str,
    trusted_signer: &TestDevice,
    new_device: &TestDevice,
) -> StatusCode {
    let (status, ch) =
        post_json_auth(app, "/v1/devices/enroll/begin", trusted_token, json!({})).await;
    if status != StatusCode::OK {
        // `begin` already fails closed for an ineligible approver — that is a refusal too.
        return status;
    }
    let account = auth_core::ids::AccountId(id16(trusted_account_hex));
    let device_id = auth_core::ids::DeviceId(id16(ch["device_id"].as_str().unwrap()));
    let txn_id = auth_core::ids::TxnId(id16(ch["txn_id"].as_str().unwrap()));
    let nonce = hex::decode(ch["nonce"].as_str().unwrap()).unwrap();
    let expires_at = ch["expires_at"].as_u64().unwrap();

    let transcript = Transcript {
        action: Action::DeviceEnroll,
        account_id: &account,
        device_id: &device_id,
        public_key: &new_device.public_key,
        challenge: &nonce,
        expires_at,
        txn_id: &txn_id,
    };
    let signature = trusted_signer.sign(&transcript.encode());
    let (status, _) = post_json_auth(
        app,
        "/v1/devices/enroll/finish",
        trusted_token,
        json!({
            "txn_id": hex::encode(txn_id.0),
            "device_public_key": hex::encode(&new_device.public_key),
            "signature": hex::encode(signature),
        }),
    )
    .await;
    status
}

/// The whole arc in one test: a freshly registered device is `software` and CANNOT approve an
/// enrollment; after a verified attestation it is `hardware` and CAN. This is the only test that
/// exercises the assurance class through the assembled server rather than through `auth-core`
/// directly, so it is what proves the feature actually does something in production shape.
#[tokio::test]
async fn a_verified_attestation_promotes_the_device_to_hardware() {
    let root = make_root();
    // Must be set BEFORE the router is built — the config is read from env at construction.
    std::env::set_var("NEDWONS_APP_ATTEST_APP_ID", APP_ID);
    std::env::set_var("NEDWONS_APP_ATTEST_ROOT_PEM", &root.pem);

    // Restriction ON, matching `NEDWONS_REQUIRE_HARDWARE_APPROVER=1`.
    let app = make_app_requiring_hardware_approver(100_000).await;
    let (device_a, session) = http_register(&app, &unique_username("attestprom")).await;
    let token = session["access_token"].as_str().unwrap();
    let device = DeviceId(id16(session["device_id"].as_str().unwrap()));

    // Baseline: every device is born Software (ADR-0017), including the registering one.
    let before = tokio::task::spawn_blocking(move || {
        shared_stores().device(&device).unwrap().unwrap().assurance
    })
    .await
    .unwrap();
    assert_eq!(before, Assurance::Software, "devices start Software");

    // ...and while Software it cannot approve an enrollment.
    let account_hex = session["account_id"].as_str().unwrap().to_string();
    let device_b = TestDevice::new();
    assert_eq!(
        try_enroll(&app, token, &account_hex, &device_a, &device_b).await,
        StatusCode::UNAUTHORIZED,
        "a software-assurance device must not be able to approve an enrollment"
    );

    // Attest over the server's own challenge.
    let (status, ch) = get_auth(&app, "/v1/attest/challenge", token).await;
    assert_eq!(status, StatusCode::OK);
    let challenge_hex = ch["challenge"].as_str().unwrap().to_string();
    let challenge = hex::decode(&challenge_hex).unwrap();
    let (cbor, key_id) = attestation_for_challenge(&root, &challenge);

    let (status, _) = post_json_auth(
        &app,
        "/v1/attest/key",
        token,
        json!({
            "key_id": key_id,
            "challenge": challenge_hex,
            "attestation": hex::encode(&cbor),
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a well-formed attestation chaining to the pinned root is accepted"
    );

    // The payoff: verification promoted the device, so it may now approve an enrollment.
    let after = tokio::task::spawn_blocking(move || {
        shared_stores().device(&device).unwrap().unwrap().assurance
    })
    .await
    .unwrap();
    assert_eq!(
        after,
        Assurance::Hardware,
        "a verified attestation must promote the device to Hardware"
    );

    // The payoff: the same enrollment that was refused above now succeeds.
    assert_eq!(
        try_enroll(&app, token, &account_hex, &device_a, &device_b).await,
        StatusCode::OK,
        "a hardware-assurance device may approve an enrollment"
    );
}
