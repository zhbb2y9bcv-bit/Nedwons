//! App Attest verifier (#10 gap closure), proven end to end WITHOUT Apple hardware: a synthetic
//! certificate chain (test root CA → intermediate → credential cert carrying Apple's nonce
//! extension) + a well-formed CBOR attestation object exercise every verification step, and each
//! tamper — wrong nonce, wrong key id, wrong app id, non-zero counter, wrong environment, a chain
//! to a different root, garbage CBOR — is rejected with the right typed error. Against real Apple
//! hardware the same code runs with the embedded Apple root (pin sanity is unit-tested in-module).

mod common;

use std::time::SystemTime;

use ciborium::value::Value;
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};
use sha2::{Digest, Sha256};

use nedwons_api::attest::{verify_attestation, AttestError, AttestationConfig};

const APP_ID: &str = "TEAM123.app.nedwons.demo";
const AAGUID_PROD: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEV: [u8; 16] = *b"appattestdevelop";

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
fn auth_data(app_id: &str, counter: u32, aaguid: &[u8; 16], cred_id: &[u8]) -> Vec<u8> {
    let mut out = Sha256::digest(app_id.as_bytes()).to_vec();
    out.push(0x40); // AT flag
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(aaguid);
    out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    out.extend_from_slice(cred_id);
    out
}

/// CBOR-encode the attestation object `{fmt, attStmt: {x5c, receipt}, authData}`.
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

/// A complete synthetic attestation: (cbor, key_id, client_data_hash, config).
struct Synthetic {
    cbor: Vec<u8>,
    key_id: Vec<u8>,
    client_data_hash: [u8; 32],
    cfg: AttestationConfig,
}

/// Build a valid synthetic attestation, with hooks to tamper the counter/aaguid/nonce.
fn build_synthetic(counter: u32, aaguid: &[u8; 16], tamper_nonce: bool) -> Synthetic {
    // Root CA (the pinned trust anchor for this test).
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut root_params = CertificateParams::new(vec![]).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root_cert = root_params.self_signed(&root_key).unwrap();

    // Intermediate CA (mirrors Apple's App Attest CA 1).
    let inter_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut inter_params = CertificateParams::new(vec![]).unwrap();
    inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let inter_cert = inter_params
        .signed_by(&inter_key, &root_cert, &root_key)
        .unwrap();

    // Credential key: key id = SHA-256(uncompressed public key).
    let cred_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let key_id = Sha256::digest(cred_key.public_key_raw()).to_vec();

    // authData + the nonce that binds it to the challenge hash.
    let ad = auth_data(APP_ID, counter, aaguid, &key_id);
    let client_data_hash: [u8; 32] = Sha256::digest(b"server-issued-challenge").into();
    let mut h = Sha256::new();
    h.update(&ad);
    h.update(client_data_hash);
    let mut nonce: [u8; 32] = h.finalize().into();
    if tamper_nonce {
        nonce[0] ^= 0xFF;
    }

    // Credential cert carrying the Apple nonce extension, issued by the intermediate.
    let mut cred_params = CertificateParams::new(vec![]).unwrap();
    cred_params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 2, 840, 113635, 100, 8, 2],
        nonce_extension_der(&nonce),
    )];
    let cred_cert = cred_params
        .signed_by(&cred_key, &inter_cert, &inter_key)
        .unwrap();

    Synthetic {
        cbor: attestation_cbor(
            vec![cred_cert.der().to_vec(), inter_cert.der().to_vec()],
            &ad,
        ),
        key_id,
        client_data_hash,
        cfg: AttestationConfig {
            app_id: APP_ID.to_string(),
            root_der: root_cert.der().to_vec(),
            allow_development: false,
        },
    }
}

#[test]
fn a_well_formed_attestation_verifies() {
    let s = build_synthetic(0, &AAGUID_PROD, false);
    let verified = verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &s.cfg,
        SystemTime::now(),
    )
    .expect("valid attestation verifies");
    // The attested public key hashes to the key id (usable for later assertion verification).
    assert_eq!(Sha256::digest(&verified.public_key_sec1).to_vec(), s.key_id);
}

#[test]
fn a_tampered_nonce_is_rejected() {
    // The nonce binds the attestation to THIS challenge; a mismatch = replay/splice.
    let s = build_synthetic(0, &AAGUID_PROD, true);
    let err = verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &s.cfg,
        SystemTime::now(),
    )
    .unwrap_err();
    assert_eq!(err, AttestError::Nonce);
}

#[test]
fn a_wrong_challenge_hash_is_rejected() {
    let s = build_synthetic(0, &AAGUID_PROD, false);
    let wrong: [u8; 32] = Sha256::digest(b"a-different-challenge").into();
    let err =
        verify_attestation(&s.cbor, &s.key_id, &wrong, &s.cfg, SystemTime::now()).unwrap_err();
    assert_eq!(err, AttestError::Nonce);
}

#[test]
fn a_wrong_key_id_is_rejected() {
    let s = build_synthetic(0, &AAGUID_PROD, false);
    let err = verify_attestation(
        &s.cbor,
        &[0xAB; 32],
        &s.client_data_hash,
        &s.cfg,
        SystemTime::now(),
    )
    .unwrap_err();
    assert_eq!(err, AttestError::KeyId);
}

#[test]
fn a_wrong_app_id_is_rejected() {
    let s = build_synthetic(0, &AAGUID_PROD, false);
    let cfg = AttestationConfig {
        app_id: "TEAM999.other.app".to_string(),
        root_der: s.cfg.root_der.clone(),
        allow_development: false,
    };
    let err = verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &cfg,
        SystemTime::now(),
    )
    .unwrap_err();
    assert_eq!(err, AttestError::AppId);
}

#[test]
fn a_nonzero_counter_is_rejected() {
    let s = build_synthetic(7, &AAGUID_PROD, false);
    let err = verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &s.cfg,
        SystemTime::now(),
    )
    .unwrap_err();
    assert_eq!(err, AttestError::Counter);
}

#[test]
fn development_environment_is_rejected_unless_allowed() {
    let s = build_synthetic(0, &AAGUID_DEV, false);
    let err = verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &s.cfg,
        SystemTime::now(),
    )
    .unwrap_err();
    assert_eq!(err, AttestError::Aaguid);

    // With development explicitly allowed, the same attestation verifies.
    let cfg = AttestationConfig {
        app_id: s.cfg.app_id.clone(),
        root_der: s.cfg.root_der.clone(),
        allow_development: true,
    };
    verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &cfg,
        SystemTime::now(),
    )
    .expect("development attestation verifies when allowed");
}

#[test]
fn a_chain_to_a_different_root_is_rejected() {
    // A valid-looking chain anchored somewhere else (e.g. an attacker's CA) must not verify.
    let s = build_synthetic(0, &AAGUID_PROD, false);
    let other_root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut other_params = CertificateParams::new(vec![]).unwrap();
    other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let other_root = other_params.self_signed(&other_root_key).unwrap();
    let cfg = AttestationConfig {
        app_id: s.cfg.app_id.clone(),
        root_der: other_root.der().to_vec(),
        allow_development: false,
    };
    let err = verify_attestation(
        &s.cbor,
        &s.key_id,
        &s.client_data_hash,
        &cfg,
        SystemTime::now(),
    )
    .unwrap_err();
    assert_eq!(err, AttestError::Signature);
}

#[test]
fn garbage_and_wrong_format_cbor_are_rejected() {
    let s = build_synthetic(0, &AAGUID_PROD, false);
    for bad in [
        b"not cbor at all".to_vec(),
        attestation_cbor(vec![], b"tiny"), // empty chain
        {
            // Right CBOR shape, wrong fmt string.
            let mut out = Vec::new();
            ciborium::ser::into_writer(
                &Value::Map(vec![(
                    Value::Text("fmt".into()),
                    Value::Text("packed".into()),
                )]),
                &mut out,
            )
            .unwrap();
            out
        },
    ] {
        let err = verify_attestation(
            &bad,
            &s.key_id,
            &s.client_data_hash,
            &s.cfg,
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AttestError::Cbor | AttestError::Chain),
            "got {err:?}"
        );
    }
}
