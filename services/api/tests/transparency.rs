//! Key transparency (R-201) end to end over the real HTTP API + PostgreSQL. A client self-monitors:
//! it verifies the STH signature, that its own enrolled binding is included under the signed root,
//! and that the log stays append-only (consistency) as it grows.

mod common;

use auth_core::transparency::{encode_sth, hash_leaf, verify_consistency, verify_inclusion, Hash};
use axum::http::StatusCode;
use common::{get_auth, http_register, make_app, unique_username};
use p256::ecdsa::signature::Verifier;
use serde_json::Value;

fn hex32(s: &str) -> Hash {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn proof_hashes(v: &Value) -> Vec<Hash> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|h| hex32(h.as_str().unwrap()))
        .collect()
}

/// Verify a STH's ECDSA-P256 signature against the log public key it advertises.
fn verify_sth_signature(sth: &Value) {
    let size = sth["tree_size"].as_u64().unwrap();
    let root = hex32(sth["root_hash"].as_str().unwrap());
    let ts = sth["timestamp"].as_u64().unwrap();
    let pk_bytes = hex::decode(sth["log_public_key"].as_str().unwrap()).unwrap();
    let sig_bytes = hex::decode(sth["signature"].as_str().unwrap()).unwrap();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes).expect("log public key");
    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).expect("sth signature");
    assert!(
        vk.verify(&encode_sth(size, &root, ts), &sig).is_ok(),
        "STH signature must verify under the advertised log key"
    );
}

#[tokio::test]
async fn enrolled_binding_is_logged_signed_and_included() {
    let app = make_app(100_000).await;
    let (device, session) = http_register(&app, &unique_username("kt")).await;
    let token = session["access_token"].as_str().unwrap();
    let account_hex = session["account_id"].as_str().unwrap();
    let device_hex = session["device_id"].as_str().unwrap();

    // Fetch + verify the signed tree head, pinning its size for the inclusion check.
    let (status, sth) = get_auth(&app, "/v1/transparency/sth", token).await;
    assert_eq!(status, StatusCode::OK);
    verify_sth_signature(&sth);
    let tree_size = sth["tree_size"].as_u64().unwrap();
    let root = hex32(sth["root_hash"].as_str().unwrap());
    assert!(tree_size >= 1);

    // Self-monitor: fetch this account's bindings PINNED to the STH size, so proofs verify against
    // the STH root even though other tests append to the shared log concurrently.
    let (status, view) = get_auth(
        &app,
        &format!("/v1/transparency/account/{account_hex}?tree_size={tree_size}"),
        token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["tree_size"].as_u64().unwrap(), tree_size);
    let bindings = view["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1, "exactly our one enrolled binding");
    let b = &bindings[0];
    assert_eq!(b["device_id"].as_str().unwrap(), device_hex);
    assert_eq!(
        b["public_key"].as_str().unwrap(),
        hex::encode(&device.public_key),
        "the logged key is exactly the key we enrolled (no substitution)"
    );

    // The inclusion proof verifies against the signed root at the pinned size.
    let entry = hex::decode(b["entry"].as_str().unwrap()).unwrap();
    let leaf = hash_leaf(&entry);
    let index = b["leaf_index"].as_u64().unwrap() as usize;
    let proof = proof_hashes(&b["proof"]);
    assert!(
        verify_inclusion(&leaf, index, tree_size as usize, &proof, &root),
        "our enrolled binding is included under the signed root"
    );
}

#[tokio::test]
async fn log_stays_append_only_across_growth() {
    let app = make_app(100_000).await;
    // A first user establishes an earlier STH.
    let (_d1, s1) = http_register(&app, &unique_username("kta")).await;
    let t1 = s1["access_token"].as_str().unwrap();
    let (_, sth_a) = get_auth(&app, "/v1/transparency/sth", t1).await;
    verify_sth_signature(&sth_a);
    let first = sth_a["tree_size"].as_u64().unwrap();
    let first_root = hex32(sth_a["root_hash"].as_str().unwrap());

    // More registrations grow the log.
    for _ in 0..3 {
        let _ = http_register(&app, &unique_username("ktb")).await;
    }
    let (_, sth_b) = get_auth(&app, "/v1/transparency/sth", t1).await;
    verify_sth_signature(&sth_b);
    let second = sth_b["tree_size"].as_u64().unwrap();
    let second_root = hex32(sth_b["root_hash"].as_str().unwrap());
    assert!(second >= first + 3);

    // The consistency proof between the two signed heads verifies (append-only, no history rewrite).
    let (status, cons) = get_auth(
        &app,
        &format!("/v1/transparency/consistency?first={first}&second={second}"),
        t1,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let proof = proof_hashes(&cons["proof"]);
    assert!(
        verify_consistency(
            first as usize,
            second as usize,
            &first_root,
            &second_root,
            &proof
        ),
        "the newer signed tree head extends the earlier one (append-only)"
    );

    // An out-of-range consistency request is a 400.
    let (status, _) = get_auth(
        &app,
        &format!(
            "/v1/transparency/consistency?first={}&second={first}",
            second + 100
        ),
        t1,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
