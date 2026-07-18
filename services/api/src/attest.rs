//! App Attest **attestation-object verification** (#10 gap closure).
//!
//! Apple's App Attest proves a request came from a genuine, unmodified build of this app on real
//! Apple hardware. The client submits a CBOR *attestation object*; this module performs the full
//! server-side verification Apple specifies (Apple: "Validating Apps That Connect to Your Server"):
//!
//! 1. **Certificate chain** — the `x5c` chain (credential cert → intermediate CA) verifies up to the
//!    pinned **Apple App Attestation Root CA** (fetched from Apple's CA page and embedded; SHA-256
//!    fingerprint `1CB9823B…42C932`, valid to 2045), with validity-window checks. ECDSA P-256/P-384
//!    with SHA-256/SHA-384, via vetted RustCrypto crates.
//! 2. **Nonce** — `SHA-256(authData ‖ clientDataHash)` must equal the value in the credential cert's
//!    Apple nonce extension (OID `1.2.840.113635.100.8.2`), binding the attestation to the server's
//!    single-use challenge.
//! 3. **Key id** — `SHA-256(credential public key)` must equal the key id the client claims.
//! 4. **authData** — RP ID hash = `SHA-256(app_id)` (Team ID.bundle-id), counter `0` at attestation,
//!    `aaguid` = `appattest` (production; `appattestdevelop` only if explicitly allowed), and the
//!    credential id must equal the key id.
//!
//! Everything here treats the input as hostile: bounded, typed, redacted errors, no panics.
//! **Honest limit:** this verifies real Apple attestations *when one is submitted* — producing one
//! still requires a physical device with the App Attest entitlement (the Simulator cannot).

use std::time::SystemTime;

use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::Certificate;

/// Apple's App Attestation Root CA (PEM), fetched from
/// `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem`.
pub const APPLE_APP_ATTEST_ROOT_PEM: &str = include_str!("apple_app_attest_root.pem");

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_EC_PUBKEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_APPLE_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.2");

/// Production aaguid: `"appattest"` padded with zero bytes to 16.
const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
/// Development-environment aaguid.
const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";

/// Upper bound on `x5c` chain length (Apple sends 2; bound hostile input).
const MAX_CHAIN_LEN: usize = 4;

/// Typed, redacted verification failure — carries no attacker-controlled bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestError {
    /// Not decodable CBOR / not the `apple-appattest` format shape.
    Cbor,
    /// Certificate parse / chain shape failure.
    Chain,
    /// A certificate is outside its validity window.
    Expired,
    /// A signature in the chain did not verify (or used an unsupported algorithm).
    Signature,
    /// The nonce extension is absent/malformed or does not match `SHA-256(authData ‖ cdh)`.
    Nonce,
    /// The credential key hash does not match the claimed key id.
    KeyId,
    /// authData is structurally invalid.
    AuthData,
    /// RP ID hash does not match the configured app id.
    AppId,
    /// The attestation counter is not zero.
    Counter,
    /// The aaguid is not the App Attest environment (or is development when not allowed).
    Aaguid,
}

/// Verifier configuration.
pub struct AttestationConfig {
    /// `TeamID.bundle.id` — hashed into authData's RP ID by the device.
    pub app_id: String,
    /// DER of the trust root (Apple's App Attest root in production; a test root in tests).
    pub root_der: Vec<u8>,
    /// Accept the `appattestdevelop` aaguid (development builds). Never enable in production.
    pub allow_development: bool,
}

impl AttestationConfig {
    /// From env: `SENTINEL_APP_ATTEST_APP_ID` (required — absent ⇒ verification disabled, `None`),
    /// `SENTINEL_APP_ATTEST_ROOT_PEM` (optional override; default = the embedded Apple root),
    /// `SENTINEL_APP_ATTEST_DEV` (accept development-environment attestations).
    pub fn from_env() -> Option<Self> {
        let app_id = std::env::var("SENTINEL_APP_ATTEST_APP_ID").ok()?;
        let pem = std::env::var("SENTINEL_APP_ATTEST_ROOT_PEM")
            .unwrap_or_else(|_| APPLE_APP_ATTEST_ROOT_PEM.to_string());
        let root = Certificate::from_pem(pem.as_bytes()).ok()?;
        let root_der = root.to_der().ok()?;
        let allow_development = std::env::var("SENTINEL_APP_ATTEST_DEV").is_ok();
        Some(Self {
            app_id,
            root_der,
            allow_development,
        })
    }
}

/// A successfully verified attestation.
#[derive(Debug)]
pub struct VerifiedAttestation {
    /// The attested credential public key (SEC1 uncompressed) — verifies later assertions.
    pub public_key_sec1: Vec<u8>,
}

/// Decode the key id the client submitted: Apple's `generateKey` returns base64; hex accepted too.
/// A key id is always `SHA-256(public key)` = exactly 32 bytes, which disambiguates the encodings
/// (a 64-char hex string is *also* valid base64 — but decodes to 48 bytes there, so length decides).
pub fn decode_key_id(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
        if bytes.len() == 32 {
            return Some(bytes);
        }
    }
    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == 32 {
            return Some(bytes);
        }
    }
    None
}

/// Verify an App Attest attestation object (see module docs for the steps).
pub fn verify_attestation(
    cbor: &[u8],
    expected_key_id: &[u8],
    client_data_hash: &[u8; 32],
    cfg: &AttestationConfig,
    now: SystemTime,
) -> Result<VerifiedAttestation, AttestError> {
    // ---- 0. CBOR shape -----------------------------------------------------------------------
    let (x5c, auth_data) = decode_attestation_cbor(cbor)?;

    // ---- 1. Certificate chain to the pinned root ---------------------------------------------
    if x5c.is_empty() || x5c.len() > MAX_CHAIN_LEN {
        return Err(AttestError::Chain);
    }
    let certs: Vec<Certificate> = x5c
        .iter()
        .map(|der| Certificate::from_der(der).map_err(|_| AttestError::Chain))
        .collect::<Result<_, _>>()?;
    let root = Certificate::from_der(&cfg.root_der).map_err(|_| AttestError::Chain)?;
    for (i, child) in certs.iter().enumerate() {
        check_validity(child, now)?;
        let parent = certs.get(i + 1).unwrap_or(&root);
        verify_cert_signature(child, parent)?;
    }

    // ---- 2. Nonce: SHA-256(authData ‖ clientDataHash) in the Apple extension ------------------
    let mut h = Sha256::new();
    h.update(&auth_data);
    h.update(client_data_hash);
    let expected_nonce: [u8; 32] = h.finalize().into();
    let cred_cert = &certs[0];
    let ext = cred_cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == OID_APPLE_NONCE))
        .ok_or(AttestError::Nonce)?;
    let nonce = parse_apple_nonce(ext.extn_value.as_bytes()).ok_or(AttestError::Nonce)?;
    if nonce != expected_nonce {
        return Err(AttestError::Nonce);
    }

    // ---- 3. Key id: SHA-256(credential public key) --------------------------------------------
    let cred_pk = cred_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let key_id: [u8; 32] = Sha256::digest(cred_pk).into();
    if key_id.as_slice() != expected_key_id {
        return Err(AttestError::KeyId);
    }

    // ---- 4. authData: rpIdHash / counter / aaguid / credentialId ------------------------------
    // Layout: rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ aaguid(16) ‖ credIdLen(2) ‖ credId.
    if auth_data.len() < 55 {
        return Err(AttestError::AuthData);
    }
    let rp_id_hash = &auth_data[..32];
    let expected_rp: [u8; 32] = Sha256::digest(cfg.app_id.as_bytes()).into();
    if rp_id_hash != expected_rp {
        return Err(AttestError::AppId);
    }
    let counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if counter != 0 {
        return Err(AttestError::Counter);
    }
    let aaguid: [u8; 16] = auth_data[37..53]
        .try_into()
        .map_err(|_| AttestError::AuthData)?;
    let aaguid_ok =
        aaguid == AAGUID_PRODUCTION || (cfg.allow_development && aaguid == AAGUID_DEVELOPMENT);
    if !aaguid_ok {
        return Err(AttestError::Aaguid);
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_len != 32 || auth_data.len() < 55 + cred_len {
        return Err(AttestError::AuthData);
    }
    if &auth_data[55..55 + cred_len] != key_id.as_slice() {
        return Err(AttestError::KeyId);
    }

    Ok(VerifiedAttestation {
        public_key_sec1: cred_pk.to_vec(),
    })
}

/// Decode the attestation object's CBOR: `{fmt: "apple-appattest", attStmt: {x5c: [..]}, authData}`.
fn decode_attestation_cbor(cbor: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<u8>), AttestError> {
    use ciborium::value::Value;
    let value: Value = ciborium::de::from_reader(cbor).map_err(|_| AttestError::Cbor)?;
    let Value::Map(entries) = value else {
        return Err(AttestError::Cbor);
    };
    let get = |key: &str| -> Option<&Value> {
        entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
            .map(|(_, v)| v)
    };
    match get("fmt") {
        Some(Value::Text(t)) if t == "apple-appattest" => {}
        _ => return Err(AttestError::Cbor),
    }
    let Some(Value::Bytes(auth_data)) = get("authData") else {
        return Err(AttestError::Cbor);
    };
    let Some(Value::Map(att_stmt)) = get("attStmt") else {
        return Err(AttestError::Cbor);
    };
    let x5c_value = att_stmt
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == "x5c"))
        .map(|(_, v)| v);
    let Some(Value::Array(x5c_items)) = x5c_value else {
        return Err(AttestError::Cbor);
    };
    let mut x5c = Vec::with_capacity(x5c_items.len());
    for item in x5c_items {
        let Value::Bytes(der) = item else {
            return Err(AttestError::Cbor);
        };
        x5c.push(der.clone());
    }
    Ok((x5c, auth_data.clone()))
}

/// `now` must be inside the certificate's validity window.
fn check_validity(cert: &Certificate, now: SystemTime) -> Result<(), AttestError> {
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_system_time();
    let not_after = validity.not_after.to_system_time();
    if now < not_before || now > not_after {
        return Err(AttestError::Expired);
    }
    Ok(())
}

/// Verify `child`'s signature under `parent`'s subject public key. ECDSA P-256/P-384 with
/// SHA-256/SHA-384 (the algorithms Apple's chain uses); anything else is refused.
fn verify_cert_signature(child: &Certificate, parent: &Certificate) -> Result<(), AttestError> {
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|_| AttestError::Signature)?;
    let sig_der = child.signature.as_bytes().ok_or(AttestError::Signature)?;

    let digest: Vec<u8> = match child.signature_algorithm.oid {
        oid if oid == OID_ECDSA_SHA256 => Sha256::digest(&tbs).to_vec(),
        oid if oid == OID_ECDSA_SHA384 => Sha384::digest(&tbs).to_vec(),
        _ => return Err(AttestError::Signature),
    };

    let spki = &parent.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != OID_EC_PUBKEY {
        return Err(AttestError::Signature);
    }
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(AttestError::Signature)?
        .decode_as()
        .map_err(|_| AttestError::Signature)?;
    let public_key = spki.subject_public_key.raw_bytes();

    match curve {
        oid if oid == OID_CURVE_P256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| AttestError::Signature)?;
            let sig =
                p256::ecdsa::Signature::from_der(sig_der).map_err(|_| AttestError::Signature)?;
            vk.verify_prehash(&digest, &sig)
                .map_err(|_| AttestError::Signature)
        }
        oid if oid == OID_CURVE_P384 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| AttestError::Signature)?;
            let sig =
                p384::ecdsa::Signature::from_der(sig_der).map_err(|_| AttestError::Signature)?;
            vk.verify_prehash(&digest, &sig)
                .map_err(|_| AttestError::Signature)
        }
        _ => Err(AttestError::Signature),
    }
}

/// Parse Apple's nonce extension content: `SEQUENCE { [1] { OCTET STRING(32) } }`. Short-form
/// lengths only (the content is 38 bytes), exact consumption, fail closed.
fn parse_apple_nonce(der: &[u8]) -> Option<[u8; 32]> {
    let inner = der_unwrap(der, 0x30)?; // SEQUENCE
    let inner = der_unwrap(inner, 0xA1)?; // [1] constructed
    let content = der_unwrap(inner, 0x04)?; // OCTET STRING
    if content.len() != 32 {
        return None;
    }
    content.try_into().ok()
}

/// Strip one short-form TLV layer with the expected tag, requiring exact consumption.
fn der_unwrap(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    if bytes.len() < 2 || bytes[0] != tag {
        return None;
    }
    let len = bytes[1] as usize;
    if len >= 0x80 || bytes.len() != 2 + len {
        return None; // long-form / trailing bytes: not the fixed Apple shape
    }
    Some(&bytes[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded pin is genuinely Apple's App Attestation root: parses, is the expected subject,
    /// and carries a P-384 key (as Apple's root does). Catches accidental corruption of the pin.
    #[test]
    fn embedded_apple_root_parses_and_matches_expectations() {
        let root = Certificate::from_pem(APPLE_APP_ATTEST_ROOT_PEM.as_bytes()).expect("parses");
        let subject = root.tbs_certificate.subject.to_string();
        assert!(
            subject.contains("Apple App Attestation Root CA"),
            "unexpected subject: {subject}"
        );
        let curve: ObjectIdentifier = root
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
            .as_ref()
            .expect("curve params")
            .decode_as()
            .expect("curve oid");
        assert_eq!(curve, OID_CURVE_P384, "Apple's root is P-384");
    }

    #[test]
    fn nonce_parser_is_exact() {
        let nonce = [0x5Au8; 32];
        let mut inner = vec![0x04, 0x20];
        inner.extend_from_slice(&nonce);
        let mut ctx = vec![0xA1, inner.len() as u8];
        ctx.extend_from_slice(&inner);
        let mut seq = vec![0x30, ctx.len() as u8];
        seq.extend_from_slice(&ctx);
        assert_eq!(parse_apple_nonce(&seq), Some(nonce));

        // Trailing byte / wrong tag / truncation all fail closed.
        let mut trailing = seq.clone();
        trailing.push(0);
        assert_eq!(parse_apple_nonce(&trailing), None);
        let mut wrong_tag = seq.clone();
        wrong_tag[0] = 0x31;
        assert_eq!(parse_apple_nonce(&wrong_tag), None);
        assert_eq!(parse_apple_nonce(&seq[..seq.len() - 1]), None);
    }

    #[test]
    fn key_id_decodes_base64_and_hex() {
        use base64::Engine;
        let raw = [0xABu8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(decode_key_id(&b64).unwrap(), raw);
        assert_eq!(decode_key_id(&hex::encode(raw)).unwrap(), raw);
        assert!(decode_key_id("!!not-a-key-id!!").is_none());
    }
}
