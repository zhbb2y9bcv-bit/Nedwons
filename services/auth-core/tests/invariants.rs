//! Security regression tests. Each maps to an invariant in THREAT_MODEL.md. These prove
//! the *logic*; the PostgreSQL implementations of the store traits must preserve the same
//! atomicity (ADR-0006) and get their own concurrency tests later.

use std::sync::Arc;

use auth_core::crypto::sha256;
use auth_core::memstore::{
    MemAccountStore, MemChallengeStore, MemRefreshStore, MemSessionStore, MockClock,
};
use auth_core::transcript::Transcript;
use auth_core::{
    refresh_txn_id, AccountId, Action, AuthError, AuthService, Config, DeviceId, RegisterRequest,
    Session,
};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;

const PASSWORD: &str = "correct horse battery staple stitch";

/// A test stand-in for a real device: it holds the private key that, in production, lives
/// non-exportably in the Secure Enclave. The service only ever sees `public_key`.
struct TestDevice {
    signing_key: SigningKey,
    public_key: Vec<u8>,
}

impl TestDevice {
    fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }
}

fn make_service() -> (AuthService, Arc<MockClock>) {
    let clock = Arc::new(MockClock::new(1_000_000));
    // One MemAccountStore serves as both CredentialStore and DeviceStore, mirroring the
    // single-transaction account+device creation the SQL schema provides.
    let accounts = Arc::new(MemAccountStore::default());
    let service = AuthService::new(
        accounts.clone(),
        accounts,
        Arc::new(MemChallengeStore::default()),
        Arc::new(MemRefreshStore::default()),
        Arc::new(MemSessionStore::default()),
        clock.clone(),
        Config::default(),
    );
    (service, clock)
}

/// Register an account and return the (real) device that enrolled it.
fn register(service: &AuthService, username: &str) -> (TestDevice, Session) {
    let device = TestDevice::new();
    let challenge = service
        .register_begin()
        .expect("register_begin should succeed");
    let transcript = Transcript {
        action: Action::Register,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());
    let session = service
        .register_finish(RegisterRequest {
            username: username.to_string(),
            password: PASSWORD.to_string(),
            device_public_key: device.public_key.clone(),
            txn_id: challenge.txn_id,
            signature,
        })
        .expect("registration should succeed");
    (device, session)
}

/// Perform a full login with the given device, returning the finish result.
fn login(
    service: &AuthService,
    device: &TestDevice,
    username: &str,
    password: &str,
) -> Result<Session, AuthError> {
    let challenge = service.login_begin(username, password);
    let transcript = Transcript {
        action: Action::Login,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());
    service.login_finish(&challenge.txn_id, &signature)
}

fn sign_refresh(
    device: &TestDevice,
    account_id: &AccountId,
    device_id: &DeviceId,
    refresh_token: &[u8],
) -> Vec<u8> {
    let old_hash = sha256(refresh_token);
    let txn_id = refresh_txn_id(&old_hash);
    let transcript = Transcript {
        action: Action::Refresh,
        account_id,
        device_id,
        public_key: &device.public_key,
        challenge: &old_hash,
        expires_at: 0,
        txn_id: &txn_id,
    };
    device.sign(&transcript.encode())
}

/// `Session` has no `PartialEq`/`Debug` on purpose (tokens must never be formatted into
/// logs), so we assert the denied case by pattern rather than `assert_eq!`.
fn assert_denied(result: Result<Session, AuthError>) {
    assert!(
        matches!(result, Err(AuthError::Denied)),
        "expected AuthError::Denied"
    );
}

// --------------------------------------------------------------------------------------

#[test]
fn full_login_succeeds_with_the_enrolled_device() {
    let (service, _clock) = make_service();
    let (device, reg_session) = register(&service, "alice");

    let session = login(&service, &device, "alice", PASSWORD).expect("login should succeed");
    assert_eq!(session.account_id, reg_session.account_id);
    assert!(!session.access_token.is_empty());
    assert!(!session.refresh_token.is_empty());
}

/// INV-2: username + password from a device WITHOUT the enrolled private key cannot log in.
#[test]
fn login_denied_without_the_device_key() {
    let (service, _clock) = make_service();
    let _ = register(&service, "alice");

    // The attacker knows the correct username and password, and login_begin returns a real
    // challenge (credentials are valid). But the attacker signs with a *different* key.
    let attacker = TestDevice::new();
    let result = login(&service, &attacker, "alice", PASSWORD);
    assert_denied(result);
}

/// INV-2 (companion): a wrong password is also denied — and reveals nothing more than the
/// device-key failure does.
#[test]
fn login_denied_with_wrong_password() {
    let (service, _clock) = make_service();
    let (device, _) = register(&service, "alice");
    let result = login(&service, &device, "alice", "not the password");
    assert_denied(result);
}

/// INV-4: a challenge is single-use. Replaying a completed login is denied.
#[test]
fn challenge_is_single_use() {
    let (service, _clock) = make_service();
    let (device, _) = register(&service, "alice");

    let challenge = service.login_begin("alice", PASSWORD);
    let transcript = Transcript {
        action: Action::Login,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());

    // First use succeeds.
    assert!(service.login_finish(&challenge.txn_id, &signature).is_ok());
    // Replay of the same challenge + signature is denied (challenge consumed).
    assert_denied(service.login_finish(&challenge.txn_id, &signature));
}

/// INV-4: an expired challenge is denied.
#[test]
fn expired_challenge_is_denied() {
    let (service, clock) = make_service();
    let (device, _) = register(&service, "alice");

    let challenge = service.login_begin("alice", PASSWORD);
    // Move time past the challenge TTL (default 120s).
    clock.advance(Config::default().challenge_ttl_secs + 1);

    let transcript = Transcript {
        action: Action::Login,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());
    assert_denied(service.login_finish(&challenge.txn_id, &signature));
}

/// INV-4: challenges are action-bound. A `Register` challenge cannot be redeemed at the
/// login endpoint even with a valid signature over it.
#[test]
fn challenge_is_action_bound() {
    let (service, _clock) = make_service();
    let device = TestDevice::new();

    // A fresh, unconsumed Register challenge.
    let reg = service.register_begin().expect("begin should succeed");
    let transcript = Transcript {
        action: Action::Register,
        account_id: &reg.account_id,
        device_id: &reg.device_id,
        public_key: &device.public_key,
        challenge: &reg.nonce,
        expires_at: reg.expires_at,
        txn_id: &reg.txn_id,
    };
    let signature = device.sign(&transcript.encode());

    // Redeeming it at login_finish must fail: the stored challenge's action is Register.
    assert_denied(service.login_finish(&reg.txn_id, &signature));
}

/// INV-4: challenges are device-bound. A second enrolled device (bob's) cannot satisfy a
/// challenge issued for alice's device.
#[test]
fn challenge_is_device_bound() {
    let (service, _clock) = make_service();
    let (_alice_device, _) = register(&service, "alice");
    let (bob_device, _) = register(&service, "bob");

    // alice's login challenge, signed by bob's device key.
    let challenge = service.login_begin("alice", PASSWORD);
    let transcript = Transcript {
        action: Action::Login,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &bob_device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = bob_device.sign(&transcript.encode());
    assert_denied(service.login_finish(&challenge.txn_id, &signature));
}

/// Refresh rotates the token, and reuse of a retired token revokes the whole family.
#[test]
fn refresh_rotates_and_reuse_revokes_family() {
    let (service, _clock) = make_service();
    let (device, session0) = register(&service, "alice");

    // Rotate once: R0 -> R1.
    let sig0 = sign_refresh(
        &device,
        &session0.account_id,
        &session0.device_id,
        &session0.refresh_token,
    );
    let session1 = service
        .refresh(&session0.refresh_token, &sig0)
        .expect("first refresh should succeed");
    assert_ne!(session0.refresh_token, session1.refresh_token);

    // Reuse the retired R0 again -> reuse detected -> family revoked.
    let sig0_again = sign_refresh(
        &device,
        &session0.account_id,
        &session0.device_id,
        &session0.refresh_token,
    );
    assert_denied(service.refresh(&session0.refresh_token, &sig0_again));

    // Because the family is now revoked, even the current R1 no longer works.
    let sig1 = sign_refresh(
        &device,
        &session1.account_id,
        &session1.device_id,
        &session1.refresh_token,
    );
    assert_denied(service.refresh(&session1.refresh_token, &sig1));
}

/// INV-2 for refresh: a stolen bearer token WITHOUT the device key cannot refresh, and a
/// failed bearer attempt must NOT revoke the victim's family (no denial-of-service).
#[test]
fn refresh_requires_device_signature_and_failed_attempt_is_not_dos() {
    let (service, _clock) = make_service();
    let (device, session) = register(&service, "alice");

    // Attacker has the refresh token but signs with the wrong key.
    let attacker = TestDevice::new();
    let bad_sig = sign_refresh(
        &attacker,
        &session.account_id,
        &session.device_id,
        &session.refresh_token,
    );
    assert_denied(service.refresh(&session.refresh_token, &bad_sig));

    // The legitimate device can still refresh — its family was not burned by the attacker.
    let good_sig = sign_refresh(
        &device,
        &session.account_id,
        &session.device_id,
        &session.refresh_token,
    );
    assert!(service.refresh(&session.refresh_token, &good_sig).is_ok());
}

/// INV-10: revoking a device denies future logins and refreshes from it.
#[test]
fn device_revocation_fails_closed() {
    let (service, _clock) = make_service();
    let (device, session) = register(&service, "alice");

    // Sanity: login works before revocation.
    assert!(login(&service, &device, "alice", PASSWORD).is_ok());

    service
        .revoke_device(&session.device_id)
        .expect("revocation should succeed");

    // After revocation there is no active device, so login is denied.
    assert_denied(login(&service, &device, "alice", PASSWORD));

    // And the existing refresh token no longer works.
    let sig = sign_refresh(
        &device,
        &session.account_id,
        &session.device_id,
        &session.refresh_token,
    );
    assert_denied(service.refresh(&session.refresh_token, &sig));
}

/// The begin step does not reveal account existence: a nonexistent user still gets a
/// well-formed challenge (an unstored decoy), not an error.
#[test]
fn login_begin_does_not_leak_account_existence() {
    let (service, _clock) = make_service();
    let _ = register(&service, "alice");

    // Nonexistent account -> still a challenge (decoy), and finishing it is denied.
    let decoy = service.login_begin("nobody", PASSWORD);
    let attacker = TestDevice::new();
    let transcript = Transcript {
        action: Action::Login,
        account_id: &decoy.account_id,
        device_id: &decoy.device_id,
        public_key: &attacker.public_key,
        challenge: &decoy.nonce,
        expires_at: decoy.expires_at,
        txn_id: &decoy.txn_id,
    };
    let signature = attacker.sign(&transcript.encode());
    assert_denied(service.login_finish(&decoy.txn_id, &signature));
}

/// The canonical transcript is unambiguous: length prefixes prevent field-splitting
/// collisions between distinct field vectors.
#[test]
fn transcript_encoding_is_unambiguous() {
    let a = AccountId([1u8; 16]);
    let b = DeviceId([2u8; 16]);
    let txn = auth_core::TxnId([3u8; 16]);
    let nonce = [9u8; 32];

    let t1 = Transcript {
        action: Action::Login,
        account_id: &a,
        device_id: &b,
        public_key: b"ABC",
        challenge: &nonce,
        expires_at: 42,
        txn_id: &txn,
    }
    .encode();

    // Move one byte from the public key into the challenge boundary region; without length
    // prefixes these could collide. With them, they must differ.
    let t2 = Transcript {
        action: Action::Login,
        account_id: &a,
        device_id: &b,
        public_key: b"AB",
        challenge: &nonce,
        expires_at: 42,
        txn_id: &txn,
    }
    .encode();

    assert_ne!(t1, t2);

    // Changing only the action changes the bytes (purpose binding).
    let t3 = Transcript {
        action: Action::Register,
        account_id: &a,
        device_id: &b,
        public_key: b"ABC",
        challenge: &nonce,
        expires_at: 42,
        txn_id: &txn,
    }
    .encode();
    assert_ne!(t1, t3);
}

/// Access tokens validate while fresh, expire on TTL, and die with logout and device
/// revocation (INV-10).
#[test]
fn access_token_lifecycle() {
    let (service, clock) = make_service();
    let (_device, session) = register(&service, "alice");

    // Fresh token validates and maps to the right account/device.
    let who = service
        .validate_access(&session.access_token)
        .expect("fresh access token should validate");
    assert_eq!(who.account_id, session.account_id);
    assert_eq!(who.device_id, session.device_id);

    // Expired token is denied.
    clock.advance(Config::default().access_ttl_secs + 1);
    assert!(matches!(
        service.validate_access(&session.access_token),
        Err(AuthError::Denied)
    ));
}

#[test]
fn logout_revokes_access_and_refresh() {
    let (service, _clock) = make_service();
    let (device, session) = register(&service, "alice");

    service.logout(&session.refresh_token).expect("logout ok");

    // Access token no longer validates.
    assert!(matches!(
        service.validate_access(&session.access_token),
        Err(AuthError::Denied)
    ));
    // Refresh family is revoked.
    let sig = sign_refresh(
        &device,
        &session.account_id,
        &session.device_id,
        &session.refresh_token,
    );
    assert_denied(service.refresh(&session.refresh_token, &sig));
}

#[test]
fn device_revocation_kills_access_tokens() {
    let (service, _clock) = make_service();
    let (_device, session) = register(&service, "alice");

    service
        .revoke_device(&session.device_id)
        .expect("revocation should succeed");
    assert!(matches!(
        service.validate_access(&session.access_token),
        Err(AuthError::Denied)
    ));
}

/// NIST-aligned password policy: length floor, generous ceiling, common-password blocklist.
#[test]
fn weak_passwords_are_rejected_at_registration() {
    let (service, _clock) = make_service();
    let device = TestDevice::new();
    let challenge = service.register_begin().expect("begin ok");
    let transcript = Transcript {
        action: Action::Register,
        account_id: &challenge.account_id,
        device_id: &challenge.device_id,
        public_key: &device.public_key,
        challenge: &challenge.nonce,
        expires_at: challenge.expires_at,
        txn_id: &challenge.txn_id,
    };
    let signature = device.sign(&transcript.encode());
    let result = service.register_finish(RegisterRequest {
        username: "alice".into(),
        password: "password1234".into(), // on the blocklist
        device_public_key: device.public_key.clone(),
        txn_id: challenge.txn_id,
        signature,
    });
    assert!(matches!(result, Err(AuthError::WeakPassword)));

    // Short passwords fail the policy check directly.
    assert!(matches!(
        auth_core::password::validate_password_policy("short11"),
        Err(AuthError::WeakPassword)
    ));
    // A long passphrase is fine.
    assert!(auth_core::password::validate_password_policy("battery staple orbit lantern").is_ok());
}

#[test]
fn username_normalization_rejects_confusables_and_bad_shapes() {
    use auth_core::normalize_username;

    // Valid.
    assert_eq!(normalize_username("Alice").unwrap(), "alice");
    assert_eq!(normalize_username("bob_2.0").unwrap(), "bob_2.0");

    // Casing collision maps to the same normalized identity.
    assert_eq!(
        normalize_username("ALICE").unwrap(),
        normalize_username("alice").unwrap()
    );

    // Rejected: too short, leading non-letter, zero-width/invisible, non-ASCII homoglyph,
    // double dot, trailing dot, whitespace injection.
    assert!(normalize_username("ab").is_err());
    assert!(normalize_username("1abc").is_err());
    assert!(normalize_username("ali\u{200b}ce").is_err()); // zero-width space
    assert!(normalize_username("аlice").is_err()); // Cyrillic 'а'
    assert!(normalize_username("a..b").is_err());
    assert!(normalize_username("alice.").is_err());
    assert!(normalize_username("alice bob").is_err());
}

// ----- Trusted-device enrollment (ADR-0008 / R-903) ---------------------------------------

use auth_core::store::AccountDevice;
use auth_core::{EnrollChallenge, EnrollRequest};

/// Enroll `new_device` onto the trusted device's account. Returns the provisioned session.
fn enroll(
    service: &AuthService,
    trusted: &AccountDevice,
    trusted_signer: &TestDevice,
    new_device: &TestDevice,
) -> Result<Session, AuthError> {
    let ch: EnrollChallenge = service.enroll_device_begin(trusted)?;
    // The TRUSTED device signs a DeviceEnroll transcript authorizing the NEW device's key.
    let transcript = Transcript {
        action: Action::DeviceEnroll,
        account_id: &trusted.account_id,
        device_id: &ch.device_id,
        public_key: &new_device.public_key,
        challenge: &ch.nonce,
        expires_at: ch.expires_at,
        txn_id: &ch.txn_id,
    };
    let signature = trusted_signer.sign(&transcript.encode());
    service.enroll_device_finish(
        trusted,
        EnrollRequest {
            txn_id: ch.txn_id,
            device_public_key: new_device.public_key.clone(),
            signature,
        },
    )
}

#[test]
fn trusted_device_enrolls_a_second_device_and_it_gets_a_working_session() {
    let (service, _clock) = make_service();
    let (device_a, reg) = register(&service, "multi_device_user");
    let trusted = AccountDevice {
        account_id: reg.account_id,
        device_id: reg.device_id,
    };

    let device_b = TestDevice::new();
    let session_b = enroll(&service, &trusted, &device_a, &device_b).expect("enroll succeeds");

    // The new device is on the SAME account but a DISTINCT device, with a working session.
    assert_eq!(session_b.account_id, reg.account_id);
    assert_ne!(session_b.device_id, reg.device_id);
    let bound = service
        .validate_access(&session_b.access_token)
        .expect("new device's session is valid");
    assert_eq!(bound.device_id, session_b.device_id);

    // Both devices are now active and listed.
    let devices = service.list_devices(&reg.account_id).expect("list");
    let active: Vec<_> = devices.iter().filter(|d| !d.revoked).collect();
    assert_eq!(active.len(), 2, "two active devices after enrollment");
}

#[test]
fn enrollment_requires_the_trusted_device_signature() {
    let (service, _clock) = make_service();
    let (_device_a, reg) = register(&service, "enroll_badsig");
    let trusted = AccountDevice {
        account_id: reg.account_id,
        device_id: reg.device_id,
    };
    // An attacker signs with a key that is NOT the trusted device's enrolled key.
    let attacker = TestDevice::new();
    let new_device = TestDevice::new();
    assert!(matches!(
        enroll(&service, &trusted, &attacker, &new_device),
        Err(AuthError::Denied)
    ));
    // No device was added.
    assert_eq!(service.list_devices(&reg.account_id).unwrap().len(), 1);
}

#[test]
fn revoked_device_cannot_authorize_enrollment() {
    let (service, _clock) = make_service();
    let (device_a, reg) = register(&service, "enroll_revoked");
    let trusted = AccountDevice {
        account_id: reg.account_id,
        device_id: reg.device_id,
    };
    service.revoke_device(&reg.device_id).expect("revoke");
    let new_device = TestDevice::new();
    // begin already fails closed for a revoked authorizer.
    assert!(matches!(
        enroll(&service, &trusted, &device_a, &new_device),
        Err(AuthError::Denied)
    ));
}

#[test]
fn enrollment_is_capped_and_revoke_cascades() {
    let (service, _clock) = make_service();
    let (device_a, reg) = register(&service, "enroll_cap");
    let trusted = AccountDevice {
        account_id: reg.account_id,
        device_id: reg.device_id,
    };

    // Fill up to the cap (device A already counts as one).
    let mut sessions = Vec::new();
    for _ in 1..AuthService::MAX_ACTIVE_DEVICES {
        let d = TestDevice::new();
        sessions.push(enroll(&service, &trusted, &device_a, &d).expect("under cap"));
    }
    let at_cap = service.list_devices(&reg.account_id).unwrap();
    assert_eq!(
        at_cap.iter().filter(|d| !d.revoked).count(),
        AuthService::MAX_ACTIVE_DEVICES
    );
    // One more is refused.
    let extra = TestDevice::new();
    assert!(matches!(
        enroll(&service, &trusted, &device_a, &extra),
        Err(AuthError::Denied)
    ));

    // Revoking an enrolled device invalidates its session AND frees a slot.
    let victim = &sessions[0];
    service.revoke_device(&victim.device_id).expect("revoke");
    assert!(service.validate_access(&victim.access_token).is_err());
    let after = service.list_devices(&reg.account_id).unwrap();
    assert_eq!(
        after.iter().filter(|d| !d.revoked).count(),
        AuthService::MAX_ACTIVE_DEVICES - 1
    );
    // A slot is free again.
    let replacement = TestDevice::new();
    assert!(enroll(&service, &trusted, &device_a, &replacement).is_ok());
}
