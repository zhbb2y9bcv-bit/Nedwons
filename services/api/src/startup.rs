//! Production readiness checks: refuse to start rather than start insecurely.
//!
//! Every security control in this service was opt-in with a permissive default, which is the right
//! choice during development and the wrong one in production. A deployment that simply forgot an
//! environment variable would come up **looking healthy** while silently:
//!
//! * minting an EPHEMERAL transparency-log key, so every client's pinned key and every key-
//!   transparency audit breaks on each restart;
//! * minting an ephemeral sender-certificate key, invalidating issued sealed-sender certificates;
//! * hashing passwords with no server-side pepper, so a database leak is offline-crackable;
//! * accepting bearer tokens with no device proof, so a stolen token alone is enough;
//! * storing App Attest attestations unverified;
//! * trusting a forwarded client-IP header nobody sets, or ignoring one a proxy does set — either
//!   way rate limiting keys on the wrong address.
//!
//! None of those announce themselves at runtime. So in production they are requirements, checked
//! once at startup and reported TOGETHER (a deployment should learn about all its gaps in one
//! restart, not one per restart).
//!
//! Development is unchanged: absent `NEDWONS_ENV=production`, every default stays as it was.

/// How the process reads configuration. A parameter rather than `std::env` directly, so the rules
/// can be tested without mutating process-global state — environment variables are shared between
/// concurrently running tests, and a test that sets one is a test that flakes another.
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;

    fn present(&self, key: &str) -> bool {
        self.get(key).map(|v| !v.trim().is_empty()).unwrap_or(false)
    }

    fn is_true(&self, key: &str) -> bool {
        self.get(key)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }
}

/// Reads the real process environment.
pub struct SystemEnv;

impl EnvSource for SystemEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Configuration resolved against the deployment's mode.
pub struct Readiness {
    pub production: bool,
    /// Fatal in production. Empty means the process may start.
    pub errors: Vec<String>,
    /// Worth saying out loud, never fatal.
    pub warnings: Vec<String>,
    /// The effective proof-enforcement decision: ON by default in production.
    pub require_proof: bool,
}

impl Readiness {
    pub fn is_ready(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Evaluate the deployment's configuration.
///
/// In production every listed control must be configured explicitly. Where a control can be
/// legitimately declined, declining is allowed — but it must be SAID, via an explicit opt-out,
/// so that "we accepted this risk" and "we forgot" stop looking identical from the outside.
pub fn evaluate(env: &impl EnvSource) -> Readiness {
    let production = env
        .get("NEDWONS_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Proofs default ON in production. Turning them off is possible but must be deliberate, and
    // it is loud, because it downgrades a stolen access token from inert to sufficient.
    let proof_explicit = env.get("NEDWONS_REQUIRE_PROOF");
    let require_proof = match proof_explicit.as_deref() {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
        Some(_) if production => {
            warnings.push(
                "NEDWONS_REQUIRE_PROOF is explicitly disabled in production: a stolen access \
                 token alone is sufficient to act as the user (ADR-0011)"
                    .into(),
            );
            false
        }
        Some(_) => false,
        None => production,
    };

    if !production {
        return Readiness {
            production,
            errors,
            warnings,
            require_proof,
        };
    }

    for (key, why) in [
        (
            "NEDWONS_LOG_SIGNING_KEY",
            "without it the transparency log is signed by an EPHEMERAL key regenerated on every \
             restart, breaking client key pinning and every key-transparency audit",
        ),
        (
            "NEDWONS_SENDER_CERT_KEY",
            "without it sealed-sender certificates are signed by an ephemeral key, so previously \
             issued certificates stop verifying after a restart (ADR-0012)",
        ),
        (
            "NEDWONS_PASSWORD_PEPPER",
            "without it password hashes carry no server-side secret, so a database leak is \
             offline-crackable (R-303)",
        ),
        (
            "NEDWONS_APP_ATTEST_APP_ID",
            "without it App Attest attestations are stored UNVERIFIED, so device assurance is \
             self-asserted (ADR-0017)",
        ),
    ] {
        if !env.present(key) {
            errors.push(format!("{key} is required in production: {why}"));
        }
    }

    // Push is all-or-nothing: a half-configured APNs is worse than none, because delivery appears
    // to work while wake pushes silently fail.
    let apns_key = env.present("NEDWONS_APNS_KEY_P8") || env.present("NEDWONS_APNS_KEY_HEX");
    let apns_fields = [
        ("NEDWONS_APNS_KEY_ID", env.present("NEDWONS_APNS_KEY_ID")),
        ("NEDWONS_APNS_TEAM_ID", env.present("NEDWONS_APNS_TEAM_ID")),
        ("NEDWONS_APNS_TOPIC", env.present("NEDWONS_APNS_TOPIC")),
    ];
    let any_apns = apns_key || apns_fields.iter().any(|(_, present)| *present);
    if any_apns {
        if !apns_key {
            errors.push(
                "APNs is partially configured: set NEDWONS_APNS_KEY_P8 or NEDWONS_APNS_KEY_HEX"
                    .into(),
            );
        }
        for (key, present) in apns_fields {
            if !present {
                errors.push(format!("APNs is partially configured: {key} is missing"));
            }
        }
    } else if !env.is_true("NEDWONS_ALLOW_NO_PUSH") {
        errors.push(
            "no APNs configuration in production: devices can never be woken, so messages arrive \
             only while the app is foregrounded. Configure NEDWONS_APNS_* or set \
             NEDWONS_ALLOW_NO_PUSH=1 to accept this deliberately"
                .into(),
        );
    }

    // Rate limiting keys on the client IP, so the deployment must say where that comes from.
    // Guessing is what makes a limiter either trivially evadable or trivially abusable.
    if !env.present("NEDWONS_TRUSTED_IP_HEADER") && !env.is_true("NEDWONS_ALLOW_DIRECT_PEER_IP") {
        errors.push(
            "the client-IP source is unspecified in production: set NEDWONS_TRUSTED_IP_HEADER \
             when behind a proxy that overwrites it on every request, or \
             NEDWONS_ALLOW_DIRECT_PEER_IP=1 when the service is exposed directly. Reading a \
             forwarded header nobody sets lets a client forge its own rate-limit key (R-306)"
                .into(),
        );
    }
    if env.present("NEDWONS_TRUSTED_IP_HEADER") && env.is_true("NEDWONS_ALLOW_DIRECT_PEER_IP") {
        errors.push(
            "NEDWONS_TRUSTED_IP_HEADER and NEDWONS_ALLOW_DIRECT_PEER_IP are both set: these \
             describe mutually exclusive deployments"
                .into(),
        );
    }

    if env.is_true("NEDWONS_APP_ATTEST_DEV") {
        errors.push(
            "NEDWONS_APP_ATTEST_DEV accepts DEVELOPMENT App Attest attestations and must never be \
             set in production"
                .into(),
        );
    }

    if !env.is_true("NEDWONS_REQUIRE_HARDWARE_APPROVER") {
        warnings.push(
            "NEDWONS_REQUIRE_HARDWARE_APPROVER is off: a software-assurance device may authorize \
             enrollment of another device (ADR-0017)"
                .into(),
        );
    }

    Readiness {
        production,
        errors,
        warnings,
        require_proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeEnv(HashMap<String, String>);

    impl FakeEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }

    impl EnvSource for FakeEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    /// A fully configured production deployment.
    fn complete() -> Vec<(&'static str, &'static str)> {
        vec![
            ("NEDWONS_ENV", "production"),
            ("NEDWONS_LOG_SIGNING_KEY", "ab".repeat(32).leak()),
            ("NEDWONS_SENDER_CERT_KEY", "cd".repeat(32).leak()),
            ("NEDWONS_PASSWORD_PEPPER", "a-real-pepper"),
            ("NEDWONS_APP_ATTEST_APP_ID", "ABCDE12345.app.nedwons"),
            ("NEDWONS_APNS_KEY_P8", "-----BEGIN PRIVATE KEY-----"),
            ("NEDWONS_APNS_KEY_ID", "KEYID12345"),
            ("NEDWONS_APNS_TEAM_ID", "TEAMID1234"),
            ("NEDWONS_APNS_TOPIC", "app.nedwons"),
            ("NEDWONS_TRUSTED_IP_HEADER", "x-real-client-ip"),
        ]
    }

    #[test]
    fn development_keeps_every_permissive_default() {
        let r = evaluate(&FakeEnv::new(&[]));
        assert!(!r.production);
        assert!(
            r.is_ready(),
            "development must not be gated: {:?}",
            r.errors
        );
        assert!(!r.require_proof, "proofs stay opt-in outside production");
    }

    #[test]
    fn a_complete_production_configuration_starts() {
        let r = evaluate(&FakeEnv::new(&complete()));
        assert!(r.is_ready(), "unexpected errors: {:?}", r.errors);
        assert!(
            r.require_proof,
            "proofs are required by default in production"
        );
    }

    #[test]
    fn production_refuses_to_start_without_stable_keys() {
        for missing in [
            "NEDWONS_LOG_SIGNING_KEY",
            "NEDWONS_SENDER_CERT_KEY",
            "NEDWONS_PASSWORD_PEPPER",
            "NEDWONS_APP_ATTEST_APP_ID",
        ] {
            let pairs: Vec<_> = complete()
                .into_iter()
                .filter(|(k, _)| *k != missing)
                .collect();
            let r = evaluate(&FakeEnv::new(&pairs));
            assert!(!r.is_ready(), "{missing} must be required in production");
            assert!(
                r.errors.iter().any(|e| e.contains(missing)),
                "the error should name {missing}: {:?}",
                r.errors
            );
        }
    }

    #[test]
    fn every_gap_is_reported_at_once() {
        let r = evaluate(&FakeEnv::new(&[("NEDWONS_ENV", "production")]));
        assert!(
            r.errors.len() >= 5,
            "a misconfigured deployment should learn all its gaps in one restart: {:?}",
            r.errors
        );
    }

    #[test]
    fn a_half_configured_apns_is_refused() {
        let mut pairs = complete();
        pairs.retain(|(k, _)| *k != "NEDWONS_APNS_KEY_ID");
        let r = evaluate(&FakeEnv::new(&pairs));
        assert!(!r.is_ready(), "partial APNs config must not start");
        assert!(r.errors.iter().any(|e| e.contains("NEDWONS_APNS_KEY_ID")));
    }

    /// Declining push is allowed — but it has to be said.
    #[test]
    fn push_may_be_declined_explicitly() {
        let mut pairs: Vec<_> = complete()
            .into_iter()
            .filter(|(k, _)| !k.starts_with("NEDWONS_APNS_"))
            .collect();
        let r = evaluate(&FakeEnv::new(&pairs));
        assert!(!r.is_ready(), "silently having no push must be refused");

        pairs.push(("NEDWONS_ALLOW_NO_PUSH", "1"));
        let r = evaluate(&FakeEnv::new(&pairs));
        assert!(
            r.is_ready(),
            "an explicit opt-out is accepted: {:?}",
            r.errors
        );
    }

    #[test]
    fn the_client_ip_source_must_be_stated() {
        let mut pairs: Vec<_> = complete()
            .into_iter()
            .filter(|(k, _)| *k != "NEDWONS_TRUSTED_IP_HEADER")
            .collect();
        let r = evaluate(&FakeEnv::new(&pairs));
        assert!(!r.is_ready(), "an unspecified IP source must be refused");

        pairs.push(("NEDWONS_ALLOW_DIRECT_PEER_IP", "1"));
        assert!(evaluate(&FakeEnv::new(&pairs)).is_ready());

        // Both at once describes two different deployments.
        let mut both = complete();
        both.push(("NEDWONS_ALLOW_DIRECT_PEER_IP", "1"));
        assert!(!evaluate(&FakeEnv::new(&both)).is_ready());
    }

    #[test]
    fn development_app_attest_is_refused_in_production() {
        let mut pairs = complete();
        pairs.push(("NEDWONS_APP_ATTEST_DEV", "1"));
        let r = evaluate(&FakeEnv::new(&pairs));
        assert!(!r.is_ready());
        assert!(r
            .errors
            .iter()
            .any(|e| e.contains("NEDWONS_APP_ATTEST_DEV")));
    }

    /// Disabling proofs in production is permitted but must be audible.
    #[test]
    fn disabling_proofs_in_production_warns_loudly() {
        let mut pairs = complete();
        pairs.push(("NEDWONS_REQUIRE_PROOF", "0"));
        let r = evaluate(&FakeEnv::new(&pairs));
        assert!(!r.require_proof);
        assert!(r.is_ready(), "it is a warning, not a refusal");
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("NEDWONS_REQUIRE_PROOF")));
    }
}
