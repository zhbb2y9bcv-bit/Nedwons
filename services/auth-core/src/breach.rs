//! Compromised-credential check via a **k-anonymity range query** (R-305, NIST SP 800-63B-4).
//!
//! Neither the password nor its full hash ever leaves: only the first 5 hex characters of
//! `SHA-1(password)` go to the corpus provider, which returns every breached suffix sharing that
//! prefix, and membership is decided locally. The provider (bundled list, Bloom filter, or HTTP
//! range API) is injected via [`RangeProvider`].

use sha1::{Digest, Sha1};

/// The breach corpus could not be consulted (e.g. an external range API is unreachable). The
/// caller decides fail-open vs fail-closed; registration fails **open** (R-305).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreachUnavailable;

/// Supplies breached SHA-1 **suffixes** (uppercase hex, 35 chars) for a 5-hex-char prefix. The
/// full hash never leaves the caller.
pub trait RangeProvider {
    /// `Err(BreachUnavailable)` if the corpus cannot be consulted.
    fn suffixes(&self, prefix: &str) -> Result<Vec<String>, BreachUnavailable>;
}

/// `SHA-1(password)` as uppercase hex (40 chars) — the HIBP corpus format.
pub fn sha1_hex(password: &str) -> String {
    let digest = Sha1::digest(password.as_bytes());
    let mut s = String::with_capacity(40);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// `(first 5 chars, remaining 35)`.
pub fn split(hash_hex: &str) -> (String, String) {
    let prefix: String = hash_hex.chars().take(5).collect();
    let suffix: String = hash_hex.chars().skip(5).collect();
    (prefix, suffix)
}

/// Only the 5-char prefix is sent to `provider` (k-anonymity); suffix comparison is
/// case-insensitive.
pub fn is_compromised(
    provider: &dyn RangeProvider,
    password: &str,
) -> Result<bool, BreachUnavailable> {
    let hash = sha1_hex(password);
    let (prefix, suffix) = split(&hash);
    let suffixes = provider.suffixes(&prefix)?;
    Ok(suffixes.iter().any(|s| s.eq_ignore_ascii_case(&suffix)))
}

/// In-memory full SHA-1 hex hashes: a small bundled corpus and tests. Production layers a large
/// external corpus behind the same [`RangeProvider`].
pub struct StaticCorpus {
    hashes: std::collections::HashSet<String>,
}

impl StaticCorpus {
    /// Build from plaintext passwords (their SHA-1 hashes are precomputed).
    pub fn from_passwords(passwords: &[&str]) -> Self {
        Self {
            hashes: passwords.iter().map(|p| sha1_hex(p)).collect(),
        }
    }
}

impl RangeProvider for StaticCorpus {
    fn suffixes(&self, prefix: &str) -> Result<Vec<String>, BreachUnavailable> {
        let up = prefix.to_uppercase();
        Ok(self
            .hashes
            .iter()
            .filter(|h| h.starts_with(&up))
            .map(|h| h.chars().skip(5).collect())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_hex_matches_known_vector() {
        // The canonical HIBP example: SHA-1("password") = 5BAA6...
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
        let (p, s) = split(&sha1_hex("password"));
        assert_eq!(p, "5BAA6");
        assert_eq!(s, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn detects_a_compromised_password_and_clears_a_safe_one() {
        let corpus = StaticCorpus::from_passwords(&["password", "hunter2", "letmein"]);
        assert!(is_compromised(&corpus, "password").unwrap());
        assert!(is_compromised(&corpus, "hunter2").unwrap());
        // A password NOT in the corpus is cleared.
        assert!(!is_compromised(&corpus, "a-unique-unbreached-passphrase-9f3a").unwrap());
    }

    #[test]
    fn only_the_prefix_is_revealed() {
        // The provider is only ever asked for a 5-char prefix — assert we never pass more.
        struct Spy(std::cell::RefCell<Vec<String>>);
        impl RangeProvider for Spy {
            fn suffixes(&self, prefix: &str) -> Result<Vec<String>, BreachUnavailable> {
                self.0.borrow_mut().push(prefix.to_string());
                Ok(vec![])
            }
        }
        let spy = Spy(std::cell::RefCell::new(Vec::new()));
        let _ = is_compromised(&spy, "whatever-the-password-is");
        let seen = spy.0.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].len(),
            5,
            "only the 5-char prefix is sent to the provider"
        );
    }

    #[test]
    fn provider_error_propagates() {
        struct Down;
        impl RangeProvider for Down {
            fn suffixes(&self, _: &str) -> Result<Vec<String>, BreachUnavailable> {
                Err(BreachUnavailable)
            }
        }
        assert!(is_compromised(&Down, "password").is_err());
    }
}
