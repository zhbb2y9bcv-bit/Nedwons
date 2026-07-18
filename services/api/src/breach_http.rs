//! HTTP k-anonymity breach provider (R-305) — the transport-agnostic half.
//!
//! [`auth_core::breach`] defines the pure k-anonymity protocol and the [`RangeProvider`] seam; the
//! bundled [`auth_core::breach::StaticCorpus`] backs it today. This module adds the **HIBP range
//! API** shape (`https://api.pwnedpasswords.com/range/{prefix}` returns `SUFFIX:COUNT` lines for the
//! 35-hex suffix that follows the 5-hex prefix), split into:
//!
//! 1. [`hibp_range_url`] + [`parse_hibp_range`] — pure, fully tested string logic, and
//! 2. [`HttpRangeProvider`] — a [`RangeProvider`] whose actual network fetch is an **injected
//!    closure**, so this crate stays free of any HTTP-client dependency.
//!
//! Wiring a concrete HTTPS client (with a strict timeout, and **fail-open** per R-305 so a slow or
//! unreachable corpus never blocks registration) is a deliberate, separately-reviewed step — adding
//! a networking crate to the auth path is a supply-chain decision, not an incidental one. Until then
//! the security-relevant parsing is implemented and covered.

use auth_core::breach::{BreachUnavailable, RangeProvider};

/// The HIBP range-query URL for a 5-hex-char SHA-1 prefix. Only the prefix is ever sent
/// (k-anonymity): the suffix comparison happens locally.
pub fn hibp_range_url(prefix: &str) -> String {
    format!("https://api.pwnedpasswords.com/range/{prefix}")
}

/// Parse a HIBP range response body into the uppercase 35-hex **suffixes** it lists. Each line is
/// `SUFFIX:COUNT` (the count is discarded); lines are separated by CRLF or LF. Blank and malformed
/// lines (no suffix, or a non-35-hex suffix) are skipped rather than trusted, so a mangled response
/// can never inject a bogus "match".
pub fn parse_hibp_range(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let suffix = line.split(':').next().unwrap_or("").trim();
            if suffix.len() == 35 && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(suffix.to_ascii_uppercase())
            } else {
                None
            }
        })
        .collect()
}

/// A [`RangeProvider`] backed by an injected transport. `fetch(prefix)` returns the raw HIBP range
/// response body, or `Err(BreachUnavailable)` on any transport failure (the caller fails **open**).
pub struct HttpRangeProvider<F>
where
    F: Fn(&str) -> Result<String, BreachUnavailable> + Send + Sync,
{
    fetch: F,
}

impl<F> HttpRangeProvider<F>
where
    F: Fn(&str) -> Result<String, BreachUnavailable> + Send + Sync,
{
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }
}

impl<F> RangeProvider for HttpRangeProvider<F>
where
    F: Fn(&str) -> Result<String, BreachUnavailable> + Send + Sync,
{
    fn suffixes(&self, prefix: &str) -> Result<Vec<String>, BreachUnavailable> {
        let body = (self.fetch)(prefix)?;
        Ok(parse_hibp_range(&body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth_core::breach::{is_compromised, sha1_hex, split};

    #[test]
    fn url_reveals_only_the_prefix() {
        assert_eq!(
            hibp_range_url("5BAA6"),
            "https://api.pwnedpasswords.com/range/5BAA6"
        );
    }

    #[test]
    fn parse_handles_crlf_counts_and_skips_junk() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                    \r\n\
                    garbage-line\r\n\
                    short:5\r\n";
        let suffixes = parse_hibp_range(body);
        assert_eq!(
            suffixes,
            vec![
                "0018A45C4D1DEF81644B54AB7F969B88D65".to_string(),
                "00D4F6E8FA6EECAD2A3AA415EEC418D38EC".to_string(),
            ]
        );
    }

    #[test]
    fn lowercase_suffixes_are_normalized() {
        let out = parse_hibp_range("0018a45c4d1def81644b54ab7f969b88d65:9");
        assert_eq!(out, vec!["0018A45C4D1DEF81644B54AB7F969B88D65".to_string()]);
    }

    #[test]
    fn provider_matches_a_known_password_via_injected_transport() {
        // "password" → SHA-1 5BAA6..., suffix 1E4C9...; the stub returns exactly that suffix for
        // the prefix it is asked for, proving the full k-anonymity round-trip through the provider.
        let hash = sha1_hex("password");
        let (prefix, suffix) = split(&hash);
        let expected_prefix = prefix.clone();
        let provider = HttpRangeProvider::new(move |p: &str| {
            assert_eq!(p, expected_prefix, "only the prefix is revealed");
            Ok(format!(
                "{suffix}:42\r\nDEADBEEF00000000000000000000000000A:1"
            ))
        });
        assert!(is_compromised(&provider, "password").unwrap());
        // A password whose suffix is absent from the (same) response is not flagged.
        let provider2 = HttpRangeProvider::new(|_: &str| {
            Ok("DEADBEEF00000000000000000000000000A:1".to_string())
        });
        assert!(!is_compromised(&provider2, "password").unwrap());
    }

    #[test]
    fn transport_failure_is_breach_unavailable() {
        let provider = HttpRangeProvider::new(|_: &str| Err(BreachUnavailable));
        assert_eq!(provider.suffixes("5BAA6"), Err(BreachUnavailable));
    }
}
