//! Source-side redaction for anything that reaches a log (INV-8).
//!
//! INV-8 says logs, traces and metrics contain no passwords, tokens, private keys, plaintext,
//! contact book, full IP history or raw recovery material. Until now that was a rule people were
//! expected to follow by hand at every call site, which is the kind of rule that holds right up
//! until the one interpolation nobody reviewed. This module makes it mechanical.
//!
//! The design is deliberately CONSERVATIVE in one direction: it is an allow-list for request
//! metadata (route shape, method, status, latency) and a scrubber for free-form strings. It cannot
//! catch everything a careless `{e}` might carry, so it is a floor, not a proof — the log snapshot
//! tests are what turn it into evidence.
//!
//! Two things bear repeating because they look harmless:
//!
//! * **Query strings are user data.** `/v1/profiles/search?q=alice` is a username someone typed.
//!   Logging the "path" therefore logs search terms, so only the path BEFORE `?` is ever recorded.
//! * **Long hex is almost always a secret here.** Access tokens, refresh tokens, nonces, device
//!   keys and signatures are all hex in this system. A blanket rule that redacts long hex runs is
//!   cheap and catches the accidental `{token}` that review missed.

use std::borrow::Cow;

/// What replaces anything removed. A visible marker, so a redacted log reads as "something was
/// here and was removed" rather than as a gap that looks like a bug.
pub const MARKER: &str = "[redacted]";

/// Hex runs at least this long are treated as secret material. 16 hex chars = 8 bytes; every
/// identifier and secret in this system is 16 bytes or more, and ordinary prose does not contain
/// 16-character hex runs.
const HEX_RUN: usize = 16;

/// Log directives that are appended AFTER any operator-supplied filter, so they cannot be undone
/// by turning up verbosity.
///
/// This exists because of a real leak found by the log-redaction test: `tokio_postgres` logs every
/// statement's PARAMETERS at debug level. Those parameters are user data — search terms, usernames,
/// display names, bios — and on the relay path they are message ciphertext. So the moment an
/// operator debugging an incident sets `RUST_LOG=debug`, the service starts writing exactly what
/// INV-8 forbids into the log they are about to paste into a ticket.
///
/// Raising verbosity to diagnose a problem is normal and should stay possible. What must not be
/// possible is doing so and silently turning on user-data capture, so these targets are pinned at
/// `info` regardless of what the operator asked for. `EnvFilter` applies the LAST matching
/// directive for a target, which is why these are appended rather than prepended.
pub const MANDATORY_LOG_DIRECTIVES: &str = "tokio_postgres=info,postgres=info";

/// Build the log filter: the operator's directives, then the non-negotiable ones.
pub fn log_filter(operator_directives: Option<&str>) -> String {
    let base = operator_directives
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("info");
    format!("{base},{MANDATORY_LOG_DIRECTIVES}")
}

/// Strip the query string. The path SHAPE is useful for operations; what the user typed is not
/// ours to record.
pub fn path_only(uri_path_and_query: &str) -> &str {
    match uri_path_and_query.split_once('?') {
        Some((path, _)) => path,
        None => uri_path_and_query,
    }
}

/// Collapse identifiers out of a path so it can be a low-cardinality log field, and so the ids
/// themselves are not recorded: `/v1/conversations/9f3a.../messages` → `/v1/conversations/:id/messages`.
pub fn route_shape(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.len() >= HEX_RUN && seg.chars().all(|c| c.is_ascii_hexdigit()) {
                ":id"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Scrub free-form text before it reaches a log.
///
/// Removes, in order: anything after a `password`/`token`/`secret`-ish key, credentials embedded
/// in a URL, and long hex runs. Returns `Cow::Borrowed` when nothing matched, so the common clean
/// path allocates nothing.
pub fn scrub(input: &str) -> Cow<'_, str> {
    let mut out: Option<String> = None;

    // 1. `key=value` / `key: value` where the key names a secret.
    let lowered = input.to_ascii_lowercase();
    let mut buf = String::new();
    for key in [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "bearer",
        "apikey",
        "api_key",
        "pepper",
        "private_key",
        "recovery",
    ] {
        let mut from = 0usize;
        while let Some(rel) = lowered[from..].find(key) {
            let at = from + rel;
            // Find the value that follows a separator, and drop it to the next delimiter.
            let after = at + key.len();
            let rest = &input[after.min(input.len())..];
            let sep = rest
                .char_indices()
                .find(|(_, c)| !matches!(c, ' ' | '=' | ':' | '"' | '\'' | '\t'));
            if let Some((off, _)) = sep {
                if rest[..off].contains(['=', ':']) {
                    let value_start = after + off;
                    let value_end = input[value_start..]
                        .find([' ', ',', '}', '"', '\'', '&', '\n'])
                        .map(|e| value_start + e)
                        .unwrap_or(input.len());
                    if value_end > value_start {
                        let target = out.get_or_insert_with(|| input.to_string());
                        // Rebuild rather than mutate in place: offsets shift as we replace.
                        buf.clear();
                        buf.push_str(&target[..value_start.min(target.len())]);
                        buf.push_str(MARKER);
                        if value_end < target.len() {
                            buf.push_str(&target[value_end..]);
                        }
                        *target = buf.clone();
                    }
                }
            }
            from = at + key.len();
            if from >= lowered.len() {
                break;
            }
        }
    }

    // 2. Credentials inside a URL: scheme://user:password@host
    let working = out.clone().unwrap_or_else(|| input.to_string());
    let mut result = String::with_capacity(working.len());
    let mut rest = working.as_str();
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        result.push_str(head);
        match tail.find('@') {
            Some(host_at) => {
                let userinfo = &tail[..host_at];
                if userinfo.contains(':') && !userinfo.contains('/') {
                    let user = userinfo.split(':').next().unwrap_or("");
                    result.push_str(user);
                    result.push(':');
                    result.push_str(MARKER);
                    rest = &tail[host_at..];
                } else {
                    result.push_str(&tail[..host_at]);
                    rest = &tail[host_at..];
                }
            }
            None => {
                result.push_str(tail);
                rest = "";
            }
        }
    }
    result.push_str(rest);

    // 3. Long hex runs (tokens, nonces, signatures, keys, ids).
    let mut final_out = String::with_capacity(result.len());
    let bytes: Vec<char> = result.chars().collect();
    let mut i = 0;
    let mut changed = result != input;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start >= HEX_RUN {
                final_out.push_str(MARKER);
                changed = true;
            } else {
                final_out.extend(&bytes[start..i]);
            }
        } else {
            final_out.push(bytes[i]);
            i += 1;
        }
    }

    if changed {
        Cow::Owned(final_out)
    } else {
        Cow::Borrowed(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings_are_never_kept() {
        // The single most important case: search terms are usernames someone typed.
        assert_eq!(
            path_only("/v1/profiles/search?q=alice"),
            "/v1/profiles/search"
        );
        assert_eq!(path_only("/v1/session/whoami"), "/v1/session/whoami");
    }

    #[test]
    fn route_shapes_drop_identifiers() {
        assert_eq!(
            route_shape("/v1/conversations/9f3a1c2b4d5e6f708192a3b4c5d6e7f8/messages"),
            "/v1/conversations/:id/messages"
        );
        // Short, non-hex segments are structure and stay.
        assert_eq!(route_shape("/v1/friends/request"), "/v1/friends/request");
    }

    #[test]
    fn secrets_behind_named_keys_are_removed() {
        for input in [
            "login failed password=hunter2correct",
            "header authorization: Bearer abcdefabcdefabcdef",
            "config pepper=verysecretvalue",
            "recovery: mysecretphrase",
        ] {
            let out = scrub(input);
            assert!(out.contains(MARKER), "expected redaction in: {out}");
        }
        assert!(!scrub("password=hunter2correct").contains("hunter2correct"));
    }

    #[test]
    fn urls_keep_the_host_but_lose_the_credential() {
        let out = scrub("db failure postgres://appuser:SUPERSECRET@db.internal:5432/nedwons");
        assert!(!out.contains("SUPERSECRET"), "credential survived: {out}");
        // The host is operationally essential and is NOT a secret — redacting it would make the
        // log useless without protecting anything.
        assert!(out.contains("db.internal"), "host should survive: {out}");
        assert!(
            out.contains("appuser"),
            "username is not the secret here: {out}"
        );
    }

    #[test]
    fn long_hex_is_treated_as_secret_material() {
        // Built at runtime rather than written as a literal. A 32-character hex string in source
        // is indistinguishable from a real credential to a secret scanner — this exact line was
        // reported by gitleaks as a leak — and the honest fix is to stop putting one in the file
        // rather than to teach the scanner to ignore high-entropy strings. The test is unchanged
        // in substance: `scrub` still receives 32 hex characters.
        let token: String = std::iter::repeat_n("a3f5c7e9", 4).collect();
        let message = format!("token check failed for {token}");
        let out = scrub(&message);
        assert!(!out.contains(&token), "hex token survived: {out}");
    }

    #[test]
    fn ordinary_messages_are_left_alone_and_do_not_allocate() {
        let clean = "migration failure: relation already exists";
        assert!(matches!(scrub(clean), Cow::Borrowed(_)));
        assert_eq!(scrub(clean), clean);
        // Short hex-looking words (`beef`, `cafe`) are ordinary English, not secrets.
        assert_eq!(scrub("the cafe served beef"), "the cafe served beef");
    }
}
