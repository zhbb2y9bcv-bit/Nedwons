//! Errors. Security failures collapse to a single generic `Denied` so that external
//! responses never reveal *why* (account existence, password validity, device mismatch,
//! replay, expiry). This is enumeration resistance and fail-closed behavior
//! (THREAT_MODEL.md §7). Internal correlation happens through logs keyed by random ids,
//! never by leaking specifics to the caller.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// Every authentication/authorization/integrity/replay/expiry failure maps here.
    /// Callers must not branch on a more specific reason for these.
    #[error("authentication denied")]
    Denied,

    /// Registration only: the requested username is unavailable. Username existence is
    /// inherently observable at registration time (you must be able to learn a name is
    /// taken to pick another), unlike login, which stays generic.
    #[error("username unavailable")]
    UsernameUnavailable,

    /// Malformed input (e.g. a username failing the normalization policy). Distinct from
    /// `Denied` because it is a client-correctable request error, not a security decision.
    #[error("invalid input")]
    InvalidInput,

    /// Registration only: password fails the NIST SP 800-63B-aligned policy (too short,
    /// too long, or on the common-password blocklist). Client-correctable, and telling the
    /// user why is required UX — this leaks nothing about other accounts.
    #[error("password does not meet requirements")]
    WeakPassword,

    /// An unexpected internal fault (e.g. the password hasher failed). Never carries
    /// secret detail.
    #[error("internal error")]
    Internal,
}

pub type Result<T> = core::result::Result<T, AuthError>;
