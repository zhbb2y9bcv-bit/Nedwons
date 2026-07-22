//! Security failures collapse to a generic `Denied` so responses never reveal *why* — account
//! existence, password validity, device mismatch, replay, or expiry (THREAT_MODEL.md §7).
//! Correlation happens through logs keyed by random ids, never by leaking specifics to the caller.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// Every auth/authz/integrity/replay/expiry failure maps here; callers must not branch further.
    #[error("authentication denied")]
    Denied,

    /// Registration only. Username existence is inherently observable there — you must learn a
    /// name is taken to pick another — unlike login, which stays generic.
    #[error("username unavailable")]
    UsernameUnavailable,

    /// Distinct from `Denied`: a client-correctable request error, not a security decision.
    #[error("invalid input")]
    InvalidInput,

    /// Registration only. Client-correctable, and saying why is required UX — it leaks nothing
    /// about other accounts.
    #[error("password does not meet requirements")]
    WeakPassword,

    /// Never carries secret detail.
    #[error("internal error")]
    Internal,
}

pub type Result<T> = core::result::Result<T, AuthError>;
