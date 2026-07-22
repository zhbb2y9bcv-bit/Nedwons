//! View-once reveal state machine.
//!
//! ```text
//!   Sealed ──begin_reveal──▶ Countdown ──(+3s)──▶ Visible ──(+10s)──▶ Consumed
//! ```
//!
//! `Consumed` is terminal (the tombstone display state); the sender's copy starts there.
//! Persisting these transitions is [`crate::durable`]'s job — it commits atomically before any
//! change is observable. Properties enforced here:
//!
//! * **One viewing opportunity.** `begin_reveal` fires only from `Sealed`, so a double-tap, replayed
//!   delivery, or concurrent window cannot restart the clock.
//! * **No clock rewind.** `now_ms` below the last observed value is clamped forward, so a changed
//!   system clock, backgrounding, or hostile caller cannot buy extra time.
//! * **Fail-closed by deadline.** Deadlines are absolute and set once, at reveal; time accrues while
//!   backgrounded, so returning past the deadline finds the message `Consumed`.
//! * **No plaintext outside `Visible`.** [`SecretRecord::visible_body`] returns `None` before reveal
//!   and forever after expiry.
//!
//! Times are elapsed durations — the caller supplies a monotonic source.

use crate::content::SECRET_ID_LEN;
use serde::{Deserialize, Serialize};

pub const COUNTDOWN_MS: u64 = 3_000;
pub const VIEW_MS: u64 = 10_000;
/// Exact tombstone text shown in place of a consumed or sent secret.
pub const TOMBSTONE_TEXT: &str = "a secret message has been sent";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSide {
    /// Tombstoned immediately; never revealable here.
    Sender,
    /// Revealable exactly once.
    Recipient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretState {
    /// Not yet tapped; the countdown has NOT started.
    Sealed,
    Countdown,
    Visible,
    /// Terminal: plaintext destroyed, cannot be reopened.
    Consumed,
}

/// Held inside the atomically-committed durable blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    pub secret_id: [u8; SECRET_ID_LEN],
    pub side: SecretSide,
    pub state: SecretState,
    /// `None` once consumed/scrubbed, or on the sender side.
    pub body: Option<Vec<u8>>,
    /// Absolute monotonic ms; 0 until reveal.
    pub countdown_deadline_ms: u64,
    /// Absolute monotonic ms; 0 until reveal.
    pub view_deadline_ms: u64,
    /// Highest `now_ms` observed — the guard against clock rewind.
    pub last_now_ms: u64,
    /// ADR-0015: local id of the `SecretConsumed` message emitted to this account's other devices at
    /// reveal, so it is built at most once. `None` until emitted; the sender side never emits.
    #[serde(default)]
    pub consumption_local_id: Option<u64>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct InvalidTransition;

impl SecretRecord {
    pub fn sealed_recipient(secret_id: [u8; SECRET_ID_LEN], body: Vec<u8>) -> Self {
        Self {
            secret_id,
            side: SecretSide::Recipient,
            state: SecretState::Sealed,
            body: Some(body),
            countdown_deadline_ms: 0,
            view_deadline_ms: 0,
            last_now_ms: 0,
            consumption_local_id: None,
        }
    }

    /// Tombstoned from creation; no body retained.
    pub fn tombstone_sender(secret_id: [u8; SECRET_ID_LEN]) -> Self {
        Self {
            secret_id,
            side: SecretSide::Sender,
            state: SecretState::Consumed,
            body: None,
            countdown_deadline_ms: 0,
            view_deadline_ms: 0,
            last_now_ms: 0,
            consumption_local_id: None,
        }
    }

    /// Time never moves backward from this record's perspective.
    fn clamp(&mut self, now_ms: u64) -> u64 {
        let now = now_ms.max(self.last_now_ms);
        self.last_now_ms = now;
        now
    }

    /// Valid only from `Sealed` on the recipient side, so a double-tap, replay or concurrent window
    /// cannot grant a second opportunity. The caller MUST treat `Err` as "no reveal" and MUST
    /// persist the resulting state before showing anything.
    pub fn begin_reveal(&mut self, now_ms: u64) -> Result<(), InvalidTransition> {
        if self.side != SecretSide::Recipient || self.state != SecretState::Sealed {
            return Err(InvalidTransition);
        }
        let now = self.clamp(now_ms);
        self.state = SecretState::Countdown;
        // Saturating so a hostile `now_ms` near u64::MAX cannot overflow-panic; a saturated deadline
        // is already past, so the reveal expires — fail closed (found by the `secret_state` fuzzer).
        self.countdown_deadline_ms = now.saturating_add(COUNTDOWN_MS);
        self.view_deadline_ms = now.saturating_add(COUNTDOWN_MS).saturating_add(VIEW_MS);
        Ok(())
    }

    /// Idempotent; call freely. A long jump goes straight to `Consumed`, scrubbing the body.
    pub fn poll(&mut self, now_ms: u64) -> SecretState {
        let now = self.clamp(now_ms);
        match self.state {
            SecretState::Sealed | SecretState::Consumed => {}
            SecretState::Countdown | SecretState::Visible => {
                if now >= self.view_deadline_ms {
                    self.consume();
                } else if self.state == SecretState::Countdown && now >= self.countdown_deadline_ms
                {
                    self.state = SecretState::Visible;
                }
            }
        }
        self.state
    }

    /// The plaintext gate: `None` while sealed or counting down, and forever after expiry.
    pub fn visible_body(&mut self, now_ms: u64) -> Option<&[u8]> {
        if self.poll(now_ms) == SecretState::Visible {
            self.body.as_deref()
        } else {
            None
        }
    }

    /// 0 once not visible. Drives the UI fade + timer.
    pub fn remaining_view_ms(&mut self, now_ms: u64) -> u64 {
        match self.poll(now_ms) {
            SecretState::Visible => self.view_deadline_ms.saturating_sub(self.last_now_ms),
            _ => 0,
        }
    }

    /// 0 once past the countdown. Drives the "3, 2, 1".
    pub fn remaining_countdown_ms(&mut self, now_ms: u64) -> u64 {
        match self.poll(now_ms) {
            SecretState::Countdown => self.countdown_deadline_ms.saturating_sub(self.last_now_ms),
            _ => 0,
        }
    }

    /// Idempotent. Used on expiry, on a screenshot/capture event, and on fail-closed relaunch.
    pub fn consume(&mut self) {
        if let Some(mut body) = self.body.take() {
            // Best-effort scrub before the buffer is dropped.
            for b in body.iter_mut() {
                *b = 0;
            }
        }
        self.state = SecretState::Consumed;
    }

    pub fn is_tombstone(&self) -> bool {
        self.state == SecretState::Consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> SecretRecord {
        SecretRecord::sealed_recipient([1u8; SECRET_ID_LEN], b"top secret".to_vec())
    }

    #[test]
    fn sealed_does_not_reveal_until_tapped() {
        let mut r = rec();
        assert_eq!(r.state, SecretState::Sealed);
        assert!(r.visible_body(1_000).is_none(), "no reveal before begin");
        // Time passing while sealed must NOT start any timer.
        assert_eq!(r.poll(999_999), SecretState::Sealed);
    }

    #[test]
    fn exact_three_second_countdown_then_visible() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        assert_eq!(r.poll(0), SecretState::Countdown);
        assert_eq!(
            r.poll(2_999),
            SecretState::Countdown,
            "still counting at 2.999s"
        );
        assert_eq!(r.poll(3_000), SecretState::Visible, "visible at exactly 3s");
        assert_eq!(r.visible_body(3_000).unwrap(), b"top secret");
    }

    #[test]
    fn exact_ten_second_window_then_consumed_and_scrubbed() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        assert_eq!(r.poll(3_000), SecretState::Visible);
        assert!(
            r.visible_body(12_999).is_some(),
            "visible at 12.999s (within window)"
        );
        assert_eq!(
            r.poll(13_000),
            SecretState::Consumed,
            "consumed at exactly 3+10s"
        );
        assert!(
            r.visible_body(13_000).is_none(),
            "no plaintext after expiry"
        );
        assert!(r.body.is_none(), "body scrubbed");
        assert!(r.is_tombstone());
    }

    #[test]
    fn double_begin_is_rejected_and_does_not_restart() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        let deadline = r.view_deadline_ms;
        assert_eq!(
            r.begin_reveal(5_000),
            Err(InvalidTransition),
            "second tap rejected"
        );
        assert_eq!(
            r.view_deadline_ms, deadline,
            "deadline unchanged (no extra time)"
        );
    }

    #[test]
    fn backgrounding_past_the_deadline_consumes() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        assert_eq!(r.poll(3_000), SecretState::Visible);
        // Returns after the deadline → consumed, never re-shown.
        assert_eq!(r.poll(20_000), SecretState::Consumed);
        assert!(r.visible_body(20_000).is_none());
    }

    #[test]
    fn clock_rewind_cannot_buy_time() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        r.poll(13_000);
        // Rewinding to mid-window is clamped forward — stays consumed.
        assert_eq!(r.poll(5_000), SecretState::Consumed);
        assert!(r.visible_body(5_000).is_none());
    }

    #[test]
    fn remaining_times_track_the_deadlines() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        assert_eq!(r.remaining_countdown_ms(1_000), 2_000);
        assert_eq!(r.remaining_view_ms(4_000), 9_000);
        assert_eq!(r.remaining_view_ms(13_000), 0);
    }

    #[test]
    fn sender_side_is_tombstone_and_never_reveals() {
        let mut r = SecretRecord::tombstone_sender([2u8; SECRET_ID_LEN]);
        assert!(r.is_tombstone());
        assert_eq!(r.begin_reveal(0), Err(InvalidTransition));
        assert!(r.visible_body(0).is_none());
    }

    #[test]
    fn extreme_now_does_not_overflow_and_fails_closed() {
        // Regression for a fuzz finding: a clock near u64::MAX must expire, not panic.
        let mut r = rec();
        r.begin_reveal(u64::MAX).unwrap();
        assert_eq!(r.poll(u64::MAX), SecretState::Consumed);
        assert!(r.visible_body(u64::MAX).is_none());
    }

    #[test]
    fn consume_is_idempotent() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        r.consume();
        r.consume();
        assert!(r.is_tombstone());
        assert!(r.body.is_none());
    }
}
