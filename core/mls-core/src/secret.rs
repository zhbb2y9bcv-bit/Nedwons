//! Secret-message reveal **state machine** (view-once ephemeral messages).
//!
//! A secret message the recipient holds moves through an explicit, one-way lifecycle:
//!
//! ```text
//!   Sealed ──begin_reveal──▶ Countdown ──(+3s)──▶ Visible ──(+10s)──▶ Consumed
//! ```
//!
//! `Consumed` is terminal and equivalent to the *tombstone* display state: the plaintext is gone and
//! the message can never be reopened through the app. The **sender**'s copy is `Consumed` from the
//! moment it is sent (the sender never retains a reopenable copy).
//!
//! Security properties this type enforces (the *persistence* of these transitions is the durable
//! layer's job — [`crate::durable`] commits every change atomically before it is observable):
//!
//! * **One viewing opportunity.** `begin_reveal` only fires from `Sealed`; a second tap, a replayed
//!   delivery, or a concurrent window cannot re-enter `Sealed` or restart the clock.
//! * **The clock cannot be rewound.** Every poll carries a monotonic `now_ms`; a value below the
//!   last observed one is clamped forward, so changing the system clock, backgrounding, or a
//!   hostile caller cannot buy extra time.
//! * **Fail-closed by deadline.** Deadlines are absolute in the caller's monotonic timebase and set
//!   once, at reveal. Elapsed time keeps accruing across backgrounding; passing the deadline while
//!   away marks the message `Consumed`.
//! * **No plaintext outside `Visible`.** [`SecretRecord::visible_body`] returns the body only while
//!   `Visible`; before reveal and after expiry it returns `None`.
//!
//! The times below are *elapsed* durations, not wall-clock — the caller supplies a monotonic source.

use crate::content::SECRET_ID_LEN;
use serde::{Deserialize, Serialize};

/// Countdown before the message becomes visible (the "3, 2, 1").
pub const COUNTDOWN_MS: u64 = 3_000;
/// Viewing window once visible.
pub const VIEW_MS: u64 = 10_000;
/// The exact, non-sensitive tombstone text shown in place of a consumed/sent secret message.
pub const TOMBSTONE_TEXT: &str = "a secret message has been sent";

/// Whether this device is the secret's sender or its recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSide {
    /// This device sent it; it is tombstoned immediately and never revealable here.
    Sender,
    /// This device received it; it may be revealed exactly once.
    Recipient,
}

/// The reveal lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretState {
    /// Received, not yet tapped. The countdown has NOT started.
    Sealed,
    /// Reveal begun; the 3-second countdown is running.
    Countdown,
    /// The body is visible; the 10-second window is running.
    Visible,
    /// Terminal: plaintext destroyed, tombstone shown, cannot be reopened.
    Consumed,
}

/// Per-secret durable record. Held inside the atomically-committed durable blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    pub secret_id: [u8; SECRET_ID_LEN],
    pub side: SecretSide,
    pub state: SecretState,
    /// The decrypted secret body. `None` once consumed/scrubbed, or on the sender side.
    pub body: Option<Vec<u8>>,
    /// Absolute monotonic time (ms) the countdown ends and the body becomes visible. 0 until reveal.
    pub countdown_deadline_ms: u64,
    /// Absolute monotonic time (ms) the viewing window ends. 0 until reveal.
    pub view_deadline_ms: u64,
    /// Highest `now_ms` observed — the monotonic guard against clock rewind.
    pub last_now_ms: u64,
}

/// Attempted an invalid or backward state transition.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct InvalidTransition;

impl SecretRecord {
    /// A freshly received sealed secret (recipient side).
    pub fn sealed_recipient(secret_id: [u8; SECRET_ID_LEN], body: Vec<u8>) -> Self {
        Self {
            secret_id,
            side: SecretSide::Recipient,
            state: SecretState::Sealed,
            body: Some(body),
            countdown_deadline_ms: 0,
            view_deadline_ms: 0,
            last_now_ms: 0,
        }
    }

    /// A sender-side record: tombstoned from creation, never revealable, no body retained.
    pub fn tombstone_sender(secret_id: [u8; SECRET_ID_LEN]) -> Self {
        Self {
            secret_id,
            side: SecretSide::Sender,
            state: SecretState::Consumed,
            body: None,
            countdown_deadline_ms: 0,
            view_deadline_ms: 0,
            last_now_ms: 0,
        }
    }

    /// Monotonic clamp: time never moves backward from this record's perspective.
    fn clamp(&mut self, now_ms: u64) -> u64 {
        let now = now_ms.max(self.last_now_ms);
        self.last_now_ms = now;
        now
    }

    /// Begin the reveal (recipient taps the sealed placeholder). Only valid from `Sealed` on the
    /// recipient side; sets both deadlines from `now_ms`. Returns `Err` for any other state so a
    /// double-tap / replay / concurrent window cannot grant a second opportunity — the caller MUST
    /// treat `Err` as "no reveal" and MUST persist the resulting state before showing anything.
    pub fn begin_reveal(&mut self, now_ms: u64) -> Result<(), InvalidTransition> {
        if self.side != SecretSide::Recipient || self.state != SecretState::Sealed {
            return Err(InvalidTransition);
        }
        let now = self.clamp(now_ms);
        self.state = SecretState::Countdown;
        self.countdown_deadline_ms = now + COUNTDOWN_MS;
        self.view_deadline_ms = now + COUNTDOWN_MS + VIEW_MS;
        Ok(())
    }

    /// Advance the state for the current `now_ms` (idempotent; call freely). Countdown→Visible at
    /// `countdown_deadline_ms`, Visible→Consumed at `view_deadline_ms`, and a long jump straight to
    /// Consumed. On reaching `Consumed` the body is scrubbed. Returns the (possibly advanced) state.
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

    /// The body iff the message is currently `Visible` at `now_ms` (advances state first). `None`
    /// while sealed/counting down and forever after expiry — the plaintext gate.
    pub fn visible_body(&mut self, now_ms: u64) -> Option<&[u8]> {
        if self.poll(now_ms) == SecretState::Visible {
            self.body.as_deref()
        } else {
            None
        }
    }

    /// Milliseconds of viewing time left (0 once not visible / consumed). For the UI's fade + timer.
    pub fn remaining_view_ms(&mut self, now_ms: u64) -> u64 {
        match self.poll(now_ms) {
            SecretState::Visible => self.view_deadline_ms.saturating_sub(self.last_now_ms),
            _ => 0,
        }
    }

    /// Milliseconds of countdown left (0 once past the countdown). For the "3, 2, 1".
    pub fn remaining_countdown_ms(&mut self, now_ms: u64) -> u64 {
        match self.poll(now_ms) {
            SecretState::Countdown => self.countdown_deadline_ms.saturating_sub(self.last_now_ms),
            _ => 0,
        }
    }

    /// Force to the terminal tombstone state and scrub the body (best-effort zeroize). Idempotent.
    /// Used on expiry, on a screenshot/capture event, and on the fail-closed relaunch path.
    pub fn consume(&mut self) {
        if let Some(mut body) = self.body.take() {
            // Best-effort scrub of the plaintext buffer before it is dropped.
            for b in body.iter_mut() {
                *b = 0;
            }
        }
        self.state = SecretState::Consumed;
    }

    /// True once terminal (tombstone shown; reopening impossible).
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
        // App backgrounded; returns after the deadline → consumed, never re-shown.
        assert_eq!(r.poll(20_000), SecretState::Consumed);
        assert!(r.visible_body(20_000).is_none());
    }

    #[test]
    fn clock_rewind_cannot_buy_time() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        r.poll(13_000); // consumed
                        // A caller trying to rewind to mid-window gets clamped forward — stays consumed.
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
    fn consume_is_idempotent() {
        let mut r = rec();
        r.begin_reveal(0).unwrap();
        r.consume();
        r.consume();
        assert!(r.is_tombstone());
        assert!(r.body.is_none());
    }
}
