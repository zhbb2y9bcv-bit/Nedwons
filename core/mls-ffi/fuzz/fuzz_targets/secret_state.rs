#![no_main]
//! Fuzz the secret-message **reveal state machine transitions** (Secret Message feature).
//!
//! Complements the deterministic unit tests in `mls_core::secret`: here an ARBITRARY sequence of
//! operations — begin/poll/visible/remaining/consume, each with an attacker-chosen `now_ms` that may
//! jump forward, stall, or attempt to rewind — is applied to a sealed recipient record. The
//! invariants that must hold under EVERY sequence:
//!
//!   * no panic;
//!   * the observed clock never rewinds (`last_now_ms` is monotonic non-decreasing);
//!   * plaintext is returned ONLY while `Visible`;
//!   * `Consumed` is terminal — once reached the state never changes again and the body stays
//!     scrubbed (no sequence of taps / clock games can re-grant a viewing opportunity).
//!
//! A crash/abort or a violated assertion here is a finding.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use mls_core::secret::{SecretRecord, SecretState};

#[derive(Arbitrary, Debug)]
enum Op {
    Begin(u64),
    Poll(u64),
    Visible(u64),
    RemainingCountdown(u64),
    RemainingView(u64),
    Consume,
}

fuzz_target!(|ops: Vec<Op>| {
    let mut r = SecretRecord::sealed_recipient([0xAB; 16], b"top secret".to_vec());
    let mut last_now = r.last_now_ms;
    let mut ever_consumed = false;

    for op in ops {
        match op {
            Op::Begin(now) => {
                let _ = r.begin_reveal(now); // may fail (already begun/consumed) — never panics
            }
            Op::Poll(now) => {
                let _ = r.poll(now);
            }
            Op::Visible(now) => {
                let body = r.visible_body(now).map(|b| b.to_vec());
                // Plaintext is only ever handed out while Visible.
                if body.is_some() {
                    assert_eq!(r.state, SecretState::Visible, "body returned outside Visible");
                    assert!(!ever_consumed, "body returned after consumption");
                }
            }
            Op::RemainingCountdown(now) => {
                let _ = r.remaining_countdown_ms(now);
            }
            Op::RemainingView(now) => {
                let _ = r.remaining_view_ms(now);
            }
            Op::Consume => r.consume(),
        }

        // The observed clock can never move backwards, whatever `now_ms` the caller supplied.
        assert!(r.last_now_ms >= last_now, "clock rewound");
        last_now = r.last_now_ms;

        // Consumed is terminal and irreversible; the body is gone for good.
        if r.state == SecretState::Consumed {
            ever_consumed = true;
        }
        if ever_consumed {
            assert_eq!(r.state, SecretState::Consumed, "left the terminal state");
            assert!(r.body.is_none(), "body survived consumption");
        }
    }
});
