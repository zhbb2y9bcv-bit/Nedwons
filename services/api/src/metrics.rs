//! Operational metrics in Prometheus text-exposition format.
//!
//! **Why this is hand-rolled rather than a metrics crate.** The exposition format is a few lines of
//! text and the counters are atomics; a dependency would buy formatting we can write in an
//! afternoon and cost a transitive tree on a service whose whole posture is a small, auditable
//! dependency surface (now gated by `deny.toml`). If this ever needs histograms, exemplars or a
//! push gateway, that trade flips and a real client is the right answer.
//!
//! **What must never appear here.** Metrics are the easiest place to leak by accident, because a
//! label feels like structure rather than data. INV-8 covers metrics explicitly, so:
//!
//! * no usernames, account ids, device ids, IP addresses, tokens or message content — ever;
//! * labels are drawn from a CLOSED set of compile-time constants, never from request input. That
//!   is also what stops a caller minting unbounded label values and turning the registry into an
//!   unbounded allocation (a cardinality bomb is both an outage and a leak).
//!
//! So every metric here is a bare counter or gauge whose meaning is in its NAME. A spike tells you
//! what is happening and roughly where; it deliberately cannot tell you to whom.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// A monotonically increasing count of events.
pub struct Counter {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Counter {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    pub fn incr(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A value that can go up and down (queue depth, open connections).
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    value: AtomicI64,
}

impl Gauge {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicI64::new(0),
        }
    }

    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn incr(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decr(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

// ----- the metric set -------------------------------------------------------------------
//
// One per flow the runbooks alert on. Grouped by the question each answers, because a metric
// nobody can act on is noise that hides the ones that matter.

// Authentication: is someone attacking credentials, or is auth broken?
pub static AUTH_FAILURES: Counter = Counter::new(
    "nedwons_auth_failures_total",
    "Authentication attempts refused (bad password, wrong device key, expired challenge).",
);
pub static AUTH_SUCCESSES: Counter = Counter::new(
    "nedwons_auth_successes_total",
    "Sessions successfully established.",
);
/// Rising without a matching deploy or clock problem means someone is replaying captured proofs.
pub static PROOF_REPLAYS_REJECTED: Counter = Counter::new(
    "nedwons_proof_replays_rejected_total",
    "Device-proof replays refused (a nonce presented more than once).",
);
pub static PROOF_FAILURES: Counter = Counter::new(
    "nedwons_proof_failures_total",
    "Requests refused for a missing, malformed, stale or invalid device proof.",
);
pub static ATTESTATION_FAILURES: Counter = Counter::new(
    "nedwons_attestation_failures_total",
    "App Attest attestations that failed verification.",
);

// Abuse: are the limits doing anything, and to whom (in aggregate)?
pub static RATE_LIMITED_IP: Counter = Counter::new(
    "nedwons_rate_limited_ip_total",
    "Requests refused by the per-IP limiter.",
);
pub static QUOTA_EXHAUSTED: Counter = Counter::new(
    "nedwons_quota_exhausted_total",
    "Requests refused by a per-account abuse quota.",
);

// Capacity: is the service about to fall over?
pub static DB_POOL_WAIT_FAILURES: Counter = Counter::new(
    "nedwons_db_pool_wait_failures_total",
    "Database connection checkouts that timed out — pool saturation.",
);
pub static DB_POOL_IN_USE: Gauge = Gauge::new(
    "nedwons_db_pool_in_use",
    "Database connections currently checked out.",
);
pub static QUEUE_DEPTH: Gauge = Gauge::new(
    "nedwons_queue_depth",
    "Undelivered envelopes queued across all recipients.",
);
pub static WEBSOCKETS_OPEN: Gauge = Gauge::new(
    "nedwons_websockets_open",
    "Currently connected delivery WebSockets.",
);

// Delivery: is mail actually moving?
pub static ENVELOPES_ENQUEUED: Counter = Counter::new(
    "nedwons_envelopes_enqueued_total",
    "Envelopes accepted for delivery.",
);
pub static ENVELOPES_DELIVERED: Counter = Counter::new(
    "nedwons_envelopes_delivered_total",
    "Envelopes acknowledged by a recipient device.",
);
pub static PUSH_SENT: Counter = Counter::new(
    "nedwons_push_sent_total",
    "Contentless APNs wake pushes accepted by Apple.",
);
pub static PUSH_FAILURES: Counter = Counter::new(
    "nedwons_push_failures_total",
    "Contentless APNs wake pushes rejected or errored.",
);
/// Distinct from a failure: the push failed AND Apple said the address is permanently gone, so the
/// row was removed. A steady trickle is normal (uninstalls); a spike means the build is pushing to
/// the wrong APNs environment or topic.
pub static PUSH_TOKENS_DROPPED: Counter = Counter::new(
    "nedwons_push_tokens_dropped_total",
    "Push tokens deleted after APNs reported them permanently invalid.",
);

// Key transparency: a gap here is a security incident, not a performance problem.
pub static KT_APPENDS: Counter = Counter::new(
    "nedwons_kt_appends_total",
    "Key-transparency leaves appended.",
);
pub static KT_APPEND_FAILURES: Counter = Counter::new(
    "nedwons_kt_append_failures_total",
    "Key-transparency appends that FAILED — the log now has a gap and must be reconciled.",
);

// Account lifecycle: deletion is irreversible and must be observable.
pub static ACCOUNTS_DELETED: Counter = Counter::new(
    "nedwons_accounts_deleted_total",
    "Accounts erased through the in-app deletion flow.",
);
pub static ACCOUNTS_REGISTERED: Counter =
    Counter::new("nedwons_accounts_registered_total", "Accounts created.");

/// Render the whole registry in Prometheus text-exposition format.
pub fn render() -> String {
    let counters: &[&Counter] = &[
        &AUTH_FAILURES,
        &AUTH_SUCCESSES,
        &PROOF_REPLAYS_REJECTED,
        &PROOF_FAILURES,
        &ATTESTATION_FAILURES,
        &RATE_LIMITED_IP,
        &QUOTA_EXHAUSTED,
        &DB_POOL_WAIT_FAILURES,
        &ENVELOPES_ENQUEUED,
        &ENVELOPES_DELIVERED,
        &PUSH_SENT,
        &PUSH_FAILURES,
        &PUSH_TOKENS_DROPPED,
        &KT_APPENDS,
        &KT_APPEND_FAILURES,
        &ACCOUNTS_DELETED,
        &ACCOUNTS_REGISTERED,
    ];
    let gauges: &[&Gauge] = &[&DB_POOL_IN_USE, &QUEUE_DEPTH, &WEBSOCKETS_OPEN];

    let mut out = String::with_capacity(4096);
    for c in counters {
        out.push_str(&format!("# HELP {} {}\n", c.name, c.help));
        out.push_str(&format!("# TYPE {} counter\n", c.name));
        out.push_str(&format!("{} {}\n", c.name, c.get()));
    }
    for g in gauges {
        out.push_str(&format!("# HELP {} {}\n", g.name, g.help));
        out.push_str(&format!("# TYPE {} gauge\n", g.name));
        out.push_str(&format!("{} {}\n", g.name, g.get()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_is_well_formed_and_carries_no_labels() {
        AUTH_FAILURES.incr();
        QUEUE_DEPTH.set(7);
        let text = render();

        assert!(text.contains("# TYPE nedwons_auth_failures_total counter"));
        assert!(text.contains("# TYPE nedwons_queue_depth gauge"));
        assert!(text.contains("nedwons_queue_depth 7"));

        // Every sample line is `name value` with no label set. Labels are the mechanism by which
        // identifiers leak into metrics, and this registry deliberately has none — so a future
        // change that introduces one has to change this assertion and think about INV-8.
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            assert!(
                !line.contains('{'),
                "metric line must carry no labels: {line}"
            );
            let parts: Vec<_> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 2, "expected `name value`, got: {line}");
            assert!(
                parts[0].starts_with("nedwons_"),
                "metric names are namespaced: {line}"
            );
            parts[1]
                .parse::<i64>()
                .unwrap_or_else(|_| panic!("value must be numeric: {line}"));
        }
    }

    #[test]
    fn counters_and_gauges_move_as_expected() {
        let before = ENVELOPES_ENQUEUED.get();
        ENVELOPES_ENQUEUED.add(3);
        assert_eq!(ENVELOPES_ENQUEUED.get(), before + 3);

        WEBSOCKETS_OPEN.set(0);
        WEBSOCKETS_OPEN.incr();
        WEBSOCKETS_OPEN.incr();
        WEBSOCKETS_OPEN.decr();
        assert_eq!(WEBSOCKETS_OPEN.get(), 1);
    }
}
