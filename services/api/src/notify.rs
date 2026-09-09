//! Delivery notifications for long-polling: a queued envelope wakes that device's waiters
//! immediately, so a waiting client costs **zero** database queries while idle.
//!
//! **Cross-instance (2026-09-09):** a sender's instance and a waiter's instance may differ, so
//! `wake` also publishes the device id over Postgres `LISTEN/NOTIFY` (`nedwons_wake` channel —
//! the database is already the shared component, no new infrastructure), and every instance runs
//! a listener that turns remote signals into LOCAL wakes only (`wake_local`): no push hook and no
//! re-publish, so a fan-out wakes each waiter once and dispatches each push once (on the origin
//! instance). The database stays the source of truth and every wait is timeout-bounded, so a
//! missed signal — a bus disconnect, a dropped NOTIFY — only delays delivery; it never loses a
//! message.
//!
//! A device that is NOT connected (backgrounded/killed) is reached instead by push (#4): an
//! optional wake hook fires on every `wake`, dispatching a contentless APNs push (see
//! [`crate::push`]). The hook is best-effort and off the delivery path — a push failure never
//! affects the durable queue.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// A side-effect invoked for a device on every `wake` — used to dispatch push notifications.
pub type WakeHook = Arc<dyn Fn([u8; 16]) + Send + Sync>;

/// Publishes a wake to OTHER instances (Postgres NOTIFY). Best-effort by contract.
pub type WakePublisher = Arc<dyn Fn([u8; 16]) + Send + Sync>;

#[derive(Default)]
struct Inner {
    waiters: HashMap<[u8; 16], Arc<Notify>>,
    on_wake: Option<WakeHook>,
    publisher: Option<WakePublisher>,
}

#[derive(Clone, Default)]
pub struct DeliveryNotifier {
    inner: Arc<Mutex<Inner>>,
}

impl DeliveryNotifier {
    /// Install the wake hook (push dispatch). Set once at startup; a later `wake` invokes it.
    pub fn set_wake_hook(&self, hook: WakeHook) {
        self.inner.lock().unwrap().on_wake = Some(hook);
    }

    /// Get (or create) the notify handle for a device. Callers register interest on this
    /// handle *before* their initial inbox check to avoid a lost-wakeup window.
    pub fn handle(&self, device: &[u8; 16]) -> Arc<Notify> {
        let mut g = self.inner.lock().unwrap();
        g.waiters
            .entry(*device)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Install the cross-instance publisher (Postgres NOTIFY). Set once at startup.
    pub fn set_publisher(&self, publisher: WakePublisher) {
        self.inner.lock().unwrap().publisher = Some(publisher);
    }

    /// Signal that a device has new mail. `notify_one` stores a single permit if no waiter
    /// is currently parked, so a notification that races just ahead of a waiter's park is
    /// still delivered on its next poll. Also fires the wake hook (push) for a device that has
    /// no connected waiter, and publishes to other instances.
    pub fn wake(&self, device: &[u8; 16]) {
        let (handle, hook, publisher) = {
            let g = self.inner.lock().unwrap();
            (
                g.waiters.get(device).cloned(),
                g.on_wake.clone(),
                g.publisher.clone(),
            )
        };
        if let Some(notify) = handle {
            notify.notify_one();
        }
        if let Some(hook) = hook {
            hook(*device);
        }
        if let Some(publisher) = publisher {
            publisher(*device);
        }
    }

    /// A wake that arrived FROM another instance: local waiters only. Deliberately no push hook
    /// (the origin dispatched it) and no re-publish (no echo storms).
    pub fn wake_local(&self, device: &[u8; 16]) {
        let handle = self.inner.lock().unwrap().waiters.get(device).cloned();
        if let Some(notify) = handle {
            notify.notify_one();
        }
    }
}

// --------------------------------------------------------------------------------------------
// Cross-instance wake bus over Postgres LISTEN/NOTIFY.

/// The NOTIFY channel. Payload = the woken device id, hex.
const WAKE_CHANNEL: &str = "nedwons_wake";

/// Start both halves of the bus. The PUBLISH half drains an in-process queue through one pooled
/// connection at a time (a burst of fan-out wakes becomes a burst of cheap `pg_notify` calls,
/// never a burst of pool checkouts per message). The LISTEN half holds its own dedicated
/// connection (LISTEN state must never leak back into the pool) and reconnects with backoff.
pub fn spawn_wake_bus(
    notifier: DeliveryNotifier,
    pool: crate::pgstore::PgPool,
    listen_url: String,
) {
    // Publisher: wake() -> channel -> pg_notify.
    let (tx, rx) = std::sync::mpsc::channel::<[u8; 16]>();
    notifier.set_publisher(Arc::new(move |device| {
        let _ = tx.send(device); // receiver gone = shutdown; nothing to do
    }));
    std::thread::Builder::new()
        .name("wake-publish".into())
        .spawn(move || {
            while let Ok(first) = rx.recv() {
                // Batch whatever is already queued behind it into one connection checkout.
                let mut batch = vec![first];
                while let Ok(more) = rx.try_recv() {
                    batch.push(more);
                    if batch.len() >= 256 {
                        break;
                    }
                }
                let Ok(mut conn) = pool.get() else { continue };
                for device in batch {
                    let _ = conn.execute(
                        "SELECT pg_notify($1, $2)",
                        &[&WAKE_CHANNEL, &hex::encode(device)],
                    );
                }
            }
        })
        .expect("spawn wake-publish");

    // Listener: dedicated connection, LISTEN, forward payloads as LOCAL wakes.
    std::thread::Builder::new()
        .name("wake-listen".into())
        .spawn(move || {
            loop {
                let mut client = match postgres::Client::connect(&listen_url, postgres::NoTls) {
                    Ok(c) => c,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }
                };
                if client
                    .batch_execute(&format!("LISTEN {WAKE_CHANNEL}"))
                    .is_err()
                {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    continue;
                }
                let mut notifications = client.notifications();
                let mut iter = notifications.blocking_iter();
                // FallibleIterator: Ok(None) or Err both mean the connection is gone.
                loop {
                    use fallible_iterator::FallibleIterator;
                    match iter.next() {
                        Ok(Some(n)) => {
                            if let Ok(bytes) = hex::decode(n.payload()) {
                                if let Ok(device) = <[u8; 16]>::try_from(bytes.as_slice()) {
                                    notifier.wake_local(&device);
                                }
                            }
                        }
                        Ok(None) | Err(_) => break, // connection gone: reconnect with backoff
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        })
        .expect("spawn wake-listen");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn wake_invokes_the_hook_with_the_device() {
        let notifier = DeliveryNotifier::default();
        let seen = Arc::new(Mutex::new(Vec::<[u8; 16]>::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let (seen2, count2) = (seen.clone(), count.clone());
        notifier.set_wake_hook(Arc::new(move |d| {
            seen2.lock().unwrap().push(d);
            count2.fetch_add(1, Ordering::SeqCst);
        }));
        notifier.wake(&[9u8; 16]);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(seen.lock().unwrap().as_slice(), &[[9u8; 16]]);
    }

    #[test]
    fn wake_without_a_hook_is_a_no_op() {
        let notifier = DeliveryNotifier::default();
        notifier.wake(&[1u8; 16]); // must not panic
    }
}
