//! In-process delivery notifications for long-polling: a queued envelope wakes that device's
//! waiters immediately, so a waiting client costs **zero** database queries.
//!
//! Single-instance. Across processes a waiter and its sender may differ, so production adds a
//! cross-instance signal (`LISTEN/NOTIFY` or a bus). The database stays the source of truth and
//! every wait is timeout-bounded, so a missed signal only delays delivery — it never loses a
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

#[derive(Default)]
struct Inner {
    waiters: HashMap<[u8; 16], Arc<Notify>>,
    on_wake: Option<WakeHook>,
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

    /// Signal that a device has new mail. `notify_one` stores a single permit if no waiter
    /// is currently parked, so a notification that races just ahead of a waiter's park is
    /// still delivered on its next poll. Also fires the wake hook (push) for a device that has
    /// no connected waiter.
    pub fn wake(&self, device: &[u8; 16]) {
        let (handle, hook) = {
            let g = self.inner.lock().unwrap();
            (g.waiters.get(device).cloned(), g.on_wake.clone())
        };
        if let Some(notify) = handle {
            notify.notify_one();
        }
        if let Some(hook) = hook {
            hook(*device);
        }
    }
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
