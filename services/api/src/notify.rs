//! In-process delivery notifications for long-polling. When an envelope is queued for a
//! device, waiters on that device's inbox wake immediately instead of polling — dropping
//! idle delivery latency to near-zero while a waiting client costs **zero** database
//! queries (unlike a server-side poll loop).
//!
//! This is single-instance. Across multiple API instances a client's waiter and its
//! sender may live on different processes, so production adds a cross-instance signal
//! (PostgreSQL `LISTEN/NOTIFY` or a lightweight bus). The database remains the source of
//! truth and every wait is bounded by a timeout, so a missed cross-instance notification
//! only delays delivery by the poll timeout — it never loses a message.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

#[derive(Clone, Default)]
pub struct DeliveryNotifier {
    inner: Arc<Mutex<HashMap<[u8; 16], Arc<Notify>>>>,
}

impl DeliveryNotifier {
    /// Get (or create) the notify handle for a device. Callers register interest on this
    /// handle *before* their initial inbox check to avoid a lost-wakeup window.
    pub fn handle(&self, device: &[u8; 16]) -> Arc<Notify> {
        let mut map = self.inner.lock().unwrap();
        map.entry(*device)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Signal that a device has new mail. `notify_one` stores a single permit if no waiter
    /// is currently parked, so a notification that races just ahead of a waiter's park is
    /// still delivered on its next poll.
    pub fn wake(&self, device: &[u8; 16]) {
        let handle = {
            let map = self.inner.lock().unwrap();
            map.get(device).cloned()
        };
        if let Some(notify) = handle {
            notify.notify_one();
        }
    }
}
