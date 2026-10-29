// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Atomic FIFO registration, carrier claims, and stale-entry cleanup.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;

use crate::transport::QuicConnection;

use super::TlsConnection;

pub(in crate::portal) type Transfer = oneshot::Sender<TlsConnection>;

enum EntryKind {
    Quic(Arc<QuicConnection>),
    Tls {
        sender: oneshot::Sender<Transfer>,
        expires_at: Instant,
    },
}

struct Entry {
    identity: Arc<()>,
    kind: EntryKind,
}

pub(crate) struct EgressRegistry {
    queue: Mutex<VecDeque<Entry>>,
    available: Notify,
    pending: Arc<Semaphore>,
    quic_pending: Arc<Semaphore>,
}

impl EgressRegistry {
    pub(in crate::portal) fn new(pending_max: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            available: Notify::new(),
            pending: Arc::new(Semaphore::new(pending_max)),
            quic_pending: Arc::new(Semaphore::new(pending_max)),
        }
    }

    pub(in crate::portal) fn reserve_tls(&self) -> Option<OwnedSemaphorePermit> {
        self.pending.clone().try_acquire_owned().ok()
    }

    pub(in crate::portal) fn reserve_quic(&self) -> Option<OwnedSemaphorePermit> {
        self.quic_pending.clone().try_acquire_owned().ok()
    }

    pub(in crate::portal) fn register_quic(
        self: &Arc<Self>,
        q: Arc<QuicConnection>,
        permit: OwnedSemaphorePermit,
    ) -> Registration {
        self.register(EntryKind::Quic(q), Some(permit))
    }

    pub(in crate::portal) fn register_tls(
        self: &Arc<Self>,
        sender: oneshot::Sender<Transfer>,
        expires_at: Instant,
    ) -> Registration {
        self.register(EntryKind::Tls { sender, expires_at }, None)
    }

    fn register(
        self: &Arc<Self>,
        kind: EntryKind,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Registration {
        let identity = Arc::new(());
        {
            let mut queue = self.queue.lock().unwrap_or_else(|err| err.into_inner());
            prune_locked(&mut queue);
            queue.push_back(Entry {
                identity: identity.clone(),
                kind,
            });
        }
        self.available.notify_waiters();
        Registration {
            registry: self.clone(),
            identity,
            _permit: permit,
        }
    }

    /// Drop dead QUIC entries and expired TLS standbys without waiting for a
    /// claim, so an idle Portal does not pin closed connections forever.
    pub(in crate::portal) fn prune(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(|err| err.into_inner());
        prune_locked(&mut queue);
    }

    pub(super) async fn claim(&self) -> Result<Selected> {
        loop {
            let notified = self.available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let selected = {
                let mut queue = self.queue.lock().unwrap_or_else(|err| err.into_inner());
                loop {
                    let Some(entry) = queue.pop_front() else {
                        break None;
                    };
                    match entry.kind {
                        EntryKind::Quic(q) => {
                            if q.connection.close_reason().is_some()
                                || q.cancel.is_cancelled()
                                || q.draining.is_cancelled()
                            {
                                continue;
                            }
                            queue.push_back(Entry {
                                identity: entry.identity,
                                kind: EntryKind::Quic(q.clone()),
                            });
                            break Some(Ok(Selected::Quic(q)));
                        }
                        EntryKind::Tls { sender, expires_at } if Instant::now() < expires_at => {
                            let (transfer, receiver) = oneshot::channel();
                            if sender.send(transfer).is_err() {
                                continue;
                            }
                            break Some(Ok(Selected::Tls(receiver)));
                        }
                        EntryKind::Tls { .. } => continue,
                    }
                }
            };
            match selected {
                Some(selected) => return selected,
                None => notified.await,
            }
        }
    }
}

fn prune_locked(queue: &mut VecDeque<Entry>) {
    queue.retain(|entry| match &entry.kind {
        EntryKind::Quic(q) => {
            q.connection.close_reason().is_none()
                && !q.cancel.is_cancelled()
                && !q.draining.is_cancelled()
        }
        EntryKind::Tls { expires_at, .. } => Instant::now() < *expires_at,
    });
}

pub(in crate::portal) struct Registration {
    registry: Arc<EgressRegistry>,
    identity: Arc<()>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.registry
            .queue
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .retain(|entry| !Arc::ptr_eq(&entry.identity, &self.identity));
    }
}

pub(super) enum Selected {
    Quic(Arc<QuicConnection>),
    Tls(oneshot::Receiver<TlsConnection>),
}

#[cfg(test)]
#[path = "../../tests/portal/egress/registry.rs"]
mod tests;
