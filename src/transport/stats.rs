// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Atomic portal traffic and session counters.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Atomic counters used by telemetry and relay accounting.
#[derive(Debug, Default)]
pub struct Stats {
    /// Bytes read from TCP clients and sent to targets.
    pub tcp_rx: AtomicU64,
    /// Bytes read from TCP targets and sent to clients.
    pub tcp_tx: AtomicU64,
    /// Bytes read from UDP clients and sent to targets.
    pub udp_rx: AtomicU64,
    /// Bytes read from UDP targets and sent to clients.
    pub udp_tx: AtomicU64,
    /// Currently active TCP relay sessions.
    pub tcp_active: AtomicI32,
    /// Currently active UDP relay sessions.
    pub udp_active: AtomicI32,
}

impl Stats {
    /// Increments the active session counter for the selected transport.
    pub fn add_session(&self, is_udp: bool) {
        if is_udp {
            self.udp_active.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tcp_active.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrements the active session counter for the selected transport.
    pub fn done_session(&self, is_udp: bool) {
        if is_udp {
            self.udp_active.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.tcp_active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
#[path = "../tests/transport/stats.rs"]
mod tests;
