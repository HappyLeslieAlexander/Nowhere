// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Atomic logical traffic totals and active Flow ownership counters.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Stats {
    pub tcp_upload_bytes: AtomicU64,
    pub tcp_download_bytes: AtomicU64,
    pub udp_upload_bytes: AtomicU64,
    pub udp_download_bytes: AtomicU64,
    pub tcp_active: AtomicI32,
    pub udp_active: AtomicI32,
    /// Datagrams dropped before routing: undecodable, FRAG != 0, or a zero
    /// target port. UDP is lossy by design, but silent loss hides incidents.
    pub udp_dropped_malformed: AtomicU64,
    /// Datagrams from a source that does not match the association lock.
    pub udp_dropped_source_mismatch: AtomicU64,
    /// Datagrams dropped under resource pressure: exhausted byte budgets,
    /// full queues, or target admission limits.
    pub udp_dropped_busy: AtomicU64,
    /// Pre-authentication connections closed without a reply: morph probe
    /// garbage, park timeouts, SOCKS admission exhaustion, QUIC ignores.
    pub silent_rejections: AtomicU64,
}

impl Stats {
    pub(crate) fn snapshot(&self) -> crate::telemetry::TelemetrySnapshot {
        crate::telemetry::TelemetrySnapshot {
            tcp_upload_bytes: self.tcp_upload_bytes.load(Ordering::Relaxed),
            tcp_download_bytes: self.tcp_download_bytes.load(Ordering::Relaxed),
            udp_upload_bytes: self.udp_upload_bytes.load(Ordering::Relaxed),
            udp_download_bytes: self.udp_download_bytes.load(Ordering::Relaxed),
            tcp_active: i64::from(self.tcp_active.load(Ordering::Relaxed)),
            udp_active: i64::from(self.udp_active.load(Ordering::Relaxed)),
            udp_dropped_malformed: self.udp_dropped_malformed.load(Ordering::Relaxed),
            udp_dropped_source_mismatch: self.udp_dropped_source_mismatch.load(Ordering::Relaxed),
            udp_dropped_busy: self.udp_dropped_busy.load(Ordering::Relaxed),
            silent_rejections: self.silent_rejections.load(Ordering::Relaxed),
        }
    }

    pub fn add_flow(&self, is_udp: bool) {
        if is_udp {
            self.udp_active.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tcp_active.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn remove_flow(&self, is_udp: bool) {
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
