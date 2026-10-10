// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Atomic logical flow, carrier payload, and active ownership counters.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use crate::protocol::Carrier;

#[derive(Clone, Copy)]
pub(crate) enum TrafficDirection {
    Upload,
    Download,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub tcp_upload_bytes: AtomicU64,
    pub tcp_download_bytes: AtomicU64,
    pub udp_upload_bytes: AtomicU64,
    pub udp_download_bytes: AtomicU64,
    pub tcp_active: AtomicI32,
    pub udp_active: AtomicI32,
    pub tls_carriers_active: AtomicU64,
    pub quic_carriers_active: AtomicU64,
    pub tls_upload_bytes: AtomicU64,
    pub quic_upload_bytes: AtomicU64,
    pub tls_download_bytes: AtomicU64,
    pub quic_download_bytes: AtomicU64,
}

impl Stats {
    pub(crate) fn payload_counter(
        &self,
        carrier: Carrier,
        direction: TrafficDirection,
    ) -> &AtomicU64 {
        match (carrier, direction) {
            (Carrier::TlsTcp, TrafficDirection::Upload) => &self.tls_upload_bytes,
            (Carrier::TlsTcp, TrafficDirection::Download) => &self.tls_download_bytes,
            (Carrier::Quic, TrafficDirection::Upload) => &self.quic_upload_bytes,
            (Carrier::Quic, TrafficDirection::Download) => &self.quic_download_bytes,
        }
    }

    pub fn add_flow(&self, is_udp: bool) {
        if is_udp {
            self.udp_active.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tcp_active.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn done_flow(&self, is_udp: bool) {
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
