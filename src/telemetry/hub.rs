// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! In-process structured telemetry publisher.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, watch};

use super::{DiagnosticContext, ResultCode};
use crate::common::{LifeReason, LifeState};
use crate::transport::Stats;

use super::process::{ProcessSampler, now_unix_ms, process_uptime_ms};
use super::wire::{
    AccessFinished, AccessStart, AccessStarted, Diagnostic, Event, InstanceDescriptor,
    InstanceRole, TelemetrySnapshot,
};

const EVENT_CAPACITY: usize = 1_024;

pub(crate) struct TelemetryHub {
    descriptor: InstanceDescriptor,
    event_sequence: Mutex<u64>,
    snapshots: watch::Sender<TelemetrySnapshot>,
    events: broadcast::Sender<Event>,
    next_access_id: AtomicU64,
    started: Instant,
    process_sampler: Mutex<ProcessSampler>,
    unavailable_reason: Option<String>,
}

impl TelemetryHub {
    pub(crate) fn new(descriptor: InstanceDescriptor) -> Arc<Self> {
        Self::with_availability(descriptor, None)
    }

    pub(crate) fn for_current_process(
        role: InstanceRole,
        endpoint: impl Into<String>,
        telemetry_interval: Duration,
    ) -> Arc<Self> {
        let endpoint = endpoint.into();
        match InstanceDescriptor::current(role, endpoint.clone(), telemetry_interval) {
            Ok(descriptor) => Self::new(descriptor),
            Err(error) => Self::with_availability(
                InstanceDescriptor::unavailable(role, endpoint, telemetry_interval),
                Some(error.to_string()),
            ),
        }
    }

    fn with_availability(
        descriptor: InstanceDescriptor,
        unavailable_reason: Option<String>,
    ) -> Arc<Self> {
        let (snapshots, _) = watch::channel(TelemetrySnapshot {
            timestamp_ms: now_unix_ms(),
            lifecycle_timestamp_ms: now_unix_ms(),
            ..TelemetrySnapshot::default()
        });
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Arc::new(Self {
            descriptor,
            event_sequence: Mutex::new(0),
            snapshots,
            events,
            next_access_id: AtomicU64::new(1),
            started: Instant::now(),
            process_sampler: Mutex::new(ProcessSampler::default()),
            unavailable_reason,
        })
    }

    pub(crate) fn descriptor(&self) -> &InstanceDescriptor {
        &self.descriptor
    }

    fn publish_event(&self, mut event: Event) {
        let mut sequence = self
            .event_sequence
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *sequence += 1;
        event.set_sequence(*sequence);
        let _ = self.events.send(event);
    }

    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    pub(crate) fn set_lifecycle(&self, state: LifeState, reason: LifeReason) {
        self.snapshots.send_modify(|snapshot| {
            snapshot.lifecycle = state;
            snapshot.lifecycle_reason = reason;
            snapshot.lifecycle_timestamp_ms = now_unix_ms();
            snapshot.sequence += 1;
            snapshot.timestamp_ms = snapshot.lifecycle_timestamp_ms;
        });
    }

    pub(crate) fn set_egress_online(&self, online: Option<bool>) {
        self.snapshots.send_if_modified(|snapshot| {
            if snapshot.egress_online == online {
                return false;
            }
            snapshot.egress_online = online;
            snapshot.sequence += 1;
            snapshot.timestamp_ms = now_unix_ms();
            true
        });
    }

    pub(crate) fn capture_and_publish(&self, stats: &Stats) {
        let mut sampler = self
            .process_sampler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let process = sampler.sample();
        self.snapshots.send_modify(|current| {
            current.sequence += 1;
            current.timestamp_ms = now_unix_ms();
            current.uptime_ms = process_uptime_ms(self.descriptor.incarnation)
                .unwrap_or_else(|| self.started.elapsed().as_millis().min(u64::MAX as u128) as u64);
            current.tcp_upload_bytes = stats.tcp_upload_bytes.load(Ordering::Relaxed);
            current.tcp_download_bytes = stats.tcp_download_bytes.load(Ordering::Relaxed);
            current.udp_upload_bytes = stats.udp_upload_bytes.load(Ordering::Relaxed);
            current.udp_download_bytes = stats.udp_download_bytes.load(Ordering::Relaxed);
            current.tls_upload_bytes = stats.tls_upload_bytes.load(Ordering::Relaxed);
            current.tls_download_bytes = stats.tls_download_bytes.load(Ordering::Relaxed);
            current.quic_upload_bytes = stats.quic_upload_bytes.load(Ordering::Relaxed);
            current.quic_download_bytes = stats.quic_download_bytes.load(Ordering::Relaxed);
            current.tls_carriers_active = stats.tls_carriers_active.load(Ordering::Relaxed);
            current.quic_carriers_active = stats.quic_carriers_active.load(Ordering::Relaxed);
            current.tcp_active = i64::from(stats.tcp_active.load(Ordering::Relaxed));
            current.udp_active = i64::from(stats.udp_active.load(Ordering::Relaxed));
            current.cpu_percent = process.cpu_percent;
            current.rss_bytes = process.rss_bytes;
            current.open_fds = process.open_fds;
        });
    }

    pub(crate) fn emit_diagnostic(&self, context: DiagnosticContext, reason: ResultCode) {
        if self.events.receiver_count() == 0 {
            return;
        }
        self.publish_event(Event::Diagnostic(Diagnostic {
            sequence: 0,
            timestamp_ms: now_unix_ms(),
            context,
            reason,
        }));
    }

    pub(crate) fn start_access(
        self: &Arc<Self>,
        build: impl FnOnce() -> AccessStart,
    ) -> AccessSpan {
        if self.events.receiver_count() == 0 {
            return AccessSpan(None);
        }
        let start = build();
        let started = AccessStarted {
            sequence: 0,
            id: self.next_access_id.fetch_add(1, Ordering::Relaxed),
            timestamp_ms: now_unix_ms(),
            protocol: start.protocol,
            target: super::privacy::target(&start.target),
            carrier: start.carrier,
        };
        let id = started.id;
        self.publish_event(Event::AccessStart(started));
        AccessSpan(Some(ActiveAccess {
            hub: Arc::clone(self),
            id,
        }))
    }

    pub(crate) fn snapshot_receiver(&self) -> watch::Receiver<TelemetrySnapshot> {
        self.snapshots.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn events_receiver_count_for_test(&self) -> usize {
        self.events.receiver_count()
    }

    pub(crate) fn event_receiver(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn finish_access(&self, id: u64, result: ResultCode) {
        self.publish_event(Event::AccessFinish(AccessFinished {
            sequence: 0,
            id,
            timestamp_ms: now_unix_ms(),
            result,
        }));
    }
}

pub(crate) struct AccessSpan(Option<ActiveAccess>);

struct ActiveAccess {
    hub: Arc<TelemetryHub>,
    id: u64,
}

impl AccessSpan {
    pub(crate) fn finish(mut self, result: ResultCode) {
        self.finish_once(result);
    }

    fn finish_once(&mut self, result: ResultCode) {
        if let Some(active) = self.0.take() {
            active.hub.finish_access(active.id, result);
        }
    }
}

impl Drop for AccessSpan {
    fn drop(&mut self) {
        self.finish_once(ResultCode::Cancelled);
    }
}

#[cfg(test)]
#[path = "../tests/telemetry/hub.rs"]
mod tests;
