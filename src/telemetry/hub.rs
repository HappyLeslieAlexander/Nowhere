// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! In-process structured telemetry publisher.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, watch};

use super::{DiagnosticReason, Runtime};
use crate::common::{LifeReason, LifeState};
use crate::transport::Stats;

use super::process::{ProcessSampler, now_unix_ms, process_uptime_ms};
use super::wire::{
    AccessFinished, AccessOutcome, AccessStart, AccessStarted, Event, InstanceDescriptor,
    InstanceRole, LifecycleSnapshot, TelemetrySnapshot,
};

const DETAIL_EVENT_CAPACITY: usize = 1_024;

pub(crate) struct TelemetryHub {
    descriptor: InstanceDescriptor,
    privacy: Option<super::privacy::Privacy>,
    event_sequence: Mutex<u64>,
    lifecycle: watch::Sender<LifecycleSnapshot>,
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
        config_summary: impl Into<String>,
        telemetry_interval: Duration,
    ) -> Arc<Self> {
        let endpoint = endpoint.into();
        let config_summary = config_summary.into();
        match InstanceDescriptor::current(
            role,
            endpoint.clone(),
            config_summary.clone(),
            telemetry_interval,
        ) {
            Ok(descriptor) => Self::new(descriptor),
            Err(error) => Self::with_availability(
                InstanceDescriptor::unavailable(role, endpoint, config_summary, telemetry_interval),
                Some(error.to_string()),
            ),
        }
    }

    fn with_availability(
        descriptor: InstanceDescriptor,
        unavailable_reason: Option<String>,
    ) -> Arc<Self> {
        let privacy = super::privacy::Privacy::new().ok();
        let unavailable_reason = unavailable_reason.or_else(|| {
            privacy
                .is_none()
                .then(|| "telemetry entropy unavailable".to_owned())
        });
        let (snapshots, _) = watch::channel(TelemetrySnapshot::default());
        let (lifecycle, _) = watch::channel(LifecycleSnapshot::default());
        let (events, _) = broadcast::channel(DETAIL_EVENT_CAPACITY);
        Arc::new(Self {
            descriptor,
            privacy,
            event_sequence: Mutex::new(0),
            lifecycle,
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
        self.lifecycle.send_replace(LifecycleSnapshot {
            state: state.to_string(),
            reason: reason.to_string(),
            timestamp_ms: now_unix_ms(),
        });
        self.emit_runtime(Runtime::Lifecycle(state, reason), None, None);
    }

    pub(crate) fn lifecycle_receiver(&self) -> watch::Receiver<LifecycleSnapshot> {
        self.lifecycle.subscribe()
    }

    pub(crate) fn set_egress_online(&self, online: Option<bool>) {
        let changed = self.snapshots.send_if_modified(|snapshot| {
            if snapshot.egress_online == online {
                return false;
            }
            snapshot.egress_online = online;
            if online != Some(true) {
                snapshot.ping_ms = None;
            }
            snapshot.sequence += 1;
            snapshot.timestamp_ms = now_unix_ms();
            true
        });
        if changed {
            self.emit_runtime(Runtime::EgressOnline(online == Some(true)), None, None);
        }
    }

    pub(crate) fn capture_and_publish(&self, stats: &Stats, ping_ms: u64) {
        let mut sampler = self
            .process_sampler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let process = sampler.sample();
        self.snapshots.send_modify(|current| {
            *current = TelemetrySnapshot {
                sequence: current.sequence + 1,
                timestamp_ms: now_unix_ms(),
                uptime_ms: process_uptime_ms(self.descriptor.incarnation).unwrap_or_else(|| {
                    self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
                }),
                egress_online: current.egress_online,
                tcp_upload_bytes: stats.tcp_upload_bytes.load(Ordering::Relaxed),
                tcp_download_bytes: stats.tcp_download_bytes.load(Ordering::Relaxed),
                udp_upload_bytes: stats.udp_upload_bytes.load(Ordering::Relaxed),
                udp_download_bytes: stats.udp_download_bytes.load(Ordering::Relaxed),
                tls_upload_bytes: stats.tls_upload_bytes.load(Ordering::Relaxed),
                tls_download_bytes: stats.tls_download_bytes.load(Ordering::Relaxed),
                quic_upload_bytes: stats.quic_upload_bytes.load(Ordering::Relaxed),
                quic_download_bytes: stats.quic_download_bytes.load(Ordering::Relaxed),
                tcp_active: i64::from(stats.tcp_active.load(Ordering::Relaxed)),
                udp_active: i64::from(stats.udp_active.load(Ordering::Relaxed)),
                tls_carriers_active: stats.tls_carriers_active.load(Ordering::Relaxed),
                quic_carriers_active: stats.quic_carriers_active.load(Ordering::Relaxed),
                ping_ms: (ping_ms > 0 && current.egress_online != Some(false)).then_some(ping_ms),
                cpu_percent: process.cpu_percent,
                rss_bytes: process.rss_bytes,
                open_fds: process.open_fds,
            };
        });
    }

    pub(crate) fn emit_runtime(
        &self,
        event: Runtime,
        reason: Option<DiagnosticReason>,
        client: Option<&str>,
    ) {
        if self.events.receiver_count() == 0 {
            return;
        }
        let Some(privacy) = &self.privacy else {
            return;
        };
        let client = client.map(|value| privacy.alias("client", value));
        self.publish_event(Event::RuntimeEvent(event.into_event(reason, client)));
    }

    pub(crate) fn start_access(
        self: &Arc<Self>,
        build: impl FnOnce() -> AccessStart,
    ) -> AccessSpan {
        if self.events.receiver_count() == 0 || self.privacy.is_none() {
            return AccessSpan(None);
        }
        let start = build();
        let started_at = Instant::now();
        let privacy = self.privacy.as_ref().expect("available privacy");
        let started = AccessStarted {
            sequence: 0,
            id: self.next_access_id.fetch_add(1, Ordering::Relaxed),
            timestamp_ms: now_unix_ms(),
            protocol: start.protocol,
            client: start.client.map(|v| privacy.alias("client", &v)),
            peer: start.peer.map(|v| privacy.alias("peer", &v)),
            target: super::privacy::target(&start.target),
            carrier: start.carrier,
        };
        self.publish_event(Event::AccessStart(started.clone()));
        AccessSpan::new(Arc::clone(self), started, started_at)
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

    fn finish_access(
        &self,
        started: &AccessStarted,
        started_at: Instant,
        bytes: (u64, u64),
        completion: (AccessOutcome, Option<DiagnosticReason>),
    ) {
        let (upload_bytes, download_bytes) = bytes;
        let (outcome, error) = completion;
        self.publish_event(Event::AccessFinish(AccessFinished {
            sequence: 0,
            id: started.id,
            timestamp_ms: now_unix_ms(),
            duration_ms: started_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
            protocol: started.protocol,
            client: started.client.clone(),
            peer: started.peer.clone(),
            target: started.target.clone(),
            carrier: started.carrier,
            upload_bytes,
            download_bytes,
            outcome,
            error: error.map(|value| value.as_str().to_owned()),
        }));
    }
}

/// Disabled observations carry no publisher, clock or counters.
pub(crate) struct AccessSpan(Option<ActiveAccess>);

struct ActiveAccess {
    hub: Arc<TelemetryHub>,
    started: AccessStarted,
    started_at: Instant,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
}

impl AccessSpan {
    fn new(hub: Arc<TelemetryHub>, started: AccessStarted, started_at: Instant) -> Self {
        Self(Some(ActiveAccess {
            hub,
            started,
            started_at,
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
        }))
    }

    pub(crate) fn add_upload(&self, bytes: u64) {
        if let Some(active) = &self.0 {
            active.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn add_download(&self, bytes: u64) {
        if let Some(active) = &self.0 {
            active.download_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn finish(mut self, outcome: AccessOutcome, error: Option<DiagnosticReason>) {
        self.finish_once(outcome, error);
    }

    pub(crate) fn finish_error(self, reason: DiagnosticReason) {
        self.finish(AccessOutcome::from_reason(reason), Some(reason));
    }

    fn finish_once(&mut self, outcome: AccessOutcome, error: Option<DiagnosticReason>) {
        let Some(active) = self.0.take() else {
            return;
        };
        active.hub.finish_access(
            &active.started,
            active.started_at,
            (
                active.upload_bytes.load(Ordering::Relaxed),
                active.download_bytes.load(Ordering::Relaxed),
            ),
            (outcome, error),
        );
    }
}

impl Drop for AccessSpan {
    fn drop(&mut self) {
        self.finish_once(AccessOutcome::Cancelled, None);
    }
}

#[cfg(test)]
#[path = "../tests/telemetry/hub.rs"]
mod tests;
