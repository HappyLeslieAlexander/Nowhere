// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! In-process structured telemetry publisher.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, watch};

use crate::transport::Stats;

use super::process::{ProcessSampler, now_unix_ms, process_uptime_ms};
use super::wire::{
    AccessFinished, AccessOutcome, AccessStart, AccessStarted, InstanceDescriptor, InstanceRole,
    LifecycleSnapshot, RuntimeEvent, RuntimeKind, RuntimeLevel, ServerMessage, TelemetrySnapshot,
};

const DETAIL_EVENT_CAPACITY: usize = 1_024;

pub(crate) struct TelemetryHub {
    descriptor: InstanceDescriptor,
    privacy: Option<super::privacy::Privacy>,
    detail_clients: AtomicU64,
    event_sequence: Mutex<u64>,
    lifecycle: watch::Sender<LifecycleSnapshot>,
    snapshots: watch::Sender<TelemetrySnapshot>,
    events: broadcast::Sender<ServerMessage>,
    next_sequence: AtomicU64,
    next_access_id: AtomicU64,
    started: Instant,
    process_sampler: Mutex<ProcessSampler>,
    unavailable_reason: Option<String>,
    egress_online: Mutex<Option<bool>>,
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
            detail_clients: AtomicU64::new(0),
            event_sequence: Mutex::new(0),
            lifecycle,
            snapshots,
            events,
            next_sequence: AtomicU64::new(1),
            next_access_id: AtomicU64::new(1),
            started: Instant::now(),
            process_sampler: Mutex::new(ProcessSampler::default()),
            unavailable_reason,
            egress_online: Mutex::new(None),
        })
    }

    pub(crate) fn descriptor(&self) -> &InstanceDescriptor {
        &self.descriptor
    }

    pub(crate) fn detail_guard(self: &Arc<Self>) -> DetailGuard {
        self.detail_clients.fetch_add(1, Ordering::Relaxed);
        DetailGuard(self.clone())
    }

    fn publish_event(&self, mut event: ServerMessage) {
        let mut sequence = self
            .event_sequence
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *sequence += 1;
        match &mut event {
            ServerMessage::RuntimeEvent(e) => e.sequence = *sequence,
            ServerMessage::AccessStart(e) => e.sequence = *sequence,
            ServerMessage::AccessFinish(e) => e.sequence = *sequence,
            _ => return,
        }
        let _ = self.events.send(event);
    }

    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    pub(crate) fn set_lifecycle(&self, state: impl Into<String>, reason: impl Into<String>) {
        let state = state.into();
        let state = if matches!(
            state.as_str(),
            "STARTING" | "READY" | "DRAINING" | "STOPPED"
        ) {
            state
        } else {
            "STOPPED".to_owned()
        };
        let reason = reason.into();
        let reason = super::privacy::lifecycle_reason(&reason).to_owned();
        self.lifecycle.send_replace(LifecycleSnapshot {
            state: state.clone(),
            reason: reason.clone(),
            timestamp_ms: now_unix_ms(),
        });
        self.emit_runtime(RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Lifecycle,
            format!("{state}: {reason}"),
        ));
    }

    pub(crate) fn lifecycle_receiver(&self) -> watch::Receiver<LifecycleSnapshot> {
        self.lifecycle.subscribe()
    }

    pub(crate) fn set_egress_online(&self, online: Option<bool>) {
        let mut current = self.egress_online.lock().unwrap();
        if *current == online {
            return;
        }
        *current = online;
        self.snapshots.send_modify(|snapshot| {
            snapshot.egress_online = online;
            if online != Some(true) {
                snapshot.ping_ms = None;
            }
            snapshot.sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
            snapshot.timestamp_ms = now_unix_ms();
        });
        self.emit_runtime(RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            if online == Some(true) {
                "Egress online"
            } else {
                "Egress offline"
            },
        ));
    }

    pub(crate) fn capture_and_publish(&self, stats: &Stats, ping_ms: u64) {
        let process = self
            .process_sampler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner())
            .sample();
        let tls_carriers_active = stats.tls_carriers_active.load(Ordering::Relaxed);
        let quic_carriers_active = stats.quic_carriers_active.load(Ordering::Relaxed);
        let online = self.egress_online.lock().unwrap();
        let snapshot = TelemetrySnapshot {
            egress_online: *online,
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            timestamp_ms: now_unix_ms(),
            uptime_ms: process_uptime_ms(self.descriptor.incarnation)
                .unwrap_or_else(|| self.started.elapsed().as_millis().min(u64::MAX as u128) as u64),
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
            tls_carriers_active,
            quic_carriers_active,
            ..TelemetrySnapshot::default()
        };
        let snapshot = TelemetrySnapshot {
            ping_ms: (ping_ms > 0 && *online != Some(false)).then_some(ping_ms),
            cpu_percent: process.cpu_percent,
            rss_bytes: process.rss_bytes,
            open_fds: process.open_fds,
            ..snapshot
        };
        self.snapshots.send_replace(snapshot);
    }

    pub(crate) fn emit_runtime(&self, mut event: RuntimeEvent) {
        if self.detail_clients.load(Ordering::Relaxed) == 0 {
            return;
        }
        event.message = super::privacy::runtime_message(event.kind, event.level, &event.message);
        event.client = event.client.map(|v| {
            self.privacy
                .as_ref()
                .expect("available privacy")
                .alias("client", &v)
        });
        self.publish_event(ServerMessage::RuntimeEvent(event));
    }

    pub(crate) fn start_access(
        self: &Arc<Self>,
        build: impl FnOnce() -> AccessStart,
    ) -> AccessSpan {
        if self.detail_clients.load(Ordering::Relaxed) == 0 || self.privacy.is_none() {
            return AccessSpan::disabled(Arc::clone(self));
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
        self.publish_event(ServerMessage::AccessStart(started.clone()));
        AccessSpan::new(Arc::clone(self), started, started_at)
    }

    pub(crate) fn snapshot_receiver(&self) -> watch::Receiver<TelemetrySnapshot> {
        self.snapshots.subscribe()
    }

    pub(crate) fn event_receiver(&self) -> broadcast::Receiver<ServerMessage> {
        self.events.subscribe()
    }

    fn finish_access(
        &self,
        started: &AccessStarted,
        started_at: Instant,
        bytes: (u64, u64),
        completion: (AccessOutcome, Option<String>),
    ) {
        let (upload_bytes, download_bytes) = bytes;
        let (outcome, error) = completion;
        self.publish_event(ServerMessage::AccessFinish(AccessFinished {
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
            error: error.map(|value| super::privacy::error_reason(&value).to_owned()),
        }));
    }
}

pub(crate) struct AccessSpan {
    hub: Arc<TelemetryHub>,
    started: Option<AccessStarted>,
    started_at: Instant,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    finished: AtomicBool,
}

impl AccessSpan {
    fn new(hub: Arc<TelemetryHub>, started: AccessStarted, started_at: Instant) -> Self {
        Self {
            hub,
            started: Some(started),
            started_at,
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            finished: AtomicBool::new(false),
        }
    }

    fn disabled(hub: Arc<TelemetryHub>) -> Self {
        Self {
            hub,
            started: None,
            started_at: Instant::now(),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            finished: AtomicBool::new(false),
        }
    }

    pub(crate) fn add_upload(&self, bytes: u64) {
        if self.started.is_some() {
            self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn add_download(&self, bytes: u64) {
        if self.started.is_some() {
            self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn finish(self, outcome: AccessOutcome, error: Option<String>) {
        self.finish_once(outcome, error);
    }

    fn finish_once(&self, outcome: AccessOutcome, error: Option<String>) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(started) = &self.started else {
            return;
        };
        self.hub.finish_access(
            started,
            self.started_at,
            (
                self.upload_bytes.load(Ordering::Relaxed),
                self.download_bytes.load(Ordering::Relaxed),
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

pub(crate) struct DetailGuard(Arc<TelemetryHub>);
impl Drop for DetailGuard {
    fn drop(&mut self) {
        self.0.detail_clients.fetch_sub(1, Ordering::Relaxed);
    }
}
