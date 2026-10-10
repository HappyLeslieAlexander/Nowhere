// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry subscriptions, snapshots, and event delivery tests.

use std::sync::atomic::Ordering;

use crate::protocol::Carrier;
use crate::telemetry::{
    AccessOutcome, AccessStart, InstanceDescriptor, InstanceRole, RuntimeEvent, RuntimeKind,
    RuntimeLevel, ServerMessage, TELEMETRY_PROTOCOL, TelemetryHub, TrafficProtocol,
};
use crate::transport::Stats;

fn descriptor() -> InstanceDescriptor {
    InstanceDescriptor {
        telemetry_protocol: TELEMETRY_PROTOCOL.to_owned(),
        id: "0123456789abcdef0123456789abcdef".to_owned(),
        role: InstanceRole::Portal,
        pid: 2,
        uid: 1,
        incarnation: 3,
        version: "test".to_owned(),
        endpoint: ":2000".to_owned(),
        config_summary: "listen=:2000 out=direct".to_owned(),
        telemetry_interval_ms: 1_000,
    }
}

#[test]
fn descriptor_serializes_operator_metadata_without_local_identity() {
    let hub = TelemetryHub::new(descriptor());
    let encoded = serde_json::to_string(hub.descriptor()).unwrap();
    assert!(encoded.contains("2000"));
    assert!(encoded.contains("config_summary"));
    assert!(!encoded.contains("\"uid\""));
    assert!(!encoded.contains("incarnation"));
}

#[test]
fn access_span_finishes_only_once() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    let _detail = hub.detail_guard();
    let span = hub.start_access(|| AccessStart {
        protocol: TrafficProtocol::Tcp,
        client: Some("127.0.0.1:1".to_owned()),
        peer: Some("127.0.0.1:1".to_owned()),
        target: "example:443".to_owned(),
        carrier: Carrier::TlsTcp,
    });
    span.add_upload(10);
    span.add_download(20);
    span.finish(AccessOutcome::Success, None);

    assert!(matches!(
        events.try_recv(),
        Ok(ServerMessage::AccessStart(_))
    ));
    let Ok(ServerMessage::AccessFinish(finish)) = events.try_recv() else {
        panic!("missing access finish");
    };
    assert_eq!(finish.upload_bytes, 10);
    assert_eq!(finish.download_bytes, 20);
    assert_eq!(finish.carrier, Carrier::TlsTcp);
    assert_eq!(finish.peer.as_deref(), Some("P001"));
    assert_eq!(finish.outcome, AccessOutcome::Success);
    assert!(events.try_recv().is_err());
}

#[test]
fn access_fields_are_not_built_without_a_receiver() {
    let hub = TelemetryHub::new(descriptor());
    let span = hub.start_access(|| panic!("unobservable access must stay lazy"));

    span.add_upload(10);
    span.add_download(20);
    span.finish(AccessOutcome::Success, None);
}

#[test]
fn snapshot_keeps_logical_and_carrier_directions_distinct() {
    let hub = TelemetryHub::new(descriptor());
    let stats = Stats::default();
    stats.tcp_upload_bytes.store(42, Ordering::Relaxed);
    stats.tcp_download_bytes.store(43, Ordering::Relaxed);
    stats.udp_upload_bytes.store(44, Ordering::Relaxed);
    stats.udp_download_bytes.store(45, Ordering::Relaxed);
    stats.tls_upload_bytes.store(46, Ordering::Relaxed);
    stats.tls_download_bytes.store(47, Ordering::Relaxed);
    stats.quic_upload_bytes.store(48, Ordering::Relaxed);
    stats.quic_download_bytes.store(49, Ordering::Relaxed);
    stats.tls_carriers_active.store(2, Ordering::Relaxed);
    hub.capture_and_publish(&stats, 17);
    let snapshot = hub.snapshots.borrow().clone();
    assert_eq!(snapshot.tcp_upload_bytes, 42);
    assert_eq!(snapshot.tcp_download_bytes, 43);
    assert_eq!(snapshot.udp_upload_bytes, 44);
    assert_eq!(snapshot.udp_download_bytes, 45);
    assert_eq!(snapshot.tls_upload_bytes, 46);
    assert_eq!(snapshot.tls_download_bytes, 47);
    assert_eq!(snapshot.quic_upload_bytes, 48);
    assert_eq!(snapshot.quic_download_bytes, 49);
    assert_eq!(snapshot.tls_carriers_active, 2);
    assert_eq!(snapshot.ping_ms, Some(17));
}

#[test]
fn detail_guards_balance_switches_and_drop() {
    let hub = TelemetryHub::new(descriptor());
    let receiver = hub.event_receiver();
    let _span = hub.start_access(|| panic!("a summary receiver is not detail"));
    let first = hub.detail_guard();
    let second = hub.detail_guard();
    assert_eq!(hub.detail_clients.load(Ordering::Relaxed), 2);
    drop(first);
    assert_eq!(hub.detail_clients.load(Ordering::Relaxed), 1);
    drop(second);
    assert_eq!(hub.detail_clients.load(Ordering::Relaxed), 0);
    drop(receiver);
}

#[test]
fn publisher_rechecks_runtime_diagnostics_before_delivery() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    let _detail = hub.detail_guard();
    let mut event = RuntimeEvent::new(
        RuntimeLevel::Warn,
        RuntimeKind::Carrier,
        "QUIC carrier connected",
    );
    event.message = "QUIC carrier connected: secret-key /private/key.pem\x1b[31m".to_owned();
    event.client = Some("203.0.113.5:4321".to_owned());
    hub.emit_runtime(event);
    let Ok(ServerMessage::RuntimeEvent(event)) = events.try_recv() else {
        panic!("missing runtime event")
    };
    assert_eq!(event.message, "QUIC carrier connected: operation failed");
    assert_eq!(event.client.as_deref(), Some("C001"));
    let encoded = serde_json::to_string(&event).unwrap();
    assert!(encoded.contains("\"message\""));
    assert!(!encoded.contains("secret-key"));
    assert!(!encoded.contains("203.0.113.5"));
}
#[test]
fn unavailable_rtt_remains_null_and_registration_updates_sequence() {
    let hub = TelemetryHub::new(descriptor());
    let stats = Stats::default();
    hub.capture_and_publish(&stats, 0);
    assert_eq!(hub.snapshot_receiver().borrow().ping_ms, None);
    let previous = hub.snapshot_receiver().borrow().sequence;
    hub.set_egress_online(Some(true));
    hub.capture_and_publish(&stats, 17);
    assert_eq!(hub.snapshot_receiver().borrow().ping_ms, Some(17));
    hub.set_egress_online(Some(false));
    assert_eq!(hub.snapshot_receiver().borrow().egress_online, Some(false));
    assert_eq!(hub.snapshot_receiver().borrow().ping_ms, None);
    assert!(hub.snapshot_receiver().borrow().sequence > previous);
    hub.capture_and_publish(&stats, 17);
    assert_eq!(hub.snapshot_receiver().borrow().ping_ms, None);
    hub.set_egress_online(Some(true));
    assert_eq!(hub.snapshot_receiver().borrow().egress_online, Some(true));
}

#[test]
fn concurrent_sampling_and_registration_keep_snapshots_ordered() {
    let hub = TelemetryHub::new(descriptor());
    let completed = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let hub = &hub;
            let completed = &completed;
            scope.spawn(move || {
                for _ in 0..300 {
                    hub.capture_and_publish(&Stats::default(), 0);
                }
                completed.fetch_add(1, Ordering::Release);
            });
        }
        let hub_ref = &hub;
        let completed_ref = &completed;
        scope.spawn(move || {
            for index in 0..600 {
                hub_ref.set_egress_online(Some(index % 2 == 0));
            }
            completed_ref.fetch_add(1, Ordering::Release);
        });
        let mut previous = 0;
        while completed.load(Ordering::Acquire) != 3 {
            let snapshot = hub.snapshot_receiver().borrow().clone();
            assert!(snapshot.sequence >= previous, "snapshot sequence regressed");
            previous = snapshot.sequence;
            std::thread::yield_now();
        }
    });
    assert_eq!(hub.snapshot_receiver().borrow().egress_online, Some(false));
}
