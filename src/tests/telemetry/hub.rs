// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry subscriptions, snapshots, and event delivery tests.

use std::sync::atomic::Ordering;

use crate::protocol::Carrier;
use crate::telemetry::{
    AccessOutcome, AccessStart, Event, InstanceDescriptor, InstanceRole, Runtime,
    TELEMETRY_PROTOCOL, TelemetryHub, TrafficProtocol,
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

    assert!(matches!(events.try_recv(), Ok(Event::AccessStart(_))));
    let Ok(Event::AccessFinish(finish)) = events.try_recv() else {
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
fn only_event_receivers_enable_access_collection() {
    let hub = TelemetryHub::new(descriptor());
    let _summary = hub.snapshot_receiver();
    let _lifecycle = hub.lifecycle_receiver();
    let span = hub.start_access(|| panic!("summary must not build access"));
    assert!(span.0.is_none());
    assert_eq!(std::sync::Arc::strong_count(&hub), 1);
    let first = hub.event_receiver();
    let second = hub.event_receiver();
    assert_eq!(hub.events.receiver_count(), 2);
    drop(first);
    assert_eq!(hub.events.receiver_count(), 1);
    drop(second);
    let _span = hub.start_access(|| panic!("disconnected receivers must not build access"));
}

#[test]
fn typed_runtime_diagnostics_and_client_aliases_are_safe() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    hub.emit_runtime(
        Runtime::QuicDisconnected,
        Some(super::super::privacy::error_reason(
            "secret-key /private/key.pem\x1b[31m",
        )),
        Some("203.0.113.5:4321"),
    );
    let Ok(Event::RuntimeEvent(event)) = events.try_recv() else {
        panic!("missing runtime event")
    };
    assert_eq!(event.message, "QUIC carrier disconnected: operation failed");
    assert_eq!(event.client.as_deref(), Some("C001"));
    let encoded = serde_json::to_string(&event).unwrap();
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
    let stats = Stats::default();
    let completed = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let hub = &hub;
            let completed = &completed;
            let stats = &stats;
            scope.spawn(move || {
                for _ in 0..300 {
                    stats.tcp_upload_bytes.fetch_add(1, Ordering::Relaxed);
                    hub.capture_and_publish(stats, 17);
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
        let mut previous_upload = 0;
        while completed.load(Ordering::Acquire) != 3 {
            let snapshot = hub.snapshot_receiver().borrow().clone();
            assert!(snapshot.sequence >= previous, "snapshot sequence regressed");
            if snapshot.egress_online == Some(false) {
                assert_eq!(snapshot.ping_ms, None);
            }
            assert!(
                snapshot.tcp_upload_bytes >= previous_upload,
                "cumulative traffic regressed"
            );
            previous_upload = snapshot.tcp_upload_bytes;
            previous = snapshot.sequence;
            std::thread::yield_now();
        }
    });
    assert_eq!(hub.snapshot_receiver().borrow().egress_online, Some(false));
    assert_eq!(hub.snapshot_receiver().borrow().tcp_upload_bytes, 600);
}

#[test]
fn access_completion_reasons_and_drop_preserve_self_contained_results() {
    let hub = TelemetryHub::new(descriptor());
    for (outcome, reason, drop_span) in [
        (AccessOutcome::Success, None, false),
        (
            AccessOutcome::Rejected,
            Some(super::super::DiagnosticReason::ResourceLimit),
            false,
        ),
        (
            AccessOutcome::Timeout,
            Some(super::super::DiagnosticReason::IdleTimeout),
            false,
        ),
        (AccessOutcome::Cancelled, None, false),
        (
            AccessOutcome::Error,
            Some(super::super::DiagnosticReason::ConnectionRefused),
            false,
        ),
        (AccessOutcome::Cancelled, None, true),
    ] {
        let mut initial = hub.event_receiver();
        let span = hub.start_access(|| AccessStart {
            protocol: TrafficProtocol::Udp,
            client: None,
            peer: None,
            target: "example.com:53".to_owned(),
            carrier: Carrier::Quic,
        });
        let Ok(Event::AccessStart(start)) = initial.try_recv() else {
            panic!("missing start")
        };
        // A subscriber arriving mid-Flow gets a complete finish without a start cache.
        let mut late = hub.event_receiver();
        std::thread::scope(|scope| {
            scope.spawn(|| span.add_upload(11));
            scope.spawn(|| span.add_download(23));
        });
        if drop_span {
            drop(span);
        } else {
            span.finish(outcome, reason);
        }
        let Ok(Event::AccessFinish(finish)) = late.try_recv() else {
            panic!("missing finish")
        };
        assert_eq!(finish.id, start.id);
        assert!(finish.sequence > start.sequence);
        assert_eq!(finish.target, start.target);
        assert_eq!(finish.protocol, start.protocol);
        assert_eq!(finish.carrier, start.carrier);
        assert_eq!((finish.upload_bytes, finish.download_bytes), (11, 23));
        assert_eq!(finish.outcome, outcome);
        assert_eq!(
            finish.error.as_deref(),
            reason.map(|reason| reason.as_str())
        );
        assert!(
            late.try_recv().is_err(),
            "completion must be published exactly once"
        );
    }
}

#[tokio::test]
async fn aborted_flow_publishes_one_cancelled_finish() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    let owner = hub.clone();
    let task = tokio::spawn(async move {
        let span = owner.start_access(|| AccessStart {
            protocol: TrafficProtocol::Tcp,
            client: None,
            peer: None,
            target: "example.com:443".to_owned(),
            carrier: Carrier::TlsTcp,
        });
        span.add_upload(7);
        std::future::pending::<()>().await;
        drop(span);
    });
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::AccessStart(_)
    ));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let Event::AccessFinish(finish) = events.try_recv().unwrap() else {
        panic!("missing finish")
    };
    assert_eq!(finish.outcome, AccessOutcome::Cancelled);
    assert_eq!(finish.upload_bytes, 7);
    assert!(events.try_recv().is_err());
}

#[test]
fn concurrent_runtime_publications_have_one_ordered_sequence() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let hub = &hub;
            scope.spawn(move || {
                for _ in 0..100 {
                    hub.emit_runtime(Runtime::QuicConnected, None, None);
                }
            });
        }
    });
    for sequence in 1..=400 {
        let Event::RuntimeEvent(event) = events.try_recv().unwrap() else {
            panic!("missing event")
        };
        assert_eq!(event.sequence, sequence);
    }
    assert!(events.try_recv().is_err());
}

#[test]
fn lifecycle_views_share_typed_state_and_reason() {
    use crate::common::{LifeReason, LifeState};
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    for (state, reason) in [
        (LifeState::Starting, LifeReason::Startup),
        (LifeState::Ready, LifeReason::Listening),
        (LifeState::Stopped, LifeReason::StartFailed),
        (LifeState::Stopped, LifeReason::CleanupComplete),
    ] {
        hub.set_lifecycle(state, reason);
        let current = hub.lifecycle_receiver().borrow().clone();
        assert_eq!(current.state, state.to_string());
        assert_eq!(current.reason, reason.to_string());
        let Event::RuntimeEvent(event) = events.try_recv().unwrap() else {
            panic!("missing event")
        };
        assert_eq!(
            event.message,
            format!("{}: {}", current.state, current.reason)
        );
    }
}
