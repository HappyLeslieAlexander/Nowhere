// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Current state and bounded Flow/diagnostic publication.

use super::*;
use crate::protocol::Carrier;
use crate::telemetry::{InstanceRole, TELEMETRY_PROTOCOL, TrafficProtocol};

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
        telemetry_interval_ms: 1_000,
    }
}

fn start() -> AccessStart {
    AccessStart {
        protocol: TrafficProtocol::Tcp,
        target: "example.com:443".to_owned(),
        carrier: Carrier::TlsTcp,
    }
}

#[test]
fn descriptor_excludes_local_identity_and_configuration() {
    let value = serde_json::to_value(descriptor()).unwrap();
    assert_eq!(value["endpoint"], ":2000");
    for field in ["uid", "incarnation", "config_summary"] {
        assert!(value.get(field).is_none());
    }
}

#[test]
fn no_receivers_do_not_construct_flow_records_or_hold_the_hub() {
    let hub = TelemetryHub::new(descriptor());
    let _snapshot = hub.snapshot_receiver();
    let span = hub.start_access(|| panic!("no event receiver"));
    assert!(span.0.is_none());
    assert_eq!(Arc::strong_count(&hub), 1);
    span.finish(ResultCode::Success);
    let first = hub.event_receiver();
    let second = hub.event_receiver();
    assert_eq!(hub.events.receiver_count(), 2);
    drop(first);
    drop(second);
    drop(hub.start_access(|| panic!("receiver leaked")));
}

#[test]
fn every_completion_is_published_once_and_finishes_are_minimal() {
    let hub = TelemetryHub::new(descriptor());
    for result in [
        ResultCode::Success,
        ResultCode::ResourceLimit,
        ResultCode::InvalidRequest,
        ResultCode::Timeout,
        ResultCode::IdleTimeout,
        ResultCode::Cancelled,
        ResultCode::ConnectionRefused,
        ResultCode::Unknown,
    ] {
        let mut events = hub.event_receiver();
        let span = hub.start_access(start);
        let Event::AccessStart(start) = events.try_recv().unwrap() else {
            panic!("start")
        };
        let mut late = hub.event_receiver();
        span.finish(result);
        let Event::AccessFinish(finish) = events.try_recv().unwrap() else {
            panic!("finish")
        };
        assert_eq!(finish.id, start.id);
        assert_eq!(finish.result, result);
        assert_eq!(finish.sequence, start.sequence + 1);
        let fields = serde_json::to_value(&finish).unwrap();
        assert_eq!(fields.as_object().unwrap().len(), 4);
        assert_eq!(fields["result"], serde_json::to_value(result).unwrap());
        assert!(matches!(late.try_recv(), Ok(Event::AccessFinish(_))));
        assert!(events.try_recv().is_err());
        assert!(late.try_recv().is_err());
    }
}

#[tokio::test]
async fn aborted_flow_publishes_one_cancelled_finish() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    let owner = hub.clone();
    let task = tokio::spawn(async move {
        let span = owner.start_access(start);
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
        panic!("finish")
    };
    assert_eq!(finish.result, ResultCode::Cancelled);
    assert!(events.try_recv().is_err());
}

#[test]
fn snapshots_keep_counters_distinct_without_event_receivers() {
    let hub = TelemetryHub::new(descriptor());
    let stats = Stats::default();
    for (counter, value) in [
        (&stats.tcp_upload_bytes, 42),
        (&stats.tcp_download_bytes, 43),
        (&stats.udp_upload_bytes, 44),
        (&stats.udp_download_bytes, 45),
        (&stats.tls_upload_bytes, 46),
        (&stats.tls_download_bytes, 47),
        (&stats.quic_upload_bytes, 48),
        (&stats.quic_download_bytes, 49),
    ] {
        counter.store(value, Ordering::Relaxed);
    }
    stats.tls_carriers_active.store(2, Ordering::Relaxed);
    hub.capture_and_publish(&stats);
    let snapshot = hub.snapshots.borrow();
    assert_eq!(
        (snapshot.tcp_upload_bytes, snapshot.tcp_download_bytes),
        (42, 43)
    );
    assert_eq!(
        (snapshot.udp_upload_bytes, snapshot.udp_download_bytes),
        (44, 45)
    );
    assert_eq!(
        (snapshot.tls_upload_bytes, snapshot.tls_download_bytes),
        (46, 47)
    );
    assert_eq!(
        (snapshot.quic_upload_bytes, snapshot.quic_download_bytes),
        (48, 49)
    );
    assert_eq!(snapshot.tls_carriers_active, 2);
}

#[test]
fn lifecycle_and_online_state_are_only_published_in_snapshots() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    hub.set_lifecycle(LifeState::Ready, LifeReason::Listening);
    hub.set_egress_online(Some(true));
    let before = hub.snapshots.borrow().clone();
    hub.capture_and_publish(&Stats::default());
    let after = hub.snapshots.borrow().clone();
    assert_eq!(after.lifecycle, LifeState::Ready);
    assert_eq!(after.lifecycle_reason, LifeReason::Listening);
    assert_eq!(after.lifecycle_timestamp_ms, before.lifecycle_timestamp_ms);
    assert_eq!(after.egress_online, Some(true));
    assert!(after.sequence > before.sequence);
    assert!(events.try_recv().is_err());
}

#[test]
fn concurrent_sampling_and_state_updates_do_not_regress() {
    let hub = TelemetryHub::new(descriptor());
    let stats = Stats::default();
    let completed = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let (hub, stats, completed) = (&hub, &stats, &completed);
            scope.spawn(move || {
                for _ in 0..300 {
                    stats.tcp_upload_bytes.fetch_add(1, Ordering::Relaxed);
                    hub.capture_and_publish(stats);
                }
                completed.fetch_add(1, Ordering::Release);
            });
        }
        let (hub_ref, done) = (&hub, &completed);
        scope.spawn(move || {
            for index in 0..600 {
                hub_ref.set_egress_online(Some(index % 2 == 0));
            }
            hub_ref.set_lifecycle(LifeState::Ready, LifeReason::Listening);
            done.fetch_add(1, Ordering::Release);
        });
        let (mut sequence, mut bytes) = (0, 0);
        while completed.load(Ordering::Acquire) != 3 {
            let state = hub.snapshots.borrow().clone();
            assert!(state.sequence >= sequence);
            assert!(state.tcp_upload_bytes >= bytes);
            (sequence, bytes) = (state.sequence, state.tcp_upload_bytes);
            std::thread::yield_now();
        }
    });
    let state = hub.snapshots.borrow();
    assert_eq!(state.tcp_upload_bytes, 600);
    assert_eq!(state.egress_online, Some(false));
    assert_eq!(state.lifecycle, LifeState::Ready);
}

#[test]
fn concurrent_diagnostics_have_one_ordered_sequence() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let hub = &hub;
            scope.spawn(move || {
                for _ in 0..100 {
                    hub.emit_diagnostic(DiagnosticContext::SocksAccept, ResultCode::Unknown);
                }
            });
        }
    });
    for sequence in 1..=400 {
        let Event::Diagnostic(event) = events.try_recv().unwrap() else {
            panic!("event")
        };
        assert_eq!(event.sequence, sequence);
    }
    assert!(events.try_recv().is_err());
}
