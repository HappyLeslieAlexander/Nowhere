// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry wire schema and published examples tests.

use super::*;
use crate::telemetry::{AccessOutcome, AccessStart, TelemetryHub};
use std::time::Duration;

fn assert_server_round_trip(value: &serde_json::Value) {
    let decoded: ServerMessage = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(&serde_json::to_value(decoded).unwrap(), value);
}
#[test]
fn public_messages_keep_targets_without_leaking_credentials_or_client_addresses() {
    let descriptor = InstanceDescriptor::current(
        InstanceRole::Portal,
        "secret.listen:2077",
        "secret-key",
        Duration::from_secs(1),
    )
    .unwrap();
    let hub = TelemetryHub::new(descriptor);
    let mut events = hub.event_receiver();
    let _detail = hub.detail_guard();
    let span = hub.start_access(|| AccessStart {
        id: 0,
        timestamp_ms: 0,
        protocol: TrafficProtocol::Tcp,
        flow_id: Some(777),
        session_tag: Some("secret-session".to_owned()),
        client: Some("10.20.30.40:1234".to_owned()),
        path_peers: vec!["secret.peer:2077".to_owned(); 20],
        target: "secret.example:443".to_owned(),
        initial_uplink: Some(Carrier::TlsTcp),
        initial_downlink: Some(Carrier::Quic),
        path: Some("secret-route".to_owned()),
    });
    span.finish(
        AccessOutcome::Error,
        Some("connection refused: secret-key error\x1b[31m".to_owned()),
    );
    hub.emit_runtime(
        RuntimeEvent::new(
            RuntimeLevel::Error,
            RuntimeKind::Authentication,
            "secret-key",
        )
        .with_client("10.20.30.40:1234"),
    );
    let mut previous = 0;
    while let Ok(message) = events.try_recv() {
        let value = serde_json::to_value(&message).unwrap();
        assert_server_round_trip(&value);
        let encoded = value.to_string();
        assert!(encoded.len() < 8192);
        for secret in [
            "secret-key",
            "secret.peer",
            "secret-route",
            "secret-session",
            "10.20",
            ":1234",
            "flow_id",
            "session_tag",
            "\u{1b}",
        ] {
            assert!(!encoded.contains(secret), "leaked {secret}: {encoded}");
        }
        if matches!(
            message,
            ServerMessage::AccessStart(_) | ServerMessage::AccessFinish(_)
        ) {
            assert_eq!(value["data"]["client"], "C001");
            assert_eq!(value["data"]["target"], "secret.example:443");
            assert_eq!(value["data"]["path_peers"][0], "P001");
        }
        if matches!(message, ServerMessage::AccessFinish(_)) {
            assert_eq!(value["data"]["error"], "connection refused");
        }
        let sequence = value["data"]["sequence"].as_u64().unwrap();
        assert!(sequence > previous);
        previous = sequence;
    }
    for message in [
        ServerMessage::Hello(Hello {
            instance: hub.descriptor().clone(),
            lifecycle: "STARTING".into(),
            lifecycle_reason: "STARTUP".into(),
        }),
        ServerMessage::Subscribed {
            request_id: 1,
            subscription: Subscription::Summary,
        },
        ServerMessage::Snapshot(TelemetrySnapshot::default()),
        ServerMessage::Lifecycle(LifecycleSnapshot::default()),
        ServerMessage::Gap { missed: 2 },
        ServerMessage::Error {
            message: "INVALID_COMMAND".into(),
        },
    ] {
        assert_server_round_trip(&serde_json::to_value(message).unwrap());
    }
    let command = ClientMessage::Subscribe {
        request_id: u64::MAX,
        subscription: Subscription::Detail,
    };
    let decoded: ClientMessage =
        serde_json::from_value(serde_json::to_value(&command).unwrap()).unwrap();
    assert_eq!(decoded, command);
}
#[test]
fn unknown_commands_and_fields_are_rejected() {
    for command in [
        r#"{"type":"execute","data":{"command":"ls"}}"#,
        r#"{"type":"subscribe","data":{"request_id":1,"subscription":"raw"}}"#,
        r#"{"type":"subscribe","data":{"request_id":1,"subscription":"detail","reveal":true}}"#,
    ] {
        assert!(serde_json::from_str::<ClientMessage>(command).is_err());
    }
}

#[test]
fn published_examples_are_valid_and_invalid_as_documented() {
    let examples: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/examples.json")).unwrap();
    for value in examples["valid"].as_array().unwrap() {
        if value["type"] == "subscribe" {
            let decoded: ClientMessage = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), *value);
        } else {
            assert_server_round_trip(value);
        }
    }
    for value in examples["invalid"].as_array().unwrap() {
        assert!(serde_json::from_value::<ClientMessage>(value.clone()).is_err());
    }
}

#[test]
fn snapshot_round_trips_transport_counters() {
    let snapshot = TelemetrySnapshot {
        tls_carriers_active: 2,
        quic_carriers_active: 3,
        tcp_logical_up: 4,
        ..TelemetrySnapshot::default()
    };
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded: TelemetrySnapshot = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
}
