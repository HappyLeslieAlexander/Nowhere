// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry wire schema and published examples tests.

use super::*;
use crate::telemetry::{AccessOutcome, AccessStart, Runtime, TelemetryHub, error_reason};
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

    let span = hub.start_access(|| AccessStart {
        protocol: TrafficProtocol::Tcp,
        client: Some("10.20.30.40:1234".to_owned()),
        peer: Some("secret.peer:2077".to_owned()),
        target: "secret.example:443".to_owned(),
        carrier: Carrier::TlsTcp,
    });
    span.finish(
        AccessOutcome::Error,
        Some(error_reason("connection refused: secret-key error\x1b[31m")),
    );
    hub.emit_runtime(
        Runtime::SocksHandshakeFailed,
        Some(error_reason("secret-key")),
        Some("10.20.30.40:1234"),
    );
    let mut previous = 0;
    while let Ok(message) = events.try_recv() {
        let message = ServerMessage::from(message);
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
            assert_eq!(value["data"]["peer"], "P001");
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
        ServerMessage::Snapshot(TelemetrySnapshot::default()),
        ServerMessage::Lifecycle(LifecycleSnapshot::default()),
        ServerMessage::Gap { missed: 2 },
    ] {
        assert_server_round_trip(&serde_json::to_value(message).unwrap());
    }
    let command = ClientMessage::Subscribe {
        subscription: Subscription::Detail,
    };
    let decoded: ClientMessage =
        serde_json::from_value(serde_json::to_value(&command).unwrap()).unwrap();
    assert_eq!(decoded, command);
}
#[test]
fn access_events_use_one_carrier_and_peer_with_the_published_shape() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/schema.json")).unwrap();
    for (carrier, name) in [(Carrier::TlsTcp, "tls"), (Carrier::Quic, "quic")] {
        for peer in [None, Some("127.0.0.1:2077".to_owned())] {
            let hub = TelemetryHub::new(
                InstanceDescriptor::current(InstanceRole::Vector, "", "", Duration::from_secs(1))
                    .unwrap(),
            );
            let mut events = hub.event_receiver();

            let span = hub.start_access(|| AccessStart {
                protocol: TrafficProtocol::Udp,
                client: None,
                peer: peer.clone(),
                target: "example.com:53".to_owned(),
                carrier,
            });
            span.add_upload(11);
            span.add_download(23);
            span.finish(AccessOutcome::Success, None);
            for kind in ["access_start", "access_finish"] {
                let value =
                    serde_json::to_value(ServerMessage::from(events.try_recv().unwrap())).unwrap();
                assert_eq!(value["type"], kind);
                let data = &value["data"];
                assert_eq!(data["carrier"], name);
                assert_eq!(
                    data["peer"],
                    if peer.is_some() {
                        serde_json::json!("P001")
                    } else {
                        serde_json::Value::Null
                    }
                );
                let actual: std::collections::BTreeSet<_> =
                    data.as_object().unwrap().keys().collect();
                let declared: std::collections::BTreeSet<_> = schema["$defs"][kind]["properties"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect();
                assert_eq!(actual, declared);
                let required: std::collections::BTreeSet<_> = schema["$defs"][kind]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|key| key.as_str().unwrap())
                    .collect();
                assert_eq!(
                    actual
                        .iter()
                        .map(|key| key.as_str())
                        .collect::<std::collections::BTreeSet<_>>(),
                    required
                );
                assert_server_round_trip(&value);
                if kind == "access_finish" {
                    assert_eq!(data["upload_bytes"], 11);
                    assert_eq!(data["download_bytes"], 23);
                }
            }
            assert!(events.try_recv().is_err());
        }
    }
}

#[test]
fn unknown_commands_and_fields_are_rejected() {
    for command in [
        r#"{"type":"execute","data":{"command":"ls"}}"#,
        r#"{"type":"subscribe","data":{"subscription":"raw"}}"#,
        r#"{"type":"subscribe","data":{"subscription":"detail","reveal":true}}"#,
    ] {
        assert!(serde_json::from_str::<ClientMessage>(command).is_err());
    }
}

#[test]
fn access_error_outcomes_use_the_same_classification_across_roles() {
    for (error, outcome) in [
        ("flow setup rejected: flow limit", AccessOutcome::Rejected),
        (
            "flow setup rejected: invalid request",
            AccessOutcome::Rejected,
        ),
        ("TCP half-close timeout", AccessOutcome::Timeout),
        ("connection timed out", AccessOutcome::Timeout),
        ("idle timeout", AccessOutcome::Timeout),
        ("service draining", AccessOutcome::Cancelled),
        ("operation cancelled", AccessOutcome::Cancelled),
        ("flow setup rejected: internal error", AccessOutcome::Error),
        ("connection refused", AccessOutcome::Error),
    ] {
        assert_eq!(
            AccessOutcome::from_reason(error_reason(error)),
            outcome,
            "{error}"
        );
    }
}

#[test]
fn unsupported_access_carriers_are_rejected() {
    let examples: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/examples.json")).unwrap();
    for example in examples["valid"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|value| {
            matches!(
                value["type"].as_str(),
                Some("access_start" | "access_finish")
            )
        })
    {
        for carrier in ["tcp", "udp", "mix", "unknown"] {
            let mut value = example.clone();
            value["data"]["carrier"] = serde_json::json!(carrier);
            assert!(serde_json::from_value::<ServerMessage>(value).is_err());
        }
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
fn nw3_roles_and_registration_state_match_the_published_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/schema.json")).unwrap();
    assert_eq!(schema["$id"], TELEMETRY_PROTOCOL);
    assert_eq!(
        schema["$defs"]["instance"]["properties"]["telemetry_protocol"]["const"],
        TELEMETRY_PROTOCOL
    );
    assert_eq!(
        schema["$defs"]["registry"]["properties"]["protocol"]["const"],
        TELEMETRY_PROTOCOL
    );
    for (role, name) in [
        (InstanceRole::Vector, "vector"),
        (InstanceRole::Portal, "portal"),
        (InstanceRole::Egress, "egress"),
    ] {
        assert_eq!(serde_json::to_value(role).unwrap(), name);
        assert!(
            schema["$defs"]["instance"]["properties"]["role"]["enum"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(name))
        );
    }
    for state in [None, Some(false), Some(true)] {
        let value = serde_json::to_value(TelemetrySnapshot {
            egress_online: state,
            ..TelemetrySnapshot::default()
        })
        .unwrap();
        assert_eq!(value["egress_online"], serde_json::to_value(state).unwrap());
        let actual: std::collections::BTreeSet<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let declared: std::collections::BTreeSet<_> = schema["$defs"]["snapshot"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let required: std::collections::BTreeSet<_> = schema["$defs"]["snapshot"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap())
            .collect();
        assert_eq!(actual, declared);
        assert_eq!(actual, required);
        assert_eq!(
            serde_json::from_value::<TelemetrySnapshot>(value)
                .unwrap()
                .egress_online,
            state
        );
    }
    assert!(
        schema["$defs"]["snapshot"]["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("egress_online"))
    );
}

#[test]
fn snapshot_round_trips_transport_counters() {
    let snapshot = TelemetrySnapshot {
        tls_carriers_active: 2,
        quic_carriers_active: 3,
        tcp_upload_bytes: 4,
        ..TelemetrySnapshot::default()
    };
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded: TelemetrySnapshot = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
}
