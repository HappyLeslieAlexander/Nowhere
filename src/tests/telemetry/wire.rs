// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only
//! Published wire shapes and privacy boundaries.
use super::*;
use crate::telemetry::{AccessStart, ResultCode, TelemetryHub, error_reason};
fn round_trip(value: &serde_json::Value) {
    let decoded: ServerMessage = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), *value);
}
#[test]
fn published_examples_round_trip_and_removed_messages_are_rejected() {
    let examples: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/examples.json")).unwrap();
    for value in examples["valid"].as_array().unwrap() {
        round_trip(value);
    }
    for value in examples["invalid"].as_array().unwrap() {
        assert!(serde_json::from_value::<ServerMessage>(value.clone()).is_err());
    }
}
#[test]
fn flow_and_diagnostic_fields_match_schema_without_raw_errors_or_identity() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/schema.json")).unwrap();
    let hub = TelemetryHub::new(
        InstanceDescriptor::current(InstanceRole::Vector, "", Duration::from_secs(1)).unwrap(),
    );
    let mut events = hub.event_receiver();
    for carrier in [Carrier::TlsTcp, Carrier::Quic] {
        let span = hub.start_access(|| AccessStart {
            protocol: TrafficProtocol::Udp,
            target: "example.com:53".to_owned(),
            carrier,
        });
        span.finish(error_reason(&anyhow::anyhow!(
            "secret credential 203.0.113.5:4321"
        )));
    }
    hub.emit_diagnostic(DiagnosticContext::SocksHandshake, ResultCode::Timeout);
    let mut previous = 0;
    while let Ok(event) = events.try_recv() {
        let value = serde_json::to_value(ServerMessage::from(event)).unwrap();
        round_trip(&value);
        let data = value["data"].as_object().unwrap();
        let definition = &schema["$defs"][value["type"].as_str().unwrap()];
        let actual: std::collections::BTreeSet<_> = data.keys().map(String::as_str).collect();
        let required: std::collections::BTreeSet<_> = definition["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(actual, required);
        assert!(data["sequence"].as_u64().unwrap() > previous);
        previous = data["sequence"].as_u64().unwrap();
        for forbidden in [
            "client",
            "peer",
            "upload_bytes",
            "download_bytes",
            "duration_ms",
            "message",
            "error",
            "outcome",
        ] {
            assert!(!data.contains_key(forbidden));
        }
        let encoded = value.to_string();
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("203.0.113"));
    }
}
#[test]
fn unsupported_carriers_and_result_codes_are_rejected() {
    for result in ["error", "rejected", "operation failed", "credential"] {
        let value = serde_json::json!({"type":"access_finish","data":{"sequence":1,"id":1,"timestamp_ms":0,"result":result}});
        assert!(serde_json::from_value::<ServerMessage>(value).is_err());
    }
    for carrier in ["tcp", "udp", "mix", "unknown"] {
        let value = serde_json::json!({"type":"access_start","data":{"sequence":1,"id":1,"timestamp_ms":0,"protocol":"tcp","target":"example:443","carrier":carrier}});
        assert!(serde_json::from_value::<ServerMessage>(value).is_err());
    }
}
