// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Minimal wire shapes and removed message rejection.

use super::*;

#[test]
fn snapshots_have_only_six_statistics() {
    let value = serde_json::to_value(TelemetrySnapshot::default()).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 6);
    for field in [
        "tcp_upload_bytes",
        "tcp_download_bytes",
        "udp_upload_bytes",
        "udp_download_bytes",
        "tcp_active",
        "udp_active",
    ] {
        assert_eq!(value[field], 0);
    }
    for kind in [
        "diagnostic",
        "access_start",
        "access_finish",
        "lifecycle",
        "gap",
        "subscribed",
    ] {
        assert!(
            serde_json::from_value::<ServerMessage>(serde_json::json!({"type":kind,"data":{}}))
                .is_err()
        );
    }
}

#[test]
fn published_examples_match_the_wire_contract() {
    let examples: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/examples.json")).unwrap();
    for value in examples["valid"].as_array().unwrap() {
        let message: ServerMessage = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(message).unwrap(), *value);
    }
    for value in examples["invalid"].as_array().unwrap() {
        assert!(serde_json::from_value::<ServerMessage>(value.clone()).is_err());
    }
}
