// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! One-shot IPC status reads, registration state, resource display, and metadata redaction tests.

use super::*;

#[tokio::test]
async fn status_reads_a_real_local_snapshot_and_redacts_metadata() {
    use crate::telemetry::{DiscoveredInstance, TelemetryHub, TelemetryServer};
    use crate::transport::Stats;
    use tokio_util::sync::CancellationToken;

    let hub = TelemetryHub::for_current_process(
        InstanceRole::Portal,
        "secret@localhost:2000",
        Duration::from_secs(1),
    );
    let descriptor = hub.descriptor();
    let discovered = DiscoveredInstance {
        registry_name: descriptor.registry_name(),
        uid: descriptor.uid,
        pid: descriptor.pid,
        incarnation: descriptor.incarnation,
    };
    let server = TelemetryServer::bind(hub.clone()).unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.run(shutdown.clone()));
    hub.capture_and_publish(&Stats::default());
    let item = read_status(discovered).await.unwrap();
    assert_eq!(item.id, hub.descriptor().id);
    assert_eq!(item.endpoint, "<redacted>");
    assert_eq!(item.role, "PORTAL");
    shutdown.cancel();
    task.await.unwrap();
}

#[test]
fn status_uses_vertical_rows_and_preserves_unavailable_resources() {
    let item = StatusItem {
        role: "PORTAL",
        pid: 42,
        id: "instance".to_owned(),
        endpoint: "127.0.0.1:2000".to_owned(),
        snapshot: TelemetrySnapshot::default(),
    };
    let output = status_panel(&item);
    assert!(output.contains("PORTAL · PID 42"));
    assert!(output.contains("CPU  —"));
    assert!(output.contains("Memory  —"));
    assert!(!output.contains("Flows and carriers"));
}

#[test]
fn status_displays_registration_state_and_resource_samples() {
    let mut item = StatusItem {
        role: "EGRESS",
        pid: 42,
        id: "instance".to_owned(),
        endpoint: "127.0.0.1:2000".to_owned(),
        snapshot: TelemetrySnapshot {
            egress_online: Some(false),
            cpu_percent: Some(12.5),
            rss_bytes: Some(1536),
            open_fds: Some(7),
            ..TelemetrySnapshot::default()
        },
    };
    let offline = status_panel(&item);
    for expected in [
        "EGRESS · PID 42",
        "Egress  OFFLINE",
        "CPU  12.5%",
        "Memory  1.50 KiB",
        "FDs  7",
    ] {
        assert!(offline.contains(expected), "{offline}");
    }
    item.snapshot.egress_online = Some(true);
    assert!(status_panel(&item).contains("Egress  ONLINE"));
    item.snapshot.egress_online = None;
    assert!(!status_panel(&item).contains("Egress"));
}
