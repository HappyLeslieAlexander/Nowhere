// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry subscribers, client limits, command floods, and publication rollback tests.

use super::super::{MAX_CLIENTS, frame::TelemetryReader, registry::registry_path};
use super::*;
use crate::telemetry::{
    InstanceDescriptor, InstanceRole, RuntimeEvent, RuntimeKind, RuntimeLevel, ServerMessage,
    Subscription, TelemetryClient, TelemetryHub,
};
use std::time::Duration;

async fn next_kind(reader: &mut TelemetryReader, kind: &str) -> ServerMessage {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let message = reader.next_message().await.unwrap();
            if serde_json::to_value(&message).unwrap()["type"] == kind {
                return message;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn multiple_clients_can_read_and_change_subscriptions() {
    let descriptor = InstanceDescriptor::current(
        InstanceRole::Portal,
        ":2000",
        "secret",
        Duration::from_secs(1),
    )
    .unwrap();
    let discovered = DiscoveredInstance {
        registry_name: descriptor.registry_name(),
        uid: descriptor.uid,
        pid: descriptor.pid,
        incarnation: descriptor.incarnation,
    };
    let hub = TelemetryHub::new(descriptor);
    let shutdown = CancellationToken::new();
    let server = TelemetryServer::bind(hub.clone()).unwrap();
    let path = server.registry_path.clone();
    let _endpoint = server.endpoint.clone();
    let task = tokio::spawn(server.run(shutdown.clone()));
    let summary = TelemetryClient::connect(&discovered, Subscription::Summary)
        .await
        .unwrap();
    let detail = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut sr, mut sw) = summary.into_parts();
    let (_, mut dr, _) = detail.into_parts();
    next_kind(&mut sr, "subscribed").await;
    next_kind(&mut dr, "subscribed").await;
    next_kind(&mut sr, "snapshot").await;
    next_kind(&mut sr, "lifecycle").await;
    next_kind(&mut dr, "snapshot").await;
    next_kind(&mut dr, "lifecycle").await;
    hub.emit_runtime(RuntimeEvent::new(
        RuntimeLevel::Warn,
        RuntimeKind::Listener,
        "secret.example:443",
    ));
    let event = next_kind(&mut dr, "runtime_event").await;
    assert!(!serde_json::to_string(&event).unwrap().contains("secret"));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sr.next_message())
            .await
            .is_err()
    );
    sw.subscribe(Subscription::Detail).await.unwrap();
    next_kind(&mut sr, "subscribed").await;
    hub.emit_runtime(RuntimeEvent::new(
        RuntimeLevel::Warn,
        RuntimeKind::Listener,
        "private",
    ));
    next_kind(&mut sr, "runtime_event").await;
    sw.subscribe(Subscription::Summary).await.unwrap();
    next_kind(&mut sr, "subscribed").await;
    shutdown.cancel();
    task.await.unwrap();
    assert!(!path.exists());
    #[cfg(unix)]
    assert!(!std::path::Path::new(&_endpoint).exists());
}

#[tokio::test]
async fn summary_clients_do_not_enable_access_collection() {
    let descriptor = InstanceDescriptor::current(
        InstanceRole::Vector,
        "private",
        "secret",
        Duration::from_secs(1),
    )
    .unwrap();
    let discovered = DiscoveredInstance {
        registry_name: descriptor.registry_name(),
        uid: descriptor.uid,
        pid: descriptor.pid,
        incarnation: descriptor.incarnation,
    };
    let hub = TelemetryHub::new(descriptor);
    let shutdown = CancellationToken::new();
    let server = TelemetryServer::bind(hub.clone()).unwrap();
    let task = tokio::spawn(server.run(shutdown.clone()));
    let client = TelemetryClient::connect(&discovered, Subscription::Summary)
        .await
        .unwrap();
    let (_, mut reader, _) = client.into_parts();
    next_kind(&mut reader, "subscribed").await;
    let _span = hub.start_access(|| panic!("summary must not build access"));
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn connection_limit_does_not_spawn_extra_clients() {
    let descriptor =
        InstanceDescriptor::current(InstanceRole::Portal, "local", "", Duration::from_secs(1))
            .unwrap();
    let endpoint = local::endpoint(&descriptor.id);
    let server = TelemetryServer::bind(TelemetryHub::new(descriptor)).unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.run(shutdown.clone()));
    let mut clients = Vec::new();
    for _ in 0..MAX_CLIENTS {
        let stream = local::connect(&endpoint, std::process::id()).await.unwrap();
        let (reader, writer) = tokio::io::split(stream);
        let mut reader = FrameReader::new(reader);
        assert!(matches!(
            reader.next::<ServerMessage>().await.unwrap(),
            ServerMessage::Hello(_)
        ));
        clients.push((reader, writer));
    }
    let stream = local::connect(&endpoint, std::process::id()).await.unwrap();
    let (reader, _) = tokio::io::split(stream);
    let mut reader = FrameReader::new(reader);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), reader.next::<ServerMessage>())
            .await
            .unwrap()
            .is_err()
    );
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn command_flood_is_disconnected_and_shutdown_reclaims_detail() {
    let descriptor =
        InstanceDescriptor::current(InstanceRole::Portal, "local", "", Duration::from_secs(1))
            .unwrap();
    let discovered = DiscoveredInstance {
        registry_name: descriptor.registry_name(),
        uid: descriptor.uid,
        pid: descriptor.pid,
        incarnation: descriptor.incarnation,
    };
    let hub = TelemetryHub::new(descriptor);
    let server = TelemetryServer::bind(hub.clone()).unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.run(shutdown.clone()));
    let client = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut reader, mut writer) = client.into_parts();
    next_kind(&mut reader, "subscribed").await;
    for _ in 0..20 {
        if writer.subscribe(Subscription::Detail).await.is_err() {
            break;
        }
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while reader.next_message().await.is_ok() {}
    })
    .await
    .unwrap();
    shutdown.cancel();
    task.await.unwrap();
    let _span = hub.start_access(|| panic!("disconnected detail guard leaked"));
}

#[tokio::test]
async fn failed_publication_rolls_back_only_owned_resources() {
    let descriptor =
        InstanceDescriptor::current(InstanceRole::Portal, "local", "", Duration::from_secs(1))
            .unwrap();
    local::prepare_directory().unwrap();
    let path = registry_path(&descriptor.registry_name());
    #[cfg(unix)]
    let endpoint = local::endpoint(&descriptor.id);
    local::publish(&path, b"{}").unwrap();
    assert!(TelemetryServer::bind(TelemetryHub::new(descriptor)).is_err());
    assert_eq!(local::read_registry(&path).unwrap(), b"{}");
    assert!(!path.with_extension("pending").exists());
    #[cfg(unix)]
    assert!(!std::path::Path::new(&endpoint).exists());
    let pending = path.with_extension("pending");
    let seed = path.with_extension("seed");
    local::publish(&seed, b"{}").unwrap();
    std::fs::rename(seed, &pending).unwrap();
    assert!(local::publish(&path, b"new").is_err());
    assert!(pending.exists());
    std::fs::remove_file(pending).unwrap();
    std::fs::remove_file(path).unwrap();
}
