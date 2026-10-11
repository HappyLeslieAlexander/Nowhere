// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed subscriptions, bounded delivery, disconnects, and publication rollback.

use super::super::{MAX_CLIENTS, frame::TelemetryReader, registry::registry_path};
use super::*;
use crate::telemetry::{
    InstanceDescriptor, InstanceRole, Runtime, ServerMessage, Subscription, TelemetryClient,
    TelemetryHub,
};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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

fn start_service() -> (
    Arc<TelemetryHub>,
    DiscoveredInstance,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
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
    let task = tokio::spawn(server.run(shutdown.clone()));
    (hub, discovered, shutdown, task)
}

async fn initial_messages(reader: &mut TelemetryReader) {
    assert!(matches!(
        reader.next_message().await.unwrap(),
        ServerMessage::Snapshot(_)
    ));
    assert!(matches!(
        reader.next_message().await.unwrap(),
        ServerMessage::Lifecycle(_)
    ));
}

async fn drain_until_closed(reader: &mut TelemetryReader) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while reader.next_message().await.is_ok() {}
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multiple_clients_read_fixed_modes_and_reconnect_to_switch() {
    let (hub, discovered, shutdown, task) = start_service();
    let summary = TelemetryClient::connect(&discovered, Subscription::Summary)
        .await
        .unwrap();
    let detail = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut sr) = summary.into_parts();
    let (_, mut dr) = detail.into_parts();
    initial_messages(&mut sr).await;
    initial_messages(&mut dr).await;
    hub.emit_runtime(Runtime::SocksClientLimit, None, None);
    next_kind(&mut dr, "runtime_event").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sr.next_message())
            .await
            .is_err()
    );
    drop(sr);
    let detail = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut sr) = detail.into_parts();
    initial_messages(&mut sr).await;
    hub.emit_runtime(Runtime::SocksClientLimit, None, None);
    next_kind(&mut sr, "runtime_event").await;
    drop(sr);
    let summary = TelemetryClient::connect(&discovered, Subscription::Summary)
        .await
        .unwrap();
    let (_, mut sr) = summary.into_parts();
    initial_messages(&mut sr).await;
    hub.emit_runtime(Runtime::SocksClientLimit, None, None);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sr.next_message())
            .await
            .is_err()
    );
    shutdown.cancel();
    task.await.unwrap();
    assert!(!registry_path(&discovered.registry_name).exists());
    #[cfg(unix)]
    assert!(!std::path::Path::new(&local::endpoint(&hub.descriptor().id)).exists());
}

#[tokio::test]
async fn summary_clients_do_not_enable_access_collection() {
    let (hub, discovered, shutdown, task) = start_service();
    let client = TelemetryClient::connect(&discovered, Subscription::Summary)
        .await
        .unwrap();
    let (_, mut reader) = client.into_parts();
    initial_messages(&mut reader).await;
    let _span = hub.start_access(|| panic!("summary must not build access"));
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn additional_input_disconnects_without_waiting_for_a_whole_frame() {
    let payload = serde_json::to_vec(&ClientMessage::Subscribe {
        subscription: Subscription::Summary,
    })
    .unwrap();
    let mut repeated = (payload.len() as u32).to_be_bytes().to_vec();
    repeated.extend_from_slice(&payload);
    for extra in [vec![0], repeated] {
        let (hub, _, shutdown, task) = start_service();
        let stream = local::connect(&local::endpoint(&hub.descriptor().id), std::process::id())
            .await
            .unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = TelemetryReader {
            inner: FrameReader::new(reader),
        };
        next_kind(&mut reader, "hello").await;
        write_frame(
            &mut writer,
            &ClientMessage::Subscribe {
                subscription: Subscription::Detail,
            },
        )
        .await
        .unwrap();
        initial_messages(&mut reader).await;
        writer.write_all(&extra).await.unwrap();
        drain_until_closed(&mut reader).await;
        let _span = hub.start_access(|| panic!("disconnected detail receiver leaked"));
        shutdown.cancel();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn idle_detail_disconnect_releases_collection_and_shutdown_releases_clients() {
    let (hub, discovered, shutdown, task) = start_service();
    let client = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut reader) = client.into_parts();
    initial_messages(&mut reader).await;
    drop(reader);
    // The subscriber sends no further commands or receives any new publications.
    tokio::time::timeout(Duration::from_secs(2), async {
        while hub.events_receiver_count_for_test() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let _span = hub.start_access(|| panic!("EOF must release detail collection"));
    let client = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut reader) = client.into_parts();
    initial_messages(&mut reader).await;
    shutdown.cancel();
    task.await.unwrap();
    drain_until_closed(&mut reader).await;
    let _span = hub.start_access(|| panic!("shutdown must release detail collection"));
}

#[tokio::test]
async fn lagging_detail_receivers_report_gap_and_continue() {
    let (hub, discovered, shutdown, task) = start_service();
    let client = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut reader) = client.into_parts();
    initial_messages(&mut reader).await;
    // This current-thread runtime cannot drain the queue during synchronous publication.
    for _ in 0..2048 {
        hub.emit_runtime(Runtime::QuicConnected, None, None);
    }
    let ServerMessage::Gap { missed } = next_kind(&mut reader, "gap").await else {
        unreachable!()
    };
    assert_eq!(missed, 1024);
    let ServerMessage::RuntimeEvent(event) = next_kind(&mut reader, "runtime_event").await else {
        unreachable!()
    };
    assert_eq!(event.sequence, 1025);
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn invalid_initial_commands_close_without_enabling_detail() {
    for command in [
        serde_json::json!({"type":"subscribe", "data":{"subscription":"detail", "request_id":1}}),
        serde_json::json!({"type":"subscribe", "data":{"subscription":"raw"}}),
        serde_json::json!({"type":"execute", "data":{"command":"secret"}}),
    ] {
        let (hub, _, shutdown, task) = start_service();
        let stream = local::connect(&local::endpoint(&hub.descriptor().id), std::process::id())
            .await
            .unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = TelemetryReader {
            inner: FrameReader::new(reader),
        };
        next_kind(&mut reader, "hello").await;
        write_frame(&mut writer, &command).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), reader.next_message())
                .await
                .unwrap()
                .is_err(),
            "invalid commands must close without publishing data"
        );
        let _span = hub.start_access(|| panic!("invalid command must not enable detail"));
        shutdown.cancel();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn no_messages_before_subscription_and_missing_subscription_times_out() {
    let (hub, _, shutdown, task) = start_service();
    let stream = local::connect(&local::endpoint(&hub.descriptor().id), std::process::id())
        .await
        .unwrap();
    let (reader, _writer) = tokio::io::split(stream);
    let mut reader = TelemetryReader {
        inner: FrameReader::new(reader),
    };
    next_kind(&mut reader, "hello").await;
    hub.capture_and_publish(&crate::transport::Stats::default(), 10);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), reader.next_message())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(6), reader.next_message())
            .await
            .unwrap()
            .is_err()
    );
    let _span = hub.start_access(|| panic!("unsubscribed connection must not collect access"));
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

#[tokio::test]
async fn subscribed_connections_remain_live_past_the_initial_deadline() {
    let (hub, discovered, shutdown, task) = start_service();
    let mut readers = Vec::new();
    for mode in [Subscription::Summary, Subscription::Detail] {
        let client = TelemetryClient::connect(&discovered, mode).await.unwrap();
        let (_, mut reader) = client.into_parts();
        initial_messages(&mut reader).await;
        readers.push(reader);
    }
    tokio::time::sleep(Duration::from_millis(5_100)).await;
    hub.capture_and_publish(&crate::transport::Stats::default(), 17);
    for reader in &mut readers {
        let ServerMessage::Snapshot(snapshot) = next_kind(reader, "snapshot").await else {
            unreachable!()
        };
        assert_eq!(snapshot.ping_ms, Some(17));
    }
    shutdown.cancel();
    task.await.unwrap();
}
