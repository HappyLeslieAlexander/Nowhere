// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Passive streaming, bounded delivery and resource cleanup.
use super::super::{
    MAX_CLIENTS,
    frame::{FrameReader, TelemetryReader},
    registry::registry_path,
};
use super::*;
use crate::telemetry::{
    DiagnosticContext, InstanceDescriptor, InstanceRole, ResultCode, TelemetryClient,
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
    let descriptor =
        InstanceDescriptor::current(InstanceRole::Portal, ":2000", Duration::from_secs(1)).unwrap();
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
async fn initial_snapshot(reader: &mut TelemetryReader) {
    assert!(matches!(
        reader.next_message().await.unwrap(),
        ServerMessage::Snapshot(_)
    ));
}
async fn drain_until_closed(reader: &mut TelemetryReader) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while reader.next_message().await.is_ok() {}
    })
    .await
    .unwrap();
}
async fn wait_no_receivers(hub: &TelemetryHub) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while hub.events_receiver_count_for_test() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn all_clients_receive_the_same_events_without_sending_commands() {
    let (hub, discovered, shutdown, task) = start_service();
    let mut readers = Vec::new();
    for _ in 0..2 {
        let (hello, mut reader) = TelemetryClient::connect(&discovered)
            .await
            .unwrap()
            .into_parts();
        assert_eq!(hello.instance.id, hub.descriptor().id);
        initial_snapshot(&mut reader).await;
        readers.push(reader);
    }
    assert_eq!(hub.events_receiver_count_for_test(), 2);
    hub.emit_diagnostic(DiagnosticContext::SocksAdmission, ResultCode::ResourceLimit);
    for reader in &mut readers {
        next_kind(reader, "diagnostic").await;
    }
    readers.clear();
    wait_no_receivers(&hub).await;
    let (_, mut reader) = TelemetryClient::connect(&discovered)
        .await
        .unwrap()
        .into_parts();
    initial_snapshot(&mut reader).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(30), reader.next_message())
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
async fn any_input_disconnects_without_parsing_a_frame() {
    for extra in [
        vec![0],
        b"{\"type\":\"subscribe\"}".to_vec(),
        vec![0, 0, 0, 2, b'{', b'}'],
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
        initial_snapshot(&mut reader).await;
        writer.write_all(&extra).await.unwrap();
        drain_until_closed(&mut reader).await;
        wait_no_receivers(&hub).await;
        drop(hub.start_access(|| panic!("disconnected receiver leaked")));
        shutdown.cancel();
        task.await.unwrap();
    }
}
#[tokio::test]
async fn idle_eof_and_shutdown_release_collection() {
    let (hub, discovered, shutdown, task) = start_service();
    let (_, mut reader) = TelemetryClient::connect(&discovered)
        .await
        .unwrap()
        .into_parts();
    initial_snapshot(&mut reader).await;
    drop(reader);
    wait_no_receivers(&hub).await;
    drop(hub.start_access(|| panic!("EOF leaked receiver")));
    let (_, mut reader) = TelemetryClient::connect(&discovered)
        .await
        .unwrap()
        .into_parts();
    initial_snapshot(&mut reader).await;
    shutdown.cancel();
    task.await.unwrap();
    drain_until_closed(&mut reader).await;
    drop(hub.start_access(|| panic!("shutdown leaked receiver")));
}
#[tokio::test]
async fn lagging_receivers_report_gap_and_continue_in_sequence() {
    let (hub, discovered, shutdown, task) = start_service();
    let (_, mut reader) = TelemetryClient::connect(&discovered)
        .await
        .unwrap()
        .into_parts();
    initial_snapshot(&mut reader).await;

    for _ in 0..2048 {
        hub.emit_diagnostic(DiagnosticContext::SocksAccept, ResultCode::Unknown);
    }
    let ServerMessage::Gap { missed } = next_kind(&mut reader, "gap").await else {
        panic!("gap")
    };
    assert_eq!(missed, 1024);
    let ServerMessage::Diagnostic(event) = next_kind(&mut reader, "diagnostic").await else {
        panic!("diagnostic")
    };
    assert_eq!(event.sequence, 1025);
    shutdown.cancel();
    task.await.unwrap();
}
#[tokio::test]
async fn passive_idle_connections_survive_and_receive_state_updates() {
    let (hub, discovered, shutdown, task) = start_service();
    let (_, mut reader) = TelemetryClient::connect(&discovered)
        .await
        .unwrap()
        .into_parts();
    initial_snapshot(&mut reader).await;
    tokio::time::sleep(Duration::from_millis(5100)).await;
    hub.set_lifecycle(
        crate::common::LifeState::Ready,
        crate::common::LifeReason::Listening,
    );
    let ServerMessage::Snapshot(snapshot) = next_kind(&mut reader, "snapshot").await else {
        panic!("snapshot")
    };
    assert_eq!(snapshot.lifecycle, crate::common::LifeState::Ready);
    shutdown.cancel();
    task.await.unwrap();
}
#[tokio::test]
async fn connection_limit_does_not_spawn_extra_clients() {
    let descriptor =
        InstanceDescriptor::current(InstanceRole::Portal, "local", Duration::from_secs(1)).unwrap();
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
        InstanceDescriptor::current(InstanceRole::Portal, "local", Duration::from_secs(1)).unwrap();
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
async fn events_are_collected_before_the_initial_snapshot_is_read() {
    let (hub, _, shutdown, task) = start_service();
    let stream = local::connect(&local::endpoint(&hub.descriptor().id), std::process::id())
        .await
        .unwrap();
    let (reader, _writer) = tokio::io::split(stream);
    let mut reader = TelemetryReader {
        inner: FrameReader::new(reader),
    };
    assert!(matches!(
        reader.next_message().await.unwrap(),
        ServerMessage::Hello(_)
    ));
    assert_eq!(hub.events_receiver_count_for_test(), 1);
    let span = hub.start_access(|| crate::telemetry::AccessStart {
        protocol: crate::telemetry::TrafficProtocol::Tcp,
        target: "example.com:443".to_owned(),
        carrier: crate::protocol::Carrier::TlsTcp,
    });
    span.finish(ResultCode::Success);
    initial_snapshot(&mut reader).await;
    let ServerMessage::AccessStart(start) = reader.next_message().await.unwrap() else {
        panic!("start")
    };
    let ServerMessage::AccessFinish(finish) = reader.next_message().await.unwrap() else {
        panic!("finish")
    };
    assert_eq!(start.id, finish.id);
    assert_eq!(finish.result, ResultCode::Success);
    shutdown.cancel();
    task.await.unwrap();
}
