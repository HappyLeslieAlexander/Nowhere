// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Cached-connection death retry and reconnect cooldown tests.

use super::*;

#[tokio::test]
async fn a_dead_cached_connection_is_replaced_by_a_fresh_flow() {
    let (endpoint, client) = quic_fixture();
    let peer_endpoint = endpoint.clone();
    let credentials = client.credentials.clone();
    let target = Target::domain("example.com", 53).unwrap();
    let (flow_seen, flow_seen_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv, _) = read_first_request(&connection, &credentials).await;
        write_flow_result(&mut send, FlowResult::Ready)
            .await
            .unwrap();
        send.finish().unwrap();
        // Wait until the client has received the result and cached the
        // connection, then kill it; the client must rebuild transparently
        // whether or not the next health check noticed.
        flow_seen_rx.await.unwrap();
        connection.close(1u32.into(), b"gone");
        let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv, _) = read_first_request(&connection, &credentials).await;
        write_flow_result(&mut send, FlowResult::Ready)
            .await
            .unwrap();
        send.finish().unwrap();
        connection.closed().await;
    });
    drop(client.open_quic_flow(FlowKind::Tcp, &target).await.unwrap());
    assert!(client.quic.lock().await.is_some());
    flow_seen.send(()).unwrap();
    let flow = timeout(
        std::time::Duration::from_secs(3),
        client.open_quic_flow(FlowKind::Tcp, &target),
    )
    .await
    .unwrap()
    .unwrap();
    drop(flow);
    client
        .close(Instant::now() + std::time::Duration::from_secs(1))
        .await;
    timeout(std::time::Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn a_failed_quic_establishment_arms_a_reconnect_cooldown() {
    let (endpoint, client) = quic_fixture();
    let peer_endpoint = endpoint.clone();
    let credentials = client.credentials.clone();
    let peer = tokio::spawn(async move {
        let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = connection.accept_bi().await.unwrap();
        let mut exporter = [0; 32];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
            .unwrap();
        assert_eq!(
            read_auth_frame(&mut recv, &credentials, AuthTransport::Quic, &exporter)
                .await
                .unwrap(),
            ConnectionRole::Vector
        );
        connection.close(1u32.into(), b"rejected");
        connection.closed().await;
    });
    let target = Target::domain("example.com", 53).unwrap();
    let error = match timeout(
        std::time::Duration::from_secs(3),
        client.open_quic_flow(FlowKind::Udp, &target),
    )
    .await
    .unwrap()
    {
        Ok(_) => panic!("expected the flow setup to fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        OpenFlowError::Transport(_) | OpenFlowError::Protocol(_)
    ));
    assert!(client.quic_cooldown_active());
    assert!(client.quic.lock().await.is_none());
    // While cooling down, attempts fail fast without touching the endpoint.
    let started = Instant::now();
    let error = match timeout(
        std::time::Duration::from_millis(200),
        client.open_quic_flow(FlowKind::Udp, &target),
    )
    .await
    .unwrap()
    {
        Ok(_) => panic!("expected the cooldown to reject the flow"),
        Err(error) => error,
    };
    let OpenFlowError::Transport(inner) = error else {
        panic!("expected a transport error, got {error}");
    };
    assert!(format!("{inner:#}").contains("cooling down"));
    assert!(started.elapsed() < std::time::Duration::from_millis(200));
    peer.await.unwrap();
    endpoint.close(0u32.into(), b"done");
}
