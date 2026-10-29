// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector client fixtures, setup cancellation, and shutdown deadline tests.

mod deadlines;
mod quic;
mod reconnect;

use std::sync::atomic::Ordering;

use tokio::time::timeout;

use crate::common::Logger;
use crate::protocol::{
    ConnectionRole, FlowResult, read_auth_frame, read_request, write_flow_result,
};
use crate::vector::tls::EXPORTER_LABEL;

use super::*;

fn quic_fixture() -> (quinn::Endpoint, Arc<PortalClient>) {
    quic_fixture_with_transport(|_| {})
}

fn quic_fixture_with_transport(
    configure: impl FnOnce(&mut quinn::TransportConfig),
) -> (quinn::Endpoint, Arc<PortalClient>) {
    let url = url::Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000").unwrap();
    let (_, tls, mut server) = crate::common::new_server_configs_with_reload_interval(
        &url,
        std::time::Duration::from_secs(3600),
        Logger,
    )
    .unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    Arc::get_mut(&mut server.transport)
        .unwrap()
        .datagram_receive_buffer_size(Some(65536))
        .max_concurrent_bidi_streams(1024u32.into());
    configure(Arc::get_mut(&mut server.transport).unwrap());
    let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (config, credentials) = PortalClientConfig::from_probe_url(
        &url::Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@127.0.0.1/udp:{}?morph=0&pin={pin}",
            endpoint.local_addr().unwrap().port(),
        ))
        .unwrap(),
    )
    .unwrap();
    let client = PortalClient::new(
        config,
        &credentials,
        4 * 1024 * 1024,
        Arc::new(Stats::default()),
        true,
        CancellationToken::new(),
    )
    .unwrap();
    (endpoint, client)
}

async fn read_first_request(
    connection: &quinn::Connection,
    credentials: &Credentials,
) -> (quinn::SendStream, quinn::RecvStream, FlowKind) {
    let (send, mut recv) = connection.accept_bi().await.unwrap();
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .unwrap();
    assert_eq!(
        read_auth_frame(&mut recv, credentials, AuthTransport::Quic, &exporter)
            .await
            .unwrap(),
        ConnectionRole::Vector
    );
    let kind = crate::protocol::read_flow_start(&mut recv)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read_request(&mut recv).await.unwrap(),
        Target::domain("example.com", 53).unwrap()
    );
    (send, recv, kind)
}

#[tokio::test]
async fn close_deadline_bounds_a_suspended_first_flow() {
    let (endpoint, client) = quic_fixture();
    let target = Target::domain("example.com", 53).unwrap();
    let pending = client.open_quic_flow(FlowKind::Udp, &target);
    tokio::pin!(pending);
    let connection = timeout(std::time::Duration::from_secs(2), async {
        tokio::select! {
            _ = &mut pending => panic!("setup completed without READY"),
            connection = async {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let streams = read_first_request(&connection, &client.credentials).await;
                (connection, streams)
            } => connection,
        }
    })
    .await
    .unwrap();
    assert!(client.quic.try_lock().is_err());
    timeout(
        std::time::Duration::from_secs(1),
        client.close(Instant::now() + std::time::Duration::from_millis(20)),
    )
    .await
    .expect("close ignored its deadline while setup was suspended");
    assert!(client.shutdown.is_cancelled());
    assert!(matches!(pending.await, Err(OpenFlowError::Cancelled)));
    assert!(client.quic.lock().await.is_none());
    timeout(std::time::Duration::from_secs(1), connection.0.closed())
        .await
        .unwrap();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn cancelling_the_first_udp_setup_closes_the_temporary_connection() {
    let (endpoint, client) = quic_fixture();
    let opening = client.clone();
    let task = tokio::spawn(async move {
        opening
            .open_quic_flow(FlowKind::Udp, &Target::domain("example.com", 53).unwrap())
            .await
    });
    let connection = timeout(std::time::Duration::from_secs(2), async {
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    let (_send, _recv, kind) = timeout(
        std::time::Duration::from_secs(2),
        read_first_request(&connection, &client.credentials),
    )
    .await
    .unwrap();
    assert_eq!(kind, FlowKind::Udp);
    timeout(
        std::time::Duration::from_secs(1),
        client.close(Instant::now()),
    )
    .await
    .unwrap();
    assert!(matches!(task.await.unwrap(), Err(OpenFlowError::Cancelled)));
    timeout(std::time::Duration::from_secs(1), connection.closed())
        .await
        .unwrap();
    assert!(client.quic.lock().await.is_none());
    assert_eq!(client.stats.udp_active.load(Ordering::Relaxed), 0);
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn cancelling_a_reused_udp_setup_releases_its_route_and_preserves_the_connection() {
    timeout(std::time::Duration::from_secs(3), async {
        let (endpoint, client) = quic_fixture();
        let peer_endpoint = endpoint.clone();
        let credentials = client.credentials.clone();
        let (seen, mut request_seen) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, _recv, _) = read_first_request(&connection, &credentials).await;
            write_flow_result(&mut send, FlowResult::Ready)
                .await
                .unwrap();
            send.finish().unwrap();
            let (send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(
                crate::protocol::read_flow_start(&mut recv).await.unwrap(),
                Some(FlowKind::Udp)
            );
            read_request(&mut recv).await.unwrap();
            seen.send(()).unwrap();
            let _ = recv.read_to_end(0).await;
            drop((send, recv));
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(
                crate::protocol::read_flow_start(&mut recv).await.unwrap(),
                Some(FlowKind::Udp)
            );
            read_request(&mut recv).await.unwrap();
            write_flow_result(&mut send, FlowResult::Ready)
                .await
                .unwrap();
            send.finish().unwrap();
            connection.closed().await;
        });
        let target = Target::domain("example.com", 53).unwrap();
        drop(client.open_quic_flow(FlowKind::Tcp, &target).await.unwrap());
        let cached = client.quic.lock().await.as_ref().unwrap().1.clone();
        {
            let pending = client.open_quic_flow(FlowKind::Udp, &target);
            tokio::pin!(pending);
            tokio::select! {
                _ = &mut pending => panic!("setup completed without READY"),
                result = &mut request_seen => result.unwrap(),
            }
        }
        drop(
            cached
                .register(2)
                .expect("cancelled setup retained its UDP route"),
        );
        drop(client.open_quic_flow(FlowKind::Udp, &target).await.unwrap());
        assert!(Arc::ptr_eq(
            &client.quic.lock().await.as_ref().unwrap().1,
            &cached
        ));
        assert!(!cached.cancel.is_cancelled());
        client.close(Instant::now()).await;
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shutdown_cancels_an_in_progress_quic_handshake_and_releases_the_cache_lock() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (config, credentials) = PortalClientConfig::from_probe_url(
        &url::Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@127.0.0.1/udp:{}?morph=0&pin={}",
            silent.local_addr().unwrap().port(),
            "00".repeat(32),
        ))
        .unwrap(),
    )
    .unwrap();
    let client = PortalClient::new(
        config,
        &credentials,
        4 * 1024 * 1024,
        Arc::new(Stats::default()),
        true,
        CancellationToken::new(),
    )
    .unwrap();
    let opening = client.clone();
    let task = tokio::spawn(async move {
        opening
            .open_quic_flow(FlowKind::Udp, &Target::domain("example.com", 53).unwrap())
            .await
    });
    let mut packet = [0; 2048];
    timeout(std::time::Duration::from_secs(2), silent.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    timeout(
        std::time::Duration::from_secs(1),
        client.close(Instant::now() + std::time::Duration::from_millis(500)),
    )
    .await
    .expect("client close remained blocked by the QUIC handshake");
    let result = timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(OpenFlowError::Cancelled)));
    assert!(client.quic.lock().await.is_none());
}
