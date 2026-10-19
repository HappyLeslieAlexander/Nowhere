// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal auth connection regression tests.

use super::*;

#[tokio::test]
async fn shutdown_cancels_incomplete_tcp_handshakes() {
    for morph in [false, true] {
        let h = Harness::new("direct", morph).await;
        let inner = h.inner.clone();
        let permits = inner.connection_admission.available_permits();
        let _stream = tokio::net::TcpStream::connect(h.tcp).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while inner.connection_admission.available_permits() == permits {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        h.close().await;
        assert_eq!(inner.connection_admission.available_permits(), permits);
    }
}

#[tokio::test]
async fn shutdown_cancels_incomplete_quic_authentication_and_registration() {
    for prefix in [0, 1, 16] {
        let h = Harness::new("egress", false).await;
        let inner = h.inner.clone();
        let permits = inner.connection_admission.available_permits();
        let (endpoint, q) = connect(&h).await;
        let (mut send, _recv) = q.open_bi().await.unwrap();
        send.write_all(&tag(&q, true)[..prefix]).await.unwrap();
        if prefix == 16 {
            tokio::time::timeout(Duration::from_secs(2), async {
                while inner.unauthenticated_admission.active() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        h.close().await;
        tokio::time::timeout(Duration::from_secs(2), q.closed())
            .await
            .unwrap();
        assert_eq!(inner.connection_admission.available_permits(), permits);
        assert!(!inner.egress_slot.as_ref().unwrap().online());
        endpoint.wait_idle().await;
    }
}

#[tokio::test]
async fn connection_replay_authentication_failure_never_dials_or_claims_a_slot() {
    let h = Harness::new("egress", false).await;
    let (e1, q1) = connect(&h).await;
    let replay = tag(&q1, true);
    q1.close(0u32.into(), b"test");
    e1.wait_idle().await;
    let (e2, q2) = connect(&h).await;
    let (mut send, _recv) = q2.open_bi().await.unwrap();
    send.write_all(&replay).await.unwrap();
    send.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(2), q2.closed())
        .await
        .unwrap();
    assert!(!h.inner.egress_slot.as_ref().unwrap().online());
    e2.wait_idle().await;
    h.close().await;
}

#[tokio::test]
async fn tls_replay_fails_on_fresh_and_resumed_connections() {
    let h = Harness::new("direct", false).await;
    let url = h.url("vector", "tcp", false);
    let (config, credentials) = PortalClientConfig::from_probe_url(&url).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    let (mut first, exporter) = tls
        .connect_tcp(
            &h.tcp.to_string(),
            &config.dial_policy,
            crate::common::AddressFamily::Any,
        )
        .await
        .unwrap();
    let frame = encode_auth_frame(credentials.vector_key, AuthTransport::TlsTcp, &exporter);
    let (target, echo) = tcp_echo().await;
    let mut request = frame.to_vec();
    request.push(0);
    request.extend(crate::protocol::encode_target(&target).unwrap());
    first.write_all(&request).await.unwrap();
    assert_eq!(
        SetupResult::from(crate::protocol::read_flow_result(&mut first).await.unwrap()),
        SetupResult::Ready
    );
    first.shutdown().await.unwrap();
    let mut buf = Vec::new();
    first.read_to_end(&mut buf).await.unwrap();
    drop(first);
    let (mut resumed, second_exporter) = tls
        .connect_tcp(
            &h.tcp.to_string(),
            &config.dial_policy,
            crate::common::AddressFamily::Any,
        )
        .await
        .unwrap();
    assert_eq!(
        resumed.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    assert_ne!(exporter, second_exporter);
    resumed.write_all(&request).await.unwrap();
    let mut byte = [0];
    let ended = tokio::time::timeout(Duration::from_secs(2), resumed.read(&mut byte))
        .await
        .unwrap();
    assert!(ended.is_err() || ended.unwrap() == 0);
    drop(resumed);
    let fresh_tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    let (mut fresh, _) = fresh_tls
        .connect_tcp(
            &h.tcp.to_string(),
            &config.dial_policy,
            crate::common::AddressFamily::Any,
        )
        .await
        .unwrap();
    assert_eq!(
        fresh.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    fresh.write_all(&request).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(2), fresh.read(&mut byte))
        .await
        .unwrap();
    assert!(ended.is_err() || ended.unwrap() == 0);
    drop(fresh);
    h.close().await;
    echo.abort();
}
