// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal egress connection regression tests.

use super::*;

#[tokio::test]
async fn multiple_quic_registrations_and_role_direction_cleanup() {
    let h = Harness::new("egress", false).await;
    let (e1, q1) = connect(&h).await;
    let (e2, q2) = connect(&h).await;
    for q in [&q1, &q2] {
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        send.write_all(&tag(q, true)).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
    }
    let (mut send, _recv) = q1.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), q1.closed())
        .await
        .unwrap();
    assert!(h.inner.egress_registry.as_ref().unwrap().online());
    q2.close(0u32.into(), b"test");
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.inner.egress_registry.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    e2.wait_idle().await;
    e1.wait_idle().await;
    h.close().await;
}

#[tokio::test]
async fn egress_source_binding_applies_only_to_targets_and_does_not_fallback() {
    let h = Harness::new("egress", false).await;
    let mut url = h.url("egress", "udp", false);
    url.query_pairs_mut().append_pair("dial4", "192.0.2.254");
    let egress = crate::Egress::new(url, Logger).unwrap();
    let task = tokio::spawn(egress.run());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !h.inner.egress_registry.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    for net in ["tcp", "udp"] {
        let client = h.client(net, false);
        assert_eq!(
            client.open_tcp(&tcp).await.err().unwrap().setup_result(),
            Some(SetupResult::DialFailed)
        );
        assert_eq!(
            crate::vector::udp_flow::open_udp(client.clone(), &udp)
                .await
                .err()
                .unwrap()
                .setup_result(),
            Some(SetupResult::DialFailed)
        );
        client
            .close(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert!(h.inner.egress_registry.as_ref().unwrap().online());
    }
    task.abort();
    let _ = task.await;
    h.close().await;
    tcp_task.abort();
    udp_task.abort();
}

async fn tls_register(
    h: &Harness,
) -> tokio_rustls::client::TlsStream<crate::transport::MorphTcpStream<tokio::net::TcpStream>> {
    let (config, credentials) =
        PortalClientConfig::from_probe_url(&h.url("vector", "tcp", false)).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    let (mut stream, exporter) = tls
        .connect_tcp(
            &h.tcp.to_string(),
            &config.dial_policy,
            crate::common::AddressFamily::Any,
        )
        .await
        .unwrap();
    stream
        .write_all(&encode_auth_frame(
            credentials.egress_key,
            AuthTransport::TlsTcp,
            &exporter,
        ))
        .await
        .unwrap();
    stream.flush().await.unwrap();
    stream
}

#[tokio::test]
async fn tls_capacity_busy_and_registration_permits_are_released() {
    let h = Harness::new("egress", false).await;
    let registry = h.inner.egress_registry.as_ref().unwrap();
    let capacity: Vec<_> = (0..128).map(|_| registry.reserve_tls().unwrap()).collect();
    let mut busy = tls_register(&h).await;
    assert_eq!(busy.read_u8().await.unwrap(), 1);
    drop(capacity);
    let mut accepted = tls_register(&h).await;
    assert_eq!(accepted.read_u8().await.unwrap(), 0);
    assert!(h.inner.connection_admission.available_permits() < 1024);
    drop(accepted);
    tokio::time::timeout(Duration::from_secs(2), async {
        while registry.online() || h.inner.connection_admission.available_permits() != 1024 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(registry.reserve_tls().unwrap().num_permits(), 1);
    h.close().await;
}

#[tokio::test]
async fn portal_expires_idle_tls_registration() {
    let ttl = Duration::from_millis(200);
    let h = Harness::with_egress_ttl(ttl).await;
    let started = tokio::time::Instant::now();
    let mut stream = tls_register(&h).await;
    assert_eq!(stream.read_u8().await.unwrap(), 0);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !h.inner.egress_registry.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.inner.egress_registry.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(started.elapsed() >= ttl);
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    drop(stream);
    h.close().await;
}

#[tokio::test]
async fn claimed_tls_flow_keeps_connection_permit_and_outlives_standby_ttl() {
    let ttl = Duration::from_millis(200);
    let h = Harness::with_egress_ttl(ttl).await;
    let mut stream = tls_register(&h).await;
    assert_eq!(stream.read_u8().await.unwrap(), 0);
    let peer = tokio::spawn(async move {
        assert_eq!(
            crate::protocol::read_flow_start(&mut stream).await.unwrap(),
            Some(crate::protocol::FlowKind::Tcp)
        );
        crate::protocol::read_request(&mut stream).await.unwrap();
        crate::protocol::write_flow_result(
            &mut stream,
            crate::protocol::FlowResult::from(SetupResult::Ready),
        )
        .await
        .unwrap();
        stream.flush().await.unwrap();
        let mut byte = [0];
        while stream.read_exact(&mut byte).await.is_ok() {
            if stream.write_all(&byte).await.is_err() || stream.flush().await.is_err() {
                break;
            }
        }
    });
    let client = h.client("tcp", false);
    let mut tunnel = client
        .open_tcp(&Target::Ip("127.0.0.1:80".parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(h.inner.connection_admission.available_permits(), 1022);
    tokio::time::sleep(ttl + Duration::from_millis(50)).await;
    tunnel.write_all(b"x").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut byte = [0];
    tokio::time::timeout(Duration::from_secs(2), tunnel.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"x");
    drop(tunnel);
    peer.abort();
    let _ = peer.await;
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    let inner = h.inner.clone();
    h.close().await;
    assert_eq!(inner.connection_admission.available_permits(), 1024);
}

#[tokio::test]
async fn selected_tls_failure_never_falls_back_to_healthy_quic() {
    let h = Harness::new("egress", false).await;
    let mut stream = tls_register(&h).await;
    assert_eq!(stream.read_u8().await.unwrap(), 0);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !h.inner.egress_registry.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let egress = crate::Egress::new(h.url("egress", "udp", false), Logger).unwrap();
    let task = tokio::spawn(egress.run());
    tokio::time::timeout(Duration::from_secs(3), async {
        while h.inner.egress_registry.as_ref().unwrap().registered_count() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let peer = tokio::spawn(async move {
        crate::protocol::read_flow_start(&mut stream).await.unwrap();
        crate::protocol::read_request(&mut stream).await.unwrap();
        crate::protocol::write_flow_result(
            &mut stream,
            crate::protocol::FlowResult::from(SetupResult::DialFailed),
        )
        .await
        .unwrap();
        stream.flush().await.unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Target::Ip(listener.local_addr().unwrap());
    let client = h.client("tcp", false);
    assert_eq!(
        client.open_tcp(&target).await.err().unwrap().setup_result(),
        Some(SetupResult::DialFailed)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    peer.await.unwrap();
    task.abort();
    let _ = task.await;
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    h.close().await;
}

#[tokio::test]
async fn concurrent_tls_claim_and_disconnect_release_every_permit() {
    let h = Harness::new("egress", false).await;
    for _ in 0..16 {
        let mut stream = tls_register(&h).await;
        assert_eq!(stream.read_u8().await.unwrap(), 0);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !h.inner.egress_registry.as_ref().unwrap().online() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let client = h.client("tcp", false);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let opening = tokio::spawn({
            let client = client.clone();
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                let target = Target::Ip("127.0.0.1:80".parse().unwrap());
                let _ = tokio::time::timeout(Duration::from_millis(100), client.open_tcp(&target))
                    .await;
            }
        });
        let closing = tokio::spawn({
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                drop(stream);
            }
        });
        barrier.wait().await;
        closing.await.unwrap();
        opening.await.unwrap();
        client
            .close(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while h.inner.egress_registry.as_ref().unwrap().online()
                || h.inner.connection_admission.available_permits() != 1024
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    h.close().await;
}

#[tokio::test]
async fn aborted_listener_reclaims_quic_registration_and_connection() {
    let mut h = Harness::new("egress", false).await;
    let (endpoint, connection) = connect(&h).await;
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&tag(&connection, true)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !h.inner.egress_registry.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let listener = h.tasks.remove(1);
    listener.abort();
    let _ = listener.await;
    tokio::time::timeout(Duration::from_secs(2), connection.closed())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.inner.egress_registry.as_ref().unwrap().online()
            || h.inner.connection_admission.available_permits() != 1024
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    endpoint.close(0u32.into(), b"test");
    h.close().await;
}
