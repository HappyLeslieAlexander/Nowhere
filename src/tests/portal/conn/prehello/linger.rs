// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph socket close policy and TLS handoff regressions.

use super::*;

#[tokio::test]
async fn burst_and_segmented_input_share_silent_close_policy() {
    let timeout = Duration::from_secs(2);
    let h = Harness::with_handshake_timeout(true, timeout).await;
    let mut probes = tokio::task::JoinSet::new();
    for (size, chunk) in [(4224, 4224), (4224, 33), (256, 1), (200_000, 200_000)] {
        for fin in [false, true] {
            let address = h.tcp;
            probes.spawn(async move {
                let start = Instant::now();
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.set_nodelay(true).unwrap();
                let mut next_write = Instant::now();
                for bytes in vec![0xff; size].chunks(chunk) {
                    stream.write_all(bytes).await.unwrap();
                    if chunk < size {
                        next_write += Duration::from_millis(1);
                        tokio::time::sleep_until(next_write).await;
                    }
                }
                if fin {
                    stream.shutdown().await.unwrap();
                }
                let mut bytes = Vec::new();
                let result = tokio::time::timeout(
                    timeout + Duration::from_secs(2),
                    stream.read_to_end(&mut bytes),
                )
                .await
                .unwrap();
                assert_silent_close(result);
                assert!(bytes.is_empty());
                assert!(start.elapsed() >= timeout);
            });
        }
    }
    while let Some(result) = probes.join_next().await {
        result.unwrap();
    }
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}

#[tokio::test]
async fn accepted_hello_restores_linger_before_normal_authentication() {
    let h = Harness::new("direct", true).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (server, _) = accepted.unwrap();
    server.set_zero_linger().unwrap();
    assert_eq!(server.linger().unwrap(), Some(Duration::ZERO));
    let mut client = MorphTcpStream::connect_legacy(client.unwrap(), h.inner.morph_keys.clone())
        .await
        .unwrap();
    let config = Arc::new(tls_config(&h, crate::protocol::ALPN));
    let mut tls = rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    tls.write_tls(&mut hello).unwrap();
    client.write_all(&hello).await.unwrap();
    let deadline = Instant::now() + h.inner.runtime.handshake_timeout;
    let mut stream = MorphTcpStream::accept(server, h.inner.morph_keys.clone())
        .await
        .unwrap();
    let accepted = tokio::time::timeout_at(deadline, crate::portal::prehello::accept(&mut stream))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stream.get_ref().linger().unwrap(), Some(Duration::ZERO));
    assert!(crate::portal::prehello::finish(stream.get_ref(), deadline).unwrap());
    assert_eq!(stream.get_ref().linger().unwrap(), None);
    accepted
        .into_connection(h.inner.tls_server_config.clone())
        .unwrap();
    h.close().await;
}

#[tokio::test]
async fn accepted_hello_continues_normal_authentication_and_close() {
    for morph in [false, true] {
        let h = Harness::new("direct", morph).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let (server, peer) = accepted.unwrap();
        let admission = h
            .inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        let portal = h.inner.clone();
        let accepted_at = Instant::now();
        let connection = tokio::spawn(async move {
            crate::portal::conn::tcp(portal, server, admission, accepted_at).await
        });
        let stream = MorphTcpStream::connect_legacy(client.unwrap(), h.inner.morph_keys.clone())
            .await
            .unwrap();
        let config = Arc::new(tls_config(&h, crate::protocol::ALPN));
        let mut tls = tokio_rustls::TlsConnector::from(config)
            .connect("localhost".try_into().unwrap(), stream)
            .await
            .unwrap();
        let mut exporter = [0; 32];
        tls.get_ref()
            .1
            .export_keying_material(
                &mut exporter,
                crate::protocol::AUTH_EXPORTER_LABEL,
                Some(&[]),
            )
            .unwrap();
        tls.write_all(&encode_auth_frame(
            h.inner.credentials.vector_key,
            AuthTransport::TlsTcp,
            &exporter,
        ))
        .await
        .unwrap();
        wait_active(&h, 0).await;
        tls.shutdown().await.unwrap();
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        h.close().await;
        tokio::time::timeout(Duration::from_secs(2), connection)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn already_expired_morph_connection_still_enables_zero_linger() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let mut client = client.unwrap();
    let (server, peer) = accepted.unwrap();
    let admission = h
        .inner
        .unauthenticated_admission
        .try_acquire(peer.ip())
        .unwrap();
    let outcome =
        crate::portal::conn::tcp(h.inner.clone(), server, admission, Instant::now() - TIMEOUT)
            .await
            .unwrap();
    assert!(matches!(
        outcome,
        crate::portal::conn::TcpOutcome::SilentPreHello
    ));
    let mut bytes = Vec::new();
    assert_silent_close(client.read_to_end(&mut bytes).await);
    assert!(bytes.is_empty());
    assert_eq!(h.inner.unauthenticated_admission.active(), 0);
    h.close().await;
}
