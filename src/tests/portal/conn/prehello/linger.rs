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
async fn socket_retains_zero_linger_through_tls_and_authentication_failures() {
    for case in [
        "valid",
        "missing",
        "partial",
        "wrong-tag",
        "egress",
        "alpn",
        "tls",
        "expired",
    ] {
        let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let (server, _) = accepted.unwrap();
        server.set_zero_linger().unwrap();
        assert_eq!(server.linger().unwrap(), Some(Duration::ZERO));
        let config = Arc::new(tls_config(
            &h,
            if case == "alpn" {
                b"bad"
            } else {
                crate::protocol::ALPN
            },
        ));
        let keys = h.inner.morph_keys.clone();
        let credentials = h.inner.credentials.clone();
        let client = tokio::spawn(async move {
            let mut stream = MorphTcpStream::connect_current_for_test(client.unwrap(), keys)
                .await
                .unwrap();
            if case == "tls" {
                let mut client =
                    rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
                let mut hello = Vec::new();
                client.write_tls(&mut hello).unwrap();
                stream.write_all(&hello).await.unwrap();
                return None;
            }
            let result = tokio_rustls::TlsConnector::from(config)
                .connect("localhost".try_into().unwrap(), stream)
                .await;
            if case == "alpn" {
                assert!(result.is_err());
                return None;
            }
            let mut tls = result.unwrap();
            let mut exporter = [0; 32];
            tls.get_ref()
                .1
                .export_keying_material(
                    &mut exporter,
                    crate::protocol::AUTH_EXPORTER_LABEL,
                    Some(&[]),
                )
                .unwrap();
            let mut frame = encode_auth_frame(
                if case == "egress" {
                    credentials.egress_key
                } else {
                    credentials.vector_key
                },
                AuthTransport::TlsTcp,
                &exporter,
            );
            if case == "wrong-tag" {
                frame[0] ^= 1;
            }
            match case {
                "missing" => {}
                "partial" => tls.write_all(&frame[..8]).await.unwrap(),
                _ => tls.write_all(&frame).await.unwrap(),
            }
            Some(tls)
        });
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = MorphTcpStream::accept(server, h.inner.morph_keys.clone())
            .await
            .unwrap();
        assert_eq!(stream.get_ref().linger().unwrap(), Some(Duration::ZERO));
        let accepted = crate::portal::prehello::accept(&mut stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.get_ref().linger().unwrap(), Some(Duration::ZERO));
        {
            let handshake = tokio::time::timeout_at(
                deadline,
                tokio_rustls::StartHandshake::from_parts(accepted, &mut stream)
                    .into_stream(h.inner.tls_server_config.clone()),
            )
            .await;
            match handshake {
                Ok(Ok(mut tls)) => {
                    assert!(!matches!(case, "alpn" | "tls"));
                    assert_eq!(
                        tls.get_ref().0.get_ref().linger().unwrap(),
                        Some(Duration::ZERO)
                    );
                    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(crate::protocol::ALPN));
                    let mut exporter = [0; 32];
                    tls.get_ref()
                        .1
                        .export_keying_material(
                            &mut exporter,
                            crate::protocol::AUTH_EXPORTER_LABEL,
                            Some(&[]),
                        )
                        .unwrap();
                    let authentication = tokio::time::timeout_at(
                        deadline,
                        crate::protocol::read_auth_frame(
                            &mut tls,
                            &h.inner.credentials,
                            AuthTransport::TlsTcp,
                            &exporter,
                        ),
                    )
                    .await;
                    assert_eq!(
                        tls.get_ref().0.get_ref().linger().unwrap(),
                        Some(Duration::ZERO)
                    );
                    if matches!(case, "valid" | "expired") {
                        assert_eq!(
                            authentication.unwrap().unwrap(),
                            crate::protocol::ConnectionRole::Vector
                        );
                        let deadline = if case == "expired" {
                            Instant::now()
                        } else {
                            deadline
                        };
                        assert_eq!(
                            crate::portal::prehello::finish_authentication(
                                tls.get_ref().0.get_ref(),
                                deadline
                            )
                            .unwrap(),
                            case == "valid"
                        );
                    } else {
                        assert!(!matches!(authentication, Ok(Ok(_))));
                    }
                }
                _ => assert!(matches!(case, "alpn" | "tls")),
            }
        }
        assert_eq!(
            stream.get_ref().linger().unwrap(),
            if case == "valid" {
                None
            } else {
                Some(Duration::ZERO)
            }
        );
        drop(client.await.unwrap());
        h.close().await;
    }
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
        let stream =
            MorphTcpStream::connect_current_for_test(client.unwrap(), h.inner.morph_keys.clone())
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

#[tokio::test]
async fn unfinished_or_invalid_authentication_closes_and_releases_admission() {
    for case in ["missing", "partial", "wrong-tag", "egress"] {
        let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
        let start = Instant::now();
        let stream = TcpStream::connect(h.tcp).await.unwrap();
        let stream = MorphTcpStream::connect_current_for_test(stream, h.inner.morph_keys.clone())
            .await
            .unwrap();
        let mut tls =
            tokio_rustls::TlsConnector::from(Arc::new(tls_config(&h, crate::protocol::ALPN)))
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
        let mut frame = encode_auth_frame(
            if case == "egress" {
                h.inner.credentials.egress_key
            } else {
                h.inner.credentials.vector_key
            },
            AuthTransport::TlsTcp,
            &exporter,
        );
        if case == "wrong-tag" {
            frame[0] ^= 1;
        }
        match case {
            "missing" => {}
            "partial" => tls.write_all(&frame[..8]).await.unwrap(),
            _ => tls.write_all(&frame).await.unwrap(),
        }
        let mut tail = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            tls.get_mut().0.read_to_end(&mut tail),
        )
        .await
        .unwrap();
        assert_silent_close(result);
        if matches!(case, "missing" | "partial") {
            assert!(start.elapsed() >= TIMEOUT);
        }
        wait_active(&h, 0).await;
        assert_eq!(h.inner.connection_admission.available_permits(), 1024);
        h.close().await;
    }
}
