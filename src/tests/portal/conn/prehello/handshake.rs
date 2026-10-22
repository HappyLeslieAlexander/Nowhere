// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph ClientHello continuation, authentication deadlines, and TLS response boundaries.

use std::io::Cursor;

use super::*;

#[tokio::test]
async fn shutdown_cancels_tls_after_accepted_hello_and_before_auth_frame() {
    for complete_tls in [false, true] {
        let h = Harness::new("direct", true).await;
        let inner = h.inner.clone();
        let config = Arc::new(tls_config(&h, crate::protocol::ALPN));
        let stream = TcpStream::connect(h.tcp).await.unwrap();
        let mut stream = MorphTcpStream::connect(stream, h.inner.morph_keys.clone())
            .await
            .unwrap();
        if complete_tls {
            let _tls = tokio_rustls::TlsConnector::from(config)
                .connect("localhost".try_into().unwrap(), stream)
                .await
                .unwrap();
            wait_active(&h, 1).await;
            h.close().await;
        } else {
            let mut client =
                rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
            flush_tls(&mut client, &mut stream).await;
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                1
            );
            assert_eq!(byte, [22]);
            h.close().await;
        }
        assert_eq!(inner.unauthenticated_admission.active(), 0);
        assert_eq!(inner.connection_admission.available_permits(), 1024);
    }
}

#[tokio::test]
async fn standard_tls_and_post_accept_alpn_rejection_still_respond_immediately() {
    let h = Harness::new("direct", false).await;
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    stream.write_all(&[0xff]).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes.len(), 7);
    h.close().await;

    let h = Harness::new("direct", true).await;
    let config = Arc::new(tls_config(&h, b"invalid-alpn"));
    let mut connection =
        rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).unwrap();
    let stream = TcpStream::connect(h.tcp).await.unwrap();
    let mut stream = MorphTcpStream::connect(stream, h.inner.morph_keys.clone())
        .await
        .unwrap();
    stream.write_all(&hello).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(!bytes.is_empty());
    connection.read_tls(&mut Cursor::new(bytes)).unwrap();
    assert!(matches!(
        connection.process_new_packets(),
        Err(rustls::Error::AlertReceived(
            rustls::AlertDescription::NoApplicationProtocol
        ))
    ));
    h.close().await;
}

#[tokio::test]
async fn captured_hello_with_modified_ciphertext_can_trigger_post_accept_response() {
    let h = Harness::new("direct", true).await;
    let mut client = rustls::ClientConnection::new(
        Arc::new(tls_config(&h, crate::protocol::ALPN)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let positions = hello
        .windows(9)
        .enumerate()
        .filter_map(|(offset, bytes)| {
            (bytes == [0, 16, 0, 6, 0, 4, 3, b'n', b'w']).then_some(offset + 7)
        })
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let offset = positions[0];
    assert_eq!(&hello[offset..offset + 3], b"nw3");
    let (sender, mut capture) = tokio::io::duplex(hello.len() + 76);
    let mut sender = MorphTcpStream::connect(sender, h.inner.morph_keys.clone())
        .await
        .unwrap();
    sender.write_all(&hello).await.unwrap();
    let mut captured = vec![0; hello.len() + 76];
    capture.read_exact(&mut captured).await.unwrap();
    drop(sender);
    for (index, (original, replacement)) in b"nw3".iter().zip(b"bad").enumerate() {
        captured[76 + offset + index] ^= original ^ replacement;
    }
    let mut replay = TcpStream::connect(h.tcp).await.unwrap();
    replay.write_all(&captured).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), replay.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(!response.is_empty());
    wait_active(&h, 0).await;
    h.close().await;
}

async fn flush_tls(client: &mut rustls::ClientConnection, stream: &mut MorphTcpStream<TcpStream>) {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    stream.write_all(&bytes).await.unwrap();
}

async fn read_tls(client: &mut rustls::ClientConnection, stream: &mut MorphTcpStream<TcpStream>) {
    let mut bytes = [0; 4096];
    let len = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(len, 0);
    let mut input = Cursor::new(&bytes[..len]);
    while input.position() < len as u64 {
        assert_ne!(client.read_tls(&mut input).unwrap(), 0);
        client.process_new_packets().unwrap();
    }
}

#[tokio::test]
async fn fragmented_client_hello_continues_authentication_and_bidirectional_flow() {
    for records in [false, true] {
        let h = Harness::new("direct", true).await;
        let config = Arc::new(tls_config(&h, crate::protocol::ALPN));
        let mut client =
            rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        if records {
            assert_eq!(hello[0], 22);
            let len = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
            assert_eq!(hello.len(), len + 5);
            let mut fragmented = Vec::new();
            for chunk in hello[5..].chunks(61) {
                fragmented.extend_from_slice(&hello[..3]);
                fragmented.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                fragmented.extend_from_slice(chunk);
            }
            hello = fragmented;
        }
        hello.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        let stream = TcpStream::connect(h.tcp).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut stream = MorphTcpStream::connect(stream, h.inner.morph_keys.clone())
            .await
            .unwrap();
        let start = Instant::now();
        write_segments(&mut stream, &hello).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while client.is_handshaking() {
                flush_tls(&mut client, &mut stream).await;
                read_tls(&mut client, &mut stream).await;
            }
            flush_tls(&mut client, &mut stream).await;
        })
        .await
        .unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        let mut exporter = [0; 32];
        client
            .export_keying_material(
                &mut exporter,
                crate::protocol::AUTH_EXPORTER_LABEL,
                Some(&[]),
            )
            .unwrap();
        let frame = encode_auth_frame(
            h.inner.credentials.vector_key,
            AuthTransport::TlsTcp,
            &exporter,
        );
        let (target, echo) = tcp_echo().await;
        let mut request = frame.to_vec();
        request.push(0);
        request.extend(crate::protocol::encode_target(&target).unwrap());
        std::io::Write::write_all(&mut client.writer(), &request).unwrap();
        flush_tls(&mut client, &mut stream).await;
        let mut result = [0];
        loop {
            read_tls(&mut client, &mut stream).await;
            match std::io::Read::read(&mut client.reader(), &mut result) {
                Ok(1) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("unexpected Flow result: {other:?}"),
            }
        }
        assert_eq!(
            SetupResult::from(
                crate::protocol::read_flow_result(&mut result.as_slice())
                    .await
                    .unwrap()
            ),
            SetupResult::Ready
        );
        wait_active(&h, 0).await;
        let payload = b"fragmented hello echo";
        std::io::Write::write_all(&mut client.writer(), payload).unwrap();
        flush_tls(&mut client, &mut stream).await;
        let mut response = Vec::new();
        while response.len() < payload.len() {
            read_tls(&mut client, &mut stream).await;
            let mut buffer = [0; 128];
            loop {
                match std::io::Read::read(&mut client.reader(), &mut buffer) {
                    Ok(0) => break,
                    Ok(len) => response.extend_from_slice(&buffer[..len]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("echo failed: {error}"),
                }
            }
        }
        assert_eq!(response, payload);
        drop(stream);
        h.close().await;
        echo.abort();
    }
}

#[tokio::test]
async fn bootstrap_prehello_tls_and_auth_share_one_deadline() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let start = Instant::now();
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(&[0; 64]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(&[0; 12]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(&[0xff]).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.is_empty());
    assert!(start.elapsed() >= TIMEOUT);
    h.close().await;

    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let config = Arc::new(tls_config(&h, crate::protocol::ALPN));
    let start = Instant::now();
    let stream = TcpStream::connect(h.tcp).await.unwrap();
    let stream = MorphTcpStream::connect(stream, h.inner.morph_keys.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut tls = tokio_rustls::TlsConnector::from(config)
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    tls.write_all(&[0; 8]).await.unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_millis(250), tls.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    assert!(start.elapsed() >= TIMEOUT);
    wait_active(&h, 0).await;
    h.close().await;
}

#[tokio::test]
async fn morph_deadline_includes_time_before_connection_task_starts() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap());
    let (client, accepted) = tokio::join!(client, listener.accept());
    let mut client = client.unwrap();
    let (server, peer) = accepted.unwrap();
    let accepted_at = Instant::now();
    let admission = h
        .inner
        .unauthenticated_admission
        .try_acquire(peer.ip())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let portal = h.inner.clone();
    let connection = tokio::spawn(async move {
        crate::portal::conn::tcp(portal, server, admission, accepted_at).await
    });
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(350), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(accepted_at.elapsed() >= TIMEOUT);
    assert!(matches!(
        connection.await.unwrap().unwrap(),
        crate::portal::conn::TcpOutcome::SilentPreHello
    ));
    assert_eq!(h.inner.unauthenticated_admission.active(), 0);
    h.close().await;
}
