// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Silent Morph TCP probe and rejected-input disposal regressions.

use super::*;

async fn probe(address: std::net::SocketAddr, size: usize, decoded: bool, split: bool, fin: bool) {
    let start = Instant::now();
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.set_nodelay(true).unwrap();
    if decoded && size >= 76 {
        let mut morph = MorphTcpStream::connect(stream, Some(MorphKeys::derive(KEY.as_bytes())))
            .await
            .unwrap();
        let bytes = vec![0xff; size - 76];
        if split {
            write_segments(&mut morph, &bytes).await;
        } else {
            morph.write_all(&bytes).await.unwrap();
        }
        stream = morph.into_inner();
    } else {
        let mut bytes = vec![0; size];
        if !decoded {
            getrandom::fill(&mut bytes).unwrap();
        }
        if split {
            write_segments(&mut stream, &bytes).await;
        } else {
            stream.write_all(&bytes).await.unwrap();
        }
    }
    if fin {
        stream.shutdown().await.unwrap();
    }
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(
        TIMEOUT + Duration::from_secs(2),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap();
    assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
    assert!(
        bytes.is_empty(),
        "size={size}, decoded={decoded}, split={split}, fin={fin}"
    );
    assert!(
        start.elapsed() >= TIMEOUT,
        "early close: size={size}, decoded={decoded}, split={split}, fin={fin}"
    );
}

#[tokio::test]
async fn invalid_morph_probe_matrix_is_silent_until_original_deadline() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let permits = h.inner.connection_admission.available_permits();
    for decoded in [false, true] {
        for split in [false, true] {
            for fin in [false, true] {
                let mut probes = tokio::task::JoinSet::new();
                for size in [0, 63, 64, 75, 76, 77, 78, 80, 81, 128, 200, 1000] {
                    probes.spawn(probe(h.tcp, size, decoded, split, fin));
                }
                while let Some(result) = probes.join_next().await {
                    result.unwrap();
                }
                wait_active(&h, 0).await;
                assert_eq!(h.inner.connection_admission.available_permits(), permits);
            }
        }
    }
    h.close().await;
}

#[tokio::test]
async fn wrong_morph_key_is_silent_until_deadline() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let mut url = h.url("vector", "tcp", true);
    url.set_username("ffffffffffffffffffffffffffffffff")
        .unwrap();
    let (config, _) = PortalClientConfig::from_probe_url(&url).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    let start = Instant::now();
    let endpoint = h.tcp.to_string();
    let result = tls.connect_tcp(
        &endpoint,
        &config.dial_policy,
        crate::common::AddressFamily::Any,
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), result)
            .await
            .unwrap()
            .is_err()
    );
    assert!(start.elapsed() >= TIMEOUT);
    wait_active(&h, 0).await;
    h.close().await;
}

#[tokio::test]
async fn truncated_valid_client_hello_with_fin_keeps_original_deadline() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let mut client = rustls::ClientConnection::new(
        Arc::new(tls_config(&h, crate::protocol::ALPN)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    for length in [1, 5, hello.len() - 1] {
        let start = Instant::now();
        let stream = TcpStream::connect(h.tcp).await.unwrap();
        let mut stream = MorphTcpStream::connect(stream, h.inner.morph_keys.clone())
            .await
            .unwrap();
        stream.write_all(&hello[..length]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(bytes.is_empty());
        assert!(start.elapsed() >= TIMEOUT);
    }
    wait_active(&h, 0).await;
    h.close().await;
}

#[tokio::test]
async fn reset_during_silent_disposal_releases_admission_early() {
    let h = Harness::new("direct", true).await;
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    stream.write_all(&[0xff; 77]).await.unwrap();
    wait_active(&h, 1).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    socket2::SockRef::from(&stream)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(stream);
    tokio::time::timeout(Duration::from_secs(1), wait_active(&h, 0))
        .await
        .unwrap();
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}

#[tokio::test]
async fn excess_rejected_input_remains_silent_and_keeps_the_deadline() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let start = Instant::now();
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    stream.write_all(&vec![0xff; 200_000]).await.unwrap();
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(
        TIMEOUT + Duration::from_secs(1),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap();
    assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
    assert!(bytes.is_empty());
    assert!(start.elapsed() >= TIMEOUT);
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}
