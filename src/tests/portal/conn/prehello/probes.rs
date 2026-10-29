// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Silent Morph TCP probe and rejected-input retention regressions.

use super::*;

async fn probe(address: std::net::SocketAddr, size: usize, decoded: bool, split: bool, fin: bool) {
    let start = Instant::now();
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.set_nodelay(true).unwrap();
    if decoded && size >= 76 {
        let mut morph = MorphTcpStream::connect_current_for_test(
            stream,
            Some(MorphKeys::derive(KEY.as_bytes())),
        )
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
    assert_silent_close(result);
    assert!(
        bytes.is_empty(),
        "size={size}, decoded={decoded}, split={split}, fin={fin}"
    );
    // Only a full prelude+nonce of garbage proves the peer lacks the key;
    // shorter inputs (or a clean EOF) stay ambiguous and keep the park.
    // Wire image of one prelude: TCP_PRELUDE_LEN(64) + NONCE_LEN(12).
    let full_garbage = !decoded && size >= 76;
    if decoded || !full_garbage {
        // A valid prelude with a non-hello payload keeps the silent park.
        assert!(
            start.elapsed() >= TIMEOUT,
            "early close: size={size}, decoded={decoded}, split={split}, fin={fin}"
        );
    } else {
        assert!(
            start.elapsed() < TIMEOUT,
            "held slot: size={size}, decoded={decoded}, split={split}, fin={fin}"
        );
    }
}

#[tokio::test]
async fn morph_probe_matrix_closes_garbage_fast_and_parks_valid_preludes() {
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
async fn wrong_morph_key_fails_fast_without_holding_a_slot() {
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
    assert!(start.elapsed() < TIMEOUT);
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
        let mut stream =
            MorphTcpStream::connect_current_for_test(stream, h.inner.morph_keys.clone())
                .await
                .unwrap();
        stream.write_all(&hello[..length]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .unwrap();
        assert_silent_close(result);
        assert!(bytes.is_empty());
        assert!(start.elapsed() >= TIMEOUT);
    }
    wait_active(&h, 0).await;
    h.close().await;
}

#[tokio::test]
async fn excess_garbage_closes_immediately_and_releases_admission() {
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
    assert_silent_close(result);
    assert!(bytes.is_empty());
    assert!(start.elapsed() < TIMEOUT);
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}
