// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph TCP admission retention, release, and shutdown regressions.

use super::*;

#[tokio::test]
async fn shutdown_releases_all_morph_prehello_states_and_disposal_budget_exhaustion() {
    for (size, fin) in [
        (0, false),
        (76, false),
        (77, false),
        (77, true),
        (200_000, false),
    ] {
        let h = Harness::new("direct", true).await;
        let inner = h.inner.clone();
        let permits = inner.connection_admission.available_permits();
        let mut stream = TcpStream::connect(h.tcp).await.unwrap();
        stream.write_all(&vec![0xff; size]).await.unwrap();
        if fin {
            stream.shutdown().await.unwrap();
        }
        wait_active(&h, 1).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        h.close().await;
        assert_eq!(inner.unauthenticated_admission.active(), 0);
        assert_eq!(inner.connection_admission.available_permits(), permits);
    }
}

#[tokio::test]
async fn silent_connections_hold_source_admission_until_timeout() {
    let h = Harness::with_handshake_timeout(true, Duration::from_secs(1)).await;
    let mut streams = Vec::new();
    for _ in 0..32 {
        let mut stream = TcpStream::connect(h.tcp).await.unwrap();
        stream.write_all(&[0xff; 77]).await.unwrap();
        stream.shutdown().await.unwrap();
        streams.push(stream);
    }
    wait_active(&h, 32).await;
    let mut rejected = TcpStream::connect(h.tcp).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), rejected.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(h.inner.unauthenticated_admission.active(), 32);
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}

#[tokio::test]
async fn global_admission_blocks_real_socket_and_recovers() {
    let h = Harness::new("direct", true).await;
    let held = (0..256)
        .map(|index| {
            h.inner
                .unauthenticated_admission
                .try_acquire(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    10,
                    0,
                    (index / 255) as u8,
                    index as u8,
                )))
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut rejected = TcpStream::connect(h.tcp).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(held);
    let (target, echo) = tcp_echo().await;
    let client = h.client("tcp", true);
    let mut tunnel = tokio::time::timeout(Duration::from_secs(2), client.open_tcp(&target))
        .await
        .unwrap()
        .unwrap();
    tunnel.write_all(b"admission recovered").await.unwrap();
    let mut buffer = [0; 19];
    tunnel.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"admission recovered");
    drop(tunnel);
    client.close(Instant::now() + Duration::from_secs(2)).await;
    h.close().await;
    echo.abort();
}
