// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS outbound tcp regression tests.

use super::*;

#[tokio::test]
async fn tcp_connect_uses_only_no_auth_and_preserves_domain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_NONE]);
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let request = read_test_command(&mut stream).await;
        assert_eq!(request, (COMMAND_CONNECT, "target.test".to_string(), 443));
        write_test_reply(&mut stream, SocketAddr::from(([127, 0, 0, 1], 50000))).await;
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("target.test", 443).unwrap();
    let mut stream = dialer
        .dial_tcp_target(&target, Duration::from_secs(2))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");
    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn authenticated_connect_cannot_downgrade_to_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_PASSWORD]);
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
    });

    let config = parse(&format!(
        "portal://secret@127.0.0.1:2000?out=user:pass@{endpoint}"
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("target.test", 443).unwrap();
    assert!(
        dialer
            .dial_tcp_target(&target, Duration::from_secs(2))
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn proxy_failure_never_falls_back_to_direct_target() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let _ = read_test_command(&mut stream).await;
        stream
            .write_all(&[SOCKS_VERSION, 5, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={proxy_addr}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let protocol_target = Target::ip(target_addr).unwrap();
    assert!(
        dialer
            .dial_tcp_target(&protocol_target, Duration::from_secs(2))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    server.await.unwrap();
}
