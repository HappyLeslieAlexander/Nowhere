// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! ClientHello buffering, asynchronous wakeups, and socket handoff regressions.

use std::sync::Arc;
use std::time::Duration;

use super::*;

#[tokio::test]
async fn linger_handoff_preserves_abortive_close_when_expired() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let _client = client.unwrap();
    let (stream, _) = accepted.unwrap();
    for _ in 0..100 {
        for offset in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_secs(1),
        ] {
            stream.set_zero_linger().unwrap();
            let deadline = Instant::now() + offset;
            let continued = finish_authentication(&stream, deadline).unwrap();
            assert_eq!(
                stream.linger().unwrap(),
                (!continued).then_some(Duration::ZERO)
            );
            if offset.is_zero() {
                assert!(!continued);
            } else if offset == Duration::from_secs(1) {
                assert!(continued);
            }
        }
    }
}

#[tokio::test]
async fn accepted_preserves_following_tls_record() {
    let url = url::Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000").unwrap();
    let (_, config, _) = crate::common::new_server_configs_with_reload_interval(
        &url,
        Duration::from_secs(3600),
        crate::common::Logger,
    )
    .unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    client_config.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes.extend_from_slice(&[21, 3, 3, 0, 2, 2, 40]);
    let mut input = bytes.as_slice();
    let accepted = accept(&mut input).await.unwrap().unwrap();
    assert!(input.is_empty());
    let mut connection = accepted.into_connection(config).unwrap();
    assert!(matches!(
        connection.process_new_packets(),
        Err(rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure
        ))
    ));
}

#[tokio::test]
async fn pending_read_wakes_and_invalid_input_is_rejected() {
    let (mut writer, mut reader) = tokio::io::duplex(8);
    let rejection = accept(&mut reader);
    tokio::pin!(rejection);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut rejection)
            .await
            .is_err()
    );
    tokio::io::AsyncWriteExt::write_all(&mut writer, &[0xff])
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), rejection)
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}
