// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! ClientHello buffering, asynchronous wakeups, and disposal budget regressions.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;

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

struct Flood {
    chunk: usize,
    bytes: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
}

impl AsyncRead for Flood {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = self.chunk.min(buffer.remaining());
        buffer.initialize_unfilled_to(len).fill(0);
        buffer.advance(len);
        self.bytes.fetch_add(len, Ordering::Relaxed);
        self.reads.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn disposal_bounds_bytes_and_reads_and_yields_to_other_tasks() {
    for (chunk, expected_bytes, expected_reads) in [(4096, DISCARD_BYTES, 16), (1, 64, 64)] {
        let bytes = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let task = discard(Flood {
            chunk,
            bytes: bytes.clone(),
            reads: reads.clone(),
        });
        tokio::pin!(task);
        tokio::select! {
            biased;
            _ = &mut task => panic!("disposal must retain the connection"),
            _ = tokio::task::yield_now() => assert!(reads.load(Ordering::Relaxed) <= 2),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), task)
                .await
                .is_err()
        );
        assert_eq!(bytes.load(Ordering::Relaxed), expected_bytes);
        assert_eq!(reads.load(Ordering::Relaxed), expected_reads);
    }
}

#[tokio::test]
async fn disposal_does_not_poll_eof_repeatedly() {
    let reads = Arc::new(AtomicUsize::new(0));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            discard(Flood {
                chunk: 0,
                bytes: Arc::new(AtomicUsize::new(0)),
                reads: reads.clone(),
            })
        )
        .await
        .is_err()
    );
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}
