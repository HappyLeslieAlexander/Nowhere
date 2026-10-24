// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared Morph TCP probe and handshake fixtures.

mod admission;
mod authenticated;
mod handshake;
mod linger;
mod probes;

use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::transport::{MorphKeys, MorphTcpStream};

use super::*;

const TIMEOUT: Duration = Duration::from_millis(400);

fn assert_silent_close(result: std::io::Result<usize>) {
    if cfg!(target_os = "linux") {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
    } else {
        assert!(
            result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
        );
    }
}

fn assert_post_accept_close(result: std::io::Result<usize>, bytes: &[u8]) {
    let reset =
        matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset);
    assert_silent_close(result);
    assert!(!bytes.is_empty() || (cfg!(windows) && reset));
}

async fn wait_active(h: &Harness, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.inner.unauthenticated_admission.active() != count {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

fn tls_config(h: &Harness, alpn: &[u8]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(crate::tls_test_support::server_certificate_der(
            &h.inner.tls_server_config,
        ))
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

async fn write_segments(stream: &mut (impl tokio::io::AsyncWrite + Unpin), bytes: &[u8]) {
    let mut offset = 0;
    for end in [1, 63, 64, 75, 76, 77, bytes.len()] {
        let end = end.min(bytes.len());
        if end > offset {
            stream.write_all(&bytes[offset..end]).await.unwrap();
            offset = end;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}
