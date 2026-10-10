// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS fingerprint queries, share-link validation, and error redaction tests.

use super::*;
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn fingerprint_connection_refusal_reports_the_cause_without_echoing_the_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let error = fingerprint(Url::parse(&format!("nowhere://secret@{address}")).unwrap())
        .await
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("TCP connection failed: connection refused"),
        "{message}"
    );
    assert!(!message.contains("secret"), "{message}");
    assert!(!message.contains(&address.to_string()), "{message}");
}

#[tokio::test]
async fn fingerprint_rejects_udp_only_and_invalid_share_links_without_leaking_secrets() {
    for (raw, expected) in [
        (
            "nowhere://secret@localhost/udp:2000#My%20Portal",
            "requires a TCP carrier",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000",
            "invalid Nowhere share link",
        ),
        (
            "portal://secret@localhost:2000",
            "invalid Nowhere share link",
        ),
        ("nowhere://secret@*:2000", "invalid Nowhere share link"),
        ("nowhere://localhost:2000", "invalid Nowhere share link"),
        (
            "nowhere://secret:password@localhost:2000",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret%ZZ@localhost:2000",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret@localhost/tcp4:2000",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret@localhost:2000?morph=secret",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret@localhost:2000?sni=secret:443",
            "invalid Nowhere share link",
        ),
    ] {
        let error = fingerprint(Url::parse(raw).unwrap()).await.unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn fingerprint_share_links_decode_keys_and_ignore_display_names_and_flow_options() {
    let url = Url::parse(
        "nowhere://shared%40key%3A%2F%3F%23%25%2B@[::1]/tcp:2006/udp:2017?morph=1&morph=0&sni=relay.example&up=udp&down=udp&mux=1&pin=wrong&socks=missing#My%20Portal",
    ).unwrap();
    let config = PortalClientConfig::from_fingerprint_url(&url).unwrap();
    assert_eq!(config.endpoint(), "[::1]/tcp:2006/udp:2017");
    assert_eq!(config.sni.as_deref(), Some("relay.example"));
    assert!(config.pin.is_none());
    assert_eq!(
        config.morph_keys.unwrap().udp_keys(),
        crate::transport::MorphKeys::derive(b"shared@key:/?#%+").udp_keys(),
    );
    assert!(
        PortalClientConfig::from_fingerprint_url(
            &Url::parse("nowhere://secret@localhost:2000").unwrap(),
        )
        .is_ok()
    );
}

#[tokio::test]
async fn fingerprint_reads_the_leaf_certificate_with_and_without_morph_without_flow_data() {
    use rustls::crypto::ring;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use crate::common::certificate_sha256;
    use crate::transport::MorphTcpStream;

    for morph in [0, 1] {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate: CertificateDer<'static> = generated.cert.into();
        let expected = certificate_sha256(&certificate);
        let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let mut server =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key.into())
                .unwrap();
        server.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = Url::parse(&format!(
            "nowhere://secret@{address}?morph={morph}&sni=wrong.example&up=udp&down=udp&mux=1#My%20Portal"
        )).unwrap();
        let config = PortalClientConfig::from_fingerprint_url(&url).unwrap();
        let morph_keys = config.morph_keys.clone();
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = MorphTcpStream::accept(tcp, morph_keys).await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server))
                .accept(stream)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.server_name(), Some("wrong.example"));
            let mut byte = [0];
            match stream.read(&mut byte).await {
                Ok(length) => assert_eq!(length, 0, "fingerprint sent application data"),
                Err(error) => assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ),
                    "unexpected TLS read error: {error}"
                ),
            }
        });
        let actual = crate::vector::fetch_certificate_fingerprint(&config)
            .await
            .unwrap();
        assert_eq!(actual, expected);
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }
}
