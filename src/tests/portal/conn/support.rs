// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared portal connection test helpers.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Connection;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger};
use crate::portal::Portal;

use super::super::*;

#[derive(Debug)]
struct AcceptAnyServerCertificate;

impl ServerCertVerifier for AcceptAnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub(super) async fn connect_test_tls(
    listen_addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"now/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(listen_addr).await.unwrap();
    connector
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            stream,
        )
        .await
        .unwrap()
}

pub(super) async fn connect_test_quic() -> (
    Portal,
    quinn::Endpoint,
    quinn::Endpoint,
    Connection,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:0?net=udp&log=none").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let server_endpoint = portal.listen_endpoints().unwrap().pop().unwrap();
    let listen_addr = server_endpoint.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server_portal = portal.inner.clone();
    let server_endpoint_for_task = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        crate::portal::listener::accept_endpoint_loop(
            server_portal,
            server_endpoint_for_task,
            server_shutdown,
        )
        .await;
    });

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate))
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"now/1".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(rustls_config).unwrap();
    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));
    let connection = client_endpoint
        .connect(listen_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    (
        portal,
        server_endpoint,
        client_endpoint,
        connection,
        shutdown,
        server_task,
    )
}

pub(super) async fn stop_test_quic(
    server_endpoint: quinn::Endpoint,
    client_endpoint: quinn::Endpoint,
    shutdown: CancellationToken,
    server_task: tokio::task::JoinHandle<()>,
) {
    shutdown.cancel();
    server_endpoint.close(VarInt::from_u32(0), b"");
    client_endpoint.close(VarInt::from_u32(0), b"");
    server_task.await.unwrap();
}
