// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS mode parsing and server configuration construction.

#[path = "tls_cert.rs"]
mod tls_cert;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::crypto::ring;
use url::Url;

use crate::protocol::ALPN;

use self::tls_cert::{ReloadingCertResolver, new_self_signed_cert};
use super::{Logger, query_first};

pub(crate) use self::tls_cert::certificate_sha256;

const TLS_QUERY_PARAMETERS: &[&str] = &["tls", "crt", "key"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMode {
    SelfSigned,
    CaTrusted,
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfSigned => f.write_str("1"),
            Self::CaTrusted => f.write_str("2"),
        }
    }
}

pub(crate) fn new_server_configs_with_reload_interval(
    parsed_url: &Url,
    reload_interval: Duration,
    logger: Logger,
) -> Result<(TlsMode, Arc<rustls::ServerConfig>, quinn::ServerConfig)> {
    let query = query_first(parsed_url, TLS_QUERY_PARAMETERS)?;
    let mode = match query.get("tls").map(String::as_str) {
        None | Some("1") => TlsMode::SelfSigned,
        Some("2") => TlsMode::CaTrusted,
        _ => bail!("common::tls::new_server_configs: invalid tls mode"),
    };

    let provider = Arc::new(ring::default_provider());
    let server_builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("common::tls::new_server_configs: failed to configure TLS versions")?
        .with_no_client_auth();

    let (mut server_crypto, cert_sha256) = match mode {
        TlsMode::SelfSigned => {
            let (certs, key) = new_self_signed_cert()
                .context("common::tls::new_server_configs: failed to create self-signed config")?;
            let cert_sha256 = certificate_sha256(&certs[0]);
            let server_crypto = server_builder
                .with_single_cert(certs, key)
                .context("common::tls::new_server_configs: failed to parse key pair")?;
            (server_crypto, cert_sha256)
        }
        TlsMode::CaTrusted => {
            let crt_file = query.get("crt").cloned().unwrap_or_default();
            let key_file = query.get("key").cloned().unwrap_or_default();
            let (resolver, cert_sha256) =
                ReloadingCertResolver::new(crt_file, key_file, provider, reload_interval, logger)
                    .context("common::tls::new_server_configs: failed to load certificate")?;
            (
                server_builder.with_cert_resolver(Arc::new(resolver)),
                cert_sha256,
            )
        }
    };

    server_crypto.max_early_data_size = 0;
    server_crypto.send_half_rtt_data = false;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicServerConfig::try_from(server_crypto.clone())
        .map_err(|e| anyhow!("common::tls::new_server_configs: QUIC TLS config failed: {e}"))?;
    logger.info(format_args!("tls certificate fingerprint: {cert_sha256}"));
    Ok((
        mode,
        Arc::new(server_crypto),
        quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)),
    ))
}

#[cfg(test)]
#[path = "../tests/common/tls.rs"]
mod tests;
