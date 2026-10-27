// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Single-supervisor TLS registration, demand growth, and standby expiration.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::portal::forward::Incoming;
use crate::protocol::{AuthTransport, FlowKind, encode_auth_frame};
use crate::transport::MorphTcpStream;
use crate::vector::{PortalClientConfig, TcpTunnelGuard, tls::ClientTls};

use super::Egress;

type TlsStream = tokio_rustls::client::TlsStream<MorphTcpStream<tokio::net::TcpStream>>;

enum PendingResult {
    Started(Box<TlsStream>, FlowKind),
    Expired,
    Failed(anyhow::Error),
}

impl Egress {
    pub(super) async fn maintain_tls(&self) {
        let mut pending = JoinSet::new();
        let mut flows = JoinSet::new();
        let mut seed_at = Instant::now();
        loop {
            // Reap completed Flows even while standby completions remain continuously ready.
            while flows.try_join_next().is_some() {}
            tokio::select! {
                biased;
                _ = self.forward.shutdown.cancelled() => break,
                _ = tokio::time::sleep_until(seed_at), if pending.is_empty() => {
                    self.spawn_tls_pending(&mut pending);
                },
                result = pending.join_next(), if !pending.is_empty() => {
                    match result {
                        Some(Ok(PendingResult::Started(stream, kind))) => {
                            let count = 2.min(self.tls_pool_max.saturating_sub(pending.len()));
                            for _ in 0..count {
                                self.spawn_tls_pending(&mut pending);
                            }
                            let forward = self.forward.clone();
                            flows.spawn(async move {
                                let (reader, writer) = tokio::io::split(*stream);
                                forward.serve_started(
                                    Incoming::Tls {
                                        reader: Box::pin(reader),
                                        writer: Box::pin(writer),
                                        guard: TcpTunnelGuard { _flow: None },
                                    },
                                    CancellationToken::new(),
                                    kind,
                                ).await;
                            });
                        },
                        Some(Ok(PendingResult::Expired)) => {
                            if pending.is_empty() { seed_at = Instant::now(); }
                        },
                        Some(Ok(PendingResult::Failed(error))) => {
                            if !self.forward.shutdown.is_cancelled() {
                                self.forward.logger.error(format_args!("egress TLS connection failed: {error:#}"));
                            }
                            if pending.is_empty() { seed_at = Instant::now() + crate::common::service_cooldown(); }
                        },
                        Some(Err(error)) => {
                            self.forward.logger.error(format_args!("egress TLS task failed: {error}"));
                            if pending.is_empty() { seed_at = Instant::now() + crate::common::service_cooldown(); }
                        },
                        None => {},
                    }
                },
                _ = flows.join_next(), if !flows.is_empty() => {},
            }
        }
        pending.abort_all();
        while pending.join_next().await.is_some() {}
        let _ = tokio::time::timeout(self.forward.runtime.shutdown_timeout, async {
            while flows.join_next().await.is_some() {}
        })
        .await;
        flows.abort_all();
        while flows.join_next().await.is_some() {}
    }

    fn spawn_tls_pending(&self, pending: &mut JoinSet<PendingResult>) {
        let config = self.config.clone();
        let tls = self.tls.clone();
        let key = self.credentials.egress_key;
        let shutdown = self.forward.shutdown.clone();
        let idle_ttl = self.forward.runtime.egress_tls_idle_ttl;
        pending.spawn(async move {
            match pending_connection(config, tls, key, shutdown, idle_ttl).await {
                Ok(result) => result,
                Err(error) => PendingResult::Failed(error),
            }
        });
    }
}

async fn pending_connection(
    config: PortalClientConfig,
    tls: ClientTls,
    key: [u8; 32],
    shutdown: CancellationToken,
    idle_ttl: Duration,
) -> Result<PendingResult> {
    let endpoint = config
        .tcp_endpoint()
        .context("TLS Egress endpoint missing")?;
    let address = config.remote.carrier_addr(endpoint);
    let (mut stream, exporter) = tokio::select! {
        biased;
        _ = shutdown.cancelled() => bail!("Egress shutting down"),
        result = tls.connect_tcp(&address, &config.dial_policy, endpoint.family) => result?,
    };
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => bail!("Egress shutting down"),
        result = tokio::time::timeout(crate::common::handshake_timeout(), async {
            stream.write_all(&encode_auth_frame(key, AuthTransport::TlsTcp, &exporter)).await?;
            stream.flush().await?;
            let reply = stream.read_u8().await?;
            match reply {
                0 => Ok(()),
                1 => bail!("Egress TLS registration busy"),
                _ => bail!("invalid Egress TLS registration reply"),
            }
        }) => result.context("Egress TLS registration timeout")??,
    }
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => bail!("Egress shutting down"),
        _ = tokio::time::sleep(idle_ttl) => Ok(PendingResult::Expired),
        result = crate::protocol::read_flow_start(&mut stream) => match result? {
            Some(kind) => Ok(PendingResult::Started(Box::new(stream), kind)),
            None => bail!("Egress TLS standby disconnected"),
        },
    }
}

#[cfg(test)]
#[path = "../tests/egress/tls.rs"]
mod tests;
