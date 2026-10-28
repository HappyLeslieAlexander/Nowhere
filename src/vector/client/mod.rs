// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector client state, TLS flow setup, and bounded connection shutdown.

mod quic;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    AuthTransport, Credentials, FlowKind, SetupResult, Target, encode_auth_frame,
    encode_flow_request_into,
};
use crate::transport::{QuicConnection, Stats};

use super::config::CarrierMode;
use super::tls::ClientTls;
use super::{BoxReader, BoxWriter, OpenFlowError, PortalClientConfig, TcpTunnel, TcpTunnelGuard};

pub(crate) use self::quic::connect_quic;

pub(crate) struct PortalClient {
    pub(crate) config: PortalClientConfig,
    pub(crate) stats: Arc<Stats>,
    pub(super) account_stats: bool,
    credentials: Credentials,
    tls: ClientTls,
    flow_setup_timeout: Duration,
    quic: Mutex<Option<(quinn::Endpoint, Arc<QuicConnection>)>>,
    pub(super) shutdown: CancellationToken,
}

pub(crate) struct QuicFlow {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
    pub(crate) udp: Option<(
        crate::transport::UdpRoute,
        tokio::sync::mpsc::Receiver<crate::common::BudgetedDatagram>,
    )>,
}

impl PortalClient {
    pub(crate) fn new(
        config: PortalClientConfig,
        credentials: &Credentials,
        stats: Arc<Stats>,
        account_stats: bool,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>> {
        crate::common::validate_timeout_env()?;
        let tls = ClientTls::new(&config)?;
        Ok(Arc::new(Self {
            config,
            stats,
            account_stats,
            credentials: credentials.clone(),
            tls,
            flow_setup_timeout: crate::common::flow_setup_timeout(),
            quic: Mutex::new(None),
            shutdown,
        }))
    }

    pub(crate) async fn open_tcp(
        self: &Arc<Self>,
        target: &Target,
    ) -> std::result::Result<TcpTunnel, OpenFlowError> {
        let (reader, writer, mut guard) = if self.config.net == CarrierMode::Tcp {
            self.open_tls_flow(FlowKind::Tcp, target).await?
        } else {
            let flow = self.open_quic_flow(FlowKind::Tcp, target).await?;
            (
                Box::pin(flow.recv) as BoxReader,
                Box::pin(flow.send) as BoxWriter,
                TcpTunnelGuard { _flow: None },
            )
        };
        if self.account_stats {
            self.stats.add_flow(false);
            guard._flow = Some(super::flow::FlowGuard::new(self.stats.clone(), false));
        }
        Ok(TcpTunnel::new(
            reader,
            writer,
            self.config.net.carrier(),
            guard,
        ))
    }

    pub(super) async fn open_tls_flow(
        &self,
        kind: FlowKind,
        target: &Target,
    ) -> std::result::Result<(BoxReader, BoxWriter, TcpTunnelGuard), OpenFlowError> {
        let deadline = Instant::now() + self.flow_setup_timeout;
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => Err(OpenFlowError::Cancelled),
            result = timeout_at(deadline, async {
                let (mut reader, mut writer, guard) = self.open_tls_stream()
                    .await.map_err(OpenFlowError::Transport)?;
                write_start(&mut writer, kind, target).await.map_err(OpenFlowError::Protocol)?;
                read_ready(&mut reader).await?;
                Ok((reader, writer, guard))
            }) => result.map_err(|error| OpenFlowError::Transport(error.into()))?,
        }
    }

    pub(crate) async fn open_tls_stream(&self) -> Result<(BoxReader, BoxWriter, TcpTunnelGuard)> {
        if self.shutdown.is_cancelled() {
            bail!("client shutting down");
        }
        let endpoint = self.config.tcp_endpoint().context("TLS endpoint missing")?;
        let (stream, exporter) = self
            .tls
            .connect_tcp(
                &self.config.remote.carrier_addr(endpoint),
                &self.config.dial_policy,
                endpoint.family,
            )
            .await?;
        let (reader, mut writer) = tokio::io::split(stream);
        writer
            .write_all(&encode_auth_frame(
                self.credentials.vector_key,
                AuthTransport::TlsTcp,
                &exporter,
            ))
            .await?;
        Ok((
            Box::pin(reader),
            Box::pin(writer),
            TcpTunnelGuard { _flow: None },
        ))
    }

    pub(crate) async fn close(&self, deadline: Instant) {
        self.shutdown.cancel();
        let Ok(mut state) = tokio::time::timeout_at(deadline, self.quic.lock()).await else {
            return;
        };
        let cached = state.take();
        drop(state);
        if let Some((endpoint, q)) = cached {
            q.close();
            let _ = tokio::time::timeout_at(deadline, endpoint.wait_idle()).await;
        }
    }
}

pub(crate) async fn write_start(
    writer: &mut BoxWriter,
    kind: FlowKind,
    target: &Target,
) -> Result<()> {
    let mut request = [0; crate::protocol::TARGET_MAX_ENCODED_LEN + 1];
    let length = encode_flow_request_into(kind, target, &mut request)?;
    writer.write_all(&request[..length]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_ready(reader: &mut BoxReader) -> std::result::Result<(), OpenFlowError> {
    let result = crate::protocol::read_flow_result(reader)
        .await
        .map_err(OpenFlowError::Protocol)?;
    match SetupResult::from(result) {
        SetupResult::Ready => Ok(()),
        result => Err(OpenFlowError::Setup(result)),
    }
}

#[cfg(test)]
#[path = "../../tests/vector/client/mod.rs"]
mod tests;
