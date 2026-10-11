// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector carrier connections, exporter authentication, and QUIC connection reuse.

use super::config::CarrierMode;
use super::tls::{ClientTls, EXPORTER_LABEL, require_quic_nw3};
use super::{BoxReader, BoxWriter, OpenFlowError, PortalClientConfig, TcpTunnel, TcpTunnelGuard};
use crate::common::{LatencyTracker, handshake_timeout};
use crate::protocol::{
    AuthTransport, Credentials, FlowKind, SetupResult, Target, encode_auth_frame,
    encode_target_into,
};
use crate::transport::{QuicConnection, Stats};
use anyhow::{Context, Result, anyhow, bail};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

pub(crate) struct PortalClient {
    pub(crate) config: PortalClientConfig,
    pub(crate) stats: Arc<Stats>,
    pub(super) account_stats: bool,
    credentials: Credentials,
    tls: ClientTls,
    quic: Mutex<Option<(quinn::Endpoint, Arc<QuicConnection>)>>,
    latency: Arc<LatencyTracker>,
    latency_guard: crate::common::LatencyGuard,
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
struct ConnectionAttempt(Option<Arc<QuicConnection>>);
impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        if let Some(q) = &self.0 {
            q.close();
        }
    }
}
pub(crate) struct TlsCarrierGuard(Arc<Stats>, Option<crate::common::LatencyGuard>);
impl TlsCarrierGuard {
    pub(crate) fn new(stats: Arc<Stats>) -> Self {
        stats.tls_carriers_active.fetch_add(1, Ordering::Relaxed);
        Self(stats, None)
    }
}
impl Drop for TlsCarrierGuard {
    fn drop(&mut self) {
        self.0.tls_carriers_active.fetch_sub(1, Ordering::Relaxed);
    }
}
impl PortalClient {
    pub(crate) fn new(
        config: PortalClientConfig,
        credentials: &Credentials,
        stats: Arc<Stats>,
        account_stats: bool,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>> {
        let tls = ClientTls::new(&config)?;
        let latency = LatencyTracker::new();
        let latency_guard = latency.register();
        Ok(Arc::new(Self {
            config,
            stats,
            account_stats,
            credentials: credentials.clone(),
            tls,
            quic: Mutex::new(None),
            latency,
            latency_guard,
            shutdown,
        }))
    }
    pub(crate) async fn open_tcp(
        self: &Arc<Self>,
        target: &Target,
    ) -> std::result::Result<TcpTunnel, OpenFlowError> {
        let (reader, writer, mut guard) = if self.config.net == CarrierMode::Tcp {
            let (mut reader, mut writer, guard) = self
                .open_tls_stream()
                .await
                .map_err(OpenFlowError::Transport)?;
            write_start(&mut writer, FlowKind::Tcp, target)
                .await
                .map_err(OpenFlowError::Protocol)?;
            read_ready(&mut reader).await?;
            (reader, writer, guard)
        } else {
            let flow = self.open_quic_flow(FlowKind::Tcp, target).await?;
            (
                Box::pin(flow.recv) as BoxReader,
                Box::pin(flow.send) as BoxWriter,
                TcpTunnelGuard {
                    _carrier: None,
                    _flow: None,
                },
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
        let mut guard = TlsCarrierGuard::new(self.stats.clone());
        let latency = self.latency.register();
        latency.update_tcp(stream.get_ref().0.get_ref());
        guard.1 = Some(latency);
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
            TcpTunnelGuard {
                _carrier: Some(guard),
                _flow: None,
            },
        ))
    }
    pub(crate) async fn open_quic_flow(
        &self,
        kind: FlowKind,
        target: &Target,
    ) -> std::result::Result<QuicFlow, OpenFlowError> {
        let state = tokio::select! {_=self.shutdown.cancelled()=>return Err(OpenFlowError::Transport(crate::telemetry::ResultCode::Cancelled.into())),state=self.quic.lock()=>state};
        let existing = state
            .as_ref()
            .filter(|(_, q)| {
                q.connection.close_reason().is_none()
                    && !q.cancel.is_cancelled()
                    && !q.draining.is_cancelled()
            })
            .map(|(_, q)| q.clone());
        let mut locked = Some(state);
        let mut attempt = None;
        let mut endpoint = None;
        let mut auth = None;
        let q = if let Some(q) = existing {
            drop(locked.take());
            q
        } else {
            let (ep, connection) = connect_quic(&self.config, &self.tls)
                .await
                .map_err(OpenFlowError::Transport)?;
            let mut exporter = [0; 32];
            connection
                .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
                .map_err(|e| OpenFlowError::Transport(anyhow!("exporter failed: {e:?}")))?;
            auth = Some(encode_auth_frame(
                self.credentials.vector_key,
                AuthTransport::Quic,
                &exporter,
            ));
            let q = QuicConnection::new(connection, false, self.stats.clone());
            attempt = Some(ConnectionAttempt(Some(q.clone())));
            endpoint = Some(ep);
            q
        };
        let (mut send, mut recv) = timeout(handshake_timeout(), q.connection.open_bi())
            .await
            .map_err(|e| OpenFlowError::Transport(e.into()))?
            .map_err(|e| OpenFlowError::Transport(e.into()))?;
        let id = q
            .flow_id(u64::from(send.id()))
            .map_err(OpenFlowError::Protocol)?;
        let udp = if kind == FlowKind::Udp {
            Some(q.register(id).map_err(OpenFlowError::Transport)?)
        } else {
            None
        };
        let mut bytes = [0; crate::protocol::TARGET_MAX_ENCODED_LEN + 17];
        let prefix = if let Some(auth) = auth {
            bytes[..16].copy_from_slice(&auth);
            16
        } else {
            0
        };
        bytes[prefix] = kind as u8;
        let size = encode_target_into(target, &mut bytes[prefix + 1..])
            .map_err(OpenFlowError::Protocol)?;
        send.write_all(&bytes[..prefix + 1 + size])
            .await
            .map_err(|e| OpenFlowError::Transport(e.into()))?;
        let result=tokio::select! {
            _=self.shutdown.cancelled()=>return Err(OpenFlowError::Transport(crate::telemetry::ResultCode::Cancelled.into())),
            result=timeout(crate::common::flow_setup_timeout(),crate::protocol::read_flow_result(&mut recv))=>result,
        }.map_err(|error|OpenFlowError::Transport(error.into()))?.map_err(OpenFlowError::Protocol)?;
        if let Some(endpoint) = endpoint {
            let limits =
                crate::transport::transport_flow_control().map_err(OpenFlowError::Transport)?;
            q.connection
                .set_receive_window(limits.connection_receive_window.into());
            q.connection.set_max_concurrent_bi_streams(1024u32.into());
            let monitor = q.clone();
            tokio::spawn(async move {
                if monitor.connection.accept_bi().await.is_ok() {
                    monitor
                        .connection
                        .close(1u32.into(), b"role direction violation");
                }
            });

            **locked.as_mut().unwrap() = Some((endpoint, q.clone()));
            attempt.as_mut().unwrap().0 = None;
        }
        let result = SetupResult::from(result);
        if result != SetupResult::Ready {
            return Err(OpenFlowError::Setup(result));
        }
        Ok(QuicFlow { send, recv, udp })
    }
    pub(crate) async fn refresh_latency(&self) {
        if let Ok(state) = self.quic.try_lock() {
            if let Some((_, q)) = &*state
                && q.connection.close_reason().is_none()
                && !q.cancel.is_cancelled()
            {
                self.latency_guard.update(q.connection.rtt());
            } else {
                self.latency_guard.update(std::time::Duration::ZERO);
            }
        }
    }
    pub(crate) fn ping_ms(&self) -> u64 {
        self.latency.current_ms()
    }
    pub(crate) async fn close(&self, deadline: Instant) {
        self.shutdown.cancel();
        if let Some((endpoint, q)) = self.quic.lock().await.take() {
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
    request[0] = kind as u8;
    let length = encode_target_into(target, &mut request[1..])?;
    writer.write_all(&request[..length + 1]).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn read_ready(reader: &mut BoxReader) -> std::result::Result<(), OpenFlowError> {
    let result = timeout(
        crate::common::flow_setup_timeout(),
        crate::protocol::read_flow_result(reader),
    )
    .await
    .map_err(|error| OpenFlowError::Transport(error.into()))?
    .map_err(OpenFlowError::Protocol)?;
    match SetupResult::from(result) {
        SetupResult::Ready => Ok(()),
        result => Err(OpenFlowError::Setup(result)),
    }
}
pub(crate) async fn connect_quic(
    config: &PortalClientConfig,
    tls: &ClientTls,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let remote = config.udp_endpoint().context("QUIC endpoint missing")?;
    let resolved = timeout(
        handshake_timeout(),
        tokio::net::lookup_host((config.host(), remote.port)),
    )
    .await
    .context("Portal DNS timeout")??;
    let addresses =
        crate::common::filter_addrs_for_family(resolved, &config.dial_policy, remote.family);
    let mut last = anyhow!("Portal DNS returned no address");
    for address in addresses {
        let result = async {
            let bind = std::net::SocketAddr::new(
                if address.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                },
                0,
            );
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            let runtime = quinn::default_runtime().context("QUIC runtime missing")?;
            let socket = crate::transport::wrap_morph_udp_socket(
                runtime.wrap_udp_socket(socket)?,
                config.morph_keys.clone(),
                crate::transport::UdpRole::Client,
            )?;
            let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
                crate::transport::morph_endpoint_config(config.morph)?,
                None,
                socket,
                runtime,
            )?;
            let mut client = tls.quic_client_config()?;
            let mut transport = quinn::TransportConfig::default();
            let limits = crate::transport::transport_flow_control()?;
            transport
                .stream_receive_window(limits.stream_receive_window.into())
                .receive_window((64 * 1024u32).into())
                .send_window(limits.send_window)
                .max_concurrent_bidi_streams(1u32.into())
                .max_concurrent_uni_streams(0u32.into())
                .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
                .datagram_send_buffer_size(4 * 1024 * 1024)
                .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                .max_idle_timeout(Some(crate::common::udp_idle_timeout().try_into()?))
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            crate::transport::configure_morph_mtu(&mut transport, config.morph);
            client.transport_config(Arc::new(transport));
            endpoint.set_default_client_config(client);
            let connection = timeout(
                handshake_timeout(),
                endpoint.connect(address, &tls.quic_server_name())?,
            )
            .await
            .context("QUIC handshake timeout")??;
            require_quic_nw3(&connection)?;
            Ok::<_, anyhow::Error>((endpoint, connection))
        }
        .await;
        match result {
            Ok(pair) => return Ok(pair),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(test)]
#[path = "../tests/vector/client.rs"]
mod tests;
