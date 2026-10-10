// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal listener supervision, independent telemetry, and graceful shutdown.

use super::{Portal, PortalInner, conn};
use crate::common::{LifeReason, LifeState, ShutdownSignals};
use crate::telemetry::TelemetryServer;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
mod binding;
impl Portal {
    pub async fn run(self) -> Result<()> {
        let forward = &self.inner.forward;
        forward.telemetry.set_lifecycle(
            LifeState::Starting.to_string(),
            LifeReason::Startup.to_string(),
        );
        let mut signals = ShutdownSignals::new()?;
        let tcp = self.listen_tcp_listeners()?;
        let endpoints = self.listen_endpoints()?;
        let stop = CancellationToken::new();
        let mut listeners = JoinSet::new();
        for listener in tcp {
            let portal = self.inner.clone();
            let stop = stop.clone();
            listeners.spawn(async move {
                tcp_loop(portal, listener, stop).await;
                LifeReason::TcpListenerExit
            });
        }
        for endpoint in &endpoints {
            let portal = self.inner.clone();
            let stop = stop.clone();
            let endpoint = endpoint.clone();
            listeners.spawn(async move {
                quic_loop(portal, endpoint, stop).await;
                LifeReason::QuicListenerExit
            });
        }
        let telemetry_stop = CancellationToken::new();
        let mut observation = JoinSet::new();
        match TelemetryServer::bind(forward.telemetry.clone()) {
            Ok(server) => {
                observation.spawn(server.run(telemetry_stop.clone()));
            }
            Err(_) => forward.logger.warn(format_args!(
                "Portal: LOCAL_IPC_UNAVAILABLE; continuing without local IPC"
            )),
        }
        let f = forward.clone();
        let sample_stop = telemetry_stop.clone();
        let interval = self.inner.runtime.telemetry_interval;
        observation.spawn(async move {
            let mut ticks = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = sample_stop.cancelled() => break,
                    _ = ticks.tick() => {
                        let ping = match &f.outbound {
                            super::forward::Outlet::Network(dialer) => dialer.ping_ms(),
                            super::forward::Outlet::Egress(slot) => slot.connection().map_or(0, |q| q.connection.rtt().as_millis().max(1) as u64),
                        };
                        f.telemetry.capture_and_publish(&f.stats, ping);
                    }
                }
            }
        });
        forward
            .logger
            .info(format_args!("Portal starting: {}", self.inner.effective));
        forward.telemetry.set_lifecycle(
            LifeState::Ready.to_string(),
            LifeReason::Listening.to_string(),
        );
        let reason = tokio::select! {reason=signals.recv()=>reason?,exit=listeners.join_next()=>exit.and_then(Result::ok).unwrap_or(LifeReason::QuicListenerExit)};
        forward
            .telemetry
            .set_lifecycle(LifeState::Draining.to_string(), reason.to_string());
        stop.cancel();
        forward.shutdown.cancel();
        let drained = tokio::time::timeout(self.inner.runtime.shutdown_timeout, async {
            while listeners.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        if drained {
            forward.telemetry.set_lifecycle(
                LifeState::Draining.to_string(),
                LifeReason::Drained.to_string(),
            );
        }
        listeners.abort_all();
        while listeners.join_next().await.is_some() {}
        for endpoint in endpoints {
            endpoint.close(0u32.into(), b"shutdown");
        }
        forward.telemetry.set_lifecycle(
            LifeState::Stopped.to_string(),
            if drained {
                LifeReason::CleanupComplete
            } else {
                LifeReason::Timeout
            }
            .to_string(),
        );
        forward.telemetry.capture_and_publish(&forward.stats, 0);
        telemetry_stop.cancel();
        while observation.join_next().await.is_some() {}
        forward.logger.flush();
        Ok(())
    }
}
pub(super) async fn tcp_loop(
    portal: Arc<PortalInner>,
    listener: tokio::net::TcpListener,
    stop: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Some(admission) = portal.unauthenticated_admission.try_acquire(peer.ip()) else { continue; };
                    let Ok(permit) = portal.connection_admission.clone().try_acquire_owned() else { continue; };
                    let p = portal.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = conn::tcp(p.clone(), stream, peer, admission).await {
                            p.forward.logger.debug(format_args!("TLS connection failed: {}", crate::telemetry::diagnostic_reason(&format!("{error:#}"))));
                        }
                    });
                }
                Err(_) => break,
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
    while tasks.join_next().await.is_some() {}
}
pub(super) async fn quic_loop(
    portal: Arc<PortalInner>,
    endpoint: quinn::Endpoint,
    stop: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                if !incoming.remote_address_validated() {
                    let _ = incoming.retry();
                    continue;
                }
                let Some(admission) = portal.unauthenticated_admission.try_acquire(incoming.remote_address().ip()) else { incoming.ignore(); continue; };
                let Ok(permit) = portal.connection_admission.clone().try_acquire_owned() else { incoming.ignore(); continue; };
                let p = portal.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = conn::quic(p.clone(), incoming, admission).await {
                        p.forward.logger.debug(format_args!("QUIC connection failed: {}", crate::telemetry::diagnostic_reason(&format!("{error:#}"))));
                    }
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
    while tasks.join_next().await.is_some() {}
}
