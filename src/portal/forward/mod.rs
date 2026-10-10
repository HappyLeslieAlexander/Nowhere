// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared target forwarding for Portal ingress and registered Egress streams.

mod incoming;
mod tcp;
mod udp;

use crate::common::{Logger, OutboundDialer};
use crate::portal::egress::EgressSlot;
use crate::protocol::{FlowKind, SetupResult};
use crate::telemetry::{AccessOutcome, AccessStart, TelemetryHub, TrafficProtocol};
use crate::transport::{Buffers, RateLimiter, Stats};
pub(crate) use incoming::Incoming;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

pub(crate) enum Outlet {
    Network(Arc<OutboundDialer>),
    Egress(Arc<EgressSlot>),
}
pub(crate) struct Forwarder {
    pub(crate) outbound: Outlet,
    pub(crate) runtime: crate::portal::config::PortalRuntimeConfig,
    pub(crate) logger: Logger,
    pub(crate) telemetry: Arc<TelemetryHub>,
    pub(crate) stats: Arc<Stats>,
    pub(crate) buffers: Buffers,
    pub(crate) rate: Option<Arc<RateLimiter>>,
    pub(crate) flows: Arc<Semaphore>,
    pub(crate) shutdown: CancellationToken,
}
struct ActiveFlow {
    stats: Arc<Stats>,
    udp: bool,
}
impl ActiveFlow {
    fn new(stats: Arc<Stats>, udp: bool) -> Self {
        stats.add_flow(udp);
        Self { stats, udp }
    }
}
impl Drop for ActiveFlow {
    fn drop(&mut self) {
        self.stats.done_flow(self.udp);
    }
}
impl Forwarder {
    pub(crate) async fn serve(
        self: Arc<Self>,
        mut incoming: Incoming,
        peer: String,
        connection_cancel: CancellationToken,
    ) {
        let carrier = incoming.carrier();
        let request = tokio::select! {
            _=connection_cancel.cancelled()=>return,
            _=self.shutdown.cancelled()=>return,
            request=tokio::time::timeout(self.runtime.handshake_timeout,incoming.request())=>request,
        };
        let (kind, target) = match request {
            Ok(Ok(Some(request))) => request,
            Ok(Ok(None)) => {
                if matches!(&incoming,Incoming::Quic {send,connection,..} if u64::from(send.id())==0&&!connection.server_initiated)
                {
                    return;
                }
                let _ = incoming.result(SetupResult::InvalidRequest).await;
                return;
            }
            _ => {
                let _ = incoming.result(SetupResult::InvalidRequest).await;
                return;
            }
        };
        let access = self.telemetry.start_access(|| AccessStart {
            protocol: if kind == FlowKind::Tcp {
                TrafficProtocol::Tcp
            } else {
                TrafficProtocol::Udp
            },
            client: Some(peer.clone()),
            peer: Some(peer),
            target: target.to_string(),
            carrier,
        });
        let Ok(_permit) = self.flows.clone().try_acquire_owned() else {
            let _ = incoming.result(SetupResult::FlowLimit).await;
            access.finish(
                AccessOutcome::Rejected,
                Some("resource limit reached".to_owned()),
            );
            return;
        };
        let result = match kind {
            FlowKind::Tcp => {
                self.tcp(incoming, &target, carrier, &access, connection_cancel)
                    .await
            }
            FlowKind::Udp => {
                self.udp(incoming, &target, &access, connection_cancel)
                    .await
            }
        };
        match result {
            Ok(outcome) => access.finish(
                outcome,
                (outcome == AccessOutcome::Timeout).then(|| "idle timeout".to_owned()),
            ),
            Err(error) => {
                let error = format!("{error:#}");
                access.finish(AccessOutcome::from_error(&error), Some(error));
            }
        }
    }
}
