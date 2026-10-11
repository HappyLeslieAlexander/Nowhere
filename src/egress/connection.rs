// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress QUIC connection ownership, authenticated stream serving, and reconnects.

use super::Egress;
use crate::portal::forward::Incoming;
use crate::telemetry::TelemetryHub;
use crate::transport::QuicConnection;
use crate::vector::client::connect_quic;
use anyhow::{Result, bail};
use std::sync::Arc;
use tokio::task::JoinSet;

impl Egress {
    pub(super) async fn maintain(&self) {
        loop {
            if self.forward.shutdown.is_cancelled() {
                return;
            }
            if let Err(error) = self.registered_connection().await {
                self.forward.logger.debug(format_args!(
                    "Egress connection failed: {}",
                    crate::telemetry::diagnostic_reason(&format!("{error:#}"))
                ));
            }
            self.forward.telemetry.set_egress_online(Some(false));
            tokio::select! {
                _ = self.forward.shutdown.cancelled() => return,
                _ = tokio::time::sleep(crate::common::service_cooldown()) => {},
            }
        }
    }
    pub(super) async fn registered_connection(&self) -> Result<()> {
        self.forward.telemetry.emit_runtime(
            crate::telemetry::Runtime::EgressConnecting,
            None,
            None,
        );
        let (endpoint, connection) = connect_quic(&self.config, &self.tls).await?;
        super::registration::register(
            &connection,
            self.credentials.egress_key,
            &self.forward.telemetry,
        )
        .await?;
        let limits = crate::transport::transport_flow_control()?;
        connection.set_receive_window(limits.connection_receive_window.into());
        connection.set_max_concurrent_bi_streams(1024u32.into());
        let q = QuicConnection::new(
            connection.clone(),
            true,
            self.forward.stats.clone(),
            self.forward.telemetry.clone(),
        );
        let _owner = Registered {
            connection: q.clone(),
            telemetry: self.forward.telemetry.clone(),
        };
        self.forward.telemetry.set_egress_online(Some(true));
        let mut tasks = JoinSet::new();
        let mut sample = tokio::time::interval(self.forward.runtime.telemetry_interval);
        loop {
            tokio::select! {
                _ = self.forward.shutdown.cancelled() => break,
                _ = q.cancel.cancelled() => break,
                _ = q.draining.cancelled() => break,
                _ = sample.tick() => self.forward.telemetry.capture_and_publish(
                    &self.forward.stats, connection.rtt().as_millis().max(1) as u64,
                ),
                stream = connection.accept_bi() => match stream {
                    Ok((send, recv)) => {
                        let raw = u64::from(recv.id());
                        if raw & 3 != 1 {
                            bail!("Portal business Stream direction violation");
                        }
                        if q.flow_id(raw).is_err() {
                            break;
                        }
                        let forward = self.forward.clone();
                        let connection = q.clone();
                        tasks.spawn(async move {
                            forward.serve(
                                Incoming::Quic { send, recv, connection: connection.clone() },
                                connection.connection.remote_address().to_string(),
                                connection.cancel.clone(),
                            ).await;
                        });
                    },
                    Err(_) => break,
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
        if q.draining.is_cancelled() {
            let _ = tokio::time::timeout(crate::common::shutdown_timeout(), async {
                while tasks.join_next().await.is_some() {}
            })
            .await;
        }
        q.close();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let _ = tokio::time::timeout(crate::common::shutdown_timeout(), endpoint.wait_idle()).await;
        Ok(())
    }
}
struct Registered {
    connection: Arc<QuicConnection>,
    telemetry: Arc<TelemetryHub>,
}
impl Drop for Registered {
    fn drop(&mut self) {
        self.connection.close();
        self.telemetry.set_egress_online(Some(false));
    }
}

#[cfg(test)]
#[path = "../tests/egress/connection.rs"]
mod tests;
