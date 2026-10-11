// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Local telemetry listener lifecycle and client subscription handling.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncReadExt;
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use super::MAX_CLIENTS;
use super::frame::write_frame;
use super::registry::{DiscoveredInstance, RegistryEntry, registry_path};
use crate::telemetry::local::{self, Listener, Stream};
use crate::telemetry::{Hello, ServerMessage, TELEMETRY_PROTOCOL, TelemetryHub};

pub(crate) struct TelemetryServer {
    listener: Listener,
    pub(super) endpoint: String,
    pub(super) hub: Arc<TelemetryHub>,
    clients: Arc<Semaphore>,
    pub(super) registry_path: PathBuf,
}

impl TelemetryServer {
    pub(crate) fn bind(hub: Arc<TelemetryHub>) -> Result<Self> {
        if let Some(reason) = hub.unavailable_reason() {
            bail!("telemetry process identity is unavailable: {reason}");
        }
        let descriptor = hub.descriptor();
        let name = descriptor.registry_name();
        local::prepare_directory()?;
        let endpoint = local::endpoint(&descriptor.id);
        let listener = Listener::bind(&endpoint)?;
        let entry = RegistryEntry {
            instance: DiscoveredInstance {
                registry_name: name,
                uid: descriptor.uid,
                pid: descriptor.pid,
                incarnation: descriptor.incarnation,
            },
            endpoint: endpoint.clone(),
            transport: local::TRANSPORT.to_owned(),
            namespace: local::namespace(),
            protocol: TELEMETRY_PROTOCOL.to_owned(),
        };
        let registry_path = registry_path(&entry.instance.registry_name);
        let payload = match serde_json::to_vec(&entry) {
            Ok(value) => value,
            Err(error) => {
                local::cleanup(&endpoint);
                return Err(error.into());
            }
        };
        if let Err(error) = local::publish(&registry_path, &payload) {
            local::cleanup(&endpoint);
            return Err(error);
        }
        Ok(Self {
            listener,
            endpoint,
            hub,
            clients: Arc::new(Semaphore::new(MAX_CLIENTS)),
            registry_path,
        })
    }

    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
                _ = shutdown.cancelled() => break,
                accepted = self.listener.accept() => accepted,
            };
            let Ok(stream) = accepted else {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
                continue;
            };
            let Ok(permit) = Arc::clone(&self.clients).try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let hub = Arc::clone(&self.hub);
            let connection_shutdown = shutdown.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let _ = serve_client(stream, hub, connection_shutdown).await;
            });
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

async fn serve_client(
    stream: Stream,
    hub: Arc<TelemetryHub>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut events = hub.event_receiver();
    let mut snapshots = hub.snapshot_receiver();
    let mut extra = [0u8; 1];
    write_frame(
        &mut writer,
        &ServerMessage::Hello(Hello {
            instance: hub.descriptor().clone(),
        }),
    )
    .await?;
    let initial_snapshot = snapshots.borrow_and_update().clone();
    write_frame(&mut writer, &ServerMessage::Snapshot(initial_snapshot)).await?;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),

            _ = reader.read(&mut extra) => return Ok(()),
            changed = snapshots.changed() => {
                changed.context("telemetry snapshot source closed")?;
                let snapshot = snapshots.borrow_and_update().clone();
                write_frame(
                    &mut writer,
                    &ServerMessage::Snapshot(snapshot),
                ).await?;
            }
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        write_frame(&mut writer, &ServerMessage::from(event)).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        write_frame(
                            &mut writer,
                            &ServerMessage::Gap { missed },
                        ).await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

impl Drop for TelemetryServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.registry_path);
        local::cleanup(&self.endpoint);
    }
}

#[cfg(test)]
#[path = "../../tests/telemetry/ipc/server.rs"]
mod tests;
