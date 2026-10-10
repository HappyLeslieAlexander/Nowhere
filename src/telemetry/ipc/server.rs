// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Local telemetry listener lifecycle and client subscription handling.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use super::MAX_CLIENTS;
use super::frame::{FrameReader, write_frame};
use super::registry::{DiscoveredInstance, RegistryEntry, registry_path};
use crate::telemetry::local::{self, Listener, Stream};
use crate::telemetry::{
    ClientMessage, Hello, ServerMessage, Subscription, TELEMETRY_PROTOCOL, TelemetryHub,
};

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
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = FrameReader::new(reader);
    let mut lifecycles = hub.lifecycle_receiver();
    let initial_lifecycle = lifecycles.borrow_and_update().clone();
    write_frame(
        &mut writer,
        &ServerMessage::Hello(Hello {
            instance: hub.descriptor().clone(),
            lifecycle: initial_lifecycle.state,
            lifecycle_reason: initial_lifecycle.reason,
        }),
    )
    .await?;

    let mut snapshots = hub.snapshot_receiver();
    let mut events;
    let command = tokio::select! {
        _ = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(5), reader.next_command()) => result??,
    };
    let ClientMessage::Subscribe {
        request_id,
        mut subscription,
    } = command;
    events = hub.event_receiver();
    let mut _detail = (subscription == Subscription::Detail).then(|| hub.detail_guard());
    write_frame(
        &mut writer,
        &ServerMessage::Subscribed {
            request_id,
            subscription,
        },
    )
    .await?;
    let initial_snapshot = snapshots.borrow_and_update().clone();
    write_frame(&mut writer, &ServerMessage::Snapshot(initial_snapshot)).await?;
    let initial_lifecycle = lifecycles.borrow_and_update().clone();
    write_frame(&mut writer, &ServerMessage::Lifecycle(initial_lifecycle)).await?;
    let mut tokens = 7.0f64;
    let mut command_at = std::time::Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            command = reader.next_command() => {
                match command? {
                    ClientMessage::Subscribe { request_id, subscription: next } => {
                        let now = std::time::Instant::now();
                        tokens = (tokens + now.duration_since(command_at).as_secs_f64() * 4.0).min(8.0);
                        command_at = now;
                        if tokens < 1.0 { bail!("command rate exceeded"); }
                        tokens -= 1.0;
                        if next != subscription {
                            events = hub.event_receiver();
                            _detail = (next == Subscription::Detail).then(|| hub.detail_guard());
                        }
                        subscription = next;
                        write_frame(&mut writer, &ServerMessage::Subscribed { request_id, subscription }).await?;
                    }
                }
            }
            changed = snapshots.changed() => {
                changed.context("telemetry snapshot source closed")?;
                let snapshot = snapshots.borrow_and_update().clone();
                write_frame(
                    &mut writer,
                    &ServerMessage::Snapshot(snapshot),
                ).await?;
            }
            changed = lifecycles.changed() => {
                changed.context("telemetry lifecycle source closed")?;
                let lifecycle = lifecycles.borrow_and_update().clone();
                write_frame(
                    &mut writer,
                    &ServerMessage::Lifecycle(lifecycle),
                ).await?;
            }
            event = events.recv(), if subscription == Subscription::Detail => {
                match event {
                    Ok(event) => {
                        write_frame(&mut writer, &event).await?;
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
