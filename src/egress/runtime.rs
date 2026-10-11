// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress service startup, independent telemetry, and graceful shutdown.

use super::Egress;
use crate::common::{LifeReason, LifeState, ShutdownSignals};
use crate::telemetry::TelemetryServer;
use anyhow::Result;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

impl Egress {
    pub async fn run(self) -> Result<()> {
        let mut signals = ShutdownSignals::new()?;
        self.forward
            .telemetry
            .set_lifecycle(LifeState::Starting, LifeReason::Startup);
        self.forward
            .logger
            .info(format_args!("Egress starting: {}", self.effective));
        let observation_stop = CancellationToken::new();
        let mut observation = JoinSet::new();
        match TelemetryServer::bind(self.forward.telemetry.clone()) {
            Ok(server) => {
                observation.spawn(server.run(observation_stop.clone()));
            }
            Err(_) => self.forward.logger.warn(format_args!(
                "Egress: LOCAL_IPC_UNAVAILABLE; continuing without local IPC"
            )),
        }
        let forward = self.forward.clone();
        let stop = observation_stop.clone();
        observation.spawn(async move {
            let mut ticks = tokio::time::interval(forward.runtime.telemetry_interval);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = ticks.tick() => {
                        if forward.telemetry.snapshot_receiver().borrow().egress_online != Some(true) {
                            forward.telemetry.capture_and_publish(&forward.stats, 0);
                        }
                    }
                }
            }
        });
        self.forward
            .telemetry
            .set_lifecycle(LifeState::Ready, LifeReason::Listening);
        let mut maintenance = Box::pin(self.maintain());
        let (reason, finished) = tokio::select! {
            reason = signals.recv() => (reason?, false),
            _ = &mut maintenance => (LifeReason::QuicListenerExit, true),
        };
        self.forward
            .telemetry
            .set_lifecycle(LifeState::Draining, reason);
        self.forward.shutdown.cancel();
        if !finished {
            let _ =
                tokio::time::timeout(self.forward.runtime.shutdown_timeout, &mut maintenance).await;
        }
        drop(maintenance);
        self.forward.telemetry.set_egress_online(Some(false));
        self.forward
            .telemetry
            .set_lifecycle(LifeState::Stopped, LifeReason::CleanupComplete);
        self.forward
            .telemetry
            .capture_and_publish(&self.forward.stats, 0);
        observation_stop.cancel();
        while observation.join_next().await.is_some() {}
        self.forward.logger.flush();
        Ok(())
    }
}
