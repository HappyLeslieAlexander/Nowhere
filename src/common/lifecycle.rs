// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared process lifecycle telemetry and platform shutdown signals.

use anyhow::{Context, Result};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum LifeState {
    #[default]
    Starting = 0,
    Ready = 1,
    Draining = 2,
    Stopped = 3,
}

impl fmt::Display for LifeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Starting => "STARTING",
            Self::Ready => "READY",
            Self::Draining => "DRAINING",
            Self::Stopped => "STOPPED",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum LifeReason {
    #[default]
    Startup,
    Listening,
    #[serde(rename = "SIGINT")]
    SigInt,
    #[cfg(unix)]
    #[serde(rename = "SIGTERM")]
    SigTerm,
    TcpListenerExit,
    QuicListenerExit,
    SocksListenerExit,
    Drained,
    CleanupComplete,
    Timeout,
    Forced,
    StartFailed,
}

impl fmt::Display for LifeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Startup => "STARTUP",
            Self::Listening => "LISTENING",
            Self::SigInt => "SIGINT",
            #[cfg(unix)]
            Self::SigTerm => "SIGTERM",
            Self::TcpListenerExit => "TCP_LISTENER_EXIT",
            Self::QuicListenerExit => "QUIC_LISTENER_EXIT",
            Self::SocksListenerExit => "SOCKS_LISTENER_EXIT",
            Self::Drained => "DRAINED",
            Self::CleanupComplete => "CLEANUP_COMPLETE",
            Self::Timeout => "TIMEOUT",
            Self::Forced => "FORCED",
            Self::StartFailed => "START_FAILED",
        })
    }
}

pub(crate) struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    pub(crate) fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            Ok(Self {
                interrupt: signal(SignalKind::interrupt())
                    .context("common::lifecycle: failed to install SIGINT handler")?,
                terminate: signal(SignalKind::terminate())
                    .context("common::lifecycle: failed to install SIGTERM handler")?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    pub(crate) async fn recv(&mut self) -> Result<LifeReason> {
        #[cfg(unix)]
        {
            tokio::select! {
                value = self.interrupt.recv() => {
                    value.ok_or_else(|| anyhow::anyhow!("common::lifecycle: SIGINT stream closed"))?;
                    Ok(LifeReason::SigInt)
                }
                value = self.terminate.recv() => {
                    value.ok_or_else(|| anyhow::anyhow!("common::lifecycle: SIGTERM stream closed"))?;
                    Ok(LifeReason::SigTerm)
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .context("common::lifecycle: failed to receive Ctrl+C")?;
            Ok(LifeReason::SigInt)
        }
    }
}

#[cfg(test)]
#[path = "../tests/common/lifecycle.rs"]
mod tests;
