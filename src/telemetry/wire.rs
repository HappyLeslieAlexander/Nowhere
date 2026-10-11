// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Messages exchanged between a Nowhere service and local IPC subscribers.

use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::diagnostic::ResultCode;
use crate::common::{LifeReason, LifeState};
use crate::protocol::Carrier;

use super::process::{process_incarnation, process_uid};

pub(crate) const TELEMETRY_PROTOCOL: &str = "nowhere.telemetry.3";
pub(crate) const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstanceRole {
    Portal,
    Vector,
    Egress,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstanceDescriptor {
    pub(crate) telemetry_protocol: String,
    pub(crate) id: String,
    pub(crate) role: InstanceRole,
    pub(crate) pid: u32,
    #[serde(skip)]
    pub(crate) uid: u32,
    #[serde(skip)]
    pub(crate) incarnation: u64,
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) endpoint: String,
    pub(crate) telemetry_interval_ms: u64,
}

impl InstanceDescriptor {
    pub(crate) fn current(
        role: InstanceRole,
        endpoint: impl Into<String>,
        telemetry_interval: Duration,
    ) -> Result<Self> {
        let pid = std::process::id();
        let uid = process_uid();
        let incarnation = process_incarnation(pid)?;
        Ok(Self {
            telemetry_protocol: TELEMETRY_PROTOCOL.to_owned(),
            id: super::privacy::random_id()?,
            role,
            pid,
            uid,
            incarnation,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint: super::privacy::endpoint(&endpoint.into()),
            telemetry_interval_ms: telemetry_interval.as_millis().min(u64::MAX as u128) as u64,
        })
    }

    pub(crate) fn registry_name(&self) -> String {
        format!("nowhere.{}", self.id)
    }

    pub(super) fn unavailable(
        role: InstanceRole,
        endpoint: String,
        telemetry_interval: Duration,
    ) -> Self {
        let pid = std::process::id();
        let uid = process_uid();
        Self {
            telemetry_protocol: TELEMETRY_PROTOCOL.to_owned(),
            id: format!("{uid}:{pid}:unavailable"),
            role,
            pid,
            uid,
            incarnation: 0,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint: super::privacy::endpoint(&endpoint),
            telemetry_interval_ms: telemetry_interval.as_millis().min(u64::MAX as u128) as u64,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetrySnapshot {
    pub(crate) sequence: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) uptime_ms: u64,
    pub(crate) lifecycle: LifeState,
    pub(crate) lifecycle_reason: LifeReason,
    pub(crate) lifecycle_timestamp_ms: u64,
    pub(crate) egress_online: Option<bool>,
    pub(crate) tcp_upload_bytes: u64,
    pub(crate) tcp_download_bytes: u64,
    pub(crate) udp_upload_bytes: u64,
    pub(crate) udp_download_bytes: u64,
    pub(crate) tls_upload_bytes: u64,
    pub(crate) tls_download_bytes: u64,
    pub(crate) quic_upload_bytes: u64,
    pub(crate) quic_download_bytes: u64,
    pub(crate) tcp_active: i64,
    pub(crate) udp_active: i64,
    pub(crate) tls_carriers_active: u64,
    pub(crate) quic_carriers_active: u64,
    pub(crate) ping_ms: Option<u64>,
    pub(crate) cpu_percent: Option<f64>,
    pub(crate) rss_bytes: Option<u64>,
    pub(crate) open_fds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrafficProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub(crate) struct AccessStart {
    pub(crate) protocol: TrafficProtocol,
    pub(crate) target: String,
    pub(crate) carrier: Carrier,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessStarted {
    pub(crate) sequence: u64,
    pub(crate) id: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) protocol: TrafficProtocol,
    pub(crate) target: String,
    pub(crate) carrier: Carrier,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessFinished {
    pub(crate) sequence: u64,
    pub(crate) id: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) result: ResultCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiagnosticContext {
    EgressRegistration,
    EgressConnection,
    SocksAccept,
    SocksHandshake,
    SocksAdmission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Diagnostic {
    pub(crate) sequence: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) context: DiagnosticContext,
    pub(crate) reason: ResultCode,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub(crate) enum ServerMessage {
    Hello(Hello),
    Snapshot(TelemetrySnapshot),
    Diagnostic(Diagnostic),
    AccessStart(AccessStarted),
    AccessFinish(AccessFinished),
    Gap { missed: u64 },
}

#[derive(Clone, Debug)]
pub(crate) enum Event {
    Diagnostic(Diagnostic),
    AccessStart(AccessStarted),
    AccessFinish(AccessFinished),
}

impl Event {
    pub(super) fn set_sequence(&mut self, sequence: u64) {
        match self {
            Self::Diagnostic(event) => event.sequence = sequence,
            Self::AccessStart(event) => event.sequence = sequence,
            Self::AccessFinish(event) => event.sequence = sequence,
        }
    }
}

impl From<Event> for ServerMessage {
    fn from(event: Event) -> Self {
        match event {
            Event::Diagnostic(event) => Self::Diagnostic(event),
            Event::AccessStart(event) => Self::AccessStart(event),
            Event::AccessFinish(event) => Self::AccessFinish(event),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hello {
    pub(crate) instance: InstanceDescriptor,
}

#[cfg(test)]
#[path = "../tests/telemetry/wire.rs"]
mod tests;
