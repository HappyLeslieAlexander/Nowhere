// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Structured, process-local telemetry for protected IPC subscribers.

mod diagnostic;
mod hub;
mod ipc;
mod local;
mod privacy;
mod process;
mod wire;

pub(crate) use diagnostic::{ResultCode, error_reason};
pub(crate) use hub::{AccessSpan, TelemetryHub};
pub(crate) use ipc::{DiscoveredInstance, TelemetryClient, TelemetryServer, discover_instances};
pub(crate) use privacy::endpoint as display_endpoint;

pub(crate) fn diagnostic_reason(value: &anyhow::Error) -> &'static str {
    error_reason(value).as_str()
}
pub(crate) use wire::{
    AccessStart, DiagnosticContext, Hello, InstanceRole, MAX_FRAME_SIZE, ServerMessage,
    TELEMETRY_PROTOCOL, TelemetrySnapshot, TrafficProtocol,
};
#[cfg(test)]
#[path = "../tests/telemetry/support.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::*;

#[cfg(test)]
pub(crate) use wire::Event;
