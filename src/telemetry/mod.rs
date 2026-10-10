// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Structured, process-local telemetry for the read-only TUI.

mod hub;
mod ipc;
mod local;
mod privacy;
mod process;
mod wire;

pub(crate) use hub::{AccessSpan, TelemetryHub};
pub(crate) use ipc::{DiscoveredInstance, TelemetryClient, TelemetryServer, discover_instances};
pub(crate) use privacy::endpoint as display_endpoint;
pub(crate) use process::now_unix_ms;
pub(crate) use wire::{
    AccessOutcome, AccessStart, ClientMessage, Hello, InstanceRole, MAX_FRAME_SIZE, RuntimeEvent,
    RuntimeKind, RuntimeLevel, ServerMessage, Subscription, TELEMETRY_PROTOCOL, TelemetrySnapshot,
    TrafficProtocol,
};
#[cfg(test)]
#[path = "../tests/telemetry/support.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::*;
