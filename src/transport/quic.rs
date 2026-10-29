// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared transport flow-control budgets for QUIC connections.

use std::sync::OnceLock;

use anyhow::{Result, bail};

const MIB: u32 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportFlowControl {
    pub(crate) stream_receive_window: u32,
    pub(crate) connection_receive_window: u32,
    pub(crate) send_window: u64,
}

impl TransportFlowControl {
    const MEMORY: Self = Self::new(4, 8, 8);
    const BALANCED: Self = Self::new(8, 16, 16);
    const THROUGHPUT: Self = Self::new(16, 32, 32);

    const fn new(stream_mib: u32, connection_mib: u32, send_mib: u64) -> Self {
        Self {
            stream_receive_window: stream_mib * MIB,
            connection_receive_window: connection_mib * MIB,
            send_window: send_mib * MIB as u64,
        }
    }
}

static TRANSPORT_PROFILE: OnceLock<TransportFlowControl> = OnceLock::new();

/// The profile parsed once at startup. A bad NOW_TRANSPORT_MEMORY_PROFILE is
/// rejected by [`validate_transport_profile`] during startup, so this can
/// never fail per connection.
pub(crate) fn transport_flow_control() -> TransportFlowControl {
    *TRANSPORT_PROFILE.get_or_init(|| {
        parse_transport_profile(
            std::env::var("NOW_TRANSPORT_MEMORY_PROFILE")
                .ok()
                .as_deref(),
        )
        .unwrap_or(TransportFlowControl::THROUGHPUT)
    })
}

pub(crate) fn validate_transport_profile() -> Result<()> {
    let profile = parse_transport_profile(
        std::env::var("NOW_TRANSPORT_MEMORY_PROFILE")
            .ok()
            .as_deref(),
    )?;
    let _ = TRANSPORT_PROFILE.set(profile);
    Ok(())
}

fn parse_transport_profile(value: Option<&str>) -> Result<TransportFlowControl> {
    match value.unwrap_or("throughput") {
        "memory" => Ok(TransportFlowControl::MEMORY),
        "balanced" => Ok(TransportFlowControl::BALANCED),
        "throughput" => Ok(TransportFlowControl::THROUGHPUT),
        _ => bail!("NOW_TRANSPORT_MEMORY_PROFILE must be memory, balanced, or throughput"),
    }
}

#[cfg(test)]
#[path = "../tests/transport/quic.rs"]
mod tests;
