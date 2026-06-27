// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared target-address validation helpers for protocol frames.

use anyhow::{Result, bail};

/// Maximum target address length accepted by proxy frames.
pub const TARGET_LEN_MAX: usize = 512;

/// Validates host:port target syntax without resolving the host.
pub fn validate_target(target_addr: &str) -> Result<()> {
    let port = split_host_port(target_addr).map_err(|e| {
        anyhow::anyhow!("protocol::util::validate_target: invalid target address: {e}")
    })?;
    if port.is_empty() {
        bail!("protocol::util::validate_target: invalid target address: empty port");
    }
    Ok(())
}

fn split_host_port(target_addr: &str) -> Result<&str> {
    if let Some(rest) = target_addr.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            bail!("missing ']' in address");
        };
        let after = &rest[end + 1..];
        let Some(port) = after.strip_prefix(':') else {
            bail!("missing port in address");
        };
        return Ok(port);
    }

    let mut parts = target_addr.rsplitn(2, ':');
    let port = parts.next().unwrap_or_default();
    let host = parts.next();
    if host.is_none() || host.unwrap().contains(':') {
        bail!("too many colons in address");
    }
    Ok(port)
}

/// Checks the shared target-address length bound with a caller-specific context.
pub fn check_target_len(context: &str, target_addr: &str) -> Result<()> {
    if target_addr.is_empty() || target_addr.len() > TARGET_LEN_MAX {
        bail!("{context}: invalid target length: {}", target_addr.len());
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/protocol/util.rs"]
mod tests;
