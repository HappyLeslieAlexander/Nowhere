// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Command utilities for credentials, certificate inspection, probes and status.

mod diagnostic;
mod fingerprint;
mod format;
mod probe;
mod status;

use std::fmt::Write;

use anyhow::{Context, Result};

pub use fingerprint::fingerprint;
pub use probe::probe;
pub use status::status;

pub fn generate_key() -> Result<String> {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).context("failed to generate a random key")?;
    let mut hex = String::with_capacity(key.len() * 2);
    for byte in key {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

#[cfg(test)]
#[path = "../tests/toolbox/mod.rs"]
mod tests;
