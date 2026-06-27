// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Per-session scratch-buffer sizing.

/// Buffer size configuration used to allocate fresh relay scratch buffers.
#[derive(Debug, Clone)]
pub struct Buffers {
    tcp_size: usize,
    udp_size: usize,
}

impl Buffers {
    /// Creates a buffer-size pair for TCP and UDP relay paths.
    pub fn new(tcp_size: usize, udp_size: usize) -> Self {
        Self { tcp_size, udp_size }
    }

    /// Allocates a zeroed TCP relay buffer.
    pub fn get_tcp_buffer(&self) -> Vec<u8> {
        vec![0; self.tcp_size]
    }

    /// Allocates a zeroed UDP relay buffer.
    pub fn get_udp_buffer(&self) -> Vec<u8> {
        vec![0; self.udp_size]
    }
}

#[cfg(test)]
#[path = "../tests/transport/buffers.rs"]
mod tests;
