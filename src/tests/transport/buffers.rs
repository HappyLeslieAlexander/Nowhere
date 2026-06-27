// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport buffer tests.

use super::*;

#[test]
fn allocates_zeroed_buffers_with_configured_sizes() {
    let buffers = Buffers::new(4, 6);

    assert_eq!(buffers.get_tcp_buffer(), vec![0; 4]);
    assert_eq!(buffers.get_udp_buffer(), vec![0; 6]);
}
