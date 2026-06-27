// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared relay session accounting and relay dispatch exports.

#[path = "relay_stream.rs"]
mod stream;
#[path = "relay_tcp.rs"]
mod tcp;
#[path = "relay_uot.rs"]
mod uot;

use std::sync::Arc;

use crate::portal::PortalInner;

pub(super) use self::tcp::relay_tcp_target;
pub(super) use self::uot::relay_udp_over_tcp_target;

/// RAII guard that keeps active TCP/UDP session counters balanced.
struct SessionGuard {
    portal: Arc<PortalInner>,
    is_udp: bool,
}

impl SessionGuard {
    fn new(portal: Arc<PortalInner>, is_udp: bool) -> Self {
        Self { portal, is_udp }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.portal.stats.done_session(self.is_udp);
    }
}
