// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Test-only local address inspection for outbound TCP source-binding assertions.

use super::*;
impl OutboundTcpStream {
    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }
}
