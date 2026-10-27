// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Independently supervised TLS and QUIC exit services registered with a Portal.

mod connection;
mod registration;
mod runtime;
mod setup;
mod tls;

use std::sync::Arc;

use crate::portal::forward::Forwarder;
use crate::protocol::Credentials;
use crate::vector::{PortalClientConfig, tls::ClientTls};

pub struct Egress {
    config: PortalClientConfig,
    credentials: Credentials,
    forward: Arc<Forwarder>,
    tls: ClientTls,
    effective: String,
    tls_pool_max: usize,
}
