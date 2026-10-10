// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP flow setup, carrier ownership, and bidirectional relay.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context as TaskContext, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::common::{
    REPLY_CONNECTION_NOT_ALLOWED, REPLY_GENERAL_FAILURE, REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE, REPLY_SUCCEEDED, SocksAddress, tcp_read_timeout,
};
use crate::protocol::{Carrier, SetupResult, Target};
use crate::telemetry::{AccessOutcome, AccessSpan};
use crate::transport::TrafficDirection;

use super::config::CarrierMode;
use super::{PortalClient, VectorInner};
mod tcp;
pub(crate) use self::tcp::{TcpTunnel, TcpTunnelGuard};
pub(super) use self::tcp::{open_tcp, relay_tcp};
pub(crate) type BoxReader = Pin<Box<dyn crate::transport::AsyncReadAny>>;
pub(crate) type BoxWriter = Pin<Box<dyn crate::transport::AsyncWriteAny>>;

pub(super) fn to_target(address: &SocksAddress) -> Result<Target> {
    match address {
        SocksAddress::Ip(address) => Target::ip(*address),
        SocksAddress::Domain(host, port) => Target::domain(host.clone(), *port),
    }
}

pub(super) fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::TlsTcp => "TLS",
        Carrier::Quic => "QUIC",
    }
}

pub(super) const fn configured_carrier(mode: CarrierMode) -> Carrier {
    match mode {
        CarrierMode::Tcp => Carrier::TlsTcp,
        CarrierMode::Udp => Carrier::Quic,
    }
}

#[derive(Debug)]
pub(crate) enum OpenFlowError {
    Setup(SetupResult),
    Transport(anyhow::Error),
    Protocol(anyhow::Error),
}

impl OpenFlowError {
    pub(super) fn socks_reply(&self) -> u8 {
        match self {
            Self::Setup(SetupResult::InvalidRequest | SetupResult::FlowLimit) => {
                REPLY_CONNECTION_NOT_ALLOWED
            }
            Self::Setup(SetupResult::DialFailed) => REPLY_HOST_UNREACHABLE,
            Self::Setup(_) => REPLY_GENERAL_FAILURE,
            Self::Transport(_) => REPLY_NETWORK_UNREACHABLE,
            Self::Protocol(_) => REPLY_GENERAL_FAILURE,
        }
    }

    pub(super) fn access_outcome(&self) -> AccessOutcome {
        match self {
            Self::Setup(SetupResult::InvalidRequest | SetupResult::FlowLimit) => {
                AccessOutcome::Rejected
            }
            Self::Setup(_) | Self::Transport(_) | Self::Protocol(_) => {
                AccessOutcome::from_error(&self.to_string())
            }
        }
    }

    pub(crate) fn setup_result(&self) -> Option<SetupResult> {
        match self {
            Self::Setup(result) => Some(*result),
            Self::Transport(_) | Self::Protocol(_) => None,
        }
    }
}

impl std::fmt::Display for OpenFlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(result) => write!(formatter, "flow setup rejected: {}", result.as_str()),
            Self::Transport(error) | Self::Protocol(error) => {
                if formatter.alternate() {
                    write!(formatter, "{error:#}")
                } else {
                    error.fmt(formatter)
                }
            }
        }
    }
}

pub(crate) struct FlowGuard {
    stats: Arc<crate::transport::Stats>,
    udp: bool,
}

impl FlowGuard {
    pub(crate) fn new(stats: Arc<crate::transport::Stats>, udp: bool) -> Self {
        Self { stats, udp }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.stats.done_flow(self.udp);
    }
}

impl std::error::Error for OpenFlowError {}
