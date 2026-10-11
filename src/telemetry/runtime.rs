// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Closed runtime observations, rendered once at the publication boundary.

use crate::common::{LifeReason, LifeState};

use super::privacy::DiagnosticReason;
use super::wire::{RuntimeEvent, RuntimeKind, RuntimeLevel};

pub(crate) enum Runtime {
    Lifecycle(LifeState, LifeReason),
    EgressOnline(bool),
    EgressConnecting,
    EgressRegistrationBusy,
    QuicConnected,
    QuicDisconnected,
    TlsConnected,
    TlsDisconnected,
    SocksClientLimit,
    SocksAcceptFailed,
    SocksHandshakeFailed,
    SocksHandshakeTimeout,
}

impl Runtime {
    pub(super) fn into_event(
        self,
        reason: Option<DiagnosticReason>,
        client: Option<String>,
    ) -> RuntimeEvent {
        use RuntimeKind::{Authentication, Carrier, Lifecycle, Listener, Reconnect};
        use RuntimeLevel::{Error, Info, Warn};
        let (level, kind, template) = match self {
            Self::Lifecycle(state, reason) => (Info, Lifecycle, format!("{state}: {reason}")),
            Self::EgressOnline(online) => (
                Info,
                Carrier,
                if online {
                    "Egress online"
                } else {
                    "Egress offline"
                }
                .to_owned(),
            ),
            Self::EgressConnecting => (Info, Reconnect, "Egress connecting".to_owned()),
            Self::EgressRegistrationBusy => {
                (Info, Authentication, "Egress registration busy".to_owned())
            }
            Self::QuicConnected => (Info, Carrier, "QUIC carrier connected".to_owned()),
            Self::QuicDisconnected => (Info, Carrier, "QUIC carrier disconnected".to_owned()),
            Self::TlsConnected => (Info, Carrier, "TLS/TCP carrier connected".to_owned()),
            Self::TlsDisconnected => (Info, Carrier, "TLS/TCP carrier disconnected".to_owned()),
            Self::SocksClientLimit => (
                Warn,
                Listener,
                "SOCKS client resource limit reached".to_owned(),
            ),
            Self::SocksAcceptFailed => (Error, Listener, "SOCKS accept failed".to_owned()),
            Self::SocksHandshakeFailed => {
                (Warn, Authentication, "SOCKS5 handshake failed".to_owned())
            }
            Self::SocksHandshakeTimeout => (
                Warn,
                Authentication,
                "SOCKS5 handshake timed out".to_owned(),
            ),
        };
        RuntimeEvent {
            sequence: 0,
            timestamp_ms: super::process::now_unix_ms(),
            level,
            kind,
            message: match reason {
                Some(reason) => format!("{template}: {}", reason.as_str()),
                None => template,
            },
            client,
        }
    }
}
