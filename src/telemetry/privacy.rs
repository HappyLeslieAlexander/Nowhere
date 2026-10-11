// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Instance-local, category-separated pseudonyms. Keys never leave memory.

use anyhow::Result;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::protocol::Target;

const ALIAS_CAPACITY: usize = 4_096;

pub(crate) fn endpoint(value: &str) -> String {
    let address = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_owned()
    };
    if value.len() <= 512
        && !value.contains(['@', '?', '#', '%', '\\'])
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        && crate::common::validate_endpoint_url_input(&format!("portal://{address}"), "telemetry")
            .is_ok()
        && url::Url::parse(&format!("portal://{address}"))
            .ok()
            .and_then(|url| crate::common::ServiceEndpoint::parse(&url, true, "telemetry").ok())
            .is_some()
    {
        value.to_owned()
    } else {
        "<redacted>".to_owned()
    }
}

pub(crate) fn config_summary(value: &str) -> String {
    value
        .split_whitespace()
        .take(64)
        .filter_map(|token| {
            let (key, value) = token.split_once('=')?;
            let option = key;
            let safe = match option {
                "listen" | "portal" | "in" => {
                    if value == "none" {
                        value.to_owned()
                    } else {
                        endpoint(value)
                    }
                }
                "out" if matches!(value, "direct" | "egress") => value.to_owned(),
                "out" => endpoint(value),
                "net" if matches!(value, "tcp" | "udp") => value.to_owned(),
                "tls" if matches!(value, "1" | "2") => value.to_owned(),
                "morph" if matches!(value, "0" | "1") => value.to_owned(),
                "log" if matches!(value, "none" | "debug" | "info" | "warn" | "error") => {
                    value.to_owned()
                }
                "rate" | "etar" => value.parse::<i32>().ok()?.to_string(),
                "dial" if value == "auto" || value.parse::<std::net::IpAddr>().is_ok() => {
                    value.to_owned()
                }
                "dial4" if value == "auto" || value.parse::<std::net::Ipv4Addr>().is_ok() => {
                    value.to_owned()
                }
                "dial6"
                    if value == "auto"
                        || value
                            .parse::<std::net::Ipv6Addr>()
                            .is_ok_and(|ip| ip.to_ipv4_mapped().is_none()) =>
                {
                    value.to_owned()
                }
                "sni"
                    if value.len() <= 253
                        && value
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')) =>
                {
                    value.to_owned()
                }
                "pin" => if value == "none" { "none" } else { "present" }.to_owned(),
                _ => return None,
            };
            Some(format!("{key}={safe}"))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Default)]
struct Aliases {
    next: u64,
    values: HashMap<[u8; 32], u64>,
    order: VecDeque<[u8; 32]>,
}

pub(super) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow::anyhow!("telemetry entropy unavailable: {e}"))?;
    Ok(hex(&bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) struct Privacy {
    key: [u8; 32],
    clients: Mutex<Aliases>,
    peers: Mutex<Aliases>,
}
impl Privacy {
    pub(super) fn new() -> Result<Self> {
        let mut key = [0; 32];
        getrandom::fill(&mut key)
            .map_err(|e| anyhow::anyhow!("telemetry entropy unavailable: {e}"))?;
        Ok(Self {
            key,
            clients: Mutex::new(Aliases::default()),
            peers: Mutex::new(Aliases::default()),
        })
    }
    pub(super) fn alias(&self, category: &str, value: &str) -> String {
        let identity = if category == "client" {
            value
                .parse::<SocketAddr>()
                .map(|v| v.ip().to_string())
                .unwrap_or_else(|_| value.to_owned())
        } else {
            value.to_owned()
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("fixed key");
        mac.update(category.as_bytes());
        mac.update(&[0]);
        mac.update(identity.as_bytes());
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        let (prefix, aliases) = if category == "client" {
            ("C", &self.clients)
        } else {
            ("P", &self.peers)
        };
        let mut aliases = aliases.lock().unwrap_or_else(|e| e.into_inner());
        let id = if let Some(id) = aliases.values.get(&digest) {
            *id
        } else {
            if aliases.values.len() == ALIAS_CAPACITY {
                let oldest = aliases.order.pop_front().expect("full alias cache");
                aliases.values.remove(&oldest);
            }
            aliases.next += 1;
            let id = aliases.next;
            aliases.values.insert(digest, id);
            aliases.order.push_back(digest);
            id
        };
        format!("{prefix}{id:03}")
    }
}
impl Drop for Privacy {
    fn drop(&mut self) {
        for byte in &mut self.key {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

pub(super) fn target(value: &str) -> String {
    value
        .parse::<Target>()
        .map(|target| target.to_string())
        .unwrap_or_else(|_| "<redacted>".to_owned())
}

/// Only classified, fixed diagnostics may leave the process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiagnosticReason {
    CertificateExpired,
    ApplicationClosed,
    IdleTimeout,
    ServiceDraining,
    TargetConnectionFailed,
    ResourceLimit,
    InvalidRequest,
    InternalError,
    SetupRejected,
    DatagramUnavailable,
    UnknownIssuer,
    CertificateVerification,
    ConnectionRefused,
    Dns,
    Timeout,
    NetworkUnreachable,
    ConnectionReset,
    BrokenPipe,
    UnexpectedEof,
    ConnectionClosed,
    Authentication,
    PermissionDenied,
    Handshake,
    Protocol,
    Cancelled,
    OperationFailed,
}

impl DiagnosticReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CertificateExpired => "certificate expired",
            Self::ApplicationClosed => "application closed",
            Self::IdleTimeout => "idle timeout",
            Self::ServiceDraining => "service draining",
            Self::TargetConnectionFailed => "target connection failed",
            Self::ResourceLimit => "resource limit reached",
            Self::InvalidRequest => "invalid request",
            Self::InternalError => "internal error",
            Self::SetupRejected => "flow setup rejected",
            Self::DatagramUnavailable => "datagram route unavailable",
            Self::UnknownIssuer => "unknown certificate issuer",
            Self::CertificateVerification => "certificate verification failed",
            Self::ConnectionRefused => "connection refused",
            Self::Dns => "DNS lookup failed",
            Self::Timeout => "connection timed out",
            Self::NetworkUnreachable => "network unreachable",
            Self::ConnectionReset => "connection reset by peer",
            Self::BrokenPipe => "broken pipe",
            Self::UnexpectedEof => "unexpected EOF",
            Self::ConnectionClosed => "connection closed",
            Self::Authentication => "authentication failed",
            Self::PermissionDenied => "permission denied",
            Self::Handshake => "handshake failed",
            Self::Protocol => "protocol error",
            Self::Cancelled => "operation cancelled",
            Self::OperationFailed => "operation failed",
        }
    }
}

pub(crate) fn error_reason(value: &str) -> DiagnosticReason {
    let lower = value
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_lowercase();
    if lower.contains("cert") && lower.contains("expired") {
        return DiagnosticReason::CertificateExpired;
    }
    match lower
        .strip_prefix("flow setup rejected: ")
        .unwrap_or(&lower)
    {
        "application closed" => return DiagnosticReason::ApplicationClosed,
        "idle timeout" => return DiagnosticReason::IdleTimeout,
        "portal draining" | "service draining" => return DiagnosticReason::ServiceDraining,
        "dial failed" | "target connection failed" => {
            return DiagnosticReason::TargetConnectionFailed;
        }
        "flow limit" => return DiagnosticReason::ResourceLimit,
        "invalid request" => return DiagnosticReason::InvalidRequest,
        "internal error" => return DiagnosticReason::InternalError,
        "flow setup rejected" => return DiagnosticReason::SetupRejected,
        "quic datagram route preparation failed" | "datagram route unavailable" => {
            return DiagnosticReason::DatagramUnavailable;
        }
        _ => {}
    }
    for (patterns, reason) in [
        (
            &[
                "certificate expired",
                "certexpired",
                "certificate has expired",
                "expired certificate",
            ][..],
            DiagnosticReason::CertificateExpired,
        ),
        (
            &[
                "unknown issuer",
                "unknownissuer",
                "unknown ca",
                "unknown certificate issuer",
            ][..],
            DiagnosticReason::UnknownIssuer,
        ),
        (
            &["certificate", "invalid peer", "pin mismatch"][..],
            DiagnosticReason::CertificateVerification,
        ),
        (
            &[
                "connection refused",
                "os error 111",
                "os error 61",
                "os error 10061",
            ][..],
            DiagnosticReason::ConnectionRefused,
        ),
        (
            &[
                "dns",
                "failed to lookup",
                "name or service not known",
                "no records",
                "resolve",
            ][..],
            DiagnosticReason::Dns,
        ),
        (&["timed out", "timeout"][..], DiagnosticReason::Timeout),
        (
            &[
                "network unreachable",
                "network is unreachable",
                "no route to host",
            ][..],
            DiagnosticReason::NetworkUnreachable,
        ),
        (
            &["connection reset", "reset by peer"][..],
            DiagnosticReason::ConnectionReset,
        ),
        (&["broken pipe"][..], DiagnosticReason::BrokenPipe),
        (
            &["unexpected eof", "early eof"][..],
            DiagnosticReason::UnexpectedEof,
        ),
        (
            &[
                "connection closed",
                "closed by peer",
                "application closed",
                "connection aborted",
            ][..],
            DiagnosticReason::ConnectionClosed,
        ),
        (
            &["authentication", "unauthorized", "invalid key"][..],
            DiagnosticReason::Authentication,
        ),
        (
            &["resource limit", "too many", "limit exceeded"][..],
            DiagnosticReason::ResourceLimit,
        ),
        (
            &["permission denied"][..],
            DiagnosticReason::PermissionDenied,
        ),
        (&["handshake"][..], DiagnosticReason::Handshake),
        (
            &["protocol", "invalid frame", "malformed"][..],
            DiagnosticReason::Protocol,
        ),
        (&["cancelled", "canceled"][..], DiagnosticReason::Cancelled),
    ] {
        if patterns.iter().any(|pattern| lower.contains(pattern)) {
            return reason;
        }
    }
    DiagnosticReason::OperationFailed
}

#[cfg(test)]
#[path = "../tests/telemetry/privacy.rs"]
mod tests;
