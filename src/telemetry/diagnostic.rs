// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed result codes and classification of typed error chains.

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResultCode {
    Success,
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
    Unknown,
}

impl ResultCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
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
            Self::Unknown => "operation failed",
        }
    }
}

impl std::fmt::Display for ResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for ResultCode {}

pub(crate) fn error_reason(error: &anyhow::Error) -> ResultCode {
    error
        .chain()
        .find_map(typed_reason)
        .unwrap_or(ResultCode::Unknown)
}

fn typed_reason(cause: &(dyn std::error::Error + 'static)) -> Option<ResultCode> {
    if let Some(code) = cause.downcast_ref::<ResultCode>() {
        return Some(*code);
    }
    if let Some(error) = cause.downcast_ref::<crate::vector::OpenFlowError>() {
        return Some(error.diagnostic_reason());
    }
    if cause.is::<tokio::time::error::Elapsed>() {
        return Some(ResultCode::Timeout);
    }
    if let Some(error) = cause.downcast_ref::<rustls::Error>() {
        return Some(tls_reason(error));
    }
    if let Some(error) = cause.downcast_ref::<quinn::ConnectionError>() {
        return Some(match error {
            quinn::ConnectionError::TimedOut => ResultCode::Timeout,
            quinn::ConnectionError::LocallyClosed => ResultCode::Cancelled,
            quinn::ConnectionError::ApplicationClosed(_) => ResultCode::ApplicationClosed,
            quinn::ConnectionError::Reset => ResultCode::ConnectionReset,
            quinn::ConnectionError::CidsExhausted => ResultCode::ResourceLimit,
            _ => ResultCode::Protocol,
        });
    }
    if let Some(error) = cause.downcast_ref::<quinn::ReadError>() {
        return match error {
            quinn::ReadError::ConnectionLost(error) => typed_reason(error),
            quinn::ReadError::Reset(_) => Some(ResultCode::ConnectionReset),
            quinn::ReadError::ClosedStream => Some(ResultCode::ConnectionClosed),
            _ => Some(ResultCode::Protocol),
        };
    }
    if let Some(error) = cause.downcast_ref::<quinn::WriteError>() {
        return match error {
            quinn::WriteError::ConnectionLost(error) => typed_reason(error),
            quinn::WriteError::Stopped(_) => Some(ResultCode::ConnectionReset),
            quinn::WriteError::ClosedStream => Some(ResultCode::ConnectionClosed),
            _ => Some(ResultCode::Protocol),
        };
    }
    if let Some(error) = cause.downcast_ref::<std::io::Error>() {
        if let Some(reason) = error.get_ref().and_then(|inner| typed_reason(inner)) {
            return Some(reason);
        }
        use std::io::ErrorKind;
        return match error.kind() {
            ErrorKind::ConnectionRefused => Some(ResultCode::ConnectionRefused),
            ErrorKind::ConnectionReset => Some(ResultCode::ConnectionReset),
            ErrorKind::ConnectionAborted | ErrorKind::NotConnected => {
                Some(ResultCode::ConnectionClosed)
            }
            ErrorKind::TimedOut => Some(ResultCode::Timeout),
            ErrorKind::PermissionDenied => Some(ResultCode::PermissionDenied),
            ErrorKind::BrokenPipe => Some(ResultCode::BrokenPipe),
            ErrorKind::UnexpectedEof => Some(ResultCode::UnexpectedEof),
            ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => {
                Some(ResultCode::NetworkUnreachable)
            }
            _ => None,
        };
    }
    None
}

fn tls_reason(error: &rustls::Error) -> ResultCode {
    match error {
        rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. },
        ) => ResultCode::CertificateExpired,
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer) => {
            ResultCode::UnknownIssuer
        }
        rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
            ResultCode::CertificateVerification
        }
        _ => ResultCode::Handshake,
    }
}

#[cfg(test)]
#[path = "../tests/telemetry/diagnostic.rs"]
mod tests;
