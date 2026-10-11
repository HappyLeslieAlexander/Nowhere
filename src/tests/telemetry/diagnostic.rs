// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Typed error classification and safe unknown fallback regressions.

use super::*;
#[test]
fn typed_errors_are_classified_through_context_and_wrappers() {
    use std::io::{Error, ErrorKind};
    for (kind, expected) in [
        (ErrorKind::ConnectionRefused, ResultCode::ConnectionRefused),
        (ErrorKind::TimedOut, ResultCode::Timeout),
        (ErrorKind::PermissionDenied, ResultCode::PermissionDenied),
        (ErrorKind::BrokenPipe, ResultCode::BrokenPipe),
        (ErrorKind::UnexpectedEof, ResultCode::UnexpectedEof),
    ] {
        let error = anyhow::Error::new(Error::new(kind, "secret-key 203.0.113.8:443"))
            .context("private credential");
        assert_eq!(error_reason(&error), expected);
        let encoded = serde_json::to_string(&error_reason(&error)).unwrap();
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("203.0.113"));
    }
    let tls = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
    let error = anyhow::Error::new(Error::other(tls)).context("TLS context");
    assert_eq!(error_reason(&error), ResultCode::UnknownIssuer);
    assert_eq!(
        error_reason(&quinn::ConnectionError::TimedOut.into()),
        ResultCode::Timeout
    );
    assert_eq!(
        error_reason(&quinn::ConnectionError::LocallyClosed.into()),
        ResultCode::Cancelled
    );
}
#[test]
fn untyped_error_text_is_never_used_to_guess_a_code() {
    for message in [
        "connection refused secret password",
        "certificate expired /private/key.pem",
        "DNS failed",
        "timed out 203.0.113.8",
        "flow limit",
    ] {
        assert_eq!(error_reason(&anyhow::anyhow!(message)), ResultCode::Unknown);
    }
}
