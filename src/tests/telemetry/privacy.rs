// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only
//! Endpoint/target validation and random instance identity regressions.

use super::*;
#[test]
fn endpoints_and_targets_reject_credentials_controls_and_invalid_addresses() {
    assert_eq!(endpoint(":2000"), ":2000");
    assert_eq!(endpoint("[::1]:2000"), "[::1]:2000");
    for input in [
        "user:password@host:443",
        "host:443?key=secret",
        "host:443\x1b[31m",
        "host:443#secret",
        "bad endpoint",
    ] {
        assert_eq!(endpoint(input), "<redacted>");
    }
    assert_eq!(target("example.com:443"), "example.com:443");
    for input in [
        "user:password@host:443",
        "host:443?key=secret",
        "host:443\x1b[31m",
    ] {
        assert_eq!(target(input), "<redacted>");
    }
}
#[test]
fn instance_ids_are_random_lowercase_hex() {
    let first = random_id().unwrap();
    let second = random_id().unwrap();
    assert_eq!(first.len(), 32);
    assert!(
        first
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
    );
    assert_ne!(first, second);
}
