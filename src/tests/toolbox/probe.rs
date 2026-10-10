// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Probe configuration, target setup, transport failures, and diagnostic redaction tests.

use super::*;

#[test]
fn toolbox_configuration_errors_explain_the_failure_without_echoing_values() {
    for (raw, expected) in [
        (
            "vector://secret@localhost:2000?up=secret",
            "up must be tcp, udp, or mix",
        ),
        (
            "vector://secret@localhost/tcp:secret",
            "carrier port must contain decimal digits only",
        ),
        ("vector://secret@localhost/secret:2000", "unknown carrier"),
        (
            "vector://secret@localhost:2000?morph=secret",
            "morph must be 0 or 1",
        ),
        (
            "vector://secret@localhost:2000?sni=secret:443",
            "sni must be an ASCII DNS name",
        ),
        (
            "vector://secret@localhost:2000?socks=user:secret@localhost:secret",
            "port must be in 1..=65535",
        ),
        (
            "vector://secret@localhost:2000?up=%FFsecret",
            "invalid UTF-8 in query value",
        ),
    ] {
        let error = parse_client(&Url::parse(raw).unwrap()).err().unwrap();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("secret"), "{message}");
        assert!(!message.contains("user:"), "{message}");
    }
}

#[test]
fn toolbox_probe_url_allows_missing_socks() {
    let url = Url::parse("vector://secret@127.0.0.1:2000?up=tcp&down=tcp").unwrap();
    assert!(ToolboxClient::parse(&url).is_ok());
}

#[test]
fn setup_results_use_cli_labels() {
    assert_eq!(setup_name(SetupResult::DialFailed), "DIAL_FAILED");
}
