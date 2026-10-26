// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI argument counts, startup validation, and secret redaction tests.

use super::*;

#[tokio::test]
async fn commands_reject_extra_arguments() {
    for command in ["help", "version", "status", "generate-key"] {
        let error = start(vec![
            "nowhere".to_owned(),
            command.to_owned(),
            "extra".to_owned(),
        ])
        .await
        .unwrap_err();
        assert!(error.to_string().starts_with("usage:"));
    }
}

#[tokio::test]
async fn fingerprint_requires_exactly_one_share_link() {
    for arguments in [
        vec!["nowhere", "fingerprint"],
        vec![
            "nowhere",
            "fingerprint",
            "nowhere://secret@localhost:2000#My%20Portal",
            "extra",
        ],
    ] {
        let error = start(arguments.into_iter().map(str::to_owned).collect())
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "usage: nowhere fingerprint <nowhere-url>"
        );
    }
}

#[tokio::test]
async fn fingerprint_rejects_invalid_raw_share_links_before_network_access() {
    for raw in [
        "nowhere://secret@localhost:2000",
        "nowhere://secret@localhost/tcp:2006/%2e%2e/udp:2017#Name",
    ] {
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            start(vec![
                "nowhere".to_owned(),
                "fingerprint".to_owned(),
                raw.to_owned(),
            ]),
        )
        .await
        .expect("invalid share link attempted network access")
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("invalid nowhere share link"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[tokio::test]
async fn probe_requires_exactly_a_url_and_target() {
    for arguments in [
        vec![
            "nowhere",
            "probe",
            "vector://0123456789abcdef0123456789abcdef@localhost:2000",
        ],
        vec![
            "nowhere",
            "probe",
            "vector://0123456789abcdef0123456789abcdef@localhost:2000",
            "example.com:443",
            "extra",
        ],
    ] {
        let error = start(arguments.into_iter().map(str::to_owned).collect())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "usage: nowhere probe <URL> <TARGET>");
    }
}

#[tokio::test]
async fn invalid_configuration_urls_fail_before_service_startup_with_safe_errors() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    for (raw, expected) in [
        (format!("portal://{KEY}@:2000"), "empty host"),
        (
            format!("ftp://{KEY}@localhost:2000"),
            "scheme must be portal, vector or egress",
        ),
        (
            format!("portal://{KEY}@*/tcp:2000?out=egress"),
            "out=egress requires QUIC listener",
        ),
        (
            format!("portal://{KEY}@*:2000?out=egress&dial=auto"),
            "out=egress conflicts with explicit dial",
        ),
        (
            format!("portal://{KEY}@*:2000?out=invalid"),
            "expected HOST:PORT",
        ),
        (
            format!("portal://{KEY}@*/tcp:2000/../udp:2001"),
            "must not contain '.' or '..' segments",
        ),
    ] {
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            start(vec!["nowhere".into(), raw]),
        )
        .await
        .expect("invalid config started service")
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(KEY));
    }
}

#[tokio::test]
async fn service_key_rejections_identify_the_role_without_starting_a_service() {
    const INVALID: &str = "do-not-print-this-secret";
    for (role, context, ingress) in [
        ("portal", "Portal listener", ""),
        ("vector", "Vector configuration", "in=127.0.0.1:1080"),
        ("egress", "Egress configuration", ""),
    ] {
        let raw = format!("{role}://{INVALID}@unresolvable.invalid:2000?{ingress}");
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            start(vec!["nowhere".into(), raw]),
        )
        .await
        .expect("invalid key attempted service startup")
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(context));
        assert!(message.contains("exactly 32 lowercase hexadecimal characters"));
        assert!(message.contains("nowhere generate-key"));
        assert!(!message.contains(INVALID));
    }
}

#[tokio::test]
async fn no_arguments_succeeds_without_a_terminal_and_unknown_commands_fail() {
    start(vec!["nowhere".to_owned()]).await.unwrap();
    let error = start(vec!["nowhere".to_owned(), "unknown-command".to_owned()])
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("unknown command"));
}
