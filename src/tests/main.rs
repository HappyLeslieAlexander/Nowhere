// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI help and version behavior tests.

use super::*;

#[test]
fn probe_results_use_the_panel_as_the_only_error_output() {
    let error = anyhow::Error::new(ProbeFailed);
    assert!(!should_print_start_error(&error));
    assert!(should_print_start_error(&anyhow::anyhow!("invalid URL")));
}

#[tokio::test]
async fn commands_reject_extra_arguments() {
    for command in [
        "help",
        "--help",
        "version",
        "--version",
        "status",
        "generate-key",
    ] {
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
        "nowhere://secret@localhost/tcp:2006/../udp:2017",
        "nowhere://secret@localhost/tcp:2006/%2e%2e/udp:2017#Name",
        "nowhere://secret@localhost/tcp:secret",
        "portal://secret@localhost:2000",
        "vector://0123456789abcdef0123456789abcdef@localhost:2000",
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
        let message = format_start_error(&error);
        assert!(message.contains("invalid Nowhere share link"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[tokio::test]
async fn probe_requires_exactly_a_url_and_target() {
    for arguments in [
        vec!["nowhere", "probe"],
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
async fn toolbox_errors_do_not_expose_configuration_values() {
    for (url, expected) in [
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?net=secret",
            "net must be tcp or udp",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost/tcp:secret",
            "carrier port must contain decimal digits only",
        ),
    ] {
        let error = start(vec![
            "nowhere".to_owned(),
            "probe".to_owned(),
            url.to_owned(),
            "example.com:443".to_owned(),
        ])
        .await
        .unwrap_err();
        let message = format_start_error(&error);
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn parse_command_url_keeps_vector_remote_host() {
    let parsed = parse_command_url(
        "vector://0123456789abcdef0123456789abcdef@relay.example:2000?up=udp&down=tcp&socks=127.0.0.1:1080",
    )
    .unwrap();
    assert_eq!(parsed.scheme(), "vector");
    assert_eq!(parsed.host_str(), Some("relay.example"));
    assert_eq!(parsed.port(), Some(2000));
}

#[test]
fn logger_rejects_unknown_or_empty_levels() {
    assert!(init_logger(Some("verbose")).is_err());
    assert!(init_logger(Some("")).is_err());
    assert!(init_logger(None).is_ok());
    assert!(init_logger(Some("event")).is_err());
}

#[test]
fn parse_command_url_normalizes_legacy_empty_listen_host() {
    let parsed = parse_command_url("portal://secret@:2000?log=none&dial=::1").unwrap();

    assert_eq!(parsed.scheme(), "portal");
    assert_eq!(parsed.username(), "secret");
    assert_eq!(parsed.host_str(), Some("*"));
    assert_eq!(parsed.port(), Some(2000));
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "dial")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some("::1")
    );
}

#[test]
fn parse_command_url_normalizes_legacy_empty_host_without_userinfo() {
    let parsed = parse_command_url("portal://:2000").unwrap();

    assert_eq!(parsed.scheme(), "portal");
    assert_eq!(parsed.username(), "");
    assert_eq!(parsed.host_str(), Some("*"));
    assert_eq!(parsed.port(), Some(2000));
}

#[test]
fn parse_command_url_rejects_empty_host_for_explicit_carriers() {
    assert!(parse_command_url("portal://secret@/tcp:2006").is_err());
}

#[test]
fn parse_command_url_keeps_normal_hosts() {
    let parsed = parse_command_url("portal://secret@[::]:2000?dial=auto").unwrap();

    assert_eq!(parsed.host_str(), Some("[::]"));
    assert_eq!(parsed.port(), Some(2000));
}

#[tokio::test]
async fn invalid_configuration_urls_fail_before_service_startup_with_safe_errors() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    for (raw, expected) in [
        (
            format!("ftp://{KEY}@localhost:2000"),
            "scheme must be portal or vector",
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
            format!("vector://{KEY}@localhost:2000?net=bad"),
            "net must be tcp or udp",
        ),
        (
            format!("vector://{KEY}@localhost:2000"),
            "in parameter is required",
        ),
        (
            format!("vector://{KEY}@localhost/udp:2000?net=tcp&in=:1080"),
            "net selects an unavailable carrier",
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
        let message = format_start_error(&error);
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(KEY));
    }
}

#[tokio::test]
async fn service_key_rejections_identify_the_role_without_starting_a_service() {
    const INVALID: &str = "do-not-print-this-secret";
    for (role, context, ingress) in [
        ("portal", "Portal listener", ""),
        ("vector", "Vector configuration", "&in=127.0.0.1:1080"),
    ] {
        for morph in [0, 1] {
            for key in [
                INVALID.to_owned(),
                "a".repeat(31),
                "a".repeat(33),
                "a".repeat(64),
            ] {
                let raw = format!(
                    "{role}://{key}@unresolvable.invalid:2000?log=none&morph={morph}{ingress}"
                );
                let error = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    start(vec!["nowhere".into(), raw]),
                )
                .await
                .expect("invalid key attempted service startup")
                .unwrap_err();
                let message = format_start_error(&error);
                assert!(message.contains(context));
                assert!(message.contains("exactly 32 lowercase hexadecimal characters"));
                assert!(message.contains("nowhere generate-key"));
                assert!(!message.contains(&key));
            }
        }
    }
}

#[tokio::test]
async fn no_arguments_succeeds_without_a_terminal_and_tui_is_unknown() {
    start(vec!["nowhere".to_owned()]).await.unwrap();
    let error = start(vec!["nowhere".to_owned(), "tui".to_owned()])
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("unknown command"));
    assert!(!HELP_TEXT.contains("TUI"));
    assert!(!HELP_TEXT.contains("nowhere tui"));
}
