// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Configuration parsing tests.

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use url::Url;

use super::*;

#[test]
fn query_first_ignores_unknown_parameters_and_keeps_first_duplicate() {
    let parsed = Url::parse("portal://key@localhost:2000?mode=first&label=now%2F1").unwrap();
    let values = query_first(&parsed, &["mode", "label"]).unwrap();
    assert_eq!(values["mode"], "first");
    assert_eq!(values["label"], "now/1");

    let duplicate = Url::parse("portal://key@localhost:2000?mode=first&mode=second").unwrap();
    assert_eq!(query_first(&duplicate, &["mode"]).unwrap()["mode"], "first");
    let unknown = Url::parse("portal://key@localhost:2000?typo=value&%FF=value").unwrap();
    assert!(query_first(&unknown, &["mode"]).unwrap().is_empty());
}

#[test]
fn query_first_preserves_literal_slash_and_plus_and_validates_the_selected_value() {
    let protocol = Url::parse("portal://key@localhost:2000?label=private/2").unwrap();
    assert_eq!(
        query_first(&protocol, &["label"]).unwrap()["label"],
        "private/2"
    );

    let parsed = Url::parse("portal://key@localhost:2000?label=now+private").unwrap();
    assert_eq!(
        query_first(&parsed, &["label"]).unwrap()["label"],
        "now+private"
    );

    let bad = Url::parse("portal://key@localhost:2000?label=%GG").unwrap();
    assert!(query_first(&bad, &["label"]).is_err());

    let ignored_bad_duplicate =
        Url::parse("portal://key@localhost:2000?label=now%2F1&label=%GG").unwrap();
    assert_eq!(
        query_first(&ignored_bad_duplicate, &["label"]).unwrap()["label"],
        "now/1"
    );
}

#[test]
fn rate_limit_converts_mbps_to_bytes_per_second() {
    assert_eq!(rate_limit_bytes_per_second(-1), 0);
    assert_eq!(rate_limit_bytes_per_second(0), 0);
    assert_eq!(rate_limit_bytes_per_second(1), 125_000);
    assert_eq!(rate_limit_bytes_per_second(8), 1_000_000);
}

#[test]
fn duration_defaults_overrides_and_invalid_values() {
    assert_eq!(
        read_duration(
            &mut |_| Ok(None),
            "NOW_FLOW_SETUP_TIMEOUT",
            Duration::from_secs(20)
        )
        .unwrap(),
        Duration::from_secs(20)
    );
    assert_eq!(
        read_duration(
            &mut |_| Ok(Some("750ms".into())),
            "NOW_FLOW_SETUP_TIMEOUT",
            Duration::from_secs(20)
        )
        .unwrap(),
        Duration::from_millis(750)
    );
    for raw in [
        "0s",
        "-1s",
        "invalid",
        "",
        "999999999999999999999999h",
        "18446744073709551615s",
    ] {
        let error = validate_timeouts(&mut |_| Ok(Some(raw.into()))).unwrap_err();
        assert!(format!("{error:#}").contains("NOW_TCP_DIAL_TIMEOUT"));
    }
    assert!(
        read_duration(
            &mut |_| Ok(Some("5000000000000000s".into())),
            "NOW_UDP_IDLE_TIMEOUT",
            Duration::from_secs(120)
        )
        .is_err()
    );
}

#[test]
fn invalid_duration_is_rejected_by_each_service_at_startup() {
    for role in ["portal", "vector", "egress"] {
        for name in [
            "NOW_TCP_DIAL_TIMEOUT",
            "NOW_UDP_DIAL_TIMEOUT",
            "NOW_TCP_READ_TIMEOUT",
            "NOW_UDP_IDLE_TIMEOUT",
            "NOW_HANDSHAKE_TIMEOUT",
            "NOW_FLOW_SETUP_TIMEOUT",
            "NOW_SHUTDOWN_TIMEOUT",
            "NOW_RELOAD_INTERVAL",
            "NOW_SERVICE_COOLDOWN",
        ] {
            assert_invalid_startup(role, name, std::ffi::OsStr::new("invalid"));
        }
    }
}

fn assert_invalid_startup(role: &str, name: &str, raw: &std::ffi::OsStr) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "common::config::tests::invalid_duration_startup_child",
            "--nocapture",
        ])
        .env("NOW_TEST_TIMEOUT_ROLE", role)
        .env("NOW_TEST_TIMEOUT_NAME", name)
        .env(name, raw)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{role} {name}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn non_unicode_duration_is_a_startup_error() {
    let raw = std::ffi::OsString::from_vec(vec![0xff]);
    for role in ["portal", "vector", "egress"] {
        assert_invalid_startup(role, "NOW_FLOW_SETUP_TIMEOUT", &raw);
    }
}

#[test]
fn invalid_duration_startup_child() {
    let Ok(role) = std::env::var("NOW_TEST_TIMEOUT_ROLE") else {
        return;
    };
    let name = std::env::var("NOW_TEST_TIMEOUT_NAME").unwrap();
    let url = Url::parse(&format!(
        "{role}://0123456789abcdef0123456789abcdef@127.0.0.1:2000"
    ))
    .unwrap();
    let error = match role.as_str() {
        "portal" => crate::Portal::new(url, crate::Logger).err(),
        "vector" => crate::Vector::new(url, crate::Logger).err(),
        "egress" => crate::Egress::new(url, crate::Logger).err(),
        _ => panic!("invalid test role"),
    }
    .expect("invalid duration did not stop startup");
    assert!(format!("{error:#}").contains(&name), "{error:#}");
}
