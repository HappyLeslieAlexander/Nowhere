// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector carrier selection, defaults, query validation, and effective configuration tests.

use super::*;
fn parse(query: &str) -> Result<VectorConfig> {
    VectorConfig::from_url(
        &Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?in=127.0.0.1:1080&{query}"
        ))
        .unwrap(),
    )
}
#[test]
fn defaults_unknown_and_removed_options_are_ignored() {
    let config =
        parse("rev=garbage&mux=bad&up=udp&down=no&next=bad&socks=bad&unknown=%ZZ").unwrap();
    assert_eq!(config.net, CarrierMode::Tcp);
    assert_eq!(
        config.effective_url(),
        "vector://localhost:2000?in=127.0.0.1:1080&net=tcp&sni=localhost&pin=none&morph=0&rate=0&etar=0&log=info"
    );
    assert!(!config.effective_url().contains("secret"));
    assert!(!config.effective_url().contains("rev="));
    assert!(!config.effective_url().contains("socks="));
    assert_eq!(parse("net=udp&net=bad").unwrap().net, CarrierMode::Udp);
    assert!(parse("net=bad&net=udp").is_err());
}
#[test]
fn recognized_invalid_values_and_missing_ingress_fail() {
    for query in [
        "net=", "net=quic", "morph=2", "rate=-1", "etar=no", "log=bad", "pin=bad",
    ] {
        assert!(parse(query).is_err(), "{query}");
    }
    let url = Url::parse("vector://0123456789abcdef0123456789abcdef@localhost:2000").unwrap();
    assert!(VectorConfig::from_url(&url).is_err());
    assert!(PortalClientConfig::from_probe_url(&url).is_ok());
}
#[test]
fn ingress_credentials_split_before_single_decode_and_are_redacted() {
    let url = Url::parse(
        "vector://0123456789abcdef0123456789abcdef@localhost:2000?in=a%3Ab:p%2540ss@127.0.0.1:1080",
    )
    .unwrap();
    let config = VectorConfig::from_url(&url).unwrap();
    assert_eq!(
        config.socks.credentials.as_ref().unwrap().as_pair(),
        ("a:b", "p%40ss")
    );
    assert!(!config.effective_url().contains("p%40ss"));
}
