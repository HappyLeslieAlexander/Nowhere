// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress configuration defaults, target dial policy, and credential redaction tests.

use super::*;
use crate::common::{DialPolicy, LogLevel};

#[test]
fn fixed_quic_and_effective_defaults_ignore_removed_options_and_hide_credentials() {
    let egress = Egress::new(
        Url::parse(
            "egress://0123456789abcdef0123456789abcdef@localhost:2000?net=tcp&rev=bad&next=secret&log=info&dial4=192.0.2.254",
        )
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    assert_eq!(egress.config.net, crate::vector::config::CarrierMode::Udp);
    assert_eq!(egress.config.dial_policy, DialPolicy::default());
    assert_eq!(
        egress.effective,
        "egress://localhost:2000?sni=localhost&pin=none&dial4=192.0.2.254&dial6=auto&morph=0&rate=0&etar=0&log=info"
    );
    assert!(!egress.effective.contains("secret"));
    assert!(!egress.effective.contains("rev="));
    assert!(!egress.effective.contains("next="));
}
