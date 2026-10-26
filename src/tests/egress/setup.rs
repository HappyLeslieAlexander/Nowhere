// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress configuration defaults, target dial policy, and credential redaction tests.

use std::collections::HashMap;

use crate::common::DialPolicy;

use super::*;

#[test]
fn endpoint_accepts_only_one_quic_carrier_or_a_compact_port() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    for endpoint in ["localhost:2000", "localhost/udp6:2000"] {
        let egress = Egress::new(
            Url::parse(&format!("egress://{KEY}@{endpoint}")).unwrap(),
            Logger,
        )
        .unwrap();
        assert_eq!(egress.config.net, crate::vector::config::CarrierMode::Udp);
        assert_eq!(egress.config.endpoint(), endpoint);
    }
    for endpoint in ["localhost/tcp:2000", "localhost/tcp:2000/udp:2001"] {
        let error = Egress::new(
            Url::parse(&format!("egress://{KEY}@{endpoint}")).unwrap(),
            Logger,
        )
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("only a QUIC carrier"),
            "{endpoint}: {error}"
        );
    }
}

#[test]
fn fixed_quic_and_effective_defaults_ignore_unknown_options_and_hide_credentials() {
    let egress = Egress::new(
        Url::parse(
            "egress://0123456789abcdef0123456789abcdef@localhost:2000?net=tcp&unknown=bad&unused=secret&dial4=192.0.2.254",
        )
        .unwrap(),
        Logger,
    )
    .unwrap();
    assert_eq!(egress.config.net, crate::vector::config::CarrierMode::Udp);
    assert_eq!(egress.config.dial_policy, DialPolicy::default());
    let effective = Url::parse(&egress.effective).unwrap();
    assert_eq!(effective.scheme(), "egress");
    assert!(effective.username().is_empty());
    assert!(effective.password().is_none());
    assert_eq!(effective.host_str(), Some("localhost"));
    assert_eq!(effective.port(), Some(2000));
    let values = effective.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(effective.query_pairs().count(), values.len());
    assert_eq!(
        values,
        HashMap::from([
            ("sni".into(), "localhost".into()),
            ("pin".into(), "none".into()),
            ("dial4".into(), "192.0.2.254".into()),
            ("dial6".into(), "auto".into()),
            ("morph".into(), "1".into()),
            ("rate".into(), "0".into()),
            ("etar".into(), "0".into()),
        ])
    );
}
