// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network helper tests.

use super::*;

#[test]
fn bind_udp_addrs_handles_wildcard_and_ip_literals() {
    assert_eq!(
        bind_udp_addrs("", 8080).unwrap(),
        vec![
            SocketAddr::from(([0, 0, 0, 0], 8080)),
            SocketAddr::from(([0u16; 8], 8080)),
        ]
    );
    assert_eq!(
        bind_udp_addrs("0.0.0.0", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("::", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("[::]", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("127.0.0.1", 8080).unwrap(),
        vec![SocketAddr::from(([127, 0, 0, 1], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("::1", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("[::1]", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
}

#[test]
fn filter_addrs_matches_local_ip_family() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];

    assert_eq!(filter_addrs(addrs.into_iter(), None), addrs);
    assert_eq!(
        filter_addrs(addrs.into_iter(), Some("127.0.0.1".parse().unwrap())),
        [addrs[0]]
    );
    assert_eq!(
        filter_addrs(addrs.into_iter(), Some("::1".parse().unwrap())),
        [addrs[1]]
    );
}
