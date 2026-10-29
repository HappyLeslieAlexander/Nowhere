// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network helper tests.

use super::*;

#[test]
fn resolve_listen_addrs_handles_wildcard_and_ip_literals() {
    // The bare "*" must bind the wildcard dual stack, not go through DNS.
    assert_eq!(
        resolve_listen_addrs("*", 8080).unwrap(),
        vec![
            SocketAddr::from(([0, 0, 0, 0], 8080)),
            SocketAddr::from(([0u16; 8], 8080)),
        ]
    );

    assert_eq!(
        resolve_listen_addrs("", 8080).unwrap(),
        vec![
            SocketAddr::from(([0, 0, 0, 0], 8080)),
            SocketAddr::from(([0u16; 8], 8080)),
        ]
    );
    assert_eq!(
        resolve_listen_addrs("0.0.0.0", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        resolve_listen_addrs("::", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        resolve_listen_addrs("[::]", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        resolve_listen_addrs("127.0.0.1", 8080).unwrap(),
        vec![SocketAddr::from(([127, 0, 0, 1], 8080))]
    );
    assert_eq!(
        resolve_listen_addrs("::1", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
    assert_eq!(
        resolve_listen_addrs("[::1]", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
}

#[test]
fn filter_addrs_matches_local_ip_family() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];

    assert_eq!(
        filter_addrs_for_family(
            addrs.into_iter(),
            &DialPolicy::default(),
            AddressFamily::Any
        ),
        addrs
    );
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), &"127.0.0.1".into(), AddressFamily::Any),
        [addrs[0]]
    );
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), &"::1".into(), AddressFamily::Any),
        [addrs[1]]
    );
}

#[test]
fn carrier_bind_resolution_expands_wildcards_and_filters_dns() {
    let v4 = CarrierEndpoint {
        port: 8080,
        family: AddressFamily::V4,
    };
    let v6 = CarrierEndpoint {
        port: 9090,
        family: AddressFamily::V6,
    };
    assert_eq!(
        resolve_bind_addrs("*", v4).unwrap(),
        [SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        resolve_bind_addrs("*", v6).unwrap(),
        [SocketAddr::from(([0u16; 8], 9090))]
    );
    assert!(resolve_bind_addrs("127.0.0.1", v6).is_err());

    let localhost = resolve_bind_addrs("localhost", v4).unwrap();
    assert!(!localhost.is_empty());
    assert!(localhost.iter().all(SocketAddr::is_ipv4));
    assert!(localhost.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn carrier_and_local_bind_family_filters_are_both_enforced() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), &DialPolicy::default(), AddressFamily::V6),
        [addrs[1]]
    );
    assert!(
        filter_addrs_for_family(addrs.into_iter(), &"127.0.0.1".into(), AddressFamily::V6,)
            .is_empty()
    );
}

#[tokio::test]
async fn dual_stack_binds_tcp_and_udp_sources_for_domain_and_ip_targets() {
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: Some("::1".parse().unwrap()),
    };
    let listener4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener6 = match tokio::net::TcpListener::bind("[::1]:0").await {
        Ok(listener) => Some(listener),
        Err(error) => {
            eprintln!("SKIP IPv6 source binding: IPv6 loopback unavailable: {error}");
            None
        }
    };
    for listener in std::iter::once(&listener4).chain(listener6.as_ref()) {
        let target = listener.local_addr().unwrap();
        for host in [target.to_string(), format!("localhost:{}", target.port())] {
            let stream = dial_tcp_with_policy(
                &policy,
                &host,
                Duration::from_secs(2),
                if target.is_ipv4() {
                    AddressFamily::V4
                } else {
                    AddressFamily::V6
                },
            )
            .await
            .unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(stream.local_addr().unwrap().ip(), target.ip());
            assert_eq!(peer.ip(), target.ip());
        }
        let udp = UdpSocket::bind(SocketAddr::new(target.ip(), 0))
            .await
            .unwrap();
        let target = udp.local_addr().unwrap();
        let socket = dial_udp_with_policy(&policy, &target.to_string(), Duration::from_secs(2))
            .await
            .unwrap();
        socket.send(b"source").await.unwrap();
        let mut data = [0; 16];
        let (size, peer) = udp.recv_from(&mut data).await.unwrap();
        assert_eq!(&data[..size], b"source");
        assert_eq!(peer.ip(), target.ip());
    }
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = dial_udp_with_policy(
        &"127.0.0.1".into(),
        &format!("localhost:{}", udp.local_addr().unwrap().port()),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(socket.peer_addr().unwrap().is_ipv4());
}

#[tokio::test]
async fn failed_explicit_source_tries_the_other_family_without_auto_fallback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = udp.local_addr().unwrap();
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: Some("2001:db8::dead".parse().unwrap()),
    };
    let failed = SocketAddr::new("::1".parse().unwrap(), target.port());
    let stream = connect_tcp_candidates(&policy, vec![failed, target], Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), target);
    let socket = connect_udp_candidates(&policy, vec![failed, udp_target], Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(socket.peer_addr().unwrap(), udp_target);
    let policy = DialPolicy::DualStack {
        v4: Some("192.0.2.254".parse().unwrap()),
        v6: None,
    };
    assert!(
        connect_tcp_candidates(&policy, vec![target], Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(
        connect_udp_candidates(&policy, vec![udp_target], Duration::from_secs(1))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dual_stack_udp_domain_binds_source_for_the_resolved_family() {
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = match UdpSocket::bind(SocketAddr::new("::1".parse().unwrap(), port)).await {
        Ok(socket) => Some(socket),
        Err(error) => {
            eprintln!("SKIP IPv6 UDP domain source: IPv6 loopback unavailable: {error}");
            None
        }
    };
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: v6.as_ref().map(|_| "::1".parse().unwrap()),
    };
    let socket = dial_udp_with_policy(
        &policy,
        &format!("localhost:{port}"),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let peer = socket.peer_addr().unwrap();
    if peer.is_ipv6() && v6.is_none() {
        eprintln!("SKIP IPv6 UDP domain exchange: resolver selected unavailable IPv6 loopback");
        return;
    }
    socket.send(b"domain").await.unwrap();
    let receiver = if peer.is_ipv4() {
        &v4
    } else {
        v6.as_ref().unwrap()
    };
    let mut bytes = [0; 16];
    let (_, source) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source.ip(), peer.ip());
}

#[test]
fn candidates_alternate_address_families_starting_with_ipv6() {
    let v4a = SocketAddr::from(([10, 0, 0, 1], 443));
    let v4b = SocketAddr::from(([10, 0, 0, 2], 443));
    let v6a = SocketAddr::new("2001:db8::a".parse().unwrap(), 443);
    let v6b = SocketAddr::new("2001:db8::b".parse().unwrap(), 443);
    assert_eq!(
        interleave_address_families(vec![v4a, v6a, v4b, v6b]),
        vec![v6a, v4a, v6b, v4b]
    );
    assert_eq!(interleave_address_families(vec![v4a, v4b]), vec![v4a, v4b]);
    assert_eq!(interleave_address_families(vec![v6a, v6b]), vec![v6a, v6b]);
    assert!(interleave_address_families(Vec::new()).is_empty());
}

#[tokio::test]
async fn a_blackholed_candidate_cannot_starve_a_reachable_one() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    // TEST-NET-3 never routes; the share budget must move on to loopback.
    let candidates = vec![
        SocketAddr::from(([203, 0, 113, 1], 443)),
        SocketAddr::from(([127, 0, 0, 1], port)),
    ];
    let started = std::time::Instant::now();
    let policy = DialPolicy::default();
    let stream = connect_tcp_candidates(&policy, candidates, Duration::from_secs(2))
        .await
        .expect("reachable candidate must win after the blackholed share");
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(stream);
    accept.abort();
}
