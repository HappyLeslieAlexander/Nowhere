// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pre-authentication admission tests.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::super::*;

#[test]
fn authentication_failure_close_uses_access_denied() {
    let (code, reason) = authentication_failure_close();

    assert_eq!(code.into_inner(), 1);
    assert_eq!(reason, b"access denied");
}

#[test]
fn authentication_timeout_jitter_covers_default_four_to_six_seconds() {
    let base = Duration::from_secs(5);

    assert_eq!(scaled_auth_timeout(base, 0), Duration::from_secs(4));
    assert_eq!(scaled_auth_timeout(base, 4_000), Duration::from_secs(6));
    let sampled = jittered_auth_timeout(base);
    assert!(sampled >= Duration::from_secs(4));
    assert!(sampled <= Duration::from_secs(6));
}

#[test]
fn unauthenticated_admission_enforces_per_source_and_releases_with_raii() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut guards = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
        .map(|_| admission.try_acquire(source).unwrap())
        .collect::<Vec<_>>();

    assert!(admission.try_acquire(source).is_none());
    drop(guards.pop());
    assert!(admission.try_acquire(source).is_some());
}

#[test]
fn unauthenticated_admission_groups_ipv6_by_slash_64() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let guards = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
        .map(|suffix| {
            admission
                .try_acquire(format!("2001:db8:1:2::{suffix:x}").parse().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert!(
        admission
            .try_acquire("2001:db8:1:2:ffff::1".parse().unwrap())
            .is_none()
    );
    assert!(
        admission
            .try_acquire("2001:db8:1:3::1".parse().unwrap())
            .is_some()
    );
    drop(guards);
}

#[test]
fn unauthenticated_admission_enforces_shared_global_limit() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let guards = (0..MAX_UNAUTHENTICATED_CONNECTIONS)
        .map(|index| {
            admission
                .try_acquire(IpAddr::V4(Ipv4Addr::from(index as u32)))
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert!(
        admission
            .try_acquire(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            .is_none()
    );
    drop(guards);
    assert!(
        admission
            .try_acquire(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            .is_some()
    );
}

#[test]
fn pre_auth_datagram_buffer_never_exceeds_64_kib() {
    let mut pending = VecDeque::new();
    let mut pending_bytes = 0;

    for _ in 0..64 {
        assert!(retain_pre_auth_datagram(
            &mut pending,
            &mut pending_bytes,
            Bytes::from(vec![0; 1024]),
        ));
    }
    assert_eq!(pending_bytes, PRE_AUTH_DATAGRAM_BUFFER_SIZE);
    assert!(!retain_pre_auth_datagram(
        &mut pending,
        &mut pending_bytes,
        Bytes::from_static(b"x"),
    ));
    assert_eq!(pending_bytes, PRE_AUTH_DATAGRAM_BUFFER_SIZE);
}
