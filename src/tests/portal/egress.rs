// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal Egress availability, shared exit bridging, counters, and disconnect cleanup tests.

use super::*;

#[tokio::test]
async fn egress_offline_fails_immediately_without_local_dial() {
    let h = Harness::new("egress", false).await;
    let (target, echo) = tcp_echo().await;
    let client = h.client("udp", false);
    let started = std::time::Instant::now();
    let error = client.open_tcp(&target).await.err().unwrap();
    assert_eq!(error.setup_result(), Some(SetupResult::DialFailed));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!h.inner.egress_slot.as_ref().unwrap().online());
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    h.close().await;
    echo.abort();
}
