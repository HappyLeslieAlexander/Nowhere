// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Deterministic TLS claim, expiration, disconnect, and shutdown priorities.

use std::time::Duration;

use super::*;

#[tokio::test]
async fn dispatched_claim_wins_when_standby_ttl_is_also_ready() {
    let (mut stream, _peer) = tokio::io::duplex(1);
    let (sender, receiver) = oneshot::channel();
    sender.send(42).unwrap();
    let deadline = Instant::now() - Duration::from_secs(1);
    tokio::time::sleep_until(deadline).await;
    assert_eq!(
        wait_tls_claim(&mut stream, receiver, deadline, &CancellationToken::new()).await,
        Some(42)
    );
}

#[tokio::test]
async fn shutdown_and_disconnect_keep_priority_over_a_dispatched_claim() {
    for shutdown_ready in [false, true] {
        let (mut stream, peer) = tokio::io::duplex(1);
        let shutdown = CancellationToken::new();
        let (sender, receiver) = oneshot::channel();
        sender.send(42).unwrap();
        let _peer = if shutdown_ready {
            shutdown.cancel();
            Some(peer)
        } else {
            drop(peer);
            None
        };
        assert_eq!(
            wait_tls_claim(
                &mut stream,
                receiver,
                Instant::now() - Duration::from_secs(1),
                &shutdown
            )
            .await,
            None
        );
    }
}

#[tokio::test]
async fn unclaimed_standby_expires_at_its_fixed_deadline() {
    let (mut stream, _peer) = tokio::io::duplex(1);
    let (_sender, receiver) = oneshot::channel::<()>();
    let deadline = Instant::now() - Duration::from_secs(1);
    tokio::time::sleep_until(deadline).await;
    assert_eq!(
        wait_tls_claim(&mut stream, receiver, deadline, &CancellationToken::new()).await,
        None
    );
}
