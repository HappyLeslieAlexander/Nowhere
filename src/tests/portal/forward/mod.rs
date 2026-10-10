// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal TLS/QUIC forwarding matrices, Morph, IPv6, and TCP half-close tests.

use super::*;

mod socks;
mod telemetry;

#[tokio::test]
async fn direct_tls_quic_tcp_udp_morph_and_half_close() {
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    for morph in [false, true] {
        let h = Harness::new("direct", morph).await;
        for net in ["tcp", "udp"] {
            let client = h.client(net, morph);
            exchange(&client, &tcp, &udp).await;
            client
                .close(tokio::time::Instant::now() + Duration::from_secs(2))
                .await;
            assert_eq!(
                client
                    .stats
                    .tcp_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert_eq!(
                client
                    .stats
                    .udp_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        }
        h.close().await;
    }
    tcp_task.abort();
    udp_task.abort();
}
