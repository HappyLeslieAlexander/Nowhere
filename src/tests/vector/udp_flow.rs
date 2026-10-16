// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP tunnel payload ownership and receive-budget lifetime tests.

use super::*;

#[test]
fn buffered_packet_borrows_the_original_payload_range_including_empty_packets() {
    let buffer = b"SOCKS headerpayload";
    for range in [
        0..buffer.len(),
        12..buffer.len(),
        buffer.len()..buffer.len(),
    ] {
        let packet = ReceivedUdpPacket::Buffered(range.clone());
        assert_eq!(packet.len(), range.len());
        let payload = packet.payload(buffer);
        assert_eq!(payload, &buffer[range.clone()]);
        assert_eq!(payload.as_ptr(), buffer[range].as_ptr());
    }
}

#[tokio::test]
async fn stream_tunnel_reuses_receive_buffer_and_accounts_only_completed_packets() {
    let stats = Arc::new(Stats::default());
    let (stream, mut peer) = tokio::io::duplex(64);
    let (reader, writer) = tokio::io::split(stream);
    let mut tunnel = UdpTunnel::stream(
        Box::pin(reader),
        Box::pin(writer),
        TcpTunnelGuard { _flow: None },
        stats.clone(),
        true,
    );
    let mut buffer = Vec::with_capacity(64);
    let pointer = buffer.as_ptr();
    for payload in [b"payload".as_slice(), b"", b"next"] {
        write_udp_packet(&mut peer, payload).await.unwrap();
        let packet = tunnel.recv_into(&mut buffer).await.unwrap().unwrap();
        assert_eq!(packet.payload(&buffer), payload);
        assert_eq!(buffer.as_ptr(), pointer);
        assert!(tunnel.send(payload).await.unwrap());
        assert_eq!(
            crate::protocol::read_udp_packet(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            payload
        );
    }
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 1);
    assert_eq!(stats.udp_upload_bytes.load(Ordering::Relaxed), 11);
    assert_eq!(stats.udp_download_bytes.load(Ordering::Relaxed), 11);
    tunnel.close().await;
    assert!(tunnel.recv_into(&mut buffer).await.unwrap().is_none());
    assert!(tunnel.send(b"closed").await.is_err());
    tunnel.close().await;
    drop(tunnel);
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn dropping_a_stream_tunnel_cancels_it_and_releases_the_active_count() {
    let stats = Arc::new(Stats::default());
    let (stream, _peer) = tokio::io::duplex(64);
    let (reader, writer) = tokio::io::split(stream);
    let tunnel = UdpTunnel::stream(
        Box::pin(reader),
        Box::pin(writer),
        TcpTunnelGuard { _flow: None },
        stats.clone(),
        true,
    );
    let cancellation = tunnel.cancellation();
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 1);
    drop(tunnel);
    assert!(cancellation.is_cancelled());
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 0);
}

#[test]
fn owned_quic_packet_retains_budget_until_consumed() {
    let payload = Bytes::from_static(b"zero-copy");
    let pointer = payload.as_ptr();
    let budget = Arc::new(tokio::sync::Semaphore::new(9));
    let permit = crate::common::reserve_udp_budget(budget.clone(), 9).unwrap();
    let packet = ReceivedUdpPacket::Owned(BudgetedDatagram::new(payload, permit));
    assert_eq!(packet.payload(&[]).as_ptr(), pointer);
    assert_eq!(budget.available_permits(), 0);
    drop(packet);
    assert_eq!(budget.available_permits(), 9);
}
