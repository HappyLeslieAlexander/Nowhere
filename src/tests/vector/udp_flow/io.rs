// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP packet payload ownership and retained receive-budget tests.

use std::sync::Arc;

use bytes::Bytes;

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
