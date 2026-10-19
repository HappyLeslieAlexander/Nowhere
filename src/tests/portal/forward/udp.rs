// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS UDP receive ranges and payload borrowing through the forwarding path.

use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};

use crate::common::{
    COMMAND_UDP_ASSOCIATE, DialPolicy, OutboundDialer, REPLY_SUCCEEDED, SocksAddress, SocksConfig,
    authenticate, encode_udp_packet_into, read_request, write_reply,
};

use super::*;

#[tokio::test]
async fn socks_target_receiver_preserves_headers_and_borrows_payload_in_place() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let config = SocksConfig::from_url(
            &url::Url::parse(&format!("portal://key@127.0.0.1:2000?out={}", listener.local_addr().unwrap())).unwrap(),
        ).unwrap();
        let proxy = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            authenticate(&mut control, None).await.unwrap();
            assert_eq!(read_request(&mut control).await.unwrap().command, COMMAND_UDP_ASSOCIATE);
            write_reply(&mut control, REPLY_SUCCEEDED, &SocksAddress::Ip(relay_address)).await.unwrap();
            let mut request = [0; 64];
            let (_, client) = relay.recv_from(&mut request).await.unwrap();
            let mut frame = Vec::new();
            for payload in [b"payload".as_slice(), b""] {
                encode_udp_packet_into(&mut frame, &SocksAddress::Ip("192.0.2.1:53".parse().unwrap()), payload).unwrap();
                relay.send_to(&frame, client).await.unwrap();
            }
            control
        });
        let socket = OutboundDialer::new(DialPolicy::default(), config)
            .dial_udp_target(&Target::domain("example.com", 53).unwrap(), Duration::from_secs(1))
            .await.unwrap();
        socket.send(b"request", &mut Vec::new()).await.unwrap();
        let _control = proxy.await.unwrap();
        let mut receiver = TargetReceiver::Network(&socket);
        let mut buffer = Vec::with_capacity(u16::MAX as usize + 262);
        let pointer = buffer.as_ptr();
        for expected in [b"payload".as_slice(), b""] {
            let packet = receiver.recv(&mut buffer).await.unwrap().unwrap();
            assert!(matches!(&packet, crate::vector::ReceivedUdpPacket::Buffered(range) if range.start == 10));
            assert_eq!(&buffer[..4], &[0, 0, 0, 1]);
            assert_eq!(packet.payload(&buffer), expected);
            assert_eq!(packet.payload(&buffer).as_ptr(), buffer[10..].as_ptr());
            assert_eq!(buffer.as_ptr(), pointer);
        }
    }).await.unwrap();
}
