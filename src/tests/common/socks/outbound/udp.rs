// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS outbound udp regression tests.

use super::*;

#[tokio::test]
async fn udp_associate_wraps_payload_and_keeps_control_alive() {
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = control_listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut control, _) = control_listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        control.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_NONE]);
        control
            .write_all(&[SOCKS_VERSION, AUTH_NONE])
            .await
            .unwrap();
        let request = read_test_command(&mut control).await;
        assert_eq!(request.0, COMMAND_UDP_ASSOCIATE);
        write_test_reply(
            &mut control,
            SocketAddr::from(([0, 0, 0, 0], relay_addr.port())),
        )
        .await;

        let mut packet = [0u8; 512];
        for expected in [b"hello".as_slice(), b"bye".as_slice()] {
            let (size, peer) = relay.recv_from(&mut packet).await.unwrap();
            let (header_len, fragment) = parse_udp_header(&packet[..size]).unwrap();
            assert_eq!(fragment, 0);
            assert_eq!(&packet[header_len..size], expected);
            if expected == b"hello" {
                let mut fragmented = packet[..size].to_vec();
                fragmented[2] = 1;
                relay.send_to(&fragmented, peer).await.unwrap();
            }
            relay.send_to(&packet[..size], peer).await.unwrap();
        }

        let mut eof = [0u8; 1];
        assert_eq!(control.read(&mut eof).await.unwrap(), 0);
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("127.0.0.1".into(), config);
    let target = Target::domain("dns.test", 53).unwrap();
    let socket = dialer
        .dial_udp_target(&target, Duration::from_secs(2))
        .await
        .unwrap();
    let mut packet = Vec::new();
    assert_eq!(socket.send(b"hello", &mut packet).await.unwrap(), 5);
    let mut response = [0u8; 512];
    let payload = socket.recv(&mut response).await.unwrap();
    assert_eq!(&response[payload], b"hello");
    let capacity = packet.capacity();
    assert_eq!(socket.send(b"bye", &mut packet).await.unwrap(), 3);
    assert_eq!(packet.capacity(), capacity);
    let payload = socket.recv(&mut response).await.unwrap();
    assert_eq!(&response[payload], b"bye");
    drop(socket);
    server.await.unwrap();
}

#[tokio::test]
async fn udp_association_ends_when_control_connection_closes() {
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = control_listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut control, _) = control_listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        control.read_exact(&mut methods).await.unwrap();
        control
            .write_all(&[SOCKS_VERSION, AUTH_NONE])
            .await
            .unwrap();
        let _ = read_test_command(&mut control).await;
        write_test_reply(&mut control, relay_addr).await;
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("dns.test", 53).unwrap();
    let socket = dialer
        .dial_udp_target(&target, Duration::from_secs(2))
        .await
        .unwrap();
    let mut response = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut response))
            .await
            .unwrap()
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn each_udp_flow_uses_a_distinct_association() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut controls = Vec::new();
        let mut relays = Vec::new();
        for _ in 0..2 {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut methods = [0u8; 3];
            control.read_exact(&mut methods).await.unwrap();
            control
                .write_all(&[SOCKS_VERSION, AUTH_NONE])
                .await
                .unwrap();
            let request = read_test_command(&mut control).await;
            assert_eq!(request.0, COMMAND_UDP_ASSOCIATE);
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            write_test_reply(&mut control, relay.local_addr().unwrap()).await;
            controls.push(control);
            relays.push(relay);
        }

        let [first, second] = controls.as_mut_slice() else {
            unreachable!();
        };
        let mut first_eof = [0u8; 1];
        let mut second_eof = [0u8; 1];
        let (first_read, second_read) =
            tokio::join!(first.read(&mut first_eof), second.read(&mut second_eof));
        assert_eq!(first_read.unwrap(), 0);
        assert_eq!(second_read.unwrap(), 0);
        drop(relays);
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let first_target = Target::domain("one.test", 53).unwrap();
    let first = dialer
        .dial_udp_target(&first_target, Duration::from_secs(2))
        .await
        .unwrap();
    let second_target = Target::domain("two.test", 53).unwrap();
    let second = dialer
        .dial_udp_target(&second_target, Duration::from_secs(2))
        .await
        .unwrap();
    drop((first, second));
    server.await.unwrap();
}
