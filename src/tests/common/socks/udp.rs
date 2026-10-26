// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP readiness, pooled receive ownership, and SOCKS control lifecycle tests.

use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::common::{SocksAddress, encode_udp_packet_into};

use super::*;

async fn pair(socks: bool) -> (OutboundUdpSocket, UdpSocket, Option<TcpStream>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay.local_addr().unwrap()).await.unwrap();
    relay.connect(socket.local_addr().unwrap()).await.unwrap();
    if socks {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (control, _) = listener.accept().await.unwrap();
        (
            OutboundUdpSocket::Socks(SocksUdpAssociation {
                control,
                socket,
                target_header: Vec::new(),
            }),
            relay,
            Some(peer),
        )
    } else {
        (OutboundUdpSocket::Direct(socket), relay, None)
    }
}

async fn readable(socket: &OutboundUdpSocket) {
    match socket {
        OutboundUdpSocket::Direct(socket) => socket.readable().await.unwrap(),
        OutboundUdpSocket::Socks(association) => association.socket.readable().await.unwrap(),
    }
}

#[tokio::test]
async fn would_block_returns_the_lease_and_readiness_can_resume() {
    for socks in [false, true] {
        let (socket, relay, _control) = pair(socks).await;
        let mut frame = Vec::new();
        encode_udp_packet_into(
            &mut frame,
            &SocksAddress::Ip("127.0.0.1:53".parse().unwrap()),
            b"data",
        )
        .unwrap();
        let wire = if socks { frame.as_slice() } else { b"data" };
        relay.send(wire).await.unwrap();
        readable(&socket).await;
        let (buffer, cached) = BufferLease::isolated_udp();
        assert_eq!(socket.try_recv(buffer).unwrap().unwrap(), b"data");
        assert_eq!(cached(), 1);
        let (buffer, cached) = BufferLease::isolated_udp();
        assert!(socket.try_recv(buffer).unwrap().is_none());
        assert_eq!(cached(), 1);
        let mut receiving = Box::pin(socket.recv());
        poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        relay.send(wire).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receiving)
                .await
                .unwrap()
                .unwrap(),
            b"data"
        );
    }
}

#[tokio::test]
async fn socks_fragment_and_parse_error_return_the_lease() {
    let (socket, relay, _control) = pair(true).await;
    let mut frame = Vec::new();
    encode_udp_packet_into(
        &mut frame,
        &SocksAddress::Domain("a".repeat(255), 53),
        b"payload",
    )
    .unwrap();
    for fragment in [1, 0] {
        frame[2] = fragment;
        relay.send(&frame).await.unwrap();
        readable(&socket).await;
        let (buffer, cached) = BufferLease::isolated_udp();
        let received = socket.try_recv(buffer).unwrap();
        assert_eq!(
            received.as_deref(),
            (fragment == 0).then_some(b"payload".as_slice())
        );
        assert_eq!(cached(), 1);
        let (buffer, cached) = BufferLease::isolated_udp();
        assert!(socket.try_recv(buffer).unwrap().is_none());
        assert_eq!(cached(), 1);
    }
    relay.send(&[0, 0, 0]).await.unwrap();
    readable(&socket).await;
    let (buffer, cached) = BufferLease::isolated_udp();
    assert!(socket.try_recv(buffer).is_err());
    assert_eq!(cached(), 1);
}

#[tokio::test]
async fn socks_idle_receive_detects_eof_and_unexpected_control_data() {
    for data in [false, true] {
        let (socket, _relay, mut control) = pair(true).await;
        let mut receiving = Box::pin(socket.recv());
        poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        if data {
            control.as_mut().unwrap().write_all(&[1]).await.unwrap();
        } else {
            drop(control);
        }
        let error = tokio::time::timeout(Duration::from_secs(1), receiving)
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains(if data {
            "unexpected control data"
        } else {
            "control connection closed"
        }));
    }
}

#[tokio::test]
async fn receive_preserves_the_largest_platform_datagram_without_truncation() {
    for socks in [false, true] {
        let (socket, relay, _control) = pair(socks).await;
        let address = SocksAddress::Domain("a".repeat(255), 53);
        let mut frame = Vec::new();
        if socks {
            encode_udp_packet_into(&mut frame, &address, &[]).unwrap();
        }
        let header_len = frame.len();
        let mut low = 0;
        let mut high = 65507 - header_len;
        while low <= high {
            let size = (low + high) / 2;
            let expected = vec![size as u8; size];
            if socks {
                encode_udp_packet_into(&mut frame, &address, &expected).unwrap();
            } else {
                frame.clone_from(&expected);
            }
            match relay.send(&frame).await {
                Ok(sent) => {
                    assert_eq!(sent, header_len + size);
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(1), socket.recv())
                            .await
                            .unwrap()
                            .unwrap(),
                        expected
                    );
                    low = size + 1;
                }
                Err(error) => {
                    #[cfg(unix)]
                    assert_eq!(error.raw_os_error(), Some(libc::EMSGSIZE));
                    #[cfg(windows)]
                    assert_eq!(error.raw_os_error(), Some(10040));
                    high = size - 1;
                }
            }
        }
        assert!(high + header_len >= 8192);
        frame.clear();
        if socks {
            encode_udp_packet_into(&mut frame, &address, &[]).unwrap();
        }
        relay.send(&frame).await.unwrap();
        assert!(socket.recv().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn many_idle_receivers_can_be_cancelled_and_resumed() {
    let mut sockets = Vec::new();
    let mut relays = Vec::new();
    for _ in 0..256 {
        let (socket, relay, _) = pair(false).await;
        sockets.push(socket);
        relays.push(relay);
    }
    let mut pending = sockets
        .iter()
        .map(|socket| Box::pin(socket.recv()))
        .collect::<Vec<_>>();
    poll_fn(|cx| {
        for receiving in &mut pending {
            assert!(receiving.as_mut().poll(cx).is_pending());
        }
        Poll::Ready(())
    })
    .await;
    drop(pending);
    for (socket, relay) in sockets.iter().zip(&relays) {
        relay.send(b"resumed").await.unwrap();
        assert_eq!(socket.recv().await.unwrap(), b"resumed");
    }
}

#[tokio::test]
async fn rate_wait_keeps_payload_ownership_without_retaining_the_receive_lease() {
    let (socket, relay, _control) = pair(false).await;
    relay.send(b"rate-limited").await.unwrap();
    readable(&socket).await;
    let (buffer, cached) = BufferLease::isolated_udp();
    let payload = socket.try_recv(buffer).unwrap().unwrap();
    let rate = crate::transport::RateLimiter::new(0, 1).unwrap();
    let mut waiting = Box::pin(async {
        rate.wait_write(payload.len() as i64).await;
        payload.as_slice()
    });
    poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(cached(), 1);
    drop(waiting);
    assert_eq!(payload, b"rate-limited");
}
