// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal flow connection regression tests.

use super::*;

#[tokio::test]
async fn first_flow_pipelines_auth_and_target_without_an_auth_ack() {
    let h = Harness::new("direct", false).await;
    let (target, echo) = tcp_echo().await;
    let (endpoint, q) = connect(&h).await;
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    assert_eq!(u64::from(send.id()), 0);
    send.write_all(&tag(&q, false)).await.unwrap();
    request(&mut send, 0xfe, &target).await;
    assert_eq!(result(&mut recv).await, SetupResult::Ready);
    send.write_all(b"first flow").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(32).await.unwrap(), b"first flow");
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn invalid_or_truncated_target_rejects_only_the_flow() {
    let h = Harness::new("direct", false).await;
    let (target, echo) = tcp_echo().await;
    let (endpoint, q) = connect(&h).await;
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    send.write_all(&tag(&q, false)).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(0).await.unwrap();
    for bytes in [vec![2], vec![0xfe, 9], vec![0xfe, 1, 127, 0, 0, 1, 0, 0]] {
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        send.write_all(&bytes).await.unwrap();
        send.finish().unwrap();
        assert_eq!(result(&mut recv).await, SetupResult::InvalidRequest);
        assert!(q.close_reason().is_none());
    }
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    request(&mut send, 0, &target).await;
    assert_eq!(result(&mut recv).await, SetupResult::Ready);
    send.finish().unwrap();
    recv.read_to_end(0).await.unwrap();
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn flow_limit_is_per_flow_and_other_flows_survive() {
    let h = Harness::new("direct", false).await;
    let (target, echo) = tcp_echo().await;
    let client = h.client("udp", false);
    let mut existing = client.open_tcp(&target).await.unwrap();
    let permits = h.inner.forward.flows.available_permits();
    let held = h
        .inner
        .forward
        .flows
        .clone()
        .acquire_many_owned(permits as u32)
        .await
        .unwrap();
    assert_eq!(
        client.open_tcp(&target).await.err().unwrap().setup_result(),
        Some(SetupResult::FlowLimit)
    );
    existing.write_all(b"survive").await.unwrap();
    existing.flush().await.unwrap();
    let mut received = [0; 7];
    existing.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"survive");
    drop(held);
    drop(existing);
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn stream_id_exhaustion_enters_bounded_drain_without_truncation() {
    let h = Harness::new("direct", false).await;
    let (endpoint, q) = connect(&h).await;
    let (mut auth, mut recv) = q.open_bi().await.unwrap();
    auth.write_all(&tag(&q, false)).await.unwrap();
    auth.finish().unwrap();
    recv.read_to_end(0).await.unwrap();
    let owned = crate::transport::QuicConnection::new(
        q,
        false,
        h.inner.runtime.udp_queue_bytes,
        Some(h.inner.forward.stats.clone()),
    );
    assert_eq!(
        owned.flow_id(4294967288).unwrap(),
        crate::protocol::MAX_FLOW_ID
    );
    assert!(owned.flow_id(4294967292).is_err());
    assert!(owned.draining.is_cancelled());
    assert!(owned.flow_id(4).is_err());
    assert!(!owned.cancel.is_cancelled());
    owned.close();
    endpoint.wait_idle().await;
    h.close().await;
}

#[tokio::test]
async fn ipv6_target_and_source_bind_failures_have_no_fallback() {
    let target = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        while let Ok((mut s, _)) = target.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let h = Harness::new("direct", false).await;
    for net in ["tcp", "udp"] {
        let client = h.client(net, false);
        let mut flow = client.open_tcp(&Target::Ip(address)).await.unwrap();
        flow.write_all(b"IPv6").await.unwrap();
        flow.flush().await.unwrap();
        let mut received = [0; 4];
        flow.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"IPv6");
        drop(flow);
        client
            .close(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
    }
    h.close().await;
    echo.abort();
    let h = Harness::new("direct&dial4=192.0.2.254", false).await;
    let (target, echo) = tcp_echo().await;
    let client = h.client("udp", false);
    assert_eq!(
        client.open_tcp(&target).await.err().unwrap().setup_result(),
        Some(SetupResult::DialFailed)
    );
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    h.close().await;
    echo.abort();
}
