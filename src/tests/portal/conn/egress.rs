// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal egress connection regression tests.

use super::*;

#[tokio::test]
async fn slot_busy_role_direction_and_old_owner_cleanup() {
    let h = Harness::new("egress", false).await;
    let (e1, q1) = connect(&h).await;
    let (mut send, mut recv) = q1.open_bi().await.unwrap();
    send.write_all(&tag(&q1, true)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
    let owner = h.inner.egress_slot.as_ref().unwrap().connection().unwrap();
    let (e2, q2) = connect(&h).await;
    let (mut send, mut recv) = q2.open_bi().await.unwrap();
    send.write_all(&tag(&q2, true)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1).await.unwrap(), [1]);
    assert!(Arc::ptr_eq(
        &owner,
        &h.inner.egress_slot.as_ref().unwrap().connection().unwrap()
    ));
    let (mut send, _recv) = q1.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), q1.closed())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.inner.egress_slot.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (e3, q3) = connect(&h).await;
    let (mut send, mut recv) = q3.open_bi().await.unwrap();
    send.write_all(&tag(&q3, true)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
    assert!(!h.inner.egress_slot.as_ref().unwrap().release(&owner));
    assert!(h.inner.egress_slot.as_ref().unwrap().online());
    q3.close(0u32.into(), b"test");
    e3.wait_idle().await;
    e2.wait_idle().await;
    e1.wait_idle().await;
    h.close().await;
}

#[tokio::test]
async fn egress_reconnects_with_new_owner_and_does_not_recover_old_flows() {
    let h = Harness::new("egress", false).await;
    let egress = crate::Egress::new(h.url("egress", "udp", false), Logger).unwrap();
    let task = tokio::spawn(egress.run());
    let slot = h.inner.egress_slot.as_ref().unwrap();
    let owner = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(owner) = slot.connection() {
                break owner;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        h.inner
            .forward
            .stats
            .tcp_active
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        h.inner
            .forward
            .stats
            .udp_active
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    owner.close();
    let new = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if let Ok(new) = slot.connection()
                && !Arc::ptr_eq(&owner, &new)
            {
                break new;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!slot.release(&owner));
    assert!(Arc::ptr_eq(&new, &slot.connection().unwrap()));
    task.abort();
    let _ = task.await;
    h.close().await;
}

#[tokio::test]
async fn egress_source_binding_applies_only_to_targets_and_does_not_fallback() {
    let h = Harness::new("egress", false).await;
    let mut url = h.url("egress", "udp", false);
    url.query_pairs_mut().append_pair("dial4", "192.0.2.254");
    let egress = crate::Egress::new(url, Logger).unwrap();
    let task = tokio::spawn(egress.run());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !h.inner.egress_slot.as_ref().unwrap().online() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    for net in ["tcp", "udp"] {
        let client = h.client(net, false);
        assert_eq!(
            client.open_tcp(&tcp).await.err().unwrap().setup_result(),
            Some(SetupResult::DialFailed)
        );
        assert_eq!(
            crate::vector::udp_flow::open_udp(client.clone(), &udp)
                .await
                .err()
                .unwrap()
                .setup_result(),
            Some(SetupResult::DialFailed)
        );
        client
            .close(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert!(h.inner.egress_slot.as_ref().unwrap().online());
    }
    task.abort();
    let _ = task.await;
    h.close().await;
    tcp_task.abort();
    udp_task.abort();
}
