// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Unified Egress FIFO ordering, cancellation, and registration cleanup.

use super::*;

impl EgressRegistry {
    pub(crate) fn registered_count(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    pub(crate) fn online(&self) -> bool {
        self.registered_count() != 0
    }
}

async fn quic_pair() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    Arc<QuicConnection>,
) {
    let url = url::Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000?morph=0")
        .unwrap();
    let (_, tls, quic) = crate::common::new_server_configs_with_reload_interval(
        &url,
        std::time::Duration::from_secs(3600),
        crate::common::Logger,
    )
    .unwrap();
    let server = quinn::Endpoint::server(quic, "127.0.0.1:0".parse().unwrap()).unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    let client_url = url::Url::parse(&format!(
        "vector://0123456789abcdef0123456789abcdef@{}/udp:{}?morph=0&pin={pin}",
        server.local_addr().unwrap().ip(),
        server.local_addr().unwrap().port()
    ))
    .unwrap();
    let (config, _) = crate::vector::PortalClientConfig::from_probe_url(&client_url).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    let accept = async { server.accept().await.unwrap().await.unwrap() };
    let (client, server_connection) =
        tokio::join!(crate::vector::client::connect_quic(&config, &tls), accept);
    let (endpoint, connection) = client.unwrap();
    (
        server,
        endpoint,
        server_connection,
        QuicConnection::new(connection, true, 4 * 1024 * 1024),
    )
}

#[tokio::test]
async fn mixed_fifo_rotates_quic_and_consumes_tls_once() {
    let (s1, e1, _server1, q1) = quic_pair().await;
    let (s2, e2, _server2, q2) = quic_pair().await;
    let registry = Arc::new(EgressRegistry::new(2));
    let _q1 = registry.register_quic(q1.clone());
    let (t1, r1) = oneshot::channel();
    let _t1 = registry.register_tls(t1, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL);
    let _q2 = registry.register_quic(q2.clone());
    let (t2, r2) = oneshot::channel();
    let _t2 = registry.register_tls(t2, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL);
    assert!(matches!(registry.claim().await.unwrap(), Selected::Quic(q) if Arc::ptr_eq(&q, &q1)));
    assert!(matches!(registry.claim().await.unwrap(), Selected::Tls(_)));
    assert!(r1.await.is_ok());
    assert!(matches!(registry.claim().await.unwrap(), Selected::Quic(q) if Arc::ptr_eq(&q, &q2)));
    assert!(matches!(registry.claim().await.unwrap(), Selected::Tls(_)));
    assert!(r2.await.is_ok());
    assert!(matches!(registry.claim().await.unwrap(), Selected::Quic(q) if Arc::ptr_eq(&q, &q1)));
    assert!(matches!(registry.claim().await.unwrap(), Selected::Quic(q) if Arc::ptr_eq(&q, &q2)));
    q1.close();
    q2.close();
    e1.close(0u32.into(), b"test");
    e2.close(0u32.into(), b"test");
    s1.close(0u32.into(), b"test");
    s2.close(0u32.into(), b"test");
}

#[tokio::test]
async fn concurrent_claims_cancelled_receivers_and_stale_cleanup_are_bounded() {
    let registry = Arc::new(EgressRegistry::new(2));
    let (closed, dropped) = oneshot::channel();
    let stale = registry.register_tls(closed, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL);
    drop(dropped);
    let (sender, receiver) = oneshot::channel();
    let live = registry.register_tls(sender, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL);
    drop(stale);
    let first = registry.claim().await.unwrap();
    assert!(matches!(first, Selected::Tls(_)));
    assert!(receiver.await.is_ok());
    drop(live);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), registry.claim())
            .await
            .is_err()
    );
    let waiter = tokio::spawn({
        let registry = registry.clone();
        async move { registry.claim().await }
    });
    tokio::task::yield_now().await;
    let (sender, receiver) = oneshot::channel();
    let _registration =
        registry.register_tls(sender, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL);
    assert!(matches!(waiter.await.unwrap().unwrap(), Selected::Tls(_)));
    assert!(receiver.await.is_ok());
    assert!(registry.reserve_tls().is_some());
}

#[tokio::test]
async fn concurrent_tls_claims_each_consume_one_registration() {
    let registry = Arc::new(EgressRegistry::new(64));
    let mut guards = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..32 {
        let (sender, receiver) = oneshot::channel();
        guards.push(
            registry.register_tls(sender, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL),
        );
        receivers.push(receiver);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let registry = registry.clone();
        tasks.spawn(async move { registry.claim().await.unwrap() });
    }
    while let Some(result) = tasks.join_next().await {
        assert!(matches!(result.unwrap(), Selected::Tls(_)));
    }
    for receiver in receivers {
        assert!(receiver.await.is_ok());
    }
    assert!(!registry.online());
    drop(guards);
}

#[tokio::test]
async fn expired_tls_is_skipped_before_its_owner_gets_scheduled() {
    let registry = Arc::new(EgressRegistry::new(2));
    let (expired, receiver) = oneshot::channel();
    let _expired = registry.register_tls(expired, Instant::now());
    let (live, live_receiver) = oneshot::channel();
    let _live = registry.register_tls(live, Instant::now() + crate::common::EGRESS_TLS_IDLE_TTL);
    let selected = registry.claim().await.unwrap();
    assert!(receiver.await.is_err());
    let transfer = live_receiver.await.unwrap();
    assert!(!transfer.is_closed());
    drop(selected);
    assert!(transfer.is_closed());
    assert!(!registry.online());
}
