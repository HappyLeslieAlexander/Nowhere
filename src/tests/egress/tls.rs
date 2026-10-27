// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Hydra growth, standby accounting, cooldown, and Egress-side TTL.

use super::*;
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

const KEY: &str = "0123456789abcdef0123456789abcdef";

async fn fake_portal() -> (
    Egress,
    mpsc::UnboundedReceiver<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    tokio::task::JoinHandle<()>,
) {
    let url = Url::parse(&format!("portal://{KEY}@127.0.0.1:2000?morph=0")).unwrap();
    let (_, tls, _) = crate::common::new_server_configs_with_reload_interval(
        &url,
        Duration::from_secs(3600),
        crate::common::Logger,
    )
    .unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let egress = Egress::new(
        Url::parse(&format!(
            "egress://{KEY}@{}/tcp:{}?morph=0&pin={pin}",
            address.ip(),
            address.port()
        ))
        .unwrap(),
        crate::common::Logger,
    )
    .unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.clone());
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(stream).await {
                    let mut auth = [0; 16];
                    if stream.read_exact(&mut auth).await.is_ok()
                        && stream.write_all(&[0]).await.is_ok()
                        && stream.flush().await.is_ok()
                    {
                        let _ = tx.send(stream);
                    }
                }
            });
        }
    });
    (egress, rx, task)
}

async fn receive(
    rx: &mut mpsc::UnboundedReceiver<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn growth_obeys_max_and_disconnects_only_reseed_when_empty() {
    let (mut egress, mut rx, server) = fake_portal().await;
    egress.tls_pool_max = 2;
    let shutdown = egress.forward.shutdown.clone();
    let task = tokio::spawn(async move { egress.maintain_tls().await });
    let mut seed = receive(&mut rx).await;
    seed.write_all(&[0]).await.unwrap();
    seed.flush().await.unwrap();
    let mut a = receive(&mut rx).await;
    let b = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    a.write_all(&[0]).await.unwrap();
    a.flush().await.unwrap();
    let c = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    drop(b);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    drop(c);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err()
    );
    let replacement = tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await
        .unwrap()
        .unwrap();
    drop(replacement);
    drop(seed);
    drop(a);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn egress_ttl_expires_standby() {
    let (egress, mut rx, server) = fake_portal().await;
    let ttl = Duration::from_millis(200);
    let started = Instant::now();
    let task = tokio::spawn(pending_connection(
        egress.config.clone(),
        egress.tls.clone(),
        egress.credentials.egress_key,
        egress.forward.shutdown.clone(),
        ttl,
    ));
    let _stream = receive(&mut rx).await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        PendingResult::Expired
    ));
    assert!(started.elapsed() >= ttl);
    server.abort();
}

#[tokio::test]
async fn max_one_replaces_consumed_standby_without_exceeding_one() {
    let (mut egress, mut rx, server) = fake_portal().await;
    egress.tls_pool_max = 1;
    let ttl = Duration::from_millis(300);
    std::sync::Arc::get_mut(&mut egress.forward)
        .unwrap()
        .runtime
        .egress_tls_idle_ttl = ttl;
    let shutdown = egress.forward.shutdown.clone();
    let task = tokio::spawn(async move { egress.maintain_tls().await });
    let mut seed = receive(&mut rx).await;
    seed.write_all(&[0]).await.unwrap();
    seed.flush().await.unwrap();
    let replacement = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    // FlowStart ends Egress standby TTL even while Target is still incomplete.
    tokio::time::sleep(ttl + Duration::from_millis(50)).await;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = crate::protocol::Target::Ip(target.local_addr().unwrap());
    seed.write_all(&crate::protocol::encode_target(&address).unwrap())
        .await
        .unwrap();
    seed.flush().await.unwrap();
    let (_socket, _) = tokio::time::timeout(Duration::from_secs(2), target.accept())
        .await
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        crate::protocol::read_flow_result(&mut seed),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        crate::protocol::SetupResult::from(result),
        crate::protocol::SetupResult::Ready
    );
    drop(seed);
    drop(replacement);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn idle_growth_decays_to_a_single_seed() {
    let (mut egress, mut rx, server) = fake_portal().await;
    std::sync::Arc::get_mut(&mut egress.forward)
        .unwrap()
        .runtime
        .egress_tls_idle_ttl = Duration::from_millis(500);
    let shutdown = egress.forward.shutdown.clone();
    let task = tokio::spawn(async move { egress.maintain_tls().await });
    let mut initial = receive(&mut rx).await;
    initial.write_all(&[0]).await.unwrap();
    initial.flush().await.unwrap();
    let a = receive(&mut rx).await;
    let b = receive(&mut rx).await;

    let seed = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    drop(initial);
    drop(a);
    drop(b);
    drop(seed);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}
