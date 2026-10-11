// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress registration ordering, target dialing barriers, and online lifecycle tests.

use super::*;
use crate::common::{LogLevel, Logger};
use crate::protocol::{AUTH_EXPORTER_LABEL, AuthTransport, Credentials};
use url::Url;

#[tokio::test]
async fn accepted_barrier_prevents_dial_when_business_stream_arrives_first() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    let url = Url::parse(&format!("portal://{KEY}@127.0.0.1:2000")).unwrap();
    let (_, tls, mut quic) = crate::common::new_server_configs_with_reload_interval(
        &url,
        std::time::Duration::from_secs(3600),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    let limits = crate::transport::transport_flow_control().unwrap();
    let transport = Arc::get_mut(&mut quic.transport).unwrap();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .receive_window((64 * 1024u32).into())
        .stream_receive_window(limits.stream_receive_window.into());
    let endpoint = quinn::Endpoint::server(quic, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let egress = Egress::new(
        Url::parse(&format!("egress://{KEY}@{address}?pin={pin}")).unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let telemetry = egress.forward.telemetry.clone();
    let mut events = telemetry.event_receiver();
    let task = tokio::spawn(async move { egress.registered_connection().await });
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let (mut auth_send, mut auth_recv) = connection.accept_bi().await.unwrap();
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, b"")
        .unwrap();
    assert_eq!(
        crate::protocol::read_auth_frame(
            &mut auth_recv,
            &Credentials::from_shared_key(KEY.as_bytes()).unwrap(),
            AuthTransport::Quic,
            &exporter
        )
        .await
        .unwrap(),
        crate::protocol::ConnectionRole::Egress
    );
    auth_recv.read_to_end(0).await.unwrap();
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut request = vec![0];
    request.extend(
        crate::protocol::encode_target(&crate::protocol::Target::Ip(target.local_addr().unwrap()))
            .unwrap(),
    );
    send.write_all(&request).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(60), target.accept())
            .await
            .is_err()
    );
    assert_eq!(
        telemetry.snapshot_receiver().borrow().egress_online,
        Some(false)
    );
    auth_send.write_all(&[0]).await.unwrap();
    auth_send.finish().unwrap();
    let (_target, _) = tokio::time::timeout(std::time::Duration::from_secs(2), target.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::protocol::SetupResult::from(
            crate::protocol::read_flow_result(&mut recv).await.unwrap()
        ),
        crate::protocol::SetupResult::Ready
    );
    assert_eq!(
        telemetry.snapshot_receiver().borrow().egress_online,
        Some(true)
    );
    connection.close(0u32.into(), b"test");
    task.await.unwrap().unwrap();
    assert_eq!(
        telemetry.snapshot_receiver().borrow().egress_online,
        Some(false)
    );
    endpoint.wait_idle().await;
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, crate::telemetry::Event::Diagnostic(_)),
            "normal connection lifecycle emitted a diagnostic"
        );
    }
}
