// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Forwarding outcomes for cancellation, idle expiry, admission, and target failure.

use super::*;
use crate::portal::forward::{Forwarder, Incoming};
use crate::telemetry::Event;
use crate::vector::TcpTunnelGuard;
use std::sync::atomic::Ordering;

fn forwarder() -> Arc<Forwarder> {
    let portal = Portal::new(
        Url::parse(&format!("portal://{KEY}@127.0.0.1:2000")).unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let mut forward = Arc::try_unwrap(portal.inner).ok().unwrap().forward;
    Arc::get_mut(&mut forward).unwrap().runtime.udp_idle_timeout = Duration::from_millis(20);
    forward
}

async fn start(
    forward: Arc<Forwarder>,
    kind: u8,
    target: &Target,
) -> (tokio::io::DuplexStream, JoinHandle<()>) {
    let (mut client, server) = tokio::io::duplex(512);
    let (reader, writer) = tokio::io::split(server);
    let task = tokio::spawn(forward.serve(
        Incoming::Tls {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            guard: TcpTunnelGuard {
                _carrier: None,
                _flow: None,
            },
        },
        CancellationToken::new(),
    ));
    let mut request = vec![kind];
    request.extend(crate::protocol::encode_target(target).unwrap());
    client.write_all(&request).await.unwrap();
    (client, task)
}

fn finished(events: &mut tokio::sync::broadcast::Receiver<Event>) -> serde_json::Value {
    loop {
        if let Event::AccessFinish(finish) = events.try_recv().unwrap() {
            return serde_json::to_value(finish).unwrap();
        }
    }
}

#[tokio::test]
async fn cancelled_tcp_and_idle_udp_are_not_reported_as_success() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (kind, target, expected) in [
        (0, Target::Ip(tcp.local_addr().unwrap()), "cancelled"),
        (1, Target::Ip(udp.local_addr().unwrap()), "idle_timeout"),
    ] {
        let forward = forwarder();
        let mut events = forward.telemetry.event_receiver();

        let (mut client, task) = start(forward.clone(), kind, &target).await;
        assert_eq!(
            SetupResult::from(
                crate::protocol::read_flow_result(&mut client)
                    .await
                    .unwrap()
            ),
            SetupResult::Ready,
        );
        if kind == 0 {
            forward.shutdown.cancel();
        }
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        let finish = finished(&mut events);
        assert_eq!(finish["result"], expected);
        assert_eq!(finish.as_object().unwrap().len(), 4);
        assert_eq!(forward.stats.tcp_active.load(Ordering::Relaxed), 0);
        assert_eq!(forward.stats.udp_active.load(Ordering::Relaxed), 0);
        assert_eq!(forward.flows.available_permits(), 1024);
    }
}

#[tokio::test]
async fn flow_limit_and_dial_failure_publish_distinct_outcomes() {
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Target::Ip(unused.local_addr().unwrap());
    drop(unused);
    for (limited, result, reason) in [
        (true, SetupResult::FlowLimit, "resource_limit"),
        (false, SetupResult::DialFailed, "connection_refused"),
    ] {
        let forward = forwarder();
        let mut events = forward.telemetry.event_receiver();

        let held = if limited {
            Some(
                forward
                    .flows
                    .clone()
                    .acquire_many_owned(1024)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let (mut client, task) = start(forward.clone(), 0, &target).await;
        assert_eq!(
            SetupResult::from(
                crate::protocol::read_flow_result(&mut client)
                    .await
                    .unwrap()
            ),
            result,
        );
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        let finish = finished(&mut events);
        assert_eq!(finish["result"], reason);
        assert_eq!(forward.stats.tcp_active.load(Ordering::Relaxed), 0);
        drop(held);
        assert_eq!(forward.flows.available_permits(), 1024);
    }
}
