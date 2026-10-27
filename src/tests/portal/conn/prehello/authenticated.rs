// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated prelude commit boundaries, strict authentication and silent replay rejection.

use crate::transport::{AuthenticatedPrelude, ClientPrelude};

use super::*;

fn authentication(counter: u64) -> AuthenticatedPrelude {
    AuthenticatedPrelude {
        identity: 0x0123_4567_89ab_cdef,
        counter,
    }
}

fn hello(h: &Harness, alpn: &[u8]) -> Vec<u8> {
    let mut client = rustls::ClientConnection::new(
        Arc::new(tls_config(h, alpn)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
}

async fn capture(h: &Harness, authentication: AuthenticatedPrelude, payload: &[u8]) -> Vec<u8> {
    let (sender, mut capture) = tokio::io::duplex(76 + payload.len());
    let mut sender = MorphTcpStream::connect_authenticated_for_test(
        sender,
        h.inner.morph_keys.clone().unwrap(),
        [0x55; 64],
        [0x23; 12],
        authentication,
    )
    .await
    .unwrap();
    sender.write_all(payload).await.unwrap();
    let mut bytes = vec![0; 76 + payload.len()];
    capture.read_exact(&mut bytes).await.unwrap();
    bytes
}

async fn silent(h: &Harness, bytes: &[u8], split: bool) {
    let start = Instant::now();
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    if split {
        write_segments(&mut stream, bytes).await;
    } else {
        stream.write_all(bytes).await.unwrap();
    }
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    let result = tokio::time::timeout(
        TIMEOUT + Duration::from_secs(2),
        stream.read_to_end(&mut response),
    )
    .await
    .unwrap();
    assert_silent_close(result);
    assert!(response.is_empty());
    assert!(start.elapsed() >= TIMEOUT);
}

async fn receives_tls(h: &Harness, bytes: &[u8]) {
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    write_segments(&mut stream, bytes).await;
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        1
    );
}

async fn rejects_after_hello(h: &Harness, bytes: &[u8]) {
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    write_segments(&mut stream, bytes).await;
    let mut response = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap();
    assert_post_accept_close(result, &response);
    wait_active(h, 0).await;
}

#[tokio::test]
async fn rejected_input_stops_reading_until_original_deadline() {
    let timeout = Duration::from_secs(2);
    let h = Harness::with_handshake_timeout(true, timeout).await;
    for (index, (case, reset)) in [
        ("prelude", false),
        ("prelude", true),
        ("replay-precheck", false),
        ("hello", false),
        ("replay-commit", false),
    ]
    .into_iter()
    .enumerate()
    {
        let token = authentication(index as u64 + 1);
        let payload = if case == "hello" {
            vec![0xff]
        } else {
            hello(&h, crate::protocol::ALPN)
        };
        let mut bytes = capture(&h, token, &payload).await;
        if case == "prelude" {
            bytes[0] ^= 1;
            bytes.truncate(76);
        }
        let replay = h.inner.prelude_replay.as_ref().unwrap();
        if case == "replay-precheck" {
            assert!(replay.commit(token));
            bytes.truncate(76);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut client = client.unwrap();
        let (server, peer) = accepted.unwrap();
        let server = server.into_std().unwrap();
        let observer = TcpStream::from_std(server.try_clone().unwrap()).unwrap();
        let server = TcpStream::from_std(server).unwrap();
        server.set_zero_linger().unwrap();
        let admission = h
            .inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        let accepted_at = Instant::now() - timeout / 2;
        let deadline = accepted_at + timeout;
        let connection = crate::portal::conn::tcp(
            h.inner.clone(),
            server,
            admission,
            accepted_at,
            Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        );
        tokio::pin!(connection);
        let last = (case == "replay-commit").then(|| bytes.pop().unwrap());
        client.write_all(&bytes).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut connection)
                .await
                .is_err()
        );
        if let Some(last) = last {
            assert!(replay.commit(token));
            client.write_all(&[last]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut connection)
                    .await
                    .is_err()
            );
        }
        client.write_all(&[0xa5; 32]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut connection)
                .await
                .is_err()
        );
        let mut unread = [0; 32];
        let count = tokio::time::timeout(Duration::from_millis(100), observer.peek(&mut unread))
            .await
            .unwrap()
            .unwrap();
        assert!(count > 0, "{case}");
        assert_eq!(&unread[..count], &[0xa5; 32][..count], "{case}");
        drop(observer);
        let mut response = Vec::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read_to_end(&mut response))
                .await
                .is_err()
        );
        assert!(response.is_empty(), "{case}");
        let client = if reset {
            client.set_zero_linger().unwrap();
            drop(client);
            None
        } else {
            client.shutdown().await.unwrap();
            Some(client)
        };
        assert!(
            tokio::time::timeout_at(deadline - Duration::from_millis(100), &mut connection)
                .await
                .is_err()
        );
        assert_eq!(h.inner.unauthenticated_admission.active(), 1, "{case}");
        assert!(matches!(
            tokio::time::timeout_at(deadline + Duration::from_millis(300), &mut connection)
                .await
                .unwrap()
                .unwrap(),
            crate::portal::conn::TcpOutcome::SilentPreHello
        ));
        assert!(Instant::now() >= deadline, "{case}");
        assert_eq!(h.inner.unauthenticated_admission.active(), 0, "{case}");
        if let Some(mut client) = client {
            assert_silent_close(
                tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
                    .await
                    .unwrap(),
            );
            assert!(response.is_empty(), "{case}");
        }
    }
    h.close().await;
}

#[tokio::test]
async fn accepted_authenticated_hello_commits_before_response_and_replay_stays_silent() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let token = authentication(1);
    let bytes = capture(&h, token, &hello(&h, crate::protocol::ALPN)).await;
    assert!(h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    receives_tls(&h, &bytes).await;
    assert!(!h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    silent(&h, &bytes, false).await;
    silent(&h, &bytes, true).await;
    wait_active(&h, 0).await;
    h.close().await;
}

#[tokio::test]
async fn bootstrap_and_malformed_or_truncated_hello_never_register() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let hello = hello(&h, crate::protocol::ALPN);
    for (index, payload) in [&[][..], &[0xff][..], &hello[..1], &hello[..hello.len() - 1]]
        .into_iter()
        .enumerate()
    {
        let token = authentication(index as u64 + 1);
        let bytes = capture(&h, token, payload).await;
        silent(&h, &bytes, true).await;
        assert!(h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    }
    h.close().await;
}

#[tokio::test]
async fn authenticated_counter_zero_is_rejected_before_valid_hello() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let bytes = capture(&h, authentication(0), &hello(&h, crate::protocol::ALPN)).await;
    silent(&h, &bytes, false).await;
    h.close().await;
}

#[tokio::test]
async fn accepted_hello_consumes_counter_when_later_alpn_check_fails() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let token = authentication(9);
    let bytes = capture(&h, token, &hello(&h, b"bad")).await;
    rejects_after_hello(&h, &bytes).await;
    assert!(!h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    silent(&h, &bytes, false).await;
    h.close().await;
}

#[tokio::test]
async fn concurrent_authenticated_connections_only_one_enters_tls() {
    let h = Harness::with_handshake_timeout(true, Duration::from_secs(2)).await;
    let token = authentication(100);
    let bytes = capture(&h, token, &hello(&h, crate::protocol::ALPN)).await;
    let mut streams = Vec::new();
    for _ in 0..16 {
        let mut stream = TcpStream::connect(h.tcp).await.unwrap();
        stream.write_all(&bytes[..76]).await.unwrap();
        streams.push(stream);
    }
    wait_active(&h, 16).await;
    assert!(h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    let mut tasks = tokio::task::JoinSet::new();
    for mut stream in streams {
        let payload = bytes[76..].to_vec();
        tasks.spawn(async move {
            stream.write_all(&payload).await.unwrap();
            let mut byte = [0];
            matches!(
                tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
                    .await
                    .unwrap(),
                Ok(1)
            )
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        accepted += usize::from(result.unwrap());
    }
    assert_eq!(accepted, 1);
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}

#[tokio::test]
async fn modified_prelude_prefix_and_tail_are_silent_even_with_valid_hello() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    for (counter, offset) in [(5, 0), (6, 32), (7, 63)] {
        let token = authentication(counter);
        let bytes = capture(&h, token, &hello(&h, crate::protocol::ALPN)).await;
        let mut modified = bytes.clone();
        modified[offset] ^= 1;
        silent(&h, &modified, false).await;
        assert!(h.inner.prelude_replay.as_ref().unwrap().precheck(token));
        receives_tls(&h, &bytes).await;
        silent(&h, &modified, true).await;
    }
    h.close().await;
}

#[tokio::test]
async fn legacy_prelude_with_valid_hello_is_silently_rejected() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let payload = hello(&h, crate::protocol::ALPN);
    let (sender, mut reader) = tokio::io::duplex(76 + payload.len());
    let mut sender =
        MorphTcpStream::connect_legacy_for_test(sender, h.inner.morph_keys.clone().unwrap())
            .await
            .unwrap();
    sender.write_all(&payload).await.unwrap();
    let mut bytes = vec![0; 76 + payload.len()];
    reader.read_exact(&mut bytes).await.unwrap();
    silent(&h, &bytes, false).await;
    silent(&h, &bytes, true).await;
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}

#[tokio::test]
async fn out_of_window_counter_with_valid_hello_is_silently_rejected() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let token = authentication(1);
    assert!(
        h.inner
            .prelude_replay
            .as_ref()
            .unwrap()
            .commit(authentication(1025))
    );
    let bytes = capture(&h, token, &hello(&h, crate::protocol::ALPN)).await;
    silent(&h, &bytes, false).await;
    h.close().await;
}

#[tokio::test]
async fn unbound_client_hello_can_be_modified_before_first_commit() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let token = authentication(6);
    let original = hello(&h, crate::protocol::ALPN);
    let offset = original
        .windows(9)
        .position(|bytes| bytes == [0, 16, 0, 6, 0, 4, 3, b'n', b'w'])
        .unwrap()
        + 7;
    let mut bytes = capture(&h, token, &original).await;
    for (index, (&before, &after)) in b"nw3".iter().zip(b"bad").enumerate() {
        bytes[76 + offset + index] ^= before ^ after;
    }
    rejects_after_hello(&h, &bytes).await;
    assert!(!h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    h.close().await;
}

#[tokio::test]
async fn fifo_eviction_preserves_established_flow_and_allows_identity_reregistration() {
    let h = Harness::new("direct", true).await;
    let client = h.client("tcp", true);
    let (target, echo) = tcp_echo().await;
    let mut tunnel = client.open_tcp(&target).await.unwrap();
    let replay = h.inner.prelude_replay.as_ref().unwrap();
    for identity in 0..16_385 {
        assert!(replay.commit(AuthenticatedPrelude {
            identity,
            counter: 1
        }));
    }
    tunnel.write_all(b"after eviction").await.unwrap();
    let mut received = [0; 14];
    tokio::time::timeout(Duration::from_secs(2), tunnel.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"after eviction");
    drop(tunnel);
    assert!(replay.commit(AuthenticatedPrelude {
        identity: 0,
        counter: 1
    }));
    client.close(Instant::now() + Duration::from_secs(1)).await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn authenticated_bootstrap_timeout_releases_admission_without_registration() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let identity = ClientPrelude::for_test(42, 0);
    let stream = TcpStream::connect(h.tcp).await.unwrap();
    let mut stream = MorphTcpStream::connect(stream, h.inner.morph_keys.clone(), &identity)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert_silent_close(result);
    assert!(bytes.is_empty());
    assert!(
        h.inner
            .prelude_replay
            .as_ref()
            .unwrap()
            .precheck(AuthenticatedPrelude {
                identity: 42,
                counter: 1
            })
    );
    wait_active(&h, 0).await;
    h.close().await;
}

#[tokio::test]
async fn portal_instance_restart_discards_replay_history() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let token = authentication(77);
    let bytes = capture(&h, token, &hello(&h, crate::protocol::ALPN)).await;
    receives_tls(&h, &bytes).await;
    assert!(!h.inner.prelude_replay.as_ref().unwrap().precheck(token));
    h.close().await;
    let restarted = Harness::with_handshake_timeout(true, TIMEOUT).await;
    assert!(
        restarted
            .inner
            .prelude_replay
            .as_ref()
            .unwrap()
            .precheck(token)
    );
    receives_tls(&restarted, &bytes).await;
    assert!(
        !restarted
            .inner
            .prelude_replay
            .as_ref()
            .unwrap()
            .precheck(token)
    );
    restarted.close().await;
}

#[tokio::test]
async fn portal_tcp_listeners_share_one_replay_registry() {
    let h = Harness::with_handshake_timeout(true, TIMEOUT).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let listener_task = tokio::spawn(crate::portal::runtime::tcp_loop(
        h.inner.clone(),
        listener,
        h.stop.clone(),
    ));
    let bytes = capture(&h, authentication(88), &hello(&h, crate::protocol::ALPN)).await;
    receives_tls(&h, &bytes).await;
    let start = Instant::now();
    let mut replay = TcpStream::connect(address).await.unwrap();
    replay.write_all(&bytes).await.unwrap();
    let mut response = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), replay.read_to_end(&mut response))
        .await
        .unwrap();
    assert_silent_close(result);
    assert!(response.is_empty());
    assert!(start.elapsed() >= TIMEOUT);
    h.close().await;
    listener_task.await.unwrap().unwrap();
}
