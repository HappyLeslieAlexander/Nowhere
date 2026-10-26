// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-stream reads retain partial framing state across cancellation.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::*;

#[tokio::test]
async fn cancelled_uot_read_retains_partial_length_header() {
    let (reader, mut writer) = tokio::io::duplex(64);
    let mut reader: BoxReader = Box::pin(reader);
    let mut state = UotReadState::default();
    let mut payload = Vec::new();

    writer.write_all(&[0]).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            state.read_packet(&mut reader, &mut payload),
        )
        .await
        .is_err()
    );
    assert_eq!(state.header_read, 1);

    writer.write_all(&[3, b'a', b'b', b'c']).await.unwrap();
    assert_eq!(
        state.read_packet(&mut reader, &mut payload).await.unwrap(),
        Some(3)
    );
    assert_eq!(payload, b"abc");
    assert_eq!(state.header_read, 0);
}

#[tokio::test]
async fn receive_storage_is_lazy_bounded_and_reused_after_partial_payload() {
    let (reader, mut writer) = tokio::io::duplex(128 * 1024);
    let mut reader: BoxReader = Box::pin(reader);
    let mut state = UotReadState::default();
    let mut payload = Vec::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            state.read_packet(&mut reader, &mut payload),
        )
        .await
        .is_err()
    );
    assert_eq!(payload.capacity(), 0);

    writer.write_all(&[0, 3, b'a']).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            state.read_packet(&mut reader, &mut payload),
        )
        .await
        .is_err()
    );
    writer.write_all(b"bc").await.unwrap();
    assert_eq!(
        state.read_packet(&mut reader, &mut payload).await.unwrap(),
        Some(3)
    );
    assert_eq!(payload, b"abc");

    for size in [32768, 32769, 65535, 0, 128, 65535] {
        let expected = vec![0x5a; size];
        writer
            .write_all(&(size as u16).to_be_bytes())
            .await
            .unwrap();
        writer.write_all(&expected).await.unwrap();
        assert_eq!(
            state.read_packet(&mut reader, &mut payload).await.unwrap(),
            Some(size)
        );
        assert_eq!(payload, expected);
        assert!(payload.capacity() <= u16::MAX as usize);
    }
    let allocation = payload.as_ptr();
    writer.write_all(&[0, 1, 42]).await.unwrap();
    assert_eq!(
        state.read_packet(&mut reader, &mut payload).await.unwrap(),
        Some(1)
    );
    assert_eq!(payload.as_ptr(), allocation);
}
