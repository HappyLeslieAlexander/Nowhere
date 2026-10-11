// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry frame limits, cancellation-safe reads, write timeouts, and command deadlines tests.

use super::*;
use crate::telemetry::{ClientMessage, MAX_FRAME_SIZE, Subscription};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn framing_round_trips_and_rejects_oversize_lengths() {
    let (mut left, mut right) = tokio::io::duplex(MAX_FRAME_SIZE + 16);
    let message = ClientMessage::Subscribe {
        subscription: Subscription::Detail,
    };
    write_frame(&mut left, &message).await.unwrap();
    let mut framed = FrameReader::new(&mut right);
    let decoded: ClientMessage = framed.next().await.unwrap();
    assert_eq!(decoded, message);

    let (mut left, mut right) = tokio::io::duplex(16);
    left.write_u32((MAX_FRAME_SIZE + 1) as u32).await.unwrap();
    let mut framed = FrameReader::new(&mut right);
    let result = framed.next::<ClientMessage>().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn frame_reader_survives_cancelled_partial_reads() {
    let message = ClientMessage::Subscribe {
        subscription: Subscription::Detail,
    };
    let payload = serde_json::to_vec(&message).unwrap();
    let length = (payload.len() as u32).to_be_bytes();
    let (mut writer, reader) = tokio::io::duplex(MAX_FRAME_SIZE + 16);
    let mut framed = FrameReader::new(reader);

    writer.write_all(&length[..2]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), framed.next::<ClientMessage>())
            .await
            .is_err()
    );
    writer.write_all(&length[2..]).await.unwrap();
    writer.write_all(&payload[..1]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), framed.next::<ClientMessage>())
            .await
            .is_err()
    );
    writer.write_all(&payload[1..]).await.unwrap();

    assert_eq!(framed.next::<ClientMessage>().await.unwrap(), message);
}

#[tokio::test]
async fn slow_frame_writes_time_out() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    let payload = vec![b'x'; 1_024];
    let result = write_payload_with_timeout(&mut writer, &payload, Duration::from_millis(10)).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timed out"));
}

#[tokio::test]
async fn command_length_and_partial_frame_deadline_are_bounded() {
    let (mut writer, reader) = tokio::io::duplex(2048);
    writer.write_u32(1025).await.unwrap();
    let mut reader = FrameReader::new(reader);
    assert!(reader.next_command().await.is_err());
    let (mut writer, reader) = tokio::io::duplex(16);
    writer.write_all(&[0]).await.unwrap();
    let mut reader = FrameReader::new(reader);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), reader.next_command())
            .await
            .is_err()
    );
    reader.started_at = Some(tokio::time::Instant::now() - Duration::from_secs(6));
    assert!(reader.next_command().await.is_err());
}
