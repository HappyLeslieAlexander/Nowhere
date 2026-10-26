// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Flush-aware reads preserve ready, pending, and error behavior.

use std::pin::Pin;
use std::task::Context;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[derive(Default)]
struct Writer {
    flushed: usize,
    fail_flush: bool,
    payload: Vec<u8>,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = bytes.len().min(2);
        self.payload.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushed += 1;
        Poll::Ready(if self.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ready_reads_do_not_flush_and_borrowed_writes_handle_short_writes() {
    let mut writer = Writer::default();
    let mut reader = &b"payload"[..];
    let mut buffer = [0; 16];
    let n = read_with_flush(reader.read(&mut buffer), &mut writer)
        .await
        .unwrap();
    writer.write_all(&buffer[..n]).await.unwrap();
    assert_eq!(writer.payload, b"payload");
    assert_eq!(writer.flushed, 0);
    assert_eq!(
        read_with_flush(reader.read(&mut buffer), &mut writer)
            .await
            .unwrap(),
        0
    );
    assert_eq!(writer.flushed, 0);
}

#[tokio::test]
async fn pending_reads_flush_before_resuming() {
    let mut writer = Writer::default();
    let mut polled = false;
    let read = poll_fn(|_| {
        if std::mem::replace(&mut polled, true) {
            Poll::Ready(Ok(7))
        } else {
            Poll::Pending
        }
    });
    assert_eq!(read_with_flush(read, &mut writer).await.unwrap(), 7);
    assert_eq!(writer.flushed, 1);
}

#[tokio::test]
async fn flush_and_read_errors_are_propagated() {
    let mut writer = Writer {
        fail_flush: true,
        ..Writer::default()
    };
    let read = std::future::pending::<io::Result<usize>>();
    assert_eq!(
        read_with_flush(read, &mut writer).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(writer.flushed, 1);
    let read = std::future::ready(Err::<usize, _>(io::Error::from(
        io::ErrorKind::ConnectionReset,
    )));
    assert_eq!(
        read_with_flush(read, &mut writer).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(writer.flushed, 1);
}
