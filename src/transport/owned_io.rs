// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Asynchronous I/O traits and flush-aware reads.

use std::future::{Future, poll_fn};
use std::io;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) trait AsyncReadAny: AsyncRead + Send + Unpin {}

impl<T: AsyncRead + Send + Unpin> AsyncReadAny for T {}

pub(crate) trait AsyncWriteAny: AsyncWrite + Send + Unpin {}

impl<T: AsyncWrite + Send + Unpin> AsyncWriteAny for T {}

pub(crate) async fn read_with_flush<T>(
    read: impl Future<Output = io::Result<T>>,
    writer: &mut (impl AsyncWrite + Unpin),
) -> io::Result<T> {
    tokio::pin!(read);
    match poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await {
        Poll::Ready(result) => result,
        Poll::Pending => {
            writer.flush().await?;
            read.await
        }
    }
}

#[cfg(test)]
#[path = "../tests/transport/owned_io.rs"]
mod tests;
