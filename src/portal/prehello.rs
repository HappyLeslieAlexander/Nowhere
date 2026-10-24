// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Silent Morph ClientHello acceptance and bounded rejected-input disposal.

use std::future::{pending, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::server::{Accepted, Acceptor};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;

const READ_CHUNK: usize = 4096;
const DISCARD_BYTES: usize = 64 * 1024;
const DISCARD_READS: usize = 64;

struct Reader<'a, 'b, R> {
    stream: &'a mut R,
    cx: &'a mut Context<'b>,
}

impl<R: AsyncRead + Unpin> io::Read for Reader<'_, '_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let len = bytes.len().min(READ_CHUNK);
        let mut buffer = ReadBuf::new(&mut bytes[..len]);
        match Pin::new(&mut self.stream).poll_read(self.cx, &mut buffer) {
            Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

pub(super) async fn accept<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Option<Accepted>> {
    let mut acceptor = Acceptor::default();
    loop {
        let read = poll_fn(|cx| match acceptor.read_tls(&mut Reader { stream, cx }) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        })
        .await;
        match read {
            Ok(0) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
            Ok(_) => match acceptor.accept() {
                Ok(Some(accepted)) => return Ok(Some(accepted)),
                Ok(None) => {}
                Err((_error, _alert)) => return Ok(None),
            },
        }
        tokio::task::yield_now().await;
    }
}

pub(super) fn finish_authentication(stream: &TcpStream, deadline: Instant) -> io::Result<bool> {
    if Instant::now() >= deadline {
        return Ok(false);
    }
    socket2::SockRef::from(stream).set_linger(None)?;
    if Instant::now() >= deadline {
        stream.set_zero_linger()?;
        return Ok(false);
    }
    Ok(true)
}

pub(super) async fn discard<R: AsyncRead + Unpin>(mut stream: R) -> io::Result<()> {
    let mut buffer = [0; READ_CHUNK];
    let mut remaining = DISCARD_BYTES;
    for _ in 0..DISCARD_READS {
        let len = buffer.len().min(remaining);
        let count = stream.read(&mut buffer[..len]).await?;
        remaining -= count;
        if count == 0 || remaining == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    pending().await
}

#[cfg(test)]
#[path = "../tests/portal/prehello.rs"]
mod tests;
