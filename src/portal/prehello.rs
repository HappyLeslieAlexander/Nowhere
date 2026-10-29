// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Silent Morph ClientHello acceptance and authenticated socket handoff.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::server::{Accepted, Acceptor};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;

const READ_CHUNK: usize = 4096;

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
    // A legitimate ClientHello is far below this; rustls would otherwise
    // buffer up to 16 MB of handshake message per admission slot.
    const ACCEPTED_BUFFER_MAX: usize = 64 * 1024;
    let mut acceptor = Acceptor::default();
    let mut buffered = 0usize;
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
            Ok(count) => {
                buffered += count;
                if buffered > ACCEPTED_BUFFER_MAX {
                    return Ok(None);
                }
                match acceptor.accept() {
                    Ok(Some(accepted)) => return Ok(Some(accepted)),
                    Ok(None) => {}
                    Err((_error, _alert)) => return Ok(None),
                }
            }
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

#[cfg(test)]
#[path = "../tests/portal/prehello.rs"]
mod tests;
