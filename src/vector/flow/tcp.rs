// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP tunnel setup and bidirectional relay.

use tokio::io::AsyncReadExt;

use crate::transport::read_with_flush;

use super::*;

pub(crate) struct TcpTunnel {
    reader: BoxReader,
    writer: BoxWriter,
    _guard: TcpTunnelGuard,
    carrier: Carrier,
}

pub(crate) struct TcpTunnelGuard {
    pub(crate) _flow: Option<FlowGuard>,
}

impl TcpTunnel {
    pub(crate) fn new(
        reader: BoxReader,
        writer: BoxWriter,
        carrier: Carrier,
        guard: TcpTunnelGuard,
    ) -> Self {
        Self {
            reader,
            writer,
            _guard: guard,
            carrier,
        }
    }

    pub(in crate::vector) fn socks_reply(&self) -> u8 {
        REPLY_SUCCEEDED
    }

    pub(crate) fn carrier(&self) -> Carrier {
        self.carrier
    }

    pub(crate) fn into_parts(self) -> (BoxReader, BoxWriter, TcpTunnelGuard) {
        (self.reader, self.writer, self._guard)
    }

    pub(crate) async fn close(mut self) -> std::io::Result<()> {
        self.writer.shutdown().await
    }
}

impl AsyncRead for TcpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.reader.as_mut().poll_read(cx, buffer)
    }
}

impl AsyncWrite for TcpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writer.as_mut().poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_shutdown(cx)
    }
}

pub(crate) async fn open_tcp(
    client: Arc<PortalClient>,
    target: &Target,
) -> std::result::Result<TcpTunnel, OpenFlowError> {
    client.open_tcp(target).await
}

pub(in crate::vector) async fn relay_tcp(
    vector: Arc<VectorInner>,
    client: TcpStream,
    mut tunnel: TcpTunnel,
) -> Result<()> {
    {
        let (mut client_read, mut client_write) = client.into_split();
        let client_to_portal = async {
            let mut buffer = vector.buffers.get_tcp_buffer();
            loop {
                let read =
                    read_with_flush(client_read.read(&mut buffer), &mut tunnel.writer).await?;
                if read == 0 {
                    drop(buffer);
                    tunnel.writer.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                if let Some(rate) = &vector.rate_limiter {
                    rate.wait_read(read as i64).await;
                }
                tunnel.writer.write_all(&buffer[..read]).await?;

                vector
                    .stats
                    .tcp_upload_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
            }
        };
        let portal_to_client = async {
            let mut buffer = vector.buffers.get_tcp_buffer();
            loop {
                let read =
                    read_with_flush(tunnel.reader.read(&mut buffer), &mut client_write).await?;
                if read == 0 {
                    drop(buffer);
                    client_write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                if let Some(rate) = &vector.rate_limiter {
                    rate.wait_write(read as i64).await;
                }
                client_write.write_all(&buffer[..read]).await?;

                vector
                    .stats
                    .tcp_download_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
            }
        };
        tokio::pin!(client_to_portal);
        tokio::pin!(portal_to_client);
        tokio::select! {
            result = &mut client_to_portal => match result {
                Ok(()) => timeout(tcp_read_timeout(), &mut portal_to_client).await.unwrap_or_else(|error| Err(error.into())),
                Err(error) => Err(error),
            },
            result = &mut portal_to_client => match result {
                Ok(()) => timeout(tcp_read_timeout(), &mut client_to_portal).await.unwrap_or_else(|error| Err(error.into())),
                Err(error) => Err(error),
            },
        }
    }
}

#[cfg(test)]
#[path = "../../tests/vector/flow/tcp.rs"]
mod tests;
