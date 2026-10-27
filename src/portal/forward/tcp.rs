// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP target dialing, Egress bridging, half-close relay, and traffic accounting.

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::portal::egress;
use crate::protocol::{SetupResult, Target};
use crate::vector::{BoxReader, BoxWriter};

use super::{ActiveFlow, Forwarder, Incoming, Outlet};

impl Forwarder {
    pub(super) async fn tcp(
        &self,
        mut incoming: Incoming,
        target: &Target,
        cancel: CancellationToken,
    ) -> Result<()> {
        let dial = async {
            match &self.outbound {
                Outlet::Network(dialer) => {
                    let target = dialer
                        .dial_tcp_target(target, self.runtime.tcp_dial_timeout)
                        .await?;
                    let (read, write) = target.into_split();
                    Ok::<_, anyhow::Error>((
                        Box::pin(read) as BoxReader,
                        Box::pin(write) as BoxWriter,
                        None,
                    ))
                }
                Outlet::Egress(registry) => {
                    let tunnel = tokio::time::timeout(
                        crate::common::flow_setup_timeout(),
                        egress::open_tcp(registry, target),
                    )
                    .await
                    .context("Egress TCP setup timeout")??;
                    let (r, w, guard) = tunnel.into_parts();
                    Ok((r, w, Some(guard)))
                }
            }
        };
        let dialed = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = self.shutdown.cancelled() => return Ok(()),
            closed = incoming.closed() => { closed?; return Ok(()); },
            result = dial => result,
        };
        let (mut target_read, mut target_write, _guard) = match dialed {
            Ok(parts) => parts,
            Err(error) => {
                let _ = incoming
                    .result(
                        error
                            .downcast_ref::<crate::vector::OpenFlowError>()
                            .and_then(|e| e.setup_result())
                            .unwrap_or(SetupResult::DialFailed),
                    )
                    .await;
                return Err(error);
            }
        };
        incoming.result(SetupResult::Ready).await?;
        let _active = ActiveFlow::new(self.stats.clone(), false);
        let (mut client_read, mut client_write, _client_guard) = incoming.into_tcp();
        let upload = async {
            let mut buffer = self.buffers.get_tcp_buffer();
            loop {
                let n = crate::transport::read_with_flush(
                    client_read.read(&mut buffer),
                    &mut target_write,
                )
                .await?;
                if n == 0 {
                    drop(buffer);
                    target_write.shutdown().await?;
                    return Ok::<_, anyhow::Error>(());
                }
                if let Some(rate) = &self.rate {
                    rate.wait_read(n as i64).await;
                }
                target_write.write_all(&buffer[..n]).await?;
                self.stats
                    .tcp_upload_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        };
        let download = async {
            let mut buffer = self.buffers.get_tcp_buffer();
            loop {
                let n = crate::transport::read_with_flush(
                    target_read.read(&mut buffer),
                    &mut client_write,
                )
                .await?;
                if n == 0 {
                    drop(buffer);
                    client_write.shutdown().await?;
                    return Ok::<_, anyhow::Error>(());
                }
                if let Some(rate) = &self.rate {
                    rate.wait_write(n as i64).await;
                }
                client_write.write_all(&buffer[..n]).await?;
                self.stats
                    .tcp_download_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        };
        tokio::pin!(upload);
        tokio::pin!(download);
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            _ = self.shutdown.cancelled() => Ok(()),
            result = async {
                tokio::select! {
                    result = &mut upload => {
                        result?;
                        tokio::time::timeout(self.runtime.tcp_read_timeout, &mut download)
                            .await.context("TCP half-close timeout")?
                    },
                    result = &mut download => {
                        result?;
                        tokio::time::timeout(self.runtime.tcp_read_timeout, &mut upload)
                            .await.context("TCP half-close timeout")?
                    },
                }
            } => result,
        }
    }
}
