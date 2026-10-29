// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Exporter-bound Egress authentication and the ACCEPTED registration barrier.

use anyhow::{Context, Result};
use tokio::time::{Instant, timeout_at};

use crate::protocol::{AUTH_EXPORTER_LABEL, AuthTransport, encode_auth_frame};

pub(super) async fn register(
    connection: &quinn::Connection,
    key: [u8; 32],
    deadline: Instant,
) -> Result<()> {
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter failed: {e:?}"))?;
    let accepted = timeout_at(deadline, async {
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(&encode_auth_frame(key, AuthTransport::Quic, &exporter))
            .await?;
        send.finish()?;
        let registration = async {
            let mut byte = [0];
            recv.read_exact(&mut byte).await?;
            recv.read_to_end(0).await?;
            Ok::<_, anyhow::Error>(byte[0])
        };
        tokio::pin!(registration);
        let mut discarded: u64 = 0;
        loop {
            tokio::select! {
                biased;
                // The registration receipt outranks the datagram drain: a
                // flood of pre-auth datagrams must not postpone it.
                result = &mut registration => break result,
                datagram = connection.read_datagram() => {
                    datagram?;
                    discarded += 1;
                    if discarded.is_multiple_of(64) {
                        tokio::task::yield_now().await;
                    }
                },
            }
        }
    })
    .await
    .context("registration timeout")??;
    match accepted {
        0 => {}
        1 => anyhow::bail!("Egress registration rejected: busy"),
        _ => anyhow::bail!("invalid Egress registration reply"),
    }
    Ok(())
}
