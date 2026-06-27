// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP request frame encoding and decoding.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::spec::{
    EffectiveProtocolSpec, PROXY_FRAME_VERSION, TcpFrameElement, tcp_request_padding_bytes,
};
use super::util::{TARGET_LEN_MAX, check_target_len, validate_target};

/// Reads a spec-derived TCP request frame and returns the target address.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<String> {
    let mut target: Option<String> = None;
    let mut padding: Option<Vec<u8>> = None;

    // Target and padding may appear in either order depending on the effective
    // spec, so validate once both fields are available.
    for element in protocol_spec.frame_layout.tcp {
        match element {
            TcpFrameElement::Version => read_version(reader).await?,
            TcpFrameElement::Target => {
                target = Some(read_target(reader).await?);
                if let (Some(target), Some(padding)) = (&target, &padding) {
                    validate_padding(protocol_spec, target, padding)?;
                }
            }
            TcpFrameElement::Padding => {
                padding = Some(read_padding(reader, protocol_spec).await?);
                if let (Some(target), Some(padding)) = (&target, &padding) {
                    validate_padding(protocol_spec, target, padding)?;
                }
            }
        }
    }

    let target =
        target.ok_or_else(|| anyhow::anyhow!("protocol::request::read_request: missing target"))?;
    if padding.is_none() {
        bail!("protocol::request::read_request: missing padding");
    }
    Ok(target)
}

async fn read_version<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut version = [0u8; 1];
    reader
        .read_exact(&mut version)
        .await
        .context("protocol::request::read_request: failed to read version")?;
    if version[0] != PROXY_FRAME_VERSION {
        bail!(
            "protocol::request::read_request: unsupported frame version: {}",
            version[0]
        );
    }
    Ok(())
}

async fn read_target<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut header = [0u8; 2];
    reader
        .read_exact(&mut header)
        .await
        .context("protocol::request::read_request: failed to read target length")?;

    let target_len = u16::from_be_bytes(header) as usize;
    if target_len == 0 || target_len > TARGET_LEN_MAX {
        bail!("protocol::request::read_request: invalid target length: {target_len}");
    }
    let mut target = vec![0; target_len];
    reader
        .read_exact(&mut target)
        .await
        .context("protocol::request::read_request: failed to read target")?;

    let addr = String::from_utf8(target)
        .context("protocol::request::read_request: target address is not valid UTF-8")?;
    validate_target(&addr).map_err(|e| anyhow::anyhow!("protocol::request::read_request: {e}"))?;
    Ok(addr)
}

async fn read_padding<R: AsyncRead + Unpin>(
    reader: &mut R,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<Vec<u8>> {
    let mut header = [0u8; 1];
    reader
        .read_exact(&mut header)
        .await
        .context("protocol::request::read_request: failed to read padding length")?;
    let padding_len = header[0];
    if padding_len != protocol_spec.tcp_padding_len {
        bail!(
            "protocol::request::read_request: invalid padding length: expected {}, got {padding_len}",
            protocol_spec.tcp_padding_len
        );
    }

    let mut padding = vec![0; padding_len as usize];
    reader
        .read_exact(&mut padding)
        .await
        .context("protocol::request::read_request: failed to read padding")?;
    Ok(padding)
}

fn validate_padding(
    protocol_spec: &EffectiveProtocolSpec,
    target_addr: &str,
    padding: &[u8],
) -> Result<()> {
    let expected = tcp_request_padding_bytes(protocol_spec, target_addr);
    if padding != expected {
        bail!("protocol::request::read_request: invalid padding");
    }
    Ok(())
}

/// Encodes a TCP request frame in the effective spec's field order.
pub fn write_request_frame(
    target_addr: &str,
    protocol_spec: &EffectiveProtocolSpec,
) -> Result<Vec<u8>> {
    check_target_len("protocol::request::write_request_frame", target_addr)?;
    validate_target(target_addr)
        .map_err(|e| anyhow::anyhow!("protocol::request::write_request_frame: {e}"))?;

    let target_len = (target_addr.len() as u16).to_be_bytes();
    let padding = tcp_request_padding_bytes(protocol_spec, target_addr);
    let mut buf = Vec::with_capacity(1 + target_len.len() + target_addr.len() + 1 + padding.len());
    // Keep the writer layout-driven to preserve parity with the reader and
    // spec-derived Swift mirror.
    for element in protocol_spec.frame_layout.tcp {
        match element {
            TcpFrameElement::Version => buf.push(PROXY_FRAME_VERSION),
            TcpFrameElement::Target => {
                buf.extend_from_slice(&target_len);
                buf.extend_from_slice(target_addr.as_bytes());
            }
            TcpFrameElement::Padding => {
                buf.push(protocol_spec.tcp_padding_len);
                buf.extend_from_slice(&padding);
            }
        }
    }
    Ok(buf)
}

#[cfg(test)]
#[path = "../tests/protocol/request.rs"]
mod tests;
