// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Payload-oriented direct and SOCKS5 UDP socket facade.

use std::io::ErrorKind;

use anyhow::{Context, Result, bail};
use tokio::net::{TcpStream, UdpSocket};

use crate::transport::{BufferLease, get_udp_buffer};

use super::protocol::parse_udp_header;

pub(crate) enum OutboundUdpSocket {
    Direct(UdpSocket),
    Socks(SocksUdpAssociation),
}

impl OutboundUdpSocket {
    pub(crate) async fn send(&self, payload: &[u8], packet: &mut Vec<u8>) -> Result<usize> {
        match self {
            Self::Direct(socket) => socket.send(payload).await.map_err(Into::into),
            Self::Socks(association) => association.send(payload, packet).await,
        }
    }

    pub(crate) async fn recv(&self) -> Result<Vec<u8>> {
        loop {
            match self {
                Self::Direct(socket) => socket.readable().await?,
                Self::Socks(association) => association.readable().await?,
            }
            if let Some(payload) = self.try_recv(get_udp_buffer())? {
                return Ok(payload);
            }
        }
    }

    fn try_recv(&self, mut buffer: BufferLease) -> Result<Option<Vec<u8>>> {
        let received = match self {
            Self::Direct(socket) => socket.try_recv(&mut buffer).map_err(Into::into),
            Self::Socks(association) => association
                .socket
                .try_recv(&mut buffer)
                .context("common::socks::SocksUdpAssociation::recv: failed to read relay"),
        };
        let size = match received {
            Ok(size) => size,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == ErrorKind::WouldBlock) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let start = match self {
            Self::Direct(_) => 0,
            Self::Socks(_) => {
                let (header_len, fragment) = parse_udp_header(&buffer[..size])?;
                if fragment != 0 {
                    return Ok(None);
                }
                header_len
            }
        };
        Ok(Some(buffer[start..size].to_vec()))
    }
}

pub(crate) struct SocksUdpAssociation {
    pub(super) control: TcpStream,
    pub(super) socket: UdpSocket,
    pub(super) target_header: Vec<u8>,
}

impl SocksUdpAssociation {
    async fn send(&self, payload: &[u8], packet: &mut Vec<u8>) -> Result<usize> {
        packet.clear();
        packet.reserve(self.target_header.len() + payload.len());
        packet.extend_from_slice(&self.target_header);
        packet.extend_from_slice(payload);
        let sent = self
            .socket
            .send(packet)
            .await
            .context("common::socks::SocksUdpAssociation::send: failed to write relay")?;
        if sent != packet.len() {
            bail!("common::socks::SocksUdpAssociation::send: partial UDP datagram");
        }
        Ok(payload.len())
    }

    async fn readable(&self) -> Result<()> {
        loop {
            tokio::select! {
                result = self.socket.readable() => return result.context(
                    "common::socks::SocksUdpAssociation::recv: failed to read relay",
                ),
                result = self.control.readable() => {
                    result.context(
                        "common::socks::SocksUdpAssociation::recv: failed to poll control connection",
                    )?;
                    let mut byte = [0u8; 1];
                    match self.control.try_read(&mut byte) {
                        Ok(0) => bail!(
                            "common::socks::SocksUdpAssociation::recv: control connection closed"
                        ),
                        Ok(_) => bail!(
                            "common::socks::SocksUdpAssociation::recv: unexpected control data"
                        ),
                        Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(err).context(
                            "common::socks::SocksUdpAssociation::recv: failed to read control connection",
                        ),
                    }
                }
            }
        }
    }
}
