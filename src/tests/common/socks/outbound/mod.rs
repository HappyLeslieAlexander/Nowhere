// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared SOCKS5 outbound fixtures and command/reply helpers.

mod policy;
mod tcp;
mod udp;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use url::Url;

use crate::protocol::Target;

use super::super::protocol::{
    ADDRESS_IPV4, AUTH_NONE, AUTH_PASSWORD, SOCKS_VERSION, encode_address, parse_udp_header,
    read_address,
};
use super::super::test_support::parse;
use super::super::{COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE};
use super::*;

async fn read_test_command(stream: &mut TcpStream) -> (u8, String, u16) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], SOCKS_VERSION);
    assert_eq!(header[2], 0);
    let address = read_address(stream, header[3]).await.unwrap();
    match address {
        SocksAddress::Ip(addr) => (header[1], addr.ip().to_string(), addr.port()),
        SocksAddress::Domain(host, port) => (header[1], host, port),
    }
}

async fn write_test_reply(stream: &mut TcpStream, address: SocketAddr) {
    let mut response = vec![SOCKS_VERSION, 0, 0];
    encode_address(&mut response, &SocksAddress::Ip(address)).unwrap();
    stream.write_all(&response).await.unwrap();
}
