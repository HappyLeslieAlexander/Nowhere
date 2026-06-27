// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP/TLS ingress handling and first-request pool behavior.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use socket2::SockRef;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::common::handshake_timeout;
use crate::protocol::{is_uot_magic_target, read_auth_frame, read_request};

use super::auth::{authentication_deadline, wait_for_auth_deadline};
use super::relay::{relay_tcp_target, relay_udp_over_tcp_target};
use crate::portal::PortalInner;
use crate::portal::admission::UnauthenticatedGuard;

const TCP_POOL_TTL: Duration = Duration::from_secs(40);

/// Handles an accepted TLS/TCP client connection.
pub(in crate::portal) async fn handle_tcp_incoming(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    handle_tcp_incoming_with_pool_ttl(portal, stream, peer, admission, shutdown, TCP_POOL_TTL)
        .await;
}

/// Handles a TLS/TCP connection with an injectable pool TTL for tests.
pub(super) async fn handle_tcp_incoming_with_pool_ttl(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
    pool_ttl: Duration,
) {
    let local = stream
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| portal.endpoint_addr.clone());
    let acceptor = TlsAcceptor::from(portal.tls_server_config.clone());
    let mut tls_stream = match timeout(handshake_timeout(), acceptor.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            portal.logger.error(format_args!(
                "portal::conn::handle_tcp_incoming: TLS handshake failed: {err}"
            ));
            return;
        }
        Err(_) => {
            portal.logger.error(format_args!(
                "portal::conn::handle_tcp_incoming: TLS handshake failed: deadline elapsed"
            ));
            return;
        }
    };
    let auth_deadline = authentication_deadline();
    let auth = tokio::select! {
        _ = shutdown.cancelled() => return,
        result = timeout_at(
        auth_deadline,
        read_auth_frame(
            &mut tls_stream,
            portal.credentials.key,
            &portal.credentials.protocol_spec,
        ),
        ) => result,
    };
    match auth {
        Ok(Ok(())) => drop(admission),
        Ok(Err(err)) => {
            if !wait_for_auth_deadline(auth_deadline, &shutdown).await {
                return;
            }
            drop(tls_stream);
            drop(admission);
            portal.logger.error(format_args!(
                "portal::conn::handle_tcp_incoming: authentication failed: {err}"
            ));
            return;
        }
        Err(_) => {
            drop(tls_stream);
            drop(admission);
            portal.logger.error(format_args!(
                "portal::conn::handle_tcp_incoming: authentication failed: deadline elapsed"
            ));
            return;
        }
    }

    if let Err(err) = SockRef::from(tls_stream.get_ref().0).set_keepalive(true) {
        portal.logger.error(format_args!(
            "portal::conn::handle_tcp_incoming: failed to enable TCP keepalive: {err}"
        ));
        return;
    }
    let (recv, mut send) = tokio::io::split(tls_stream);
    let mut recv = BufReader::new(recv);

    let pool_guard = PoolGuard::new(&portal.pool_active);
    let target_addr = match tokio::select! {
        result = timeout(pool_ttl, async {
            // A pooled client may hold an authenticated TCP connection open
            // without sending a request yet. Treat a clean close before any
            // request bytes as normal pool churn, not a protocol error.
            match recv.fill_buf().await {
                Ok([]) => return Ok(None),
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(err.into()),
            }
            read_request(&mut recv, &portal.credentials.protocol_spec)
                .await
                .map(Some)
        }) => Some(result),
        _ = shutdown.cancelled() => None,
    } {
        Some(Ok(Ok(Some(target)))) => target,
        Some(Ok(Ok(None))) => {
            portal.logger.debug(format_args!(
                "portal::conn::handle_tcp_incoming: unused pooled connection closed by client"
            ));
            return;
        }
        Some(Ok(Err(err))) => {
            portal.logger.error(format_args!(
                "portal::conn::handle_tcp_incoming: failed to read request: {err}"
            ));
            return;
        }
        Some(Err(_)) => {
            portal.logger.debug(format_args!(
                "portal::conn::handle_tcp_incoming: unused pooled connection expired"
            ));
            return;
        }
        None => return,
    };
    drop(pool_guard);

    let peer = peer.to_string();
    if is_uot_magic_target(&target_addr) {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = relay_udp_over_tcp_target(
                portal,
                &mut recv,
                &mut send,
                peer,
                local,
            ) => {}
        }
    } else {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = relay_tcp_target(
                portal,
                &mut recv,
                &mut send,
                target_addr,
                peer,
                local,
            ) => {}
        }
    }
}

/// Tracks an authenticated but not-yet-claimed TCP pooled connection.
struct PoolGuard<'a>(&'a AtomicU64);

impl<'a> PoolGuard<'a> {
    fn new(active: &'a AtomicU64) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self(active)
    }
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
