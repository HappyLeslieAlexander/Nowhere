// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 UDP association routing and relay.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

use super::*;

pub(super) async fn run_udp_association(
    vector: Arc<VectorInner>,
    mut control: TcpStream,
    control_peer: SocketAddr,
    requested: SocksAddress,
    shutdown: CancellationToken,
) -> Result<()> {
    let requested_port = validate_udp_source_request(&requested, control_peer.ip());
    let requested_port = match requested_port {
        Ok(port) => port,
        Err(error) => {
            let _ = write_reply(
                &mut control,
                REPLY_CONNECTION_NOT_ALLOWED,
                &SocksAddress::unspecified(),
            )
            .await;
            return Err(error);
        }
    };
    let local_ip = control.local_addr()?.ip();
    let bind = SocketAddr::new(
        if local_ip.is_unspecified() {
            match control_peer.ip() {
                IpAddr::V4(_) => IpAddr::from([0, 0, 0, 0]),
                IpAddr::V6(_) => IpAddr::from([0u16; 8]),
            }
        } else {
            local_ip
        },
        0,
    );
    let udp = Arc::new(UdpSocket::bind(bind).await?);
    let mut advertised = udp.local_addr()?;
    if advertised.ip().is_unspecified() && !local_ip.is_unspecified() {
        advertised.set_ip(local_ip);
    }
    write_reply(&mut control, REPLY_SUCCEEDED, &SocksAddress::Ip(advertised)).await?;

    let association_shutdown = shutdown.child_token();
    let client_endpoint = Arc::new(StdMutex::new(
        requested_port.map(|port| SocketAddr::new(control_peer.ip(), port)),
    ));
    let mut flows: HashMap<SocksAddress, UdpFlowQueue> = HashMap::new();
    let mut tasks = JoinSet::new();
    let active_targets = vector.socks_udp_target_admission.clone();
    // A UDP association has no liveness signal of its own, so the association
    // and every target flow close after this long without any traffic.
    let idle_after = vector.socks_udp_idle;
    let activity = Arc::new(AssociationActivity::new());
    let mut packet = Vec::new();
    let mut control_byte = [0u8; 1];
    let mut idle_deadline = Instant::now() + idle_after;

    let outcome = loop {
        tokio::select! {
            _ = association_shutdown.cancelled() => break Ok(()),
            _ = tokio::time::sleep_until(idle_deadline) => {
                if activity.is_idle(idle_after) {
                    break Ok(());
                }
                idle_deadline = activity.next_deadline(idle_after);
            }
            result = control.read(&mut control_byte) => {
                match result {
                    Ok(0) => break Ok(()),
                    Ok(_) => break Err(anyhow!("unexpected UDP ASSOCIATE control data")),
                    Err(error) => break Err(error.into()),
                }
            }
            ready = udp.readable() => {
                if let Err(error) = ready {
                    break Err(error.into());
                }
                if packet.is_empty() {
                    packet.resize(SOCKS_UDP_PACKET_MAX, 0);
                }
                let (size, source) = match udp.try_recv_from(&mut packet) {
                    Ok(received) => received,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => break Err(error.into()),
                };
                if source.ip() != control_peer.ip() {
                    continue;
                }
                if !accept_udp_source(&client_endpoint, control_peer.ip(), source) {
                    continue;
                }
                activity.touch();
                idle_deadline = activity.next_deadline(idle_after);
                let Ok((target, fragment, payload)) = decode_udp_packet(&packet[..size]) else {
                    continue;
                };
                if fragment != 0 || target.port() == 0 {
                    continue;
                }
                let Ok(permit) = vector
                    .local_udp_budget
                    .clone()
                    .try_acquire_many_owned(payload.len().max(1) as u32)
                else {
                    continue;
                };
                let mut payload = QueuedLocalPacket {
                    payload: payload.to_vec(),
                    _permit: permit,
                    _flow_permit: None,
                };
                if let Some(queue) = flows.get(&target) {
                    match queue.try_send(payload) {
                        FlowSend::Queued | FlowSend::Full => continue,
                        FlowSend::Closed(returned) => payload = returned,
                    }
                    flows.remove(&target);
                }
                flows.retain(|_, queue| !queue.sender.is_closed());
                let Some(target_admission) = try_admit_udp_target(&active_targets) else {
                    continue;
                };
                let (queue, receiver) = UdpFlowQueue::new(vector.local_udp_flow_budget);
                if matches!(queue.try_send(payload), FlowSend::Closed(_)) {
                    continue;
                }
                flows.insert(target.clone(), queue);
                tasks.spawn(open_and_relay_udp_target(
                    UdpTargetTask {
                        vector: vector.clone(),
                        socket: udp.clone(),
                        client_endpoint: client_endpoint.clone(),
                        target_admission,
                        activity: activity.clone(),
                    },
                    target,
                    receiver,
                    association_shutdown.clone(),
                ));
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {
                flows.retain(|_, queue| !queue.sender.is_closed());
            }
        }
    };
    association_shutdown.cancel();
    flows.clear();
    while tasks.join_next().await.is_some() {}
    outcome
}

/// Everything one target relay task holds for the association it serves.
struct UdpTargetTask {
    vector: Arc<VectorInner>,
    socket: Arc<UdpSocket>,
    client_endpoint: Arc<StdMutex<Option<SocketAddr>>>,
    target_admission: OwnedSemaphorePermit,
    activity: Arc<AssociationActivity>,
}

async fn open_and_relay_udp_target(
    task: UdpTargetTask,
    target: SocksAddress,
    outbound: mpsc::Receiver<QueuedLocalPacket>,
    shutdown: CancellationToken,
) {
    let UdpTargetTask {
        vector,
        socket,
        client_endpoint,
        target_admission: _target_admission,
        activity,
    } = task;
    let Ok(protocol_target) = to_target(&target) else {
        return;
    };
    let tunnel = tokio::select! {
        _ = shutdown.cancelled() => return,
        result = open_udp(vector.client.clone(), &protocol_target) => match result {
            Ok(tunnel) => tunnel,
            Err(error) => {
                let error = anyhow::Error::new(error);
                if crate::common::is_normal_close(&error) { return; }
                vector.logger.error(format_args!(
                    "udp setup failed: {error:#}"
                ));
                return;
            }
        },
    };
    relay_udp_target(
        vector.clone(),
        UdpClientSide {
            socket,
            endpoint: client_endpoint,
            idle_timeout: vector.socks_udp_idle,
        },
        target,
        tunnel,
        outbound,
        shutdown,
        activity,
    )
    .await;
}

pub(super) fn try_admit_udp_target(
    admission: &Arc<tokio::sync::Semaphore>,
) -> Option<OwnedSemaphorePermit> {
    admission.clone().try_acquire_owned().ok()
}

pub(super) fn validate_udp_source_request(
    requested: &SocksAddress,
    peer_ip: IpAddr,
) -> Result<Option<u16>> {
    match requested {
        SocksAddress::Ip(address) => {
            if !address.ip().is_unspecified() && address.ip() != peer_ip {
                return Err(anyhow!("UDP source IP differs from control peer"));
            }
            Ok((address.port() != 0).then_some(address.port()))
        }
        SocksAddress::Domain(_, _) => Err(anyhow!("domain UDP source constraint unsupported")),
    }
}

pub(super) fn accept_udp_source(
    endpoint: &StdMutex<Option<SocketAddr>>,
    peer_ip: IpAddr,
    source: SocketAddr,
) -> bool {
    if source.ip() != peer_ip {
        return false;
    }
    let mut endpoint = endpoint.lock().unwrap_or_else(|lock| lock.into_inner());
    match *endpoint {
        Some(expected) => expected == source,
        None => {
            *endpoint = Some(source);
            true
        }
    }
}

struct UdpClientSide {
    socket: Arc<UdpSocket>,
    endpoint: Arc<StdMutex<Option<SocketAddr>>>,
    idle_timeout: std::time::Duration,
}

async fn relay_udp_target(
    vector: Arc<VectorInner>,
    client: UdpClientSide,
    target: SocksAddress,
    mut tunnel: UdpTunnel,
    mut outbound: mpsc::Receiver<QueuedLocalPacket>,
    shutdown: CancellationToken,
    activity: Arc<AssociationActivity>,
) {
    let mut inbound = Vec::new();
    let mut local_packet = Vec::new();
    let idle = tokio::time::sleep_until(Instant::now() + client.idle_timeout);
    tokio::pin!(idle);
    let tunnel_cancel = tunnel.cancellation();
    let completion = 'relay: loop {
        tokio::select! {
            _ = shutdown.cancelled() => break Ok::<(), anyhow::Error>(()),
            _ = tunnel_cancel.cancelled() => break Ok::<(), anyhow::Error>(()),
            _ = &mut idle => break Ok(()),
            payload = outbound.recv() => {
                let Some(payload) = payload else { break Ok(()); };
                let sent = tokio::select! {
                    _ = shutdown.cancelled() => break 'relay Ok(()),
                    _ = tunnel_cancel.cancelled() => break 'relay Ok(()),
                    _ = &mut idle => break 'relay Ok(()),
                    result = async {
                        if let Some(rate) = &vector.rate_limiter {
                            rate.wait_read(payload.payload.len() as i64).await;
                        }
                        tunnel.send(&payload.payload).await
                    } => result,
                };
                if let Err(error) = sent { break Err(error); }
                activity.touch();
                idle.as_mut().reset(Instant::now() + client.idle_timeout);
            }
            received = tunnel.recv_into(&mut inbound) => {
                let packet = match received {
                    Ok(Some(packet)) => packet,
                    Ok(None) => break Ok(()),
                    Err(error) => break Err(error),
                };
                let size = packet.len();
                let endpoint = *client
                    .endpoint
                    .lock()
                    .unwrap_or_else(|lock| lock.into_inner());
                let Some(endpoint) = endpoint else { continue; };
                if encode_udp_packet_into(&mut local_packet, &target, packet.payload(&inbound)).is_err() {
                    continue;
                }
                let sent = tokio::select! {
                    _ = shutdown.cancelled() => break 'relay Ok(()),
                    _ = tunnel_cancel.cancelled() => break 'relay Ok(()),
                    _ = &mut idle => break 'relay Ok(()),
                    result = async {
                        if let Some(rate) = &vector.rate_limiter {
                            rate.wait_write(size as i64).await;
                        }
                        client.socket.send_to(&local_packet, endpoint).await
                    } => result,
                };
                if let Err(error) = sent { break Err(error.into()); }
                activity.touch();
                idle.as_mut().reset(Instant::now() + client.idle_timeout);
            }
        }
    };
    tunnel.close().await;
    if let Err(error) = completion
        && !crate::common::is_normal_close(&error)
    {
        vector
            .logger
            .error(format_args!("udp forwarding failed: {error:#}"));
    }
}

/// Liveness clock for one UDP association: packets from the locked source or
/// successful relay transfers push the idle deadline out.
struct AssociationActivity {
    started: Instant,
    last_millis: AtomicU64,
}

impl AssociationActivity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        self.last_millis.store(
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    fn next_deadline(&self, idle_after: Duration) -> Instant {
        self.started + Duration::from_millis(self.last_millis.load(Ordering::Relaxed)) + idle_after
    }

    fn is_idle(&self, idle_after: Duration) -> bool {
        Instant::now() >= self.next_deadline(idle_after)
    }
}

/// Outbound queue for one target with its own in-flight packet budget, so a
/// single busy target cannot drain the association-wide byte budget.
struct UdpFlowQueue {
    sender: mpsc::Sender<QueuedLocalPacket>,
    budget: Arc<tokio::sync::Semaphore>,
}

enum FlowSend {
    Queued,
    Full,
    Closed(QueuedLocalPacket),
}

impl UdpFlowQueue {
    fn new(budget_packets: usize) -> (Self, mpsc::Receiver<QueuedLocalPacket>) {
        let (sender, receiver) = mpsc::channel(64);
        (
            Self {
                sender,
                budget: Arc::new(Semaphore::new(budget_packets.max(1))),
            },
            receiver,
        )
    }

    fn try_send(&self, payload: QueuedLocalPacket) -> FlowSend {
        let Ok(flow_permit) = self.budget.clone().try_acquire_owned() else {
            drop(payload);
            return FlowSend::Full;
        };
        let mut payload = payload;
        payload._flow_permit = Some(flow_permit);
        match self.sender.try_send(payload) {
            Ok(()) => FlowSend::Queued,
            Err(TrySendError::Full(returned)) => {
                drop(returned);
                FlowSend::Full
            }
            Err(TrySendError::Closed(returned)) => FlowSend::Closed(returned),
        }
    }
}

struct QueuedLocalPacket {
    payload: Vec<u8>,
    _permit: OwnedSemaphorePermit,
    _flow_permit: Option<OwnedSemaphorePermit>,
}

#[cfg(test)]
#[path = "../../tests/vector/socks/udp.rs"]
mod tests;
