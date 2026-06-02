use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, OnceCell};
use tokio::time;
use tracing::{debug, trace, warn};

use crate::dns::config::DnsServerConfig;
use crate::dns::error::DnsError;
use crate::dns::packet::dns_query_id;

const MAX_UDP_DNS_PACKET: usize = 65_535;

type PendingKey = (SocketAddr, u16);

#[derive(Clone, Default)]
pub struct UdpDnsTransport {
    inner: Arc<UdpDnsTransportInner>,
}

#[derive(Default)]
struct UdpDnsTransportInner {
    v4: OnceCell<Arc<UdpSocketDispatcher>>,
    v6: OnceCell<Arc<UdpSocketDispatcher>>,
}

struct UdpSocketDispatcher {
    socket: Arc<UdpSocket>,
    pending: Mutex<HashMap<PendingKey, oneshot::Sender<Vec<u8>>>>,
}

impl UdpDnsTransport {
    pub async fn query(
        &self,
        query: &[u8],
        server: &DnsServerConfig,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        let server_addr = socket_addr_for_server(&server.host, server.port)?;
        self.query_at(server_addr, query, timeout).await
    }

    pub async fn query_at(
        &self,
        server: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        let expected_id = dns_query_id(query).ok_or(DnsError::MalformedQuery)?;
        let dispatcher = self.dispatcher_for(server).await?;
        let key = (server, expected_id);

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = dispatcher.pending.lock().await;
            if pending.contains_key(&key) {
                return Err(DnsError::Upstream);
            }
            pending.insert(key, tx);
        }

        let send_started = std::time::Instant::now();
        if let Err(err) = dispatcher.socket.send_to(query, server).await {
            dispatcher.pending.lock().await.remove(&key);
            return Err(err.into());
        }

        debug!(
            server = %server,
            query_len = query.len(),
            dns_id = expected_id,
            elapsed_ms = send_started.elapsed().as_millis(),
            "dns upstream send done"
        );

        let wait_started = std::time::Instant::now();
        match time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                debug!(
                    server = %server,
                    response_len = response.len(),
                    latency_ms = wait_started.elapsed().as_millis(),
                    dns_id = expected_id,
                    "dns upstream response received"
                );
                Ok(response)
            }
            Ok(Err(_)) => {
                dispatcher.pending.lock().await.remove(&key);
                Err(DnsError::Upstream)
            }
            Err(_) => {
                dispatcher.pending.lock().await.remove(&key);
                debug!(
                    server = %server,
                    dns_id = expected_id,
                    timeout_ms = timeout.as_millis(),
                    "dns upstream timeout"
                );
                Err(DnsError::Timeout)
            }
        }
    }

    async fn dispatcher_for(
        &self,
        server: SocketAddr,
    ) -> Result<Arc<UdpSocketDispatcher>, DnsError> {
        let cell = if server.is_ipv4() {
            &self.inner.v4
        } else {
            &self.inner.v6
        };
        let bind_ip = if server.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        Ok(Arc::clone(
            cell.get_or_try_init(|| Self::bind_dispatcher(bind_ip))
                .await?,
        ))
    }

    async fn bind_dispatcher(bind_ip: IpAddr) -> Result<Arc<UdpSocketDispatcher>, DnsError> {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::new(bind_ip, 0))
                .await
                .map_err(DnsError::from)?,
        );
        let family = if bind_ip.is_ipv4() { "ipv4" } else { "ipv6" };
        debug!(family, "dns udp transport socket bound");

        let dispatcher = Arc::new(UdpSocketDispatcher {
            socket: Arc::clone(&socket),
            pending: Mutex::new(HashMap::new()),
        });
        let recv_dispatcher = Arc::clone(&dispatcher);
        tokio::spawn(async move {
            recv_loop(recv_dispatcher).await;
        });
        Ok(dispatcher)
    }
}

async fn recv_loop(dispatcher: Arc<UdpSocketDispatcher>) {
    let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
    loop {
        let (len, peer) = match dispatcher.socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(err) => {
                warn!(error = %err, "dns udp recv loop error");
                continue;
            }
        };
        if len < 2 {
            trace!(%peer, packet_len = len, "dns udp ignored short packet");
            continue;
        }
        let response_id = match dns_query_id(&buf[..len]) {
            Some(id) => id,
            None => {
                trace!(%peer, packet_len = len, "dns udp ignored packet without dns id");
                continue;
            }
        };
        let key = (peer, response_id);
        let sender = dispatcher.pending.lock().await.remove(&key);
        let Some(sender) = sender else {
            trace!(
                %peer,
                dns_id = response_id,
                response_len = len,
                "dns udp ignored unmatched response"
            );
            continue;
        };
        if sender.send(buf[..len].to_vec()).is_err() {
            trace!(%peer, dns_id = response_id, "dns udp response delivered to closed waiter");
        }
    }
}

pub fn socket_addr_for_server(host: &str, port: u16) -> Result<SocketAddr, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    Err(DnsError::UnsupportedTransport(format!(
        "dns server host must be numeric IP on this stage: {host}"
    )))
}

#[cfg(test)]
#[path = "../../tests/unit/dns/udp_transport.rs"]
mod tests;
