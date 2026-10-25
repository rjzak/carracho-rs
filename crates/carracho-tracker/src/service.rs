//! Network front ends: the UDP registry and the TCP list service.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carracho_proto::tracker::{self, MAX_DATAGRAM_LEN, QUERY};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::registry::{Registered, Registry};

#[derive(Clone, Debug)]
pub struct Config {
    /// Address for the UDP registry.
    pub udp: SocketAddr,
    /// Address for the TCP list service.
    pub tcp: SocketAddr,
    /// How long a server stays listed without re-registering.
    pub expiry: Duration,
    /// Most servers listed at once.
    pub max_servers: usize,
    /// Most list requests served at once.
    pub max_connections: usize,
    /// Time allowed for a client to send its query and receive the list.
    pub client_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tracker::PORT);
        Self {
            udp: any,
            tcp: any,
            expiry: tracker::DEFAULT_EXPIRY,
            max_servers: 2048,
            max_connections: 256,
            client_timeout: Duration::from_secs(10),
        }
    }
}

/// A bound tracker, ready to serve.
pub struct Tracker {
    udp: UdpSocket,
    tcp: TcpListener,
    registry: Arc<Mutex<Registry>>,
    config: Config,
}

impl Tracker {
    pub async fn bind(config: Config) -> std::io::Result<Self> {
        let udp = UdpSocket::bind(config.udp).await?;
        let tcp = TcpListener::bind(config.tcp).await?;
        let registry = Arc::new(Mutex::new(Registry::new(config.expiry, config.max_servers)));
        Ok(Self { udp, tcp, registry, config })
    }

    pub fn udp_addr(&self) -> std::io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    pub fn tcp_addr(&self) -> std::io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    /// Serve until an I/O error occurs on one of the listening sockets.
    pub async fn serve(self) -> std::io::Result<()> {
        info!(udp = %self.udp_addr()?, tcp = %self.tcp_addr()?, "tracker listening");
        let Tracker { udp, tcp, registry, config } = self;
        tokio::try_join!(
            serve_registry(udp, registry.clone()),
            serve_lists(tcp, registry, config),
        )?;
        Ok(())
    }
}

async fn serve_registry(udp: UdpSocket, registry: Arc<Mutex<Registry>>) -> std::io::Result<()> {
    // One spare byte so an oversized datagram is seen as oversized rather than truncated.
    let mut buf = [0u8; MAX_DATAGRAM_LEN + 1];
    loop {
        let (len, from) = udp.recv_from(&mut buf).await?;
        let Some(source) = ipv4_of(from.ip()) else {
            debug!(%from, "ignoring registration from non-IPv4 address");
            continue;
        };
        let result = registry.lock().unwrap().register(source, &buf[..len], Instant::now());
        match result {
            Ok((server, outcome)) => {
                let count = registry.lock().unwrap().len();
                let verb = if outcome == Registered::Added { "added" } else { "refreshed" };
                info!(
                    %from, port = server.port, name = %server.name_lossy(), users = server.users,
                    servers = count, "server {verb}"
                );
            }
            Err(e) => warn!(%from, "dropping registration: {e}"),
        }
    }
}

async fn serve_lists(
    tcp: TcpListener,
    registry: Arc<Mutex<Registry>>,
    config: Config,
) -> std::io::Result<()> {
    let slots = Arc::new(Semaphore::new(config.max_connections));
    loop {
        let (stream, peer) = tcp.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            warn!(%peer, "too many list requests, dropping connection");
            continue;
        };
        let registry = registry.clone();
        let timeout = config.client_timeout;
        tokio::spawn(async move {
            match tokio::time::timeout(timeout, send_list(stream, &registry)).await {
                Ok(Ok(true)) => info!(%peer, "server list sent"),
                Ok(Ok(false)) => debug!(%peer, "ignoring connection with unknown request"),
                Ok(Err(e)) => debug!(%peer, "list request failed: {e}"),
                Err(_) => debug!(%peer, "list request timed out"),
            }
            drop(permit);
        });
    }
}

/// Answer one list request. Returns false if the client sent something other
/// than a list query.
async fn send_list(mut stream: TcpStream, registry: &Mutex<Registry>) -> std::io::Result<bool> {
    let mut request = [0u8; QUERY.len()];
    stream.read_exact(&mut request).await?;
    if request != QUERY {
        return Ok(false);
    }
    let reply = registry.lock().unwrap().server_list(Instant::now());
    stream.write_all(&reply).await?;
    stream.shutdown().await?;
    Ok(true)
}

fn ipv4_of(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}
