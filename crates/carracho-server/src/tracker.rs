//! Registration with trackers (protocol.md, 3.1): a UDP datagram to each
//! tracker every five minutes while the "register" flag is set.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use carracho_proto::macroman;
use carracho_proto::tracker::{self, ServerFlags, ServerInfo};
use tokio::net::UdpSocket;

use crate::state::Server;

/// Register with every configured tracker once.
pub async fn register_once(server: &Arc<Server>, port: u16) {
    let (info, hosts) = {
        let st = server.lock();
        let s = &st.store.settings;
        let flags = ServerFlags(s.tracker_flags);
        if !flags.is_registered() || s.trackers.is_empty() {
            return;
        }
        let mut name = macroman::encode(&s.name);
        name.truncate(tracker::MAX_NAME_LEN);
        let mut description = macroman::encode(&s.tracker_description);
        description.truncate(tracker::MAX_DESCRIPTION_LEN);
        let info = ServerInfo {
            // Trackers record the datagram's source address instead.
            address: Ipv4Addr::UNSPECIFIED,
            port,
            name,
            description,
            users: st.users.len().min(u16::MAX as usize) as u16,
            flags,
        };
        (info, s.trackers.iter().map(|t| t.host.clone()).collect::<Vec<_>>())
    };
    let datagram = tracker::encode_registration(&info);
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else { return };
    for host in hosts {
        let target = if host.contains(':') { host.clone() } else { format!("{host}:{}", tracker::PORT) };
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(&target).await {
            Ok(a) => a.filter(SocketAddr::is_ipv4).collect(),
            Err(e) => {
                tracing::warn!("tracker {target}: {e}");
                continue;
            }
        };
        if let Some(addr) = addrs.first() {
            match socket.send_to(&datagram, addr).await {
                Ok(_) => tracing::debug!("registered with tracker {target}"),
                Err(e) => tracing::warn!("tracker {target}: {e}"),
            }
        }
    }
}

/// Re-register every five minutes, forever.
pub async fn run(server: Arc<Server>, port: u16) {
    let mut tick = tokio::time::interval(tracker::REREGISTER_INTERVAL);
    loop {
        tick.tick().await;
        register_once(&server, port).await;
    }
}
