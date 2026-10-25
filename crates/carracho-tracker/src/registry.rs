//! The list of known servers.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use carracho_proto::tracker::{decode_registration, encode_server_list, ServerInfo};
use carracho_proto::DecodeError;

struct Entry {
    address: Ipv4Addr,
    port: u16,
    /// Entry body as listed to clients: the datagram without its magic, with
    /// the address replaced by the one the datagram actually came from.
    body: Vec<u8>,
    last_seen: Instant,
}

/// What happened to a registration datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Registered {
    Added,
    Refreshed,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    #[error("malformed registration: {0}")]
    Malformed(#[from] DecodeError),
    #[error("server list is full")]
    Full,
}

/// Servers in order of their most recent registration, oldest first, which is
/// the order the original tracker listed them in.
pub struct Registry {
    entries: Vec<Entry>,
    expiry: Duration,
    max_servers: usize,
}

impl Registry {
    pub fn new(expiry: Duration, max_servers: usize) -> Self {
        Self { entries: Vec::new(), expiry, max_servers }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a registration datagram received from `source`.
    pub fn register(
        &mut self,
        source: Ipv4Addr,
        datagram: &[u8],
        now: Instant,
    ) -> Result<(ServerInfo, Registered), RegisterError> {
        let mut info = decode_registration(datagram)?;
        info.address = source;
        self.expire(now);

        let existing = self.entries.iter().position(|e| e.address == source && e.port == info.port);
        let outcome = match existing {
            Some(i) => {
                self.entries.remove(i);
                Registered::Refreshed
            }
            None if self.entries.len() >= self.max_servers => return Err(RegisterError::Full),
            None => Registered::Added,
        };

        // Keep the datagram's bytes (including any trailing extension data a
        // newer server might send) rather than re-encoding the parsed fields.
        let mut body = datagram[4..].to_vec();
        body[..4].copy_from_slice(&source.octets());
        self.entries.push(Entry { address: source, port: info.port, body, last_seen: now });
        Ok((info, outcome))
    }

    /// Drop servers not heard from within the expiry period.
    pub fn expire(&mut self, now: Instant) {
        let expiry = self.expiry;
        self.entries.retain(|e| now.saturating_duration_since(e.last_seen) <= expiry);
    }

    /// The server list reply for a client, after expiring stale servers.
    pub fn server_list(&mut self, now: Instant) -> Vec<u8> {
        self.expire(now);
        encode_server_list(self.entries.iter().map(|e| e.body.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carracho_proto::tracker::{decode_server_list, encode_registration, ServerFlags};

    fn datagram(name: &str, claimed: Ipv4Addr, port: u16, users: u16) -> Vec<u8> {
        encode_registration(&ServerInfo {
            address: claimed,
            port,
            name: name.as_bytes().to_vec(),
            description: b"desc".to_vec(),
            users,
            flags: ServerFlags::new(9, false),
        })
    }

    const LAN: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
    const A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const B: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);

    fn listed(reg: &mut Registry, now: Instant) -> Vec<ServerInfo> {
        decode_server_list(&reg.server_list(now)).unwrap()
    }

    #[test]
    fn lists_source_address_not_claimed_address() {
        let mut reg = Registry::new(Duration::from_secs(600), 10);
        let now = Instant::now();
        reg.register(A, &datagram("one", LAN, 6700, 1), now).unwrap();
        let list = listed(&mut reg, now);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, A);
        assert_eq!(list[0].name, b"one");
    }

    #[test]
    fn refresh_replaces_and_moves_to_end() {
        let mut reg = Registry::new(Duration::from_secs(600), 10);
        let now = Instant::now();
        reg.register(A, &datagram("a", A, 6700, 1), now).unwrap();
        reg.register(B, &datagram("b", B, 6700, 1), now).unwrap();
        let (_, outcome) = reg.register(A, &datagram("a2", A, 6700, 5), now).unwrap();
        assert_eq!(outcome, Registered::Refreshed);

        let list = listed(&mut reg, now);
        let names: Vec<_> = list.iter().map(|s| s.name.as_slice()).collect();
        assert_eq!(names, [b"b".as_slice(), b"a2"]);
        assert_eq!(list[1].users, 5);
    }

    #[test]
    fn same_host_different_ports_are_separate_servers() {
        let mut reg = Registry::new(Duration::from_secs(600), 10);
        let now = Instant::now();
        reg.register(A, &datagram("a", A, 6700, 0), now).unwrap();
        reg.register(A, &datagram("b", A, 6800, 0), now).unwrap();
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn expires_after_the_expiry_period() {
        let mut reg = Registry::new(Duration::from_secs(600), 10);
        let start = Instant::now();
        reg.register(A, &datagram("a", A, 6700, 0), start).unwrap();
        reg.register(B, &datagram("b", B, 6700, 0), start + Duration::from_secs(300)).unwrap();

        assert_eq!(listed(&mut reg, start + Duration::from_secs(600)).len(), 2);
        let list = listed(&mut reg, start + Duration::from_secs(601));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, b"b");
    }

    #[test]
    fn full_registry_rejects_new_servers_but_refreshes_known_ones() {
        let mut reg = Registry::new(Duration::from_secs(600), 1);
        let now = Instant::now();
        reg.register(A, &datagram("a", A, 6700, 0), now).unwrap();
        assert_eq!(reg.register(B, &datagram("b", B, 6700, 0), now), Err(RegisterError::Full));
        assert!(reg.register(A, &datagram("a", A, 6700, 2), now).is_ok());
    }

    #[test]
    fn rejects_garbage() {
        let mut reg = Registry::new(Duration::from_secs(600), 10);
        assert!(matches!(
            reg.register(A, b"hello", Instant::now()),
            Err(RegisterError::Malformed(_))
        ));
        assert!(reg.is_empty());
    }
}
