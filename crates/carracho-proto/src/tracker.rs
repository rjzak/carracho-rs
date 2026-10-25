//! Tracker protocol: servers register over UDP and clients fetch the server
//! list over TCP. Specified in `docs/protocol.md`, section 3.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::wire::{put_pstr, Reader};
use crate::{macroman, DecodeError};

/// Port used for both the UDP registry and the TCP list service.
pub const PORT: u16 = 6702;

/// First four bytes of a server registration datagram: `"CTT"` and version 1.
pub const REGISTER_MAGIC: [u8; 4] = *b"CTT\x01";

/// The complete request a client sends to fetch the server list.
pub const QUERY: [u8; 7] = *b"CTQ\x01QLI";

/// Longest server name the original tracker accepted.
pub const MAX_NAME_LEN: usize = 40;

/// Longest server description the original tracker accepted.
pub const MAX_DESCRIPTION_LEN: usize = 100;

/// Largest registration datagram the original trackers would read.
pub const MAX_DATAGRAM_LEN: usize = 255;

/// How often the original server re-registers (18000 ticks).
pub const REREGISTER_INTERVAL: Duration = Duration::from_secs(300);

/// How long the original OS X tracker kept a server without hearing from it.
pub const DEFAULT_EXPIRY: Duration = Duration::from_secs(600);

/// Labels for the connection speed stored in the top byte of [`ServerFlags`],
/// from the client's `STR#` 130 resource. Index 0 here is speed 1.
pub const SPEED_LABELS: [&str; 13] = [
    "28.8K", "33.6K", "56K", "56K", "64K", "112K", "128K", "Cable", "DSL", "T1", "T3", "Ethernet",
    "ATM",
];

/// The `flags` word of a server listing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServerFlags(pub u32);

impl ServerFlags {
    /// Set when the administrator enabled "Register server with Carracho Trackers".
    pub const REGISTERED: u32 = 0x0080_0000;
    /// Set when the administrator enabled "Is private"; clients show a padlock.
    pub const PRIVATE: u32 = 0x0040_0000;

    pub fn new(speed: u8, private: bool) -> Self {
        let mut bits = (speed as u32) << 24 | Self::REGISTERED;
        if private {
            bits |= Self::PRIVATE;
        }
        Self(bits)
    }

    /// Connection speed index (1-based into [`SPEED_LABELS`]); 0 means unknown.
    pub fn speed(self) -> u8 {
        (self.0 >> 24) as u8
    }

    pub fn speed_label(self) -> Option<&'static str> {
        SPEED_LABELS.get((self.speed() as usize).checked_sub(1)?).copied()
    }

    pub fn is_private(self) -> bool {
        self.0 & Self::PRIVATE != 0
    }

    pub fn is_registered(self) -> bool {
        self.0 & Self::REGISTERED != 0
    }
}

/// One server as announced to, and listed by, a tracker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    pub address: Ipv4Addr,
    pub port: u16,
    /// Server name, Mac OS Roman.
    pub name: Vec<u8>,
    /// Server description, Mac OS Roman.
    pub description: Vec<u8>,
    pub users: u16,
    pub flags: ServerFlags,
}

impl ServerInfo {
    pub fn name_lossy(&self) -> String {
        macroman::decode(&self.name)
    }

    pub fn description_lossy(&self) -> String {
        macroman::decode(&self.description)
    }

    /// Append the entry body: everything after the magic in a registration.
    pub fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.address.octets());
        out.extend_from_slice(&self.port.to_be_bytes());
        put_pstr(out, &self.name);
        put_pstr(out, &self.description);
        out.extend_from_slice(&self.users.to_be_bytes());
        out.extend_from_slice(&self.flags.0.to_be_bytes());
    }

    /// Parse an entry body. Bytes after the flags are ignored, as the
    /// original client did.
    pub fn decode_body(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        Ok(Self {
            address: Ipv4Addr::from(r.array::<4>()?),
            port: r.u16()?,
            name: r.pstr()?.to_vec(),
            description: r.pstr()?.to_vec(),
            users: r.u16()?,
            flags: ServerFlags(r.u32()?),
        })
    }
}

/// Build a registration datagram.
pub fn encode_registration(info: &ServerInfo) -> Vec<u8> {
    let mut out = REGISTER_MAGIC.to_vec();
    info.encode_body(&mut out);
    out
}

/// Parse and validate a registration datagram, applying the limits the
/// original Classic tracker enforced.
pub fn decode_registration(datagram: &[u8]) -> Result<ServerInfo, DecodeError> {
    if datagram.len() > MAX_DATAGRAM_LEN {
        return Err(DecodeError::TooLong {
            field: "registration",
            len: datagram.len(),
            max: MAX_DATAGRAM_LEN,
        });
    }
    let mut r = Reader::new(datagram);
    if r.array::<4>()? != REGISTER_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let info = ServerInfo::decode_body(&datagram[r.position()..])?;
    if info.name.len() > MAX_NAME_LEN {
        return Err(DecodeError::TooLong { field: "name", len: info.name.len(), max: MAX_NAME_LEN });
    }
    if info.description.len() > MAX_DESCRIPTION_LEN {
        return Err(DecodeError::TooLong {
            field: "description",
            len: info.description.len(),
            max: MAX_DESCRIPTION_LEN,
        });
    }
    Ok(info)
}

/// Build a server list reply from raw entry bodies.
///
/// # Panics
/// If an entry is longer than 255 bytes. Registrations are capped at
/// [`MAX_DATAGRAM_LEN`], so stored entries always fit.
pub fn encode_server_list<'a>(entries: impl ExactSizeIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = (entries.len() as u32).to_be_bytes().to_vec();
    for body in entries {
        let len = u8::try_from(body.len()).expect("tracker entry longer than 255 bytes");
        out.push(len);
        out.extend_from_slice(body);
    }
    out
}

/// Parse a complete server list reply.
pub fn decode_server_list(reply: &[u8]) -> Result<Vec<ServerInfo>, DecodeError> {
    let mut r = Reader::new(reply);
    let count = r.u32()?;
    // Each entry needs at least its length byte; don't trust `count` for allocation.
    let mut servers = Vec::with_capacity((count as usize).min(reply.len()));
    for _ in 0..count {
        let body = r.pstr()?;
        servers.push(ServerInfo::decode_body(body)?);
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from docs/protocol.md, section 3.4.
    fn example() -> ServerInfo {
        ServerInfo {
            address: Ipv4Addr::new(192, 0, 2, 10),
            port: 6700,
            name: b"Retro".to_vec(),
            description: b"Old Mac files".to_vec(),
            users: 3,
            flags: ServerFlags::new(9, false),
        }
    }

    const EXAMPLE_DATAGRAM: &[u8] = &[
        0x43, 0x54, 0x54, 0x01, 0xc0, 0x00, 0x02, 0x0a, 0x1a, 0x2c, 0x05, b'R', b'e', b't', b'r',
        b'o', 0x0d, b'O', b'l', b'd', b' ', b'M', b'a', b'c', b' ', b'f', b'i', b'l', b'e', b's',
        0x00, 0x03, 0x09, 0x80, 0x00, 0x00,
    ];

    #[test]
    fn registration_matches_documented_example() {
        assert_eq!(encode_registration(&example()), EXAMPLE_DATAGRAM);
        assert_eq!(decode_registration(EXAMPLE_DATAGRAM).unwrap(), example());
    }

    #[test]
    fn server_list_matches_documented_example() {
        let mut listed = example();
        listed.address = Ipv4Addr::new(198, 51, 100, 7);
        let mut body = Vec::new();
        listed.encode_body(&mut body);
        assert_eq!(body.len(), 32);

        let reply = encode_server_list([body.as_slice()].into_iter());
        assert_eq!(&reply[..5], &[0, 0, 0, 1, 0x20]);
        assert_eq!(decode_server_list(&reply).unwrap(), vec![listed]);
    }

    #[test]
    fn flags() {
        let f = ServerFlags(0x0d40_0000);
        assert_eq!(f.speed(), 13);
        assert_eq!(f.speed_label(), Some("ATM"));
        assert!(f.is_private());
        assert!(!f.is_registered());
        assert_eq!(ServerFlags(0).speed_label(), None);
        assert_eq!(ServerFlags(0x0e00_0000).speed_label(), None);
    }

    #[test]
    fn rejects_bad_registrations() {
        let mut bad_magic = EXAMPLE_DATAGRAM.to_vec();
        bad_magic[2] = b'Q';
        assert_eq!(decode_registration(&bad_magic), Err(DecodeError::BadMagic));

        assert!(matches!(
            decode_registration(&EXAMPLE_DATAGRAM[..EXAMPLE_DATAGRAM.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));

        let mut long_name = example();
        long_name.name = vec![b'x'; MAX_NAME_LEN + 1];
        assert!(matches!(
            decode_registration(&encode_registration(&long_name)),
            Err(DecodeError::TooLong { field: "name", .. })
        ));

        let mut long_desc = example();
        long_desc.description = vec![b'x'; MAX_DESCRIPTION_LEN + 1];
        assert!(matches!(
            decode_registration(&encode_registration(&long_desc)),
            Err(DecodeError::TooLong { field: "description", .. })
        ));
    }

    #[test]
    fn server_list_with_absurd_count_fails_cleanly() {
        assert!(matches!(
            decode_server_list(&[0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::Truncated { .. })
        ));
    }
}
