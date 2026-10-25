//! A client that logs in and records every packet it sends and receives, for
//! comparing servers.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use carracho_proto::crypto::{self, FrameCipher};
use carracho_proto::macroman;
use carracho_proto::packet::{self, Field, MAX_BODY_LEN, Packet};

/// One recorded packet.
#[derive(Clone, Debug)]
pub enum Event {
    Sent(Packet),
    Received(Packet),
    /// Something that isn't a packet: a data connection exchange, a
    /// disconnect.
    Note(String),
}

pub struct Client {
    pub name: String,
    stream: TcpStream,
    cipher: FrameCipher,
    next_task: u32,
    pub user_id: u32,
    pub privileges: u64,
    pub secret: Vec<u8>,
    pub addr: SocketAddr,
    pub events: Vec<Event>,
    pub closed: bool,
}

impl Client {
    /// Connect and log in. A refused login is not an error: the client is
    /// returned closed, with the server's reply recorded.
    pub fn login(addr: SocketAddr, name: &str, login: &str, password: &str, nick: &str) -> anyhow::Result<Self> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).with_context(|| format!("connecting to {addr}"))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.write_all(&packet::greeting(packet::CLIENT_VERSION))?;
        let mut greeting = [0u8; 13];
        stream.read_exact(&mut greeting).context("reading the server greeting")?;
        let version = packet::parse_greeting(&greeting)?;
        ensure!(version == packet::SERVER_VERSION, "server protocol version {version}");
        let mut c = Self {
            name: name.into(),
            stream,
            cipher: FrameCipher::new(crypto::INITIAL_KEY),
            next_task: 1,
            user_id: 0,
            privileges: 0,
            secret: Vec::new(),
            addr,
            events: Vec::new(),
            closed: false,
        };
        let challenge = c.read_packet(Duration::from_secs(15))?.context("no challenge")?;
        let challenge: [u8; crypto::CHALLENGE_LEN] =
            challenge.field(1).and_then(|f| f.data.as_slice().try_into().ok()).context("bad challenge")?;
        let secret = crypto::session_secret(&macroman::encode(password), &challenge);
        let request = Packet::new(
            2,
            c.next_task,
            vec![
                Field::new(1, macroman::encode(login)),
                Field::new(2, crypto::login_response(&secret)),
                Field::new(4, macroman::encode(nick)),
            ],
        );
        c.next_task += 1;
        c.stream.write_all(&request.to_frame(&c.cipher))?;
        let reply = c.read_packet(Duration::from_secs(15))?.context("no login reply")?;
        c.events.push(Event::Received(reply.clone()));
        match reply.command {
            3 => {
                let ident = &reply.field(1).context("no tag 1")?.data;
                ensure!(ident.len() == 12, "bad login reply tag 1");
                c.user_id = u32::from_be_bytes(ident[..4].try_into().unwrap());
                c.privileges = u64::from_be_bytes(ident[4..].try_into().unwrap());
                c.cipher = FrameCipher::new(&secret);
                c.secret = secret;
            }
            _ => c.closed = true,
        }
        Ok(c)
    }

    pub fn send(&mut self, command: u32, fields: Vec<Field>) -> u32 {
        let task = self.next_task;
        self.next_task += 1;
        let p = Packet::new(command, task, fields);
        self.events.push(Event::Sent(p.clone()));
        if !self.closed && self.stream.write_all(&p.to_frame(&self.cipher)).is_err() {
            self.note("send failed: connection closed");
            self.closed = true;
        }
        task
    }

    pub fn note(&mut self, text: impl Into<String>) {
        self.events.push(Event::Note(text.into()));
    }

    fn read_packet(&mut self, timeout: Duration) -> anyhow::Result<Option<Packet>> {
        self.stream.set_read_timeout(Some(timeout))?;
        let mut len = [0u8; 4];
        match self.stream.read(&mut len[..1]) {
            Ok(0) => bail!("closed"),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        self.stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        self.stream.read_exact(&mut len[1..])?;
        let len = u32::from_be_bytes(len) as usize;
        ensure!(len % 8 == 0 && len <= MAX_BODY_LEN + 64, "bad frame length {len}");
        let mut frame = vec![0u8; len];
        self.stream.read_exact(&mut frame)?;
        self.cipher.open(&mut frame);
        fix_settings_reply(&mut frame);
        Ok(Some(Packet::decode(&frame)?))
    }

    /// Record everything that arrives until the server has been quiet for
    /// `quiet`.
    pub fn drain(&mut self, quiet: Duration) {
        if self.closed {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match self.read_packet(quiet) {
                Ok(Some(p)) => self.events.push(Event::Received(p)),
                Ok(None) => return,
                Err(e) => {
                    let what = if e.to_string() == "closed" { "server closed the connection".to_string() } else { format!("connection error: {e}") };
                    self.note(what);
                    self.closed = true;
                    return;
                }
            }
        }
    }

    pub fn data_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr.ip(), self.addr.port() + 1)
    }

    pub fn disconnect(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.closed = true;
    }
}

/// The original server declares 3 bytes for tag 0x32 (tracker flags) in the
/// settings reply but writes 4 (protocol.md, 4.12). Correct the length so the
/// rest of the packet parses.
pub fn fix_settings_reply(frame: &mut [u8]) {
    if frame.len() < packet::HEADER_LEN || frame[..4] != 0xc0u32.to_be_bytes() {
        return;
    }
    let mut i = packet::HEADER_LEN;
    while i + 6 <= frame.len() {
        let tag = u32::from_be_bytes(frame[i..i + 4].try_into().unwrap());
        let len = u16::from_be_bytes([frame[i + 4], frame[i + 5]]);
        if tag == 0x32 && len == 3 {
            frame[i + 5] = 4;
            return;
        }
        i += 6 + len as usize;
    }
}
