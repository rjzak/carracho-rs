//! Test client for Carracho servers. It logs in, sends a few requests and
//! prints every packet the server sends, decoding the ones it knows.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use carracho_proto::crypto::{self, FrameCipher};
use carracho_proto::macroman;
use carracho_proto::packet::{self, Field, MAX_BODY_LEN, Packet};
use carracho_proto::wire::Reader;
use carracho_probe::data;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Log in to a Carracho server and dump what it sends")]
struct Args {
    /// Server address, `host` or `host:port`.
    server: String,
    /// Account name; empty for a guest login.
    #[arg(long, default_value = "")]
    login: String,
    #[arg(long, default_value = "")]
    password: String,
    #[arg(long, default_value = "probe")]
    nick: String,
    /// Folder to list (0x01-separated on the wire; give it with `/`). Repeatable;
    /// `/` is the root.
    #[arg(long)]
    list: Vec<String>,
    /// Join the lobby and say this.
    #[arg(long)]
    say: Option<String>,
    /// Ask for server information (0xc3).
    #[arg(long)]
    info: bool,
    /// Ask for the flat news (0xFD0001).
    #[arg(long)]
    news: bool,
    /// Ask for the channel list (0x86).
    #[arg(long)]
    channels: bool,
    /// Send any command: `CMD` or `CMD:FIELD,FIELD...`, where a field is
    /// `TAG` (empty), `TAG=HEX`, `TAG=u8:N`, `TAG=u16:N`, `TAG=u32:N` or
    /// `TAG=s:TEXT`. Numbers may be decimal or 0x-prefixed. Repeatable.
    #[arg(long)]
    raw: Vec<String>,
    /// Upload this local file (encrypted data connection).
    #[arg(long)]
    upload: Option<PathBuf>,
    /// Folder to upload into, `/`-separated.
    #[arg(long, default_value = "/")]
    upload_to: String,
    /// Download this file or folder, `/`-separated. Repeatable.
    #[arg(long)]
    download: Vec<String>,
    /// Use the unencrypted data connection types (1 and 2).
    #[arg(long)]
    plain: bool,
    /// Where downloaded files are saved.
    #[arg(long, default_value = ".")]
    save_dir: PathBuf,
    /// Keep printing packets until the server is quiet for this many seconds.
    #[arg(long, default_value_t = 3)]
    listen: u64,
}

struct Conn {
    stream: TcpStream,
    cipher: FrameCipher,
    next_task: u32,
}

impl Conn {
    fn send(&mut self, command: u32, fields: Vec<Field>) -> anyhow::Result<u32> {
        let task = self.next_task;
        self.next_task += 1;
        let p = Packet::new(command, task, fields);
        println!("> {} task {task}", name(command));
        print_fields(&p);
        self.stream.write_all(&p.to_frame(&self.cipher))?;
        Ok(task)
    }

    /// Read one packet, or `None` if nothing arrives before the timeout.
    fn recv(&mut self, timeout: Duration) -> anyhow::Result<Option<Packet>> {
        self.stream.set_read_timeout(Some(timeout))?;
        let mut len = [0u8; 4];
        match self.stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(None),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => bail!("server closed the connection"),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len) as usize;
        ensure!(len % 8 == 0 && len <= MAX_BODY_LEN + 64, "implausible frame length {len}");
        self.stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut frame = vec![0u8; len];
        self.stream.read_exact(&mut frame)?;
        self.cipher.open(&mut frame);
        fix_settings_reply(&mut frame);
        let p = Packet::decode(&frame).with_context(|| format!("bad packet: {}", hex(&frame)))?;
        println!("< {} task {}", name(p.command), p.task);
        print_fields(&p);
        Ok(Some(p))
    }

    /// Read until a packet arrives, failing after `timeout`.
    fn expect(&mut self, timeout: Duration) -> anyhow::Result<Packet> {
        self.recv(timeout)?.context("timed out waiting for the server")
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let addr = if args.server.contains(':') { args.server.clone() } else { format!("{}:{}", args.server, packet::PORT) };
    let stream = TcpStream::connect(&addr).with_context(|| format!("connecting to {addr}"))?;
    stream.set_nodelay(true)?;
    println!("connected to {addr}");
    let main_addr = addr.to_socket_addrs()?.next().context("no address")?;
    let data_addr = std::net::SocketAddr::new(main_addr.ip(), main_addr.port() + 1);
    let mut conn = Conn { stream, cipher: FrameCipher::new(crypto::INITIAL_KEY), next_task: 1 };

    conn.stream.write_all(&packet::greeting(packet::CLIENT_VERSION))?;
    let mut greeting = [0u8; 13];
    conn.stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    conn.stream.read_exact(&mut greeting).context("reading the server greeting")?;
    let version = packet::parse_greeting(&greeting).with_context(|| format!("greeting {}", hex(&greeting)))?;
    println!("server greeting: protocol version {version}");

    let challenge = conn.expect(Duration::from_secs(10))?;
    ensure!(challenge.command == 1, "expected the login challenge (command 1)");
    let challenge: [u8; crypto::CHALLENGE_LEN] = challenge
        .field(1)
        .and_then(|f| f.data.as_slice().try_into().ok())
        .context("challenge has no 12-byte tag 1")?;

    let secret = crypto::session_secret(args.password.as_bytes(), &challenge);
    conn.send(
        2,
        vec![
            Field::new(1, macroman::encode(&args.login)),
            Field::new(2, crypto::login_response(&secret)),
            Field::new(4, macroman::encode(&args.nick)),
        ],
    )?;
    let reply = conn.expect(Duration::from_secs(10))?;
    match reply.command {
        3 => println!("login accepted"),
        0 => bail!("login refused"),
        c => bail!("unexpected reply {c:#x} to login"),
    }
    conn.cipher = FrameCipher::new(&secret);
    let user_id = reply.field(1).and_then(|f| f.data.get(..4)).map(|b| u32::from_be_bytes(b.try_into().unwrap())).context("no user ID")?;

    for path in &args.list {
        conn.send(9, vec![Field::new(1, wire_path(path))])?;
    }
    if args.info {
        conn.send(0xc3, vec![])?;
    }
    if args.news {
        conn.send(0xFD_0001, vec![])?;
    }
    if args.channels {
        conn.send(0x86, vec![])?;
    }
    if let Some(text) = &args.say {
        conn.send(0x80, vec![Field::u32(0, 1)])?;
        conn.send(0x82, vec![Field::u32(0, 1), Field::new(2, macroman::encode(text)), Field::u8(3, 0)])?;
    }

    for spec in &args.raw {
        let (command, fields) = parse_raw(spec).with_context(|| format!("bad --raw {spec:?}"))?;
        conn.send(command, fields)?;
    }

    let data_key = (!args.plain).then_some(secret.as_slice());
    if let Some(local) = &args.upload {
        let mut log = Vec::new();
        let result = data::upload(data_addr, user_id, data_key, local, &wire_path(&args.upload_to), &mut log);
        log.iter().for_each(|l| println!("{l}"));
        if let Err(e) = result {
            println!("upload failed: {e:#}");
        }
    }
    for path in &args.download {
        let mut log = Vec::new();
        let result = data::download(data_addr, user_id, data_key, &wire_path(path), &args.save_dir, &mut log);
        log.iter().for_each(|l| println!("{l}"));
        if let Err(e) = result {
            println!("download failed: {e:#}");
        }
    }

    let deadline = Duration::from_secs(args.listen);
    let started = Instant::now();
    while conn.recv(deadline)?.is_some() {
        if started.elapsed() > Duration::from_secs(120) {
            break;
        }
    }
    println!("quiet for {}s, disconnecting", args.listen);
    Ok(())
}

/// The original server declares 3 bytes for tag 0x32 (tracker flags) in the
/// settings reply but writes 4 (protocol.md, 4.12). Correct the length so the
/// rest of the packet parses.
fn fix_settings_reply(frame: &mut [u8]) {
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

/// `/`-separated path to the wire form: UTF-8 components joined by 0x01.
fn wire_path(path: &str) -> Vec<u8> {
    path.split('/').filter(|c| !c.is_empty()).collect::<Vec<_>>().join("\x01").into_bytes()
}

fn parse_num(s: &str) -> anyhow::Result<u64> {
    Ok(match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16)?,
        None => s.parse()?,
    })
}

fn parse_raw(spec: &str) -> anyhow::Result<(u32, Vec<Field>)> {
    let (command, rest) = spec.split_once(':').unwrap_or((spec, ""));
    let mut fields = Vec::new();
    for f in rest.split(',').filter(|f| !f.is_empty()) {
        let (tag, value) = f.split_once('=').unwrap_or((f, ""));
        let tag = parse_num(tag)? as u32;
        let field = match value.split_once(':') {
            Some(("s", text)) => Field::new(tag, macroman::encode(text)),
            Some(("u8", n)) => Field::u8(tag, parse_num(n)? as u8),
            Some(("u16", n)) => Field::u16(tag, parse_num(n)? as u16),
            Some(("u32", n)) => Field::u32(tag, parse_num(n)? as u32),
            Some((kind, _)) => bail!("unknown field kind {kind:?}"),
            None => {
                ensure!(value.len() % 2 == 0, "odd-length hex {value:?}");
                let bytes = (0..value.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
                    .collect::<Result<Vec<_>, _>>()?;
                Field::new(tag, bytes)
            }
        };
        fields.push(field);
    }
    Ok((parse_num(command)? as u32, fields))
}

fn name(command: u32) -> String {
    let n = match command {
        0x00 => "error",
        0x01 => "challenge",
        0x02 => "login",
        0x03 => "login accepted",
        0x06 => "private message",
        0x07 => "user joined",
        0x08 => "user left",
        0x09 => "list folder",
        0x14 => "file info / move",
        0x16 => "set extended info",
        0x17 => "user info",
        0x18 => "nick/icon changed",
        0x80 => "join channel",
        0x81 => "leave channel",
        0x82 => "chat",
        0x84 => "channel settings",
        0x86 => "channel list",
        0x87 => "user joined channel",
        0x88 => "user left channel",
        0xc3 => "server info",
        0xd0 => "broadcast",
        0xff => "task complete",
        0xFD_0000 => "flat news post",
        0xFD_0001 => "flat news",
        0xF000_0000 => "user state",
        0xFFFF_FFFF => "keepalive",
        _ => "",
    };
    if n.is_empty() { format!("{command:#x}") } else { format!("{command:#x} ({n})") }
}

fn print_fields(p: &Packet) {
    for f in &p.fields {
        let decoded = match (p.command, f.tag) {
            (0, 1) => f.as_u16().map(|c| format!("error code {c:#x} ({c})")),
            (3, 1) if f.data.len() == 12 => {
                let r = |i: usize| u32::from_be_bytes(f.data[i..i + 4].try_into().unwrap());
                Some(format!("user ID {}, privileges {:08x} {:08x}", r(0), r(4), r(8)))
            }
            (3, 3) => user_list(&f.data).ok(),
            (9, 2) => listing(&f.data).ok(),
            (0xcd, 0x10) => account_list(&f.data).ok(),
            _ => None,
        };
        let shown = decoded.unwrap_or_else(|| show(&f.data));
        println!("    tag {:#x} [{}] {shown}", f.tag, f.data.len());
    }
}

fn user_list(data: &[u8]) -> Result<String, carracho_proto::DecodeError> {
    let mut r = Reader::new(data);
    let count = r.u32()?;
    let mut out = format!("{count} users:");
    for _ in 0..count {
        let nick = macroman::decode(r.string()?);
        let flags = r.u16()?;
        let id = r.u32()?;
        let icon = r.u32()? as usize;
        r.bytes(icon)?;
        out += &format!("\n        #{id} {nick:?} flags {flags:#06x} icon {icon} bytes");
    }
    Ok(out)
}

fn account_list(data: &[u8]) -> Result<String, carracho_proto::DecodeError> {
    let cstr = |b: &[u8]| macroman::decode(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
    let mut r = Reader::new(data);
    let count = r.u32()?;
    let mut out = format!("{count} accounts:");
    for _ in 0..count {
        let e = r.bytes(0x88)?;
        let last = u32::from_be_bytes(e[0x82..0x86].try_into().unwrap());
        out += &format!("\n        {:?} real name {:?} last login {last} class {}", cstr(&e[..0x40]), cstr(&e[0x40..0x82]), e[0x86]);
    }
    Ok(out)
}

fn listing(data: &[u8]) -> Result<String, carracho_proto::DecodeError> {
    let mut r = Reader::new(data);
    let path = String::from_utf8_lossy(r.string()?).replace('\x01', "/");
    let count = r.u16()?;
    let mut out = format!("/{path}: {count} entries");
    for _ in 0..count {
        let _entry_len = r.u16()?;
        let name = String::from_utf8_lossy(r.string()?).into_owned();
        let size = r.u32()?;
        let date = r.u32()?;
        let ty = r.array::<4>()?;
        let creator = r.array::<4>()?;
        let flags = r.u16()?;
        out += &format!(
            "\n        {name:?} size {size} date {date} type {:?} creator {:?} flags {flags:#06x}",
            macroman::decode(&ty),
            macroman::decode(&creator)
        );
    }
    Ok(out)
}

/// Field data as text if it looks like text, otherwise as (shortened) hex.
fn show(data: &[u8]) -> String {
    let texty = !data.is_empty() && data.iter().all(|&b| b >= 0x20 || b == b'\r' || b == b'\n' || b == b'\t');
    if texty && data.len() > 4 {
        format!("{:?}", macroman::decode(data))
    } else if data.len() > 48 {
        format!("{}…", hex(&data[..48]))
    } else {
        hex(data)
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
