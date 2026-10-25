//! Run the same scenarios against two Carracho servers (typically the
//! original in an emulator and the Rust one) and diff what each client saw.
//!
//! Values that legitimately differ between runs are normalized before the
//! comparison: user and channel IDs become `<A>`, `<B>`, `<ch1>`; dates,
//! counters and addresses become placeholders.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use carracho_probe::client::{Client, Event};
use carracho_probe::data::{self, BlockStream};
use carracho_proto::account::{self, Record};
use carracho_proto::macroman;
use carracho_proto::packet::{Field, Packet};
use carracho_proto::wire::{self, Reader};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Run scenarios against two Carracho servers and diff the results")]
struct Args {
    /// Reference server (e.g. the original), `host` or `host:port`.
    a: String,
    /// Server under test, `host` or `host:port`.
    b: String,
    /// Run only scenarios whose names contain this.
    #[arg(long)]
    only: Vec<String>,
    /// How long a client waits for more packets after each step.
    #[arg(long, default_value_t = 700)]
    quiet_ms: u64,
    /// Where to write each side's normalized transcript.
    #[arg(long)]
    out: Option<PathBuf>,
    /// List the scenarios and exit.
    #[arg(long)]
    list: bool,
}

/// Test names. Everything a scenario creates uses these, and the prelude
/// removes leftovers from earlier runs.
const FOLDER: &str = "CmpTest";
const ACCOUNT: &str = "zztest";
const GROUP: &str = "CmpGroup";

struct Harness {
    addr: SocketAddr,
    quiet: Duration,
    clients: Vec<Client>,
}

fn sep(parts: &[&str]) -> Vec<u8> {
    parts.join("\x01").into_bytes()
}

impl Harness {
    fn login(&mut self, login: &str, password: &str, nick: &str) -> anyhow::Result<usize> {
        let name = ((b'A' + self.clients.len() as u8) as char).to_string();
        let c = Client::login(self.addr, &name, login, password, nick)?;
        self.clients.push(c);
        self.settle();
        Ok(self.clients.len() - 1)
    }

    fn settle(&mut self) {
        for c in &mut self.clients {
            c.drain(self.quiet);
        }
    }

    fn send(&mut self, i: usize, command: u32, fields: Vec<Field>) {
        self.clients[i].send(command, fields);
        self.settle();
    }

    fn note(&mut self, i: usize, text: String) {
        self.clients[i].note(text);
    }

    fn open_data(&self, i: usize, kind: i16) -> anyhow::Result<BlockStream> {
        let c = &self.clients[i];
        let encrypted = matches!(kind, data::DOWNLOAD_ENCRYPTED | data::UPLOAD_ENCRYPTED);
        BlockStream::open(c.data_addr(), kind, c.user_id, encrypted.then_some(c.secret.as_slice()))
    }

    /// Upload one file (data fork only) over an encrypted data connection.
    fn upload(&mut self, i: usize, folder: &[u8], name: &str, contents: &[u8], replace: bool) {
        let result = (|| -> anyhow::Result<Vec<String>> {
            let mut log = Vec::new();
            let mut s = self.open_data(i, data::UPLOAD_ENCRYPTED)?;
            s.send(&with_len(folder))?;
            s.send(&with_len(name.as_bytes()))?;
            log.push(format!("item state {}", s.u8()?));
            s.send(&[replace as u8])?;
            let mut summary = (contents.len() as u64).to_be_bytes().to_vec();
            summary.extend_from_slice(&1u32.to_be_bytes());
            s.send(&summary)?;
            let mut item = with_len(name.as_bytes());
            item.extend_from_slice(b"TEXTttxt");
            item.extend_from_slice(&[0; 2 + 16 + 4]);
            s.send(&item)?;
            let (have_data, have_rsrc) = (s.u64()?, s.u64()?);
            log.push(format!("server has {have_data}+{have_rsrc}"));
            let rest = &contents[(have_data as usize).min(contents.len())..];
            let mut sizes = (rest.len() as u64).to_be_bytes().to_vec();
            sizes.extend_from_slice(&0u64.to_be_bytes());
            s.send(&sizes)?;
            for chunk in rest.chunks(8192) {
                s.send(chunk)?;
            }
            s.send(&with_len(b"compare comment"))?;
            s.stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut tail = Vec::new();
            let _ = s.stream.read_to_end(&mut tail);
            log.push(format!("closed, {} trailing bytes", tail.len()));
            Ok(log)
        })();
        self.record_data(i, &format!("upload {name}"), result);
        self.settle();
    }

    /// Download over an encrypted data connection; records a summary of each
    /// item.
    fn download(&mut self, i: usize, path: &[u8]) {
        let result = (|| -> anyhow::Result<Vec<String>> {
            let mut log = Vec::new();
            let mut s = self.open_data(i, data::DOWNLOAD_ENCRYPTED)?;
            s.send(&with_len(path))?;
            let mut queue = s.u32()?;
            log.push(format!("queue {queue}"));
            while queue > 0 {
                if s.u8()? == 1 {
                    queue -= 1;
                }
            }
            let total = s.u64()?;
            let items = s.u32()?;
            log.push(format!("{total} bytes in {items} items"));
            for _ in 0..items {
                let rel = s.string()?;
                let ty = s.read(4)?;
                let creator = s.read(4)?;
                let flags = s.u16()?;
                let ext = s.read(16)?;
                let extra = s.u32()?;
                s.read(extra as usize)?;
                let mut line = format!(
                    "item {:?} {}/{} finder {flags:#06x} ext {} extra {extra}",
                    show_path(&rel),
                    macroman::decode(&ty),
                    macroman::decode(&creator),
                    hex(&ext)
                );
                if &ty[..] != b"FLDR" {
                    let mut offsets = 0u64.to_be_bytes().to_vec();
                    offsets.extend_from_slice(&0u64.to_be_bytes());
                    s.send(&offsets)?;
                    let (d, r) = (s.u64()?, s.u64()?);
                    let content = s.read(d as usize)?;
                    s.read(r as usize)?;
                    let comment = s.string()?;
                    line += &format!(" data {d} ({}) rsrc {r} comment {:?}", checksum(&content), macroman::decode(&comment));
                }
                log.push(line);
            }
            Ok(log)
        })();
        self.record_data(i, &format!("download {:?}", show_path(path)), result);
        self.settle();
    }

    /// A raw (unencrypted, unblocked) data connection: send `request`, then
    /// record what comes back until the server closes or goes quiet.
    fn raw_data(&mut self, i: usize, kind: i16, request: &[u8], describe: fn(&[u8]) -> String) {
        let result = (|| -> anyhow::Result<Vec<String>> {
            let mut s = self.open_data(i, kind)?;
            s.stream.write_all(request)?;
            s.stream.set_read_timeout(Some(Duration::from_secs(4)))?;
            let mut reply = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match s.stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => reply.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            Ok(vec![describe(&reply)])
        })();
        self.record_data(i, &format!("data type {kind}"), result);
        self.settle();
    }

    fn record_data(&mut self, i: usize, what: &str, result: anyhow::Result<Vec<String>>) {
        match result {
            Ok(lines) => {
                for l in lines {
                    self.note(i, format!("{what}: {l}"));
                }
            }
            Err(e) => self.note(i, format!("{what}: failed: {}", short_error(&e))),
        }
    }

    fn finish(&mut self) {
        self.settle();
        for c in &mut self.clients {
            c.disconnect();
        }
    }
}

fn short_error(e: &anyhow::Error) -> String {
    // Normalize OS-specific wording.
    let s = e.root_cause().to_string();
    if s.contains("reset") || s.contains("closed") || s.contains("end of file") || s.contains("broken pipe") {
        "connection closed".into()
    } else if s.contains("timed out") || s.contains("temporarily unavailable") {
        "timed out".into()
    } else {
        s
    }
}

fn with_len(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_string(&mut out, s);
    out
}

fn checksum(data: &[u8]) -> String {
    let mut h: u32 = 2166136261;
    for &b in data {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    format!("fnv {h:08x}")
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn show_path(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace('\x01', "/")
}

// ---------------------------------------------------------------- scenarios

type Scenario = fn(&mut Harness) -> anyhow::Result<()>;

fn scenarios() -> Vec<(&'static str, Scenario)> {
    vec![
        ("guest-basics", guest_basics),
        ("login-errors", login_errors),
        ("users", users),
        ("channels", channels),
        ("files", files),
        ("drop-box", drop_box),
        ("transfers", transfers),
        ("flat-news", flat_news),
        ("accounts", accounts),
        ("settings", settings),
        ("newsgroups", newsgroups),
        ("kick", kick),
        ("data-misc", data_misc),
        ("errors", errors),
    ]
}

/// Remove what earlier runs may have left behind. Not compared.
fn prelude(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "prelude")?;
    h.send(a, 0x11, vec![Field::new(1, FOLDER.as_bytes().to_vec())]);
    h.send(a, 0x11, vec![Field::new(1, b"probe-test.txt".to_vec())]);
    h.send(a, 0xcf, vec![Field::new(2, ACCOUNT.as_bytes().to_vec())]);
    h.send(a, 0xcf, vec![Field::new(2, b"zzrenamed".to_vec())]);
    h.send(a, 0xa6, vec![Field::new(1, GROUP.as_bytes().to_vec())]);
    h.send(a, 0xa6, vec![Field::new(1, b"CmpRenamed".to_vec())]);
    h.send(a, 0xFD_0003, vec![]);
    h.finish();
    Ok(())
}

fn guest_basics(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("anonymous", "", "guest")?;
    h.send(a, 0x09, vec![Field::new(1, vec![])]);
    h.send(a, 0xc3, vec![]);
    h.send(a, 0xFD_0001, vec![]);
    h.send(a, 0x86, vec![]);
    h.send(a, 0x80, vec![Field::u32(0, 1)]);
    h.send(a, 0x82, vec![Field::u32(0, 1), Field::new(2, b"hello".to_vec()), Field::u8(3, 0)]);
    h.send(a, 0x82, vec![Field::u32(0, 1), Field::new(2, b"waves".to_vec()), Field::u8(3, 1)]);
    h.send(a, 0x16, vec![Field::new(0xb0, b"Real".to_vec()), Field::new(0xb1, b"a@b.c".to_vec()), Field::new(0xb2, b"About".to_vec())]);
    h.send(a, 0xFFFF_FFFF, vec![]);
    h.send(a, 0x81, vec![Field::u32(0, 1)]);
    h.send(a, 0x81, vec![Field::u32(0, 1)]);
    h.finish();
    Ok(())
}

fn login_errors(h: &mut Harness) -> anyhow::Result<()> {
    h.login("", "", "empty")?;
    h.login("nosuchuser", "", "x")?;
    h.login("admin", "wrong", "x")?;
    h.login("ADMIN", "", "case")?;
    h.finish();
    Ok(())
}

fn users(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    let (ida, idb) = (h.clients[a].user_id, h.clients[b].user_id);
    h.send(a, 0x06, vec![Field::u32(1, idb), Field::new(2, b"hi bob".to_vec())]);
    h.send(b, 0x06, vec![Field::u32(1, ida), Field::new(2, b"hi alice".to_vec()), Field::new(3, b"second".to_vec())]);
    h.send(a, 0x06, vec![Field::u32(1, 0x7fff_0000), Field::new(2, b"nobody".to_vec())]);
    h.send(a, 0xd0, vec![Field::new(1, b"broadcast".to_vec())]);
    h.send(b, 0xd0, vec![Field::new(1, b"guest broadcast".to_vec())]);
    h.send(b, 0x18, vec![Field::new(2, b"bobby".to_vec())]);
    h.send(b, 0xF000_0000, vec![Field::u8(0xF000_0001, 2)]);
    h.send(b, 0x16, vec![Field::new(0xb0, b"Bob B".to_vec()), Field::new(0xb1, b"bob@x".to_vec()), Field::new(0xb2, b"me".to_vec())]);
    h.send(a, 0x17, vec![Field::u32(1, idb)]);
    h.send(b, 0x17, vec![Field::u32(1, ida)]);
    h.send(a, 0x17, vec![Field::u32(1, 0x7fff_0000)]);
    h.finish();
    Ok(())
}

fn channels(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    let idb = h.clients[b].user_id;
    h.send(a, 0x80, vec![Field::u32(0, 0), Field::new(1, b"CmpRoom".to_vec()), Field::new(9, b"pw".to_vec())]);
    let room = last_channel(&h.clients[a]).context("no channel ID in join reply")?;
    h.send(b, 0x80, vec![Field::u32(0, 0), Field::new(1, b"CmpRoom".to_vec())]);
    h.send(b, 0x80, vec![Field::u32(0, 0), Field::new(1, b"CmpRoom".to_vec()), Field::new(9, b"bad".to_vec())]);
    h.send(b, 0x80, vec![Field::u32(0, room), Field::new(9, b"pw".to_vec())]);
    h.send(b, 0x80, vec![Field::u32(0, room), Field::new(9, b"pw".to_vec())]);
    h.send(a, 0x86, vec![]);
    h.send(a, 0x84, vec![Field::u32(0, room), Field::new(4, b"the topic".to_vec()), Field::u16(6, 0x0800 | 0x1000)]);
    h.send(b, 0x84, vec![Field::u32(0, room), Field::new(4, b"bob topic".to_vec()), Field::u16(6, 0x0800 | 0x1000)]);
    h.send(b, 0x82, vec![Field::u32(0, room), Field::new(2, b"moderated?".to_vec()), Field::u8(3, 0)]);
    h.send(b, 0x0f, vec![Field::u32(0, room), Field::u32(7, idb), Field::u8(8, 0x80)]);
    h.send(a, 0x0f, vec![Field::u32(0, room), Field::u32(7, idb), Field::u8(8, 0x40)]);
    h.send(b, 0x82, vec![Field::u32(0, room), Field::new(2, b"voiced".to_vec()), Field::u8(3, 0)]);
    h.send(a, 0x84, vec![Field::u32(0, room), Field::new(4, b"the topic".to_vec()), Field::u16(6, 0x2000)]);
    h.send(b, 0x86, vec![]);
    h.send(b, 0x81, vec![Field::u32(0, room)]);
    h.send(a, 0x89, vec![Field::u32(0, room), Field::u32(7, idb)]);
    h.send(b, 0x0c, vec![Field::u32(0, room), Field::u32(0xb, h.clients[a].user_id)]);
    h.send(a, 0x89, vec![Field::u32(0, 0x7fff_0000), Field::u32(7, idb)]);
    h.send(a, 0x81, vec![Field::u32(0, room)]);
    h.send(a, 0x86, vec![]);
    h.send(a, 0x80, vec![Field::u32(0, 0x7fff_0000)]);
    h.send(a, 0x80, vec![Field::u32(0, 0)]);
    h.send(a, 0x84, vec![Field::u32(0, 0x7fff_0000), Field::new(4, b"x".to_vec())]);
    h.send(a, 0x80, vec![Field::u32(0, 1)]);
    h.send(a, 0x84, vec![Field::u32(0, 1), Field::new(4, b"lobby topic".to_vec()), Field::u16(6, 0x1000)]);
    h.send(a, 0x81, vec![Field::u32(0, 1)]);
    h.send(a, 0x80, vec![Field::u32(0, 1)]);
    h.send(a, 0x81, vec![Field::u32(0, 1)]);
    h.finish();
    Ok(())
}

/// The most recent channel ID in a join reply this client received.
fn last_channel(c: &Client) -> Option<u32> {
    c.events.iter().rev().find_map(|e| match e {
        Event::Received(p) if p.command == 0x80 && p.task != 0 => p.field(0).and_then(Field::as_u32),
        _ => None,
    })
}

fn files(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    let f = FOLDER;
    h.send(a, 0x10, vec![Field::new(1, vec![]), Field::new(3, f.as_bytes().to_vec()), Field::u16(2, 0)]);
    h.send(a, 0x10, vec![Field::new(1, vec![]), Field::new(3, f.as_bytes().to_vec()), Field::u16(2, 0)]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"Sub".to_vec()), Field::u16(2, 0x4000)]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"Other".to_vec())]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f, "Missing"])), Field::new(3, b"X".to_vec())]);
    h.send(b, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"Guest".to_vec())]);
    h.send(a, 0x09, vec![Field::new(1, sep(&[f]))]);
    h.send(a, 0x09, vec![Field::new(1, sep(&[f, "Missing"]))]);
    h.send(a, 0x12, vec![Field::new(1, sep(&[f]))]);
    h.send(a, 0x12, vec![Field::new(1, sep(&[f, "Sub"]))]);
    h.send(a, 0x12, vec![Field::new(1, sep(&[f, "Missing"]))]);
    h.send(a, 0x13, vec![Field::new(1, sep(&[f, "Sub"])), Field::new(2, b"Sub".to_vec()), Field::new(4, b"a comment".to_vec())]);
    h.send(a, 0x13, vec![Field::new(1, sep(&[f, "Sub"])), Field::new(2, b"Renamed".to_vec())]);
    h.send(a, 0x13, vec![Field::new(1, sep(&[f, "Renamed"])), Field::new(2, b"Renamed".to_vec()), Field::u16(3, 0x2000)]);
    h.send(a, 0x12, vec![Field::new(1, sep(&[f, "Renamed"]))]);
    h.send(b, 0x13, vec![Field::new(1, sep(&[f, "Other"])), Field::new(2, b"Guested".to_vec())]);
    h.send(b, 0x13, vec![Field::new(1, sep(&[f, "Other"])), Field::new(2, b"Other".to_vec()), Field::new(4, b"guest comment".to_vec())]);
    h.send(a, 0x14, vec![Field::new(1, sep(&[f, "Other"])), Field::new(2, sep(&[f, "Renamed"]))]);
    h.send(a, 0x14, vec![Field::new(1, sep(&[f, "Missing"])), Field::new(2, sep(&[f]))]);
    h.send(a, 0x14, vec![Field::new(1, sep(&[f, "Renamed"])), Field::new(2, sep(&[f, "Missing"]))]);
    h.send(a, 0x09, vec![Field::new(1, sep(&[f]))]);
    h.send(a, 0x09, vec![Field::new(1, sep(&[f, "Renamed"]))]);
    h.send(b, 0x11, vec![Field::new(1, sep(&[f, "Renamed"]))]);
    h.send(a, 0x11, vec![Field::new(1, sep(&[f, "Missing"]))]);
    h.send(a, 0x11, vec![Field::new(1, sep(&[f]))]);
    h.send(a, 0x09, vec![Field::new(1, vec![])]);
    h.finish();
    Ok(())
}

fn drop_box(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let f = FOLDER;
    h.send(a, 0x10, vec![Field::new(1, vec![]), Field::new(3, f.as_bytes().to_vec()), Field::u16(2, 0)]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"Box".to_vec()), Field::u16(2, 0x2000)]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f, "Box"])), Field::new(3, b"Inside".to_vec()), Field::u16(2, 0)]);
    h.upload(a, &sep(&[f, "Box"]), "boxed.txt", b"secret contents\r", false);
    let b = h.login("anonymous", "", "bob")?;
    h.send(b, 0x09, vec![Field::new(1, sep(&[f]))]);
    h.send(b, 0x09, vec![Field::new(1, sep(&[f, "Box"]))]);
    h.send(b, 0x12, vec![Field::new(1, sep(&[f, "Box", "boxed.txt"]))]);
    h.download(b, &sep(&[f, "Box", "boxed.txt"]));
    h.send(a, 0x09, vec![Field::new(1, sep(&[f, "Box"]))]);
    h.send(a, 0x11, vec![Field::new(1, sep(&[f]))]);
    h.finish();
    Ok(())
}

fn transfers(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let f = FOLDER;
    let content: Vec<u8> = (0..70_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    h.send(a, 0x10, vec![Field::new(1, vec![]), Field::new(3, f.as_bytes().to_vec()), Field::u16(2, 0)]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"Uploads".to_vec()), Field::u16(2, 0x4000)]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"Deep".to_vec())]);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f, "Deep"])), Field::new(3, b"Deeper".to_vec())]);
    h.upload(a, &sep(&[f]), "big.bin", &content, false);
    h.upload(a, &sep(&[f, "Deep", "Deeper"]), "deep.txt", b"deep\r", false);
    h.send(a, 0x09, vec![Field::new(1, sep(&[f]))]);
    h.send(a, 0x12, vec![Field::new(1, sep(&[f, "big.bin"]))]);
    h.download(a, &sep(&[f, "big.bin"]));
    h.upload(a, &sep(&[f]), "big.bin", b"replacement\r", false);
    h.upload(a, &sep(&[f]), "big.bin", b"replacement\r", true);
    h.download(a, &sep(&[f, "big.bin"]));
    h.download(a, &sep(&[f]));
    h.download(a, &sep(&[f, "Missing"]));
    let b = h.login("anonymous", "", "bob")?;
    h.upload(b, &sep(&[f]), "guest.txt", b"not allowed\r", false);
    h.upload(b, &sep(&[f, "Uploads"]), "guest.txt", b"allowed\r", false);
    h.upload(b, &sep(&[f, "Missing"]), "guest.txt", b"nowhere\r", false);
    h.download(b, &sep(&[f, "Uploads", "guest.txt"]));
    h.send(a, 0xe0, vec![]);
    h.send(b, 0xe0, vec![]);
    h.send(a, 0x11, vec![Field::new(1, sep(&[f]))]);
    h.finish();
    Ok(())
}

fn flat_news(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    h.send(a, 0xFD_0000, vec![Field::new(0xFD_0000, b"First post".to_vec())]);
    h.send(b, 0xFD_0000, vec![Field::new(0xFD_0000, b"Guest post\rline two".to_vec())]);
    h.send(a, 0xFD_0001, vec![]);
    h.send(b, 0xFD_0002, vec![Field::u32(0xFD_0002, 1)]);
    h.send(a, 0xFD_0002, vec![Field::u32(0xFD_0002, 1)]);
    h.send(a, 0xFD_0001, vec![]);
    h.send(a, 0xFD_0003, vec![]);
    h.send(b, 0xFD_0001, vec![]);
    h.finish();
    Ok(())
}

fn record(login: &str, password: &str, privileges: u64) -> Vec<u8> {
    Record {
        login: login.as_bytes().to_vec(),
        real_name: b"Compare Test".to_vec(),
        password: password.as_bytes().to_vec(),
        privileges,
        ..Record::default()
    }
    .encode_for_server()
}

fn accounts(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let holder = 0x4030_0008_0001_8000u64;
    h.send(a, 0xcd, vec![]);
    h.send(a, 0xcc, vec![Field::new(2, b"admin".to_vec())]);
    h.send(a, 0xcc, vec![Field::new(2, b"nosuch".to_vec())]);
    h.send(a, 0xcb, vec![Field::new(1, record(ACCOUNT, "pw1", holder))]);
    h.send(a, 0xcb, vec![Field::new(1, record(ACCOUNT, "pw1", holder))]);
    h.send(a, 0xcb, vec![Field::new(1, record("bad:name", "x", holder))]);
    h.send(a, 0xcc, vec![Field::new(2, ACCOUNT.as_bytes().to_vec())]);
    let t = h.login(ACCOUNT, "pw1", "tester")?;
    h.send(t, 0xcd, vec![]);
    h.clients[t].disconnect();
    // Keep the password (first byte 0xAD) while changing privileges.
    let mut keep = Record::decode(&record(ACCOUNT, "", holder | 1 << 47)).unwrap();
    keep.password = vec![account::KEEP_PASSWORD];
    let mut bytes = keep.encode_masked();
    bytes[0x81] = account::KEEP_PASSWORD;
    h.send(a, 0xcb, vec![Field::new(3, ACCOUNT.as_bytes().to_vec()), Field::new(1, bytes)]);
    h.login(ACCOUNT, "pw1", "tester2")?;
    h.send(a, 0xcb, vec![Field::new(3, ACCOUNT.as_bytes().to_vec()), Field::new(1, record("zzrenamed", "pw2", holder))]);
    h.send(a, 0xcb, vec![Field::new(3, b"nosuch".to_vec()), Field::new(1, record("nosuch", "x", holder))]);
    h.send(a, 0xcb, vec![Field::new(3, b"zzrenamed".to_vec()), Field::new(1, record("admin", "x", holder))]);
    h.login("zzrenamed", "pw2", "tester3")?;
    h.send(a, 0xcf, vec![Field::new(2, b"zzrenamed".to_vec())]);
    h.send(a, 0xcf, vec![Field::new(2, b"zzrenamed".to_vec())]);
    let b = h.login("anonymous", "", "bob")?;
    h.send(b, 0xcd, vec![]);
    h.send(b, 0xcc, vec![Field::new(2, b"admin".to_vec())]);
    h.send(a, 0xcd, vec![]);
    h.finish();
    Ok(())
}

const ALL_SETTINGS: [u32; 30] = [
    4, 5, 6, 7, 8, 9, 0xc, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
    0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
];

fn get_all() -> Vec<Field> {
    ALL_SETTINGS.iter().map(|&t| Field::new(t, vec![])).collect()
}

fn settings(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    h.send(a, 0xc1, get_all());
    h.send(b, 0xc1, get_all());
    h.send(b, 0xc2, vec![Field::new(6, b"guest location".to_vec())]);
    let mut trackers = Vec::new();
    wire::put_u16(&mut trackers, 1);
    wire::put_string(&mut trackers, b"Test Tracker");
    wire::put_string(&mut trackers, b"192.0.2.1");
    wire::put_string(&mut trackers, b"");
    wire::put_u32(&mut trackers, 0);
    let mut ips = Vec::new();
    wire::put_u32(&mut ips, 1);
    ips.extend_from_slice(&[192, 0, 2, 0, 255, 255, 255, 0, 1, 0]);
    h.send(
        a,
        0xc2,
        vec![
            Field::new(6, b"Test Location".to_vec()),
            Field::new(7, b"Test Operator".to_vec()),
            Field::new(8, b"Test description".to_vec()),
            Field::u16(0x23, 4),
            Field::new(0x30, trackers),
            Field::new(0x2f, ips),
            Field::u32(0x32, 0x0900_0000),
            Field::new(0x33, b"tracker text".to_vec()),
            Field::u16(0x35, 3),
            Field::new(4, b"Please be nice.".to_vec()),
        ],
    );
    h.send(a, 0xc1, get_all());
    h.send(a, 0xc3, vec![]);
    let c = h.login("anonymous", "", "carol")?;
    h.send(c, 0xc3, vec![]);
    // Restore the defaults.
    let mut no_trackers = Vec::new();
    wire::put_u16(&mut no_trackers, 0);
    h.send(
        a,
        0xc2,
        vec![
            Field::new(6, b"unknown".to_vec()),
            Field::new(7, b"unknown".to_vec()),
            Field::new(8, vec![]),
            Field::u16(0x23, 5),
            Field::new(0x30, no_trackers),
            Field::new(0x2f, vec![0, 0, 0, 0]),
            Field::u32(0x32, 0),
            Field::new(0x33, vec![]),
            Field::u16(0x35, 1),
            Field::new(4, vec![0]),
        ],
    );
    h.send(a, 0xc1, get_all());
    h.finish();
    Ok(())
}

fn post_article_request(group: &str, subject: &str, parent: u32, text: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    wire::put_string(&mut body, group.as_bytes());
    wire::put_string(&mut body, subject.as_bytes());
    wire::put_u32(&mut body, 0);
    wire::put_u32(&mut body, parent);
    wire::put_u32(&mut body, text.len() as u32);
    wire::put_u32(&mut body, 0);
    body.extend_from_slice(text);
    let mut out = Vec::new();
    wire::put_u32(&mut out, body.len() as u32);
    out.extend_from_slice(&body);
    out
}

fn index_request(group: &str) -> Vec<u8> {
    with_len(group.as_bytes())
}

fn describe_index(reply: &[u8]) -> String {
    let parse = || -> Option<String> {
        let mut r = Reader::new(reply);
        let len = r.u32().ok()?;
        let name = macroman::decode(r.string().ok()?);
        let count = r.u32().ok()?;
        let mut out = format!("index {len} bytes, group {name:?}, {count} articles");
        for _ in 0..count {
            let id = r.u32().ok()?;
            let subject = macroman::decode(r.string().ok()?);
            let author = macroman::decode(r.string().ok()?);
            let _date = r.u32().ok()?;
            let parent = r.u32().ok()?;
            out += &format!("; #{id} {subject:?} by {author:?} parent {parent:#x}");
        }
        if r.remaining() > 0 {
            out += &format!("; {} trailing bytes {}", r.remaining(), hex(r.bytes(r.remaining()).ok()?));
        }
        Some(out)
    };
    parse().unwrap_or_else(|| format!("unparsed {} bytes: {}", reply.len(), hex(&reply[..reply.len().min(64)])))
}

fn describe_empty(reply: &[u8]) -> String {
    format!("{} bytes back: {}", reply.len(), hex(&reply[..reply.len().min(64)]))
}

fn newsgroups(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    h.send(a, 0xa8, vec![]);
    h.send(a, 0xa5, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 30), Field::u16(3, 0xfc00)]);
    h.send(a, 0xa5, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 30), Field::u16(3, 0xfc00)]);
    h.send(b, 0xa5, vec![Field::new(1, b"GuestGroup".to_vec()), Field::u32(2, 1), Field::u16(3, 0)]);
    h.send(a, 0xa8, vec![]);
    h.send(a, 0xa0, vec![]);
    h.send(b, 0xa0, vec![]);
    h.raw_data(a, data::POST_ARTICLE, &post_article_request(GROUP, "Hello", 0xFFFF_FFFF, b"First article\r"), describe_empty);
    h.raw_data(b, data::POST_ARTICLE, &post_article_request(GROUP, "Re: Hello", 1, b"A reply\r"), describe_empty);
    h.raw_data(a, data::ARTICLE_INDEX, &index_request(GROUP), describe_index);
    h.send(a, 0xa2, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 1)]);
    h.send(b, 0xa2, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 2)]);
    h.send(a, 0xa2, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 99)]);
    h.send(a, 0xa8, vec![]);
    h.send(a, 0xa9, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 1)]);
    h.send(a, 0xa9, vec![Field::new(1, GROUP.as_bytes().to_vec()), Field::u32(2, 1)]);
    h.raw_data(a, data::ARTICLE_INDEX, &index_request(GROUP), describe_index);
    h.send(a, 0xa7, vec![Field::new(4, GROUP.as_bytes().to_vec()), Field::new(1, b"CmpRenamed".to_vec()), Field::u32(2, 7), Field::u16(3, 0xf000)]);
    h.send(b, 0xa0, vec![]);
    h.send(a, 0xa8, vec![]);
    h.send(a, 0xa6, vec![Field::new(1, b"CmpRenamed".to_vec())]);
    h.send(a, 0xa6, vec![Field::new(1, b"CmpRenamed".to_vec())]);
    h.send(a, 0xa8, vec![]);
    h.finish();
    Ok(())
}

fn kick(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let b = h.login("anonymous", "", "bob")?;
    let c = h.login("anonymous", "", "carol")?;
    let (idb, idc) = (h.clients[b].user_id, h.clients[c].user_id);
    h.send(b, 0x04, vec![Field::u32(1, idc)]);
    h.send(c, 0x80, vec![Field::u32(0, 1)]);
    h.send(a, 0x04, vec![Field::u32(1, idc)]);
    h.send(a, 0x04, vec![Field::u32(1, 0x7fff_0000)]);
    h.send(b, 0x05, vec![Field::u32(1, h.clients[a].user_id)]);
    let _ = idb;
    h.finish();
    Ok(())
}

fn search_request(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_u16(&mut out, 1);
    out.extend_from_slice(&[1, 1, 0]);
    wire::put_u32(&mut out, text.len() as u32);
    out.extend_from_slice(text.as_bytes());
    out
}

fn data_misc(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("admin", "", "alice")?;
    let f = FOLDER;
    h.send(a, 0x10, vec![Field::new(1, vec![]), Field::new(3, f.as_bytes().to_vec()), Field::u16(2, 0)]);
    h.upload(a, &sep(&[f]), "findme-one.txt", b"1\r", false);
    h.send(a, 0x10, vec![Field::new(1, sep(&[f])), Field::new(3, b"FindMe Folder".to_vec())]);
    h.raw_data(a, data::SEARCH, &search_request("findme"), describe_empty);
    h.raw_data(a, data::SEARCH, &search_request("nothing-matches-this"), describe_empty);
    h.raw_data(a, data::BANNER_DOWNLOAD, &[], describe_empty);
    h.raw_data(a, data::LOG, &[], |r| format!("{} bytes back", if r.len() > 4 { "some" } else { "few" }));
    let b = h.login("anonymous", "", "bob")?;
    h.raw_data(b, data::LOG, &[], describe_empty);
    h.send(a, 0x11, vec![Field::new(1, sep(&[f]))]);
    h.finish();
    Ok(())
}

fn errors(h: &mut Harness) -> anyhow::Result<()> {
    let a = h.login("anonymous", "", "guest")?;
    h.send(a, 0x77, vec![]);
    h.send(a, 0x15, vec![]);
    h.send(a, 0xcd, vec![]);
    h.send(a, 0xe0, vec![]);
    h.send(a, 0xa8, vec![]);
    h.send(a, 0xFD_0003, vec![]);
    h.send(a, 0x09, vec![Field::new(1, b"..".to_vec())]);
    h.finish();
    Ok(())
}

// ------------------------------------------------------------ normalization

/// Maps run-specific values to stable placeholders.
struct Norm {
    users: HashMap<u32, String>,
    channels: HashMap<u32, String>,
}

impl Norm {
    fn new(clients: &[Client]) -> Self {
        let mut users = HashMap::new();
        for c in clients {
            if c.user_id != 0 {
                users.insert(c.user_id, format!("<{}>", c.name));
            }
        }
        let mut channels = HashMap::new();
        channels.insert(1, "<lobby>".to_string());
        for c in clients {
            for e in &c.events {
                if let Event::Received(p) = e {
                    if p.command == 0x80 && p.task != 0 {
                        if let Some(id) = p.field(0).and_then(Field::as_u32) {
                            let n = channels.len();
                            channels.entry(id).or_insert_with(|| format!("<ch{n}>"));
                        }
                    }
                }
            }
        }
        Self { users, channels }
    }

    fn user(&self, id: u32) -> String {
        self.users.get(&id).cloned().unwrap_or_else(|| if id >= 0x7fff_0000 { format!("{id:#x}") } else { "<other user>".into() })
    }

    fn channel(&self, id: u32) -> String {
        self.channels.get(&id).cloned().unwrap_or_else(|| format!("{id:#x}"))
    }
}

fn be32(b: &[u8]) -> Option<u32> {
    b.try_into().ok().map(u32::from_be_bytes)
}

fn text_or_hex(data: &[u8]) -> String {
    let texty = !data.is_empty() && data.iter().all(|&b| b >= 0x20 || b == b'\r' || b == b'\n');
    if texty { format!("{:?}", macroman::decode(data)) } else if data.is_empty() { "\"\"".into() } else { hex(data) }
}

fn normalize_news(text: &str) -> String {
    text.lines()
        .map(|l| if l.starts_with("Date: ") { "Date: <date>".to_string() } else { l.to_string() })
        .collect::<Vec<_>>()
        .join("\\r")
}

/// Structures that need parsing to normalize; `None` falls back to the
/// generic rendering.
fn structured(cmd: u32, tag: u32, d: &[u8], sent: bool, n: &Norm) -> Option<String> {
    let mut r = Reader::new(d);
    Some(match (cmd, tag, sent) {
        (3, 1, false) => format!("{} privs {}", n.user(be32(&d[..4])?), hex(&d[4..])),
        (3, 3, false) => {
            let count = r.u32().ok()?;
            let mut users = Vec::new();
            for _ in 0..count {
                let nick = macroman::decode(r.string().ok()?);
                let flags = r.u16().ok()?;
                let id = r.u32().ok()?;
                let icon = r.u32().ok()?;
                r.bytes(icon as usize).ok()?;
                users.push(format!("{} {nick:?} {flags:#06x} icon {icon}", n.user(id)));
            }
            users.sort();
            format!("users [{}]", users.join(", "))
        }
        (0x80, 5, false) => {
            let count = r.u32().ok()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let id = r.u32().ok()?;
                let mode = r.u8().ok()?;
                out.push(format!("{}:{mode:02x}", n.user(id)));
            }
            format!("members [{}]", out.join(", "))
        }
        (0x86, 0xa, false) => {
            let count = r.u32().ok()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let id = r.u32().ok()?;
                let members = r.u32().ok()?;
                let flags = r.u16().ok()?;
                let name = macroman::decode(r.string().ok()?);
                out.push(format!("{} {name:?} {members} members flags {flags:#06x}", n.channel(id)));
            }
            format!("channels [{}]", out.join(", "))
        }
        (0x09, 2, false) => {
            let path = show_path(r.string().ok()?);
            let count = r.u16().ok()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let elen = r.u16().ok()?;
                let name = String::from_utf8_lossy(r.string().ok()?).into_owned();
                let size = r.u32().ok()?;
                let _date = r.u32().ok()?;
                let creator = macroman::decode(r.bytes(4).ok()?);
                let ty = macroman::decode(r.bytes(4).ok()?);
                let flags = r.u16().ok()?;
                out.push(format!("{name:?} len {elen} size {size} {creator}/{ty} flags {flags:#06x}"));
            }
            format!("listing {path:?} [{}]", out.join(", "))
        }
        (0x14, 3, false) if d.len() == 30 => {
            let flags = r.u16().ok()?;
            let size = r.u32().ok()?;
            r.u32().ok()?;
            r.u32().ok()?;
            let ty = r.bytes(4).ok()?;
            let creator = r.bytes(4).ok()?;
            let finder = hex(r.bytes(8).ok()?);
            let is_folder = flags != 0;
            if is_folder {
                format!("info flags {flags:#06x} size {size} <folder finder info>")
            } else {
                format!("info flags {flags:#06x} size {size} {}/{} finder {finder}", macroman::decode(ty), macroman::decode(creator))
            }
        }
        (0xcd, 0x10, false) => {
            let count = r.u32().ok()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let e = r.bytes(account::LIST_ENTRY_LEN).ok()?;
                let cstr = |b: &[u8]| macroman::decode(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
                out.push(format!("{:?} {:?} class {}", cstr(&e[..0x40]), cstr(&e[0x40..0x82]), e[0x86]));
            }
            format!("accounts [{}]", out.join(", "))
        }
        (0xce, 1, false) => {
            let cstr = |b: &[u8]| macroman::decode(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
            format!("entry {:?} {:?} class {}", cstr(&d[..0x40]), cstr(&d[0x40..0x82]), d.get(0x86)?)
        }
        (0xca, 1, false) | (0xcb, 1, true) => {
            let rec = Record::decode(d).ok()?;
            format!(
                "record {:?} {:?} password {} privs {:016x}",
                macroman::decode(&rec.login),
                macroman::decode(&rec.real_name),
                hex(&rec.password),
                rec.privileges
            )
        }
        (0xFD_0000, 0xFD_0000, false) | (0xFD_0001, 0xFD_0000, false) => format!("{:?}", normalize_news(&macroman::decode(d))),
        (0xe0, 1, false) => {
            let dir = r.u8().ok()?;
            let user = n.user(r.u32().ok()?);
            let name = macroman::decode(r.string().ok()?);
            format!("transfer dir {dir} {user} {name:?} <sizes>")
        }
        (0x17, 0x86, false) => {
            let count = r.u16().ok()?;
            format!("{count} transfers")
        }
        (0xa1, 1, false) | (0xa4, 2, false) if !sent => {
            // Newsgroup lists: s32 count then names (and details for 0xa4).
            let count = r.u32().ok()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let name = macroman::decode(r.string().ok()?);
                if cmd == 0xa4 {
                    let articles = r.u32().ok()?;
                    let expiry = r.u32().ok()?;
                    let perms = r.u16().ok()?;
                    out.push(format!("{name:?} {articles} articles expiry {expiry} perms {perms:#06x}"));
                } else {
                    out.push(format!("{name:?}"));
                }
            }
            if r.remaining() > 0 {
                return None;
            }
            format!("groups [{}]", out.join(", "))
        }
        _ => return None,
    })
}

fn render_field(cmd: u32, f: &Field, sent: bool, n: &Norm) -> String {
    let d = &f.data;
    let user_tag = matches!(
        (cmd, f.tag),
        (0x06, 1) | (0x07, 1) | (0x08, 1) | (0x18, 1) | (0xF000_0000, 1) | (0x17, 1) | (0x04, 1) | (0x05, 1)
    ) || (matches!(cmd, 0x82 | 0x87 | 0x88 | 0x0f | 0x89 | 0x0c) && f.tag == 7)
        || (matches!(cmd, 0x89 | 0x0c) && f.tag == 0xb)
        || (cmd == 0xd0 && f.tag == 2);
    let channel_tag = matches!(cmd, 0x80..=0x89 | 0x0f | 0x0c) && f.tag == 0;
    let value = if user_tag && d.len() == 4 {
        n.user(be32(d).unwrap())
    } else if channel_tag && d.len() == 4 {
        n.channel(be32(d).unwrap())
    } else if cmd == 0x01 || (cmd == 0x02 && f.tag == 2) {
        "<random>".into()
    } else if (cmd == 0x17 && matches!(f.tag, 0x85 | 0x87 | 0x84)) || (cmd == 0xc0 && matches!(f.tag, 0x24..=0x2e | 0x34 | 0x36) && f.tag != 0x2f) {
        format!("<volatile {} bytes>", d.len())
    } else if let Some(s) = structured(cmd, f.tag, d, sent, n) {
        s
    } else {
        text_or_hex(d)
    };
    format!("{:#x}[{}]={value}", f.tag, d.len())
}

fn render_packet(p: &Packet, sent: bool, n: &Norm) -> String {
    let fields: Vec<String> = p.fields.iter().map(|f| render_field(p.command, f, sent, n)).collect();
    format!("{} {:#x} task {}: {}", if sent { ">" } else { "<" }, p.command, p.task, fields.join("  "))
}

fn transcript(clients: &[Client]) -> String {
    let n = Norm::new(clients);
    let mut out = String::new();
    for c in clients {
        out += &format!("=== client {}\n", c.name);
        for e in &c.events {
            match e {
                Event::Sent(p) => out += &render_packet(p, true, &n),
                Event::Received(p) => out += &render_packet(p, false, &n),
                Event::Note(s) => out += &format!("# {s}"),
            }
            out.push('\n');
        }
    }
    out
}

fn resolve(s: &str) -> anyhow::Result<SocketAddr> {
    let with_port = if s.contains(':') { s.to_string() } else { format!("{s}:6700") };
    with_port.to_socket_addrs()?.next().with_context(|| format!("no address for {s}"))
}

fn run(addr: SocketAddr, quiet: Duration, scenario: Scenario) -> String {
    let mut h = Harness { addr, quiet, clients: Vec::new() };
    if let Err(e) = scenario(&mut h) {
        h.clients.first_mut().map(|c| c.note(format!("scenario aborted: {}", short_error(&e))));
        if h.clients.is_empty() {
            return format!("scenario aborted: {e:#}\n");
        }
    }
    h.finish();
    transcript(&h.clients)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let all = scenarios();
    if args.list {
        for (name, _) in &all {
            println!("{name}");
        }
        return Ok(());
    }
    let (a, b) = (resolve(&args.a)?, resolve(&args.b)?);
    let quiet = Duration::from_millis(args.quiet_ms);
    for addr in [a, b] {
        let mut h = Harness { addr, quiet, clients: Vec::new() };
        prelude(&mut h).with_context(|| format!("prelude on {addr}"))?;
    }
    let mut failed = 0;
    for (name, scenario) in all {
        if !args.only.is_empty() && !args.only.iter().any(|o| name.contains(o.as_str())) {
            continue;
        }
        let ta = run(a, quiet, scenario);
        let tb = run(b, quiet, scenario);
        if let Some(dir) = &args.out {
            std::fs::create_dir_all(dir)?;
            std::fs::write(dir.join(format!("{name}.a.txt")), &ta)?;
            std::fs::write(dir.join(format!("{name}.b.txt")), &tb)?;
        }
        if ta == tb {
            println!("ok    {name}");
        } else {
            failed += 1;
            println!("DIFF  {name}");
            let diff = similar::TextDiff::from_lines(&ta, &tb);
            print!("{}", diff.unified_diff().context_radius(2).header(&args.a, &args.b));
        }
    }
    println!("{failed} scenario(s) differ");
    std::process::exit(if failed > 0 { 1 } else { 0 });
}
