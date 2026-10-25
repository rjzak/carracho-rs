//! Runtime server state: connected users, chat channels, transfers and
//! statistics. Everything sits behind one mutex, which is never held across
//! an `.await`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use carracho_proto::packet::{Field, Packet};
use carracho_proto::{macroman, mactime, wire};
use tokio::sync::mpsc::UnboundedSender;

use crate::codes::{cmd, privs};
use crate::files::{Requester, Vfs};
use crate::store::Store;

/// Messages to a connection's writer task.
#[derive(Debug)]
pub enum Out {
    Packet(Packet),
    /// Switch the outgoing key (after the login reply).
    Rekey(Vec<u8>),
    /// Close the connection after what has been queued.
    Close,
}

/// User flags in the user list (protocol.md, 4.7).
pub const USER_ADMIN: u16 = 0x8000;
pub const USER_IDLE: u16 = 0x0100;

/// The lobby channel.
pub const LOBBY: u32 = 1;
/// Most channels one user may be in.
pub const MAX_CHANNELS_PER_USER: usize = 6;

/// Channel flags (protocol.md, 4.10).
pub mod channel_flags {
    pub const SERVER: u16 = 0x8000;
    pub const KEPT: u16 = 0x4000;
    pub const HIDDEN: u16 = 0x2000;
    pub const MODERATED: u16 = 0x1000;
    pub const TOPIC_OPS_ONLY: u16 = 0x0800;
}

/// Member modes.
pub const MODE_OPERATOR: u8 = 0x80;
pub const MODE_VOICE: u8 = 0x40;

pub struct User {
    pub id: u32,
    pub nick: Vec<u8>,
    pub icon: Vec<u8>,
    pub login: String,
    pub privileges: u64,
    pub ip: Ipv4Addr,
    pub tx: UnboundedSender<Out>,
    pub real_name: Vec<u8>,
    pub email: Vec<u8>,
    pub about: Vec<u8>,
    pub login_time: u32,
    pub last_activity: Instant,
    pub idle: bool,
    pub state: u8,
    pub channels: Vec<u32>,
    /// The session secret, which also keys this user's data connections.
    pub secret: Vec<u8>,
}

impl User {
    pub fn flags(&self) -> u16 {
        let mut f = 0;
        if privs::has(self.privileges, privs::ADMIN) {
            f |= USER_ADMIN;
        }
        if self.idle {
            f |= USER_IDLE;
        }
        f
    }

    pub fn has(&self, bit: u32) -> bool {
        privs::has(self.privileges, bit)
    }

    pub fn requester(&self) -> Requester {
        Requester { login: self.login.clone(), privileges: self.privileges }
    }

    pub fn send(&self, p: Packet) {
        let _ = self.tx.send(Out::Packet(p));
    }
}

pub struct Channel {
    pub id: u32,
    pub name: Vec<u8>,
    pub topic: Vec<u8>,
    pub topic_setter: u32,
    pub flags: u16,
    pub password: Vec<u8>,
    /// Members in joining order, with their mode.
    pub members: Vec<(u32, u8)>,
}

impl Channel {
    pub fn mode_of(&self, user: u32) -> Option<u8> {
        self.members.iter().find(|(id, _)| *id == user).map(|&(_, m)| m)
    }

    pub fn is_operator(&self, user: u32) -> bool {
        self.mode_of(user).is_some_and(|m| m & MODE_OPERATOR != 0)
    }
}

/// A file transfer in progress.
pub struct Transfer {
    pub id: u64,
    pub user: u32,
    pub upload: bool,
    pub name: Vec<u8>,
    pub total: u64,
    pub done: Arc<AtomicU64>,
    pub started: u32,
}

#[derive(Default)]
pub struct Stats {
    pub hits: u32,
    pub peak: u32,
    pub incorrect_logins: u32,
    pub total_downloads: u32,
    pub total_uploads: u32,
    pub private_messages: u32,
}

pub struct State {
    pub store: Store,
    pub users: BTreeMap<u32, User>,
    pub next_user_id: u32,
    pub channels: BTreeMap<u32, Channel>,
    pub next_channel_id: u32,
    pub transfers: Vec<Transfer>,
    pub next_transfer_id: u64,
    pub stats: Stats,
    pub connections_per_ip: HashMap<Ipv4Addr, u32>,
    pub data_connections_per_ip: HashMap<Ipv4Addr, u32>,
    pub log: VecDeque<String>,
    pub emptying_trash: bool,
}

/// Lines of server log kept for the log viewer.
const LOG_LINES: usize = 2000;

impl State {
    pub fn new(store: Store) -> Self {
        let mut channels = BTreeMap::new();
        channels.insert(LOBBY, lobby());
        Self {
            store,
            users: BTreeMap::new(),
            next_user_id: 1,
            channels,
            next_channel_id: LOBBY + 1,
            transfers: Vec::new(),
            next_transfer_id: 1,
            stats: Stats::default(),
            connections_per_ip: HashMap::new(),
            data_connections_per_ip: HashMap::new(),
            log: VecDeque::new(),
            emptying_trash: false,
        }
    }

    pub fn log(&mut self, line: String) {
        tracing::info!("{line}");
        let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        self.log.push_back(format!("{stamp}  {line}"));
        while self.log.len() > LOG_LINES {
            self.log.pop_front();
        }
    }

    /// Send to everyone logged in.
    pub fn broadcast(&self, p: &Packet) {
        for u in self.users.values() {
            u.send(p.clone());
        }
    }

    /// Send to everyone except `except`.
    pub fn broadcast_except(&self, except: u32, p: &Packet) {
        for u in self.users.values().filter(|u| u.id != except) {
            u.send(p.clone());
        }
    }

    pub fn send_to(&self, user: u32, p: Packet) {
        if let Some(u) = self.users.get(&user) {
            u.send(p);
        }
    }

    /// Send to every member of a channel.
    pub fn send_to_channel(&self, channel: u32, p: &Packet) {
        if let Some(ch) = self.channels.get(&channel) {
            for &(id, _) in &ch.members {
                self.send_to(id, p.clone());
            }
        }
    }

    /// The user list structure (login reply tag 3).
    pub fn user_list(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u32(&mut out, self.users.len() as u32);
        for u in self.users.values() {
            wire::put_string(&mut out, &u.nick);
            wire::put_u16(&mut out, u.flags());
            wire::put_u32(&mut out, u.id);
            wire::put_u32(&mut out, u.icon.len() as u32);
            out.extend_from_slice(&u.icon);
        }
        out
    }

    /// Push 7: a user joined the server.
    pub fn user_joined_packet(u: &User) -> Packet {
        let mut fields = vec![Field::u32(1, u.id), Field::new(2, u.nick.clone()), Field::u16(3, u.flags())];
        if !u.icon.is_empty() {
            fields.push(Field::new(0xb4, u.icon.clone()));
        }
        Packet::new(cmd::USER_JOINED, 0, fields)
    }

    /// Remove a user from a channel, telling the remaining members.
    pub fn leave_channel(&mut self, user: u32, channel: u32) {
        let Some(ch) = self.channels.get_mut(&channel) else { return };
        let before = ch.members.len();
        ch.members.retain(|&(id, _)| id != user);
        if ch.members.len() == before {
            return;
        }
        let empty = ch.members.is_empty();
        let server_channel = ch.flags & channel_flags::SERVER != 0;
        if let Some(u) = self.users.get_mut(&user) {
            u.channels.retain(|&c| c != channel);
        }
        if empty {
            if server_channel {
                let ch = self.channels.get_mut(&channel).unwrap();
                ch.topic.clear();
                ch.topic_setter = 0;
            } else {
                self.channels.remove(&channel);
            }
        } else {
            let p = Packet::new(cmd::CHANNEL_USER_LEFT, 0, vec![Field::u32(0, channel), Field::u32(7, user)]);
            self.send_to_channel(channel, &p);
        }
    }

    /// Remove a disconnected user: leave their channels and tell everyone.
    pub fn remove_user(&mut self, user: u32) {
        let Some(u) = self.users.get(&user) else { return };
        let channels = u.channels.clone();
        let line = format!("\"{}\" ({}) logged out", macroman::decode(&u.nick), u.login);
        for c in channels {
            self.leave_channel(user, c);
        }
        self.users.remove(&user);
        self.transfers.retain(|t| t.user != user);
        self.broadcast(&Packet::new(cmd::USER_LEFT, 0, vec![Field::u32(1, user)]));
        self.log(line);
    }

    /// Disconnect a user (kick, ban, account deleted).
    pub fn disconnect(&mut self, user: u32) {
        if let Some(u) = self.users.get(&user) {
            let _ = u.tx.send(Out::Close);
        }
        self.remove_user(user);
    }

    pub fn find_channel_by_name(&self, name: &[u8]) -> Option<u32> {
        self.channels.values().find(|c| c.name.eq_ignore_ascii_case(name)).map(|c| c.id)
    }

    pub fn counts_by_class(&self) -> (u32, u32, u32) {
        let mut out = (0, 0, 0);
        for u in self.users.values() {
            match carracho_proto::account::account_class(u.privileges) {
                2 => out.0 += 1,
                1 => out.1 += 1,
                _ => out.2 += 1,
            }
        }
        out
    }

    pub fn transfers_of(&self, user: u32) -> usize {
        self.transfers.iter().filter(|t| t.user == user).count()
    }

    pub fn start_transfer(&mut self, user: u32, upload: bool, name: Vec<u8>, total: u64) -> (u64, Arc<AtomicU64>) {
        let id = self.next_transfer_id;
        self.next_transfer_id += 1;
        let done = Arc::new(AtomicU64::new(0));
        self.transfers.push(Transfer { id, user, upload, name, total, done: done.clone(), started: mactime::now() });
        if upload {
            self.stats.total_uploads += 1;
        } else {
            self.stats.total_downloads += 1;
        }
        (id, done)
    }

    pub fn end_transfer(&mut self, id: u64) {
        self.transfers.retain(|t| t.id != id);
    }

    pub fn transfer_bytes(t: &Transfer) -> u64 {
        t.done.load(Ordering::Relaxed)
    }
}

fn lobby() -> Channel {
    Channel {
        id: LOBBY,
        name: b"Public".to_vec(),
        topic: Vec::new(),
        topic_setter: 0,
        flags: channel_flags::SERVER,
        password: Vec::new(),
        members: Vec::new(),
    }
}

/// Everything shared by the server's tasks.
pub struct Server {
    pub state: Mutex<State>,
    pub vfs: Vfs,
    pub started: Instant,
    pub data_dir: PathBuf,
}

impl Server {
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}
