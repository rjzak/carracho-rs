//! Request handlers, by area. Each handler runs on the requesting user's
//! connection task and takes the state lock only briefly.

mod admin;
mod chat;
mod files;
pub(crate) mod news;

use std::net::Ipv4Addr;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use carracho_proto::packet::{Field, Packet};
use carracho_proto::{macroman, wire};

use crate::codes::{cmd, err, privs};
use crate::state::{Server, State};
use crate::store::IpRule;


/// Why a request failed.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// Send error 0 with this code.
    Error(u16),
    /// Drop the connection.
    Disconnect,
}

impl From<u16> for Fail {
    fn from(code: u16) -> Self {
        Fail::Error(code)
    }
}

pub type Result<T = ()> = std::result::Result<T, Fail>;

/// A request being handled.
pub struct Ctx<'a> {
    pub server: &'a Arc<Server>,
    pub uid: u32,
    pub p: &'a Packet,
}

impl<'a> Ctx<'a> {
    pub fn st(&self) -> MutexGuard<'a, State> {
        self.server.lock()
    }

    pub fn field(&self, tag: u32) -> Option<&'a [u8]> {
        self.p.field(tag).map(|f| f.data.as_slice())
    }

    /// A field the request must have. The original server drops the
    /// connection when one is missing; we answer with an error instead.
    pub fn required(&self, tag: u32) -> Result<&'a [u8]> {
        self.field(tag).ok_or(Fail::Error(err::UNKNOWN_COMMAND))
    }

    pub fn u8(&self, tag: u32) -> Option<u8> {
        self.p.field(tag).and_then(Field::as_u8)
    }

    pub fn u16(&self, tag: u32) -> Option<u16> {
        self.p.field(tag).and_then(Field::as_u16)
    }

    pub fn u32(&self, tag: u32) -> Option<u32> {
        self.p.field(tag).and_then(Field::as_u32)
    }

    /// Reply to the requester with the request's task.
    pub fn reply(&self, st: &State, command: u32, fields: Vec<Field>) {
        st.send_to(self.uid, Packet::new(command, self.p.task, fields));
    }

    /// Answer with task complete.
    pub fn complete(&self, st: &State) {
        self.reply(st, cmd::TASK_COMPLETE, Vec::new());
    }

    pub fn privileges(&self, st: &State) -> u64 {
        st.users.get(&self.uid).map(|u| u.privileges).unwrap_or(0)
    }

    pub fn require(&self, st: &State, bit: u32) -> Result {
        if privs::has(self.privileges(st), bit) { Ok(()) } else { Err(Fail::Error(err::NO_PRIVILEGE)) }
    }
}

/// Record activity; an idle user becomes active again.
pub fn note_activity(server: &Arc<Server>, uid: u32) {
    let mut st = server.lock();
    let Some(u) = st.users.get_mut(&uid) else { return };
    u.last_activity = std::time::Instant::now();
    if u.idle {
        u.idle = false;
        u.state = 0;
        st.broadcast(&state_packet(uid, 0));
    }
}

/// After this long without a request, a user is marked idle.
pub const IDLE_AFTER: Duration = Duration::from_secs(10 * 60);

/// Mark users idle who have been inactive too long.
pub fn mark_idle(server: &Arc<Server>) {
    let mut st = server.lock();
    let now = std::time::Instant::now();
    let newly: Vec<u32> = st
        .users
        .values_mut()
        .filter(|u| !u.idle && now.duration_since(u.last_activity) >= IDLE_AFTER)
        .map(|u| {
            u.idle = true;
            u.state = 1;
            u.id
        })
        .collect();
    for id in newly {
        st.broadcast(&state_packet(id, 1));
    }
}

fn state_packet(uid: u32, state: u8) -> Packet {
    Packet::new(cmd::USER_STATE, 0, vec![Field::u32(1, uid), Field::u8(0xF000_0001, state)])
}

pub fn dispatch(server: &Arc<Server>, uid: u32, p: &Packet) -> Result {
    let c = Ctx { server, uid, p };
    match p.command {
        cmd::KEEPALIVE => Ok(()),
        cmd::KICK => kick(&c, false),
        cmd::BAN => kick(&c, true),
        cmd::PRIVATE_MESSAGE => private_message(&c),
        cmd::BROADCAST => broadcast(&c),
        cmd::CHANGE_NICK => change_nick(&c),
        cmd::SET_EXTENDED_INFO => set_extended_info(&c),
        cmd::GET_USER_INFO => user_info(&c),
        cmd::USER_STATE => set_state(&c),
        cmd::SERVER_INFO => server_info(&c),

        cmd::JOIN_CHANNEL => chat::join(&c),
        cmd::LEAVE_CHANNEL => chat::leave(&c),
        cmd::CHAT => chat::say(&c),
        cmd::SET_MEMBER_MODE => chat::set_mode(&c),
        cmd::CHANNEL_SETTINGS => chat::settings(&c),
        cmd::CHANNEL_LIST => chat::list(&c),
        cmd::INVITE => chat::invite(&c),
        cmd::DECLINE_INVITATION => chat::decline(&c),

        cmd::LIST_FOLDER => files::list(&c),
        cmd::CREATE_FOLDER => files::create_folder(&c),
        cmd::DELETE => files::delete(&c),
        cmd::GET_FILE_INFO => files::info(&c),
        cmd::SET_FILE_INFO => files::set_info(&c),
        cmd::MOVE => files::move_item(&c),
        cmd::EMPTY_TRASH => files::empty_trash(&c),

        cmd::GET_SETTINGS => admin::get_settings(&c),
        cmd::SET_SETTINGS => admin::set_settings(&c),
        cmd::LIST_ACCOUNTS => admin::list_accounts(&c),
        cmd::GET_ACCOUNT => admin::get_account(&c),
        cmd::SAVE_ACCOUNT => admin::save_account(&c),
        cmd::DELETE_ACCOUNT => admin::delete_account(&c),
        cmd::TRANSFERS => admin::transfers(&c),

        cmd::GET_NEWS => news::get_flat(&c),
        cmd::POST_NEWS => news::post_flat(&c),
        cmd::DELETE_NEWS => news::delete_flat(&c),
        cmd::DELETE_ALL_NEWS => news::delete_all_flat(&c),
        cmd::LIST_NEWSGROUPS => news::list_groups(&c),
        cmd::ADMIN_LIST_NEWSGROUPS => news::admin_list_groups(&c),
        cmd::ADD_NEWSGROUP => news::add_group(&c),
        cmd::CHANGE_NEWSGROUP => news::change_group(&c),
        cmd::DELETE_NEWSGROUP => news::delete_group(&c),
        cmd::READ_ARTICLE => news::read_article(&c),
        cmd::DELETE_ARTICLE => news::delete_article(&c),

        _ => Err(Fail::Error(err::UNKNOWN_COMMAND)),
    }
}

/// Kick (0x04) or ban (0x05) the users named in tag 1 fields.
fn kick(c: &Ctx, ban: bool) -> Result {
    let mut st = c.st();
    c.require(&st, if ban { privs::BAN } else { privs::KICK })?;
    let targets: Vec<u32> = c.p.fields.iter().filter(|f| f.tag == 1).filter_map(Field::as_u32).collect();
    let actor = st.users.get(&c.uid).map(|u| macroman::decode(&u.nick)).unwrap_or_default();
    for &target in &targets {
        let Some(u) = st.users.get(&target) else { continue };
        let (ip, nick) = (u.ip, macroman::decode(&u.nick));
        if ban {
            st.store.settings.ip_rules.insert(0, IpRule { address: ip, mask: Ipv4Addr::BROADCAST, deny: true });
            if let Err(e) = st.store.save_settings() {
                tracing::warn!("saving settings: {e:#}");
            }
            st.log(format!("\"{nick}\" ({ip}) banned by \"{actor}\""));
        } else {
            st.log(format!("\"{nick}\" disconnected by \"{actor}\""));
        }
        st.disconnect(target);
    }
    if targets.last() != Some(&c.uid) {
        c.complete(&st);
    }
    Ok(())
}

fn private_message(c: &Ctx) -> Result {
    let to = c.u32(1).ok_or(Fail::Error(err::USER_NOT_FOUND))?;
    let text = c.required(2)?;
    let mut st = c.st();
    if !st.users.contains_key(&to) {
        return Err(Fail::Error(err::USER_NOT_FOUND));
    }
    let mut fields = vec![Field::u32(1, c.uid), Field::new(2, text.to_vec())];
    if let Some(second) = c.field(3) {
        fields.push(Field::new(3, second.to_vec()));
    }
    st.send_to(to, Packet::new(cmd::PRIVATE_MESSAGE, 0, fields));
    st.stats.private_messages += 1;
    c.complete(&st);
    Ok(())
}

fn broadcast(c: &Ctx) -> Result {
    let st = c.st();
    c.require(&st, privs::BROADCAST)?;
    let text = c.required(1)?;
    st.broadcast(&Packet::new(cmd::BROADCAST, 0, vec![Field::new(1, text.to_vec()), Field::u32(2, c.uid)]));
    c.complete(&st);
    Ok(())
}

fn change_nick(c: &Ctx) -> Result {
    let mut st = c.st();
    let Some(u) = st.users.get_mut(&c.uid) else { return Ok(()) };
    if let Some(nick) = c.field(2) {
        u.nick = nick[..nick.len().min(64)].to_vec();
    }
    let mut fields = vec![Field::u32(1, c.uid), Field::new(2, u.nick.clone())];
    if let Some(icon) = c.field(5) {
        if icon.len() <= 0x27c {
            u.icon = icon.to_vec();
            fields.push(Field::new(0xb4, u.icon.clone()));
        }
    }
    st.broadcast(&Packet::new(cmd::CHANGE_NICK, 0, fields));
    Ok(())
}

fn set_extended_info(c: &Ctx) -> Result {
    let mut st = c.st();
    let Some(u) = st.users.get_mut(&c.uid) else { return Ok(()) };
    let clip = |b: &[u8], n: usize| b[..b.len().min(n)].to_vec();
    if let Some(v) = c.field(0xb0) {
        u.real_name = clip(v, 64);
    }
    if let Some(v) = c.field(0xb1) {
        u.email = clip(v, 64);
    }
    if let Some(v) = c.field(0xb2) {
        u.about = clip(v, 128);
    }
    Ok(())
}

fn user_info(c: &Ctx) -> Result {
    let target = c.u32(1).ok_or(Fail::Error(err::USER_NOT_FOUND))?;
    let st = c.st();
    let u = st.users.get(&target).ok_or(Fail::Error(err::USER_NOT_FOUND))?;
    let mut fields = Vec::new();
    if !u.icon.is_empty() {
        fields.push(Field::new(0xb4, u.icon.clone()));
    }
    fields.push(Field::new(4, u.nick.clone()));
    fields.push(Field::new(0xb1, u.email.clone()));
    fields.push(Field::new(0xb2, u.about.clone()));
    fields.push(Field::new(0xb0, u.real_name.clone()));
    if privs::has(c.privileges(&st), privs::EXTENDED_USER_INFO) {
        let ticks = (u.last_activity.elapsed().as_millis() * 60 / 1000).min(u32::MAX as u128) as u32;
        let mut transfers = Vec::new();
        let mine: Vec<_> = st.transfers.iter().filter(|t| t.user == target).collect();
        wire::put_u16(&mut transfers, mine.len() as u16);
        for t in mine {
            wire::put_u32(&mut transfers, t.id as u32);
            transfers.push(t.upload as u8);
            wire::put_string(&mut transfers, &t.name);
            transfers.push(0);
        }
        fields.push(Field::u32(0x85, u.login_time));
        fields.push(Field::u32(0x87, ticks));
        fields.push(Field::u32(0x84, u32::from(u.ip)));
        fields.push(Field::new(0x88, macroman::encode(&u.login)));
        fields.push(Field::new(0x86, transfers));
    }
    c.reply(&st, cmd::GET_USER_INFO, fields);
    Ok(())
}

fn set_state(c: &Ctx) -> Result {
    let mut st = c.st();
    let state = c.u8(0xF000_0001).unwrap_or(0);
    if let Some(u) = st.users.get_mut(&c.uid) {
        u.state = state;
    }
    st.broadcast(&state_packet(c.uid, state));
    Ok(())
}

fn server_info(c: &Ctx) -> Result {
    let st = c.st();
    let s = &st.store.settings;
    let fields = vec![
        Field::new(2, macroman::encode(&s.name)),
        Field::new(6, macroman::encode(&s.location)),
        Field::new(7, macroman::encode(&s.operator)),
        Field::new(8, macroman::encode(&s.description)),
    ];
    c.reply(&st, cmd::SERVER_INFO, fields);
    Ok(())
}
