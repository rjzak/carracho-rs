//! Chat channels (protocol.md, 4.10).

use carracho_proto::packet::{Field, Packet};
use carracho_proto::wire;

use super::{Ctx, Fail, Result};
use crate::codes::{cmd, err, privs};
use crate::state::{Channel, MAX_CHANNELS_PER_USER, MODE_OPERATOR, MODE_VOICE, channel_flags};

const MAX_NAME: usize = 64;
const MAX_PASSWORD: usize = 32;
const MAX_TOPIC: usize = 256;
const MAX_TEXT: usize = 2048;

fn clip(b: &[u8], n: usize) -> Vec<u8> {
    b[..b.len().min(n)].to_vec()
}

pub fn join(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::CHAT)?;
    let user = st.users.get(&c.uid).ok_or(Fail::Disconnect)?;
    if user.channels.len() >= MAX_CHANNELS_PER_USER {
        return Err(Fail::Error(err::TOO_MANY_CHANNELS));
    }
    let is_admin = user.has(privs::ADMIN);
    let password = clip(c.field(9).unwrap_or_default(), MAX_PASSWORD);
    let requested = c.u32(0).unwrap_or(0);
    let (id, created) = if requested != 0 {
        if !st.channels.contains_key(&requested) {
            return Err(Fail::Error(err::CHANNEL_NOT_FOUND));
        }
        (requested, false)
    } else {
        let name = c.field(1).filter(|n| !n.is_empty()).ok_or(Fail::Error(err::CHANNEL_NOT_FOUND))?;
        match st.find_channel_by_name(name) {
            Some(id) => (id, false),
            None => {
                let id = st.next_channel_id;
                st.next_channel_id += 1;
                let channel = Channel {
                    id,
                    name: clip(name, MAX_NAME),
                    topic: Vec::new(),
                    topic_setter: 0,
                    flags: 0,
                    password: password.clone(),
                    members: Vec::new(),
                };
                st.channels.insert(id, channel);
                (id, true)
            }
        }
    };
    let ch = st.channels.get_mut(&id).unwrap();
    if !created && !ch.password.is_empty() && ch.password != password {
        return Err(Fail::Error(err::WRONG_CHANNEL_PASSWORD));
    }
    if ch.mode_of(c.uid).is_some() {
        return Err(Fail::Error(err::ALREADY_IN_CHANNEL));
    }
    let server_channel = ch.flags & channel_flags::SERVER != 0;
    let mode = if created || (server_channel && is_admin) { MODE_OPERATOR } else { 0 };
    ch.members.push((c.uid, mode));
    let mut members = Vec::new();
    wire::put_u32(&mut members, ch.members.len() as u32);
    for &(uid, m) in &ch.members {
        wire::put_u32(&mut members, uid);
        members.push(m);
    }
    let reply = vec![
        Field::new(1, ch.name.clone()),
        Field::new(4, ch.topic.clone()),
        Field::u32(0, id),
        // The original sends 0 here (protocol.md, 4.10); the real flags are
        // what it meant to send.
        Field::u16(6, ch.flags),
        Field::new(5, members),
    ];
    if let Some(u) = st.users.get_mut(&c.uid) {
        u.channels.push(id);
    }
    let joined = Packet::new(cmd::CHANNEL_USER_JOINED, 0, vec![Field::u32(0, id), Field::u32(7, c.uid), Field::u8(8, mode)]);
    st.send_to_channel(id, &joined);
    c.reply(&st, cmd::JOIN_CHANNEL, reply);
    Ok(())
}

pub fn leave(c: &Ctx) -> Result {
    let mut st = c.st();
    if let Some(id) = c.u32(0) {
        st.leave_channel(c.uid, id);
    }
    c.reply(&st, cmd::LEAVE_CHANNEL, Vec::new());
    Ok(())
}

pub fn say(c: &Ctx) -> Result {
    let st = c.st();
    let id = c.u32(0).unwrap_or(0);
    let text = c.required(2)?;
    let style = c.u8(3).unwrap_or(0);
    let Some(ch) = st.channels.get(&id) else { return Ok(()) };
    let mode = ch.mode_of(c.uid).ok_or(Fail::Error(err::NOT_IN_CHANNEL))?;
    if ch.flags & channel_flags::MODERATED != 0 && mode & (MODE_OPERATOR | MODE_VOICE) == 0 {
        return Err(Fail::Error(err::MODERATED));
    }
    let p = Packet::new(
        cmd::CHAT,
        0,
        vec![Field::u32(0, id), Field::u32(7, c.uid), Field::u8(3, style), Field::new(2, clip(text, MAX_TEXT))],
    );
    st.send_to_channel(id, &p);
    Ok(())
}

pub fn set_mode(c: &Ctx) -> Result {
    let mut st = c.st();
    let id = c.u32(0).unwrap_or(0);
    let target = c.u32(7).unwrap_or(0);
    let mode = c.u8(8).unwrap_or(0);
    let ch = st.channels.get_mut(&id).ok_or(Fail::Error(err::CHANNEL_NOT_FOUND))?;
    if ch.mode_of(c.uid).is_none() {
        return Err(Fail::Error(err::NOT_IN_CHANNEL));
    }
    if !ch.is_operator(c.uid) {
        return Err(Fail::Error(err::NOT_OPERATOR));
    }
    let member = ch.members.iter_mut().find(|(uid, _)| *uid == target).ok_or(Fail::Error(err::NOT_A_MEMBER))?;
    member.1 = mode;
    let p = Packet::new(cmd::SET_MEMBER_MODE, 0, vec![Field::u32(0, id), Field::u32(7, target), Field::u8(8, mode)]);
    st.send_to_channel(id, &p);
    Ok(())
}

pub fn settings(c: &Ctx) -> Result {
    let mut st = c.st();
    let id = c.u32(0).unwrap_or(0);
    let ch = st.channels.get_mut(&id).ok_or(Fail::Error(err::CHANNEL_NOT_FOUND))?;
    if ch.mode_of(c.uid).is_none() {
        return Err(Fail::Error(err::NOT_A_MEMBER));
    }
    let op = ch.is_operator(c.uid);
    if let Some(topic) = c.field(4) {
        if topic != ch.topic.as_slice() {
            if ch.flags & channel_flags::TOPIC_OPS_ONLY != 0 && !op {
                return Err(Fail::Error(err::TOPIC_OPERATORS_ONLY));
            }
            ch.topic = clip(topic, MAX_TOPIC);
            ch.topic_setter = c.uid;
        }
    }
    if let Some(flags) = c.u16(6) {
        if op && id != crate::state::LOBBY {
            let kept = channel_flags::SERVER | channel_flags::KEPT;
            ch.flags = (ch.flags & kept) | (flags & !kept);
        }
    }
    let p = Packet::new(cmd::CHANNEL_SETTINGS, 0, vec![Field::u32(0, id), Field::new(4, ch.topic.clone()), Field::u16(6, ch.flags)]);
    st.send_to_channel(id, &p);
    Ok(())
}

pub fn list(c: &Ctx) -> Result {
    let st = c.st();
    let visible: Vec<&Channel> = st.channels.values().filter(|ch| ch.flags & channel_flags::HIDDEN == 0).collect();
    let mut out = Vec::new();
    wire::put_u32(&mut out, visible.len() as u32);
    for ch in visible {
        wire::put_u32(&mut out, ch.id);
        wire::put_u32(&mut out, ch.members.len() as u32);
        wire::put_u16(&mut out, ch.flags);
        wire::put_string(&mut out, &ch.name);
    }
    c.reply(&st, cmd::CHANNEL_LIST, vec![Field::new(0xa, out)]);
    Ok(())
}

pub fn invite(c: &Ctx) -> Result {
    let st = c.st();
    let id = c.u32(0).unwrap_or(0);
    let target = c.u32(7).unwrap_or(0);
    let ch = st.channels.get(&id).ok_or(Fail::Error(err::CHANNEL_NOT_FOUND))?;
    if st.users.contains_key(&target) && ch.mode_of(target).is_none() {
        let p = Packet::new(cmd::INVITE, 0, vec![Field::u32(0, id), Field::u32(0xb, c.uid), Field::new(1, ch.name.clone())]);
        st.send_to(target, p);
        c.complete(&st);
    }
    Ok(())
}

pub fn decline(c: &Ctx) -> Result {
    let st = c.st();
    let id = c.u32(0).unwrap_or(0);
    if let Some(inviter) = c.u32(0xb) {
        st.send_to(inviter, Packet::new(cmd::DECLINE_INVITATION, 0, vec![Field::u32(0, id), Field::u32(7, c.uid)]));
    }
    Ok(())
}
