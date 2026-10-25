//! Server settings (4.12), accounts (4.14) and the transfer list (4.15).

use std::net::Ipv4Addr;

use carracho_proto::account::{self, Record};
use carracho_proto::packet::{Field, Packet};
use carracho_proto::wire::{self, Reader};
use carracho_proto::{macroman, mactime};

use super::{Ctx, Fail, Result};
use crate::codes::{cmd, err, privs};
use crate::files::Requester;
use crate::state::State;
use crate::store::{Account, IpRule, Settings, TrackerEntry};

/// Which privilege reads and which writes each settings tag; `None` for
/// read-only statistics.
fn settings_privileges(tag: u32) -> Option<(u32, Option<u32>)> {
    use privs::*;
    Some(match tag {
        4 => (AGREEMENT, Some(AGREEMENT)),
        5..=8 => (SERVER_INFO, Some(SERVER_INFO)),
        9 | 0x20..=0x23 | 0x2f => (ADVANCED_SETTINGS, Some(ADVANCED_SETTINGS)),
        0xc => (NEWS_ADMIN, Some(NEWS_ADMIN)),
        0x35 => (STATISTICS, Some(ADVANCED_SETTINGS)),
        0x30 | 0x32 | 0x33 => (TRACKERS, Some(TRACKERS)),
        0x24..=0x2e | 0x34 | 0x36 => (STATISTICS, None),
        _ => return None,
    })
}

fn text(s: &str) -> Vec<u8> {
    macroman::encode(s)
}

fn ip_list(rules: &[IpRule]) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_u32(&mut out, rules.len() as u32);
    for r in rules {
        wire::put_u32(&mut out, u32::from(r.address));
        wire::put_u32(&mut out, u32::from(r.mask));
        out.push(r.deny as u8);
        out.push(0);
    }
    out
}

fn parse_ip_list(data: &[u8]) -> Option<Vec<IpRule>> {
    let mut r = Reader::new(data);
    let count = r.u32().ok()?;
    let mut out = Vec::new();
    for _ in 0..count.min(4096) {
        let address = Ipv4Addr::from(r.u32().ok()?);
        let mask = Ipv4Addr::from(r.u32().ok()?);
        let deny = r.u8().ok()? != 0;
        r.u8().ok()?;
        out.push(IpRule { address, mask, deny });
    }
    Some(out)
}

fn tracker_list(trackers: &[TrackerEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_u16(&mut out, trackers.len() as u16);
    for t in trackers {
        wire::put_string(&mut out, &text(&t.name));
        wire::put_string(&mut out, &text(&t.host));
        wire::put_string(&mut out, b"");
        wire::put_u32(&mut out, 0);
    }
    out
}

fn parse_tracker_list(data: &[u8]) -> Option<Vec<TrackerEntry>> {
    let mut r = Reader::new(data);
    let count = r.u16().ok()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let name = macroman::decode(r.string().ok()?);
        let host = macroman::decode(r.string().ok()?);
        r.string().ok()?;
        r.u32().ok()?;
        out.push(TrackerEntry { name, host });
    }
    Some(out)
}

/// The value of one settings tag.
fn setting(st: &State, server_uptime: u32, tag: u32) -> Option<Vec<u8>> {
    let s = &st.store.settings;
    let u16b = |v: u16| v.to_be_bytes().to_vec();
    let u32b = |v: u32| v.to_be_bytes().to_vec();
    let (admins, holders, guests) = st.counts_by_class();
    let in_progress = |upload| st.transfers.iter().filter(|t| t.upload == upload).count() as u32;
    Some(match tag {
        // With no agreement the original sends a single zero byte.
        4 if s.agreement.is_empty() => vec![0],
        4 => text(&s.agreement),
        5 => text(&s.name),
        6 => text(&s.location),
        7 => text(&s.operator),
        8 => text(&s.description),
        9 => u16b(s.port),
        0xc => u16b(s.news_expire_time),
        0x20 => u16b(s.max_transfers),
        0x21 => u16b(s.max_transfers_per_user),
        0x22 => u16b(s.max_users),
        0x23 => u16b(s.max_connections_per_ip),
        0x24 => u32b(st.stats.hits),
        0x25 => u32b(st.stats.peak),
        0x26 => u32b(st.stats.incorrect_logins),
        0x27 => u32b(admins),
        0x28 => u32b(holders),
        0x29 => u32b(guests),
        0x2a => u32b(in_progress(false)),
        0x2b => u32b(st.stats.total_downloads),
        0x2c => u32b(in_progress(true)),
        0x2d => u32b(st.stats.total_uploads),
        0x2e => u32b(st.users.len() as u32),
        0x2f => ip_list(&s.ip_rules),
        0x30 => tracker_list(&s.trackers),
        0x32 => u32b(s.tracker_flags),
        0x33 => text(&s.tracker_description),
        0x34 => u32b(st.stats.private_messages),
        0x35 => s.folder_depth.to_be_bytes().to_vec(),
        // Not shown by the original client; meaning unknown. We report uptime.
        0x36 => u32b(server_uptime),
        _ => return None,
    })
}

pub fn get_settings(c: &Ctx) -> Result {
    let st = c.st();
    let mask = c.privileges(&st);
    let uptime = c.server.started.elapsed().as_secs() as u32;
    let mut fields = Vec::new();
    for f in &c.p.fields {
        let Some((read, _)) = settings_privileges(f.tag) else { continue };
        if !privs::has(mask, read) {
            continue;
        }
        if let Some(v) = setting(&st, uptime, f.tag) {
            fields.push(Field::new(f.tag, v));
        }
    }
    c.reply(&st, cmd::SETTINGS_REPLY, fields);
    Ok(())
}

fn apply_setting(s: &mut Settings, tag: u32, data: &[u8]) {
    let s16 = || <[u8; 2]>::try_from(data).ok().map(u16::from_be_bytes);
    let s32 = || <[u8; 4]>::try_from(data).ok().map(u32::from_be_bytes);
    let string = || macroman::decode(data);
    match tag {
        4 => s.agreement = if data == [0] { String::new() } else { string() },
        5 => s.name = string(),
        6 => s.location = string(),
        7 => s.operator = string(),
        8 => s.description = string().chars().take(255).collect(),
        9 => s.port = s16().unwrap_or(s.port),
        0xc => s.news_expire_time = s16().unwrap_or(s.news_expire_time),
        0x20 => s.max_transfers = s16().unwrap_or(s.max_transfers),
        0x21 => s.max_transfers_per_user = s16().unwrap_or(s.max_transfers_per_user),
        0x22 => s.max_users = s16().unwrap_or(s.max_users),
        0x23 => s.max_connections_per_ip = s16().unwrap_or(s.max_connections_per_ip),
        0x2f => s.ip_rules = parse_ip_list(data).unwrap_or_else(|| s.ip_rules.clone()),
        0x30 => s.trackers = parse_tracker_list(data).unwrap_or_else(|| s.trackers.clone()),
        0x32 => s.tracker_flags = s32().unwrap_or(s.tracker_flags),
        0x33 => s.tracker_description = string().chars().take(100).collect(),
        0x35 => s.folder_depth = s16().map(|v| v as i16).unwrap_or(s.folder_depth),
        _ => {}
    }
}

pub fn set_settings(c: &Ctx) -> Result {
    let mut st = c.st();
    let mask = c.privileges(&st);
    for f in &c.p.fields {
        // The original forgets to skip denied fields; we skip them.
        let Some((_, Some(write))) = settings_privileges(f.tag) else { continue };
        if privs::has(mask, write) {
            apply_setting(&mut st.store.settings, f.tag, &f.data);
        }
    }
    if let Err(e) = st.store.save_settings() {
        tracing::warn!("saving settings: {e:#}");
    }
    c.complete(&st);
    Ok(())
}

pub fn list_accounts(c: &Ctx) -> Result {
    let st = c.st();
    c.require(&st, privs::ACCOUNTS)?;
    let mut out = Vec::new();
    wire::put_u32(&mut out, st.store.accounts.len() as u32);
    for a in &st.store.accounts {
        out.extend_from_slice(&a.to_record().list_entry());
    }
    c.reply(&st, cmd::LIST_ACCOUNTS, vec![Field::new(0x10, out)]);
    Ok(())
}

pub fn get_account(c: &Ctx) -> Result {
    let st = c.st();
    c.require(&st, privs::ACCOUNTS)?;
    let login = macroman::decode(c.field(2).unwrap_or_default());
    let a = st.store.account(&login).ok_or(Fail::Error(err::NO_SUCH_ACCOUNT))?;
    c.reply(&st, cmd::ACCOUNT_REPLY, vec![Field::new(1, a.to_record().encode_masked())]);
    Ok(())
}

fn valid_login(login: &[u8]) -> bool {
    !login.is_empty() && login.len() <= account::MAX_LOGIN_LEN && !login.contains(&b':')
}

pub fn save_account(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::ACCOUNTS)?;
    let record = Record::decode(c.required(1)?).map_err(|_| Fail::Error(err::INVALID_LOGIN_NAME))?;
    if !valid_login(&record.login) {
        return Err(Fail::Error(err::INVALID_LOGIN_NAME));
    }
    let login = macroman::decode(&record.login);
    let keep_password = record.password.first() == Some(&account::KEEP_PASSWORD);
    let password = macroman::decode(&account::scramble(&record.password));
    let now = mactime::now();
    let (modified, given) = match c.field(3) {
        Some(old) => {
            let old = macroman::decode(old);
            let clash = st.store.account(&login).is_some_and(|a| !a.login.eq_ignore_ascii_case(&old));
            if clash {
                return Err(Fail::Error(err::ACCOUNT_EXISTS));
            }
            let a = st.store.account_mut(&old).ok_or(Fail::Error(err::NO_SUCH_ACCOUNT))?;
            let renamed = !a.login.eq_ignore_ascii_case(&login);
            let old_login = std::mem::replace(&mut a.login, login.clone());
            a.real_name = macroman::decode(&record.real_name);
            if !keep_password {
                a.password = password;
            }
            a.privileges = record.privileges;
            a.modified = now;
            if renamed {
                let (from, to) = (c.server.vfs.home(&old_login), c.server.vfs.home(&login));
                if from.exists() && !to.exists() {
                    let _ = std::fs::rename(from, to);
                }
            }
            (true, old)
        }
        None => {
            if st.store.account(&login).is_some() {
                return Err(Fail::Error(err::ACCOUNT_EXISTS));
            }
            st.store.accounts.push(Account {
                login: login.clone(),
                real_name: macroman::decode(&record.real_name),
                password: if keep_password { String::new() } else { password },
                created: now,
                modified: now,
                last_login: 0,
                privileges: record.privileges,
            });
            (false, login.clone())
        }
    };
    let _ = c.server.vfs.ensure_home(&Requester { login: login.clone(), privileges: record.privileges });
    if let Err(e) = st.store.save_accounts() {
        tracing::warn!("saving accounts: {e:#}");
    }
    let entry = st.store.account(&login).map(|a| a.to_record().list_entry()).unwrap_or_default();
    c.complete(&st);
    let push = vec![Field::u8(0x11, modified as u8), Field::new(3, macroman::encode(&given)), Field::new(1, entry)];
    st.send_to(c.uid, Packet::new(cmd::ACCOUNT_CHANGED, 0, push));
    let actor = st.users.get(&c.uid).map(|u| u.login.clone()).unwrap_or_default();
    st.log(format!("Account \"{login}\" {} by {actor}", if modified { "modified" } else { "created" }));
    Ok(())
}

pub fn delete_account(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::ACCOUNTS)?;
    let given = c.field(2).unwrap_or_default().to_vec();
    let login = macroman::decode(&given);
    let before = st.store.accounts.len();
    st.store.accounts.retain(|a| !a.login.eq_ignore_ascii_case(&login));
    if st.store.accounts.len() == before {
        return Err(Fail::Error(err::NO_SUCH_ACCOUNT));
    }
    if let Err(e) = st.store.save_accounts() {
        tracing::warn!("saving accounts: {e:#}");
    }
    c.complete(&st);
    st.send_to(c.uid, Packet::new(cmd::ACCOUNT_CHANGED, 0, vec![Field::u8(0x11, 2), Field::new(3, given)]));
    st.log(format!("Account \"{login}\" deleted"));
    Ok(())
}

pub fn transfers(c: &Ctx) -> Result {
    let st = c.st();
    c.require(&st, privs::STATISTICS)?;
    let mut fields = Vec::new();
    for t in &st.transfers {
        let mut out = vec![t.upload as u8];
        wire::put_u32(&mut out, t.user);
        wire::put_string(&mut out, &t.name);
        wire::put_u64(&mut out, t.total);
        wire::put_u64(&mut out, State::transfer_bytes(t));
        wire::put_u64(&mut out, t.started as u64);
        fields.push(Field::new(1, out));
    }
    c.reply(&st, cmd::TRANSFERS, fields);
    Ok(())
}
