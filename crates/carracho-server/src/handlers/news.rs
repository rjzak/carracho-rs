//! Flat news (4.17) and newsgroups (4.18).

use carracho_proto::macroman;
use carracho_proto::packet::{Field, Packet};
use carracho_proto::wire;

use super::{Ctx, Fail, Result};
use crate::codes::{cmd, err, privs};
use crate::state::State;
use crate::store::{Article, Newsgroup, group_perm};

/// The date line in flat news headers, as the original formats it.
pub fn news_date() -> String {
    chrono::Local::now().format("%-m/%-d/%y, %-I:%M %p").to_string()
}

pub fn get_flat(c: &Ctx) -> Result {
    let st = c.st();
    let fields = st.store.flat_news.iter().map(|a| Field::new(cmd::POST_NEWS, macroman::encode(a))).collect();
    c.reply(&st, cmd::GET_NEWS, fields);
    Ok(())
}

pub fn post_flat(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::POST_NEWS)?;
    let text = macroman::decode(c.required(cmd::POST_NEWS)?);
    let user = st.users.get(&c.uid).ok_or(Fail::Disconnect)?;
    let nick = macroman::decode(&user.nick);
    let real_name = st.store.account(&user.login).map(|a| a.real_name.clone()).unwrap_or_default();
    let article = format!("From: {nick} ({real_name})\rDate: {}\r\r{text}", news_date());
    st.store.flat_news.push(article.clone());
    if let Err(e) = st.store.save_flat_news() {
        tracing::warn!("saving news: {e:#}");
    }
    st.broadcast(&Packet::new(cmd::POST_NEWS, 0, vec![Field::new(cmd::POST_NEWS, macroman::encode(&article))]));
    c.complete(&st);
    Ok(())
}

pub fn delete_flat(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    let n = c.u32(cmd::DELETE_NEWS).unwrap_or(0);
    if n >= 1 && (n as usize) <= st.store.flat_news.len() {
        st.store.flat_news.remove(n as usize - 1);
        if let Err(e) = st.store.save_flat_news() {
            tracing::warn!("saving news: {e:#}");
        }
    }
    st.broadcast(&Packet::new(cmd::DELETE_NEWS, 0, vec![Field::u32(cmd::DELETE_NEWS, n)]));
    c.complete(&st);
    Ok(())
}

pub fn delete_all_flat(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    st.store.flat_news.clear();
    if let Err(e) = st.store.save_flat_news() {
        tracing::warn!("saving news: {e:#}");
    }
    st.broadcast(&Packet::new(cmd::DELETE_ALL_NEWS, 0, Vec::new()));
    c.complete(&st);
    Ok(())
}

/// The (read, post) permission bits that apply to a user.
pub fn group_bits(privileges: u64) -> (u16, u16) {
    if privs::has(privileges, privs::ADMIN) {
        (group_perm::ADMIN_READ, group_perm::ADMIN_POST)
    } else if privs::has(privileges, privs::ACCOUNT_HOLDER) {
        (group_perm::HOLDER_READ, group_perm::HOLDER_POST)
    } else {
        (group_perm::GUEST_READ, group_perm::GUEST_POST)
    }
}

pub fn can_read(g: &Newsgroup, privileges: u64) -> bool {
    g.permissions & group_bits(privileges).0 != 0
}

pub fn can_post(g: &Newsgroup, privileges: u64) -> bool {
    g.permissions & group_bits(privileges).1 != 0
}

pub fn list_groups(c: &Ctx) -> Result {
    let st = c.st();
    let mask = c.privileges(&st);
    let (read, post) = group_bits(mask);
    let groups: Vec<&Newsgroup> = st.store.newsgroups.iter().filter(|g| g.permissions & (read | post) != 0).collect();
    let mut out = Vec::new();
    wire::put_u32(&mut out, groups.len() as u32);
    for g in groups {
        wire::put_string(&mut out, &macroman::encode(&g.name));
    }
    c.reply(&st, cmd::NEWSGROUP_REPLY, vec![Field::new(1, out)]);
    Ok(())
}

pub fn admin_list_groups(c: &Ctx) -> Result {
    let st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    let mut out = Vec::new();
    wire::put_u32(&mut out, st.store.newsgroups.len() as u32);
    for g in &st.store.newsgroups {
        wire::put_string(&mut out, &macroman::encode(&g.name));
        wire::put_u32(&mut out, g.articles.len() as u32);
        wire::put_u32(&mut out, g.expiry);
        wire::put_u16(&mut out, g.permissions);
    }
    c.reply(&st, cmd::ADMIN_NEWSGROUP_REPLY, vec![Field::new(2, out)]);
    Ok(())
}

fn save_groups(st: &State) {
    if let Err(e) = st.store.save_newsgroups() {
        tracing::warn!("saving newsgroups: {e:#}");
    }
}

pub fn add_group(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    let raw = c.required(1)?;
    let name = macroman::decode(&raw[..raw.len().min(64)]);
    if name.is_empty() || st.store.newsgroup(&name).is_some() {
        return Err(Fail::Error(err::NO_PRIVILEGE));
    }
    let expiry = c.u32(2).unwrap_or(0);
    let permissions = c.u16(3).unwrap_or(0);
    st.store.newsgroups.push(Newsgroup { name: name.clone(), expiry, permissions, next_id: 1, articles: Vec::new() });
    save_groups(&st);
    c.complete(&st);
    let push = vec![Field::u8(5, 0), Field::new(1, macroman::encode(&name)), Field::u32(2, expiry), Field::u16(3, permissions)];
    st.send_to(c.uid, Packet::new(cmd::NEWSGROUP_CHANGED, 0, push));
    Ok(())
}

pub fn change_group(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    let current = macroman::decode(c.required(4)?);
    let new_name = c.field(1).map(macroman::decode).unwrap_or_else(|| current.clone());
    if !new_name.eq_ignore_ascii_case(&current) && st.store.newsgroup(&new_name).is_some() {
        return Err(Fail::Error(err::NO_PRIVILEGE));
    }
    let g = st.store.newsgroup_mut(&current).ok_or(Fail::Error(err::NOT_FOUND))?;
    g.name = new_name.clone();
    if let Some(v) = c.u32(2) {
        g.expiry = v;
    }
    if let Some(v) = c.u16(3) {
        g.permissions = v;
    }
    let (expiry, permissions) = (g.expiry, g.permissions);
    save_groups(&st);
    c.complete(&st);
    let push = vec![
        Field::u8(5, 1),
        Field::new(4, macroman::encode(&current)),
        Field::new(1, macroman::encode(&new_name)),
        Field::u32(2, expiry),
        Field::u16(3, permissions),
    ];
    st.send_to(c.uid, Packet::new(cmd::NEWSGROUP_CHANGED, 0, push));
    Ok(())
}

pub fn delete_group(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    let raw = c.required(1)?.to_vec();
    let name = macroman::decode(&raw);
    let before = st.store.newsgroups.len();
    st.store.newsgroups.retain(|g| !g.name.eq_ignore_ascii_case(&name));
    if st.store.newsgroups.len() == before {
        return Err(Fail::Error(err::NOT_FOUND));
    }
    save_groups(&st);
    c.complete(&st);
    st.send_to(c.uid, Packet::new(cmd::NEWSGROUP_CHANGED, 0, vec![Field::u8(5, 2), Field::new(1, raw)]));
    Ok(())
}

/// The article header structure in the read-article reply (tag 1).
/// Field meanings beyond subject, ID and author are provisional.
fn article_header(a: &Article) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_string(&mut out, &macroman::encode(&a.subject));
    wire::put_u32(&mut out, a.id);
    wire::put_u32(&mut out, a.date);
    wire::put_u32(&mut out, a.parent);
    wire::put_string(&mut out, &macroman::encode(&a.author));
    wire::put_string(&mut out, b"");
    wire::put_u32(&mut out, a.styles.len() as u32);
    out
}

pub fn read_article(c: &Ctx) -> Result {
    let st = c.st();
    let mask = c.privileges(&st);
    let name = macroman::decode(c.field(1).unwrap_or_default());
    let id = c.u32(2).unwrap_or(0);
    let g = st.store.newsgroup(&name).ok_or(Fail::Error(err::NO_SUCH_ARTICLE))?;
    if !can_read(g, mask) {
        return Err(Fail::Error(err::NO_PRIVILEGE));
    }
    let a = g.articles.iter().find(|a| a.id == id).ok_or(Fail::Error(err::NO_SUCH_ARTICLE))?;
    let mut fields = vec![Field::new(1, article_header(a)), Field::new(2, macroman::encode(&a.text))];
    if !a.styles.is_empty() {
        fields.push(Field::new(3, a.styles.clone()));
    }
    c.reply(&st, cmd::NEWSGROUP_REPLY, fields);
    Ok(())
}

pub fn delete_article(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::NEWS_ADMIN)?;
    let name = macroman::decode(c.field(1).unwrap_or_default());
    let id = c.u32(2).unwrap_or(0);
    let g = st.store.newsgroup_mut(&name).ok_or(Fail::Error(err::NO_SUCH_ARTICLE))?;
    let before = g.articles.len();
    g.articles.retain(|a| a.id != id);
    if g.articles.len() == before {
        return Err(Fail::Error(err::NO_SUCH_ARTICLE));
    }
    save_groups(&st);
    c.complete(&st);
    Ok(())
}

/// The article index (data connection type 5).
pub fn article_index(g: &Newsgroup) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_string(&mut out, &macroman::encode(&g.name));
    wire::put_u32(&mut out, g.articles.len() as u32);
    for a in &g.articles {
        wire::put_u32(&mut out, a.id);
        wire::put_string(&mut out, &macroman::encode(&a.subject));
        wire::put_string(&mut out, &macroman::encode(&a.author));
        wire::put_u32(&mut out, a.date);
        wire::put_u32(&mut out, a.parent);
    }
    out
}
