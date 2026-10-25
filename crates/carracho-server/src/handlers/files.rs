//! File commands on the main connection (protocol.md, 4.15).

use carracho_proto::macroman;
use carracho_proto::packet::Field;

use super::{Ctx, Fail, Result};
use crate::codes::{cmd, err, privs};
use crate::files::{Item, Requester};
use crate::state::State;

const MAX_NAME: usize = 255;
const MAX_COMMENT: usize = 512;

pub fn requester_of(st: &State, uid: u32) -> Requester {
    st.users.get(&uid).map(|u| u.requester()).unwrap_or(Requester { login: String::new(), privileges: 0 })
}

/// Resolve tag `tag` (missing means the root).
fn resolve(c: &Ctx, who: &Requester, tag: u32) -> Result<Item> {
    Ok(c.server.vfs.resolve(who, c.field(tag).unwrap_or_default())?)
}

/// Drop box contents are off limits to users without privilege 0xd.
fn check_drop_box(who: &Requester, item: &Item) -> Result {
    if item.in_drop_box && !privs::has(who.privileges, privs::VIEW_DROP_BOXES) {
        return Err(Fail::Error(err::IN_DROP_BOX));
    }
    Ok(())
}

pub fn list(c: &Ctx) -> Result {
    let who = requester_of(&c.st(), c.uid);
    let folder = resolve(c, &who, 1)?;
    let listing = c.server.vfs.listing(&who, &folder)?;
    c.reply(&c.st(), cmd::LIST_FOLDER, vec![Field::new(2, listing)]);
    Ok(())
}

pub fn create_folder(c: &Ctx) -> Result {
    let who = requester_of(&c.st(), c.uid);
    c.require(&c.st(), privs::CREATE_FOLDERS)?;
    let parent = resolve(c, &who, 1).map_err(|_| Fail::Error(err::DESTINATION_NOT_FOUND))?;
    let name = c.required(3)?;
    let flags = if privs::has(who.privileges, privs::CHANGE_FOLDER_MODE) { c.u16(2).unwrap_or(0) } else { 0 };
    c.server.vfs.create_folder(&parent, &name[..name.len().min(MAX_NAME)], flags)?;
    let st = c.st();
    c.complete(&st);
    Ok(())
}

pub fn delete(c: &Ctx) -> Result {
    let who = requester_of(&c.st(), c.uid);
    let item = resolve(c, &who, 1)?;
    if !item.exists() {
        return Err(Fail::Error(err::NOT_FOUND));
    }
    c.require(&c.st(), if item.is_dir() { privs::DELETE_FOLDERS } else { privs::DELETE_FILES })?;
    check_drop_box(&who, &item)?;
    c.server.vfs.delete(&item)?;
    let mut st = c.st();
    let nick = st.users.get(&c.uid).map(|u| macroman::decode(&u.nick)).unwrap_or_default();
    st.log(format!("\"{nick}\" deleted {}", String::from_utf8_lossy(&item.wire).replace('\x01', "/")));
    c.complete(&st);
    Ok(())
}

pub fn info(c: &Ctx) -> Result {
    let who = requester_of(&c.st(), c.uid);
    let item = resolve(c, &who, 1)?;
    check_drop_box(&who, &item)?;
    let (info, comment) = c.server.vfs.info(&item)?;
    let fields = vec![
        Field::new(1, c.field(1).unwrap_or_default().to_vec()),
        Field::new(2, item.name.as_bytes().to_vec()),
        Field::new(3, info),
        Field::new(4, comment),
    ];
    c.reply(&c.st(), cmd::MOVE, fields);
    Ok(())
}

pub fn set_info(c: &Ctx) -> Result {
    let who = requester_of(&c.st(), c.uid);
    let item = resolve(c, &who, 1)?;
    let new_name = c.required(2)?;
    if !item.exists() {
        return Err(Fail::Error(err::NOT_FOUND));
    }
    check_drop_box(&who, &item)?;
    let is_dir = item.is_dir();
    let has = |bit| privs::has(who.privileges, bit);
    let vfs = &c.server.vfs;
    if let Some(comment) = c.field(4) {
        let comment = macroman::decode(&comment[..comment.len().min(MAX_COMMENT)]);
        if comment != vfs.meta(&item.path).comment {
            if is_dir && !has(privs::COMMENT_FOLDERS) {
                return Err(Fail::Error(err::NO_FOLDER_COMMENT_PRIVILEGE));
            }
            if !is_dir && !has(privs::COMMENT_FILES) {
                return Err(Fail::Error(err::NO_FILE_COMMENT_PRIVILEGE));
            }
            vfs.update_meta(&item.path, |m| m.comment = comment).map_err(|_| Fail::Error(err::NOT_FOUND))?;
        }
    }
    if let Some(flags) = c.u16(3) {
        // Without the privilege the change is silently ignored.
        if is_dir && has(privs::CHANGE_FOLDER_MODE) {
            vfs.set_folder_flags(&item.path, flags).map_err(|_| Fail::Error(err::NOT_FOUND))?;
        }
    }
    if new_name != item.name.as_bytes() {
        if !has(if is_dir { privs::RENAME_FOLDERS } else { privs::RENAME_FILES }) {
            return Err(Fail::Error(err::NO_PRIVILEGE));
        }
        vfs.rename(&item, &new_name[..new_name.len().min(MAX_NAME)])?;
    }
    let st = c.st();
    c.complete(&st);
    Ok(())
}

pub fn move_item(c: &Ctx) -> Result {
    let who = requester_of(&c.st(), c.uid);
    let item = resolve(c, &who, 1)?;
    if !item.exists() {
        return Err(Fail::Error(err::NOT_FOUND));
    }
    c.require(&c.st(), if item.is_dir() { privs::MOVE_FOLDERS } else { privs::MOVE_FILES })?;
    let dest = resolve(c, &who, 2).map_err(|_| Fail::Error(err::DESTINATION_NOT_FOUND))?;
    c.server.vfs.move_to(&item, &dest)?;
    let st = c.st();
    c.complete(&st);
    Ok(())
}

pub fn empty_trash(c: &Ctx) -> Result {
    let mut st = c.st();
    c.require(&st, privs::EMPTY_TRASH)?;
    if st.emptying_trash {
        return Err(Fail::Error(err::BUSY));
    }
    st.emptying_trash = true;
    c.complete(&st);
    drop(st);
    let server = c.server.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = server.vfs.empty_trash() {
            tracing::warn!("emptying trash: {e}");
        }
        server.lock().emptying_trash = false;
    });
    Ok(())
}
