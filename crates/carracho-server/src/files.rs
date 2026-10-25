//! The shared folder tree (protocol.md, 4.15).
//!
//! Files live in an ordinary directory tree. Mac metadata that has no place in
//! a modern file system (type, creator, Finder flags and extended info,
//! comments, folder modes) is kept per folder in a hidden `.carracho-info`
//! JSON file, keyed by item name. Resource forks are kept in a hidden
//! `.carracho-rsrc` folder next to the item. Names starting with `.` are never
//! listed or reachable, as on the original server.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use carracho_proto::{mactime, macroman, wire};
use serde::{Deserialize, Serialize};

use crate::codes::{err, privs};

const INFO_FILE: &str = ".carracho-info";
const RSRC_DIR: &str = ".carracho-rsrc";

/// Path separator on the wire.
pub const SEPARATOR: u8 = 0x01;
const MAX_COMPONENT: usize = 255;
const MAX_PATH: usize = 4096;

/// Folder flags.
pub mod folder_flags {
    /// An ordinary folder: what a folder without stored flags reports.
    pub const ORDINARY: u16 = 0x8000;
    pub const UPLOAD: u16 = 0x4000;
    pub const DROP_BOX: u16 = 0x2000;
    /// Flags of the `~login` entry for a nested personal folder.
    pub const PERSONAL: u16 = 0xC000;
}

/// Type and creator of a file while it is being uploaded.
pub const PARTIAL_TYPE: u32 = u32::from_be_bytes(*b"PART");
pub const PARTIAL_CREATOR: u32 = u32::from_be_bytes(*b"CarC");
const UNKNOWN: u32 = u32::from_be_bytes(*b"????");

/// Per-item metadata stored in the parent folder's info file.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ItemMeta {
    pub file_type: Option<u32>,
    pub creator: Option<u32>,
    pub finder_flags: u16,
    /// Extended Finder info, 16 bytes when present.
    pub ext: Vec<u8>,
    pub comment: String,
    /// Stored folder flags; `None` reports [`folder_flags::ORDINARY`].
    pub folder_flags: Option<u16>,
}

/// Who is asking: decides the root, the personal folder and drop box access.
#[derive(Clone, Debug)]
pub struct Requester {
    pub login: String,
    pub privileges: u64,
}

impl Requester {
    fn has(&self, bit: u32) -> bool {
        privs::has(self.privileges, bit)
    }
}

/// A resolved protocol path.
#[derive(Clone, Debug)]
pub struct Item {
    /// Real location on disk.
    pub path: PathBuf,
    /// The path as the client sent it, normalized (no empty components).
    pub wire: Vec<u8>,
    /// Final component, empty for the root.
    pub name: String,
    /// Some folder above the item is a drop box.
    pub in_drop_box: bool,
    /// The item is the requester's root (the shared root or their personal
    /// folder when it is their root).
    pub is_root: bool,
}

impl Item {
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    pub fn exists(&self) -> bool {
        self.path.symlink_metadata().is_ok()
    }
}

pub struct Vfs {
    root: PathBuf,
    homes: PathBuf,
    trash: PathBuf,
    /// Serializes read-modify-write of info files.
    meta_lock: Mutex<()>,
}

/// Mac type and creator for files that have none stored, from the extension.
fn guess_type(name: &str) -> (u32, u32) {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    let code = |s: &[u8; 4]| u32::from_be_bytes(*s);
    match ext.as_str() {
        "txt" | "text" | "md" => (code(b"TEXT"), code(b"ttxt")),
        "html" | "htm" => (code(b"TEXT"), code(b"MOSS")),
        "jpg" | "jpeg" => (code(b"JPEG"), code(b"ogle")),
        "gif" => (code(b"GIFf"), code(b"ogle")),
        "png" => (code(b"PNGf"), code(b"ogle")),
        "pdf" => (code(b"PDF "), code(b"CARO")),
        "sit" => (code(b"SIT!"), code(b"SIT!")),
        "sitx" => (code(b"SITX"), code(b"SITx")),
        "hqx" => (code(b"TEXT"), code(b"SITx")),
        "bin" => (code(b"BINA"), code(b"SITx")),
        "zip" => (code(b"ZIP "), code(b"SITx")),
        "mp3" => (code(b"MPG3"), code(b"TVOD")),
        "mov" => (code(b"MooV"), code(b"TVOD")),
        _ => (UNKNOWN, UNKNOWN),
    }
}

fn mac_date(t: io::Result<SystemTime>) -> u32 {
    t.map(mactime::from_system).unwrap_or(0)
}

fn valid_component(c: &[u8]) -> bool {
    !c.is_empty() && c.len() <= MAX_COMPONENT && c[0] != b'.' && !c.contains(&b':') && !c.contains(&b'/')
}

impl Vfs {
    pub fn new(root: PathBuf, homes: PathBuf, trash: PathBuf) -> io::Result<Self> {
        for dir in [&root, &homes, &trash] {
            fs::create_dir_all(dir)?;
        }
        Ok(Self { root, homes, trash, meta_lock: Mutex::new(()) })
    }

    pub fn home(&self, login: &str) -> PathBuf {
        self.homes.join(login.to_lowercase())
    }

    /// Create a user's personal folder if their privileges call for one.
    pub fn ensure_home(&self, who: &Requester) -> io::Result<()> {
        if who.has(privs::NESTED_HOME) || who.has(privs::HOME_IS_ROOT) {
            fs::create_dir_all(self.home(&who.login))?;
        }
        Ok(())
    }

    pub fn remove_home(&self, login: &str) -> io::Result<()> {
        let home = self.home(login);
        if home.exists() { self.trash_path(&home) } else { Ok(()) }
    }

    /// Resolve a wire path for `who`. Errors are protocol error codes.
    pub fn resolve(&self, who: &Requester, wire_path: &[u8]) -> Result<Item, u16> {
        if wire_path.len() > MAX_PATH {
            return Err(err::NOT_FOUND);
        }
        let components: Vec<&[u8]> = wire_path.split(|&b| b == SEPARATOR).filter(|c| !c.is_empty()).collect();
        let mut path = if who.has(privs::HOME_IS_ROOT) { self.home(&who.login) } else { self.root.clone() };
        let mut rest = &components[..];
        if let Some(first) = components.first() {
            let personal = format!("~{}", who.login);
            if who.has(privs::NESTED_HOME) && !who.has(privs::HOME_IS_ROOT) && first.eq_ignore_ascii_case(personal.as_bytes()) {
                path = self.home(&who.login);
                rest = &components[1..];
            }
        }
        let mut in_drop_box = false;
        let mut name = String::new();
        for c in rest {
            if !valid_component(c) {
                return Err(err::NOT_FOUND);
            }
            let Ok(s) = std::str::from_utf8(c) else { return Err(err::NOT_FOUND) };
            // Every folder we descend through contains the target.
            if self.folder_flags_of(&path) & folder_flags::DROP_BOX != 0 {
                in_drop_box = true;
            }
            path.push(s);
            name = s.to_owned();
        }
        let is_root = rest.is_empty();
        let wire = components.join(&[SEPARATOR][..]);
        Ok(Item { path, wire, name, in_drop_box, is_root })
    }

    fn info_path(dir: &Path) -> PathBuf {
        dir.join(INFO_FILE)
    }

    fn read_info(dir: &Path) -> BTreeMap<String, ItemMeta> {
        fs::read(Self::info_path(dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn write_info(dir: &Path, info: &BTreeMap<String, ItemMeta>) -> io::Result<()> {
        let path = Self::info_path(dir);
        if info.is_empty() {
            return match fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        let tmp = dir.join(".carracho-info.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(info)?)?;
        fs::rename(tmp, path)
    }

    /// Metadata stored for the item at `path`.
    pub fn meta(&self, path: &Path) -> ItemMeta {
        match (path.parent(), path.file_name().and_then(|n| n.to_str())) {
            (Some(dir), Some(name)) => Self::read_info(dir).remove(name).unwrap_or_default(),
            _ => ItemMeta::default(),
        }
    }

    /// Change the metadata stored for the item at `path`.
    pub fn update_meta(&self, path: &Path, f: impl FnOnce(&mut ItemMeta)) -> io::Result<()> {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
            return Ok(());
        };
        let _guard = self.meta_lock.lock().unwrap();
        let mut info = Self::read_info(dir);
        let mut meta = info.remove(name).unwrap_or_default();
        f(&mut meta);
        if meta != ItemMeta::default() {
            info.insert(name.to_owned(), meta);
        }
        Self::write_info(dir, &info)
    }

    /// Move an item's metadata and resource fork along with a rename or move.
    fn carry_meta(&self, from: &Path, to: &Path) -> io::Result<()> {
        let meta = self.meta(from);
        let rsrc = Self::rsrc_path(from);
        self.update_meta(from, |m| *m = ItemMeta::default())?;
        if meta != ItemMeta::default() {
            self.update_meta(to, |m| *m = meta)?;
        }
        if rsrc.exists() {
            let dest = Self::rsrc_path(to);
            if let Some(dir) = dest.parent() {
                fs::create_dir_all(dir)?;
            }
            fs::rename(rsrc, dest)?;
        }
        Ok(())
    }

    pub fn rsrc_path(path: &Path) -> PathBuf {
        let name = path.file_name().unwrap_or_default();
        path.parent().unwrap_or(Path::new("")).join(RSRC_DIR).join(name)
    }

    pub fn rsrc_len(path: &Path) -> u64 {
        fs::metadata(Self::rsrc_path(path)).map(|m| m.len()).unwrap_or(0)
    }

    /// Folder flags as the protocol reports them.
    pub fn folder_flags_of(&self, dir: &Path) -> u16 {
        if dir == self.root || dir.parent() == Some(&self.homes) {
            return folder_flags::ORDINARY;
        }
        self.meta(dir).folder_flags.unwrap_or(folder_flags::ORDINARY)
    }

    /// Store folder flags the way the original's `SetFolderFlags` does:
    /// the "ordinary" bit is cleared, and nothing is stored if that leaves 0.
    pub fn set_folder_flags(&self, dir: &Path, flags: u16) -> io::Result<()> {
        let flags = flags & !folder_flags::ORDINARY;
        self.update_meta(dir, |m| m.folder_flags = (flags != 0).then_some(flags))
    }

    /// Type and creator of a file.
    pub fn type_creator(&self, path: &Path) -> (u32, u32) {
        let meta = self.meta(path);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let (t, c) = guess_type(name);
        (meta.file_type.unwrap_or(t), meta.creator.unwrap_or(c))
    }

    pub fn is_partial(&self, path: &Path) -> bool {
        self.type_creator(path) == (PARTIAL_TYPE, PARTIAL_CREATOR)
    }

    fn visible_entries(dir: &Path) -> Vec<(String, fs::Metadata)> {
        let mut out: Vec<(String, fs::Metadata)> = fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                if name.starts_with('.') {
                    return None;
                }
                let meta = e.metadata().ok()?;
                (meta.is_dir() || meta.is_file()).then_some((name, meta))
            })
            .collect();
        out.sort_by_key(|(n, _)| n.to_lowercase());
        out
    }

    /// Number of listed items in a folder.
    pub fn item_count(dir: &Path) -> u32 {
        Self::visible_entries(dir).len() as u32
    }

    /// The listing structure for command 0x09 (tag 2).
    pub fn listing(&self, who: &Requester, folder: &Item) -> Result<Vec<u8>, u16> {
        if !folder.path.is_dir() {
            return Err(err::NOT_FOUND);
        }
        let in_box = folder.in_drop_box || (!folder.is_root && self.folder_flags_of(&folder.path) & folder_flags::DROP_BOX != 0);
        let hide = in_box && !who.has(privs::VIEW_DROP_BOXES);
        let mut entries = Vec::new();
        let mut count = 0u16;
        let mut entry = |name: &[u8], size: u32, date: u32, creator: u32, ty: u32, flags: u16| {
            wire::put_u16(&mut entries, (name.len() + 20) as u16);
            wire::put_string(&mut entries, name);
            wire::put_u32(&mut entries, size);
            wire::put_u32(&mut entries, date);
            wire::put_u32(&mut entries, creator);
            wire::put_u32(&mut entries, ty);
            wire::put_u16(&mut entries, flags);
            count += 1;
        };
        if folder.is_root && who.has(privs::NESTED_HOME) && !who.has(privs::HOME_IS_ROOT) {
            let home = self.home(&who.login);
            let date = mac_date(fs::metadata(&home).and_then(|m| m.modified()));
            let name = format!("~{}", who.login);
            entry(name.as_bytes(), Self::item_count(&home), date, UNKNOWN, UNKNOWN, folder_flags::PERSONAL);
        }
        for (name, meta) in Self::visible_entries(&folder.path) {
            let path = folder.path.join(&name);
            let date = mac_date(meta.modified());
            if meta.is_dir() {
                if hide {
                    continue;
                }
                entry(name.as_bytes(), Self::item_count(&path), date, UNKNOWN, UNKNOWN, self.folder_flags_of(&path));
            } else {
                let (ty, creator) = self.type_creator(&path);
                if hide && (ty, creator) != (PARTIAL_TYPE, PARTIAL_CREATOR) {
                    continue;
                }
                let size = meta.len() + Self::rsrc_len(&path);
                entry(name.as_bytes(), size.min(u32::MAX as u64) as u32, date, creator, ty, 0);
            }
        }
        let mut out = Vec::with_capacity(4 + entries.len());
        wire::put_string(&mut out, &folder.wire);
        wire::put_u16(&mut out, count);
        out.extend_from_slice(&entries);
        Ok(out)
    }

    /// The 30-byte info structure for the file info reply (tag 3), and the
    /// item's comment.
    pub fn info(&self, item: &Item) -> Result<(Vec<u8>, Vec<u8>), u16> {
        let meta = fs::metadata(&item.path).map_err(|_| err::NOT_FOUND)?;
        let stored = self.meta(&item.path);
        let mut out = Vec::with_capacity(30);
        let (flags, size, ty, creator) = if meta.is_dir() {
            (self.folder_flags_of(&item.path), 0, 0, 0)
        } else {
            let (ty, creator) = self.type_creator(&item.path);
            (0, meta.len() + Self::rsrc_len(&item.path), ty, creator)
        };
        wire::put_u16(&mut out, flags);
        wire::put_u32(&mut out, size.min(u32::MAX as u64) as u32);
        wire::put_u32(&mut out, mac_date(meta.created().or_else(|_| meta.modified())));
        wire::put_u32(&mut out, mac_date(meta.modified()));
        wire::put_u32(&mut out, ty);
        wire::put_u32(&mut out, creator);
        wire::put_u16(&mut out, stored.finder_flags);
        wire::put_u32(&mut out, 0);
        wire::put_u16(&mut out, 0);
        Ok((out, macroman::encode(&stored.comment)))
    }

    pub fn create_folder(&self, parent: &Item, name: &[u8], flags: u16) -> Result<(), u16> {
        if !parent.path.is_dir() {
            return Err(err::DESTINATION_NOT_FOUND);
        }
        let name = std::str::from_utf8(name).ok().filter(|n| valid_component(n.as_bytes())).ok_or(err::NOT_FOUND)?;
        let path = parent.path.join(name);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(err::NOT_FOUND),
        }
        self.set_folder_flags(&path, flags).map_err(|_| err::NOT_FOUND)
    }

    fn trash_path(&self, path: &Path) -> io::Result<()> {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("item");
        let mut dest = self.trash.join(name);
        let mut n = 1;
        while dest.symlink_metadata().is_ok() {
            n += 1;
            dest = self.trash.join(format!("{name} {n}"));
        }
        let meta = self.meta(path);
        let rsrc = Self::rsrc_path(path);
        fs::rename(path, &dest)?;
        self.update_meta(path, |m| *m = ItemMeta::default())?;
        if rsrc.exists() {
            fs::remove_file(rsrc)?;
        }
        if meta != ItemMeta::default() {
            self.update_meta(&dest, |m| *m = meta)?;
        }
        Ok(())
    }

    /// Delete an item by moving it to the server's trash.
    pub fn delete(&self, item: &Item) -> Result<(), u16> {
        if item.is_root || !item.exists() {
            return Err(err::NOT_FOUND);
        }
        self.trash_path(&item.path).map_err(|_| err::NOT_FOUND)
    }

    /// Permanently delete everything in the trash.
    pub fn empty_trash(&self) -> io::Result<()> {
        for entry in fs::read_dir(&self.trash)? {
            let path = entry?.path();
            if path.is_dir() { fs::remove_dir_all(&path)? } else { fs::remove_file(&path)? }
        }
        Ok(())
    }

    pub fn rename(&self, item: &Item, new_name: &[u8]) -> Result<PathBuf, u16> {
        if item.is_root {
            return Err(err::NOT_FOUND);
        }
        let name = std::str::from_utf8(new_name).ok().filter(|n| valid_component(n.as_bytes())).ok_or(err::NOT_FOUND)?;
        let dest = item.path.with_file_name(name);
        if dest == item.path {
            return Ok(dest);
        }
        if dest.symlink_metadata().is_ok() && !dest.as_os_str().eq_ignore_ascii_case(item.path.as_os_str()) {
            return Err(err::NOT_FOUND);
        }
        fs::rename(&item.path, &dest).map_err(|_| err::NOT_FOUND)?;
        self.carry_meta(&item.path, &dest).map_err(|_| err::NOT_FOUND)?;
        Ok(dest)
    }

    pub fn move_to(&self, item: &Item, dest_folder: &Item) -> Result<(), u16> {
        if item.is_root || !item.exists() {
            return Err(err::NOT_FOUND);
        }
        if !dest_folder.path.is_dir() || dest_folder.path.starts_with(&item.path) {
            return Err(err::DESTINATION_NOT_FOUND);
        }
        let dest = dest_folder.path.join(item.path.file_name().unwrap());
        if dest.symlink_metadata().is_ok() {
            return Err(err::DESTINATION_NOT_FOUND);
        }
        fs::rename(&item.path, &dest).map_err(|_| err::NOT_FOUND)?;
        self.carry_meta(&item.path, &dest).map_err(|_| err::NOT_FOUND)
    }

    /// Search the requester's tree for names containing `needle`
    /// (case-insensitive). Returns wire paths of matches.
    pub fn search(&self, who: &Requester, needle: &str, limit: usize) -> Vec<(Vec<u8>, PathBuf)> {
        let needle = needle.to_lowercase();
        let base = match self.resolve(who, b"") {
            Ok(item) => item,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        let mut stack = vec![(base.path.clone(), Vec::<u8>::new())];
        while let Some((dir, wire_dir)) = stack.pop() {
            if dir != base.path && self.folder_flags_of(&dir) & folder_flags::DROP_BOX != 0 && !who.has(privs::VIEW_DROP_BOXES) {
                continue;
            }
            for (name, meta) in Self::visible_entries(&dir) {
                let mut wire_path = wire_dir.clone();
                if !wire_path.is_empty() {
                    wire_path.push(SEPARATOR);
                }
                wire_path.extend_from_slice(name.as_bytes());
                let path = dir.join(&name);
                if name.to_lowercase().contains(&needle) {
                    out.push((wire_path.clone(), path.clone()));
                    if out.len() >= limit {
                        return out;
                    }
                }
                if meta.is_dir() {
                    stack.push((path, wire_path));
                }
            }
        }
        out
    }

    /// Items to send for a download of `item`: the item itself and, for a
    /// folder, everything inside down to `depth` levels. Paths are relative to
    /// the download, starting with the item's own name.
    pub fn download_items(&self, item: &Item, depth: i16) -> Vec<(Vec<u8>, PathBuf)> {
        let mut out = vec![(item.name.as_bytes().to_vec(), item.path.clone())];
        if item.path.is_dir() {
            self.collect(&item.path, item.name.as_bytes(), 1, depth.max(0) as u32, &mut out);
        }
        out
    }

    fn collect(&self, dir: &Path, rel: &[u8], level: u32, depth: u32, out: &mut Vec<(Vec<u8>, PathBuf)>) {
        for (name, meta) in Self::visible_entries(dir) {
            let mut wire_path = rel.to_vec();
            wire_path.push(SEPARATOR);
            wire_path.extend_from_slice(name.as_bytes());
            let path = dir.join(&name);
            out.push((wire_path.clone(), path.clone()));
            if meta.is_dir() && level < depth {
                self.collect(&path, &wire_path, level + 1, depth, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Vfs, Requester) {
        let tmp = tempfile::tempdir().unwrap();
        let vfs = Vfs::new(tmp.path().join("files"), tmp.path().join("homes"), tmp.path().join("trash")).unwrap();
        let admin = Requester { login: "admin".into(), privileges: 0x803f_ffc8_7daf_8000 };
        (tmp, vfs, admin)
    }

    #[test]
    fn folder_flags_behave_like_the_original() {
        let (_tmp, vfs, admin) = setup();
        let root = vfs.resolve(&admin, b"").unwrap();
        vfs.create_folder(&root, b"Plain", 0).unwrap();
        vfs.create_folder(&root, b"Uploads", folder_flags::UPLOAD).unwrap();
        let plain = vfs.resolve(&admin, b"Plain").unwrap();
        assert_eq!(vfs.folder_flags_of(&plain.path), folder_flags::ORDINARY);
        let up = vfs.resolve(&admin, b"Uploads").unwrap();
        assert_eq!(vfs.folder_flags_of(&up.path), folder_flags::UPLOAD);
        vfs.set_folder_flags(&up.path, 0).unwrap();
        assert_eq!(vfs.folder_flags_of(&up.path), folder_flags::ORDINARY);
    }

    #[test]
    fn listing_matches_the_original_layout() {
        let (_tmp, vfs, admin) = setup();
        let root = vfs.resolve(&admin, b"").unwrap();
        assert_eq!(vfs.listing(&admin, &root).unwrap(), vec![0, 0, 0, 0], "empty root: no path, no entries");
        vfs.create_folder(&root, b"Sub", 0).unwrap();
        fs::write(root.path.join("a.txt"), b"hello").unwrap();
        fs::write(root.path.join(".hidden"), b"x").unwrap();
        let l = vfs.listing(&admin, &root).unwrap();
        assert_eq!(&l[..4], &[0, 0, 0, 2]);
        // First entry "a.txt": length 25, name, size 5, date, creator ttxt, type TEXT, flags 0.
        assert_eq!(&l[4..13], b"\x00\x19\x00\x05a.txt");
        assert_eq!(&l[13..17], &5u32.to_be_bytes());
        assert_eq!(&l[21..29], b"ttxtTEXT");
        assert_eq!(&l[29..31], &[0, 0]);
    }

    #[test]
    fn paths_cannot_escape_the_root() {
        let (_tmp, vfs, admin) = setup();
        for bad in [&b".."[..], b"a\x01..", b".carracho-info", b"x:y", b"a/b"] {
            assert!(vfs.resolve(&admin, bad).is_err(), "{bad:?}");
        }
        assert!(vfs.resolve(&admin, b"\x01\x01ok\x01").unwrap().wire == b"ok");
    }

    #[test]
    fn rename_and_move_carry_metadata() {
        let (_tmp, vfs, admin) = setup();
        let root = vfs.resolve(&admin, b"").unwrap();
        vfs.create_folder(&root, b"Dest", 0).unwrap();
        fs::write(root.path.join("f"), b"data").unwrap();
        let f = vfs.resolve(&admin, b"f").unwrap();
        vfs.update_meta(&f.path, |m| m.comment = "note".into()).unwrap();
        vfs.rename(&f, b"g").unwrap();
        let g = vfs.resolve(&admin, b"g").unwrap();
        assert_eq!(vfs.meta(&g.path).comment, "note");
        vfs.move_to(&g, &vfs.resolve(&admin, b"Dest").unwrap()).unwrap();
        let moved = vfs.resolve(&admin, b"Dest\x01g").unwrap();
        assert_eq!(vfs.meta(&moved.path).comment, "note");
        vfs.delete(&moved).unwrap();
        assert!(!moved.exists());
    }
}
