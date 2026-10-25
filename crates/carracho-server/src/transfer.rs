//! The data connection (protocol.md, 4.16): one job per connection, on the
//! main port + 1.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use carracho_proto::crypto::FrameCipher;
use carracho_proto::packet::{Field, Packet};
use carracho_proto::{macroman, mactime, wire};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::codes::{cmd, err, privs};
use crate::files::{self, ItemMeta, Requester, Vfs};
use crate::handlers::news;
use crate::session::ipv4_of;
use crate::state::Server;
use crate::store::Article;

/// Data connection types.
mod kind {
    pub const DOWNLOAD: i16 = 1;
    pub const UPLOAD: i16 = 2;
    pub const POST_ARTICLE: i16 = 4;
    pub const ARTICLE_INDEX: i16 = 5;
    pub const LOG: i16 = 7;
    pub const BANNER_UPLOAD: i16 = 8;
    pub const SEARCH: i16 = 9;
    pub const DOWNLOAD_ENCRYPTED: i16 = 10;
    pub const UPLOAD_ENCRYPTED: i16 = 11;
    pub const BANNER_DOWNLOAD: i16 = 15;
}

/// Most data connections open at once from one address.
const MAX_DATA_CONNECTIONS_PER_IP: u32 = 6;
const IO_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CHUNK: usize = 32 * 1024;
const FOLDER_TYPE: &[u8; 4] = b"FLDR";
const FOLDER_CREATOR: &[u8; 4] = b"CarS";
const MAX_SEARCH_RESULTS: usize = 500;
const MAX_ARTICLE: usize = 1 << 20;
const MAX_BANNER: usize = 1 << 20;

/// A data connection's byte stream: BF blocks on the encrypted types, the raw
/// socket otherwise.
struct DataStream {
    stream: TcpStream,
    cipher: Option<FrameCipher>,
    pending: Vec<u8>,
}

impl DataStream {
    async fn fill(&mut self) -> anyhow::Result<()> {
        let Some(cipher) = &self.cipher else {
            let mut buf = vec![0u8; CHUNK];
            let n = tokio::time::timeout(IO_TIMEOUT, self.stream.read(&mut buf)).await??;
            ensure!(n > 0, "client closed the data connection");
            self.pending.extend_from_slice(&buf[..n]);
            return Ok(());
        };
        let mut head = [0u8; 9];
        tokio::time::timeout(IO_TIMEOUT, self.stream.read_exact(&mut head)).await??;
        let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
        let pad = head[8] as usize;
        ensure!(len % 8 == 0 && pad < 8 && pad <= len && len <= 1 << 24, "bad block header");
        let mut buf = vec![0u8; len];
        tokio::time::timeout(IO_TIMEOUT, self.stream.read_exact(&mut buf)).await??;
        cipher.decrypt_transfer(&mut buf);
        buf.truncate(len - pad);
        self.pending.extend_from_slice(&buf);
        Ok(())
    }

    async fn read(&mut self, n: usize) -> anyhow::Result<Vec<u8>> {
        while self.pending.len() < n {
            self.fill().await?;
        }
        Ok(self.pending.drain(..n).collect())
    }

    async fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.read(1).await?[0])
    }

    async fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.read(2).await?.try_into().unwrap()))
    }

    async fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.read(4).await?.try_into().unwrap()))
    }

    async fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_be_bytes(self.read(8).await?.try_into().unwrap()))
    }

    async fn string(&mut self) -> anyhow::Result<Vec<u8>> {
        let n = self.u16().await? as usize;
        self.read(n).await
    }

    /// A fork size or offset: 8 bytes on the encrypted types, 4 otherwise.
    async fn size(&mut self) -> anyhow::Result<u64> {
        if self.cipher.is_some() { self.u64().await } else { Ok(self.u32().await? as u64) }
    }

    fn size_bytes(&self, v: u64) -> Vec<u8> {
        if self.cipher.is_some() { v.to_be_bytes().to_vec() } else { (v.min(u32::MAX as u64) as u32).to_be_bytes().to_vec() }
    }

    /// Send one block (or the raw bytes on an unencrypted connection).
    async fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let out = match &self.cipher {
            None => data.to_vec(),
            Some(cipher) => {
                let pad = (8 - data.len() % 8) % 8;
                let mut buf = data.to_vec();
                buf.resize(data.len() + pad, 0);
                cipher.encrypt_transfer(&mut buf);
                let mut out = Vec::with_capacity(9 + buf.len());
                wire::put_u32(&mut out, buf.len() as u32);
                wire::put_u32(&mut out, 0);
                out.push(pad as u8);
                out.extend_from_slice(&buf);
                out
            }
        };
        tokio::time::timeout(IO_TIMEOUT, self.stream.write_all(&out)).await??;
        Ok(())
    }
}

/// Releases the per-IP data connection slot.
struct Slot {
    server: Arc<Server>,
    ip: Ipv4Addr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = self.server.lock();
        if let Some(n) = st.data_connections_per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Ends a transfer's entry in the transfer list.
struct TransferGuard {
    server: Arc<Server>,
    id: u64,
}

impl Drop for TransferGuard {
    fn drop(&mut self) {
        self.server.lock().end_transfer(self.id);
    }
}

/// The user a data connection belongs to.
struct Owner {
    id: u32,
    requester: Requester,
    secret: Vec<u8>,
}

impl Owner {
    fn has(&self, bit: u32) -> bool {
        privs::has(self.requester.privileges, bit)
    }
}

/// Report an error on the user's main connection.
fn main_error(server: &Server, user: u32, code: u16) {
    server.lock().send_to(user, Packet::new(cmd::ERROR, 0, vec![Field::u16(1, code)]));
}

pub async fn serve(server: Arc<Server>, mut stream: TcpStream, peer: SocketAddr) {
    let ip = ipv4_of(peer);
    let mut header = [0u8; 10];
    if tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut header)).await.map(|r| r.is_ok()) != Ok(true) {
        return;
    }
    let magic = i32::from_be_bytes(header[..4].try_into().unwrap());
    let kind = i16::from_be_bytes(header[4..6].try_into().unwrap());
    let user_id = u32::from_be_bytes(header[6..10].try_into().unwrap());
    if magic > 0x0100_0000 {
        return;
    }
    let owner = {
        let mut st = server.lock();
        let Some(u) = st.users.get(&user_id).filter(|u| u.ip == ip) else { return };
        let owner = Owner { id: u.id, requester: u.requester(), secret: u.secret.clone() };
        let n = st.data_connections_per_ip.entry(ip).or_default();
        if *n >= MAX_DATA_CONNECTIONS_PER_IP {
            return;
        }
        *n += 1;
        owner
    };
    let _slot = Slot { server: server.clone(), ip };
    let encrypted = matches!(kind, kind::DOWNLOAD_ENCRYPTED | kind::UPLOAD_ENCRYPTED);
    let cipher = encrypted.then(|| FrameCipher::new(&owner.secret));
    let mut s = DataStream { stream, cipher, pending: Vec::new() };
    let result = match kind {
        kind::DOWNLOAD | kind::DOWNLOAD_ENCRYPTED => download(&server, &owner, &mut s).await,
        kind::UPLOAD | kind::UPLOAD_ENCRYPTED => upload(&server, &owner, &mut s).await,
        kind::POST_ARTICLE => post_article(&server, &owner, &mut s).await,
        kind::ARTICLE_INDEX => article_index(&server, &owner, &mut s).await,
        kind::LOG => send_log(&server, &owner, &mut s).await,
        kind::BANNER_UPLOAD => banner_upload(&server, &owner, &mut s).await,
        kind::BANNER_DOWNLOAD => banner_download(&server, &mut s).await,
        kind::SEARCH => search(&server, &owner, &mut s).await,
        _ => Ok(()),
    };
    if let Err(e) = result {
        tracing::debug!(user = owner.id, kind, "data connection ended: {e:#}");
    }
    let _ = s.stream.shutdown().await;
}

/// Wait for a free transfer slot, telling the client its queue position.
async fn wait_for_slot(server: &Arc<Server>, s: &mut DataStream) -> anyhow::Result<()> {
    let busy = || {
        let st = server.lock();
        st.transfers.len() >= st.store.settings.max_transfers.max(1) as usize
    };
    if !busy() {
        s.send(&0u32.to_be_bytes()).await?;
        return Ok(());
    }
    s.send(&1u32.to_be_bytes()).await?;
    let mut waited = Duration::ZERO;
    while busy() {
        tokio::time::sleep(Duration::from_secs(1)).await;
        waited += Duration::from_secs(1);
        if waited >= Duration::from_secs(30) {
            s.send(&[0]).await?;
            waited = Duration::ZERO;
        }
    }
    s.send(&[1]).await
}

fn fork_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

async fn send_fork(s: &mut DataStream, path: &Path, offset: u64, len: u64, done: &AtomicU64) -> anyhow::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut left = len;
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let n = f.read(&mut buf[..CHUNK.min(left as usize)]).await?;
        ensure!(n > 0, "file shrank during download");
        s.send(&buf[..n]).await?;
        left -= n as u64;
        done.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(())
}

async fn download(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    let path = s.string().await?;
    if !owner.has(privs::DOWNLOAD) {
        main_error(server, owner.id, err::NO_DOWNLOAD_PRIVILEGE);
        return Ok(());
    }
    let vfs = &server.vfs;
    let item = match vfs.resolve(&owner.requester, &path) {
        Ok(item) if item.exists() && !item.is_root => item,
        _ => {
            main_error(server, owner.id, err::NOT_FOUND);
            return Ok(());
        }
    };
    if item.in_drop_box && !owner.has(privs::VIEW_DROP_BOXES) {
        main_error(server, owner.id, err::DOWNLOAD_FROM_DROP_BOX);
        return Ok(());
    }
    let (depth, per_user) = {
        let st = server.lock();
        (st.store.settings.folder_depth, st.store.settings.max_transfers_per_user.max(1) as usize)
    };
    if server.lock().transfers_of(owner.id) >= per_user {
        // The original drops the connection rather than queueing.
        return Ok(());
    }
    wait_for_slot(server, s).await?;

    let items = vfs.download_items(&item, depth);
    let total: u64 = items.iter().filter(|(_, p)| p.is_file()).map(|(_, p)| fork_len(p) + Vfs::rsrc_len(p)).sum();
    let (id, done) = server.lock().start_transfer(owner.id, false, item.name.as_bytes().to_vec(), total);
    let _guard = TransferGuard { server: server.clone(), id };
    server.lock().log(format!("Download of {} started", item.name));

    let mut summary = Vec::new();
    wire::put_u64(&mut summary, total);
    wire::put_u32(&mut summary, items.len() as u32);
    s.send(&summary).await?;
    for (rel, path) in &items {
        let meta = vfs.meta(path);
        let is_dir = path.is_dir();
        let mut header = Vec::new();
        wire::put_string(&mut header, rel);
        if is_dir {
            header.extend_from_slice(FOLDER_TYPE);
            header.extend_from_slice(FOLDER_CREATOR);
        } else {
            let (ty, creator) = vfs.type_creator(path);
            wire::put_u32(&mut header, ty);
            wire::put_u32(&mut header, creator);
        }
        wire::put_u16(&mut header, meta.finder_flags);
        let mut ext = meta.ext.clone();
        ext.resize(16, 0);
        header.extend_from_slice(&ext);
        wire::put_u32(&mut header, 0);
        s.send(&header).await?;
        if is_dir {
            continue;
        }
        let (data_offset, rsrc_offset) = (s.size().await?, s.size().await?);
        let rsrc_path = Vfs::rsrc_path(path);
        let data_len = fork_len(path).saturating_sub(data_offset);
        let rsrc_len = fork_len(&rsrc_path).saturating_sub(rsrc_offset);
        let mut sizes = s.size_bytes(data_len);
        sizes.extend(s.size_bytes(rsrc_len));
        s.send(&sizes).await?;
        send_fork(s, path, data_offset, data_len, &done).await?;
        send_fork(s, &rsrc_path, rsrc_offset, rsrc_len, &done).await?;
        let mut comment = Vec::new();
        wire::put_string(&mut comment, &macroman::encode(&meta.comment));
        s.send(&comment).await?;
    }
    Ok(())
}

/// Resolve an upload item's relative path under the destination folder.
fn item_path(dest: &Path, rel: &[u8]) -> anyhow::Result<std::path::PathBuf> {
    let mut path = dest.to_path_buf();
    for c in rel.split(|&b| b == files::SEPARATOR).filter(|c| !c.is_empty()) {
        let name = std::str::from_utf8(c).context("item name is not UTF-8")?;
        ensure!(!name.starts_with('.') && !name.contains(':') && !name.contains('/') && name.len() <= 255, "bad item name");
        path.push(name);
    }
    ensure!(path != dest, "empty item path");
    Ok(path)
}

async fn receive_fork(s: &mut DataStream, path: &Path, offset: u64, len: u64, done: &AtomicU64) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let mut f = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(path).await?;
    f.set_len(offset).await?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut left = len;
    while left > 0 {
        if s.pending.is_empty() {
            s.fill().await?;
        }
        let n = s.pending.len().min(left as usize);
        f.write_all(&s.pending[..n]).await?;
        s.pending.drain(..n);
        left -= n as u64;
        done.fetch_add(n as u64, Ordering::Relaxed);
    }
    f.flush().await?;
    Ok(())
}

async fn upload(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    if !owner.has(privs::UPLOAD) {
        main_error(server, owner.id, err::NO_UPLOAD_PRIVILEGE);
        return Ok(());
    }
    let folder = s.string().await?;
    let vfs = &server.vfs;
    let dest = match vfs.resolve(&owner.requester, &folder) {
        Ok(item) if item.is_dir() => item,
        _ => {
            main_error(server, owner.id, err::DESTINATION_NOT_FOUND);
            return Ok(());
        }
    };
    let upload_folder = !dest.is_root && vfs.folder_flags_of(&dest.path) & files::folder_flags::UPLOAD != 0;
    if !upload_folder && !owner.has(privs::UPLOAD_ANYWHERE) {
        main_error(server, owner.id, err::NOT_UPLOAD_FOLDER);
        return Ok(());
    }
    let name = s.string().await?;
    if name.is_empty() {
        return Ok(());
    }
    let target = item_path(&dest.path, &name)?;
    let state: u8 = if !target.exists() {
        0
    } else if vfs.is_partial(&target) {
        2
    } else {
        1
    };
    s.send(&[state]).await?;
    if s.u8().await? == 1 && target.exists() {
        if !owner.has(privs::DELETE_FILES) {
            main_error(server, owner.id, err::NO_REPLACE_PRIVILEGE);
            return Ok(());
        }
        let item = vfs.resolve(&owner.requester, &[&dest.wire[..], &[files::SEPARATOR], &name[..]].concat());
        if let Ok(item) = item {
            vfs.delete(&item).ok();
        }
    }
    let total = s.u64().await?;
    let count = s.u32().await?;
    let label = String::from_utf8_lossy(&name).into_owned();
    let (id, done) = server.lock().start_transfer(owner.id, true, name.clone(), total);
    let _guard = TransferGuard { server: server.clone(), id };
    server.lock().log(format!("Upload of {label} started"));

    for _ in 0..count {
        let rel = s.string().await?;
        let ty = s.read(4).await?;
        let creator = s.read(4).await?;
        let finder_flags = s.u16().await?;
        let ext = s.read(16).await?;
        let extra = s.u32().await? as usize;
        ensure!(extra <= 1 << 16, "item header extra bytes too long");
        s.read(extra).await?;
        let path = item_path(&dest.path, &rel)?;
        if ty == FOLDER_TYPE && creator == FOLDER_CREATOR {
            tokio::fs::create_dir_all(&path).await?;
            continue;
        }
        let final_meta = |m: &mut ItemMeta| {
            m.file_type = Some(u32::from_be_bytes(ty[..].try_into().unwrap()));
            m.creator = Some(u32::from_be_bytes(creator[..].try_into().unwrap()));
            m.finder_flags = finder_flags;
            m.ext = if ext.iter().all(|&b| b == 0) { Vec::new() } else { ext.clone() };
        };
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        if !path.exists() {
            tokio::fs::write(&path, b"").await?;
        }
        vfs.update_meta(&path, |m| {
            m.file_type = Some(files::PARTIAL_TYPE);
            m.creator = Some(files::PARTIAL_CREATOR);
        })?;
        let rsrc_path = Vfs::rsrc_path(&path);
        let (data_have, rsrc_have) = (fork_len(&path), fork_len(&rsrc_path));
        let mut offsets = s.size_bytes(data_have);
        offsets.extend(s.size_bytes(rsrc_have));
        s.send(&offsets).await?;
        let (data_len, rsrc_len) = (s.size().await?, s.size().await?);
        receive_fork(s, &path, data_have, data_len, &done).await?;
        if rsrc_len > 0 || rsrc_have > 0 {
            receive_fork(s, &rsrc_path, rsrc_have, rsrc_len, &done).await?;
        }
        let comment = macroman::decode(&s.string().await?);
        vfs.update_meta(&path, |m| {
            final_meta(m);
            m.comment = comment;
        })?;
    }
    server.lock().log(format!("Upload of {label} finished"));
    Ok(())
}

/// Read a `u32`-length-prefixed blob from a raw data connection.
async fn read_blob(s: &mut DataStream, max: usize) -> anyhow::Result<Vec<u8>> {
    let n = s.u32().await? as usize;
    ensure!(n <= max, "blob of {n} bytes is too long");
    s.read(n).await
}

async fn post_article(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    let blob = read_blob(s, MAX_ARTICLE).await?;
    let mut r = carracho_proto::wire::Reader::new(&blob);
    let group = macroman::decode(r.string()?);
    let subject = macroman::decode(r.string()?);
    r.u32()?;
    let parent = r.u32()?;
    let text_len = r.u32()? as usize;
    let style_len = r.u32()? as usize;
    let text = macroman::decode(r.bytes(text_len)?);
    let styles = r.bytes(style_len)?.to_vec();

    let mut st = server.lock();
    let author = st.users.get(&owner.id).map(|u| macroman::decode(&u.nick)).unwrap_or_default();
    let mask = owner.requester.privileges;
    let Some(g) = st.store.newsgroup_mut(&group) else {
        drop(st);
        main_error(server, owner.id, err::NOT_FOUND);
        return Ok(());
    };
    if !news::can_post(g, mask) {
        drop(st);
        main_error(server, owner.id, err::NO_PRIVILEGE);
        return Ok(());
    }
    let id = g.next_id.max(1);
    g.next_id = id + 1;
    g.articles.push(Article { id, parent, subject, author, date: mactime::now(), text, styles });
    if let Err(e) = st.store.save_newsgroups() {
        tracing::warn!("saving newsgroups: {e:#}");
    }
    Ok(())
}

async fn article_index(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    let group = macroman::decode(&s.string().await?);
    let index = {
        let st = server.lock();
        match st.store.newsgroup(&group) {
            Some(g) if news::can_read(g, owner.requester.privileges) => Some(news::article_index(g)),
            _ => None,
        }
    };
    let Some(index) = index else {
        main_error(server, owner.id, err::NO_PRIVILEGE);
        return Ok(());
    };
    let mut out = Vec::new();
    wire::put_u32(&mut out, index.len() as u32);
    out.extend_from_slice(&index);
    s.send(&out).await?;
    // The original waits for the client to close.
    let mut sink = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(30), s.stream.read(&mut sink)).await;
    Ok(())
}

async fn send_log(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    if !owner.has(privs::VIEW_LOG) {
        main_error(server, owner.id, err::NO_PRIVILEGE);
        return Ok(());
    }
    let text: Vec<u8> = {
        let st = server.lock();
        let lines: Vec<&str> = st.log.iter().map(String::as_str).collect();
        macroman::encode(&lines.join("\r"))
    };
    let mut out = Vec::new();
    wire::put_u32(&mut out, text.len() as u32);
    out.extend_from_slice(&text);
    s.send(&out).await
}

async fn banner_upload(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    if !owner.has(privs::SERVER_INFO) {
        main_error(server, owner.id, err::NO_PRIVILEGE);
        return Ok(());
    }
    let png = read_blob(s, MAX_BANNER).await?;
    let url_len = s.u8().await? as usize;
    let url = macroman::decode(&s.read(url_len).await?);
    let mut st = server.lock();
    st.store.set_banner(&png)?;
    st.store.settings.banner_url = url;
    st.store.save_settings()?;
    Ok(())
}

async fn banner_download(server: &Arc<Server>, s: &mut DataStream) -> anyhow::Result<()> {
    let (png, url) = {
        let st = server.lock();
        (st.store.banner().unwrap_or_default(), macroman::encode(&st.store.settings.banner_url))
    };
    let mut out = Vec::new();
    wire::put_u32(&mut out, png.len() as u32);
    out.extend_from_slice(&png);
    out.push(url.len().min(255) as u8);
    out.extend_from_slice(&url[..url.len().min(255)]);
    s.send(&out).await
}

async fn search(server: &Arc<Server>, owner: &Owner, s: &mut DataStream) -> anyhow::Result<()> {
    if !owner.has(privs::SEARCH) || owner.has(privs::HOME_IS_ROOT) {
        main_error(server, owner.id, err::NO_PRIVILEGE);
        return Ok(());
    }
    s.u16().await?;
    // Criteria records until "name contains", the only kind supported.
    let mut needle = None;
    for _ in 0..16 {
        let kind = s.u8().await?;
        let op = s.u8().await?;
        s.u8().await?;
        let n = s.u32().await? as usize;
        ensure!(n <= 255, "search text too long");
        let value = s.read(n).await?;
        if kind == 1 && op == 1 {
            needle = Some(macroman::decode(&value));
            break;
        }
    }
    let Some(needle) = needle else { bail!("no name criterion in search") };
    s.send(&0u32.to_be_bytes()).await?;
    let vfs = &server.vfs;
    let requester = owner.requester.clone();
    let needle2 = needle.clone();
    let server2 = server.clone();
    let hits = tokio::task::spawn_blocking(move || server2.vfs.search(&requester, &needle2, MAX_SEARCH_RESULTS)).await?;
    for (wire_path, path) in hits {
        let meta = std::fs::metadata(&path).ok();
        let is_dir = path.is_dir();
        let (ty, creator) = if is_dir { (0, 0) } else { vfs.type_creator(&path) };
        let size = if is_dir { Vfs::item_count(&path) as u64 } else { fork_len(&path) + Vfs::rsrc_len(&path) };
        let modified = meta.and_then(|m| m.modified().ok()).map(mactime::from_system).unwrap_or(0);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").as_bytes().to_vec();
        let parent = &wire_path[..wire_path.len() - name.len()].strip_suffix(&[files::SEPARATOR]).unwrap_or(&[]);
        let mut rec = vec![0u8];
        wire::put_u32(&mut rec, 0);
        wire::put_u32(&mut rec, 0);
        rec.push(is_dir as u8);
        wire::put_string(&mut rec, parent);
        wire::put_u32(&mut rec, size.min(u32::MAX as u64) as u32);
        wire::put_u32(&mut rec, modified);
        wire::put_u32(&mut rec, ty);
        wire::put_u32(&mut rec, creator);
        wire::put_string(&mut rec, &name);
        s.send(&rec).await?;
    }
    let mut end = vec![1u8];
    wire::put_u32(&mut end, 0);
    s.send(&end).await
}
