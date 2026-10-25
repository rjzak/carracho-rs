//! The data connection (protocol.md, 4.16): encrypted uploads and downloads.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, ensure};
use carracho_proto::crypto::FrameCipher;

/// Data connection types.
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

/// Byte stream over BF blocks: `u32 L, u32 0, u8 pad, L encrypted bytes`.
/// On the unencrypted types (1, 2) the same bytes go over the socket as they
/// are, and sizes are 4 bytes instead of 8.
pub struct BlockStream {
    pub stream: TcpStream,
    cipher: Option<FrameCipher>,
    pending: Vec<u8>,
}

impl BlockStream {
    pub fn open(addr: SocketAddr, kind: i16, user_id: u32, secret: Option<&[u8]>) -> anyhow::Result<Self> {
        let mut stream = TcpStream::connect(addr).with_context(|| format!("data connection to {addr}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut header = Vec::with_capacity(10);
        header.extend_from_slice(&0x0100_0000u32.to_be_bytes());
        header.extend_from_slice(&kind.to_be_bytes());
        header.extend_from_slice(&user_id.to_be_bytes());
        stream.write_all(&header)?;
        Ok(Self { stream, cipher: secret.map(FrameCipher::new), pending: Vec::new() })
    }

    /// Send `data` as one block, zero-padded only if it isn't block-aligned.
    pub fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let Some(cipher) = &self.cipher else {
            self.stream.write_all(data)?;
            return Ok(());
        };
        let pad = (8 - data.len() % 8) % 8;
        let mut buf = data.to_vec();
        buf.resize(data.len() + pad, 0);
        cipher.encrypt_transfer(&mut buf);
        let mut out = Vec::with_capacity(9 + buf.len());
        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(pad as u8);
        out.extend_from_slice(&buf);
        self.stream.write_all(&out)?;
        Ok(())
    }

    fn read_block(&mut self) -> anyhow::Result<()> {
        let Some(cipher) = &self.cipher else {
            let mut buf = [0u8; 4096];
            let n = self.stream.read(&mut buf)?;
            ensure!(n > 0, "server closed the data connection");
            self.pending.extend_from_slice(&buf[..n]);
            return Ok(());
        };
        let mut head = [0u8; 9];
        self.stream.read_exact(&mut head).context("reading block header")?;
        let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
        let pad = head[8] as usize;
        ensure!(len % 8 == 0 && pad <= len.min(8) && len <= 1 << 24, "bad block header {head:02x?}");
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf)?;
        cipher.decrypt_transfer(&mut buf);
        buf.truncate(len - pad);
        self.pending.extend_from_slice(&buf);
        Ok(())
    }

    pub fn read(&mut self, n: usize) -> anyhow::Result<Vec<u8>> {
        while self.pending.len() < n {
            self.read_block()?;
        }
        Ok(self.pending.drain(..n).collect())
    }

    pub fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.read(1)?[0])
    }

    pub fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.read(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.read(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_be_bytes(self.read(8)?.try_into().unwrap()))
    }

    /// A size or offset: 8 bytes when encrypted, 4 when not.
    pub fn size(&mut self) -> anyhow::Result<u64> {
        if self.cipher.is_some() { self.u64() } else { self.u32().map(u64::from) }
    }

    pub fn size_bytes(&self, v: u64) -> Vec<u8> {
        if self.cipher.is_some() { v.to_be_bytes().to_vec() } else { (v as u32).to_be_bytes().to_vec() }
    }

    pub fn string(&mut self) -> anyhow::Result<Vec<u8>> {
        let n = self.u16()? as usize;
        self.read(n)
    }
}

fn with_len(s: &[u8]) -> Vec<u8> {
    let mut out = (s.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(s);
    out
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace('\x01', "/")
}

/// Upload a local file (data fork only) into `folder` on the server.
pub fn upload(addr: SocketAddr, user_id: u32, secret: Option<&[u8]>, local: &Path, folder: &[u8], log: &mut Vec<String>) -> anyhow::Result<()> {
    let data = std::fs::read(local).with_context(|| format!("reading {}", local.display()))?;
    let name = local.file_name().context("no file name")?.to_string_lossy().into_owned();
    log.push(format!("upload {:?} ({} bytes) to /{}", name, data.len(), show(folder)));
    let kind = if secret.is_some() { UPLOAD_ENCRYPTED } else { UPLOAD };
    let mut s = BlockStream::open(addr, kind, user_id, secret)?;
    s.send(&with_len(folder))?;
    s.send(&with_len(name.as_bytes()))?;
    let exists = s.u8()?;
    log.push(format!("  server: item state {exists} (0 new, 1 exists, 2 partial)"));
    s.send(&[0])?;

    let mut summary = (data.len() as u64).to_be_bytes().to_vec();
    summary.extend_from_slice(&1u32.to_be_bytes());
    s.send(&summary)?;

    let mut item = with_len(name.as_bytes());
    item.extend_from_slice(b"TEXTttxt");
    // Finder flags, extended Finder info, and a count of extra bytes (none).
    item.extend_from_slice(&[0; 2 + 16 + 4]);
    s.send(&item)?;

    let (data_have, rsrc_have) = (s.size()?, s.size()?);
    log.push(format!("  server: already has data {data_have}, resource {rsrc_have}"));
    let rest = &data[(data_have as usize).min(data.len())..];
    let mut sizes = s.size_bytes(rest.len() as u64);
    sizes.extend_from_slice(&s.size_bytes(0));
    s.send(&sizes)?;
    for chunk in rest.chunks(16 * 1024) {
        s.send(chunk)?;
    }
    s.send(&with_len(b"uploaded by carracho-probe"))?;
    s.stream.flush()?;

    // Wait for the server to close the connection.
    let mut rest = Vec::new();
    s.stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    match s.stream.read_to_end(&mut rest) {
        Ok(_) => log.push(format!("  server closed the data connection ({} extra bytes)", rest.len())),
        Err(e) => log.push(format!("  data connection: {e} ({} extra bytes)", rest.len())),
    }
    Ok(())
}

/// Download a file or folder; files are saved in `dir`.
pub fn download(addr: SocketAddr, user_id: u32, secret: Option<&[u8]>, path: &[u8], dir: &Path, log: &mut Vec<String>) -> anyhow::Result<()> {
    log.push(format!("download /{}", show(path)));
    let kind = if secret.is_some() { DOWNLOAD_ENCRYPTED } else { DOWNLOAD };
    let mut s = BlockStream::open(addr, kind, user_id, secret)?;
    s.send(&with_len(path))?;
    let mut queue = s.u32()?;
    log.push(format!("  queue position {queue}"));
    while queue > 0 {
        if s.u8()? == 1 {
            queue -= 1;
        }
    }
    let total = s.u64()?;
    let items = s.u32()?;
    log.push(format!("  {total} bytes in {items} items"));
    for _ in 0..items {
        let rel = s.string()?;
        let ty = s.read(4)?;
        let creator = s.read(4)?;
        let finder_flags = s.u16()?;
        let ext = s.read(16)?;
        let extra_len = s.u32()?;
        let extra = s.read(extra_len as usize)?;
        log.push(format!(
            "  item {:?} type {:?} creator {:?} finder flags {finder_flags:#06x} ext {} extra {:02x?}",
            show(&rel),
            String::from_utf8_lossy(&ty),
            String::from_utf8_lossy(&creator),
            ext.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            extra
        ));
        if ty == b"FLDR" {
            continue;
        }
        let mut offsets = s.size_bytes(0);
        offsets.extend_from_slice(&s.size_bytes(0));
        s.send(&offsets)?;
        let (data_len, rsrc_len) = (s.size()?, s.size()?);
        let data = s.read(data_len as usize)?;
        s.read(rsrc_len as usize)?;
        let comment = s.string()?;
        log.push(format!("    data {data_len} bytes, resource {rsrc_len} bytes, comment {:?}", show(&comment)));
        let file = dir.join(show(&rel).replace('/', "_"));
        std::fs::write(&file, &data)?;
        log.push(format!("    saved data fork to {}", file.display()));
    }
    Ok(())
}
