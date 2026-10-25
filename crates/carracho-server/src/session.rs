//! The main connection (protocol.md, 4.1–4.4): greeting, login, then reading
//! requests and dispatching them while a writer task sends replies and pushes.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use carracho_proto::crypto::{self, FrameCipher};
use carracho_proto::packet::{self, Field, MAX_BODY_LEN, Packet};
use carracho_proto::{macroman, mactime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use crate::codes::{cmd, err, privs};
use crate::handlers;
use crate::state::{Out, Server, State, User};

/// The connection is dropped after this long without any packet (keepalives
/// count).
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Time allowed for the greeting and login.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest icon accepted.
const ICON_LEN: usize = 0x27c;

/// Map an IPv4-mapped IPv6 address to IPv4; other IPv6 addresses become
/// 0.0.0.0, which the protocol can't represent anyway.
pub fn ipv4_of(addr: SocketAddr) -> Ipv4Addr {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
    }
}

/// Decrements the per-IP connection count when the connection ends.
struct IpSlot {
    server: Arc<Server>,
    ip: Ipv4Addr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut st = self.server.lock();
        if let Some(n) = st.connections_per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.connections_per_ip.remove(&self.ip);
            }
        }
    }
}

/// Read one frame and decrypt it into a packet.
async fn read_packet(r: &mut OwnedReadHalf, cipher: &FrameCipher) -> anyhow::Result<Packet> {
    let len = r.read_u32().await? as usize;
    ensure!(len % 8 == 0 && (8..=MAX_BODY_LEN + packet::HEADER_LEN + 8).contains(&len), "bad frame length {len}");
    let mut frame = vec![0u8; len];
    r.read_exact(&mut frame).await?;
    cipher.open(&mut frame);
    Ok(Packet::decode(&frame)?)
}

/// The writer task: encrypts and sends queued packets.
async fn writer(mut w: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Out>) {
    let mut cipher = FrameCipher::new(crypto::INITIAL_KEY);
    while let Some(out) = rx.recv().await {
        match out {
            Out::Packet(p) => {
                if w.write_all(&p.to_frame(&cipher)).await.is_err() {
                    break;
                }
            }
            Out::Rekey(key) => cipher = FrameCipher::new(&key),
            Out::Close => break,
        }
    }
    let _ = w.shutdown().await;
}

fn error(task: u32, code: u16) -> Packet {
    Packet::new(cmd::ERROR, task, vec![Field::u16(1, code)])
}

/// Serve one main connection to the end.
pub async fn serve(server: Arc<Server>, stream: TcpStream, peer: SocketAddr) {
    let ip = ipv4_of(peer);
    {
        let mut st = server.lock();
        if !st.store.settings.allows(ip) {
            st.log(format!("Connection rejected from {ip}"));
            return;
        }
        let limit = st.store.settings.max_connections_per_ip.max(1) as u32;
        let n = st.connections_per_ip.entry(ip).or_default();
        if *n >= limit {
            st.log(format!("Too many connections from {ip}"));
            return;
        }
        *n += 1;
        st.stats.hits += 1;
    }
    let _slot = IpSlot { server: server.clone(), ip };
    let _ = stream.set_nodelay(true);
    let (mut r, mut w) = stream.into_split();

    let mut greeting = [0u8; 13];
    match tokio::time::timeout(LOGIN_TIMEOUT, r.read_exact(&mut greeting)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    if greeting[..11] != packet::GREETING_MAGIC {
        server.lock().log(format!("Unknown protocol from {ip}"));
        return;
    }
    if w.write_all(&packet::greeting(packet::SERVER_VERSION)).await.is_err() {
        return;
    }

    let (tx, rx) = mpsc::unbounded_channel();
    let writer = tokio::spawn(writer(w, rx));
    let user_id = match tokio::time::timeout(LOGIN_TIMEOUT, login(&server, &mut r, &tx, ip)).await {
        Ok(Ok(Some((id, secret)))) => {
            let cipher = FrameCipher::new(&secret);
            if let Err(e) = request_loop(&server, &mut r, &cipher, id).await {
                tracing::debug!(user = id, "connection ended: {e:#}");
            }
            Some(id)
        }
        Ok(Ok(None)) => None,
        Ok(Err(e)) => {
            tracing::debug!(%ip, "login failed: {e:#}");
            None
        }
        Err(_) => None,
    };
    if let Some(id) = user_id {
        server.lock().remove_user(id);
    }
    let _ = tx.send(Out::Close);
    drop(tx);
    let _ = writer.await;
}

/// Run the login exchange. Returns the new user's ID and session secret, or
/// `None` if the login was refused (the error has been queued).
async fn login(
    server: &Arc<Server>,
    r: &mut OwnedReadHalf,
    tx: &mpsc::UnboundedSender<Out>,
    ip: Ipv4Addr,
) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
    let challenge: [u8; crypto::CHALLENGE_LEN] = rand::random();
    tx.send(Out::Packet(Packet::new(cmd::CHALLENGE, 0, vec![Field::new(1, challenge.to_vec())])))?;

    let initial = FrameCipher::new(crypto::INITIAL_KEY);
    let request = read_packet(r, &initial).await?;
    if request.command != cmd::LOGIN {
        bail!("expected login, got command {:#x}", request.command);
    }
    let text = |tag| request.field(tag).map(|f| f.data.clone()).unwrap_or_default();
    let login = macroman::decode(&text(1));
    let response = String::from_utf8_lossy(&text(2)).to_ascii_lowercase();
    let mut nick = text(4);
    nick.truncate(64);
    let mut icon = text(5);
    if icon.len() > ICON_LEN {
        icon.clear();
    }

    let mut st = server.lock();
    // The login reply and any login error carry task 0, as on the original.
    let refuse = |st: &mut State, code: u16, why: &str| {
        st.log(format!("Login refused for \"{login}\" from {ip}: {why}"));
        let _ = tx.send(Out::Packet(error(0, code)));
    };
    let Some(account) = st.store.account(&login).cloned() else {
        st.stats.incorrect_logins += 1;
        refuse(&mut st, err::INCORRECT_LOGIN, "no such account");
        return Ok(None);
    };
    if st.users.len() >= st.store.settings.max_users as usize && !privs::has(account.privileges, privs::ADMIN) {
        refuse(&mut st, err::SERVER_FULL, "server full");
        return Ok(None);
    }
    let secret = crypto::session_secret(&macroman::encode(&account.password), &challenge);
    if crypto::login_response(&secret) != response {
        st.stats.incorrect_logins += 1;
        refuse(&mut st, err::INCORRECT_LOGIN, "wrong password");
        return Ok(None);
    }

    let id = st.next_user_id;
    st.next_user_id += 1;
    let now = mactime::now();
    if let Some(a) = st.store.account_mut(&account.login) {
        a.last_login = now;
    }
    if let Err(e) = st.store.save_accounts() {
        tracing::warn!("saving accounts: {e:#}");
    }
    let user = User {
        id,
        nick,
        icon,
        login: account.login.clone(),
        privileges: account.privileges,
        ip,
        tx: tx.clone(),
        real_name: Vec::new(),
        email: Vec::new(),
        about: Vec::new(),
        login_time: now,
        last_activity: Instant::now(),
        idle: false,
        state: 0,
        channels: Vec::new(),
        secret: secret.clone(),
    };
    let _ = server.vfs.ensure_home(&user.requester());
    let joined = State::user_joined_packet(&user);
    let line = format!("\"{}\" ({}) logged in", macroman::decode(&user.nick), user.login);
    st.users.insert(id, user);
    st.stats.peak = st.stats.peak.max(st.users.len() as u32);

    let settings = &st.store.settings;
    let mut ident = Vec::with_capacity(12);
    ident.extend_from_slice(&id.to_be_bytes());
    ident.extend_from_slice(&account.privileges.to_be_bytes());
    let mut fields = vec![
        Field::new(1, ident),
        Field::new(2, macroman::encode(&settings.name)),
        Field::new(3, st.user_list()),
        Field::u16(0x21, settings.max_transfers_per_user),
        Field::u16(5, 2),
    ];
    if !settings.agreement.is_empty() {
        fields.push(Field::new(4, macroman::encode(&settings.agreement)));
    }
    tx.send(Out::Packet(Packet::new(cmd::LOGIN_ACCEPTED, 0, fields)))?;
    tx.send(Out::Rekey(secret.clone()))?;
    st.broadcast_except(id, &joined);
    st.log(line);
    Ok(Some((id, secret)))
}

async fn request_loop(server: &Arc<Server>, r: &mut OwnedReadHalf, cipher: &FrameCipher, id: u32) -> anyhow::Result<()> {
    loop {
        let p = tokio::time::timeout(RECEIVE_TIMEOUT, read_packet(r, cipher))
            .await
            .context("no packets for 5 minutes")??;
        if !server.lock().users.contains_key(&id) {
            return Ok(()); // kicked
        }
        if p.command != cmd::KEEPALIVE {
            handlers::note_activity(server, id);
        }
        match handlers::dispatch(server, id, &p) {
            Ok(()) => {}
            Err(handlers::Fail::Error(code)) => server.lock().send_to(id, error(p.task, code)),
            Err(handlers::Fail::Disconnect) => return Ok(()),
        }
    }
}
