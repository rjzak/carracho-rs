//! Carracho server: the main connection, the data connection and tracker
//! registration, compatible with the original clients. See
//! `docs/protocol.md`.

pub mod codes;
pub mod files;
mod handlers;
pub mod session;
pub mod state;
pub mod store;
pub mod tracker;
pub mod transfer;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::net::TcpListener;

use crate::files::Vfs;
use crate::state::{Server, State};
use crate::store::Store;

pub struct Config {
    /// Main connection address; the data connection uses the next port.
    pub bind: SocketAddr,
    /// Settings, accounts, news, personal folders and trash.
    pub data_dir: PathBuf,
    /// The shared folder tree.
    pub files_dir: PathBuf,
}

/// A bound server, ready to serve.
pub struct CarrachoServer {
    pub server: Arc<Server>,
    main: TcpListener,
    data: TcpListener,
}

impl CarrachoServer {
    pub async fn bind(config: Config) -> anyhow::Result<Self> {
        let store = Store::open(&config.data_dir)?;
        let vfs = Vfs::new(config.files_dir.clone(), config.data_dir.join("homes"), config.data_dir.join("trash"))
            .with_context(|| format!("preparing {}", config.files_dir.display()))?;
        let main = TcpListener::bind(config.bind).await.with_context(|| format!("binding {}", config.bind))?;
        let mut data_addr = main.local_addr()?;
        data_addr.set_port(data_addr.port() + 1);
        let data = TcpListener::bind(data_addr).await.with_context(|| format!("binding {data_addr}"))?;
        let server = Arc::new(Server {
            state: Mutex::new(State::new(store)),
            vfs,
            started: Instant::now(),
            data_dir: config.data_dir,
        });
        Ok(Self { server, main, data })
    }

    pub fn main_addr(&self) -> std::io::Result<SocketAddr> {
        self.main.local_addr()
    }

    pub fn data_addr(&self) -> std::io::Result<SocketAddr> {
        self.data.local_addr()
    }

    pub async fn serve(self) -> anyhow::Result<()> {
        let Self { server, main, data } = self;
        let port = main.local_addr()?.port();
        server.lock().log(format!("Server started on port {port}"));
        tokio::spawn(tracker::run(server.clone(), port));
        let idle = server.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                handlers::mark_idle(&idle);
            }
        });
        let data_server = server.clone();
        tokio::spawn(async move {
            loop {
                match data.accept().await {
                    Ok((stream, peer)) => {
                        tokio::spawn(transfer::serve(data_server.clone(), stream, peer));
                    }
                    Err(e) => {
                        tracing::warn!("data accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        loop {
            match main.accept().await {
                Ok((stream, peer)) => {
                    tokio::spawn(session::serve(server.clone(), stream, peer));
                }
                Err(e) => {
                    tracing::warn!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}
