use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use carracho_server::{CarrachoServer, Config};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Carracho server: file sharing, chat and news for Carracho clients.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    bind: IpAddr,
    /// Main port; the data connection uses the next port up.
    #[arg(long, default_value_t = carracho_proto::packet::PORT)]
    port: u16,
    /// Directory for settings, accounts, news, personal folders and trash.
    #[arg(long, default_value = "carracho-data")]
    data: PathBuf,
    /// The shared folder. Defaults to `files` inside the data directory.
    #[arg(long)]
    files: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let files_dir = args.files.unwrap_or_else(|| args.data.join("files"));
    let config = Config { bind: SocketAddr::new(args.bind, args.port), data_dir: args.data, files_dir };
    let server = CarrachoServer::bind(config).await?;
    tokio::select! {
        result = server.serve() => result?,
        result = shutdown_signal() => {
            result?;
            tracing::info!("server shut down");
        }
    }
    Ok(())
}

/// Resolves on Ctrl-C, or on SIGTERM from a service manager.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
