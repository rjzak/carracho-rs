use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use carracho_proto::tracker;
use carracho_tracker::{Config, Tracker};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Carracho tracker: lists Carracho servers for Carracho clients.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    bind: IpAddr,
    /// Port for both server registration (UDP) and list requests (TCP).
    #[arg(long, default_value_t = tracker::PORT)]
    port: u16,
    /// Seconds a server stays listed without re-registering.
    #[arg(long, default_value_t = tracker::DEFAULT_EXPIRY.as_secs())]
    expiry: u64,
    /// Most servers listed at once.
    #[arg(long, default_value_t = Config::default().max_servers)]
    max_servers: usize,
    /// Most list requests served at once.
    #[arg(long, default_value_t = Config::default().max_connections)]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let addr = SocketAddr::new(args.bind, args.port);
    let config = Config {
        udp: addr,
        tcp: addr,
        expiry: Duration::from_secs(args.expiry),
        max_servers: args.max_servers,
        max_connections: args.max_connections,
        ..Config::default()
    };
    let tracker = Tracker::bind(config).await?;
    tokio::select! {
        result = tracker.serve() => result?,
        result = shutdown_signal() => {
            result?;
            tracing::info!("tracker shut down");
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
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
