//! Query a Carracho tracker, or register a server with one by hand.

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context};
use carracho_proto::tracker::{
    decode_server_list, encode_registration, ServerFlags, ServerInfo, PORT, QUERY, SPEED_LABELS,
};
use carracho_proto::macroman;
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the servers a tracker lists.
    Query {
        /// Tracker host, optionally with :port.
        tracker: String,
    },
    /// Send one registration datagram, as a Carracho server would every 5 minutes.
    Register {
        /// Tracker host, optionally with :port.
        tracker: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        /// The server's TCP port.
        #[arg(long, default_value_t = 6700)]
        port: u16,
        #[arg(long, default_value_t = 0)]
        users: u16,
        /// Connection speed, 1-13 (see `docs/protocol.md`); 0 for unknown.
        #[arg(long, default_value_t = 0)]
        speed: u8,
        #[arg(long)]
        private: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::Query { tracker } => query(resolve(&tracker)?).await,
        Command::Register { tracker, name, description, port, users, speed, private } => {
            if speed as usize > SPEED_LABELS.len() {
                bail!("speed must be between 0 and {}", SPEED_LABELS.len());
            }
            let info = ServerInfo {
                // Trackers replace this with the address the datagram came from.
                address: Ipv4Addr::UNSPECIFIED,
                port,
                name: macroman::encode(&name),
                description: macroman::encode(&description),
                users,
                flags: ServerFlags::new(speed, private),
            };
            let to = resolve(&tracker)?;
            let udp = UdpSocket::bind("0.0.0.0:0").await?;
            udp.send_to(&encode_registration(&info), to).await?;
            println!("registration sent to {to}");
            Ok(())
        }
    }
}

fn resolve(host: &str) -> anyhow::Result<SocketAddr> {
    let with_port = if host.contains(':') { host.to_string() } else { format!("{host}:{PORT}") };
    with_port
        .to_socket_addrs()
        .with_context(|| format!("resolving {with_port}"))?
        .find(SocketAddr::is_ipv4)
        .with_context(|| format!("{with_port} has no IPv4 address"))
}

async fn query(addr: SocketAddr) -> anyhow::Result<()> {
    // The Classic tracker doesn't close the connection after replying, so
    // read the reply by its count instead of to end-of-stream.
    let reply = tokio::time::timeout(Duration::from_secs(15), async {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(&QUERY).await?;
        let mut reply = vec![0u8; 4];
        stream.read_exact(&mut reply).await?;
        let count = u32::from_be_bytes(reply[..4].try_into().unwrap());
        for _ in 0..count {
            let len = stream.read_u8().await?;
            reply.push(len);
            let start = reply.len();
            reply.resize(start + len as usize, 0);
            stream.read_exact(&mut reply[start..]).await?;
        }
        anyhow::Ok(reply)
    })
    .await
    .context("tracker did not answer within 15 seconds")??;

    let servers = decode_server_list(&reply).context("malformed server list")?;
    println!("{} server(s) on {addr}", servers.len());
    for s in servers {
        println!(
            "{:<21} {:>5} users  {:<8} {}{}",
            format!("{}:{}", s.address, s.port),
            s.users,
            s.flags.speed_label().unwrap_or("-"),
            if s.flags.is_private() { "[private] " } else { "" },
            s.name_lossy(),
        );
        if !s.description.is_empty() {
            println!("{:<21} {}", "", s.description_lossy());
        }
    }
    Ok(())
}
