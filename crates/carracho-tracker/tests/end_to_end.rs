//! Drive a running tracker over real sockets, the way an original Carracho
//! server and client would.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use carracho_proto::tracker::{decode_server_list, encode_registration, ServerFlags, ServerInfo};
use carracho_tracker::{Config, Tracker};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn start(expiry: Duration) -> (SocketAddr, SocketAddr) {
    let localhost = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let tracker =
        Tracker::bind(Config { udp: localhost, tcp: localhost, expiry, ..Config::default() })
            .await
            .unwrap();
    let addrs = (tracker.udp_addr().unwrap(), tracker.tcp_addr().unwrap());
    tokio::spawn(tracker.serve());
    addrs
}

fn registration(name: &str, users: u16) -> Vec<u8> {
    encode_registration(&ServerInfo {
        // A server behind NAT announces its private address.
        address: Ipv4Addr::new(10, 0, 1, 2),
        port: 6700,
        name: name.as_bytes().to_vec(),
        description: b"Old Mac files".to_vec(),
        users,
        flags: ServerFlags::new(9, true),
    })
}

/// Query the way the original client does: magic and command in two writes.
async fn query(tcp: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(tcp).await.unwrap();
    stream.write_all(b"CTQ\x01").await.unwrap();
    stream.write_all(b"QLI").await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    reply
}

/// Registration is fire-and-forget UDP, so poll until the tracker has it.
async fn wait_for_count(tcp: SocketAddr, count: usize) -> Vec<ServerInfo> {
    for _ in 0..100 {
        let servers = decode_server_list(&query(tcp).await).unwrap();
        if servers.len() == count {
            return servers;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("tracker never listed {count} servers");
}

#[tokio::test]
async fn server_registers_and_client_lists_it() {
    let (udp, tcp) = start(Duration::from_secs(600)).await;
    assert_eq!(query(tcp).await, [0, 0, 0, 0], "empty tracker lists zero servers");

    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    server.send_to(&registration("Retro", 3), udp).await.unwrap();
    let servers = wait_for_count(tcp, 1).await;

    let s = &servers[0];
    assert_eq!(s.address, Ipv4Addr::LOCALHOST, "listed under the address it was seen from");
    assert_eq!(s.port, 6700);
    assert_eq!(s.name, b"Retro");
    assert_eq!(s.users, 3);
    assert!(s.flags.is_private());
    assert_eq!(s.flags.speed_label(), Some("DSL"));

    // Re-registering updates the existing entry instead of adding another.
    server.send_to(&registration("Retro", 7), udp).await.unwrap();
    for _ in 0..100 {
        if decode_server_list(&query(tcp).await).unwrap()[0].users == 7 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("re-registration did not update the user count");
}

#[tokio::test]
async fn malformed_registrations_are_ignored() {
    let (udp, tcp) = start(Duration::from_secs(600)).await;
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    sender.send_to(b"not a carracho packet", udp).await.unwrap();
    sender.send_to(&[0u8; 300], udp).await.unwrap();
    // A valid one afterwards proves the bad ones were processed and dropped.
    sender.send_to(&registration("Good", 0), udp).await.unwrap();
    let servers = wait_for_count(tcp, 1).await;
    assert_eq!(servers[0].name, b"Good");
}

#[tokio::test]
async fn servers_expire() {
    let (udp, tcp) = start(Duration::from_millis(200)).await;
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    server.send_to(&registration("Brief", 0), udp).await.unwrap();
    wait_for_count(tcp, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(decode_server_list(&query(tcp).await).unwrap().is_empty());
}

#[tokio::test]
async fn unknown_query_gets_no_reply() {
    let (_, tcp) = start(Duration::from_secs(600)).await;
    let mut stream = TcpStream::connect(tcp).await.unwrap();
    stream.write_all(b"GET / H").await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert!(reply.is_empty());
}
