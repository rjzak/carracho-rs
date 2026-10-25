//! A Carracho tracker: servers register over UDP and clients download the
//! list of servers over TCP. Compatible with the original Carracho 1.0
//! clients and servers; see `docs/protocol.md`, section 3.

pub mod registry;
pub mod service;

pub use service::{Config, Tracker};
