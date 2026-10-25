//! Wire formats for the Carracho protocols.
//!
//! See `docs/protocol.md` in the repository for the full specification. All
//! integers are big-endian and strings are Mac OS Roman Pascal strings.

pub mod account;
pub mod crypto;
pub mod mactime;
pub mod macroman;
pub mod packet;
pub mod tracker;
pub mod wire;

pub use wire::DecodeError;
