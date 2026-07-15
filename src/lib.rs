//! QUIC protocol implementations used by `sing-box-rs`.
//!
//! The first implemented protocol is the authenticated Hysteria2 TCP path.

mod address;
mod error;
pub mod hysteria2;
mod varint;

pub use address::Address;
pub use error::{Error, Result};
