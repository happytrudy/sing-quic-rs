//! QUIC protocol implementations used by `sing-box-rs`.
//!
//! The first implemented protocol is the authenticated Hysteria2 TCP path.

mod address;
pub mod congestion;
mod error;
pub mod hysteria2;
pub mod shadowquic;
pub mod sunnyquic;
pub mod transport;
mod varint;

pub use address::Address;
pub use error::{Error, Result};
