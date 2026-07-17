mod client;
mod protocol;
mod server;

pub use client::{Client, ClientOptions};
pub use server::{Accepted, MasqueradeHandler, Server, ServerOptions, User};
pub use tokio::io::DuplexStream as Hysteria2Stream;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientBandwidth {
    pub send_bps: u64,
    pub receive_bps: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerBandwidth {
    pub send_bps: u64,
    pub receive_bps: u64,
    pub ignore_client_bandwidth: bool,
}
