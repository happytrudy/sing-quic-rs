mod client;
mod metrics;
mod protocol;
mod server;
mod stream;
mod transport;

pub use client::{Client, ClientOptions};
pub use server::{Accepted, MasqueradeHandler, Server, ServerOptions, User};
pub use stream::Hysteria2Stream;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientBandwidth {
    pub send_bps: u64,
    pub receive_bps: u64,
    pub disable_loss_compensation: bool,
    pub brutal_debug: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerBandwidth {
    pub send_bps: u64,
    pub receive_bps: u64,
    pub ignore_client_bandwidth: bool,
    pub disable_loss_compensation: bool,
    pub brutal_debug: bool,
}
