use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use crate::congestion::SwitchableCongestionFactory;
use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use socket2::{Domain, Protocol, Socket, Type};

pub(crate) const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
pub(crate) const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
pub(crate) const SEND_WINDOW: u64 = 20 * 1024 * 1024;
pub(crate) const UDP_SOCKET_BUFFER_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const DATAGRAM_BUFFER_SIZE: usize = 2_500_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuicTransportOptions {
    pub initial_packet_size: u16,
    pub disable_path_mtu_discovery: bool,
}

pub(crate) fn base_transport_config(options: QuicTransportOptions) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .congestion_controller_factory(Arc::new(SwitchableCongestionFactory))
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .send_window(SEND_WINDOW)
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_SIZE)
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(10)));
    if options.initial_packet_size > 0 {
        transport.initial_mtu(options.initial_packet_size);
    }
    if options.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    transport
}

pub(crate) fn bind_endpoint(
    address: SocketAddr,
    server_config: Option<ServerConfig>,
) -> io::Result<Endpoint> {
    let socket = bind_udp_socket(address)?;
    tune_udp_socket(&socket);
    Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(TokioRuntime),
    )
}

fn bind_udp_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6()
        && let Err(error) = socket.set_only_v6(false)
    {
        tracing::debug!(%error, "unable to make QUIC UDP socket dual-stack");
    }
    socket.bind(&address.into())?;
    Ok(socket.into())
}

fn tune_udp_socket(socket: &UdpSocket) {
    let state = match quinn::udp::UdpSocketState::new(socket.into()) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(%error, "failed to initialize UDP socket tuning");
            return;
        }
    };
    if let Err(error) = state.set_send_buffer_size(socket.into(), UDP_SOCKET_BUFFER_SIZE) {
        tracing::warn!(%error, "failed to increase UDP send buffer");
    }
    if let Err(error) = state.set_recv_buffer_size(socket.into(), UDP_SOCKET_BUFFER_SIZE) {
        tracing::warn!(%error, "failed to increase UDP receive buffer");
    }
    let send_buffer = state.send_buffer_size(socket.into()).unwrap_or_default();
    let receive_buffer = state.recv_buffer_size(socket.into()).unwrap_or_default();
    if send_buffer < UDP_SOCKET_BUFFER_SIZE || receive_buffer < UDP_SOCKET_BUFFER_SIZE {
        tracing::warn!(
            requested = UDP_SOCKET_BUFFER_SIZE,
            send_buffer,
            receive_buffer,
            "operating system limited QUIC UDP socket buffers"
        );
    } else {
        tracing::debug!(
            send_buffer,
            receive_buffer,
            "configured QUIC UDP socket buffers"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_official_hysteria2_flow_control_windows() {
        assert_eq!(STREAM_RECEIVE_WINDOW, 8_388_608);
        assert_eq!(CONNECTION_RECEIVE_WINDOW, 20_971_520);
        assert!(SEND_WINDOW >= u64::from(CONNECTION_RECEIVE_WINDOW));
        let _ = base_transport_config(QuicTransportOptions::default());
        let _ = base_transport_config(QuicTransportOptions {
            initial_packet_size: 1200,
            disable_path_mtu_discovery: true,
        });
    }

    #[tokio::test]
    async fn binds_tuned_udp_endpoint() {
        let endpoint = bind_endpoint("127.0.0.1:0".parse().unwrap(), None).unwrap();
        assert_ne!(endpoint.local_addr().unwrap().port(), 0);
        endpoint.close(0u32.into(), b"test complete");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_unspecified_socket_is_explicitly_dual_stack() {
        let socket = bind_udp_socket("[::]:0".parse().unwrap()).unwrap();
        assert!(!socket2::SockRef::from(&socket).only_v6().unwrap());
    }
}
