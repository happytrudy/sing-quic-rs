use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use crate::congestion::SwitchableCongestionFactory;
use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig, VarInt};

// Start with the upstream Hysteria2 connection window. Per-stream credit is
// bounded by this aggregate window so the connection window can grow at
// runtime without a Quinn-internal stream-window setter.
pub(crate) const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
pub(crate) const SEND_WINDOW: u64 = 20 * 1024 * 1024;
pub(crate) const UDP_SOCKET_BUFFER_SIZE: usize = 16 * 1024 * 1024;

pub(crate) fn base_transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .congestion_controller_factory(Arc::new(SwitchableCongestionFactory))
        .stream_receive_window(VarInt::MAX)
        .receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(10)));
    transport
}

pub(crate) fn bind_endpoint(
    address: SocketAddr,
    server_config: Option<ServerConfig>,
) -> io::Result<Endpoint> {
    let socket = UdpSocket::bind(address)?;
    tune_udp_socket(&socket);
    Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(TokioRuntime),
    )
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
    fn uses_adaptive_hysteria2_flow_control_windows() {
        assert_eq!(CONNECTION_RECEIVE_WINDOW, 20_971_520);
        assert!(SEND_WINDOW >= u64::from(CONNECTION_RECEIVE_WINDOW));
        let _ = base_transport_config();
    }

    #[tokio::test]
    async fn binds_tuned_udp_endpoint() {
        let endpoint = bind_endpoint("127.0.0.1:0".parse().unwrap(), None).unwrap();
        assert_ne!(endpoint.local_addr().unwrap().port(), 0);
        endpoint.close(0u32.into(), b"test complete");
    }
}
