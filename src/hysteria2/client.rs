use std::{
    future::poll_fn,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use http::{Method, Request};
use quinn::{ClientConfig, Endpoint, TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, pki_types::CertificateDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::Mutex,
};

use crate::congestion::{
    CongestionKind, SwitchableCongestionFactory, configure_connection_brutal,
    connection_congestion_kind,
};
use crate::{Address, Error, Result};

use super::ClientBandwidth;
use super::protocol::{
    CongestionReceive, HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, STATUS_AUTH_OK, URL_AUTHORITY,
    URL_PATH, padding, parse_congestion_receive, read_tcp_response, write_tcp_request,
};

const BRIDGE_CAPACITY: usize = 256 * 1024;
const ALPN_H3: &[u8] = b"h3";

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: SocketAddr,
    pub server_name: String,
    pub password: String,
    pub ca_certificates: Vec<Vec<u8>>,
}

pub struct Client {
    endpoint: Endpoint,
    options: ClientOptions,
    bandwidth: ClientBandwidth,
    connection: Mutex<Option<Arc<ClientConnection>>>,
}

struct ClientConnection {
    connection: quinn::Connection,
    congestion: CongestionKind,
    h3_driver: tokio::task::JoinHandle<()>,
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"client closed");
        self.h3_driver.abort();
    }
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Self> {
        Self::new_with_bandwidth(options, ClientBandwidth::default())
    }

    pub fn new_with_bandwidth(options: ClientOptions, bandwidth: ClientBandwidth) -> Result<Self> {
        if options.server_name.is_empty() {
            return Err(Error::InvalidServerName(options.server_name));
        }
        let mut roots = RootCertStore::empty();
        for certificate in &options.ca_certificates {
            roots.add(CertificateDer::from(certificate.clone()))?;
        }
        let mut tls = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];
        let crypto =
            QuicClientConfig::try_from(tls).map_err(|error| Error::QuicTls(error.to_string()))?;
        let mut transport = TransportConfig::default();
        transport.congestion_controller_factory(Arc::new(SwitchableCongestionFactory));
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        let mut client_config = ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));

        let bind_address = match options.server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint = Endpoint::client(bind_address)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            options,
            bandwidth,
            connection: Mutex::new(None),
        })
    }

    async fn connection(&self) -> Result<Arc<ClientConnection>> {
        let mut cached = self.connection.lock().await;
        if let Some(connection) = cached.as_ref()
            && connection.connection.close_reason().is_none()
        {
            return Ok(Arc::clone(connection));
        }
        let connection = self
            .endpoint
            .connect(self.options.server, &self.options.server_name)?
            .await?;
        let connection = authenticate(connection, &self.options.password, self.bandwidth).await?;
        let connection = Arc::new(connection);
        *cached = Some(Arc::clone(&connection));
        Ok(connection)
    }

    pub async fn connect(&self, destination: Address) -> Result<DuplexStream> {
        let connection = self.connection().await?;
        let (mut send, recv) = connection.connection.open_bi().await?;
        write_tcp_request(&mut send, &destination).await?;
        let (application, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
        let (bridge_read, bridge_write) = tokio::io::split(bridge);
        spawn_encode(bridge_read, send);
        spawn_decode(recv, bridge_write);
        Ok(application)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"client closed");
    }

    pub async fn congestion_kind(&self) -> Option<CongestionKind> {
        self.connection
            .lock()
            .await
            .as_ref()
            .map(|connection| connection.congestion)
    }
}

async fn authenticate(
    connection: quinn::Connection,
    password: &str,
    bandwidth: ClientBandwidth,
) -> Result<ClientConnection> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut send_request) = h3::client::new(h3_connection)
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{URL_AUTHORITY}{URL_PATH}"))
        .header(HEADER_AUTH, password)
        .header(HEADER_CC_RX, bandwidth.receive_bps.to_string())
        .header(HEADER_PADDING, padding(256, 2048))
        .body(())
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    while stream
        .recv_data()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?
        .is_some()
    {}
    if response.status().as_u16() != STATUS_AUTH_OK {
        connection.close(0u32.into(), b"authentication failed");
        return Err(Error::AuthenticationFailed(response.status().as_u16()));
    }

    let remote_receive = parse_congestion_receive(response.headers().get(HEADER_CC_RX));
    if let Some(bytes_per_second) = negotiated_send_rate(bandwidth.send_bps, remote_receive)
        && !configure_connection_brutal(&connection, bytes_per_second)
    {
        connection.close(0u32.into(), b"congestion control failed");
        return Err(Error::CongestionControl);
    }
    let congestion = connection_congestion_kind(&connection).ok_or(Error::CongestionControl)?;

    let h3_driver = tokio::spawn(async move {
        let _keep_sender_alive = send_request;
        let _ = poll_fn(|context| driver.poll_close(context)).await;
    });
    Ok(ClientConnection {
        connection,
        congestion,
        h3_driver,
    })
}

fn negotiated_send_rate(
    configured_send_bps: u64,
    remote_receive: CongestionReceive,
) -> Option<u64> {
    let CongestionReceive::Rate(remote_receive_bps) = remote_receive else {
        return None;
    };
    let actual = if remote_receive_bps == 0 || remote_receive_bps > configured_send_bps {
        configured_send_bps
    } else {
        remote_receive_bps
    };
    (actual > 0).then_some(actual)
}

fn spawn_encode(mut source: ReadHalf<DuplexStream>, mut destination: quinn::SendStream) {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match source.read(&mut buffer).await {
                Ok(0) => {
                    let _ = destination.shutdown().await;
                    break;
                }
                Ok(length) => {
                    if destination.write_all(&buffer[..length]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn spawn_decode(mut source: quinn::RecvStream, mut destination: WriteHalf<DuplexStream>) {
    tokio::spawn(async move {
        if read_tcp_response(&mut source).await.is_err() {
            let _ = destination.shutdown().await;
            return;
        }
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match source.read(&mut buffer).await {
                Ok(Some(length)) => {
                    if destination.write_all(&buffer[..length]).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = destination.shutdown().await;
                    break;
                }
            }
        }
    });
}
