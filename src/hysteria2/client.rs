use std::{
    future::poll_fn,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use http::{Method, Request};
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, pki_types::CertificateDer};
use tokio::sync::Mutex;

use crate::congestion::{
    CongestionKind, configure_connection_brutal_with_options, connection_congestion_kind,
};
use crate::transport::AdaptiveWindowTask;
use crate::{Address, Error, Result};

use super::protocol::{
    CongestionReceive, HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, STATUS_AUTH_OK, URL_AUTHORITY,
    URL_PATH, padding, parse_congestion_receive, read_tcp_response, write_tcp_request,
};
use super::{
    ClientBandwidth, Hysteria2Stream,
    metrics::ConnectionMetricsTask,
    transport::{base_transport_config, bind_endpoint},
};

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
    _window_task: AdaptiveWindowTask,
    _metrics_task: Option<ConnectionMetricsTask>,
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
        let transport = base_transport_config();
        let mut client_config = ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));

        let bind_address = match options.server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint = bind_endpoint(bind_address, None)?;
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

    pub async fn connect(&self, destination: Address) -> Result<Hysteria2Stream> {
        let connection = self.connection().await?;
        let (mut send, mut recv) = connection.connection.open_bi().await?;
        write_tcp_request(&mut send, &destination).await?;
        read_tcp_response(&mut recv).await?;
        Ok(Hysteria2Stream::new(send, recv))
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

    #[cfg(test)]
    pub(crate) async fn connection_handle(&self) -> Result<quinn::Connection> {
        Ok(self.connection().await?.connection.clone())
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
    let send_rate = negotiated_send_rate(bandwidth.send_bps, remote_receive);
    if let Some(bytes_per_second) = send_rate
        && !configure_connection_brutal_with_options(
            &connection,
            bytes_per_second,
            bandwidth.disable_loss_compensation,
        )
    {
        connection.close(0u32.into(), b"congestion control failed");
        return Err(Error::CongestionControl);
    }
    let congestion = connection_congestion_kind(&connection).ok_or(Error::CongestionControl)?;
    let window_task = AdaptiveWindowTask::spawn(
        connection.clone(),
        send_rate.unwrap_or_default(),
        bandwidth.receive_bps,
        super::transport::SEND_WINDOW,
        u64::from(super::transport::CONNECTION_RECEIVE_WINDOW),
    );
    tracing::info!(
        remote = %connection.remote_address(),
        ?congestion,
        configured_send_bps = bandwidth.send_bps,
        configured_receive_bps = bandwidth.receive_bps,
        "Hysteria2 client congestion negotiated"
    );

    let h3_driver = tokio::spawn(async move {
        let _keep_sender_alive = send_request;
        let _ = poll_fn(|context| driver.poll_close(context)).await;
    });
    let metrics_task = bandwidth.brutal_debug.then(|| {
        ConnectionMetricsTask::spawn(
            connection.clone(),
            "client",
            connection.remote_address(),
            congestion,
        )
    });
    Ok(ClientConnection {
        connection,
        congestion,
        h3_driver,
        _window_task: window_task,
        _metrics_task: metrics_task,
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
