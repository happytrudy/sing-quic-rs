//! ShadowQuic's QUIC stream protocol.
//!
//! ShadowQuic authenticates the TLS ClientHello with JLS and then carries
//! SOCKS5-addressed TCP and UDP requests over QUIC streams and datagrams. The
//! JLS implementation lives in the local rustls fork; this module only consumes
//! the authentication result exposed by the QUIC TLS adapter.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use quinn::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt, crypto::rustls::QuicClientConfig,
};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, Notify, mpsc, watch},
};

use crate::congestion::SwitchableCongestionFactory;
use crate::congestion::{
    CongestionKind, configure_connection_bbr, configure_connection_brutal_with_options,
    connection_congestion_kind,
};
use crate::hysteria2::transport::bind_endpoint;
use crate::transport::AdaptiveWindowTask;
use crate::{Address, Error, Result};

const SQ_CONNECT: u8 = 0x01;
const SQ_ASSOCIATE_OVER_DATAGRAM: u8 = 0x03;
const SQ_ASSOCIATE_OVER_STREAM: u8 = 0x04;
const SQ_AUTHENTICATE: u8 = 0x05;
const SQ_EXTENSION: u8 = 0xff;
const SQ_EXTENSION_CONNECTION: u64 = 0x01;
const SQ_EXTENSION_GET_STATS: u8 = 0x00;
const SQ_IPV4: u8 = 0x01;
const SQ_DOMAIN: u8 = 0x03;
const SQ_IPV6: u8 = 0x04;
const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;
const MAX_CONCURRENT_STREAMS: u32 = 1_000;
const DATAGRAM_BUFFER_SIZE: usize = 2_500_000;
const MAX_PENDING_UDP_DATAGRAMS: usize = 1_024;
const SHADOWQUIC_INITIAL_MTU: u16 = 1_300;
const SHADOWQUIC_MIN_MTU: u16 = 1_290;
const SHADOWQUIC_SEND_WINDOW: u64 = 40_000_000;
const SUNNYQUIC_SEND_WINDOW: u64 = 40_000_000;
const STREAM_ERROR_CODE: u32 = 0x100;
const SUNNY_AUTH_ERROR_CODE: u32 = 263;
const SUNNY_AUTH_TIMEOUT: Duration = Duration::from_millis(3_200);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CongestionConfig {
    #[default]
    Bbr,
    Brutal {
        bytes_per_second: u64,
        disable_loss_compensation: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportOptions {
    pub initial_packet_size: u16,
    pub max_concurrent_streams: u64,
    pub connection_receive_window: u64,
    pub stream_receive_window: u64,
    pub keep_alive_period: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub disable_path_mtu_discovery: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            initial_packet_size: SHADOWQUIC_INITIAL_MTU,
            max_concurrent_streams: u64::from(MAX_CONCURRENT_STREAMS),
            connection_receive_window: 20 * 1024 * 1024,
            stream_receive_window: 5_000_000,
            keep_alive_period: None,
            idle_timeout: Some(Duration::from_secs(30)),
            disable_path_mtu_discovery: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: SocketAddr,
    pub server_name: String,
    pub username: String,
    pub password: String,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
    pub transport: TransportOptions,
}

#[derive(Clone, Debug)]
pub(crate) struct SunnyClientOptions {
    pub server: SocketAddr,
    pub server_name: String,
    pub credential: [u8; 64],
    pub ca_certificates: Vec<Vec<u8>>,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
    pub transport: crate::sunnyquic::TransportOptions,
}

#[derive(Clone, Copy, Debug)]
enum ClientAuthentication {
    Jls,
    Sunny { credential: [u8; 64] },
}

struct ClientConnection {
    connection: quinn::Connection,
    incoming_udp: Arc<IncomingUdpRegistry>,
    udp_ids: Arc<StdMutex<UdpIdAllocator>>,
    next_udp_owner: Arc<AtomicU64>,
}

#[derive(Debug)]
pub struct ShadowQuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl ShadowQuicStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for ShadowQuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for ShadowQuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), context)
    }
}

#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    server: SocketAddr,
    server_name: String,
    congestion: CongestionConfig,
    authentication: ClientAuthentication,
    zero_rtt: bool,
    connection: Arc<Mutex<Option<Arc<ClientConnection>>>>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Self> {
        if options.server_name.is_empty() {
            return Err(Error::InvalidServerName(options.server_name));
        }
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let mut tls = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = options.zero_rtt;
        tls.jls_config = rustls::jls::JlsClientConfig::new(&options.password, &options.username);
        let crypto =
            QuicClientConfig::try_from(tls).map_err(|error| Error::QuicTls(error.to_string()))?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(shadowquic_client_transport_config(
            options.transport,
        )?));
        let bind = match options.server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let endpoint = bind_endpoint(bind, None)?;
        endpoint.set_default_client_config(config);
        Ok(Self::from_endpoint(
            endpoint,
            options.server,
            options.server_name,
            options.congestion,
            ClientAuthentication::Jls,
            options.zero_rtt,
        ))
    }

    pub(crate) fn new_sunny(options: SunnyClientOptions) -> Result<Self> {
        if options.server_name.is_empty() {
            return Err(Error::InvalidServerName(options.server_name));
        }
        let mut roots = if options.ca_certificates.is_empty() {
            RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.into(),
            }
        } else {
            RootCertStore::empty()
        };
        for certificate in &options.ca_certificates {
            roots.add(CertificateDer::from(certificate.clone()))?;
        }
        let mut tls = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = options.zero_rtt;
        let crypto =
            QuicClientConfig::try_from(tls).map_err(|error| Error::QuicTls(error.to_string()))?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(sunnyquic_client_transport_config(
            options.transport,
        )?));
        let bind = match options.server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let endpoint = bind_endpoint(bind, None)?;
        endpoint.set_default_client_config(config);
        Ok(Self::from_endpoint(
            endpoint,
            options.server,
            options.server_name,
            options.congestion,
            ClientAuthentication::Sunny {
                credential: options.credential,
            },
            options.zero_rtt,
        ))
    }

    fn from_endpoint(
        endpoint: Endpoint,
        server: SocketAddr,
        server_name: String,
        congestion: CongestionConfig,
        authentication: ClientAuthentication,
        zero_rtt: bool,
    ) -> Self {
        Self {
            endpoint,
            server,
            server_name,
            congestion,
            authentication,
            zero_rtt,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    async fn connection_state(&self) -> Result<Arc<ClientConnection>> {
        let mut cached = self.connection.lock().await;
        if let Some(state) = cached.as_ref()
            && state.connection.close_reason().is_none()
        {
            return Ok(Arc::clone(state));
        }
        let connecting = self.endpoint.connect(self.server, &self.server_name)?;
        let (connection, attempted_0rtt) = if self.zero_rtt {
            match connecting.into_0rtt() {
                Ok(connection) => (connection, true),
                Err(connecting) => (connecting.await?, false),
            }
        } else {
            (connecting.await?, false)
        };
        apply_congestion(&connection, self.congestion)?;
        if attempted_0rtt {
            let validation_connection = connection.clone();
            let authentication = self.authentication;
            tokio::spawn(async move {
                let authenticated = validation_connection.authenticated().await.is_ok();
                tracing::debug!(authenticated, "SQuic 0-RTT handshake completed");
                if matches!(authentication, ClientAuthentication::Jls)
                    && (!authenticated || validate_jls_connection(&validation_connection).is_err())
                {
                    validation_connection.close(0u32.into(), b"JLS authentication failed");
                }
            });
        } else if matches!(self.authentication, ClientAuthentication::Jls) {
            validate_jls_connection(&connection)?;
        }
        match self.authentication {
            ClientAuthentication::Jls => {}
            ClientAuthentication::Sunny { credential } => {
                let (mut send, _) = connection.open_bi().await?;
                send.write_all(&[SQ_AUTHENTICATE]).await?;
                send.write_all(&credential).await?;
                send.finish()
                    .map_err(|error| Error::Protocol(error.to_string()))?;
            }
        }
        let state = Arc::new(ClientConnection {
            connection,
            incoming_udp: Arc::new(IncomingUdpRegistry::default()),
            udp_ids: Arc::new(StdMutex::new(UdpIdAllocator::default())),
            next_udp_owner: Arc::new(AtomicU64::new(1)),
        });
        spawn_client_udp_receiver(Arc::clone(&state));
        *cached = Some(Arc::clone(&state));
        Ok(state)
    }

    #[cfg(test)]
    async fn connection(&self) -> Result<quinn::Connection> {
        let connection = self
            .endpoint
            .connect(self.server, &self.server_name)?
            .await?;
        apply_congestion(&connection, self.congestion)?;
        if matches!(self.authentication, ClientAuthentication::Jls) {
            validate_jls_connection(&connection)?;
        }
        Ok(connection)
    }

    pub async fn connect(&self, destination: Address) -> Result<ShadowQuicStream> {
        let state = self.connection_state().await?;
        let (mut send, recv) = state.connection.open_bi().await?;
        let request = encode_connect(&destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        Ok(ShadowQuicStream::new(send, recv))
    }

    pub async fn associate(
        &self,
        destination: Address,
        over_stream: bool,
    ) -> Result<Arc<ShadowQuicPacketConnection>> {
        let state = self.connection_state().await?;
        let (mut send, recv) = state.connection.open_bi().await?;
        send.write_all(&[if over_stream {
            SQ_ASSOCIATE_OVER_STREAM
        } else {
            SQ_ASSOCIATE_OVER_DATAGRAM
        }])
        .await?;
        send.write_all(&encode_address(&destination)?).await?;
        send.flush().await?;
        let (packet_sender, packet_receiver) = mpsc::channel(256);
        let incoming_udp = Arc::clone(&state.incoming_udp);
        let owner = state.next_udp_owner.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(error) =
                handle_udp_control_stream(recv, incoming_udp, packet_sender, owner).await
            {
                tracing::debug!(%error, "SQuic UDP control stream closed");
            }
        });
        Ok(Arc::new(ShadowQuicPacketConnection {
            connection: state.connection.clone(),
            mode: if over_stream {
                UdpMode::Stream
            } else {
                UdpMode::Datagram
            },
            udp_ids: Arc::clone(&state.udp_ids),
            allocated_ids: StdMutex::new(Vec::new()),
            incoming: Mutex::new(packet_receiver),
            outgoing: Mutex::new(OutgoingUdpState {
                control: send,
                contexts: HashMap::new(),
            }),
        }))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn congestion_kind(&self) -> Option<CongestionKind> {
        let connection = self.connection.lock().await;
        connection
            .as_ref()
            .and_then(|state| connection_congestion_kind(&state.connection))
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"client closed");
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub listen: SocketAddr,
    pub users: Vec<User>,
    pub server_name: Option<String>,
    pub jls_upstream_addr: Option<String>,
    pub jls_rate_limit: u64,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
    pub transport: TransportOptions,
}

#[derive(Clone, Debug)]
pub(crate) struct SunnyServerOptions {
    pub listen: SocketAddr,
    pub users: Vec<User>,
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
    pub transport: crate::sunnyquic::TransportOptions,
}

#[derive(Clone)]
enum ServerAuthentication {
    Jls,
    Sunny(Arc<HashMap<[u8; 64], String>>),
}

#[derive(Debug)]
pub struct AcceptedStream {
    pub stream: ShadowQuicStream,
    pub destination: Address,
    pub user: String,
    pub source: SocketAddr,
}

#[derive(Debug)]
pub struct ShadowQuicPacket {
    pub data: Vec<u8>,
    pub destination: Address,
}

#[derive(Debug)]
pub struct AcceptedPacket {
    pub connection: Arc<ShadowQuicPacketConnection>,
    pub destination: Address,
    pub user: String,
    pub source: SocketAddr,
}

#[derive(Debug)]
pub enum Accepted {
    Stream(AcceptedStream),
    Packet(AcceptedPacket),
}

pub struct Server {
    endpoint: Endpoint,
    incoming: Mutex<mpsc::Receiver<Accepted>>,
    accept_task: tokio::task::JoinHandle<()>,
    congestion: Arc<RwLock<CongestionConfig>>,
    authentication: Arc<RwLock<ServerAuthentication>>,
    receive_window: Arc<RwLock<u64>>,
    zero_rtt: Arc<RwLock<bool>>,
}

impl Server {
    pub fn bind(options: ServerOptions) -> Result<Self> {
        let server_config = build_server_config(&options)?;
        Self::bind_inner(
            options.listen,
            server_config,
            options.congestion,
            options.transport.connection_receive_window,
            options.zero_rtt,
            ServerAuthentication::Jls,
            "ShadowQuic",
        )
    }

    pub(crate) fn bind_sunny(options: SunnyServerOptions) -> Result<Self> {
        let server_config = build_sunny_server_config(
            options.certificate_chain,
            options.private_key,
            options.zero_rtt,
            options.transport,
        )?;
        let authentication = ServerAuthentication::Sunny(Arc::new(sunny_users(&options.users)));
        Self::bind_inner(
            options.listen,
            server_config,
            options.congestion,
            options.transport.connection_receive_window,
            options.zero_rtt,
            authentication,
            "SunnyQUIC",
        )
    }

    fn bind_inner(
        listen: SocketAddr,
        server_config: ServerConfig,
        initial_congestion: CongestionConfig,
        initial_receive_window: u64,
        initial_zero_rtt: bool,
        initial_authentication: ServerAuthentication,
        protocol: &'static str,
    ) -> Result<Self> {
        let endpoint = bind_endpoint(listen, Some(server_config))?;
        let (sender, receiver) = mpsc::channel(256);
        let accept_endpoint = endpoint.clone();
        let congestion = Arc::new(RwLock::new(initial_congestion));
        let accept_congestion = Arc::clone(&congestion);
        let authentication = Arc::new(RwLock::new(initial_authentication));
        let accept_authentication = Arc::clone(&authentication);
        let receive_window = Arc::new(RwLock::new(initial_receive_window));
        let accept_receive_window = Arc::clone(&receive_window);
        let zero_rtt = Arc::new(RwLock::new(initial_zero_rtt));
        let accept_zero_rtt = Arc::clone(&zero_rtt);
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let sender = sender.clone();
                let congestion = *accept_congestion.read().expect("SQuic congestion lock");
                let authentication = accept_authentication
                    .read()
                    .expect("SQuic authentication lock")
                    .clone();
                let receive_window = *accept_receive_window
                    .read()
                    .expect("SQuic receive window lock");
                let zero_rtt = *accept_zero_rtt.read().expect("SQuic 0-RTT lock");
                tokio::spawn(async move {
                    let connection = async {
                        let connecting = incoming.accept()?;
                        if zero_rtt {
                            match connecting.into_0rtt() {
                                Ok(connection) => Ok(connection),
                                Err(connecting) => connecting.await,
                            }
                        } else {
                            connecting.await
                        }
                    }
                    .await;
                    match connection {
                        Ok(connection) => {
                            if let Err(error) = apply_congestion(&connection, congestion) {
                                connection.close(0u32.into(), b"congestion control failed");
                                tracing::debug!(%error, %protocol, "SQuic congestion setup failed");
                                return;
                            }
                            if let Err(error) = serve_connection(
                                connection,
                                sender,
                                authentication,
                                protocol,
                                receive_window,
                            )
                            .await
                            {
                                tracing::debug!(%error, %protocol, "SQuic connection closed");
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, %protocol, "SQuic QUIC handshake failed")
                        }
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            incoming: Mutex::new(receiver),
            accept_task,
            congestion,
            authentication,
            receive_window,
            zero_rtt,
        })
    }

    pub async fn accept(&self) -> Result<Accepted> {
        self.incoming.lock().await.recv().await.ok_or(Error::Closed)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn update_config(&self, options: ServerOptions) -> Result<()> {
        *self.congestion.write().expect("ShadowQuic congestion lock") = options.congestion;
        *self
            .receive_window
            .write()
            .expect("ShadowQuic receive window lock") = options.transport.connection_receive_window;
        *self.zero_rtt.write().expect("ShadowQuic 0-RTT lock") = options.zero_rtt;
        self.endpoint
            .set_server_config(Some(build_server_config(&options)?));
        Ok(())
    }

    pub(crate) fn update_sunny_config(&self, options: SunnyServerOptions) -> Result<()> {
        let server_config = build_sunny_server_config(
            options.certificate_chain,
            options.private_key,
            options.zero_rtt,
            options.transport,
        )?;
        *self.congestion.write().expect("SQuic congestion lock") = options.congestion;
        *self
            .receive_window
            .write()
            .expect("SQuic receive window lock") = options.transport.connection_receive_window;
        *self.zero_rtt.write().expect("SQuic 0-RTT lock") = options.zero_rtt;
        *self
            .authentication
            .write()
            .expect("SQuic authentication lock") =
            ServerAuthentication::Sunny(Arc::new(sunny_users(&options.users)));
        self.endpoint.set_server_config(Some(server_config));
        Ok(())
    }

    pub async fn close(&self) {
        self.endpoint.close(0u32.into(), b"server closed");
        self.endpoint.wait_idle().await;
        self.accept_task.abort();
    }
}

fn apply_congestion(connection: &quinn::Connection, congestion: CongestionConfig) -> Result<()> {
    let configured = match congestion {
        CongestionConfig::Bbr => configure_connection_bbr(connection),
        CongestionConfig::Brutal {
            bytes_per_second,
            disable_loss_compensation,
        } => configure_connection_brutal_with_options(
            connection,
            bytes_per_second,
            disable_loss_compensation,
        ),
    };
    if configured {
        Ok(())
    } else {
        Err(Error::CongestionControl)
    }
}

fn validate_jls_connection(connection: &quinn::Connection) -> Result<()> {
    let authenticated = connection
        .handshake_data()
        .and_then(|data| {
            data.downcast::<quinn_proto::crypto::rustls::HandshakeData>()
                .ok()
        })
        .is_some_and(|data| data.jls_authenticated == Some(true));
    if authenticated {
        Ok(())
    } else {
        connection.close(0u32.into(), b"JLS authentication failed");
        Err(Error::JlsAuthenticationFailed)
    }
}

async fn wait_for_sunny_auth(
    authentication: &ServerAuthentication,
    mut receiver: watch::Receiver<Option<std::result::Result<String, String>>>,
) -> Result<String> {
    if matches!(authentication, ServerAuthentication::Jls) {
        return Ok(String::new());
    }
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result.map_err(Error::Protocol);
        }
        tokio::time::timeout(SUNNY_AUTH_TIMEOUT, receiver.changed())
            .await
            .map_err(|_| Error::Protocol("SunnyQUIC authentication timed out".into()))?
            .map_err(|_| Error::Closed)?;
    }
}

fn spawn_client_udp_receiver(state: Arc<ClientConnection>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                datagram = state.connection.read_datagram() => match datagram {
                    Ok(datagram) => {
                        if let Err(error) = handle_incoming_udp_datagram(
                            datagram,
                            Arc::clone(&state.incoming_udp),
                        ).await {
                            tracing::debug!(%error, "SQuic client UDP datagram dropped");
                        }
                    }
                    Err(error) => break tracing::debug!(%error, "SQuic client datagram receiver stopped"),
                },
                stream = state.connection.accept_uni() => match stream {
                    Ok(stream) => {
                        let incoming_udp = Arc::clone(&state.incoming_udp);
                        tokio::spawn(async move {
                            if let Err(error) = handle_incoming_udp_stream(stream, incoming_udp).await {
                                tracing::debug!(%error, "SQuic client UDP stream closed");
                            }
                        });
                    }
                    Err(error) => break tracing::debug!(%error, "SQuic client stream receiver stopped"),
                },
            }
        }
        state.incoming_udp.close();
    });
}

fn shadowquic_client_transport_config(options: TransportOptions) -> Result<TransportConfig> {
    protocol_transport_config(
        options.initial_packet_size,
        options.max_concurrent_streams,
        options.connection_receive_window,
        options.stream_receive_window,
        options.keep_alive_period,
        options.idle_timeout,
        options.disable_path_mtu_discovery,
        SHADOWQUIC_SEND_WINDOW,
    )
}

fn shadowquic_server_transport_config(options: TransportOptions) -> Result<TransportConfig> {
    shadowquic_client_transport_config(options)
}

fn sunnyquic_client_transport_config(
    options: crate::sunnyquic::TransportOptions,
) -> Result<TransportConfig> {
    protocol_transport_config(
        options.initial_packet_size,
        options.max_concurrent_streams,
        options.connection_receive_window,
        options.stream_receive_window,
        options.keep_alive_period,
        options.idle_timeout,
        options.disable_path_mtu_discovery,
        SUNNYQUIC_SEND_WINDOW,
    )
}

fn sunnyquic_server_transport_config(
    options: crate::sunnyquic::TransportOptions,
) -> Result<TransportConfig> {
    sunnyquic_client_transport_config(options)
}

#[allow(clippy::too_many_arguments)]
fn protocol_transport_config(
    initial_packet_size: u16,
    max_concurrent_streams: u64,
    connection_receive_window: u64,
    stream_receive_window: u64,
    keep_alive_period: Option<Duration>,
    idle_timeout: Option<Duration>,
    disable_path_mtu_discovery: bool,
    send_window: u64,
) -> Result<TransportConfig> {
    if initial_packet_size < 1_200 {
        return Err(Error::Protocol(
            "SQuic initial_packet_size must be at least 1200".into(),
        ));
    }
    let max_concurrent_streams = VarInt::from_u64(max_concurrent_streams)
        .map_err(|_| Error::Protocol("SQuic max_concurrent_streams is too large".into()))?;
    let connection_receive_window = VarInt::from_u64(connection_receive_window)
        .map_err(|_| Error::Protocol("SQuic connection_receive_window is too large".into()))?;
    let stream_receive_window = VarInt::from_u64(stream_receive_window)
        .map_err(|_| Error::Protocol("SQuic stream_receive_window is too large".into()))?;
    let idle_timeout = idle_timeout
        .map(|duration| {
            duration
                .try_into()
                .map_err(|_| Error::Protocol("SQuic idle_timeout is too large".into()))
        })
        .transpose()?;
    let mut transport = TransportConfig::default();
    transport
        .congestion_controller_factory(Arc::new(SwitchableCongestionFactory))
        .max_concurrent_bidi_streams(max_concurrent_streams)
        .max_concurrent_uni_streams(max_concurrent_streams)
        .receive_window(connection_receive_window)
        .stream_receive_window(stream_receive_window)
        .send_window(send_window)
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_SIZE)
        .max_idle_timeout(idle_timeout)
        .keep_alive_interval(keep_alive_period)
        .min_mtu(initial_packet_size.min(SHADOWQUIC_MIN_MTU))
        .initial_mtu(initial_packet_size);
    if disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    Ok(transport)
}

fn build_server_config(options: &ServerOptions) -> Result<ServerConfig> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|error| Error::QuicTls(format!("generate ephemeral certificate: {error}")))?;
    let certificates = vec![CertificateDer::from(certificate.cert)];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut jls = rustls::jls::JlsServerConfig::default()
        .enable(true)
        .with_rate_limit(options.jls_rate_limit);
    if let Some(upstream_addr) = options.jls_upstream_addr.clone() {
        jls = jls.with_upstream_addr(upstream_addr);
    }
    if let Some(server_name) = options.server_name.clone() {
        jls = jls.with_server_name(server_name);
    }
    tls.max_early_data_size = if options.zero_rtt { u32::MAX } else { 0 };
    for user in &options.users {
        jls = jls.add_user(user.password.clone(), user.name.clone());
    }
    tls.jls_config = Arc::new(jls);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| Error::QuicTls(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(shadowquic_server_transport_config(
        options.transport,
    )?));
    Ok(config)
}

fn build_sunny_server_config(
    certificate_chain: Vec<Vec<u8>>,
    private_key: Vec<u8>,
    zero_rtt: bool,
    transport: crate::sunnyquic::TransportOptions,
) -> Result<ServerConfig> {
    let certificates = certificate_chain
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let private_key = detect_private_key(private_key)?;
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = if zero_rtt { u32::MAX } else { 0 };
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| Error::QuicTls(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(sunnyquic_server_transport_config(transport)?));
    Ok(config)
}

fn detect_private_key(key: Vec<u8>) -> Result<PrivateKeyDer<'static>> {
    let candidates = [
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())),
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key.clone())),
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key)),
    ];
    let mut last_error = None;
    for candidate in candidates {
        match rustls::crypto::ring::sign::any_supported_type(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(error) => last_error = Some(error),
        }
    }
    Err(Error::Tls(last_error.expect("private key candidates")))
}

fn sunny_users(users: &[User]) -> HashMap<[u8; 64], String> {
    users
        .iter()
        .map(|user| {
            (
                sunny_credential(&user.name, &user.password),
                user.name.clone(),
            )
        })
        .collect()
}

pub(crate) fn sunny_credential(username: &str, password: &str) -> [u8; 64] {
    let input = format!("{username}:{password}");
    let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
    let mut credential = [0u8; 64];
    credential[..digest.as_ref().len()].copy_from_slice(digest.as_ref());
    credential
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpMode {
    Datagram,
    Stream,
}

#[derive(Clone)]
struct IncomingUdpRoute {
    owner: u64,
    sender: mpsc::Sender<ShadowQuicPacket>,
    destination: Address,
}

#[derive(Default)]
struct IncomingUdpState {
    routes: HashMap<u16, IncomingUdpRoute>,
    pending: HashMap<u16, VecDeque<Bytes>>,
    pending_datagrams: usize,
    pending_bytes: usize,
}

#[derive(Default)]
struct IncomingUdpRegistry {
    state: Mutex<IncomingUdpState>,
    changed: Notify,
    closed: AtomicBool,
}

impl IncomingUdpRegistry {
    async fn register(
        &self,
        owner: u64,
        id: u16,
        destination: Address,
        sender: mpsc::Sender<ShadowQuicPacket>,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.routes.contains_key(&id) {
            return Err(Error::Protocol(format!(
                "duplicate SQuic UDP association id {id}"
            )));
        }
        let route = IncomingUdpRoute {
            owner,
            sender,
            destination,
        };
        state.routes.insert(id, route.clone());
        let pending = state.pending.remove(&id).unwrap_or_default();
        for payload in &pending {
            state.pending_datagrams -= 1;
            state.pending_bytes -= payload.len();
        }
        drop(state);
        for payload in pending {
            let _ = route.sender.try_send(ShadowQuicPacket {
                data: payload.to_vec(),
                destination: route.destination.clone(),
            });
        }
        self.changed.notify_waiters();
        Ok(())
    }

    async fn remove(&self, owner: u64, ids: &[u16]) {
        let mut state = self.state.lock().await;
        for id in ids {
            if state
                .routes
                .get(id)
                .is_some_and(|route| route.owner == owner)
            {
                state.routes.remove(id);
            }
        }
    }

    async fn wait(&self, id: u16) -> Result<IncomingUdpRoute> {
        loop {
            let changed = self.changed.notified();
            if let Some(route) = self.state.lock().await.routes.get(&id).cloned() {
                return Ok(route);
            }
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Closed);
            }
            changed.await;
        }
    }

    async fn route_datagram(&self, datagram: Bytes) -> Result<()> {
        if datagram.len() < 2 {
            return Err(Error::Protocol("truncated ShadowQuic UDP datagram".into()));
        }
        let id = u16::from_be_bytes([datagram[0], datagram[1]]);
        let payload = datagram.slice(2..);
        let route = {
            let mut state = self.state.lock().await;
            if let Some(route) = state.routes.get(&id).cloned() {
                Some(route)
            } else {
                if state.pending_datagrams >= MAX_PENDING_UDP_DATAGRAMS
                    || state.pending_bytes.saturating_add(payload.len()) > DATAGRAM_BUFFER_SIZE
                {
                    tracing::debug!(id, "SQuic pending UDP datagram buffer is full");
                    return Ok(());
                }
                state.pending_datagrams += 1;
                state.pending_bytes += payload.len();
                state
                    .pending
                    .entry(id)
                    .or_default()
                    .push_back(payload.clone());
                None
            }
        };
        if let Some(route) = route {
            let _ = route.sender.try_send(ShadowQuicPacket {
                data: payload.to_vec(),
                destination: route.destination,
            });
        }
        Ok(())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

#[derive(Debug, Default)]
struct UdpIdAllocator {
    next: u16,
    active: HashSet<u16>,
}

impl UdpIdAllocator {
    fn allocate(&mut self) -> Result<u16> {
        for _ in 0..=u16::MAX {
            let id = self.next;
            self.next = self.next.wrapping_add(1);
            if self.active.insert(id) {
                return Ok(id);
            }
        }
        Err(Error::Protocol(
            "SQuic UDP association id space is exhausted".into(),
        ))
    }

    fn release(&mut self, id: u16) {
        self.active.remove(&id);
    }
}

#[derive(Debug)]
enum OutgoingUdpContext {
    Datagram { id: u16 },
    Stream { stream: quinn::SendStream },
}

#[derive(Debug)]
struct OutgoingUdpState {
    control: quinn::SendStream,
    contexts: HashMap<Address, OutgoingUdpContext>,
}

#[derive(Debug)]
pub struct ShadowQuicPacketConnection {
    connection: quinn::Connection,
    mode: UdpMode,
    udp_ids: Arc<StdMutex<UdpIdAllocator>>,
    allocated_ids: StdMutex<Vec<u16>>,
    incoming: Mutex<mpsc::Receiver<ShadowQuicPacket>>,
    outgoing: Mutex<OutgoingUdpState>,
}

impl ShadowQuicPacketConnection {
    pub async fn send(&self, packet: ShadowQuicPacket) -> Result<()> {
        let mut outgoing = self.outgoing.lock().await;
        if !outgoing.contexts.contains_key(&packet.destination) {
            let address = encode_address(&packet.destination)?;
            let id = self.udp_ids.lock().expect("SQuic UDP id lock").allocate()?;
            let context = async {
                outgoing.control.write_all(&address).await?;
                outgoing.control.write_all(&id.to_be_bytes()).await?;
                outgoing.control.flush().await?;
                Ok::<_, Error>(match self.mode {
                    UdpMode::Datagram => OutgoingUdpContext::Datagram { id },
                    UdpMode::Stream => {
                        let mut stream = self.connection.open_uni().await?;
                        stream.write_all(&id.to_be_bytes()).await?;
                        OutgoingUdpContext::Stream { stream }
                    }
                })
            }
            .await;
            let context = match context {
                Ok(context) => context,
                Err(error) => {
                    self.udp_ids.lock().expect("SQuic UDP id lock").release(id);
                    return Err(error);
                }
            };
            self.allocated_ids
                .lock()
                .expect("SQuic allocated UDP id lock")
                .push(id);
            outgoing
                .contexts
                .insert(packet.destination.clone(), context);
        }

        match outgoing
            .contexts
            .get_mut(&packet.destination)
            .expect("ShadowQuic UDP context inserted")
        {
            OutgoingUdpContext::Datagram { id } => {
                let mut frame = Vec::with_capacity(packet.data.len() + 2);
                frame.extend_from_slice(&id.to_be_bytes());
                frame.extend_from_slice(&packet.data);
                self.connection
                    .send_datagram(Bytes::from(frame))
                    .map_err(|error| Error::Protocol(error.to_string()))?;
            }
            OutgoingUdpContext::Stream { stream } => {
                let length = u16::try_from(packet.data.len()).map_err(|_| {
                    Error::Protocol("ShadowQuic UDP packet exceeds 65535 bytes".into())
                })?;
                stream.write_all(&length.to_be_bytes()).await?;
                stream.write_all(&packet.data).await?;
                stream.flush().await?;
            }
        }
        Ok(())
    }

    pub async fn recv(&self) -> Result<ShadowQuicPacket> {
        self.incoming.lock().await.recv().await.ok_or(Error::Closed)
    }
}

impl Drop for ShadowQuicPacketConnection {
    fn drop(&mut self) {
        let ids = self
            .allocated_ids
            .get_mut()
            .expect("SQuic allocated UDP id lock");
        let allocator = self.udp_ids.lock().expect("SQuic UDP id lock");
        let mut allocator = allocator;
        for id in ids.drain(..) {
            allocator.release(id);
        }
    }
}

async fn serve_connection(
    connection: quinn::Connection,
    sender: mpsc::Sender<Accepted>,
    authentication: ServerAuthentication,
    protocol: &'static str,
    receive_window: u64,
) -> Result<()> {
    let source = connection.remote_address();
    let user = match &authentication {
        ServerAuthentication::Jls => authenticated_jls_user(&connection).await?,
        ServerAuthentication::Sunny(_) => String::new(),
    };
    let congestion = connection_congestion_kind(&connection).ok_or(Error::CongestionControl)?;
    let send_rate = match congestion {
        CongestionKind::Brutal { bytes_per_second } => bytes_per_second,
        CongestionKind::Bbr => 0,
    };
    let path = connection.stats().path;
    tracing::info!(
        %source,
        ?congestion,
        configured_send_bps = send_rate,
        rtt_ms = path.rtt.as_secs_f64() * 1_000.0,
        mtu = path.current_mtu,
        "SQuic server transport configured"
    );
    let _window_task = AdaptiveWindowTask::spawn(
        connection.clone(),
        send_rate,
        0,
        SHADOWQUIC_SEND_WINDOW,
        receive_window,
    );
    let incoming_udp = Arc::new(IncomingUdpRegistry::default());
    let udp_ids = Arc::new(StdMutex::new(UdpIdAllocator::default()));
    let next_udp_owner = Arc::new(AtomicU64::new(1));
    let (auth_sender, mut auth_receiver) = watch::channel(None);
    let mut pending_auth_datagrams: VecDeque<Bytes> = VecDeque::new();
    let mut pending_auth_bytes = 0usize;

    let result = loop {
        tokio::select! {
            changed = auth_receiver.changed(), if matches!(authentication, ServerAuthentication::Sunny(_)) => {
                changed.map_err(|_| Error::Closed)?;
                let authentication_result = auth_receiver.borrow().clone();
                match authentication_result {
                    Some(Ok(_)) => {
                        while let Some(datagram) = pending_auth_datagrams.pop_front() {
                            pending_auth_bytes -= datagram.len();
                            if let Err(error) = handle_incoming_udp_datagram(
                                datagram,
                                Arc::clone(&incoming_udp),
                            )
                            .await
                            {
                                tracing::debug!(%error, %protocol, "SQuic pending UDP datagram dropped");
                            }
                        }
                    }
                    Some(Err(error)) => break Err(Error::Protocol(error)),
                    None => {}
                }
            }
            stream = connection.accept_bi() => match stream {
                Ok((send, recv)) => {
                    let connection = connection.clone();
                    let sender = sender.clone();
                    let user = user.clone();
                    let authentication = authentication.clone();
                    let auth_sender = auth_sender.clone();
                    let auth_receiver = auth_receiver.clone();
                    let incoming_udp = Arc::clone(&incoming_udp);
                    let udp_ids = Arc::clone(&udp_ids);
                    let next_udp_owner = Arc::clone(&next_udp_owner);
                    tokio::spawn(async move {
                        if let Err(error) = handle_bi_stream(
                            connection,
                            send,
                            recv,
                            sender,
                            source,
                            user,
                            authentication,
                            auth_sender,
                            auth_receiver,
                            incoming_udp,
                            udp_ids,
                            next_udp_owner,
                        ).await {
                            tracing::debug!(%error, %protocol, "SQuic bidirectional stream closed");
                        }
                    });
                }
                Err(error) => break Err(error.into()),
            },
            stream = connection.accept_uni() => match stream {
                Ok(recv) => {
                    let incoming_udp = Arc::clone(&incoming_udp);
                    let authentication = authentication.clone();
                    let auth_receiver = auth_receiver.clone();
                    tokio::spawn(async move {
                        let result = async {
                            wait_for_sunny_auth(&authentication, auth_receiver).await?;
                            handle_incoming_udp_stream(recv, incoming_udp).await
                        }
                        .await;
                        if let Err(error) = result {
                            tracing::debug!(%error, %protocol, "SQuic UDP unidirectional stream closed");
                        }
                    });
                }
                Err(error) => break Err(error.into()),
            },
            datagram = connection.read_datagram() => match datagram {
                Ok(datagram) => {
                    let authenticated = matches!(authentication, ServerAuthentication::Jls)
                        || matches!(&*auth_receiver.borrow(), Some(Ok(_)));
                    if !authenticated {
                        if pending_auth_datagrams.len() < MAX_PENDING_UDP_DATAGRAMS
                            && pending_auth_bytes.saturating_add(datagram.len()) <= DATAGRAM_BUFFER_SIZE
                        {
                            pending_auth_bytes += datagram.len();
                            pending_auth_datagrams.push_back(datagram);
                        } else {
                            tracing::debug!(%protocol, "SQuic pre-authentication UDP buffer is full");
                        }
                    } else if let Err(error) =
                        handle_incoming_udp_datagram(datagram, Arc::clone(&incoming_udp)).await
                    {
                        tracing::debug!(%error, %protocol, "SQuic UDP datagram dropped");
                    }
                }
                Err(error) => break Err(error.into()),
            },
        }
    };
    incoming_udp.close();
    result
}

async fn authenticated_jls_user(connection: &quinn::Connection) -> Result<String> {
    if connection.handshake_data().is_none() {
        connection.authenticated().await?;
    }
    let authenticated = connection
        .handshake_data()
        .and_then(|data| {
            data.downcast::<quinn_proto::crypto::rustls::HandshakeData>()
                .ok()
        })
        .filter(|data| data.jls_authenticated == Some(true));
    if let Some(data) = authenticated {
        Ok(data.jls_user.unwrap_or_default())
    } else {
        connection.close(0u32.into(), b"JLS authentication failed");
        Err(Error::JlsAuthenticationFailed)
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_bi_stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sender: mpsc::Sender<Accepted>,
    source: SocketAddr,
    user: String,
    authentication: ServerAuthentication,
    auth_sender: watch::Sender<Option<std::result::Result<String, String>>>,
    auth_receiver: watch::Receiver<Option<std::result::Result<String, String>>>,
    incoming_udp: Arc<IncomingUdpRegistry>,
    udp_ids: Arc<StdMutex<UdpIdAllocator>>,
    next_udp_owner: Arc<AtomicU64>,
) -> Result<()> {
    let mut opcode = [0u8; 1];
    recv.read_exact(&mut opcode).await?;
    match opcode[0] {
        SQ_AUTHENTICATE => {
            let ServerAuthentication::Sunny(users) = authentication else {
                let code = VarInt::from_u32(STREAM_ERROR_CODE);
                let _ = send.reset(code);
                let _ = recv.stop(code);
                return Ok(());
            };
            let mut credential = [0u8; 64];
            recv.read_exact(&mut credential).await?;
            match users.get(&credential) {
                Some(username) => {
                    let _ = auth_sender.send(Some(Ok(username.clone())));
                }
                None => {
                    let _ = auth_sender.send(Some(Err("invalid SunnyQUIC credentials".into())));
                    connection.close(
                        VarInt::from_u32(SUNNY_AUTH_ERROR_CODE),
                        b"authentication failed",
                    );
                    return Err(Error::Protocol("SunnyQUIC authentication failed".into()));
                }
            }
        }
        SQ_CONNECT => {
            let authenticated_user = wait_for_sunny_auth(&authentication, auth_receiver).await?;
            let destination = decode_address(&mut recv).await?;
            sender
                .send(Accepted::Stream(AcceptedStream {
                    stream: ShadowQuicStream::new(send, recv),
                    destination,
                    user: if authenticated_user.is_empty() {
                        user
                    } else {
                        authenticated_user
                    },
                    source,
                }))
                .await
                .map_err(|_| Error::Closed)?;
        }
        SQ_ASSOCIATE_OVER_DATAGRAM | SQ_ASSOCIATE_OVER_STREAM => {
            let authenticated_user = wait_for_sunny_auth(&authentication, auth_receiver).await?;
            let destination = decode_address(&mut recv).await?;
            let mode = if opcode[0] == SQ_ASSOCIATE_OVER_DATAGRAM {
                UdpMode::Datagram
            } else {
                UdpMode::Stream
            };
            let (packet_sender, packet_receiver) = mpsc::channel(256);
            let owner = next_udp_owner.fetch_add(1, Ordering::Relaxed);
            let packet_connection = Arc::new(ShadowQuicPacketConnection {
                connection,
                mode,
                udp_ids,
                allocated_ids: StdMutex::new(Vec::new()),
                incoming: Mutex::new(packet_receiver),
                outgoing: Mutex::new(OutgoingUdpState {
                    control: send,
                    contexts: HashMap::new(),
                }),
            });
            sender
                .send(Accepted::Packet(AcceptedPacket {
                    connection: packet_connection,
                    destination,
                    user: if authenticated_user.is_empty() {
                        user
                    } else {
                        authenticated_user
                    },
                    source,
                }))
                .await
                .map_err(|_| Error::Closed)?;
            handle_udp_control_stream(recv, incoming_udp, packet_sender, owner).await?;
        }
        SQ_EXTENSION => {
            wait_for_sunny_auth(&authentication, auth_receiver).await?;
            handle_extension(&connection, &mut send, &mut recv).await?
        }
        opcode => {
            tracing::debug!(opcode, "unsupported ShadowQuic stream request");
            let code = VarInt::from_u32(STREAM_ERROR_CODE);
            let _ = send.reset(code);
            let _ = recv.stop(code);
        }
    }
    Ok(())
}

async fn handle_extension(
    connection: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<()> {
    let mut extension = [0u8; 8];
    recv.read_exact(&mut extension).await?;
    let mut opcode = [0u8; 1];
    recv.read_exact(&mut opcode).await?;
    if u64::from_be_bytes(extension) != SQ_EXTENSION_CONNECTION
        || opcode[0] != SQ_EXTENSION_GET_STATS
    {
        let code = VarInt::from_u32(STREAM_ERROR_CODE);
        let _ = send.reset(code);
        let _ = recv.stop(code);
        return Ok(());
    }

    let stats = connection.stats().path;
    let mut response = Vec::with_capacity(31);
    response.push(0); // Result::Ok
    response.extend_from_slice(&26u32.to_be_bytes());
    response.extend_from_slice(&stats.lost_packets.to_be_bytes());
    response.extend_from_slice(&stats.sent_packets.to_be_bytes());
    response.extend_from_slice(&(stats.rtt.as_secs_f64() * 1_000.0).to_be_bytes());
    response.extend_from_slice(&stats.current_mtu.to_be_bytes());
    send.write_all(&response).await?;
    send.finish()
        .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(())
}

async fn handle_udp_control_stream(
    mut recv: quinn::RecvStream,
    incoming_udp: Arc<IncomingUdpRegistry>,
    sender: mpsc::Sender<ShadowQuicPacket>,
    owner: u64,
) -> Result<()> {
    let mut ids = Vec::new();
    let result = async {
        loop {
            let destination = decode_address(&mut recv).await?;
            let mut id = [0u8; 2];
            recv.read_exact(&mut id).await?;
            let id = u16::from_be_bytes(id);
            incoming_udp
                .register(owner, id, destination, sender.clone())
                .await?;
            ids.push(id);
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    }
    .await;
    incoming_udp.remove(owner, &ids).await;
    result
}

async fn handle_incoming_udp_datagram(
    datagram: Bytes,
    incoming_udp: Arc<IncomingUdpRegistry>,
) -> Result<()> {
    incoming_udp.route_datagram(datagram).await
}

async fn handle_incoming_udp_stream(
    mut recv: quinn::RecvStream,
    incoming_udp: Arc<IncomingUdpRegistry>,
) -> Result<()> {
    let mut id = [0u8; 2];
    recv.read_exact(&mut id).await?;
    let route = incoming_udp.wait(u16::from_be_bytes(id)).await?;
    loop {
        let mut length = [0u8; 2];
        recv.read_exact(&mut length).await?;
        let mut data = vec![0u8; u16::from_be_bytes(length) as usize];
        recv.read_exact(&mut data).await?;
        route
            .sender
            .send(ShadowQuicPacket {
                data,
                destination: route.destination.clone(),
            })
            .await
            .map_err(|_| Error::Closed)?;
    }
}

fn encode_connect(destination: &Address) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(destination.host().len() + 8);
    frame.push(SQ_CONNECT);
    frame.extend_from_slice(&encode_address(destination)?);
    Ok(frame)
}

fn encode_address(destination: &Address) -> Result<Vec<u8>> {
    let host = destination.host();
    let mut frame = Vec::with_capacity(host.len() + 7);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            frame.push(SQ_IPV4);
            frame.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            frame.push(SQ_IPV6);
            frame.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > MAX_DOMAIN_LENGTH || !host.is_ascii() {
                return Err(Error::InvalidAddress);
            }
            frame.push(SQ_DOMAIN);
            frame.push(host.len() as u8);
            frame.extend_from_slice(host.as_bytes());
        }
    }
    frame.extend_from_slice(&destination.port().to_be_bytes());
    Ok(frame)
}

async fn decode_address(recv: &mut quinn::RecvStream) -> Result<Address> {
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind).await?;
    let host = match kind[0] {
        SQ_IPV4 => {
            let mut bytes = [0u8; 4];
            recv.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        SQ_IPV6 => {
            let mut bytes = [0u8; 16];
            recv.read_exact(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        SQ_DOMAIN => {
            let mut length = [0u8; 1];
            recv.read_exact(&mut length).await?;
            let mut bytes = vec![0u8; length[0] as usize];
            recv.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| Error::InvalidAddress)?
        }
        _ => return Err(Error::Protocol("invalid ShadowQuic address type".into())),
    };
    let mut port = [0u8; 2];
    recv.read_exact(&mut port).await?;
    Address::new(host, u16::from_be_bytes(port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn shadowquic_address_frames_match_socks5_encoding() {
        let frame = encode_connect(&Address::new("example.com", 443).unwrap()).unwrap();
        assert_eq!(frame[0..4], [SQ_CONNECT, SQ_DOMAIN, 11, b'e']);
        assert_eq!(&frame[14..], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn jls_authenticated_tcp_stream_round_trip() {
        let server = Arc::new(
            Server::bind(ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
                server_name: Some("localhost".into()),
                jls_upstream_addr: None,
                jls_rate_limit: u64::MAX,
                congestion: CongestionConfig::Brutal {
                    bytes_per_second: 12_500_000,
                    disable_loss_compensation: false,
                },
                zero_rtt: true,
                transport: TransportOptions::default(),
            })
            .unwrap(),
        );
        let accept_server = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let Accepted::Stream(accepted) = accept_server.accept().await.unwrap() else {
                panic!("expected ShadowQuic TCP stream");
            };
            assert_eq!(accepted.user, "alice");
            let mut stream = accepted.stream;
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&request).await.unwrap();
            stream.flush().await.unwrap();
        });
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            username: "alice".into(),
            password: "secret".into(),
            congestion: CongestionConfig::Brutal {
                bytes_per_second: 12_500_000,
                disable_loss_compensation: false,
            },
            zero_rtt: true,
            transport: TransportOptions::default(),
        })
        .unwrap();
        let mut stream = client
            .connect(Address::new("example.com", 443).unwrap())
            .await
            .unwrap();
        assert_eq!(
            client.congestion_kind().await,
            Some(CongestionKind::Brutal {
                bytes_per_second: 12_500_000
            })
        );
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        task.await.unwrap();
        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn failed_jls_handshake_is_forwarded_to_upstream() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = Server::bind(ServerOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![User {
                name: "alice".into(),
                password: "secret".into(),
            }],
            server_name: Some("localhost".into()),
            jls_upstream_addr: Some(upstream.local_addr().unwrap().to_string()),
            jls_rate_limit: u64::MAX,
            congestion: CongestionConfig::Bbr,
            zero_rtt: true,
            transport: TransportOptions::default(),
        })
        .unwrap();

        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let mut tls = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicClientConfig::try_from(tls).unwrap();
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(
            shadowquic_client_transport_config(TransportOptions::default()).unwrap(),
        ));
        let endpoint = bind_endpoint("127.0.0.1:0".parse().unwrap(), None).unwrap();
        endpoint.set_default_client_config(config);
        let connecting = endpoint
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let connection_task = tokio::spawn(connecting);

        let mut datagram = vec![0; 2_048];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(3), upstream.recv_from(&mut datagram))
                .await
                .expect("failed JLS handshake was not forwarded")
                .unwrap();
        assert!(length >= 1_200);

        connection_task.abort();
        endpoint.close(0u32.into(), b"test complete");
        server.close().await;
    }

    #[test]
    fn udp_id_allocator_skips_live_ids_and_reuses_released_ids() {
        let mut allocator = UdpIdAllocator {
            next: u16::MAX,
            active: HashSet::new(),
        };
        assert_eq!(allocator.allocate().unwrap(), u16::MAX);
        assert_eq!(allocator.allocate().unwrap(), 0);
        allocator.release(u16::MAX);
        allocator.next = u16::MAX;
        assert_eq!(allocator.allocate().unwrap(), u16::MAX);
        assert!(allocator.active.contains(&0));
    }

    #[tokio::test]
    async fn pending_udp_datagrams_are_bounded() {
        let registry = IncomingUdpRegistry::default();
        for index in 0..(MAX_PENDING_UDP_DATAGRAMS + 128) {
            let mut frame = (index as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(b"payload");
            registry.route_datagram(Bytes::from(frame)).await.unwrap();
        }
        let state = registry.state.lock().await;
        assert_eq!(state.pending_datagrams, MAX_PENDING_UDP_DATAGRAMS);
        assert!(state.pending_bytes <= DATAGRAM_BUFFER_SIZE);
    }

    #[tokio::test]
    async fn stale_udp_owner_cannot_remove_replacement_route() {
        let registry = IncomingUdpRegistry::default();
        let destination = Address::new("1.1.1.1", 53).unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        registry.register(2, 7, destination, sender).await.unwrap();
        registry.remove(1, &[7]).await;
        assert!(registry.state.lock().await.routes.contains_key(&7));
    }

    #[tokio::test]
    async fn jls_client_receives_udp_datagram_responses() {
        let server = test_server();
        let client = test_client(&server);
        let client_packets = client
            .associate(Address::new("0.0.0.0", 0).unwrap(), false)
            .await
            .unwrap();
        let Accepted::Packet(accepted) = server.accept().await.unwrap() else {
            panic!("expected ShadowQuic UDP association");
        };
        let destination = Address::new("1.1.1.1", 53).unwrap();
        client_packets
            .send(ShadowQuicPacket {
                data: b"query".to_vec(),
                destination: destination.clone(),
            })
            .await
            .unwrap();
        let query = accepted.connection.recv().await.unwrap();
        assert_eq!(query.destination, destination);
        accepted
            .connection
            .send(ShadowQuicPacket {
                data: b"reply".to_vec(),
                destination: Address::new("8.8.8.8", 53).unwrap(),
            })
            .await
            .unwrap();
        let reply = client_packets.recv().await.unwrap();
        assert_eq!(reply.data, b"reply");

        client.close();
        server.close().await;
    }

    fn test_server() -> Arc<Server> {
        Arc::new(
            Server::bind(ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
                server_name: Some("localhost".into()),
                jls_upstream_addr: None,
                jls_rate_limit: u64::MAX,
                congestion: CongestionConfig::Bbr,
                zero_rtt: true,
                transport: TransportOptions::default(),
            })
            .unwrap(),
        )
    }

    fn test_client(server: &Server) -> Client {
        Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            username: "alice".into(),
            password: "secret".into(),
            congestion: CongestionConfig::Bbr,
            zero_rtt: true,
            transport: TransportOptions::default(),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn official_stats_extension_keeps_connection_alive() {
        let server = test_server();
        let client = test_client(&server);
        let connection = client.connection().await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&[SQ_EXTENSION]).await.unwrap();
        send.write_all(&SQ_EXTENSION_CONNECTION.to_be_bytes())
            .await
            .unwrap();
        send.write_all(&[SQ_EXTENSION_GET_STATS]).await.unwrap();
        send.finish().unwrap();

        let mut status = [0u8; 1];
        recv.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0]);
        let mut length = [0u8; 4];
        recv.read_exact(&mut length).await.unwrap();
        assert_eq!(u32::from_be_bytes(length), 26);
        let mut stats = [0u8; 26];
        recv.read_exact(&mut stats).await.unwrap();
        assert!(u16::from_be_bytes([stats[24], stats[25]]) >= 1_200);

        let accept_server = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let Accepted::Stream(mut accepted) = accept_server.accept().await.unwrap() else {
                panic!("expected ShadowQuic TCP stream");
            };
            let mut request = [0u8; 4];
            accepted.stream.read_exact(&mut request).await.unwrap();
            accepted.stream.write_all(&request).await.unwrap();
        });
        let mut stream = client
            .connect(Address::new("example.com", 443).unwrap())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        task.await.unwrap();
        client.close();
        server.close().await;
    }

    async fn official_udp_round_trip(mode: UdpMode) {
        let server = test_server();
        let client = test_client(&server);
        let connection = client.connection().await.unwrap();
        let (mut control_send, mut control_recv) = connection.open_bi().await.unwrap();
        let opcode = match mode {
            UdpMode::Datagram => SQ_ASSOCIATE_OVER_DATAGRAM,
            UdpMode::Stream => SQ_ASSOCIATE_OVER_STREAM,
        };
        control_send.write_all(&[opcode]).await.unwrap();
        control_send
            .write_all(&encode_address(&Address::new("0.0.0.0", 0).unwrap()).unwrap())
            .await
            .unwrap();
        control_send.flush().await.unwrap();

        let Accepted::Packet(accepted) = server.accept().await.unwrap() else {
            panic!("expected ShadowQuic UDP association");
        };
        assert_eq!(accepted.user, "alice");
        let destination = Address::new("1.1.1.1", 53).unwrap();
        let client_id = 7u16;
        control_send
            .write_all(&encode_address(&destination).unwrap())
            .await
            .unwrap();
        control_send
            .write_all(&client_id.to_be_bytes())
            .await
            .unwrap();
        control_send.flush().await.unwrap();
        match mode {
            UdpMode::Datagram => {
                let mut datagram = client_id.to_be_bytes().to_vec();
                datagram.extend_from_slice(b"query");
                connection.send_datagram(Bytes::from(datagram)).unwrap();
            }
            UdpMode::Stream => {
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(&client_id.to_be_bytes()).await.unwrap();
                stream.write_all(&5u16.to_be_bytes()).await.unwrap();
                stream.write_all(b"query").await.unwrap();
                stream.finish().unwrap();
            }
        }

        let packet = accepted.connection.recv().await.unwrap();
        assert_eq!(packet.destination, destination);
        assert_eq!(packet.data, b"query");
        let response_source = Address::new("8.8.8.8", 53).unwrap();
        accepted
            .connection
            .send(ShadowQuicPacket {
                data: b"reply".to_vec(),
                destination: response_source.clone(),
            })
            .await
            .unwrap();

        assert_eq!(
            decode_address(&mut control_recv).await.unwrap(),
            response_source
        );
        let mut server_id = [0u8; 2];
        control_recv.read_exact(&mut server_id).await.unwrap();
        let server_id = u16::from_be_bytes(server_id);
        match mode {
            UdpMode::Datagram => {
                let datagram = connection.read_datagram().await.unwrap();
                assert_eq!(&datagram[..2], &server_id.to_be_bytes());
                assert_eq!(&datagram[2..], b"reply");
            }
            UdpMode::Stream => {
                let mut stream = connection.accept_uni().await.unwrap();
                let mut id = [0u8; 2];
                stream.read_exact(&mut id).await.unwrap();
                assert_eq!(u16::from_be_bytes(id), server_id);
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                assert_eq!(u16::from_be_bytes(length), 5);
                let mut payload = [0u8; 5];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"reply");
            }
        }

        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn official_udp_over_datagram_round_trip() {
        official_udp_round_trip(UdpMode::Datagram).await;
    }

    #[tokio::test]
    async fn official_udp_over_stream_round_trip() {
        official_udp_round_trip(UdpMode::Stream).await;
    }
}
