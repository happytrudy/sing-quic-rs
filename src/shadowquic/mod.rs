//! ShadowQuic's QUIC stream protocol.
//!
//! ShadowQuic authenticates the TLS ClientHello with JLS and then carries
//! SOCKS5-addressed TCP and UDP requests over QUIC streams and datagrams. The
//! JLS implementation lives in the local rustls fork; this module only consumes
//! the authentication result exposed by the QUIC TLS adapter.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use quinn::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt, crypto::rustls::QuicClientConfig,
};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, Notify, mpsc},
};

use crate::congestion::{
    CongestionKind, configure_connection_bbr, configure_connection_brutal_with_options,
    connection_congestion_kind,
};
use crate::hysteria2::transport::{base_transport_config, bind_endpoint};
use crate::transport::AdaptiveWindowTask;
use crate::{Address, Error, Result};

const SQ_CONNECT: u8 = 0x01;
const SQ_ASSOCIATE_OVER_DATAGRAM: u8 = 0x03;
const SQ_ASSOCIATE_OVER_STREAM: u8 = 0x04;
const SQ_EXTENSION: u8 = 0xff;
const SQ_EXTENSION_CONNECTION: u64 = 0x01;
const SQ_EXTENSION_GET_STATS: u8 = 0x00;
const SQ_IPV4: u8 = 0x01;
const SQ_DOMAIN: u8 = 0x03;
const SQ_IPV6: u8 = 0x04;
const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;
const MAX_CONCURRENT_STREAMS: u32 = 1_000;
const DATAGRAM_BUFFER_SIZE: usize = 2_500_000;
const SHADOWQUIC_INITIAL_MTU: u16 = 1_300;
const SHADOWQUIC_MIN_MTU: u16 = 1_290;
const STREAM_ERROR_CODE: u32 = 0x100;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CongestionConfig {
    #[default]
    Bbr,
    Brutal {
        bytes_per_second: u64,
        disable_loss_compensation: bool,
    },
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: SocketAddr,
    pub server_name: String,
    pub username: String,
    pub password: String,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
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

#[derive(Clone, Debug)]
pub struct Client {
    endpoint: Endpoint,
    options: ClientOptions,
    connection: Arc<Mutex<Option<quinn::Connection>>>,
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
        config.transport_config(Arc::new(shadowquic_transport_config()));
        let bind = match options.server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint = bind_endpoint(bind, None)?;
        endpoint.set_default_client_config(config);
        Ok(Self {
            endpoint,
            options,
            connection: Arc::new(Mutex::new(None)),
        })
    }

    async fn connection(&self) -> Result<quinn::Connection> {
        let mut cached = self.connection.lock().await;
        if let Some(connection) = cached.as_ref()
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let connecting = self
            .endpoint
            .connect(self.options.server, &self.options.server_name)?;
        let connection = connecting.await?;
        apply_congestion(&connection, self.options.congestion)?;
        if let Some(data) = connection.handshake_data()
            && let Some(data) = data.downcast_ref::<quinn_proto::crypto::rustls::HandshakeData>()
            && data.jls_authenticated != Some(true)
        {
            connection.close(0u32.into(), b"JLS authentication failed");
            return Err(Error::JlsAuthenticationFailed);
        }
        *cached = Some(connection.clone());
        Ok(connection)
    }

    pub async fn connect(&self, destination: Address) -> Result<ShadowQuicStream> {
        let connection = self.connection().await?;
        let (mut send, recv) = connection.open_bi().await?;
        let request = encode_connect(&destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        Ok(ShadowQuicStream::new(send, recv))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn congestion_kind(&self) -> Option<CongestionKind> {
        let connection = self.connection.lock().await;
        connection.as_ref().and_then(connection_congestion_kind)
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
}

impl Server {
    pub fn bind(options: ServerOptions) -> Result<Self> {
        let server_config = build_server_config(&options)?;
        let endpoint = bind_endpoint(options.listen, Some(server_config))?;
        let (sender, receiver) = mpsc::channel(256);
        let accept_endpoint = endpoint.clone();
        let congestion = Arc::new(RwLock::new(options.congestion));
        let accept_congestion = Arc::clone(&congestion);
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let sender = sender.clone();
                let congestion = *accept_congestion
                    .read()
                    .expect("ShadowQuic congestion lock");
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            if let Err(error) = apply_congestion(&connection, congestion) {
                                connection.close(0u32.into(), b"congestion control failed");
                                tracing::debug!(%error, "ShadowQuic congestion setup failed");
                                return;
                            }
                            if let Err(error) = serve_connection(connection, sender).await {
                                tracing::debug!(%error, "ShadowQuic connection closed");
                            }
                        }
                        Err(error) => tracing::debug!(%error, "ShadowQuic QUIC handshake failed"),
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            incoming: Mutex::new(receiver),
            accept_task,
            congestion,
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
        self.endpoint
            .set_server_config(Some(build_server_config(&options)?));
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

fn shadowquic_transport_config() -> TransportConfig {
    let mut transport = base_transport_config(Default::default());
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_CONCURRENT_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(MAX_CONCURRENT_STREAMS))
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_SIZE)
        .min_mtu(SHADOWQUIC_MIN_MTU)
        .initial_mtu(SHADOWQUIC_INITIAL_MTU);
    transport
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
    config.transport_config(Arc::new(shadowquic_transport_config()));
    Ok(config)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpMode {
    Datagram,
    Stream,
}

#[derive(Clone)]
struct IncomingUdpRoute {
    sender: mpsc::Sender<ShadowQuicPacket>,
    destination: Address,
}

#[derive(Default)]
struct IncomingUdpRegistry {
    routes: Mutex<HashMap<u16, IncomingUdpRoute>>,
    changed: Notify,
    closed: AtomicBool,
}

impl IncomingUdpRegistry {
    async fn register(
        &self,
        id: u16,
        destination: Address,
        sender: mpsc::Sender<ShadowQuicPacket>,
    ) {
        self.routes.lock().await.insert(
            id,
            IncomingUdpRoute {
                sender,
                destination,
            },
        );
        self.changed.notify_waiters();
    }

    async fn remove(&self, ids: &[u16]) {
        let mut routes = self.routes.lock().await;
        for id in ids {
            routes.remove(id);
        }
    }

    async fn wait(&self, id: u16) -> Result<IncomingUdpRoute> {
        loop {
            let changed = self.changed.notified();
            if let Some(route) = self.routes.lock().await.get(&id).cloned() {
                return Ok(route);
            }
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Closed);
            }
            changed.await;
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
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
    next_id: Arc<AtomicU16>,
    incoming: Mutex<mpsc::Receiver<ShadowQuicPacket>>,
    outgoing: Mutex<OutgoingUdpState>,
}

impl ShadowQuicPacketConnection {
    pub async fn send(&self, packet: ShadowQuicPacket) -> Result<()> {
        let mut outgoing = self.outgoing.lock().await;
        if !outgoing.contexts.contains_key(&packet.destination) {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let address = encode_address(&packet.destination)?;
            outgoing.control.write_all(&address).await?;
            outgoing.control.write_all(&id.to_be_bytes()).await?;
            outgoing.control.flush().await?;
            let context = match self.mode {
                UdpMode::Datagram => OutgoingUdpContext::Datagram { id },
                UdpMode::Stream => {
                    let mut stream = self.connection.open_uni().await?;
                    stream.write_all(&id.to_be_bytes()).await?;
                    OutgoingUdpContext::Stream { stream }
                }
            };
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

async fn serve_connection(
    connection: quinn::Connection,
    sender: mpsc::Sender<Accepted>,
) -> Result<()> {
    let source = connection.remote_address();
    let user = match connection.handshake_data() {
        Some(data) => match data.downcast::<quinn_proto::crypto::rustls::HandshakeData>() {
            Ok(data) if data.jls_authenticated == Some(true) => data.jls_user.unwrap_or_default(),
            _ => {
                connection.close(0u32.into(), b"JLS authentication failed");
                return Err(Error::JlsAuthenticationFailed);
            }
        },
        None => {
            connection.close(0u32.into(), b"JLS authentication missing");
            return Err(Error::JlsAuthenticationFailed);
        }
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
        "ShadowQuic server transport configured"
    );
    let _window_task = AdaptiveWindowTask::spawn(
        connection.clone(),
        send_rate,
        0,
        crate::hysteria2::transport::SEND_WINDOW,
        u64::from(crate::hysteria2::transport::CONNECTION_RECEIVE_WINDOW),
    );
    let incoming_udp = Arc::new(IncomingUdpRegistry::default());
    let next_udp_id = Arc::new(AtomicU16::new(0));

    let result = loop {
        tokio::select! {
            stream = connection.accept_bi() => match stream {
                Ok((send, recv)) => {
                    let connection = connection.clone();
                    let sender = sender.clone();
                    let user = user.clone();
                    let incoming_udp = Arc::clone(&incoming_udp);
                    let next_udp_id = Arc::clone(&next_udp_id);
                    tokio::spawn(async move {
                        if let Err(error) = handle_bi_stream(
                            connection,
                            send,
                            recv,
                            sender,
                            source,
                            user,
                            incoming_udp,
                            next_udp_id,
                        ).await {
                            tracing::debug!(%error, "ShadowQuic bidirectional stream closed");
                        }
                    });
                }
                Err(error) => break Err(error.into()),
            },
            stream = connection.accept_uni() => match stream {
                Ok(recv) => {
                    let incoming_udp = Arc::clone(&incoming_udp);
                    tokio::spawn(async move {
                        if let Err(error) = handle_incoming_udp_stream(recv, incoming_udp).await {
                            tracing::debug!(%error, "ShadowQuic UDP unidirectional stream closed");
                        }
                    });
                }
                Err(error) => break Err(error.into()),
            },
            datagram = connection.read_datagram() => match datagram {
                Ok(datagram) => {
                    let incoming_udp = Arc::clone(&incoming_udp);
                    tokio::spawn(async move {
                        if let Err(error) = handle_incoming_udp_datagram(datagram, incoming_udp).await {
                            tracing::debug!(%error, "ShadowQuic UDP datagram dropped");
                        }
                    });
                }
                Err(error) => break Err(error.into()),
            },
        }
    };
    incoming_udp.close();
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_bi_stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sender: mpsc::Sender<Accepted>,
    source: SocketAddr,
    user: String,
    incoming_udp: Arc<IncomingUdpRegistry>,
    next_udp_id: Arc<AtomicU16>,
) -> Result<()> {
    let mut opcode = [0u8; 1];
    recv.read_exact(&mut opcode).await?;
    match opcode[0] {
        SQ_CONNECT => {
            let destination = decode_address(&mut recv).await?;
            sender
                .send(Accepted::Stream(AcceptedStream {
                    stream: ShadowQuicStream::new(send, recv),
                    destination,
                    user,
                    source,
                }))
                .await
                .map_err(|_| Error::Closed)?;
        }
        SQ_ASSOCIATE_OVER_DATAGRAM | SQ_ASSOCIATE_OVER_STREAM => {
            let destination = decode_address(&mut recv).await?;
            let mode = if opcode[0] == SQ_ASSOCIATE_OVER_DATAGRAM {
                UdpMode::Datagram
            } else {
                UdpMode::Stream
            };
            let (packet_sender, packet_receiver) = mpsc::channel(256);
            let packet_connection = Arc::new(ShadowQuicPacketConnection {
                connection,
                mode,
                next_id: next_udp_id,
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
                    user,
                    source,
                }))
                .await
                .map_err(|_| Error::Closed)?;
            handle_udp_control_stream(recv, incoming_udp, packet_sender).await?;
        }
        SQ_EXTENSION => handle_extension(&connection, &mut send, &mut recv).await?,
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
) -> Result<()> {
    let mut ids = Vec::new();
    let result = async {
        loop {
            let destination = decode_address(&mut recv).await?;
            let mut id = [0u8; 2];
            recv.read_exact(&mut id).await?;
            let id = u16::from_be_bytes(id);
            incoming_udp.register(id, destination, sender.clone()).await;
            ids.push(id);
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    }
    .await;
    incoming_udp.remove(&ids).await;
    result
}

async fn handle_incoming_udp_datagram(
    datagram: Bytes,
    incoming_udp: Arc<IncomingUdpRegistry>,
) -> Result<()> {
    if datagram.len() < 2 {
        return Err(Error::Protocol("truncated ShadowQuic UDP datagram".into()));
    }
    let id = u16::from_be_bytes([datagram[0], datagram[1]]);
    let route = incoming_udp.wait(id).await?;
    route
        .sender
        .send(ShadowQuicPacket {
            data: datagram[2..].to_vec(),
            destination: route.destination,
        })
        .await
        .map_err(|_| Error::Closed)
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
