//! ShadowQuic's QUIC stream protocol.
//!
//! ShadowQuic authenticates the TLS ClientHello with JLS and then carries a
//! SOCKS5-addressed TCP request as the first bytes of a QUIC bidirectional
//! stream. The JLS implementation lives in the local rustls fork; this module
//! only consumes the authentication result exposed by the QUIC TLS adapter.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use quinn::{ClientConfig, Endpoint, ServerConfig, crypto::rustls::QuicClientConfig};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, mpsc},
};

use crate::congestion::{
    CongestionKind, configure_connection_bbr, configure_connection_brutal_with_options,
    connection_congestion_kind,
};
use crate::hysteria2::transport::{base_transport_config, bind_endpoint};
use crate::{Address, Error, Result};

const SQ_CONNECT: u8 = 0x01;
const SQ_IPV4: u8 = 0x01;
const SQ_DOMAIN: u8 = 0x03;
const SQ_IPV6: u8 = 0x04;
const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;

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
        config.transport_config(Arc::new(base_transport_config()));
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
pub struct Accepted {
    pub stream: ShadowQuicStream,
    pub destination: Address,
    pub user: String,
    pub source: SocketAddr,
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
    config.transport_config(Arc::new(base_transport_config()));
    Ok(config)
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
    loop {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let mut opcode = [0u8; 1];
        recv.read_exact(&mut opcode).await?;
        if opcode[0] != SQ_CONNECT {
            connection.close(0u32.into(), b"unsupported ShadowQuic request");
            return Err(Error::Protocol("unsupported ShadowQuic request".into()));
        }
        let destination = decode_address(&mut recv).await?;
        send.flush().await?;
        sender
            .send(Accepted {
                stream: ShadowQuicStream::new(send, recv),
                destination,
                user: user.clone(),
                source,
            })
            .await
            .map_err(|_| Error::Closed)?;
    }
}

fn encode_connect(destination: &Address) -> Result<Vec<u8>> {
    let host = destination.host();
    let mut frame = Vec::with_capacity(host.len() + 8);
    frame.push(SQ_CONNECT);
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
            let accepted = accept_server.accept().await.unwrap();
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
}
