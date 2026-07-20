use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::{Buf, Bytes};
use futures::future::BoxFuture;
use http::{
    Request, Response, StatusCode,
    header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING},
};
use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    },
};
use tokio::sync::{Mutex, mpsc};

use crate::congestion::{
    CongestionKind, configure_connection_brutal_with_options, connection_congestion_kind,
};
use crate::transport::AdaptiveWindowTask;
use crate::{Address, Error, Result};

use super::protocol::{
    CongestionReceive, HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, HEADER_UDP, STATUS_AUTH_OK,
    URL_AUTHORITY, URL_PATH, congestion_receive_value, padding, parse_congestion_receive,
    read_tcp_request, write_tcp_response,
};
use super::{
    Hysteria2PacketConnection, Hysteria2Stream, ServerBandwidth,
    metrics::ConnectionMetricsTask,
    packet::decode_message,
    transport::{QuicTransportOptions, base_transport_config, bind_endpoint},
};

const ALPN_H3: &[u8] = b"h3";
const MAX_MASQUERADE_REQUEST_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub listen: SocketAddr,
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
    pub users: Vec<User>,
}

pub trait MasqueradeHandler: Send + Sync + 'static {
    fn handle(
        &self,
        source: SocketAddr,
        request: Request<Vec<u8>>,
    ) -> BoxFuture<'static, Response<Vec<u8>>>;
}

#[derive(Debug)]
pub struct AcceptedStream {
    pub stream: Hysteria2Stream,
    pub destination: Address,
    pub user: String,
    pub source: SocketAddr,
    pub congestion: CongestionKind,
}

#[derive(Debug)]
pub struct AcceptedPacket {
    pub connection: Arc<Hysteria2PacketConnection>,
    pub destination: Address,
    pub user: String,
    pub source: SocketAddr,
    pub congestion: CongestionKind,
}

#[derive(Debug)]
pub enum Accepted {
    Stream(AcceptedStream),
    Packet(AcceptedPacket),
}

pub struct Server {
    endpoint: Endpoint,
    transport_options: QuicTransportOptions,
    incoming: Mutex<mpsc::Receiver<Accepted>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Server {
    pub fn bind(options: ServerOptions) -> Result<Self> {
        Self::bind_with_bandwidth(options, ServerBandwidth::default())
    }

    pub fn bind_with_bandwidth(options: ServerOptions, bandwidth: ServerBandwidth) -> Result<Self> {
        Self::bind_with_bandwidth_and_masquerade(options, bandwidth, None)
    }

    pub fn bind_with_bandwidth_and_masquerade(
        options: ServerOptions,
        bandwidth: ServerBandwidth,
        masquerade: Option<Arc<dyn MasqueradeHandler>>,
    ) -> Result<Self> {
        Self::bind_with_bandwidth_and_transport_and_masquerade(
            options,
            bandwidth,
            QuicTransportOptions::default(),
            masquerade,
        )
    }

    pub fn bind_with_bandwidth_and_transport_and_masquerade(
        options: ServerOptions,
        bandwidth: ServerBandwidth,
        transport_options: QuicTransportOptions,
        masquerade: Option<Arc<dyn MasqueradeHandler>>,
    ) -> Result<Self> {
        let server_config = build_server_config(
            options.certificate_chain,
            options.private_key,
            transport_options,
        )?;
        let endpoint = bind_endpoint(options.listen, Some(server_config))?;
        let users = Arc::new(
            options
                .users
                .into_iter()
                .map(|user| (user.password, user.name))
                .collect::<HashMap<_, _>>(),
        );
        let (sender, receiver) = mpsc::channel(256);
        let accept_endpoint = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let users = Arc::clone(&users);
                let sender = sender.clone();
                let masquerade = masquerade.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            let observed_connection = connection.clone();
                            if let Err(error) =
                                serve_connection(connection, users, sender, bandwidth, masquerade)
                                    .await
                            {
                                let stats = observed_connection.stats();
                                tracing::warn!(
                                    %error,
                                    error_debug = ?error,
                                    close_reason = ?observed_connection.close_reason(),
                                    peer = %observed_connection.remote_address(),
                                    rtt_ms = stats.path.rtt.as_secs_f64() * 1_000.0,
                                    cwnd_bytes = stats.path.cwnd,
                                    mtu = stats.path.current_mtu,
                                    sent_packets = stats.path.sent_packets,
                                    lost_packets = stats.path.lost_packets,
                                    lost_bytes = stats.path.lost_bytes,
                                    "Hysteria2 connection closed unexpectedly"
                                );
                            }
                        }
                        Err(error) => tracing::debug!(%error, "QUIC handshake failed"),
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            transport_options,
            incoming: Mutex::new(receiver),
            accept_task,
        })
    }

    pub async fn accept(&self) -> Result<Accepted> {
        self.incoming.lock().await.recv().await.ok_or(Error::Closed)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn update_certificate(
        &self,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> Result<()> {
        self.endpoint.set_server_config(Some(build_server_config(
            certificate_chain,
            private_key,
            self.transport_options,
        )?));
        Ok(())
    }

    pub async fn close(&self) {
        self.endpoint.close(0u32.into(), b"server closed");
        self.endpoint.wait_idle().await;
        self.accept_task.abort();
    }
}

fn build_server_config(
    certificate_chain: Vec<Vec<u8>>,
    private_key: Vec<u8>,
    transport_options: QuicTransportOptions,
) -> Result<ServerConfig> {
    let certificates = certificate_chain
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let private_key = detect_private_key(private_key)?;
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|error| Error::QuicTls(error.to_string()))?;
    let mut transport = base_transport_config(transport_options);
    transport.max_concurrent_bidi_streams(1024u32.into());
    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
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

async fn serve_connection(
    connection: quinn::Connection,
    users: Arc<HashMap<String, String>>,
    sender: mpsc::Sender<Accepted>,
    bandwidth: ServerBandwidth,
    masquerade: Option<Arc<dyn MasqueradeHandler>>,
) -> Result<()> {
    let source = connection.remote_address();
    let mut h3_connection: h3::server::Connection<_, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|error| Error::Http3(error.to_string()))?;
    let resolver = h3_connection
        .accept()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?
        .ok_or_else(|| Error::Protocol("connection closed before authentication".into()))?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    let authority_matches = request
        .uri()
        .authority()
        .is_some_and(|authority| authority.as_str() == URL_AUTHORITY);
    let user = request
        .headers()
        .get(HEADER_AUTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|password| users.get(password))
        .cloned();
    let client_receive = parse_congestion_receive(request.headers().get(HEADER_CC_RX));
    let authenticated = request.method() == http::Method::POST
        && authority_matches
        && request.uri().path() == URL_PATH
        && user.is_some();
    if !authenticated {
        spawn_masquerade_request(source, request, stream, masquerade.clone());
        loop {
            let Some(resolver) = h3_connection
                .accept()
                .await
                .map_err(|error| Error::Http3(error.to_string()))?
            else {
                return Ok(());
            };
            let (request, stream) = resolver
                .resolve_request()
                .await
                .map_err(|error| Error::Http3(error.to_string()))?;
            spawn_masquerade_request(source, request, stream, masquerade.clone());
        }
    }
    let send_rate = if bandwidth.ignore_client_bandwidth {
        None
    } else {
        negotiated_send_rate(bandwidth, client_receive)
    };
    let congestion = if authenticated {
        if let Some(bytes_per_second) = send_rate
            && !configure_connection_brutal_with_options(
                &connection,
                bytes_per_second,
                bandwidth.disable_loss_compensation,
            )
        {
            return Err(Error::CongestionControl);
        }
        connection_congestion_kind(&connection).ok_or(Error::CongestionControl)?
    } else {
        CongestionKind::Bbr
    };
    let advertised_receive = if bandwidth.ignore_client_bandwidth {
        CongestionReceive::Auto
    } else {
        CongestionReceive::Rate(bandwidth.receive_bps)
    };
    let response = Response::builder()
        .status(StatusCode::from_u16(STATUS_AUTH_OK).expect("valid custom status"))
        .header(HEADER_UDP, "true")
        .header(HEADER_CC_RX, congestion_receive_value(advertised_receive))
        .header(HEADER_PADDING, padding(256, 2048))
        .body(())
        .map_err(|error| Error::Protocol(error.to_string()))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    let user = user.expect("authenticated request has a user");
    tracing::info!(
        %source,
        %user,
        ?congestion,
        configured_send_bps = bandwidth.send_bps,
        configured_receive_bps = bandwidth.receive_bps,
        client_receive = ?client_receive,
        negotiated_send_bps = send_rate.unwrap_or_default(),
        "Hysteria2 server congestion negotiated"
    );
    let _metrics_task = bandwidth
        .brutal_debug
        .then(|| ConnectionMetricsTask::spawn(connection.clone(), "server", source, congestion));
    let _window_task = AdaptiveWindowTask::spawn(
        connection.clone(),
        send_rate.unwrap_or_default(),
        if bandwidth.ignore_client_bandwidth {
            0
        } else {
            bandwidth.receive_bps
        },
        super::transport::SEND_WINDOW,
        u64::from(super::transport::CONNECTION_RECEIVE_WINDOW),
    );

    // Keep the HTTP/3 state alive while raw Hysteria2 streams use the same
    // Quinn connection. The h3 connection is intentionally no longer polled,
    // so it cannot race with the raw bidirectional stream accept loop.
    let _h3_connection = h3_connection;
    let mut udp_sessions = HashMap::<u32, Arc<Hysteria2PacketConnection>>::new();
    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                let (send, recv) = stream?;
                let sender = sender.clone();
                let user = user.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_stream(send, recv, source, user, congestion, sender).await {
                        tracing::debug!(%error, "Hysteria2 stream closed");
                    }
                });
            }
            datagram = connection.read_datagram() => {
                let message = decode_message(&datagram?)?;
                let packet_connection = match udp_sessions.get(&message.session_id) {
                    Some(connection) => Arc::clone(connection),
                    None => {
                        let packet_connection = Hysteria2PacketConnection::new(
                            connection.clone(),
                            message.session_id,
                        );
                        sender
                            .send(Accepted::Packet(AcceptedPacket {
                                connection: Arc::clone(&packet_connection),
                                destination: message.destination.clone(),
                                user: user.clone(),
                                source,
                                congestion,
                            }))
                            .await
                            .map_err(|_| Error::Closed)?;
                        udp_sessions.insert(message.session_id, Arc::clone(&packet_connection));
                        packet_connection
                    }
                };
                packet_connection.input(message).await?;
            }
        }
    }
}

fn spawn_masquerade_request<S>(
    source: SocketAddr,
    request: Request<()>,
    stream: h3::server::RequestStream<S, Bytes>,
    masquerade: Option<Arc<dyn MasqueradeHandler>>,
) where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) =
            serve_masquerade_request(source, request, stream, masquerade.as_ref()).await
        {
            tracing::debug!(%error, "Hysteria2 masquerade request failed");
        }
    });
}

async fn serve_masquerade_request<S>(
    source: SocketAddr,
    request: Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    masquerade: Option<&Arc<dyn MasqueradeHandler>>,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let is_head = request.method() == http::Method::HEAD;
    let (parts, _) = request.into_parts();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?
    {
        if body.len().saturating_add(chunk.remaining()) > MAX_MASQUERADE_REQUEST_SIZE {
            send_masquerade_response(
                &mut stream,
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Vec::new())
                    .expect("valid response"),
                is_head,
            )
            .await?;
            return Ok(());
        }
        let length = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(length));
    }
    let request = Request::from_parts(parts, body);
    let response = match masquerade {
        Some(handler) => handler.handle(source, request).await,
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Vec::new())
            .expect("valid response"),
    };
    send_masquerade_response(&mut stream, response, is_head).await
}

async fn send_masquerade_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: Response<Vec<u8>>,
    is_head: bool,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(CONNECTION);
    parts.headers.remove(TRANSFER_ENCODING);
    let body_is_allowed = !parts.status.is_informational()
        && parts.status != StatusCode::NO_CONTENT
        && parts.status != StatusCode::NOT_MODIFIED;
    if is_head {
        if !parts.headers.contains_key(CONTENT_LENGTH) {
            parts.headers.insert(
                CONTENT_LENGTH,
                http::HeaderValue::from_str(&body.len().to_string())
                    .expect("body length is a valid header value"),
            );
        }
    } else if body_is_allowed {
        parts.headers.insert(
            CONTENT_LENGTH,
            http::HeaderValue::from_str(&body.len().to_string())
                .expect("body length is a valid header value"),
        );
    } else {
        parts.headers.remove(CONTENT_LENGTH);
    }
    stream
        .send_response(Response::from_parts(parts, ()))
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    if !is_head && body_is_allowed && !body.is_empty() {
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|error| Error::Http3(error.to_string()))?;
    }
    stream
        .finish()
        .await
        .map_err(|error| Error::Http3(error.to_string()))
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    source: SocketAddr,
    user: String,
    congestion: CongestionKind,
    accepted_sender: mpsc::Sender<Accepted>,
) -> Result<()> {
    let destination = read_tcp_request(&mut recv).await?;
    write_tcp_response(&mut send, Ok(())).await?;
    accepted_sender
        .send(Accepted::Stream(AcceptedStream {
            stream: Hysteria2Stream::new(send, recv),
            destination,
            user,
            source,
            congestion,
        }))
        .await
        .map_err(|_| Error::Closed)
}

fn negotiated_send_rate(
    bandwidth: ServerBandwidth,
    client_receive: CongestionReceive,
) -> Option<u64> {
    let CongestionReceive::Rate(client_receive_bps) = client_receive else {
        return None;
    };
    if client_receive_bps == 0 {
        return None;
    }
    Some(
        if bandwidth.send_bps > 0 && client_receive_bps > bandwidth.send_bps {
            bandwidth.send_bps
        } else {
            client_receive_bps
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2::{
        Client, ClientBandwidth, ClientOptions, Hysteria2Packet, Hysteria2PacketConnection,
    };
    use futures::future::poll_fn;
    use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
    use rcgen::generate_simple_self_signed;
    use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestMasquerade;

    impl MasqueradeHandler for TestMasquerade {
        fn handle(
            &self,
            _source: SocketAddr,
            request: Request<Vec<u8>>,
        ) -> BoxFuture<'static, Response<Vec<u8>>> {
            let body = format!("decoy {}", request.uri().path()).into_bytes();
            Box::pin(async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .body(body)
                    .unwrap()
            })
        }
    }

    #[tokio::test]
    async fn serves_multiple_masquerade_requests_on_one_connection() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let server = Server::bind_with_bandwidth_and_masquerade(
            ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_chain: vec![certificate_der.clone()],
                private_key: certificate.signing_key.serialize_der(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
            },
            ServerBandwidth::default(),
            Some(Arc::new(TestMasquerade)),
        )
        .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(certificate_der)).unwrap();
        let mut tls = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];
        let crypto = QuicClientConfig::try_from(tls).unwrap();
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
        let connection = endpoint
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();

        for (method, path) in [
            (http::Method::GET, "/"),
            (http::Method::HEAD, "/head"),
            (http::Method::GET, "/assets/app.js"),
        ] {
            let is_head = method == http::Method::HEAD;
            let request = Request::builder()
                .method(method)
                .uri(format!("https://localhost{path}"))
                .body(())
                .unwrap();
            let mut stream = sender.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(CONTENT_LENGTH).unwrap(),
                &format!("decoy {path}").len().to_string()
            );
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                let length = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(length));
            }
            if is_head {
                assert!(body.is_empty());
            } else {
                assert_eq!(body, format!("decoy {path}").as_bytes());
            }
        }

        connection.close(0u32.into(), b"test complete");
        let _ = poll_fn(|context| driver.poll_close(context)).await;
        endpoint.close(0u32.into(), b"test complete");
        server.close().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ipv6_unspecified_listener_accepts_ipv4_and_ipv6() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let server = Arc::new(
            Server::bind(ServerOptions {
                listen: "[::]:0".parse().unwrap(),
                certificate_chain: vec![certificate_der.clone()],
                private_key: certificate.signing_key.serialize_der(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
            })
            .unwrap(),
        );
        let port = server.local_addr().unwrap().port();
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                for _ in 0..2 {
                    let Accepted::Stream(accepted) = server.accept().await.unwrap() else {
                        panic!("expected Hysteria2 TCP stream");
                    };
                    tokio::spawn(async move {
                        let (mut read, mut write) = tokio::io::split(accepted.stream);
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
            }
        });

        for server_address in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ] {
            let client = Client::new(ClientOptions {
                server: server_address,
                server_name: "localhost".into(),
                password: "secret".into(),
                ca_certificates: vec![certificate_der.clone()],
            })
            .unwrap();
            let mut stream = client
                .connect(Address::new("example.com", 443).unwrap())
                .await
                .unwrap();
            stream.write_all(b"dual stack").await.unwrap();
            let mut response = [0; 10];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"dual stack");
            stream.shutdown().await.unwrap();
            client.close();
        }

        server_task.await.unwrap();
        server.close().await;
    }

    #[tokio::test]
    async fn authenticated_tcp_stream_round_trip() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let private_key = certificate.signing_key.serialize_der();
        let server = Arc::new(
            Server::bind_with_bandwidth(
                ServerOptions {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    certificate_chain: vec![certificate_der.clone()],
                    private_key,
                    users: vec![User {
                        name: "alice".into(),
                        password: "secret".into(),
                    }],
                },
                ServerBandwidth {
                    send_bps: 3_000_000,
                    receive_bps: 0,
                    ignore_client_bandwidth: true,
                    ..ServerBandwidth::default()
                },
            )
            .unwrap(),
        );
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let Accepted::Stream(accepted) = server.accept().await.unwrap() else {
                    panic!("expected Hysteria2 TCP stream");
                };
                assert_eq!(accepted.user, "alice");
                assert_eq!(accepted.congestion, CongestionKind::Bbr);
                assert_eq!(
                    accepted.destination,
                    Address::new("example.com", 443).unwrap()
                );
                let (mut read, mut write) = tokio::io::split(accepted.stream);
                tokio::io::copy(&mut read, &mut write).await.unwrap();
            }
        });
        let client = Client::new_with_bandwidth(
            ClientOptions {
                server: server.local_addr().unwrap(),
                server_name: "localhost".into(),
                password: "secret".into(),
                ca_certificates: vec![certificate_der],
            },
            ClientBandwidth {
                send_bps: 1_000_000,
                receive_bps: 2_000_000,
                ..ClientBandwidth::default()
            },
        )
        .unwrap();
        let mut stream = client
            .connect(Address::new("example.com", 443).unwrap())
            .await
            .unwrap();
        assert_eq!(client.congestion_kind().await, Some(CongestionKind::Bbr));
        stream.write_all(b"hello over Hysteria2").await.unwrap();
        let mut response = vec![0u8; 20];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello over Hysteria2");
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn negotiates_asymmetric_brutal_rates_in_both_directions() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let private_key = certificate.signing_key.serialize_der();
        let server = Arc::new(
            Server::bind_with_bandwidth_and_transport_and_masquerade(
                ServerOptions {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    certificate_chain: vec![certificate_der.clone()],
                    private_key,
                    users: vec![User {
                        name: "alice".into(),
                        password: "secret".into(),
                    }],
                },
                ServerBandwidth {
                    send_bps: 125_000_000,
                    receive_bps: 125_000_000,
                    ignore_client_bandwidth: false,
                    ..ServerBandwidth::default()
                },
                QuicTransportOptions {
                    initial_packet_size: 1200,
                    disable_path_mtu_discovery: true,
                },
                None,
            )
            .unwrap(),
        );
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let Accepted::Stream(accepted) = server.accept().await.unwrap() else {
                    panic!("expected Hysteria2 TCP stream");
                };
                assert_eq!(
                    accepted.congestion,
                    CongestionKind::Brutal {
                        bytes_per_second: 12_500_000
                    }
                );
                let (mut read, mut write) = tokio::io::split(accepted.stream);
                tokio::io::copy(&mut read, &mut write).await.unwrap();
            }
        });
        let client = Client::new_with_bandwidth_and_transport(
            ClientOptions {
                server: server.local_addr().unwrap(),
                server_name: "localhost".into(),
                password: "secret".into(),
                ca_certificates: vec![certificate_der],
            },
            ClientBandwidth {
                send_bps: 3_750_000,
                receive_bps: 12_500_000,
                ..ClientBandwidth::default()
            },
            QuicTransportOptions {
                initial_packet_size: 1200,
                disable_path_mtu_discovery: true,
            },
        )
        .unwrap();
        let mut stream = client
            .connect(Address::new("example.com", 443).unwrap())
            .await
            .unwrap();
        assert_eq!(
            client.congestion_kind().await,
            Some(CongestionKind::Brutal {
                bytes_per_second: 3_750_000
            })
        );
        assert_eq!(
            client
                .connection_handle()
                .await
                .unwrap()
                .stats()
                .path
                .current_mtu,
            1200
        );
        let payload = vec![0x5a; 4 * 1024 * 1024];
        let mut response = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), async {
            stream.write_all(&payload).await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
        })
        .await
        .expect("30 Mbps Brutal transfer exceeded its throughput budget");
        assert_eq!(response, payload);
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn official_udp_datagram_fragmentation_round_trip() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let server = Arc::new(
            Server::bind(ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_chain: vec![certificate_der.clone()],
                private_key: certificate.signing_key.serialize_der(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
            })
            .unwrap(),
        );
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let Accepted::Packet(accepted) = server.accept().await.unwrap() else {
                    panic!("expected Hysteria2 UDP session");
                };
                assert_eq!(accepted.user, "alice");
                assert_eq!(accepted.destination, Address::new("1.1.1.1", 53).unwrap());
                let packet = accepted.connection.recv().await.unwrap();
                assert_eq!(packet.destination, Address::new("1.1.1.1", 53).unwrap());
                assert_eq!(packet.data, vec![0x5a; 4096]);
                accepted
                    .connection
                    .send(Hysteria2Packet {
                        data: b"reply".to_vec(),
                        destination: Address::new("8.8.8.8", 53).unwrap(),
                    })
                    .await
                    .unwrap();
            }
        });
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            password: "secret".into(),
            ca_certificates: vec![certificate_der],
        })
        .unwrap();
        let connection = client.connection_handle().await.unwrap();
        let packet_connection = Hysteria2PacketConnection::new(connection.clone(), 9);
        tokio::time::timeout(Duration::from_secs(5), async {
            packet_connection
                .send(Hysteria2Packet {
                    data: vec![0x5a; 4096],
                    destination: Address::new("1.1.1.1", 53).unwrap(),
                })
                .await
                .unwrap();
            let message = decode_message(&connection.read_datagram().await.unwrap()).unwrap();
            packet_connection.input(message).await.unwrap();
            let response = packet_connection.recv().await.unwrap();
            assert_eq!(response.destination, Address::new("8.8.8.8", 53).unwrap());
            assert_eq!(response.data, b"reply");
        })
        .await
        .expect("Hysteria2 UDP round trip timed out");
        server_task.await.unwrap();
        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn rejects_invalid_password() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let server = Server::bind(ServerOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_chain: vec![certificate_der.clone()],
            private_key: certificate.signing_key.serialize_der(),
            users: vec![User {
                name: "alice".into(),
                password: "secret".into(),
            }],
        })
        .unwrap();
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            password: "wrong-password".into(),
            ca_certificates: vec![certificate_der],
        })
        .unwrap();
        let error = match client
            .connect(Address::new("example.com", 443).unwrap())
            .await
        {
            Ok(_) => panic!("invalid password unexpectedly authenticated"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Error::AuthenticationFailed(404)),
            "unexpected authentication error: {error:?}"
        );
        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn ignore_client_bandwidth_forces_bbr_without_rejecting_client() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let server = Arc::new(
            Server::bind_with_bandwidth(
                ServerOptions {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    certificate_chain: vec![certificate_der.clone()],
                    private_key: certificate.signing_key.serialize_der(),
                    users: vec![User {
                        name: "alice".into(),
                        password: "secret".into(),
                    }],
                },
                ServerBandwidth {
                    send_bps: 1_000_000,
                    receive_bps: 1_000_000,
                    ignore_client_bandwidth: true,
                    ..ServerBandwidth::default()
                },
            )
            .unwrap(),
        );
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let Accepted::Stream(accepted) = server.accept().await.unwrap() else {
                    panic!("expected Hysteria2 TCP stream");
                };
                assert_eq!(accepted.congestion, CongestionKind::Bbr);
                let (mut read, mut write) = tokio::io::split(accepted.stream);
                tokio::io::copy(&mut read, &mut write).await.unwrap();
            }
        });
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            password: "secret".into(),
            ca_certificates: vec![certificate_der],
        })
        .unwrap();
        let mut stream = client
            .connect(Address::new("example.com", 443).unwrap())
            .await
            .unwrap();
        assert_eq!(client.congestion_kind().await, Some(CongestionKind::Bbr));
        stream.write_all(b"configured BBR").await.unwrap();
        let mut response = [0u8; 14];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"configured BBR");
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
        client.close();
        server.close().await;
    }
}
