use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Response, StatusCode};
use quinn::{Endpoint, ServerConfig, TransportConfig, crypto::rustls::QuicServerConfig};
use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{Mutex, mpsc},
};

use crate::congestion::{
    CongestionKind, SwitchableCongestionFactory, configure_connection_brutal,
    connection_congestion_kind,
};
use crate::{Address, Error, Result};

use super::ServerBandwidth;
use super::protocol::{
    CongestionReceive, HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, HEADER_UDP, STATUS_AUTH_OK,
    URL_AUTHORITY, URL_PATH, congestion_receive_value, padding, parse_congestion_receive,
    read_tcp_request, write_tcp_response,
};

const BRIDGE_CAPACITY: usize = 256 * 1024;
const ALPN_H3: &[u8] = b"h3";

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

#[derive(Debug)]
pub struct Accepted {
    pub stream: DuplexStream,
    pub destination: Address,
    pub user: String,
    pub source: SocketAddr,
    pub congestion: CongestionKind,
}

pub struct Server {
    endpoint: Endpoint,
    incoming: Mutex<mpsc::Receiver<Accepted>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Server {
    pub fn bind(options: ServerOptions) -> Result<Self> {
        Self::bind_with_bandwidth(options, ServerBandwidth::default())
    }

    pub fn bind_with_bandwidth(options: ServerOptions, bandwidth: ServerBandwidth) -> Result<Self> {
        let certificates = options
            .certificate_chain
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private_key = detect_private_key(options.private_key)?;
        let mut tls = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)?;
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];
        let crypto =
            QuicServerConfig::try_from(tls).map_err(|error| Error::QuicTls(error.to_string()))?;
        let mut transport = TransportConfig::default();
        transport.congestion_controller_factory(Arc::new(SwitchableCongestionFactory));
        transport.max_concurrent_bidi_streams((1u32 << 20).into());
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::server(server_config, options.listen)?;
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
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            if let Err(error) =
                                serve_connection(connection, users, sender, bandwidth).await
                            {
                                tracing::debug!(%error, "Hysteria2 connection closed");
                            }
                        }
                        Err(error) => tracing::debug!(%error, "QUIC handshake failed"),
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
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

    pub async fn close(&self) {
        self.endpoint.close(0u32.into(), b"server closed");
        self.endpoint.wait_idle().await;
        self.accept_task.abort();
    }
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
        && user.is_some()
        && !server_rejects_bbr_client(bandwidth, client_receive);
    let congestion = if authenticated {
        if let Some(bytes_per_second) = negotiated_send_rate(bandwidth, client_receive)
            && !configure_connection_brutal(&connection, bytes_per_second)
        {
            return Err(Error::CongestionControl);
        }
        connection_congestion_kind(&connection).ok_or(Error::CongestionControl)?
    } else {
        CongestionKind::Bbr
    };
    let advertised_receive = if congestion == CongestionKind::Bbr {
        CongestionReceive::Auto
    } else {
        CongestionReceive::Rate(bandwidth.receive_bps)
    };
    let response = if authenticated {
        Response::builder()
            .status(StatusCode::from_u16(STATUS_AUTH_OK).expect("valid custom status"))
            .header(HEADER_UDP, "false")
            .header(HEADER_CC_RX, congestion_receive_value(advertised_receive))
            .header(HEADER_PADDING, padding(256, 2048))
            .body(())
    } else {
        Response::builder().status(StatusCode::NOT_FOUND).body(())
    }
    .map_err(|error| Error::Protocol(error.to_string()))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| Error::Http3(error.to_string()))?;
    let Some(user) = user.filter(|_| authenticated) else {
        // Keep the connection alive until the client consumes the HTTP error
        // and closes it. Closing immediately can race the response flight and
        // turn a useful 404 into a generic QUIC ApplicationClose.
        let _ = connection.closed().await;
        return Err(Error::AuthenticationFailed(404));
    };

    // Keep the HTTP/3 state alive while raw Hysteria2 streams use the same
    // Quinn connection. The h3 connection is intentionally no longer polled,
    // so it cannot race with the raw bidirectional stream accept loop.
    let _h3_connection = h3_connection;
    loop {
        let (send, recv) = connection.accept_bi().await?;
        let sender = sender.clone();
        let user = user.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_stream(send, recv, source, user, congestion, sender).await {
                tracing::debug!(%error, "Hysteria2 stream closed");
            }
        });
    }
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
    let (application, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (bridge_read, bridge_write) = tokio::io::split(bridge);
    spawn_encode(bridge_read, send);
    spawn_decode(recv, bridge_write);
    accepted_sender
        .send(Accepted {
            stream: application,
            destination,
            user,
            source,
            congestion,
        })
        .await
        .map_err(|_| Error::Closed)
}

fn negotiated_send_rate(
    bandwidth: ServerBandwidth,
    client_receive: CongestionReceive,
) -> Option<u64> {
    if bandwidth.receive_bps == 0 && bandwidth.ignore_client_bandwidth {
        return None;
    }
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

fn server_rejects_bbr_client(
    bandwidth: ServerBandwidth,
    client_receive: CongestionReceive,
) -> bool {
    bandwidth.ignore_client_bandwidth
        && bandwidth.receive_bps > 0
        && !matches!(client_receive, CongestionReceive::Rate(rate) if rate > 0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2::{Client, ClientBandwidth, ClientOptions};
    use rcgen::generate_simple_self_signed;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                    let accepted = server.accept().await.unwrap();
                    let (mut read, mut write) = tokio::io::split(accepted.stream);
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
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
                },
            )
            .unwrap(),
        );
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let accepted = server.accept().await.unwrap();
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
    async fn negotiates_brutal_rates_in_both_directions() {
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
                    receive_bps: 4_000_000,
                    ignore_client_bandwidth: false,
                },
            )
            .unwrap(),
        );
        let server_task = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let accepted = server.accept().await.unwrap();
                assert_eq!(
                    accepted.congestion,
                    CongestionKind::Brutal {
                        bytes_per_second: 2_000_000
                    }
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
                bytes_per_second: 1_000_000
            })
        );
        stream.write_all(b"brutal negotiation").await.unwrap();
        let mut response = [0u8; 18];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"brutal negotiation");
        stream.shutdown().await.unwrap();
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
    async fn configured_server_can_reject_bbr_clients() {
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = certificate.cert.der().to_vec();
        let server = Server::bind_with_bandwidth(
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
            },
        )
        .unwrap();
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            password: "secret".into(),
            ca_certificates: vec![certificate_der],
        })
        .unwrap();
        let error = match client
            .connect(Address::new("example.com", 443).unwrap())
            .await
        {
            Ok(_) => panic!("BBR client unexpectedly authenticated"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Error::AuthenticationFailed(404)),
            "unexpected authentication error: {error:?}"
        );
        client.close();
        server.close().await;
    }
}
