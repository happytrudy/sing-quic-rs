//! SunnyQUIC over the native QUIC TLS stack.
//!
//! SunnyQUIC uses the SQuic stream and UDP framing shared with ShadowQUIC, but
//! authenticates at the application layer with `SHA256(username:password)`.
//! The QUIC congestion controller remains the common BBR/Brutal controller.

use std::{net::SocketAddr, sync::Arc};

use crate::{Address, Result};

pub use crate::congestion::CongestionKind;
pub use crate::shadowquic::{
    Accepted, AcceptedPacket, AcceptedStream, CongestionConfig, ShadowQuicPacket,
    ShadowQuicPacketConnection, ShadowQuicStream, User,
};

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: SocketAddr,
    pub server_name: String,
    pub username: String,
    pub password: String,
    pub ca_certificates: Vec<Vec<u8>>,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
}

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub listen: SocketAddr,
    pub users: Vec<User>,
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
    pub congestion: CongestionConfig,
    pub zero_rtt: bool,
}

pub struct Client {
    inner: crate::shadowquic::Client,
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Self> {
        let credential = crate::shadowquic::sunny_credential(&options.username, &options.password);
        Ok(Self {
            inner: crate::shadowquic::Client::new_sunny(crate::shadowquic::SunnyClientOptions {
                server: options.server,
                server_name: options.server_name,
                credential,
                ca_certificates: options.ca_certificates,
                congestion: options.congestion,
                zero_rtt: options.zero_rtt,
            })?,
        })
    }

    pub async fn connect(&self, destination: Address) -> Result<ShadowQuicStream> {
        self.inner.connect(destination).await
    }

    pub async fn associate(
        &self,
        destination: Address,
        over_stream: bool,
    ) -> Result<Arc<ShadowQuicPacketConnection>> {
        self.inner.associate(destination, over_stream).await
    }

    pub async fn congestion_kind(&self) -> Option<CongestionKind> {
        self.inner.congestion_kind().await
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn close(&self) {
        self.inner.close();
    }
}

pub struct Server {
    inner: crate::shadowquic::Server,
    options: ServerOptions,
}

impl Server {
    pub fn bind(options: ServerOptions) -> Result<Self> {
        let inner = crate::shadowquic::Server::bind_sunny(crate::shadowquic::SunnyServerOptions {
            listen: options.listen,
            users: options.users.clone(),
            certificate_chain: options.certificate_chain.clone(),
            private_key: options.private_key.clone(),
            congestion: options.congestion,
            zero_rtt: options.zero_rtt,
        })?;
        Ok(Self { inner, options })
    }

    pub async fn accept(&self) -> Result<Accepted> {
        self.inner.accept().await
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn update_certificate(
        &self,
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> Result<()> {
        let mut options = self.options.clone();
        options.certificate_chain = certificate_chain;
        options.private_key = private_key;
        self.inner
            .update_sunny_config(crate::shadowquic::SunnyServerOptions {
                listen: options.listen,
                users: options.users.clone(),
                certificate_chain: options.certificate_chain.clone(),
                private_key: options.private_key.clone(),
                congestion: options.congestion,
                zero_rtt: options.zero_rtt,
            })
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SunnyQuicClient")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SunnyQuicServer")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_certificate() -> (Vec<Vec<u8>>, Vec<u8>) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (
            vec![certificate.cert.der().to_vec()],
            certificate.signing_key.serialize_der(),
        )
    }

    #[test]
    fn sunnyquic_uses_the_upstream_64_byte_credential_shape() {
        let credential = crate::shadowquic::sunny_credential("alice", "secret");
        assert_eq!(
            &credential[..32],
            &[
                0x3d, 0x11, 0xdc, 0x47, 0x9c, 0x08, 0xe3, 0xb3, 0x68, 0x77, 0x31, 0x03, 0xd6, 0x47,
                0x66, 0xc2, 0xe4, 0x20, 0xce, 0x39, 0x72, 0x79, 0x32, 0xfc, 0xf2, 0xd8, 0xf4, 0xd9,
                0xd5, 0x99, 0xbe, 0x59,
            ]
        );
        assert!(credential[32..].iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn sunnyquic_authenticates_and_proxies_tcp_with_bbr() {
        let (certificate_chain, private_key) = test_certificate();
        let server = Arc::new(
            Server::bind(ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
                certificate_chain: certificate_chain.clone(),
                private_key,
                congestion: CongestionConfig::Bbr,
                zero_rtt: true,
            })
            .unwrap(),
        );
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            username: "alice".into(),
            password: "secret".into(),
            ca_certificates: certificate_chain,
            congestion: CongestionConfig::Bbr,
            zero_rtt: true,
        })
        .unwrap();
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let Accepted::Stream(accepted) = server.accept().await.unwrap() else {
                    panic!("expected SunnyQUIC TCP stream");
                };
                assert_eq!(accepted.user, "alice");
                let mut stream = accepted.stream;
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                stream.write_all(&request).await.unwrap();
                stream.flush().await.unwrap();
            })
        };
        let mut stream = client
            .connect(Address::new("example.com", 443).unwrap())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        assert_eq!(client.congestion_kind().await, Some(CongestionKind::Bbr));
        server_task.await.unwrap();
        client.close();
        server.close().await;
    }

    #[tokio::test]
    async fn sunnyquic_supports_udp_datagrams_with_brutal() {
        let (certificate_chain, private_key) = test_certificate();
        let server = Arc::new(
            Server::bind(ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                users: vec![User {
                    name: "alice".into(),
                    password: "secret".into(),
                }],
                certificate_chain: certificate_chain.clone(),
                private_key,
                congestion: CongestionConfig::Brutal {
                    bytes_per_second: 12_500_000,
                    disable_loss_compensation: false,
                },
                zero_rtt: true,
            })
            .unwrap(),
        );
        let client = Client::new(ClientOptions {
            server: server.local_addr().unwrap(),
            server_name: "localhost".into(),
            username: "alice".into(),
            password: "secret".into(),
            ca_certificates: certificate_chain,
            congestion: CongestionConfig::Brutal {
                bytes_per_second: 12_500_000,
                disable_loss_compensation: false,
            },
            zero_rtt: true,
        })
        .unwrap();
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let Accepted::Packet(accepted) = server.accept().await.unwrap() else {
                    panic!("expected SunnyQUIC UDP packet connection");
                };
                let packet = accepted.connection.recv().await.unwrap();
                assert_eq!(packet.data, b"query");
                accepted.connection.send(packet).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            })
        };
        let packet_connection = client
            .associate(Address::new("0.0.0.0", 0).unwrap(), false)
            .await
            .unwrap();
        packet_connection
            .send(ShadowQuicPacket {
                data: b"query".to_vec(),
                destination: Address::new("example.com", 443).unwrap(),
            })
            .await
            .unwrap();
        let response = packet_connection.recv().await.unwrap();
        assert_eq!(response.data, b"query");
        assert_eq!(
            client.congestion_kind().await,
            Some(CongestionKind::Brutal {
                bytes_per_second: 12_500_000
            })
        );
        server_task.await.unwrap();
        client.close();
        server.close().await;
    }
}
