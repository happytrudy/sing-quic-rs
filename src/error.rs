#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("QUIC TLS configuration error: {0}")]
    QuicTls(String),
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid QUIC variable integer")]
    InvalidVarInt,
    #[error("Hysteria2 authentication failed with HTTP status {0}")]
    AuthenticationFailed(u16),
    #[error("JLS authentication failed")]
    JlsAuthenticationFailed,
    #[error("Hysteria2 protocol error: {0}")]
    Protocol(String),
    #[error("HTTP/3 error: {0}")]
    Http3(String),
    #[error("QUIC connection does not use the switchable congestion controller")]
    CongestionControl,
    #[error("service is closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, Error>;
