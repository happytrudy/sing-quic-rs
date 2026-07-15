use std::{fmt, net::SocketAddr, str::FromStr};

use crate::{Error, Result};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    host: String,
    port: u16,
}

impl Address {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.is_empty() {
            return Err(Error::InvalidAddress);
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        if let Ok(socket) = value.parse::<SocketAddr>() {
            return Ok(socket.into());
        }
        let (host, port) = value.rsplit_once(':').ok_or(Error::InvalidAddress)?;
        let host = host
            .strip_prefix('[')
            .and_then(|item| item.strip_suffix(']'))
            .unwrap_or(host);
        Self::new(host, port.parse().map_err(|_| Error::InvalidAddress)?)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn authority_round_trip() {
        for address in [
            Address::new("example.com", 443).unwrap(),
            Address::new("2001:db8::1", 8443).unwrap(),
        ] {
            assert_eq!(Address::from_str(&address.to_string()).unwrap(), address);
        }
    }
}
