use rand::{Rng, distributions::Alphanumeric};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Address, Error, Result, varint};

pub(crate) const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub(crate) const URL_AUTHORITY: &str = "hysteria";
pub(crate) const URL_PATH: &str = "/auth";
pub(crate) const STATUS_AUTH_OK: u16 = 233;
pub(crate) const HEADER_AUTH: &str = "hysteria-auth";
pub(crate) const HEADER_UDP: &str = "hysteria-udp";
pub(crate) const HEADER_CC_RX: &str = "hysteria-cc-rx";
pub(crate) const HEADER_PADDING: &str = "hysteria-padding";

const MAX_ADDRESS_LENGTH: usize = 2048;
const MAX_MESSAGE_LENGTH: usize = 2048;
const MAX_PADDING_LENGTH: usize = 4096;

pub(crate) fn padding(min: usize, max: usize) -> String {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(min..max);
    (&mut rng)
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub(crate) async fn write_tcp_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    destination: &Address,
) -> Result<()> {
    let address = destination.to_string();
    if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
        return Err(Error::InvalidAddress);
    }
    let padding = padding(64, 512);
    varint::write(writer, FRAME_TYPE_TCP_REQUEST).await?;
    varint::write(writer, address.len() as u64).await?;
    writer.write_all(address.as_bytes()).await?;
    varint::write(writer, padding.len() as u64).await?;
    writer.write_all(padding.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_tcp_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Address> {
    let frame_type = varint::read(reader).await?;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        return Err(Error::Protocol(format!(
            "unexpected stream frame type {frame_type:#x}"
        )));
    }
    let address_length = varint::read(reader).await? as usize;
    if address_length == 0 || address_length > MAX_ADDRESS_LENGTH {
        return Err(Error::InvalidAddress);
    }
    let mut address = vec![0u8; address_length];
    reader.read_exact(&mut address).await?;
    let padding_length = varint::read(reader).await? as usize;
    if padding_length > MAX_PADDING_LENGTH {
        return Err(Error::Protocol("request padding is too large".into()));
    }
    let mut padding = vec![0u8; padding_length];
    reader.read_exact(&mut padding).await?;
    std::str::from_utf8(&address)
        .map_err(|_| Error::InvalidAddress)?
        .parse()
}

pub(crate) async fn write_tcp_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    result: std::result::Result<(), &str>,
) -> Result<()> {
    let (status, message) = match result {
        Ok(()) => (0, ""),
        Err(message) => (1, message),
    };
    let message = &message.as_bytes()[..message.len().min(MAX_MESSAGE_LENGTH)];
    let padding = padding(128, 1024);
    writer.write_u8(status).await?;
    varint::write(writer, message.len() as u64).await?;
    writer.write_all(message).await?;
    varint::write(writer, padding.len() as u64).await?;
    writer.write_all(padding.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_tcp_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let status = reader.read_u8().await?;
    let message_length = varint::read(reader).await? as usize;
    if message_length > MAX_MESSAGE_LENGTH {
        return Err(Error::Protocol("response message is too large".into()));
    }
    let mut message = vec![0u8; message_length];
    reader.read_exact(&mut message).await?;
    let padding_length = varint::read(reader).await? as usize;
    if padding_length > MAX_PADDING_LENGTH {
        return Err(Error::Protocol("response padding is too large".into()));
    }
    let mut padding = vec![0u8; padding_length];
    reader.read_exact(&mut padding).await?;
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "remote error: {}",
            String::from_utf8_lossy(&message)
        )))
    }
}
