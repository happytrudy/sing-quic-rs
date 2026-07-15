use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

const MAX: u64 = (1u64 << 62) - 1;

pub(crate) async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64> {
    let first = reader.read_u8().await?;
    let length = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..length {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

pub(crate) async fn write<W: AsyncWrite + Unpin>(writer: &mut W, value: u64) -> Result<()> {
    writer.write_all(&encode(value)?).await?;
    Ok(())
}

pub(crate) fn encode(value: u64) -> Result<Vec<u8>> {
    if value > MAX {
        return Err(Error::InvalidVarInt);
    }
    let length = match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    };
    let mut output = vec![0u8; length];
    let mut remaining = value;
    for byte in output.iter_mut().rev() {
        *byte = remaining as u8;
        remaining >>= 8;
    }
    output[0] |= match length {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_boundaries() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, MAX] {
            let encoded = encode(value).unwrap();
            let mut input = encoded.as_slice();
            assert_eq!(read(&mut input).await.unwrap(), value);
        }
        assert_eq!(encode(0x401).unwrap(), [0x44, 0x01]);
    }
}
