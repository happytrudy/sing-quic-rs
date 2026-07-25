use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Address, Error, Result};

use super::protocol::{encode_tcp_request, encode_tcp_response, read_tcp_response};

type ResponseFuture =
    Pin<Box<dyn Future<Output = (Result<()>, quinn::RecvStream)> + Send + 'static>>;

enum ReadState {
    AwaitResponse(ResponseFuture),
    Ready(quinn::RecvStream),
    Failed,
}

/// A Hysteria2 TCP stream backed directly by one QUIC bidirectional stream.
pub struct Hysteria2Stream {
    send: quinn::SendStream,
    recv: ReadState,
    write_prefix: Option<(Vec<u8>, usize)>,
    server_handshake_pending: bool,
}

impl Hysteria2Stream {
    pub(crate) fn client(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        destination: &Address,
    ) -> Result<Self> {
        let request = encode_tcp_request(destination)?;
        let response = Box::pin(async move {
            let mut recv = recv;
            let result = read_tcp_response(&mut recv).await;
            (result, recv)
        });
        Ok(Self {
            send,
            recv: ReadState::AwaitResponse(response),
            write_prefix: Some((request, 0)),
            server_handshake_pending: false,
        })
    }

    pub(crate) fn server(send: quinn::SendStream, recv: quinn::RecvStream) -> Result<Self> {
        Ok(Self {
            send,
            recv: ReadState::Ready(recv),
            write_prefix: Some((encode_tcp_response(Ok(()))?, 0)),
            server_handshake_pending: true,
        })
    }

    pub async fn handshake_success(&mut self) -> Result<()> {
        if !self.server_handshake_pending {
            return Ok(());
        }
        self.write_pending_prefix().await?;
        self.server_handshake_pending = false;
        Ok(())
    }

    pub async fn handshake_failure(&mut self, message: &str) -> Result<()> {
        if !self.server_handshake_pending {
            return Ok(());
        }
        self.write_prefix = Some((encode_tcp_response(Err(message))?, 0));
        self.write_pending_prefix().await?;
        self.send
            .finish()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        self.server_handshake_pending = false;
        Ok(())
    }

    async fn write_pending_prefix(&mut self) -> Result<()> {
        if let Some((prefix, offset)) = self.write_prefix.take() {
            self.send.write_all(&prefix[offset..]).await?;
        }
        Ok(())
    }

    fn poll_write_prefix(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let Some((prefix, offset)) = self.write_prefix.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match AsyncWrite::poll_write(Pin::new(&mut self.send), context, &prefix[*offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write Hysteria2 handshake",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    *offset += written;
                    if *offset == prefix.len() {
                        self.write_prefix = None;
                        self.server_handshake_pending = false;
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl std::fmt::Debug for Hysteria2Stream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Hysteria2Stream")
            .field("write_prefix_pending", &self.write_prefix.is_some())
            .field("server_handshake_pending", &self.server_handshake_pending)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.server_handshake_pending {
            match self.poll_write_prefix(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        loop {
            match &mut self.recv {
                ReadState::AwaitResponse(response) => match response.as_mut().poll(context) {
                    Poll::Ready((Ok(()), recv)) => self.recv = ReadState::Ready(recv),
                    Poll::Ready((Err(error), _)) => {
                        self.recv = ReadState::Failed;
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReadState::Ready(recv) => return Pin::new(recv).poll_read(context, buffer),
                ReadState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Hysteria2 handshake failed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.poll_write_prefix(context) {
            Poll::Ready(Ok(())) => {
                AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_write_prefix(context) {
            Poll::Ready(Ok(())) => AsyncWrite::poll_flush(Pin::new(&mut self.send), context),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_write_prefix(context) {
            Poll::Ready(Ok(())) => AsyncWrite::poll_shutdown(Pin::new(&mut self.send), context),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
