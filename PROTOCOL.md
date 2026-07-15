# Hysteria2 TCP protocol

The implementation follows the Hysteria2 boundaries used by `sing-quic`.

## Connection authentication

1. Establish QUIC with TLS 1.3 and ALPN `h3`.
2. Start an HTTP/3 connection.
3. Send `POST https://hysteria/auth`.
4. Put the password in `Hysteria-Auth`.
5. Send `Hysteria-CC-RX: 0` and randomized `Hysteria-Padding`.
6. Accept status `233` as successful authentication.

The server responds with `Hysteria-UDP: false` because UDP forwarding is not
implemented yet. TLS certificate validation is mandatory; the client API does
not expose an insecure verifier.

## TCP stream

Each proxied TCP connection uses a new QUIC bidirectional stream on the
authenticated connection.

```text
request:
  0x401                     QUIC varint frame type
  address length            QUIC varint
  address                   UTF-8 host:port authority
  padding length            QUIC varint
  randomized padding
  application bytes...

response:
  status                    0 = success, 1 = error
  message length            QUIC varint
  message
  padding length            QUIC varint
  randomized padding
  application bytes...
```

The HTTP/3 connection state remains alive for the lifetime of the Quinn
connection. After authentication, the server accepts raw bidirectional streams
directly so HTTP/3 request parsing cannot consume Hysteria2 `0x401` streams.

## Current compatibility boundary

The authentication headers, custom status, QUIC varints, TCP request/response
frames, address representation, and padding ranges match upstream. The current
implementation intentionally advertises UDP as disabled and does not implement
bandwidth-based congestion selection, packet obfuscation, port hopping, or NAT
traversal.

