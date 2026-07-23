# Hysteria2 protocol

The implementation follows the Hysteria2 boundaries used by `sing-quic`.

## Connection authentication

1. Establish QUIC with TLS 1.3 and ALPN `h3`.
2. Start an HTTP/3 connection.
3. Send `POST https://hysteria/auth`.
4. Put the password in `Hysteria-Auth`.
5. Send the client receive rate in `Hysteria-CC-RX` and randomized
   `Hysteria-Padding`.
6. Accept status `233` as successful authentication.

The server responds with its receive rate in `Hysteria-CC-RX`. Each sender uses
the lower of its configured send rate and the peer receive rate. A positive
negotiated rate selects Brutal; otherwise the connection stays on the default
BBR controller.

With `ignore_client_bandwidth` and an automatic server receive rate, both sides
use BBR and the server responds with `auto`. With a fixed server receive rate,
a client that requests automatic detection is sent to the masquerade handler;
a positive client rate still negotiates Brutal. This matches `sing-quic`.

The server responds with `Hysteria-UDP: true`. TLS certificate validation is
mandatory; the client API does not expose an insecure verifier.

## TCP stream

Each proxied TCP connection uses a new QUIC bidirectional stream on the
authenticated connection. The public stream directly wraps Quinn's send and
receive halves; there is no intermediate duplex buffer or copy task. Both
endpoints use the upstream 8 MiB stream receive window and 20 MiB connection
receive window. Endpoints request 16 MiB operating-system UDP socket buffers
and report when the host limits the requested size.

Loss compensation is enabled by default and can be disabled independently on
each sender. It counts acknowledged and lost packets over five one-second
slots, starts after 50 samples, and clamps the ACK rate to at least 0.8. Brutal
uses a 10,240-byte window before an RTT sample and two bandwidth-delay products
afterward. Optional two-second connection metrics expose the
negotiated controller, RTT, congestion window, path MTU, measured throughput,
and loss.

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
directly so HTTP/3 request parsing cannot consume Hysteria2 `0x401` streams,
while continuing to process the HTTP/3 control stream.

## UDP session

UDP uses QUIC datagrams with the upstream session ID, packet ID, fragment ID,
fragment count, destination, and payload layout. Payloads are limited to 4096
bytes and fragmented to the official 1197-byte initial datagram budget. Server
sessions are released when routing ends or after the upstream five-minute
inactivity timeout.

The Hysteria2 server disables standard QUIC path management. An authenticated
packet from a changed source address updates the remote address directly while
preserving RTT, MTU, and Brutal state. Source addresses are passed to the core,
where IPv4-mapped IPv6 addresses are normalized before route matching.

## Current compatibility boundary

The authentication headers, bandwidth negotiation, BBR/Brutal selection,
custom status, QUIC varints, TCP request/response frames, address
representation, and padding ranges match upstream. The current implementation
also implements upstream UDP framing, fixed flow-control defaults, direct
server-side port rebinding, and UDP session timeout behavior. It does not yet
implement packet obfuscation, a client-side port-hopping scheduler, or realm/NAT
traversal.

# SunnyQUIC protocol

SunnyQUIC uses the same SQuic TCP and UDP framing as ShadowQUIC on top of a
normal QUIC TLS 1.3 connection with ALPN `h3`. It does not use JLS. The first
bidirectional stream carries the authentication request:

```text
0x05
SHA256(username ":" password)[0..32]
32 zero bytes
```

The 64-byte field is kept for compatibility with the upstream SunnyQUIC wire
format. The server accepts proxy streams and UDP associations only after a
matching credential has been authenticated. Authentication is independent of
the congestion controller, so either endpoint can select the shared BBR or
Brutal controller. Server certificates can be loaded from files or from the
common `certificate_provider` manager, including live provider updates.
