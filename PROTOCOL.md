# Hysteria2 TCP protocol

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

When `ignore_client_bandwidth` is enabled, the server ignores bandwidth hints,
keeps its configured non-Brutal controller, and responds with `auto` so the
client does the same. It does not reject clients based on their bandwidth
header.

The server responds with `Hysteria-UDP: false` because UDP forwarding is not
implemented yet. TLS certificate validation is mandatory; the client API does
not expose an insecure verifier.

## TCP stream

Each proxied TCP connection uses a new QUIC bidirectional stream on the
authenticated connection. The public stream directly wraps Quinn's send and
receive halves; there is no intermediate duplex buffer or copy task. Both
endpoints start with a 20 MiB connection flow-control window, then refresh the
send and receive windows once per second from the negotiated byte rate and
current RTT. The target has two BDPs of headroom, and the send window is also
kept above twice the active congestion window. Per-stream credit is governed
by the aggregate connection window. Endpoints request 16 MiB operating-system
UDP socket buffers and report when the host limits the requested size.

Loss compensation is enabled by default and can be disabled independently on
each sender. It measures acknowledged and lost bytes in one-second buckets and
updates the delivery rate using EWMA. Brutal starts from the larger of one BDP
or ten current-MTU packets. Optional two-second connection metrics expose the
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
directly so HTTP/3 request parsing cannot consume Hysteria2 `0x401` streams.

## Current compatibility boundary

The authentication headers, bandwidth negotiation, BBR/Brutal selection,
custom status, QUIC varints, TCP request/response frames, address
representation, and padding ranges match upstream. The current implementation
intentionally advertises UDP as disabled and does not implement packet
obfuscation, port hopping, or NAT traversal.
