# sing-quic-rs

Rust QUIC protocol library for `sing-box-rs`, based on Quinn and the Hyperium
HTTP/3 implementation.

See [PROTOCOL.md](PROTOCOL.md) for the implemented wire flow and upstream
compatibility boundary.

Implemented:

- QUIC endpoint and TLS configuration
- BBR as the default congestion controller for every endpoint
- protocol-independent Brutal congestion controller
- runtime BBR/Brutal switching for established Quinn connections
- Hysteria2 HTTP/3 authentication (`POST https://hysteria/auth`)
- Hysteria2 bidirectional bandwidth negotiation (`Hysteria-CC-RX`)
- password-to-user authentication
- Hysteria2 TCP request frame type `0x401`
- QUIC variable integer framing
- request and response padding
- multiplexed TCP streams over one authenticated QUIC connection
- direct Tokio `AsyncRead + AsyncWrite` streams over Quinn without an
  intermediate copy bridge
- adaptive QUIC flow control with a 20 MiB baseline and runtime RTT/BDP updates
- 16 MiB UDP socket buffer requests with actual-size diagnostics
- optional loss compensation and two-second connection metrics
- endpoint shutdown and connection reuse

Not implemented yet:

- Hysteria2 QUIC datagram UDP protocol and fragmentation
- Salamander and Gecko packet obfuscation
- port hopping and realm/NAT traversal
- TUIC v5
- legacy Hysteria v1

Unsupported capabilities are rejected by the `sing-box-rs` adapter rather than
silently mapped to a different wire protocol.

## Congestion control

The `sing_quic::congestion` module is independent of Hysteria2. Protocols can
install `BrutalConfig` directly as a Quinn controller factory, or install
`SwitchableCongestionFactory` to start with BBR and switch an established
connection through `configure_connection_brutal` and
`configure_connection_bbr`. This API is intended to be shared by Hysteria2,
TUIC, ShadowQUIC, SunnyQUIC, and other Quinn-based transports.

Brutal implements a Quinn-adapted target window and ACK/loss compensation.
Quinn 0.11 derives pacing from the congestion window instead of accepting a
per-connection controller rate, so the window uses one target BDP rather than
the upstream Go implementation's two BDP plus independent token-bucket pacer.
This prevents a negotiated 100 Mbps connection from being paced at several
times that rate. Exact upstream pacing can replace this adaptation when an
official Quinn API supports runtime per-connection pacing rates.

The QUIC send and connection receive windows are refreshed once per second.
They use two bandwidth-delay products of headroom, while the send window also
stays above twice the active congestion window. Stream credit is governed by
the adaptive aggregate connection window instead of imposing a second fixed
per-stream ceiling.

Loss compensation samples acknowledged and lost bytes in one-second buckets.
Each complete bucket updates the delivery rate with a 0.25 EWMA factor and an
0.8 floor. The Brutal startup window uses one target BDP and never falls below
ten current path-MTU packets. `disable_loss_compensation` is local to the
sender. Connection metrics are opt-in and report RTT, congestion window, path
MTU, loss, congestion events, and measured UDP send/receive Mbps every two
seconds.

The endpoint requests 16 MiB UDP send and receive socket buffers. Operating
systems may cap the request and the runtime logs both actual values. On Linux,
raise the host limits when the warning is present, for example:

```bash
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

## Test

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
