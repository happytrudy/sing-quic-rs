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
- Tokio `DuplexStream` client/server API
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

Brutal implements the target window and ACK/loss compensation and reports its
target pacing rate. Quinn 0.11 only exposes that rate as a metric; its generic
pacer still derives pacing from the congestion window. Exact independent
Brutal pacing therefore requires a future Quinn/h3-quinn dependency line that
consumes controller pacing rates.

## Test

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
