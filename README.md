# sing-quic-rs

Rust QUIC protocol library for `sing-box-rs`, based on Quinn and the Hyperium
HTTP/3 implementation.

See [PROTOCOL.md](PROTOCOL.md) for the implemented wire flow and upstream
compatibility boundary.

Implemented:

- QUIC endpoint and TLS configuration
- Hysteria2 HTTP/3 authentication (`POST https://hysteria/auth`)
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
- bandwidth negotiation and Brutal/BBR selection
- port hopping and realm/NAT traversal
- TUIC v5
- legacy Hysteria v1
- custom congestion-control implementations

Unsupported capabilities are rejected by the `sing-box-rs` adapter rather than
silently mapped to a different wire protocol.

## Test

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
