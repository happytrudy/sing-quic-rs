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
- official Hysteria2 8 MiB stream and 20 MiB connection flow-control windows
- Hysteria2 UDP datagrams, fragmentation, and session reuse
- SunnyQUIC native TLS authentication and shared SQuic TCP/UDP framing
- SunnyQUIC BBR and Brutal congestion-control selection
- SunnyQUIC 64-byte SHA256 credential authentication
- server-side port rebinding without resetting RTT, MTU, or congestion state
- 16 MiB UDP socket buffer requests with actual-size diagnostics
- optional loss compensation and two-second connection metrics
- endpoint shutdown and connection reuse

Not implemented yet:

- Salamander and Gecko packet obfuscation
- client-side port hopping and realm/NAT traversal
- TUIC v5
- legacy Hysteria v1

Unsupported capabilities are rejected by the `sing-box-rs` adapter rather than
silently mapped to a different wire protocol.

## Congestion control

The protocol-independent `BrutalConfig` and controller-specific pacing API live
in the local fork of official Quinn 0.12. `sing_quic::congestion` adds a shared
runtime switch that starts a connection with BBR and changes it to Brutal after
a protocol negotiates its send rate. Hysteria2 and ShadowQUIC use the same API;
TUIC, SunnyQUIC, and other Quinn-based transports can use it without depending
on Hysteria2.

Brutal uses the upstream algorithm's two-bandwidth-delay-product congestion
window together with an independent token-bucket pacer. The pacer sends at the
negotiated byte rate divided by the measured ACK rate and allows a burst of the
greater of ten MTU-sized packets or four milliseconds of traffic. Switching an
established connection preserves its measured RTT.

Hysteria2 uses the upstream 8 MiB per-stream receive window and 20 MiB
connection receive window. The protocol-independent adaptive window task
remains available to ShadowQUIC, but is not applied to Hysteria2.

Loss compensation counts acknowledged and lost packets over five one-second
slots. It starts after 50 samples and applies the upstream 0.8 ACK-rate floor.
Before an RTT sample is available the Brutal congestion window is 10,240 bytes;
afterward it uses two bandwidth-delay products adjusted by the ACK rate.
`disable_loss_compensation` is local to the sender. Connection metrics are
opt-in and report RTT, congestion window, path MTU, loss, congestion events,
and measured UDP send/receive Mbps every two seconds.

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
