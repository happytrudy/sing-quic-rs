use std::{net::SocketAddr, time::Duration};

use tokio::task::JoinHandle;

use crate::congestion::CongestionKind;

pub(crate) struct ConnectionMetricsTask(JoinHandle<()>);

impl ConnectionMetricsTask {
    pub(crate) fn spawn(
        connection: quinn::Connection,
        role: &'static str,
        peer: SocketAddr,
        congestion: CongestionKind,
    ) -> Self {
        Self(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            let mut previous = connection.stats();
            let mut previous_at = tokio::time::Instant::now();
            loop {
                interval.tick().await;
                let now = tokio::time::Instant::now();
                let elapsed = now.duration_since(previous_at).as_secs_f64().max(0.001);
                let current = connection.stats();
                let sent_bytes = current.udp_tx.bytes.saturating_sub(previous.udp_tx.bytes);
                let received_bytes = current.udp_rx.bytes.saturating_sub(previous.udp_rx.bytes);
                let sent_packets = current
                    .path
                    .sent_packets
                    .saturating_sub(previous.path.sent_packets);
                let lost_packets = current
                    .path
                    .lost_packets
                    .saturating_sub(previous.path.lost_packets);
                let lost_bytes = current
                    .path
                    .lost_bytes
                    .saturating_sub(previous.path.lost_bytes);
                let congestion_events = current
                    .path
                    .congestion_events
                    .saturating_sub(previous.path.congestion_events);
                let loss_percent = if sent_packets == 0 {
                    0.0
                } else {
                    lost_packets as f64 * 100.0 / sent_packets as f64
                };
                tracing::info!(
                    target: "sing_quic::hysteria2::metrics",
                    role,
                    %peer,
                    ?congestion,
                    rtt_ms = current.path.rtt.as_secs_f64() * 1000.0,
                    cwnd_bytes = current.path.cwnd,
                    mtu = current.path.current_mtu,
                    tx_mbps = sent_bytes as f64 * 8.0 / elapsed / 1_000_000.0,
                    rx_mbps = received_bytes as f64 * 8.0 / elapsed / 1_000_000.0,
                    sent_packets,
                    lost_packets,
                    lost_bytes,
                    loss_percent,
                    congestion_events,
                    "Hysteria2 connection metrics"
                );
                previous = current;
                previous_at = now;
                if connection.close_reason().is_some() {
                    return;
                }
            }
        }))
    }
}

impl Drop for ConnectionMetricsTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
