//! Protocol-independent QUIC transport tuning.

use std::time::Duration;

use quinn::VarInt;
use tokio::task::JoinHandle;

const WINDOW_HEADROOM: u64 = 2;
const WINDOW_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const INITIAL_WINDOW_PACKETS: u64 = 10;

/// Keeps QUIC connection flow-control windows aligned with bandwidth and RTT.
pub struct AdaptiveWindowTask(JoinHandle<()>);

impl AdaptiveWindowTask {
    pub fn spawn(
        connection: quinn::Connection,
        send_bytes_per_second: u64,
        receive_bytes_per_second: u64,
        minimum_send_window: u64,
        minimum_receive_window: u64,
    ) -> Self {
        update_connection_windows(
            &connection,
            send_bytes_per_second,
            receive_bytes_per_second,
            minimum_send_window,
            minimum_receive_window,
        );
        Self(tokio::spawn(async move {
            let mut interval = tokio::time::interval(WINDOW_UPDATE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                if connection.close_reason().is_some() {
                    return;
                }
                update_connection_windows(
                    &connection,
                    send_bytes_per_second,
                    receive_bytes_per_second,
                    minimum_send_window,
                    minimum_receive_window,
                );
            }
        }))
    }
}

impl Drop for AdaptiveWindowTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn update_connection_windows(
    connection: &quinn::Connection,
    send_bytes_per_second: u64,
    receive_bytes_per_second: u64,
    minimum_send_window: u64,
    minimum_receive_window: u64,
) {
    let stats = connection.stats();
    let rtt = stats.path.rtt;
    let mtu_window = u64::from(stats.path.current_mtu).saturating_mul(INITIAL_WINDOW_PACKETS);
    let send_window = adaptive_window(send_bytes_per_second, rtt, minimum_send_window)
        .max(stats.path.cwnd.saturating_mul(WINDOW_HEADROOM))
        .max(mtu_window);
    let receive_window =
        adaptive_window(receive_bytes_per_second, rtt, minimum_receive_window).max(mtu_window);
    connection.set_send_window(send_window);
    connection.set_receive_window(VarInt::try_from(receive_window).unwrap_or(VarInt::MAX));
}

fn adaptive_window(bytes_per_second: u64, rtt: Duration, minimum: u64) -> u64 {
    let bdp = u128::from(bytes_per_second).saturating_mul(rtt.as_nanos()) / 1_000_000_000;
    let target = bdp
        .saturating_mul(u128::from(WINDOW_HEADROOM))
        .min(u128::from(u64::MAX)) as u64;
    target.max(minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_control_window_tracks_bandwidth_delay_product() {
        assert_eq!(
            adaptive_window(125_000_000, Duration::from_millis(100), 1),
            25_000_000
        );
        assert_eq!(
            adaptive_window(12_500_000, Duration::from_millis(100), 20_971_520),
            20_971_520
        );
    }
}
