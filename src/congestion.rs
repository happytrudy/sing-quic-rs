//! Congestion controllers used by QUIC protocols in this crate.

use std::{
    any::Any,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

const MIN_SAMPLE_PACKETS_PER_SECOND: u64 = 10;
const MIN_ACK_RATE: f64 = 0.8;
const LOSS_EWMA_ALPHA: f64 = 0.25;
// Upstream Hysteria uses a 2 BDP window together with an independent
// token-bucket pacer. Quinn 0.11 derives its pacing rate from cwnd / RTT, so a
// 2 BDP window would send far above the negotiated Brutal rate. One BDP keeps
// the effective rate at the negotiated target while retaining loss
// compensation through ack_rate.
const WINDOW_MULTIPLIER: f64 = 1.0;
const INITIAL_WINDOW: u64 = 10_240;
const INITIAL_WINDOW_PACKETS: u64 = 10;
const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(100);

/// Rate-based Brutal congestion controller configuration.
///
/// The algorithm originated in Hysteria, but this implementation is protocol
/// agnostic and can be used by any Quinn-based transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrutalConfig {
    bytes_per_second: u64,
    initial_window: u64,
    disable_loss_compensation: bool,
}

impl BrutalConfig {
    /// Creates a controller targeting a delivered rate in bytes per second.
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            initial_window: INITIAL_WINDOW,
            disable_loss_compensation: false,
        }
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }

    pub fn initial_window(&mut self, bytes: u64) -> &mut Self {
        self.initial_window = bytes.max(1);
        self
    }

    pub fn disable_loss_compensation(&mut self, disabled: bool) -> &mut Self {
        self.disable_loss_compensation = disabled;
        self
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self, current_mtu, Duration::ZERO))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ByteSample {
    timestamp: i64,
    acknowledged_bytes: u64,
    lost_bytes: u64,
}

/// Protocol-independent Brutal congestion controller.
#[derive(Clone, Debug)]
pub struct Brutal {
    config: Arc<BrutalConfig>,
    current_mtu: u64,
    byte_sample: Option<ByteSample>,
    ack_rate: f64,
    ack_rate_initialized: bool,
    smoothed_rtt: Duration,
    epoch: Option<Instant>,
}

impl Brutal {
    fn new(config: Arc<BrutalConfig>, current_mtu: u16, initial_rtt: Duration) -> Self {
        Self {
            config,
            current_mtu: u64::from(current_mtu),
            byte_sample: None,
            ack_rate: 1.0,
            ack_rate_initialized: false,
            smoothed_rtt: if initial_rtt.is_zero() {
                DEFAULT_INITIAL_RTT
            } else {
                initial_rtt
            },
            epoch: None,
        }
    }

    fn timestamp(&mut self, now: Instant) -> i64 {
        let epoch = *self.epoch.get_or_insert(now);
        now.saturating_duration_since(epoch).as_secs() as i64
    }

    fn advance_byte_sample(&mut self, now: Instant) {
        let timestamp = self.timestamp(now);
        if self
            .byte_sample
            .is_some_and(|sample| sample.timestamp == timestamp)
        {
            return;
        }
        if let Some(sample) = self.byte_sample.take() {
            self.apply_byte_sample(sample);
        }
        self.byte_sample = Some(ByteSample {
            timestamp,
            ..ByteSample::default()
        });
    }

    fn apply_byte_sample(&mut self, sample: ByteSample) {
        if self.config.disable_loss_compensation {
            self.ack_rate = 1.0;
            self.ack_rate_initialized = false;
            return;
        }
        let total_bytes = sample.acknowledged_bytes.saturating_add(sample.lost_bytes);
        let minimum_sample_bytes = self
            .current_mtu
            .saturating_mul(MIN_SAMPLE_PACKETS_PER_SECOND);
        if total_bytes < minimum_sample_bytes {
            return;
        }
        let sample_ack_rate =
            (sample.acknowledged_bytes as f64 / total_bytes as f64).clamp(MIN_ACK_RATE, 1.0);
        if self.ack_rate_initialized {
            self.ack_rate =
                (1.0 - LOSS_EWMA_ALPHA) * self.ack_rate + LOSS_EWMA_ALPHA * sample_ack_rate;
        } else {
            self.ack_rate = sample_ack_rate;
            self.ack_rate_initialized = true;
        }
    }

    fn record_acknowledged(&mut self, now: Instant, acknowledged_bytes: u64) {
        self.advance_byte_sample(now);
        let sample = self.byte_sample.as_mut().expect("byte sample initialized");
        sample.acknowledged_bytes = sample.acknowledged_bytes.saturating_add(acknowledged_bytes);
    }

    fn record_lost(&mut self, now: Instant, lost_bytes: u64) {
        self.advance_byte_sample(now);
        let sample = self.byte_sample.as_mut().expect("byte sample initialized");
        sample.lost_bytes = sample.lost_bytes.saturating_add(lost_bytes);
    }

    fn minimum_window(&self) -> u64 {
        self.config
            .initial_window
            .max(self.current_mtu.saturating_mul(INITIAL_WINDOW_PACKETS))
    }

    fn target_bdp(&self) -> u64 {
        (self.config.bytes_per_second as f64 * self.smoothed_rtt.as_secs_f64()) as u64
    }

    fn startup_window(&self) -> u64 {
        self.target_bdp().max(self.minimum_window())
    }

    fn congestion_window(&self) -> u64 {
        let window = self.config.bytes_per_second as f64
            * self.smoothed_rtt.as_secs_f64()
            * WINDOW_MULTIPLIER
            / self.ack_rate;
        (window as u64).max(self.minimum_window())
    }

    fn pacing_rate_bits_per_second(&self) -> u64 {
        ((self.config.bytes_per_second as f64 / self.ack_rate) * 8.0) as u64
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        self.record_acknowledged(now, bytes);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.advance_byte_sample(now);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.record_lost(now, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        self.congestion_window()
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.pacing_rate_bits_per_second());
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.startup_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Active congestion controller selected for a QUIC connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionKind {
    Bbr,
    Brutal { bytes_per_second: u64 },
}

struct SwitchState {
    controller: Box<dyn Controller>,
    kind: CongestionKind,
    current_mtu: u16,
}

/// Controller wrapper whose shared state can be switched at runtime.
struct SwitchableController {
    state: Arc<Mutex<SwitchState>>,
}

impl SwitchableController {
    fn set_bbr(&self) {
        let mut state = self.state.lock().expect("congestion state lock");
        state.controller = ControllerFactory::build(
            Arc::new(BbrConfig::default()),
            Instant::now(),
            state.current_mtu,
        );
        state.kind = CongestionKind::Bbr;
    }

    fn set_brutal(
        &self,
        bytes_per_second: u64,
        initial_rtt: Duration,
        disable_loss_compensation: bool,
    ) {
        let mut state = self.state.lock().expect("congestion state lock");
        let mut config = BrutalConfig::new(bytes_per_second);
        config.disable_loss_compensation(disable_loss_compensation);
        state.controller = Box::new(Brutal::new(
            Arc::new(config),
            state.current_mtu,
            initial_rtt,
        ));
        state.kind = CongestionKind::Brutal { bytes_per_second };
    }

    fn kind(&self) -> CongestionKind {
        self.state.lock().expect("congestion state lock").kind
    }
}

impl Clone for SwitchableController {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let mut state = self.state.lock().expect("congestion state lock");
        state.current_mtu = new_mtu;
        state.controller.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Builds controllers that start with BBR and can be switched at runtime.
#[derive(Debug, Default)]
pub struct SwitchableCongestionFactory;

impl ControllerFactory for SwitchableCongestionFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let bbr = ControllerFactory::build(Arc::new(BbrConfig::default()), now, current_mtu);
        Box::new(SwitchableController {
            state: Arc::new(Mutex::new(SwitchState {
                controller: bbr,
                kind: CongestionKind::Bbr,
                current_mtu,
            })),
        })
    }
}

/// Switches an established Quinn connection to Brutal.
pub fn configure_connection_brutal(connection: &quinn::Connection, bytes_per_second: u64) -> bool {
    configure_connection_brutal_with_options(connection, bytes_per_second, false)
}

/// Switches an established Quinn connection to Brutal with loss policy.
pub fn configure_connection_brutal_with_options(
    connection: &quinn::Connection,
    bytes_per_second: u64,
    disable_loss_compensation: bool,
) -> bool {
    if bytes_per_second == 0 {
        return false;
    }
    let controller = connection.congestion_state().into_any();
    let Ok(controller) = controller.downcast::<SwitchableController>() else {
        return false;
    };
    controller.set_brutal(
        bytes_per_second,
        connection.rtt(),
        disable_loss_compensation,
    );
    true
}

/// Switches an established Quinn connection back to BBR.
pub fn configure_connection_bbr(connection: &quinn::Connection) -> bool {
    let controller = connection.congestion_state().into_any();
    let Ok(controller) = controller.downcast::<SwitchableController>() else {
        return false;
    };
    controller.set_bbr();
    true
}

/// Returns the active controller for a switchable Quinn connection.
pub fn connection_congestion_kind(connection: &quinn::Connection) -> Option<CongestionKind> {
    connection
        .congestion_state()
        .into_any()
        .downcast::<SwitchableController>()
        .ok()
        .map(|controller| controller.kind())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brutal(bytes_per_second: u64, rtt: Duration) -> Brutal {
        Brutal::new(Arc::new(BrutalConfig::new(bytes_per_second)), 1200, rtt)
    }

    #[test]
    fn bbr_is_the_default_controller() {
        let controller =
            ControllerFactory::build(Arc::new(SwitchableCongestionFactory), Instant::now(), 1200);
        let switchable = controller
            .into_any()
            .downcast::<SwitchableController>()
            .unwrap();
        assert_eq!(switchable.kind(), CongestionKind::Bbr);
        switchable.set_brutal(1_000_000, Duration::from_millis(100), false);
        assert_eq!(
            switchable.kind(),
            CongestionKind::Brutal {
                bytes_per_second: 1_000_000
            }
        );
        switchable.set_bbr();
        assert_eq!(switchable.kind(), CongestionKind::Bbr);
    }

    #[test]
    fn brutal_window_matches_target_bdp_for_quinn_pacing() {
        let controller = brutal(1_000_000, Duration::from_millis(100));
        assert_eq!(controller.window(), 100_000);
        assert_eq!(controller.metrics().pacing_rate, Some(8_000_000));
    }

    #[test]
    fn brutal_window_does_not_collapse_below_ten_mtu_packets() {
        let controller = brutal(1_000_000, Duration::from_micros(100));
        assert_eq!(controller.window(), 12_000);
    }

    #[test]
    fn brutal_100_mbps_window_scales_across_wan_rtt() {
        let bytes_per_second = 12_500_000;
        for (rtt, expected_window) in [
            (Duration::from_millis(50), 625_000),
            (Duration::from_millis(100), 1_250_000),
            (Duration::from_millis(200), 2_500_000),
        ] {
            assert_eq!(brutal(bytes_per_second, rtt).window(), expected_window);
        }
    }

    #[test]
    fn brutal_compensates_for_loss_and_clamps_ack_rate() {
        let mut controller = brutal(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        controller.record_acknowledged(now, 48_000);
        controller.on_congestion_event(now, now, false, 12_000);
        controller.advance_byte_sample(now + Duration::from_secs(1));
        assert_eq!(controller.ack_rate, MIN_ACK_RATE);
        assert_eq!(controller.window(), 125_000);
        assert_eq!(controller.metrics().pacing_rate, Some(10_000_000));
    }

    #[test]
    fn insufficient_samples_assume_perfect_delivery() {
        let mut controller = brutal(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        controller.record_acknowledged(now, 1_000);
        controller.record_lost(now, 1_000);
        controller.advance_byte_sample(now + Duration::from_secs(1));
        assert_eq!(controller.ack_rate, 1.0);
    }

    #[test]
    fn brutal_loss_samples_use_bytes_instead_of_packet_callbacks() {
        let mut controller = brutal(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        controller.record_acknowledged(now, 54_000);
        controller.record_lost(now, 6_000);
        controller.advance_byte_sample(now + Duration::from_secs(1));
        assert_eq!(controller.ack_rate, 0.9);
    }

    #[test]
    fn brutal_loss_compensation_uses_per_second_ewma() {
        let mut controller = brutal(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        controller.record_acknowledged(now, 48_000);
        controller.record_lost(now, 12_000);
        controller.advance_byte_sample(now + Duration::from_secs(1));
        assert_eq!(controller.ack_rate, 0.8);

        controller.record_acknowledged(now + Duration::from_secs(1), 60_000);
        controller.advance_byte_sample(now + Duration::from_secs(2));
        assert!((controller.ack_rate - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn brutal_startup_window_tracks_mtu_and_initial_rtt() {
        let mut controller = brutal(1, Duration::from_millis(1));
        assert_eq!(controller.initial_window(), 12_000);
        controller.on_mtu_update(1400);
        assert_eq!(controller.initial_window(), 14_000);

        let controller = Brutal::new(Arc::new(BrutalConfig::new(1_000_000)), 1200, Duration::ZERO);
        assert_eq!(controller.initial_window(), 100_000);
    }

    #[test]
    fn brutal_can_disable_loss_compensation() {
        let mut config = BrutalConfig::new(1_000_000);
        config.disable_loss_compensation(true);
        let mut controller = Brutal::new(Arc::new(config), 1200, Duration::from_millis(100));
        let now = Instant::now();
        controller.record_acknowledged(now, 48_000);
        controller.record_lost(now, 12_000);
        controller.advance_byte_sample(now + Duration::from_secs(1));
        assert_eq!(controller.ack_rate, 1.0);
        assert_eq!(controller.window(), 100_000);
    }
}
