//! Congestion controllers used by QUIC protocols in this crate.

use std::{
    any::Any,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

const SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const WINDOW_MULTIPLIER: f64 = 2.0;
const INITIAL_WINDOW: u64 = 10_240;

/// Rate-based Brutal congestion controller configuration.
///
/// The algorithm originated in Hysteria, but this implementation is protocol
/// agnostic and can be used by any Quinn-based transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrutalConfig {
    bytes_per_second: u64,
    initial_window: u64,
}

impl BrutalConfig {
    /// Creates a controller targeting a delivered rate in bytes per second.
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            initial_window: INITIAL_WINDOW,
        }
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }

    pub fn initial_window(&mut self, bytes: u64) -> &mut Self {
        self.initial_window = bytes.max(1);
        self
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self, current_mtu, Duration::ZERO))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PacketSlot {
    timestamp: i64,
    acknowledged: u64,
    lost: u64,
}

/// Protocol-independent Brutal congestion controller.
#[derive(Clone, Debug)]
pub struct Brutal {
    config: Arc<BrutalConfig>,
    current_mtu: u64,
    slots: [PacketSlot; SLOT_COUNT],
    ack_rate: f64,
    smoothed_rtt: Duration,
    epoch: Option<Instant>,
}

impl Brutal {
    fn new(config: Arc<BrutalConfig>, current_mtu: u16, initial_rtt: Duration) -> Self {
        Self {
            config,
            current_mtu: u64::from(current_mtu),
            slots: [PacketSlot::default(); SLOT_COUNT],
            ack_rate: 1.0,
            smoothed_rtt: initial_rtt,
            epoch: None,
        }
    }

    fn timestamp(&mut self, now: Instant) -> i64 {
        let epoch = *self.epoch.get_or_insert(now);
        now.saturating_duration_since(epoch).as_secs() as i64
    }

    fn record_acknowledged(&mut self, now: Instant) {
        let timestamp = self.timestamp(now);
        let slot = &mut self.slots[timestamp as usize % SLOT_COUNT];
        if slot.timestamp == timestamp {
            slot.acknowledged += 1;
        } else {
            *slot = PacketSlot {
                timestamp,
                acknowledged: 1,
                lost: 0,
            };
        }
    }

    fn record_lost(&mut self, now: Instant, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        let timestamp = self.timestamp(now);
        let lost_packets = lost_bytes.div_ceil(self.current_mtu.max(1));
        let slot = &mut self.slots[timestamp as usize % SLOT_COUNT];
        if slot.timestamp == timestamp {
            slot.lost += lost_packets;
        } else {
            *slot = PacketSlot {
                timestamp,
                acknowledged: 0,
                lost: lost_packets,
            };
        }
    }

    fn update_ack_rate(&mut self, now: Instant) {
        let minimum_timestamp = self.timestamp(now) - SLOT_COUNT as i64;
        let (acknowledged, lost) = self
            .slots
            .iter()
            .filter(|slot| slot.timestamp >= minimum_timestamp)
            .fold((0, 0), |(acknowledged, lost), slot| {
                (acknowledged + slot.acknowledged, lost + slot.lost)
            });
        let total = acknowledged + lost;
        self.ack_rate = if total < MIN_SAMPLE_COUNT {
            1.0
        } else {
            (acknowledged as f64 / total as f64).max(MIN_ACK_RATE)
        };
    }

    fn congestion_window(&self) -> u64 {
        if self.smoothed_rtt.is_zero() {
            return self.config.initial_window.max(self.current_mtu);
        }
        let window = self.config.bytes_per_second as f64
            * self.smoothed_rtt.as_secs_f64()
            * WINDOW_MULTIPLIER
            / self.ack_rate;
        (window as u64).max(self.current_mtu)
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
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        self.record_acknowledged(now);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.update_ack_rate(now);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.record_lost(now, lost_bytes);
        self.update_ack_rate(now);
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
        self.config.initial_window.max(self.current_mtu)
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

    fn set_brutal(&self, bytes_per_second: u64, initial_rtt: Duration) {
        let mut state = self.state.lock().expect("congestion state lock");
        state.controller = Box::new(Brutal::new(
            Arc::new(BrutalConfig::new(bytes_per_second)),
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
    if bytes_per_second == 0 {
        return false;
    }
    let controller = connection.congestion_state().into_any();
    let Ok(controller) = controller.downcast::<SwitchableController>() else {
        return false;
    };
    controller.set_brutal(bytes_per_second, connection.rtt());
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
        switchable.set_brutal(1_000_000, Duration::from_millis(100));
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
    fn brutal_window_is_twice_the_target_bdp() {
        let controller = brutal(1_000_000, Duration::from_millis(100));
        assert_eq!(controller.window(), 200_000);
        assert_eq!(controller.metrics().pacing_rate, Some(8_000_000));
    }

    #[test]
    fn brutal_compensates_for_loss_and_clamps_ack_rate() {
        let mut controller = brutal(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        for _ in 0..40 {
            controller.record_acknowledged(now);
        }
        controller.on_congestion_event(now, now, false, 12_000);
        assert_eq!(controller.ack_rate, MIN_ACK_RATE);
        assert_eq!(controller.window(), 250_000);
        assert_eq!(controller.metrics().pacing_rate, Some(10_000_000));
    }

    #[test]
    fn insufficient_samples_assume_perfect_delivery() {
        let mut controller = brutal(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        controller.record_acknowledged(now);
        controller.record_lost(now, 1200);
        controller.update_ack_rate(now);
        assert_eq!(controller.ack_rate, 1.0);
    }
}
