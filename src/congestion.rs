//! Congestion controllers used by QUIC protocols in this crate.

use std::{
    any::Any,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use quinn::congestion::{
    BbrConfig, BrutalConfig, Controller, ControllerFactory, ControllerMetrics, Pacing,
};
use quinn_proto::RttEstimator;

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
        config.loss_compensation(!disable_loss_compensation);
        state.controller = Box::new(Arc::new(config).build_with_rtt(
            Instant::now(),
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
        is_ecn: bool,
        lost_bytes: u64,
        lost_packets: u64,
    ) {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .on_congestion_event(
                now,
                sent,
                is_persistent_congestion,
                is_ecn,
                lost_bytes,
                lost_packets,
            );
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

    fn pacing(&self, current_mtu: u16) -> Option<Pacing> {
        self.state
            .lock()
            .expect("congestion state lock")
            .controller
            .pacing(current_mtu)
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
}
