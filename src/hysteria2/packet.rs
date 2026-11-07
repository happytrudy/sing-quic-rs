use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc, watch};

use crate::{Address, Error, Result, varint};

const UDP_HEADER_SIZE: usize = 8;
const MAX_UDP_SIZE: usize = 4096;
const MAX_ADDRESS_LENGTH: usize = 2048;
const FRAGMENT_LIFETIME: Duration = Duration::from_secs(10);
const MAX_FRAGMENT_SETS: usize = 256;
const MAX_FRAGMENT_BYTES: usize = 1024 * 1024;
const INITIAL_UDP_MTU: usize = 1200 - 3;

#[derive(Debug)]
pub struct Hysteria2Packet {
    pub data: Vec<u8>,
    pub destination: Address,
}

#[derive(Debug)]
pub(crate) struct UdpMessage {
    pub session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    pub destination: Address,
    data: Vec<u8>,
}

#[derive(Debug)]
struct FragmentSet {
    updated_at: Instant,
    destination: Address,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Defragger {
    fragments: HashMap<u16, FragmentSet>,
    bytes: usize,
}

impl Defragger {
    fn feed(&mut self, message: UdpMessage) -> Result<Option<Hysteria2Packet>> {
        self.expire(Instant::now());
        if message.fragment_total == 0 || message.fragment_id >= message.fragment_total {
            return Ok(None);
        }
        if message.data.len() > MAX_UDP_SIZE {
            return Err(Error::Protocol(
                "Hysteria2 UDP packet exceeds 4096 bytes".into(),
            ));
        }
        if message.fragment_total == 1 {
            return Ok(Some(Hysteria2Packet {
                data: message.data,
                destination: message.destination,
            }));
        }
        let now = Instant::now();
        let total = usize::from(message.fragment_total);
        let fragment_id = usize::from(message.fragment_id);
        if !self.fragments.contains_key(&message.packet_id) {
            if self.fragments.len() >= MAX_FRAGMENT_SETS
                || self.bytes.saturating_add(message.data.len()) > MAX_FRAGMENT_BYTES
            {
                return Ok(None);
            }
            self.fragments.insert(
                message.packet_id,
                FragmentSet {
                    updated_at: now,
                    destination: message.destination.clone(),
                    parts: (0..total).map(|_| None).collect(),
                    received: 0,
                    bytes: 0,
                },
            );
        }
        let (received, empty) = {
            let fragment = self
                .fragments
                .get_mut(&message.packet_id)
                .expect("inserted fragment set");
            if fragment.parts.len() != total {
                self.bytes = self.bytes.saturating_sub(fragment.bytes);
                *fragment = FragmentSet {
                    updated_at: now,
                    destination: message.destination.clone(),
                    parts: (0..total).map(|_| None).collect(),
                    received: 0,
                    bytes: 0,
                };
            }
            fragment.updated_at = now;
            if fragment.parts[fragment_id].is_none() {
                if fragment.bytes.saturating_add(message.data.len()) > MAX_UDP_SIZE {
                    let discarded = fragment.bytes;
                    self.fragments.remove(&message.packet_id);
                    self.bytes = self.bytes.saturating_sub(discarded);
                    return Ok(None);
                }
                if self.bytes.saturating_add(message.data.len()) > MAX_FRAGMENT_BYTES {
                    (fragment.received, true)
                } else {
                    self.bytes += message.data.len();
                    fragment.bytes += message.data.len();
                    fragment.parts[fragment_id] = Some(message.data);
                    fragment.received += 1;
                    (fragment.received, false)
                }
            } else {
                (fragment.received, false)
            }
        };
        if empty {
            if received == 0 {
                self.fragments.remove(&message.packet_id);
            }
            return Ok(None);
        }
        if received != total {
            return Ok(None);
        }

        let fragment = self
            .fragments
            .remove(&message.packet_id)
            .expect("complete Hysteria2 fragment set");
        self.bytes = self.bytes.saturating_sub(fragment.bytes);
        let length = fragment
            .parts
            .iter()
            .map(|part| part.as_ref().expect("complete Hysteria2 fragment").len())
            .sum::<usize>();
        if length > MAX_UDP_SIZE {
            return Err(Error::Protocol(
                "Hysteria2 reassembled UDP packet exceeds 4096 bytes".into(),
            ));
        }
        let mut data = Vec::with_capacity(length);
        for part in fragment.parts {
            data.extend_from_slice(&part.expect("complete Hysteria2 fragment"));
        }
        Ok(Some(Hysteria2Packet {
            data,
            destination: fragment.destination,
        }))
    }

    fn expire(&mut self, now: Instant) {
        self.fragments.retain(|_, fragment| {
            let keep = now.saturating_duration_since(fragment.updated_at) <= FRAGMENT_LIFETIME;
            if !keep {
                self.bytes = self.bytes.saturating_sub(fragment.bytes);
            }
            keep
        });
    }
}

#[cfg(test)]
mod defrag_tests {
    use super::*;

    fn message(packet_id: u16, fragment_id: u8, fragment_total: u8) -> UdpMessage {
        UdpMessage {
            session_id: 1,
            packet_id,
            fragment_id,
            fragment_total,
            destination: "127.0.0.1:53".parse().unwrap(),
            data: vec![0; 1200],
        }
    }

    #[test]
    fn completed_and_expired_sets_release_accounted_bytes() {
        let mut defragger = Defragger::default();
        assert!(defragger.feed(message(1, 0, 2)).unwrap().is_none());
        assert_eq!(defragger.bytes, 1200);
        assert_eq!(
            defragger
                .feed(message(1, 1, 2))
                .unwrap()
                .unwrap()
                .data
                .len(),
            2400
        );
        assert_eq!(defragger.bytes, 0);
        defragger.feed(message(2, 0, 2)).unwrap();
        defragger.expire(Instant::now() + FRAGMENT_LIFETIME + Duration::from_secs(1));
        assert!(defragger.fragments.is_empty());
        assert_eq!(defragger.bytes, 0);
    }

    #[test]
    fn oversized_and_invalid_fragment_sets_are_discarded() {
        let mut defragger = Defragger::default();
        assert!(defragger.feed(message(1, 0, 0)).unwrap().is_none());
        assert!(defragger.feed(message(1, 1, 1)).unwrap().is_none());
        for index in 0..4 {
            assert!(defragger.feed(message(2, index, 5)).unwrap().is_none());
        }
        assert_eq!(defragger.bytes, 0);
        assert!(defragger.fragments.is_empty());
    }

    #[test]
    fn incomplete_fragment_sets_have_entry_and_byte_limits() {
        let mut defragger = Defragger::default();
        for id in 0..MAX_FRAGMENT_SETS as u16 {
            assert!(defragger.feed(message(id, 0, 255)).unwrap().is_none());
        }
        assert_eq!(defragger.fragments.len(), MAX_FRAGMENT_SETS);
        assert!(defragger.feed(message(40_000, 0, 255)).unwrap().is_none());
        assert_eq!(defragger.fragments.len(), MAX_FRAGMENT_SETS);
        assert!(defragger.bytes <= MAX_FRAGMENT_BYTES);
    }
}

#[derive(Debug)]
pub struct Hysteria2PacketConnection {
    connection: quinn::Connection,
    session_id: u32,
    next_packet_id: AtomicU32,
    incoming_sender: mpsc::Sender<Hysteria2Packet>,
    incoming: Mutex<mpsc::Receiver<Hysteria2Packet>>,
    defragger: Mutex<Defragger>,
    activity: watch::Sender<Instant>,
    released: Option<mpsc::UnboundedSender<u32>>,
}

impl Hysteria2PacketConnection {
    #[cfg(test)]
    pub(crate) fn new(connection: quinn::Connection, session_id: u32) -> Arc<Self> {
        Self::new_with_release(connection, session_id, None)
    }

    pub(crate) fn new_with_release(
        connection: quinn::Connection,
        session_id: u32,
        released: Option<mpsc::UnboundedSender<u32>>,
    ) -> Arc<Self> {
        let (incoming_sender, incoming) = mpsc::channel(64);
        let (activity, _) = watch::channel(Instant::now());
        Arc::new(Self {
            connection,
            session_id,
            next_packet_id: AtomicU32::new(0),
            incoming_sender,
            incoming: Mutex::new(incoming),
            defragger: Mutex::new(Defragger::default()),
            activity,
            released,
        })
    }

    pub(crate) async fn input(&self, message: UdpMessage) -> Result<()> {
        if let Some(packet) = self.defragger.lock().await.feed(message)? {
            let _ = self.incoming_sender.try_send(packet);
        }
        Ok(())
    }

    pub async fn send(&self, packet: Hysteria2Packet) -> Result<()> {
        if packet.data.len() > MAX_UDP_SIZE {
            return Err(Error::Protocol(
                "Hysteria2 UDP packet exceeds 4096 bytes".into(),
            ));
        }
        let packet_id = (self
            .next_packet_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            % u32::from(u16::MAX)) as u16;
        let address = packet.destination.to_string();
        if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
            return Err(Error::InvalidAddress);
        }
        let address_length = varint::encode(address.len() as u64)?;
        let header_size = UDP_HEADER_SIZE + address_length.len() + address.len();
        let max_datagram_size = self
            .connection
            .max_datagram_size()
            .map(|size| size.saturating_sub(3))
            .unwrap_or(INITIAL_UDP_MTU)
            .min(INITIAL_UDP_MTU);
        if header_size >= max_datagram_size {
            return Err(Error::Protocol(
                "Hysteria2 UDP address exceeds QUIC datagram size".into(),
            ));
        }
        let fragment_size = max_datagram_size - header_size;
        let fragment_total = packet.data.len().div_ceil(fragment_size).max(1);
        let fragment_total = u8::try_from(fragment_total)
            .map_err(|_| Error::Protocol("too many Hysteria2 UDP fragments".into()))?;

        for (fragment_id, data) in packet.data.chunks(fragment_size).enumerate() {
            let frame = encode_message(
                self.session_id,
                packet_id,
                fragment_id as u8,
                fragment_total,
                &address,
                &address_length,
                data,
            );
            self.connection
                .send_datagram(Bytes::from(frame))
                .map_err(|error| Error::Protocol(error.to_string()))?;
        }
        if packet.data.is_empty() {
            let frame = encode_message(
                self.session_id,
                packet_id,
                0,
                1,
                &address,
                &address_length,
                &[],
            );
            self.connection
                .send_datagram(Bytes::from(frame))
                .map_err(|error| Error::Protocol(error.to_string()))?;
        }
        self.activity.send_replace(Instant::now());
        Ok(())
    }

    pub async fn recv(&self) -> Result<Hysteria2Packet> {
        let mut incoming = self.incoming.lock().await;
        tokio::select! {
            packet = incoming.recv() => {
                let packet = packet.ok_or(Error::Closed)?;
                self.activity.send_replace(Instant::now());
                Ok(packet)
            },
            error = self.connection.closed() => Err(error.into()),
        }
    }

    pub async fn wait_inactive(&self, timeout: Duration) {
        let mut activity = self.activity.subscribe();
        loop {
            let deadline = tokio::time::Instant::from_std(*activity.borrow() + timeout);
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    if Instant::now().duration_since(*activity.borrow()) >= timeout {
                        return;
                    }
                }
                changed = activity.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = self.connection.closed() => return,
            }
        }
    }
}

impl Drop for Hysteria2PacketConnection {
    fn drop(&mut self) {
        if let Some(released) = &self.released {
            let _ = released.send(self.session_id);
        }
    }
}

pub(crate) fn decode_message(data: &[u8]) -> Result<UdpMessage> {
    if data.len() < UDP_HEADER_SIZE {
        return Err(Error::Protocol("truncated Hysteria2 UDP message".into()));
    }
    let session_id = u32::from_be_bytes(data[0..4].try_into().expect("session ID length"));
    let packet_id = u16::from_be_bytes(data[4..6].try_into().expect("packet ID length"));
    let fragment_id = data[6];
    let fragment_total = data[7];
    let (address_length, encoded_length) = decode_varint(&data[UDP_HEADER_SIZE..])?;
    let address_length = usize::try_from(address_length).map_err(|_| Error::InvalidAddress)?;
    if address_length == 0 || address_length > MAX_ADDRESS_LENGTH {
        return Err(Error::InvalidAddress);
    }
    let address_start = UDP_HEADER_SIZE + encoded_length;
    let address_end = address_start
        .checked_add(address_length)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| Error::Protocol("truncated Hysteria2 UDP address".into()))?;
    let destination = std::str::from_utf8(&data[address_start..address_end])
        .map_err(|_| Error::InvalidAddress)?
        .parse()?;
    Ok(UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_total,
        destination,
        data: data[address_end..].to_vec(),
    })
}

fn encode_message(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    address: &str,
    address_length: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut frame =
        Vec::with_capacity(UDP_HEADER_SIZE + address_length.len() + address.len() + data.len());
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(&packet_id.to_be_bytes());
    frame.push(fragment_id);
    frame.push(fragment_total);
    frame.extend_from_slice(address_length);
    frame.extend_from_slice(address.as_bytes());
    frame.extend_from_slice(data);
    frame
}

fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    let first = *data
        .first()
        .ok_or_else(|| Error::Protocol("missing Hysteria2 UDP address length".into()))?;
    let length = 1usize << (first >> 6);
    if data.len() < length {
        return Err(Error::Protocol(
            "truncated Hysteria2 UDP address length".into(),
        ));
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &data[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_udp_message_round_trip() {
        let address = "1.1.1.1:53";
        let address_length = varint::encode(address.len() as u64).unwrap();
        let frame = encode_message(9, 7, 0, 1, address, &address_length, b"query");
        let message = decode_message(&frame).unwrap();
        assert_eq!(message.session_id, 9);
        assert_eq!(message.packet_id, 7);
        assert_eq!(message.destination, Address::new("1.1.1.1", 53).unwrap());
        assert_eq!(message.data, b"query");
    }

    #[test]
    fn official_udp_fragments_reassemble_in_order() {
        let destination = Address::new("dns.example", 53).unwrap();
        let mut defragger = Defragger::default();
        assert!(
            defragger
                .feed(UdpMessage {
                    session_id: 1,
                    packet_id: 2,
                    fragment_id: 1,
                    fragment_total: 2,
                    destination: destination.clone(),
                    data: b"two".to_vec(),
                })
                .unwrap()
                .is_none()
        );
        let packet = defragger
            .feed(UdpMessage {
                session_id: 1,
                packet_id: 2,
                fragment_id: 0,
                fragment_total: 2,
                destination: destination.clone(),
                data: b"one".to_vec(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(packet.destination, destination);
        assert_eq!(packet.data, b"onetwo");
    }
}
