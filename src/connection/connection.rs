// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Implementation of QUIC protocol.

#![allow(unused_variables)]

use core::ops::Range;
use std::any::Any;
use std::cell::RefCell;
use std::cmp;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time;

use bytes::Bytes;
use enumflags2::bitflags;
use enumflags2::BitFlags;
use log::*;
use strum::IntoEnumIterator;

use self::cid::ConnectionIdItem;
use self::datagrams::DatagramState;
pub use self::datagrams::DatagramStats;
pub use self::datagrams::SendDatagramError;
use self::space::BufferFlags;
use self::space::BufferType;
use self::space::PacketNumSpace;
use self::space::RateSamplePacketState;
use self::space::SpaceId;
use self::stream::Stream;
use self::stream::StreamIter;
use self::timer::Timer;
use self::ConnectionFlags::*;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::error::ConnectionError;
use crate::error::Error;
use crate::frame;
use crate::frame::Frame;
use crate::multipath_scheduler::*;
use crate::packet;
use crate::packet::PacketHeader;
use crate::packet::PacketType;
#[cfg(feature = "qlog")]
use crate::qlog;
#[cfg(feature = "qlog")]
use crate::qlog::events;
use crate::tls;
use crate::tls::Keys;
use crate::tls::Level;
use crate::tls::Open;
use crate::tls::TlsSession;
use crate::token::AddressToken;
use crate::token::ResetToken;
use crate::trans_param::TransportParams;
use crate::Config;
use crate::ConnectionId;
use crate::ConnectionQueues;
use crate::Event;
use crate::EventQueue;
use crate::FourTuple;
use crate::FourTupleIter;
use crate::MultipathConfig;
use crate::PacketInfo;
use crate::PacketSendHandler;
use crate::PacketSendMeta;
use crate::PathEvent;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::Shutdown;

/// A QUIC connection.
pub struct Connection {
    /// QUIC version used for the connection.
    version: u32,

    /// Whether this is a server connection.
    is_server: bool,

    /// Connection Identifiers.
    cids: cid::ConnectionIdMgr,

    /// Packet number spaces.
    spaces: space::PacketNumSpaceMap,

    /// The path manager.
    paths: path::PathMap,

    /// Multipath scheduler for MPQUIC
    multipath_scheduler: Option<Box<dyn MultipathScheduler>>,

    /// Config for multipath scheduler
    multipath_conf: MultipathConfig,

    /// The stream manager.
    streams: stream::StreamMap,

    /// TLS session.
    tls_session: TlsSession,

    /// The crypto streams for Initial/Handshake/1RTT level, each of which
    /// starts at an offset of 0.
    crypto_streams: Rc<RefCell<CryptoStreams>>,

    /// Raw packets that were received before decryption keys are available.
    undecryptable_packets: UndecryptablePackets,

    /// Peer transport parameters.
    peer_transport_params: TransportParams,

    /// Local transport parameters.
    local_transport_params: TransportParams,

    /// Recovery and congestion control configurations.
    recovery_conf: RecoveryConfig,

    /// Error to be sent to the peer in a CONNECTION_CLOSE frame.
    local_error: Option<ConnectionError>,

    /// Error received from the peer in a CONNECTION_CLOSE frame.
    peer_error: Option<ConnectionError>,

    /// Various connection timers.
    timers: timer::TimerTable,

    /// Various connection states.
    flags: BitFlags<ConnectionFlags>,

    /// Various connection metrics.
    stats: ConnectionStats,

    /// Original destination connection ID created by the client.
    odcid: Option<ConnectionId>,

    /// Retry source connection ID from server.
    rscid: Option<ConnectionId>,

    /// For client, it is the received address token from server;
    /// For server, it is the resume address token to issue to the client.
    token: Option<Vec<u8>>,

    /// Internal Identifier of connection on the Endpoint.
    index: Option<u64>,

    /// Events to be sent to the endpoint.
    events: EventQueue,

    /// Status observed by the endpoint.
    queues: Option<Rc<RefCell<ConnectionQueues>>>,

    /// User context for the connection.
    context: Option<Box<dyn Any + Send + Sync>>,

    /// Qlog writer
    #[cfg(feature = "qlog")]
    qlog: Option<qlog::QlogWriter>,

    /// Unique trace id for debug logging
    trace_id: String,

    /// Unreliable datagram queues (RFC 9221).
    datagrams: DatagramState,

    /// Bytes of received datagrams buffered for the application.
    datagram_recv_buffer_size: usize,

    /// Bytes of datagrams queued for sending.
    datagram_send_buffer_size: usize,

    /// Sequence number of the next OBSERVED_ADDRESS frame.
    observed_addr_seq: u64,

    /// PATH_ABANDON frames still to send, by the sequence number of the
    /// DCID this endpoint used on the abandoned path.
    pending_path_abandons: VecDeque<u64>,

    /// Recent path abandon events (local and received), for the host to
    /// log: this crate's `log` records do not reach every host's logger.
    path_abandon_events: VecDeque<String>,

    /// Path lifecycle events not yet taken by the host, oldest first.
    path_events: VecDeque<crate::PathLifecycleEvent>,

    /// Serial of the next path to be created (the initial path is 0).
    next_path_serial: u64,
}

impl Connection {
    /// Create a new QUIC client connection
    #[doc(hidden)]
    pub fn new_client(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        server_name: Option<&str>,
        conf: &Config,
    ) -> Result<Self> {
        Connection::new(scid, local, remote, server_name, None, conf, false)
    }

    /// Create a new QUIC server connection
    #[doc(hidden)]
    pub fn new_server(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        token: Option<&AddressToken>,
        conf: &Config,
    ) -> Result<Self> {
        Connection::new(scid, local, remote, None, token, conf, true)
    }

    /// Create a new QUIC connection
    ///
    /// The `scid` is the local cid for the connection.
    /// The `addr_token` is optional and used to create the server connection. It
    /// is extracted from Initial packet with Token sent by the client connection.
    fn new(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        server_name: Option<&str>,
        addr_token: Option<&AddressToken>,
        conf: &Config,
        is_server: bool,
    ) -> Result<Self> {
        let trace_id = format!("{}-{}", if is_server { "SERVER" } else { "CLIENT" }, scid);

        let mut path = path::Path::new(local, remote, true, &conf.recovery, &trace_id);
        if is_server {
            // The server connection is created upon receiving an Initial packet
            // with a valid token sent by the client.
            path.verified_peer_address = addr_token.is_some();
            // The server connection assumes the peer has validate the server's
            // address implicitly.
            path.peer_verified_local_address = true;
        }

        let cid_limit = conf.local_transport_params.active_conn_id_limit as usize;
        let paths = path::PathMap::new(path, cid_limit, conf.anti_amplification_factor, is_server);

        let active_pid = paths.get_active_path_id()?;
        let reset_token = if is_server && conf.stateless_reset {
            // Note that clients cannot use the stateless_reset_token transport
            // parameter because their transport parameters do not have
            // confidentiality protection
            Some(ResetToken::generate(&conf.reset_token_key, scid).to_u128())
        } else {
            None
        };
        let cids = cid::ConnectionIdMgr::new(cid_limit, scid, active_pid, reset_token);

        let mut streams = stream::StreamMap::new(
            is_server,
            conf.max_connection_window,
            conf.max_stream_window,
            stream::StreamTransportParams::from(&conf.local_transport_params),
        );
        streams.set_trace_id(&trace_id);

        let mut tls_session = conf.new_tls_session(server_name, is_server)?;
        if let Some(tls_config_selector) = &conf.tls_config_selector {
            tls_session.set_config_selector(tls_config_selector.clone());
        }
        tls_session.set_trace_id(&trace_id);

        let mut conn = Connection {
            version: crate::QUIC_VERSION_V1,
            is_server,
            cids,
            spaces: space::PacketNumSpaceMap::new(),
            paths,
            multipath_scheduler: None,
            multipath_conf: conf.multipath.clone(),
            streams,
            tls_session,
            crypto_streams: Rc::new(RefCell::new(CryptoStreams::new())),
            undecryptable_packets: UndecryptablePackets::new(conf.max_undecryptable_packets),
            peer_transport_params: TransportParams::default(),
            local_transport_params: conf.local_transport_params.clone(),
            recovery_conf: conf.recovery.clone(),
            local_error: None,
            peer_error: None,
            timers: timer::TimerTable::default(),
            flags: BitFlags::default(),
            stats: ConnectionStats::default(),
            odcid: None,
            rscid: None,
            token: None,
            index: None,
            events: EventQueue::default(),
            queues: None,
            context: None,
            #[cfg(feature = "qlog")]
            qlog: None,
            trace_id,
            datagrams: DatagramState::default(),
            datagram_recv_buffer_size: conf.datagram_recv_buffer_size,
            datagram_send_buffer_size: conf.datagram_send_buffer_size,
            observed_addr_seq: 0,
            pending_path_abandons: VecDeque::new(),
            path_abandon_events: VecDeque::new(),
            path_events: VecDeque::new(),
            next_path_serial: 1,
        };
        conn.datagrams
            .breaker
            .set_enabled(conf.datagram_bypass_cwnd);
        conn.datagrams
            .breaker
            .set_trips(conf.datagram_bypass_breaker);

        let write_method = conn.get_write_method();
        conn.tls_session.set_write_method(write_method);

        // When advertising the enable_multipath transport parameter, the
        // endpoint MUST use non-zero source and destination CIDs.
        if conn.cids.zero_length_scid() || conn.cids.zero_length_dcid() {
            conn.local_transport_params.enable_multipath = false;
        }

        conn.local_transport_params.initial_source_connection_id = Some(conn.cids.get_scid(0)?.cid);
        if let Some(addr_token) = addr_token {
            conn.local_transport_params
                .original_destination_connection_id = addr_token.odcid;
            conn.local_transport_params.retry_source_connection_id = addr_token.rscid;
            conn.flags.insert(DidRetry);
        }
        conn.local_transport_params.stateless_reset_token = reset_token;
        conn.set_transport_params()?;

        // Derive initial secrets for the client.
        if !is_server {
            let dcid = ConnectionId::random(); // original dcid created by client
            let reset_token = conn.peer_transport_params.stateless_reset_token;
            conn.set_initial_dcid(dcid, reset_token, active_pid)?;

            conn.tls_session
                .derive_initial_secrets(&dcid, conn.version)?;
            conn.flags.insert(DerivedInitialSecrets);
        }

        if !conf.max_handshake_timeout.is_zero() {
            conn.timers.set(
                Timer::Handshake,
                time::Instant::now() + conf.max_handshake_timeout,
            );
        }

        // Prepare resume address token if needed
        if is_server {
            let token = AddressToken::new_resume_token(remote);
            if let Ok(token) = token.encode(&conf.address_token_key[0]) {
                conn.token = Some(token);
            }
        }

        Ok(conn)
    }

    /// Configure the given session data for resumption.
    pub fn set_session(&mut self, mut buf: &[u8]) -> Result<()> {
        let session_len = buf.read_u64()? as usize;
        let session_bytes = buf.read(session_len)?;
        self.tls_session.set_session(&session_bytes)?;

        let params_len = buf.read_u64()? as usize;
        let params_bytes = buf.read(params_len)?;
        let (peer_params, _) = TransportParams::decode(&params_bytes, self.is_server)?;
        self.set_peer_trans_params(peer_params)?;

        Ok(())
    }

    /// Set address token used by the client connection.
    pub fn set_token(&mut self, token: Vec<u8>) -> Result<()> {
        if self.is_server {
            return Err(Error::InvalidOperation("not a client".into()));
        }
        self.token = Some(token);
        Ok(())
    }

    /// Set keylog output to the given [`writer`]
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    pub fn set_keylog(&mut self, writer: Box<dyn std::io::Write + Send + Sync>) {
        self.tls_session.set_keylog(writer);
    }

    /// Set qlog output to the given [`writer`]
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    pub fn set_qlog(
        &mut self,
        writer: Box<dyn std::io::Write + Send + Sync>,
        title: String,
        description: String,
    ) {
        let trace = qlog::TraceSeq::new(
            Some(title.to_string()),
            Some(description.to_string()),
            None,
            qlog::VantagePoint::new(None, self.is_server),
        );
        let level = events::EventImportance::Extra;
        let mut writer = qlog::QlogWriter::new(
            Some(title),
            Some(description),
            trace,
            level,
            writer,
            time::Instant::now(),
        );
        writer.start().ok();

        // Write TransportParametersSet event to qlog
        Self::qlog_quic_params_set(
            &mut writer,
            &self.local_transport_params,
            events::Owner::Local,
            self.tls_session.cipher(),
        );

        self.qlog = Some(writer);
    }

    /// Process an incoming UDP datagram from the peer.
    ///
    /// On success the number of bytes processed is returned. On error the
    /// connection will be closed with an error code.
    #[doc(hidden)]
    pub fn recv(&mut self, buf: &mut [u8], info: &PacketInfo) -> Result<usize> {
        let len = buf.len();
        if len == 0 {
            return Err(Error::NoError);
        }

        // Check path of incoming datagram
        let pid = self.paths.get_path_id(&(info.dst, info.src)); // (local, remote)
        if pid.is_none() && !self.is_server {
            // If a client receives packets from an unknown address, it
            // discards these invalid packets.
            trace!(
                "{} client drop packet with unknown addr {:?}",
                self.trace_id,
                info
            );
            return Ok(len);
        }
        if let Some(pid) = pid {
            // Update send limit before address validation for server
            self.paths.inc_anti_ampl_limit(pid, len);
        }

        // Process each QUIC packet in the UDP datagram
        let mut left = len;
        while left > 0 {
            let read = match self.recv_packet(&mut buf[(len - left)..len], info, pid) {
                Ok(s) => s,
                Err(Error::Done) => left, // stop and skip the remaining data
                Err(e) => {
                    self.close(false, e.to_wire(), b"").ok(); // close connection
                    info!("{} recv error and close {:?}", self.trace_id, e);
                    return Err(e);
                }
            };
            left -= read;
        }

        // Try to process undecryptable packets
        if !self.is_established() {
            self.try_process_undecryptable_packets();
        }

        Ok(len - left)
    }

    /// Process an incoming QUIC packet from the peer.
    fn recv_packet(
        &mut self,
        buf: &mut [u8],
        info: &PacketInfo,
        pid: Option<usize>,
    ) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::Done);
        }
        let now = time::Instant::now();

        // Check close status of connection
        if self.is_closing() || self.is_draining() || self.is_closed() {
            return Err(Error::Done);
        }

        // Parse header of the QUIC packet
        let (mut hdr, mut read) =
            PacketHeader::from_bytes(buf, self.scid()?.len()).map_err(|_| Error::Done)?;

        // Process Version Negotiation packet
        if hdr.pkt_type == PacketType::VersionNegotiation {
            return self.process_version_negotiation(&hdr, &buf[read..], info.time);
        }

        // Process Retry packet
        if hdr.pkt_type == PacketType::Retry {
            return self.process_retry(&hdr, buf, info.time);
        }

        // Check version of packet
        if self.is_server && !self.flags.contains(DidVersionNegotiation) {
            if !crate::version_is_supported(hdr.version) {
                return Err(Error::UnknownVersion);
            }
            self.version = hdr.version;
            self.flags.insert(DidVersionNegotiation);
        }
        if hdr.pkt_type != PacketType::OneRTT && hdr.version != self.version {
            return Err(Error::Done);
        }

        // Create new path if need.
        let pid = if hdr.pkt_type == PacketType::OneRTT && self.flags.contains(HandshakeCompleted) {
            self.get_or_create_path(pid, &hdr.dcid, info, buf.len())?
        } else {
            // Use the initial path during handshake.
            self.paths.get_active_path_id()?
        };

        // Get length of packet number field and packet payload
        let length = if hdr.pkt_type == PacketType::OneRTT {
            // A packet with a short header does not include a length field, so it
            // can only be the last packet included in a UDP datagram.
            buf.len() - read
        } else {
            let mut b = &buf[read..];
            let len = b.read_varint().map_err(|_| Error::Done)?;
            read = buf.len() - b.len();
            // Make sure the length field is valid.
            if len > b.len() as u64 {
                return Err(Error::Done);
            }
            len as usize
        };
        let pkt_num_offset = read;

        // Derive initial secrets for the server
        if !self.flags.contains(DerivedInitialSecrets) {
            self.tls_session
                .derive_initial_secrets(&hdr.dcid, self.version)?;
            self.flags.insert(DerivedInitialSecrets);
        }

        // Decrypt packet header
        let key = self.tls_session.get_keys(hdr.pkt_type.to_level()?);
        let key = match &key.open {
            Some(open) => open,
            None => {
                let pkt = buf[..read + length].to_vec();
                self.try_buffer_undecryptable_packets(&hdr, pkt, info);
                return Ok(read + length);
            }
        };
        let is_encryption_disabled = self.is_encryption_disabled(hdr.pkt_type);
        packet::decrypt_header(buf, pkt_num_offset, &mut hdr, key, is_encryption_disabled)
            .map_err(|_| Error::Done)?;

        // Decode packet sequence number
        let handshake_confirmed = self.is_confirmed();
        let space_id = self.get_space_id(hdr.pkt_type, pid)?;
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        let largest_rx_pkt_num = space.largest_rx_pkt_num;
        let pkt_num = packet::decode_packet_num(largest_rx_pkt_num, hdr.pkt_num, hdr.pkt_num_len);

        if space.detect_duplicated_pkt_num(pkt_num) {
            trace!(
                "{} ignore duplicated packet {:?}:{}",
                self.trace_id,
                space_id,
                pkt_num
            );
            return Err(Error::Done);
        }

        // Select key and decrypt packet payload.
        let payload_offset = pkt_num_offset + hdr.pkt_num_len;
        let payload_len = length.checked_sub(hdr.pkt_num_len).ok_or(Error::Done)?;
        let mut cid_seq = None;
        if self.flags.contains(EnableMultipath) {
            let (seq, _) = self
                .cids
                .find_scid(&hdr.dcid)
                .ok_or(Error::InvalidState("unknown dcid".into()))?;
            cid_seq = Some(seq as u32)
        }

        let (key, attempt_key_update) = self.tls_session.select_key(
            handshake_confirmed,
            self.flags.contains(EnableMultipath),
            &hdr,
            space,
        )?;
        let mut payload = if !is_encryption_disabled {
            packet::decrypt_payload(buf, payload_offset, payload_len, cid_seq, pkt_num, key)
                .map_err(|_| Error::Done)?
        } else {
            bytes::Bytes::copy_from_slice(&buf[payload_offset..payload_offset + payload_len])
        };
        if payload.is_empty() {
            // An endpoint MUST treat receipt of a packet containing no frames as a connection error
            // of type PROTOCOL_VIOLATION.
            return Err(Error::ProtocolViolation);
        }
        read += length;

        debug!(
            "{} recv packet {:?} pn={} {:?}",
            self.trace_id,
            hdr,
            pkt_num,
            self.paths.get(pid)?
        );

        // Try to update key.
        self.tls_session.try_update_key(
            &mut self.timers,
            space,
            attempt_key_update,
            &hdr,
            now,
            self.paths.max_pto(),
        )?;

        // Update dcid for initial path
        self.try_set_dcid_for_initial_path(pid, &hdr)?;

        // Process each QUIC frame in the QUIC packet
        let mut ack_eliciting_pkt = false;
        let mut probing_pkt = true;
        #[cfg(feature = "qlog")]
        let mut qframes = vec![];

        while !payload.is_empty() {
            let (frame, len) = Frame::from_bytes(&mut payload, hdr.pkt_type)?;
            if frame.ack_eliciting() {
                ack_eliciting_pkt = true;
            }
            if !frame.probing() {
                probing_pkt = false;
            }
            #[cfg(feature = "qlog")]
            if self.qlog.is_some() {
                qframes.push(frame.to_qlog());
            }

            self.recv_frame(frame, &hdr, pid, space_id, info.time, info.recv_timestamp)?;
            let _ = payload.split_to(len);
        }

        // Write events to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            // Write TransportPacketReceived event to qlog.
            Self::qlog_quic_packet_received(qlog, &hdr, pkt_num, read, payload_len, qframes);

            // Write RecoveryMetricsUpdate event to qlog.
            if let Ok(path) = self.paths.get_mut(pid) {
                path.recovery.qlog_recovery_metrics_updated(qlog);
            }
        }

        // Process acknowledged frames.
        self.try_process_acked_frames();
        self.try_process_lost_datagrams(now);

        // The peer may issue new connection ids. If there is any path waiting
        // for a dcid, try to allocate one for it.
        self.try_allocate_cids_from_peer();

        // Update packet number space
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        if space.recv_pkt_num_need_ack.max() < Some(pkt_num) {
            space.largest_rx_pkt_time = info.time;
        }
        space.recv_pkt_num_win.insert(pkt_num);
        space.recv_pkt_num_need_ack.add_elem(pkt_num);
        space.largest_rx_pkt_num = cmp::max(space.largest_rx_pkt_num, pkt_num);
        if !probing_pkt {
            space.largest_rx_non_probing_pkt_num =
                cmp::max(space.largest_rx_non_probing_pkt_num, pkt_num);
            // TODO: try to do connection migration
        }
        if ack_eliciting_pkt {
            space.largest_rx_ack_eliciting_pkt_num =
                cmp::max(space.largest_rx_ack_eliciting_pkt_num, pkt_num);
        }

        self.try_schedule_ack_frame(space_id, pkt_num, ack_eliciting_pkt)?;

        // An endpoint restarts its idle timer when a packet from its peer is
        // received and processed successfully.
        // See RFC 9000 Section 10.1
        if let Some(idle_timeout) = self.idle_timeout() {
            self.timers.set(Timer::Idle, now + idle_timeout);
        }

        // Update statistic metrics
        self.stats.recv_count += 1;
        self.stats.recv_bytes += read as u64;
        let path = self.paths.get_mut(pid)?;
        path.on_packet_received(now);
        path.recovery.stat_recv_event(1, read as u64);

        // The successful use of Handshake packets indicates that no more
        // Initial packets need to be exchanged, as these keys can only be
        // produced after receiving all CRYPTO frames from Initial packets.
        // Thus, a server MUST discard Initial keys when it first successfully
        // processes a Handshake packet.
        // See RFC 9001 Section 4.9.3
        if self.is_server && hdr.pkt_type == PacketType::Handshake {
            self.drop_space_state(SpaceId::Initial, info.time);

            // Receipt of a packet protected with Handshake keys confirms that
            // the peer successfully processed an Initial packet. Once an
            // endpoint has successfully processed a Handshake packet from the
            // peer, it can consider the peer address to have been validated.
            // See RFC 9000 Section 8.1
            self.paths.get_mut(pid)?.verified_peer_address = true;
        }

        self.flags.insert(NeedSendAckEliciting);

        Ok(read)
    }

    /// Process an incoming QUIC frame from the peer.
    fn recv_frame(
        &mut self,
        frame: Frame,
        hdr: &PacketHeader,
        path_id: usize,
        space_id: SpaceId,
        now: time::Instant,
        recv_timestamp: Option<u64>,
    ) -> Result<()> {
        debug!("{} recv frame {:?}", self.trace_id, &frame);
        match frame {
            Frame::Paddings { .. } => (), // just ignore

            Frame::Ping { .. } => (), // just ignore

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ..
            } => {
                // ACK Delay is decoded by multiplying the value in the field
                // by 2 to the power of the ack_delay_exponent transport
                // parameter sent by the sender of the ACK frame.
                let mul = 2_u64.pow(self.peer_transport_params.ack_delay_exponent as u32);
                let ack_delay = ack_delay
                    .checked_mul(mul)
                    .ok_or(Error::FrameEncodingError)?;

                if space_id == SpaceId::Handshake {
                    self.flags.insert(PeerVerifiedInitialAddress);
                }
                if space_id == SpaceId::Data && self.is_established() {
                    self.flags.insert(PeerVerifiedInitialAddress);
                    // A client MAY consider the handshake to be confirmed when
                    // it receives an acknowledgment for a 1-RTT packet. This
                    // can be implemented by recording the lowest packet number
                    // sent with 1-RTT keys and comparing it to the Largest
                    // Acknowledged field in any received 1-RTT ACK frame
                    // See RFC 9001 Section 4.1.2
                    let space = self.spaces.get(space_id).ok_or(Error::InternalError)?;
                    if !self.is_server && ack_ranges.max() > Some(space.lowest_1rtt_pkt_num) {
                        self.flags.insert(HandshakeConfirmed);
                    }
                }

                // Process acknowledgement
                let handshake_status = self.handshake_status();
                let path = self.paths.get_mut(path_id)?;
                let (lost_pkts, lost_bytes) = path.recovery.on_ack_received(
                    &ack_ranges,
                    ack_delay,
                    space_id,
                    &mut self.spaces,
                    handshake_status,
                    #[cfg(feature = "qlog")]
                    self.qlog.as_mut(),
                    now,
                )?;
                self.stats.lost_count += lost_pkts;
                self.stats.lost_bytes += lost_bytes;
                path.on_ack_progress();
                if let Some(current) = path.check_pmtu_black_hole() {
                    debug!("{} path {:?} PMTU black hole, MTU is {} now", self.trace_id, path, current);
                }

                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                if self.flags.contains(HandshakeConfirmed) {
                    self.drop_space_state(SpaceId::Handshake, now);
                }
            }

            Frame::Crypto { offset, data, .. } => {
                let level = space_id.to_level();

                // Insert crypto data to the corresponding crypto stream.
                {
                    // Note: The crypto_streams is shared between the QUIC connection and
                    // the TLS session. It may be mutably borrowed during calling
                    // self.tls_session.read(). Do NOT mutably borrrow it again at the
                    // same scope.
                    let mut crypto_streams = self.crypto_streams.borrow_mut();
                    let crypto_stream = crypto_streams.get_mut(level)?;
                    crypto_stream.recv.write(offset, data, false)?;
                }

                // Read crypto data in order and feed it to the TLS session
                let mut crypto_buf = [0; 512];
                loop {
                    let read = {
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        let crypto_stream = crypto_streams.get_mut(level)?;
                        match crypto_stream.recv.read(&mut crypto_buf) {
                            Ok((read, _)) => read,
                            _ => break,
                        }
                    };

                    let r = self.tls_session.provide(level, &crypto_buf[..read]);
                    self.process_tls_session(r)?;
                }
            }

            Frame::HandshakeDone => {
                if self.is_server {
                    return Err(Error::ProtocolViolation);
                }
                self.flags.insert(PeerVerifiedInitialAddress);
                self.flags.insert(HandshakeConfirmed);
                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                self.drop_space_state(SpaceId::Handshake, now);
            }

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                if self.cids.zero_length_dcid() {
                    // An endpoint that is sending packets with a zero-length
                    // Destination CID MUST treat receipt of a NEW_CONNECTION_ID
                    // frame as a connection error of type PROTOCOL_VIOLATION.
                    return Err(Error::ProtocolViolation);
                }

                // Add a new dcid and retire the specified dcids
                let retired_dcids = self.cids.add_dcid(
                    conn_id,
                    seq_num,
                    u128::from_be_bytes(reset_token.0),
                    retire_prior_to,
                )?;
                self.events.add(Event::DcidAdvertised(reset_token));

                // Try to assign unused dcids to the affected paths
                for (dcid_seq, pid) in retired_dcids {
                    let path = self.paths.get_mut(pid)?;
                    if path.dcid_seq != Some(dcid_seq) {
                        continue;
                    }
                    if let Some(new_dcid_seq) = self.cids.lowest_unused_dcid_seq() {
                        path.dcid_seq = Some(new_dcid_seq);
                        self.cids.mark_dcid_used(new_dcid_seq, pid)?;
                    } else {
                        path.dcid_seq = None; // wait for a new DCID from peer
                    }
                }
            }

            Frame::RetireConnectionId { seq_num } => {
                if self.cids.zero_length_scid() {
                    // An endpoint that provides a zero-length connection ID
                    // MUST treat receipt of a RETIRE_CONNECTION_ID frame as
                    // a connection error of type PROTOCOL_VIOLATION.
                    return Err(Error::ProtocolViolation);
                }

                // Remove the connection route entry on the endpoint
                match self.cids.get_scid(seq_num) {
                    Ok(c) => self.events.add(Event::ScidRetired(c.cid)),
                    Err(_) => return Ok(()),
                };

                if let Some(pid) = self.cids.retire_scid(seq_num, &hdr.dcid)? {
                    // The path may be gone already: it drained on this end first.
                    if let Ok(path) = self.paths.get_mut(pid) {
                        if path.scid_seq == Some(seq_num) {
                            path.scid_seq = None;
                        }
                    }
                }
            }

            Frame::PathChallenge { data } => {
                self.paths.on_path_chal_received(path_id, data);
            }

            Frame::PathResponse { data } => {
                if self.paths.on_path_resp_received(path_id, data) {
                    // Notify the path event to the multipath scheduler
                    if let Some(ref mut scheduler) = self.multipath_scheduler {
                        scheduler.on_path_updated(&mut self.paths, PathEvent::Validated(path_id));
                    }
                }
            }

            // The peer stopped using the path it reached us on with our CID
            // `dcid_seq_num`; stop sending on it too, and move what is still
            // in flight there to the other paths.
            // The last path is never taken away by a PATH_ABANDON: a peer
            // closing its last path closes the connection instead, so such a
            // frame can only mean it named a path we never shared with it.
            frame::Frame::PathAbandon { dcid_seq_num, .. } => {
                let live = self.paths.iter().filter(|(_, p)| !p.is_abandoned()).count();
                let pid = self
                    .paths
                    .iter()
                    .find(|(_, p)| p.scid_seq == Some(dcid_seq_num) && !p.is_abandoned())
                    .map(|(pid, _)| pid);
                let event = format!(
                    "recv PATH_ABANDON dcid_seq {} on path {} -> local path {:?} (live {})",
                    dcid_seq_num, path_id, pid, live
                );
                self.record_path_abandon_event(event);
                match pid {
                    Some(pid) if live > 1 => self.abandon_path_by_id(pid, false)?,
                    Some(pid) => debug!(
                        "{} ignored PATH_ABANDON for its last path {}",
                        self.trace_id, pid
                    ),
                    None => {}
                }
            }

            frame::Frame::PathStatus {
                dcid_seq_num,
                seq_num,
                status,
            } => { // temparaily ignore
            }

            Frame::ObservedAddress { seq_num, addr } => {
                // An endpoint that did not ask for address reports must not
                // receive them. See draft-ietf-quic-address-discovery.
                if !self.local_transport_params.address_discovery_receives() {
                    return Err(Error::ProtocolViolation);
                }
                if self
                    .paths
                    .get_mut(path_id)?
                    .on_observed_addr_received(seq_num, addr)
                {
                    debug!(
                        "{} peer observed local address {} on path {}",
                        self.trace_id, addr, path_id
                    );
                }
            }

            Frame::Datagram { data, .. } => {
                // A DATAGRAM frame larger than the advertised limit, or any
                // DATAGRAM frame when none was advertised, is a protocol
                // violation. See RFC 9221 Section 3.
                let max_frame_size = self
                    .local_transport_params
                    .max_datagram_frame_size
                    .ok_or(Error::ProtocolViolation)?;
                let frame_len = 1 + codec::encode_varint_len(data.len() as u64) + data.len();
                if frame_len as u64 > max_frame_size {
                    return Err(Error::ProtocolViolation);
                }
                self.datagrams
                    .received(data, Some(self.datagram_recv_buffer_size), recv_timestamp)?;
            }

            Frame::NewToken { token } => {
                self.events.add(Event::NewToken(token));
            }

            // After receiving a CONNECTION_CLOSE frame, endpoints enter the
            // draining state. While otherwise identical to the closing state,
            // an endpoint in the draining state MUST NOT send any packets.
            Frame::ConnectionClose {
                error_code, reason, ..
            } => {
                self.peer_error = Some(ConnectionError {
                    is_app: false,
                    frame: None,
                    error_code,
                    reason,
                });
                let pto = self.paths.get_active_mut()?.recovery.rtt.pto_base();
                self.timers.set(Timer::Draining, now + pto * 3);
            }
            Frame::ApplicationClose { error_code, reason } => {
                self.peer_error = Some(ConnectionError {
                    is_app: true,
                    frame: None,
                    error_code,
                    reason,
                });
                let pto = self.paths.get_active_mut()?.recovery.rtt.pto_base();
                self.timers.set(Timer::Draining, now + pto * 3);
            }

            Frame::Stream {
                stream_id,
                offset,
                length,
                fin,
                data,
            } => {
                self.streams
                    .on_stream_frame_received(stream_id, offset, length, fin, data)?;
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                self.streams
                    .on_reset_stream_frame_received(stream_id, error_code, final_size)?;
            }

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                self.streams
                    .on_stop_sending_frame_received(stream_id, error_code)?;
            }

            Frame::MaxData { max } => {
                self.streams.on_max_data_frame_received(max);
            }

            Frame::MaxStreamData { stream_id, max } => {
                self.streams
                    .on_max_stream_data_frame_received(stream_id, max)?;
            }

            Frame::MaxStreams { bidi, max } => {
                self.streams.on_max_streams_frame_received(max, bidi)?;
            }

            Frame::DataBlocked { max } => {
                self.streams.on_data_blocked_frame_received(max);
            }

            Frame::StreamDataBlocked { stream_id, max } => {
                self.streams
                    .on_stream_data_blocked_frame_received(stream_id, max)?;
            }

            Frame::StreamsBlocked { bidi, max } => {
                self.streams.on_streams_blocked_frame_received(max, bidi)?;
            }
        }

        Ok(())
    }

    /// Process the incoming Version Negotiation packet.
    fn process_version_negotiation(
        &mut self,
        pkt_hdr: &PacketHeader,
        mut payload: &[u8],
        now: time::Instant,
    ) -> Result<usize> {
        // The Version Negotiation packet is a response to a client packet that
        // contains a version that is not supported by the server. It is only
        // sent by servers.
        if self.is_server {
            return Err(Error::Done);
        }

        if self.flags.contains(DidVersionNegotiation) {
            return Err(Error::Done);
        }

        // A client MUST discard any Version Negotiation packet if it has
        // received and successfully processed any other packet, including an
        // earlier Version Negotiation packet.
        if self.stats.recv_count > 0 {
            return Err(Error::Done);
        }

        // The sever must echo both CIDs gives clients some assurance that the
        // server received the packet and that the Version Negotiation packet
        // was not generated by an entity that did not observe the Initial packet.
        if pkt_hdr.dcid != self.scid()? {
            return Err(Error::Done);
        }
        if pkt_hdr.scid != self.dcid()? {
            return Err(Error::Done);
        }

        let mut found_version = 0;
        while !payload.is_empty() {
            let version = payload.read_u32().map_err(|_| Error::Done)?;
            if crate::version_is_supported(version) {
                found_version = cmp::max(found_version, version);
            }
        }

        if found_version == 0 {
            return Err(Error::UnknownVersion);
        }

        // A client MUST discard a Version Negotiation packet that lists the
        // QUIC version selected by the client.
        if found_version == self.version {
            return Err(Error::Done);
        }

        self.version = found_version;
        self.flags.insert(DidVersionNegotiation);
        self.flags.remove(GotPeerCid);

        // Reset connection state to force sending another Initial packet.
        self.drop_space_state(SpaceId::Initial, now);
        self.tls_session.clear()?;
        self.set_transport_params()?;

        // Derive Initial secrets based on the new version.
        self.tls_session
            .derive_initial_secrets(&self.dcid()?, self.version)?;
        self.tls_session.process()?;

        Err(Error::Done)
    }

    /// Process the incoming RETRY packet.
    fn process_retry(
        &mut self,
        pkt_hdr: &PacketHeader,
        pkt_buf: &mut [u8],
        now: time::Instant,
    ) -> Result<usize> {
        // The Retry packet is only sent by the server to request address
        // validation upon receiving the client's Initial packet.
        if self.is_server {
            return Err(Error::Done);
        }

        // A client MUST accept and process at most one Retry packet for each
        // connection attempt. After the client has received and processed an
        // Initial or Retry packet from the server, it MUST discard any
        // subsequent Retry packets that it receives.
        if self.flags.contains(DidRetry) {
            return Err(Error::Done);
        }

        // Clients MUST discard Retry packets that have a Retry Integrity Tag
        // that cannot be validated. This diminishes an attacker's ability to
        // inject a Retry packet and protects against accidental corruption of
        // Retry packets.
        if packet::verify_retry_integrity_tag(pkt_buf, &self.dcid()?, self.version).is_err() {
            return Err(Error::Done);
        }

        self.token.clone_from(&pkt_hdr.token);
        self.flags.insert(DidRetry);
        self.flags.remove(GotPeerCid);

        // A client sets the Destination Connection ID field of this Initial
        // packet to the value from the Source Connection ID field in the Retry
        // packet.
        self.odcid = Some(self.dcid()?);
        self.set_initial_dcid(pkt_hdr.scid, None, self.paths.get_active_path_id()?)?;
        self.rscid = Some(self.dcid()?);

        // Reset connection state to force sending another Initial packet.
        self.drop_space_state(SpaceId::Initial, now);
        self.tls_session.clear()?;

        // Changing the Destination Connection ID field also results in a
        // change to the keys used to protect the Initial packet.
        self.tls_session
            .derive_initial_secrets(&self.dcid()?, self.version)?;
        self.tls_session.process()?;

        Err(Error::Done)
    }

    /// Check and record handshake status.
    fn process_tls_session(&mut self, tls_result: Result<()>) -> Result<()> {
        if self.flags.contains(HandshakeCompleted) {
            return tls_result;
        }

        match tls_result {
            Ok(_) => (),
            Err(Error::Done) => {
                // Try to parse transport parameters as soon as the first flight data is processed.
                let peer_params = self.tls_session.peer_transport_params();
                if !self.flags.contains(AppliedPeerTransportParams) && !peer_params.is_empty() {
                    let (peer_params, _) = TransportParams::decode(peer_params, self.is_server)?;
                    self.process_peer_trans_params(peer_params)?;
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        let peer_params = self.tls_session.peer_transport_params();
        if !self.flags.contains(AppliedPeerTransportParams) && !peer_params.is_empty() {
            let (peer_params, _) = TransportParams::decode(peer_params, self.is_server)?;
            self.process_peer_trans_params(peer_params)?;
        }

        if self.tls_session.is_completed() {
            self.flags.insert(HandshakeCompleted);
            self.events.add(Event::ConnectionEstablished);
            self.timers.stop(Timer::Handshake);
            self.try_process_undecryptable_packets();

            if self.is_server {
                // The TLS handshake is considered confirmed at the server when
                // the handshake completes. The server MUST send a HANDSHAKE_DONE
                // frame as soon as the handshake is complete.
                self.flags.insert(HandshakeConfirmed);
                self.flags.insert(NeedSendHandshakeDone);

                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                self.drop_space_state(SpaceId::Handshake, time::Instant::now());
            }

            // Try to promote to multipath mode.
            if self.peer_transport_params.enable_multipath
                && self.local_transport_params.enable_multipath
            {
                // If an enable_multipath transport parameter is received and
                // the carrying packet contains a zero length connection ID,
                // the receiver MUST treat this as a connection error.
                if self.cids.zero_length_dcid() {
                    return Err(Error::MultipathProtocolViolation);
                }

                self.multipath_scheduler = Some(build_multipath_scheduler(&self.multipath_conf));
                self.paths.enable_multipath();
                self.flags.insert(EnableMultipath);
                debug!("{} enable multipath", &self.trace_id);
            }

            // Prepare for sending NEW_CONNECTION_ID/NEW_TOKEN frames.
            self.try_schedule_control_frames();
        }

        Ok(())
    }

    /// Validate and apply transport parameters advertised by the peer.
    fn process_peer_trans_params(&mut self, peer_params: TransportParams) -> Result<()> {
        // Validate cid related transport parameters
        if peer_params.initial_source_connection_id != Some(self.dcid()?) {
            return Err(Error::TransportParameterError);
        }
        if !self.is_server {
            if peer_params.original_destination_connection_id != self.odcid {
                return Err(Error::TransportParameterError);
            }
            if peer_params.retry_source_connection_id != self.rscid {
                return Err(Error::TransportParameterError);
            }
        }

        // The remote server can issue a stateless_reset_token transport parameter
        // that applies to the connection ID that it selected during the handshake.
        if let Some(reset_token) = peer_params.stateless_reset_token {
            let reset_token = ResetToken::from_u128(reset_token);
            self.events.add(Event::ResetTokenAdvertised(reset_token));
        }

        // The connection enters disable_1rtt_encryption mode
        if peer_params.disable_encryption && self.local_transport_params.disable_encryption {
            self.flags.insert(DisableEncryption);
            debug!(
                "{} encryption on 1-RTT packets has been negotiated to be disabled",
                self.trace_id
            );
        }

        self.set_peer_trans_params(peer_params)?;
        self.flags.insert(AppliedPeerTransportParams);

        // Write TransportParametersSet event to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            Self::qlog_quic_params_set(
                qlog,
                &self.peer_transport_params,
                events::Owner::Remote,
                self.tls_session.cipher(),
            );
        }

        Ok(())
    }

    /// Set transport parameters advertised by the peer
    fn set_peer_trans_params(&mut self, peer_params: TransportParams) -> Result<()> {
        trace!(
            "{} set peer transport parameters {:?}",
            self.trace_id,
            peer_params
        );

        self.streams
            .update_peer_stream_transport_params(stream::StreamTransportParams::from(&peer_params));

        let active_path = self.paths.get_active_mut()?;
        let max_ack_delay = time::Duration::from_millis(peer_params.max_ack_delay);
        active_path.recovery.max_ack_delay = max_ack_delay;

        let max_datagram_size = peer_params.max_udp_payload_size as usize;
        active_path
            .recovery
            .update_max_datagram_size(max_datagram_size, true);

        self.cids.set_scid_limit(peer_params.active_conn_id_limit);

        self.peer_transport_params = peer_params;
        Ok(())
    }

    /// Set peer context for the specific path
    pub fn set_path_peer_context<T: Any + Send + Sync>(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ctx: T,
    ) -> Result<()> {
        let path_id = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InternalError)?;

        let path = self.paths.get_mut(path_id)?;
        path.set_peer_context(ctx);
        Ok(())
    }

    /// Get peer context for the specific path
    pub fn path_peer_context(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<Option<&mut dyn Any>> {
        let path_id = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InternalError)?;

        let path = self.paths.get_mut(path_id)?;
        Ok(path.peer_context())
    }

    /// Prepare for sending NEW_CONNECTION_ID/NEW_TOKEN frames.
    fn try_schedule_control_frames(&mut self) {
        // An endpoint SHOULD ensure that its peer has a sufficient number of
        // available and unused connection IDs. An endpoint MUST NOT provide
        // more connection IDs than the peer's limit.
        let id_limit = cmp::min(
            self.peer_transport_params.active_conn_id_limit,
            crate::MAX_CID_LIMIT,
        );
        let num = (id_limit - 1) as u8;
        self.events.add(Event::ScidToAdvertise(num));

        // A server sends a NEW_TOKEN frame to provide the client with a token
        // to send in the header of an Initial packet for a future connection.
        if self.is_server && self.token.is_some() {
            self.flags.insert(NeedSendNewToken);
        }
    }

    /// Try to buffer undecryptable packets when the keys are not yet available.
    fn try_buffer_undecryptable_packets(
        &mut self,
        hdr: &PacketHeader,
        pkt: Vec<u8>,
        info: &PacketInfo,
    ) {
        if self.is_established()
            || (self.is_server
                && hdr.pkt_type != PacketType::ZeroRTT
                && hdr.pkt_type != PacketType::OneRTT)
            || (!self.is_server
                && hdr.pkt_type != PacketType::Handshake
                && hdr.pkt_type != PacketType::OneRTT)
        {
            trace!("{} drop packet {:?}", self.trace_id, hdr);
            return;
        }

        if self.undecryptable_packets.push(&hdr.pkt_type, pkt, info) {
            trace!("{} buffer undecryptable packets: {:?}", self.trace_id, hdr);
        } else {
            trace!(
                "{} key not yet available, drop packet {:?}",
                self.trace_id,
                hdr
            );
        }
    }

    /// Try to process undecryptable packets.
    fn try_process_undecryptable_packets(&mut self) {
        if self.undecryptable_packets.all_empty() {
            return;
        }

        let pkt_types = if self.is_server {
            vec![PacketType::ZeroRTT, PacketType::OneRTT]
        } else {
            vec![PacketType::Handshake, PacketType::OneRTT]
        };

        for pkt_type in pkt_types {
            if self.undecryptable_packets.is_empty(&pkt_type) {
                continue;
            }

            let level = pkt_type.to_level().unwrap();
            let key = self.tls_session.get_keys(level);
            if key.open.is_none() {
                continue;
            }

            while let Some((mut pkt, info)) = self.undecryptable_packets.pop(&pkt_type) {
                if let Err(e) = self.recv(&mut pkt, &info) {
                    error!(
                        "{} try process undecryptable packet error {:?} type {:?}",
                        self.trace_id, e, pkt_type
                    );
                }
            }
        }
    }

    /// Check and schedule an ACK frame to acknowledge incoming packets.
    fn try_schedule_ack_frame(
        &mut self,
        space_id: SpaceId,
        pkt_num: u64,
        ack_eliciting: bool,
    ) -> Result<()> {
        if !ack_eliciting {
            return Ok(());
        }

        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        if space.need_send_ack {
            return Ok(());
        }

        // An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
        // packets immediately
        if space.id == SpaceId::Initial || space.id == SpaceId::Handshake {
            space.need_send_ack = true;
            return Ok(());
        }

        // A receiver SHOULD send an ACK frame after receiving at least two
        // ack-eliciting packets.
        space.ack_eliciting_pkts_since_last_sent_ack += 1;
        let ack_eliciting_threshold = self.recovery_conf.ack_eliciting_threshold;
        if space.ack_eliciting_pkts_since_last_sent_ack >= ack_eliciting_threshold {
            space.need_send_ack = true;
            space.ack_timer = None;
            return Ok(());
        }

        // In order to assist loss detection at the sender, an endpoint SHOULD
        // generate and send an ACK frame without delay when it receives an
        // ack-eliciting packet either:
        // - when the received packet has a packet number less than another
        //   ack-eliciting packet that has been received, or
        // - when the packet has a packet number larger than the highest-numbered
        // ack-eliciting packet that has been received and there are missing
        // packets between that packet and this packet.
        if pkt_num < space.largest_rx_ack_eliciting_pkt_num
            || pkt_num > space.largest_rx_ack_eliciting_pkt_num + 1
        {
            space.need_send_ack = true;
            space.ack_timer = None;
            return Ok(());
        }

        // All ack-eliciting 0-RTT and 1-RTT packets within its advertised
        // max_ack_delay.
        if space.ack_timer.is_none() {
            let ack_delay = time::Duration::from_millis(self.peer_transport_params.max_ack_delay);
            space.ack_timer = Some(time::Instant::now() + ack_delay);
            debug!(
                "{} set ack timer for space {:?}, timeout {:?} ",
                &self.trace_id, space_id, space.ack_timer
            );
        }
        Ok(())
    }

    /// Process acknowledged frames in each packet number space
    fn try_process_acked_frames(&mut self) {
        for (_, space) in self.spaces.iter_mut() {
            for acked_frame in space.acked.drain(..) {
                match acked_frame {
                    // When a packet containing an ACK frame is acknowledged by
                    // the peer, the endpoint can stop acknowledging packets
                    // less than or equal to the Largest Acknowledged field in
                    // the sent ACK frame.
                    Frame::Ack { ack_ranges, .. } => {
                        if let Some(largest_acked) = ack_ranges.max() {
                            space.recv_pkt_num_need_ack.remove_until(largest_acked);
                        }
                    }

                    Frame::Crypto { offset, length, .. } => {
                        let level = space.id.to_level();
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        if let Ok(stream) = crypto_streams.get_mut(level) {
                            stream.send.ack_and_drop(offset, length);
                        }
                    }

                    // HandshakeDone has been successfully deliveried to client.
                    Frame::HandshakeDone => {
                        self.flags.remove(NeedSendHandshakeDone);
                        self.flags.insert(HandshakeDoneAcked);
                    }

                    Frame::Stream {
                        stream_id,
                        offset,
                        length,
                        ..
                    } => {
                        self.streams
                            .on_stream_frame_acked(stream_id, offset, length);

                        // Write QuicStreamDataMoved event to qlog
                        #[cfg(feature = "qlog")]
                        if let Some(qlog) = &mut self.qlog {
                            Self::qlog_quic_data_acked(qlog, stream_id, offset, length);
                        }
                    }

                    Frame::ResetStream { stream_id, .. } => {
                        self.streams.on_reset_stream_frame_acked(stream_id);
                    }

                    Frame::Ping {
                        pmtu_probe: Some((path_id, probe_size)),
                    } => {
                        if let Ok(path) = self.paths.get_mut(path_id) {
                            let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
                            path.dplpmtud.on_pmtu_probe_acked(probe_size, peer_mds);
                            let current = path.dplpmtud.get_current_size();
                            path.recovery.update_max_datagram_size(current, false);
                            debug!("{} path {:?} MTU is {} now", self.trace_id, path, current);
                        }
                    }

                    Frame::Datagram { .. } => {
                        self.datagrams.stats.acked += 1;
                        self.datagrams.breaker.on_acked(1);
                    }

                    _ => (),
                }
            }
        }
    }

    /// Take lost DATAGRAM frames out of every packet number space: they are
    /// never retransmitted (RFC 9221 Section 5.2). They are only counted,
    /// for the congestion window bypass circuit breaker.
    fn try_process_lost_datagrams(&mut self, now: time::Instant) {
        let mut lost = 0;
        for (_, space) in self.spaces.iter_mut() {
            space.lost.retain(|frame| {
                let is_datagram = matches!(frame, Frame::Datagram { .. });
                lost += u64::from(is_datagram);
                !is_datagram
            });
        }
        self.datagrams.stats.lost += lost;
        self.datagrams.breaker.on_lost(lost);

        let srtt = self
            .paths
            .get_active()
            .map_or(crate::INITIAL_RTT, |p| p.recovery.rtt.smoothed_rtt());
        if self.datagrams.breaker.on_tick(now, srtt) {
            warn!(
                "{} datagrams are back under the congestion window after sustained loss",
                self.trace_id
            );
        }
    }

    /// If any path doesn't has a DCID, try to allocate one for it.
    fn try_allocate_cids_from_peer(&mut self) {
        // An abandoned path will never carry data again; a CID handed to it
        // would be lost to paths that can use it.
        let paths_no_dcid = self
            .paths
            .iter_mut()
            .filter(|(_, p)| p.dcid_seq.is_none() && !p.is_abandoned());

        for (pid, path) in paths_no_dcid {
            if self.cids.zero_length_dcid() {
                path.dcid_seq = Some(0);
                continue;
            }

            let dcid_seq = match self.cids.lowest_unused_dcid_seq() {
                Some(seq) => seq,
                None => break,
            };
            let _ = self.cids.mark_dcid_used(dcid_seq, pid); // alaways success
            path.dcid_seq = Some(dcid_seq);
        }
    }

    /// Get the maximum datagram size of the given path.
    pub(crate) fn max_datagram_size(&self, pid: usize) -> usize {
        // The peer's `max_udp_payload_size` transport parameter limits the
        // size of UDP payloads that it is willing to receive. Therefore,
        // prior to receiving that parameter, we only use the default value.
        if !self.flags.contains(AppliedPeerTransportParams) {
            return crate::MIN_CLIENT_INITIAL_LEN;
        }

        // Use the validated max_datagram_size
        self.paths
            .get(pid)
            .ok()
            .map_or(crate::MIN_CLIENT_INITIAL_LEN, |path| {
                path.recovery.max_datagram_size
            })
    }

    /// Write coalesced multiple QUIC packets to the given buffer which will
    /// then be sent to the peer.
    ///
    /// The size of `out` should be at least 1200 bytes, ideally matching or
    /// exceeding the maximum possible MTU.
    ///
    /// Return Error::Done if no packet can be sent.
    ///
    /// `sender` is consulted (via `PacketSendHandler::can_send_data`) before
    /// application-data frames are written into a 1-RTT packet; it is not
    /// otherwise used to actually deliver the generated packet (that happens
    /// later, when the caller hands the returned bytes to
    /// `PacketSendHandler::on_packets_send`).
    pub(crate) fn send(
        &mut self,
        out: &mut [u8],
        sender: &dyn PacketSendHandler,
    ) -> Result<(usize, PacketInfo)> {
        if out.len() < crate::MIN_CLIENT_INITIAL_LEN {
            return Err(Error::BufferTooShort);
        }

        // Check close status of connection
        if self.is_draining() || self.is_closed() {
            return Err(Error::Done);
        }

        if !self.flags.contains(DerivedInitialSecrets) {
            return Err(Error::Done);
        }

        if !self.is_server && !self.flags.contains(InitiatedClientHandshake) {
            match self.tls_session.process() {
                Ok(_) => {}
                Err(Error::Done) => {}
                Err(e) => {
                    return Err(e);
                }
            };
            self.flags.insert(InitiatedClientHandshake);
        }

        // Process all lost frames and prepare for retransmitting
        self.process_all_lost_frames();

        // Select a path for sending a packet
        let pid = match self.select_send_path(sender) {
            Ok(pid) => pid,
            Err(Error::Done) => {
                self.mark_paths_with_nothing_to_send(sender);
                return Err(Error::Done);
            }
            Err(e) => return Err(e),
        };

        // Limit bytes sent by path MTU limit and server send limit before address validation
        let mut left = cmp::min(out.len(), self.max_datagram_size(pid));
        left = self.paths.cmp_anti_ampl_limit(pid, left);

        let mut done = 0;
        let mut send_meta = PacketSendMeta::default();

        // Write QUIC packets to the buffer
        let mut has_initial = false;
        while left > 0 {
            let (pkt_type, is_pmtu_probe, written, packet_meta) = match self.send_packet(
                &mut out[done..],
                left,
                pid,
                done == 0,
                has_initial,
                sender,
            ) {
                Ok(v) => v,
                Err(Error::BufferTooShort) | Err(Error::Done) => break,
                Err(e) => return Err(e),
            };

            send_meta.contains_data |= packet_meta.contains_data;
            send_meta.contains_ack |= packet_meta.contains_ack;
            send_meta.contains_probe |= packet_meta.contains_probe;
            send_meta.contains_path_validation |= packet_meta.contains_path_validation;
            send_meta.contains_handshake |= packet_meta.contains_handshake;
            send_meta.contains_close |= packet_meta.contains_close;
            send_meta.contains_retransmission |= packet_meta.contains_retransmission;
            send_meta.flow_hash = send_meta.flow_hash.or(packet_meta.flow_hash);

            left = left.saturating_sub(written);
            done = done.saturating_add(written);

            match pkt_type {
                PacketType::Initial => has_initial = true,

                // A packet with a short header does not include a length, so it
                // can only be the last packet included in a UDP datagram.
                PacketType::OneRTT => break,

                _ => (),
            }

            // The PMTU probe is not coalesced with other packets, since packets
            // that are larger than the current maximum datagram size are more
            // likely to be dropped by the network.
            if is_pmtu_probe {
                break;
            }
        }

        if done == 0 {
            self.mark_paths_with_nothing_to_send(sender);
            return Err(Error::Done);
        }

        // Sending UDP datagrams carrying Initial packets of this size ensures
        // that the network path supports a reasonable Path Maximum Transmission
        // Unit (PMTU), in both directions. Initial packets can even be coalesced
        // with invalid packets, which a receiver will discard.
        // See RFC 9000 Section 14.1
        if has_initial && left > 0 && done < crate::MIN_CLIENT_INITIAL_LEN {
            let pad_len = cmp::min(left, crate::MIN_CLIENT_INITIAL_LEN - done);
            out[done..done + pad_len].fill(0);
            done += pad_len;
        }

        let path = self.paths.get(pid)?;
        let info = PacketInfo {
            src: path.local_addr(),
            dst: path.remote_addr(),
            time: time::Instant::now(),
            recv_timestamp: None,
            send_meta,
        };
        Ok((done, info))
    }

    /// Write a QUIC packet to the given buffer.
    ///
    /// The `out` is the write buffer with a size that must be no less than `left`.
    /// The `left` is the upper limit for the write size when sending a non-PMTU
    /// probe packet.
    /// The `path_id` is the selected path for sending out packets.
    /// The `first` indicates that it is the first packet being written to the UDP
    /// datagram.
    /// The `has_initial` indicates that a previous Initial packet has been written
    /// the UDP datagram.
    ///
    /// Return a tuple consisting of the packet type, PMUT probe flag, and the
    /// packet size upon success.
    /// Return `Error::BufferTooShort` if the input buffer is too small to
    /// write a single QUIC packet.
    /// Return `Error::Done` if no packet can be sent.
    /// Return other Error if found unexpected error.
    fn send_packet(
        &mut self,
        out: &mut [u8],
        mut left: usize,
        path_id: usize,
        first: bool,
        has_initial: bool,
        sender: &dyn PacketSendHandler,
    ) -> Result<(PacketType, bool, usize, PacketSendMeta)> {
        let now = time::Instant::now();

        if out.len() < left {
            return Err(Error::InvalidState("buffer too short".into()));
        }

        if self.is_draining() {
            return Err(Error::Done);
        }

        // Select packet type and encryption level
        let pkt_type = self.select_send_packet_type(path_id)?;
        let level = pkt_type.to_level()?;

        // Prepare and encode packet header (except for the Length and Packet Number field)
        let space_id = self.get_space_id(pkt_type, path_id)?;
        let (pkt_num, pkt_num_len) = {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            let largest_acked = space.get_largest_acked_pkt();
            let pkt_num = space.next_pkt_num;
            let pkt_num_len = packet::packet_num_len(pkt_num, largest_acked);
            (pkt_num, pkt_num_len)
        };

        let dcid_seq = self
            .paths
            .get(path_id)?
            .dcid_seq
            .ok_or(Error::InternalError)?;
        let dcid = self.cids.get_dcid(dcid_seq)?.cid;

        let scid = if let Some(scid_seq) = self.paths.get(path_id)?.scid_seq {
            self.cids.get_scid(scid_seq)?.cid
        } else if pkt_type == PacketType::OneRTT {
            ConnectionId::default()
        } else {
            return Err(Error::InternalError);
        };

        let hdr = PacketHeader {
            pkt_type,
            version: self.version,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len,
            token: if !self.is_server && pkt_type == PacketType::Initial {
                // Note: Retry packet is not sent by send_packet()
                self.token.clone()
            } else {
                None
            },
            key_phase: self.tls_session.current_key_phase(),
        };
        let hdr_offset = hdr.to_bytes(&mut out[..left])?;

        // Check the size of remaining space of the buffer
        let mut pkt_num_offset = hdr_offset;
        if pkt_type != PacketType::OneRTT {
            pkt_num_offset += crate::LENGTH_FIELD_LEN; // Reserved for Packet length field
        }
        let crypto_overhead = self
            .tls_session
            .get_overhead(level)
            .ok_or(Error::InternalError)?;
        let total_overhead = if !self.is_encryption_disabled(hdr.pkt_type) {
            pkt_num_offset + pkt_num_len + crypto_overhead
        } else {
            pkt_num_offset + pkt_num_len
        };

        match left.checked_sub(total_overhead) {
            Some(val) => left = val,
            None => {
                return Err(Error::BufferTooShort);
            }
        }
        if left < crate::MIN_PAYLOAD_LEN {
            return Err(Error::BufferTooShort);
        }

        // Encode packet number
        let len = packet::encode_packet_num(
            pkt_num,
            pkt_num_len,
            &mut out[pkt_num_offset..pkt_num_offset + pkt_num_len],
        )?;
        let payload_offset = pkt_num_offset + len;

        // Write frames into the packet payload
        let (ack_elicit_required, is_probe) = {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            (space.need_elicit_ack(), space.loss_probes > 0)
        };
        let mut write_status = FrameWriteStatus {
            ack_elicit_required,
            is_probe,
            overhead: total_overhead,
            ..FrameWriteStatus::default()
        };

        match self.send_frames(
            &mut out[payload_offset..],
            left,
            &mut write_status,
            pkt_type,
            path_id,
            first,
            has_initial,
            sender,
        ) {
            Ok(..) => (),
            Err(Error::Done) if write_status.written > 0 => (), // at least one frame was written
            Err(e) => return Err(e),
        };

        // Fill in Length field of the packet header. This is the length of the
        // remainder of the packet (that is, the Packet Number and Payload
        // fields) in bytes
        let payload_len = write_status.written;
        if pkt_type != PacketType::OneRTT {
            // Note: This type of packet is always encrypted, even if the disable_1rtt_encryption
            // transport parameter is successfully negotiated.
            let len = pkt_num_len + payload_len + crypto_overhead;
            let mut out = &mut out[hdr_offset..];
            out.write_varint_with_len(len as u64, crate::LENGTH_FIELD_LEN)?;
        }

        // Encrypt the packet header fields and payload
        let key = self.tls_session.get_keys(pkt_type.to_level()?);
        let key = match &key.seal {
            Some(seal) => seal,
            None => return Err(Error::InternalError),
        };
        let mut cid_seq = None;
        if self.flags.contains(EnableMultipath) {
            cid_seq = Some(dcid_seq as u32);
        }

        let written = if !self.is_encryption_disabled(hdr.pkt_type) {
            packet::encrypt_packet(
                out,
                cid_seq,
                pkt_num,
                pkt_num_len,
                payload_len,
                payload_offset,
                None,
                key,
            )?
        } else {
            payload_offset + payload_len
        };

        let mut send_meta = Self::packet_send_meta(
            &write_status.frames,
            pkt_type,
            write_status.is_probe,
            write_status.contains_retransmission,
        );
        if !write_status
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::Stream { .. }))
        {
            send_meta.flow_hash = write_status.datagram_flow.flatten();
        }
        let sent_pkt = space::SentPacket {
            pkt_type,
            pkt_num,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            sent_size: written,
            ack_eliciting: write_status.ack_eliciting,
            in_flight: write_status.in_flight,
            has_data: write_status.has_data,
            pmtu_probe: write_status.is_pmtu_probe,
            pacing: write_status.pacing,
            frames: write_status.frames,
            rate_sample_state: Default::default(),
            buffer_flags: write_status.buffer_flags,
        };
        debug!(
            "{} sent packet {:?} {:?} {:?}",
            self.trace_id,
            hdr,
            &sent_pkt,
            self.paths.get(path_id)?
        );

        // Write events to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            // Write TransportPacketSent event to qlog.
            let mut qframes = Vec::with_capacity(sent_pkt.frames.len());
            for frame in &sent_pkt.frames {
                qframes.push(frame.to_qlog());
            }
            Self::qlog_quic_packet_sent(qlog, &hdr, pkt_num, written, payload_len, qframes);

            // Write RecoveryMetricsUpdate event to qlog.
            if let Ok(path) = self.paths.get_mut(path_id) {
                path.recovery.qlog_recovery_metrics_updated(qlog);
            }
        }

        // Notify the packet sent event to the multipath scheduler
        if let Some(ref mut scheduler) = self.multipath_scheduler {
            scheduler.on_sent(
                &sent_pkt,
                now,
                path_id,
                &mut self.paths,
                &mut self.spaces,
                &mut self.streams,
            );
        }

        // TODO: check app limited
        // if write_status.in_flight == true and check app limited

        let handshake_status = self.handshake_status();
        self.paths.get_mut(path_id)?.recovery.on_packet_sent(
            sent_pkt,
            space_id,
            &mut self.spaces,
            handshake_status,
            now,
        );

        if let Some(data) = write_status.challenge {
            // Record packet size and loss time if a PATH_CHALLENGE is sent.
            self.paths.on_path_chal_sent(path_id, data, written, now)?;
        }

        if write_status.is_pmtu_probe {
            self.paths
                .get_mut(path_id)?
                .dplpmtud
                .on_pmtu_probe_sent(written);
        }

        // Update connection state and statistic metrics
        self.stats.sent_count += 1;
        self.stats.sent_bytes += written as u64;
        self.paths
            .get_mut(path_id)?
            .recovery
            .stat_sent_event(1, written as u64);
        self.paths.dec_anti_ampl_limit(path_id, written);
        {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            space.next_pkt_num += 1;
            if pkt_type == PacketType::OneRTT {
                let lowest_1rtt_pkt_num = space.lowest_1rtt_pkt_num;
                space.lowest_1rtt_pkt_num = cmp::min(lowest_1rtt_pkt_num, pkt_num);
                if space.first_pkt_num_sent.is_none() {
                    space.first_pkt_num_sent = Some(pkt_num);
                }
            }
        }

        // The successful use of Handshake packets indicates that no more
        // Initial packets need to be exchanged, as these keys can only be
        // produced after receiving all CRYPTO frames from Initial packets.
        // Thus, a client MUST discard Initial keys when it first sends a
        // Handshake packet
        if !self.is_server && pkt_type == PacketType::Handshake {
            self.drop_space_state(SpaceId::Initial, now);
        }

        // An endpoint also restarts its idle timer when sending an ack-eliciting
        // packet if no other ack-eliciting packets have been sent since last
        // receiving and processing a packet.
        if write_status.ack_eliciting && !self.flags.contains(SentAckElicitingSinceRecvPkt) {
            if let Some(idle_timeout) = self.idle_timeout() {
                self.timers.set(Timer::Idle, now + idle_timeout);
            }
        }
        if write_status.ack_eliciting {
            self.flags.insert(SentAckElicitingSinceRecvPkt);
        }

        Ok((pkt_type, write_status.is_pmtu_probe, written, send_meta))
    }

    /// Write QUIC frames to the payload of a QUIC packet.
    ///
    /// The current write offset in the `out` buffer is recorded in `st.written`
    /// Return Error::Done if there is no frame to send or no left room to write more frames.
    /// Return other Error if found unexpected error.
    #[allow(clippy::too_many_arguments)]
    fn send_frames(
        &mut self,
        buf: &mut [u8],
        left: usize,
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        first: bool,
        has_initial: bool,
        sender: &dyn PacketSendHandler,
    ) -> Result<()> {
        // Write an ACK frame
        self.try_write_ack_frame(&mut buf[..left], st, pkt_type, path_id)?;

        // Write a CONNECTION_CLOSE frame
        self.try_write_close_frame(&mut buf[..left], st, pkt_type, path_id)?;

        let path = self.paths.get_mut(path_id)?;
        path.recovery.stat_cwnd_limited();

        let now = time::Instant::now();
        let r = &mut self.paths.get_mut(path_id)?.recovery;

        // Check the congestion window
        // - Packets containing frames besides ACK or CONNECTION_CLOSE frames
        // count toward congestion control limits. (RFC 9002 Section 3)
        // - Probe packets are allowed to temporarily exceed the congestion
        // window. (RFC 9002 Section 4.7)
        if !st.is_probe && !r.can_send() {
            if pkt_type == PacketType::OneRTT && self.datagrams.has_outgoing() {
                if self.datagrams.breaker.active() {
                    return self.try_write_datagrams_bypassing_cwnd(
                        buf, left, st, pkt_type, path_id, false,
                    );
                }
                // A tripped breaker or a closed window holds the bulk, not
                // the measurements of the path (`OutgoingDatagram::measurement`).
                if self.datagrams.has_measurement() {
                    return self.try_write_datagrams_bypassing_cwnd(
                        buf, left, st, pkt_type, path_id, true,
                    );
                }
            }
            return Err(Error::Done);
        }
        st.pacing = true;

        // Write PMTU probe frames
        // Note: To probe the path MTU, the write size will exceed `left` but
        // not surpass the length of `buf`.
        self.try_write_pmut_probe_frames(buf, st, pkt_type, path_id, first)?;

        // Since it's not a PMTU probe packet, let's cap the buffer size for
        // simplicity.
        let out = &mut buf[..left];

        // Write PATH_CHALLENGE/PATH_RESPONSE frames
        self.try_write_path_validation_frames(out, st, pkt_type, path_id)?;

        // Write an OBSERVED_ADDRESS frame
        self.try_write_observed_address_frame(out, st, pkt_type, path_id)?;

        // Write PATH_ABANDON frames
        self.try_write_path_abandon_frames(out, st, pkt_type, path_id)?;

        // Write NEW_CONNECTION_ID/RETRIE_CONNECTION_ID frames
        self.try_write_cid_control_frame(out, st, pkt_type, path_id)?;

        // Write a HANDSHAKE_DONE frame
        if pkt_type == PacketType::OneRTT
            && !self.is_closing()
            && self.paths.get(path_id)?.active()
            && self.need_send_handshake_done_frame()
        {
            let frame = Frame::HandshakeDone;
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.flags.remove(NeedSendHandshakeDone);
        }

        // Write stream control frames
        self.try_write_stream_control_frames(out, st, pkt_type, path_id)?;

        // Write a CRYPTO frame
        self.try_write_crypto_frame(out, st, pkt_type, path_id)?;

        // A path the schedulers hold back carries no data at all: a standby
        // (backup) path while another path is available (draft-ietf-quic-
        // multipath Section 3.3, PATH_STATUS_BACKUP; noq checks
        // `may_send_data` before every data frame), and a backed-off path,
        // whose data went to the other paths. It is still chosen to send its
        // ACKs, PINGs and probes, which is how data leaked onto it before.
        let held_back = self.paths.held_back().applies(self.paths.get(path_id)?);

        // Data gate: ask the sender whether it currently has budget for more
        // application-data bytes before writing STREAM frames -- fresh ones
        // below, and multipath buffered/retransmitted ones just above them.
        // Both write Frame::Stream and both carry line-rate application
        // bytes, so they share one gate; bypassing it for buffered frames
        // would let a paused sender keep leaking retransmitted data. This is
        // deliberately queried after ACK/CLOSE/PATH_CHALLENGE/HANDSHAKE_DONE/
        // CRYPTO are already written above in this function and before PING
        // at the bottom of it, so a closed gate still produces a
        // control-only, ack-eliciting packet (PING) instead of Error::Done
        // -- see PacketSendHandler::can_send_data.
        let mut data_gate_open = !held_back && self.data_gate_open(sender, pkt_type, path_id)?;

        // Write DATAGRAM frames. Under the bypass they go to the sender's
        // queue whatever the data gate says: that queue is where they wait
        // and are dropped (the WireGuard model, MP_FIX_PHASES.md S-I1), and
        // the gate is for congestion-controlled data (S-I12). Otherwise they
        // share the data gate, the congestion window and the pacer with
        // STREAM frames.
        if !held_back && (data_gate_open || self.datagrams.breaker.active()) {
            self.try_write_datagram_frames(out, st, pkt_type, path_id, false)?;
        } else if !held_back && self.datagrams.has_measurement() {
            self.try_write_datagram_frames(out, st, pkt_type, path_id, true)?;
        }

        // A packet holding datagrams of an application flow carries nothing
        // else, so that its flow is the packet's: a send queue below QUIC
        // (`PacketSendMeta::flow_hash`) isolates flows by packet. The STREAM
        // data waits for the next packet.
        if matches!(st.datagram_flow, Some(Some(_))) {
            data_gate_open = false;
        }

        // Write buffered frames
        if data_gate_open {
            self.try_write_buffered_frames(out, st, pkt_type, path_id)?;
        }

        // Write STREAM frames
        if data_gate_open {
            self.try_write_stream_frames(out, st, pkt_type, path_id)?;
        }

        // Write a NEW_TOKEN frame
        self.try_write_new_token_frame(out, st, pkt_type, path_id)?;

        // Write a PING frame
        if ((st.ack_elicit_required && !st.ack_eliciting)
            || self.paths.get_mut(path_id)?.need_send_ping)
            && !self.is_closing()
        {
            let frame = Frame::Ping { pmtu_probe: None };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.paths.get_mut(path_id)?.need_send_ping = false;
        }

        // No frames to be sent
        if st.frames.is_empty() {
            // TODO: set app-limited
            return Err(Error::Done);
        }

        // Write PADDING frames
        if (out.len() - st.written >= 1)
            && (
                // Expand the payload of all UDP datagrams carrying Initial packets to
                // at least the smallest allowed maximum datagram size. Sending UDP
                // datagrams of this size ensures that the network path supports a
                // reasonable Path Maximum Transmission Unit (PMTU), in both directions.
                has_initial
                // To prevent deadlock when the server reaches its anti-amplification
                // limit, clients MUST send a packet on a Probe Timeout (PTO).
                // Specifically, the client MUST send an Initial packet in a UDP datagram
                // that contains at least 1200 bytes if it does not have Handshake keys,
                // and otherwise send a Handshake packet.
                || (st.is_probe && !self.is_server && pkt_type == PacketType::Handshake)
                // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE or
                // PATH_RESPONSE frame to at least the smallest allowed maximum datagram
                // size. This verifies that the path is able to carry datagrams of this
                // size in both directions.
                || self.paths.get(path_id)?.need_expand_padding_frames(self.is_server)
            )
        {
            let frame = Frame::Paddings {
                len: out.len() - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true
        }
        if st.written < crate::MIN_PAYLOAD_LEN {
            let frame = Frame::Paddings {
                len: crate::MIN_PAYLOAD_LEN - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true
        }

        Ok(())
    }

    /// Ask the sender whether application data may be written now.
    fn data_gate_open(
        &self,
        sender: &dyn PacketSendHandler,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<bool> {
        if pkt_type != PacketType::OneRTT && pkt_type != PacketType::ZeroRTT {
            return Ok(true);
        }
        let path = self.paths.get(path_id)?;
        Ok(sender.can_send_data(
            path.local_addr(),
            path.remote_addr(),
            path.recovery.max_datagram_size,
        ))
    }

    /// Write a packet of DATAGRAM frames while the congestion window or the
    /// pacer holds the path (RFC 9484 Section 10.2). Datagrams wait and are
    /// dropped in the sender's queue below QUIC, as WireGuard's packets wait
    /// in the NIC's qdisc, not here (MP_FIX_PHASES.md S-I1); a path the
    /// schedulers hold back still carries none.
    fn try_write_datagrams_bypassing_cwnd(
        &mut self,
        buf: &mut [u8],
        left: usize,
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        only_measurement: bool,
    ) -> Result<()> {
        if self.paths.held_back().applies(self.paths.get(path_id)?) {
            return Err(Error::Done);
        }
        // Counted against the pacer, so the path's congestion-controlled
        // data waits for the share the datagrams took.
        st.pacing = true;

        let out = &mut buf[..left];
        self.try_write_datagram_frames(out, st, pkt_type, path_id, only_measurement)?;
        if st.frames.is_empty() {
            return Err(Error::Done);
        }
        if st.written < crate::MIN_PAYLOAD_LEN {
            let frame = Frame::Paddings {
                len: crate::MIN_PAYLOAD_LEN - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true;
        }
        Ok(())
    }

    /// Populate DATAGRAM frames to packet payload buffer.
    fn try_write_datagram_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        only_measurement: bool,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT
            || self.is_closing()
            || !self.datagrams.has_outgoing()
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }

        // Never keep a datagram queued that can no longer be sent.
        if let Some(max) = self.dgram_max_writable_len() {
            self.datagrams.drop_oversized(max);
        }

        // With several paths each flow's datagrams keep one path (S-I5/I6).
        let now = time::Instant::now();
        let flow_path = if self.flags.contains(EnableMultipath) {
            Some(self.datagram_flow_paths(now))
        } else {
            None
        };

        loop {
            let room = out.len() - st.written;
            let d = match &flow_path {
                Some(flow_path) => self.datagrams.pop_fitting_for_path(
                    room,
                    &mut st.datagram_flow,
                    only_measurement,
                    |flow| flow_path.get(&flow) == Some(&path_id),
                ),
                None => self.datagrams.pop_fitting_in_packet(
                    room,
                    &mut st.datagram_flow,
                    only_measurement,
                ),
            };
            let Some(d) = d else {
                break;
            };
            self.datagrams.flow_paths.on_sent(d.flow, now);
            let frame = Frame::Datagram { data: d.data };
            st.written += frame.to_bytes(&mut out[st.written..])?;
            // The payload is not kept: datagrams are never retransmitted,
            // the frame is only counted when acknowledged or lost.
            st.frames.push(Frame::Datagram { data: Bytes::new() });
            st.ack_eliciting = true;
            st.in_flight = true;
        }
        Ok(())
    }

    /// Whether this endpoint reports observed addresses to the peer.
    fn observed_address_reporting(&self) -> bool {
        self.flags.contains(AppliedPeerTransportParams)
            && self.local_transport_params.address_discovery_provides()
            && self.peer_transport_params.address_discovery_receives()
    }

    /// Populate an OBSERVED_ADDRESS frame to packet payload buffer if the
    /// peer's address on the path has not been reported yet.
    fn try_write_observed_address_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT
            || self.is_closing()
            || !self.observed_address_reporting()
        {
            return Ok(());
        }
        let path = self.paths.get(path_id)?;
        if !path.need_report_observed_addr() {
            return Ok(());
        }

        let frame = Frame::ObservedAddress {
            seq_num: self.observed_addr_seq,
            addr: path.remote_addr(),
        };
        Connection::write_frame_to_packet(frame, out, st)?;
        st.ack_eliciting = true;
        st.in_flight = true;
        self.observed_addr_seq += 1;
        self.paths.get_mut(path_id)?.on_observed_addr_reported();
        Ok(())
    }

    /// Populate pending PATH_ABANDON frames, on any path still in use.
    fn try_write_path_abandon_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT
            || self.is_closing()
            || self.pending_path_abandons.is_empty()
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }
        while let Some(&dcid_seq_num) = self.pending_path_abandons.front() {
            let frame = Frame::PathAbandon {
                dcid_seq_num,
                error_code: 0,
                reason: Vec::new(),
            };
            if frame.wire_len() > out.len().saturating_sub(st.written) {
                break;
            }
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.pending_path_abandons.pop_front();

            // The path this frame is about drains from now on.
            let pid = self
                .paths
                .iter()
                .find(|(_, p)| p.dcid_seq == Some(dcid_seq_num) && p.is_abandoned())
                .map(|(pid, _)| pid);
            if let Some(pid) = pid {
                self.start_path_drain(pid, time::Instant::now());
            }
        }
        Ok(())
    }

    /// Write PATH_RESPONSE/PATH_CHALLENGE frames if needed.
    fn try_write_path_validation_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT {
            return Ok(());
        }

        // Create PATH_RESPONSE frame if needed.
        while let Some(challenge) = self.paths.get_mut(path_id)?.pop_recv_chal() {
            let frame = Frame::PathResponse { data: challenge };

            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
        }

        // Create PATH_CHALLENGE frame if needed.
        if self.paths.get(path_id)?.path_chal_initiated() {
            let data = rand::random::<u64>().to_be_bytes();
            let frame = Frame::PathChallenge { data };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            st.challenge = Some(data);
        }

        Ok(())
    }

    /// Write PMTU probe frames if needed.
    fn try_write_pmut_probe_frames(
        &mut self,
        buf: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        first: bool,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT
            || !self.flags.contains(HandshakeCompleted)
            || self.is_closing()
            || !first
            || !st.frames.is_empty()
        {
            return Ok(());
        }

        let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
        let path = self.paths.get_mut(path_id)?;
        let probe_size = path.dplpmtud.get_probe_size(peer_mds);
        if !path.validated()
            || !path.dplpmtud.should_probe()
            || probe_size > buf.len()
            || (probe_size as u64) > path.recovery.congestion.congestion_window()
            || path.recovery.congestion.in_recovery(time::Instant::now())
        {
            return Ok(());
        }

        // The content of the PMTU probe is limited to PING and PADDING frames.
        let frame = frame::Frame::Ping {
            pmtu_probe: Some((path_id, probe_size)),
        };
        Connection::write_frame_to_packet(frame, buf, st)?;

        let padding_len = probe_size - st.overhead - 1;
        let frame = frame::Frame::Paddings { len: padding_len };
        Connection::write_frame_to_packet(frame, buf, st)?;

        st.ack_eliciting = true;
        st.in_flight = true;
        st.is_pmtu_probe = true;

        // Finish writing the datagram to prevent it from coalescing with other
        // QUIC packets.
        Err(Error::Done)
    }

    /// Populate Acknowledgement frame to packet payload buffer.
    fn try_write_ack_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        let is_closing = self.is_closing();
        let space_id = self.get_space_id(pkt_type, path_id)?;
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;

        if space.recv_pkt_num_need_ack.is_empty()
            || !space.need_send_ack
            || is_closing
            || !self.paths.get(path_id)?.can_send_ack()
        {
            return Ok(());
        }

        // Create ACK frame if needed.
        let ack_delay_exp = self.local_transport_params.ack_delay_exponent as u32;
        let ack_delay = space.largest_rx_pkt_time.elapsed();
        let ack_delay = ack_delay.as_micros() as u64 / 2_u64.pow(ack_delay_exp);
        let frame = Frame::Ack {
            ack_delay,
            ack_ranges: space.recv_pkt_num_need_ack.clone(),
            ecn_counts: None, // ECN not supported
        };
        Connection::write_frame_to_packet(frame, out, st)?;
        space.need_send_ack = false;
        space.ack_eliciting_pkts_since_last_sent_ack = 0;

        Ok(())
    }

    /// Populate Connection ID control frames to packet payload buffer.
    fn try_write_cid_control_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }

        // Create NEW_CONNECTION_ID frames as needed.
        while let Some(seq) = self.cids.next_scid_to_advertise() {
            let frame = self.cids.create_new_connection_id_frame(seq)?;

            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.cids.mark_scid_to_advertise(seq, false);
        }

        if !self.paths.get(path_id)?.active() {
            return Ok(());
        }

        // Create RETIRE_CONNECTION_ID frames as needed.
        while let Some(seq) = self
            .cids
            .next_dcid_to_retire_except(self.paths.get(path_id)?.dcid_seq)
        {
            // The sequence number specified in a RETIRE_CONNECTION_ID frame
            // MUST NOT refer to the Destination Connection ID field of the
            // packet in which the frame is contained: such a CID waits for a
            // packet on another path.

            let frame = Frame::RetireConnectionId { seq_num: seq };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.cids.mark_dcid_to_retire(seq, false);

            if let Ok(cid) = self.cids.get_dcid(seq) {
                if let Some(token) = cid.reset_token {
                    let token = ResetToken(token.to_be_bytes());
                    self.events.add(Event::DcidRetired(token));
                }
            }
        }

        Ok(())
    }

    /// Populate Stream control frames to packet payload buffer.
    fn try_write_stream_control_frames(
        &mut self,
        buf: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // STREAM control frames can only be sent in 1-RTT packet.
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }

        let path = self.paths.get(path_id)?;
        if !path.active() {
            return Ok(());
        }

        let now = time::Instant::now();

        // Create MAX_STREAMS frame if needed.
        for bidi in &[true, false] {
            if self.streams.should_update_local_max_streams(*bidi) {
                let frame = frame::Frame::MaxStreams {
                    bidi: *bidi,
                    max: self.streams.max_streams_next(*bidi),
                };

                Connection::write_frame_to_packet(frame, buf, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                // Apply the new max_streams limit.
                self.streams.update_local_max_streams(*bidi);
            }
        }

        // Create DATA_BLOCKED frame if needed.
        if let Some(blocked_at) = self.streams.data_blocked_at() {
            let frame = frame::Frame::DataBlocked { max: blocked_at };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            // Clear the data_blocked state.
            self.streams.update_data_blocked_at(None);
        }

        // Create MAX_STREAM_DATA frames if needed.
        for stream_id in self.streams.almost_full() {
            let stream = match self.streams.get_mut(stream_id) {
                Some(v) => v,

                None => {
                    // The stream closed, remove it from the almost full set.
                    self.streams.mark_almost_full(stream_id, false);
                    continue;
                }
            };

            // Adjust the stream window size automatically.
            stream
                .recv
                .autotune_window(now, path.recovery.rtt.smoothed_rtt());

            let frame = frame::Frame::MaxStreamData {
                stream_id,
                max: stream.recv.max_data_next(),
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            let recv_win = stream.recv.window();
            // Apply the new flow control limit.
            stream.recv.update_max_data(now);
            self.streams.mark_almost_full(stream_id, false);

            // Ensure that the connection window always has some room
            // compared to the stream window.
            self.streams.ensure_window_lower_bound(
                (recv_win as f64 * crate::CONNECTION_WINDOW_FACTOR) as u64,
            );

            // When MAX_STREAM_DATA is sent, trigger MAX_DATA as well to avoid a
            // potential race condition.
            self.streams.rx_almost_full = true
        }

        // Create MAX_DATA frame if needed.
        if self.streams.need_send_max_data() {
            // Adjust the connection window size automatically.
            self.streams
                .autotune_window(now, path.recovery.rtt.smoothed_rtt());

            let frame = frame::Frame::MaxData {
                max: self.streams.max_rx_data_next(),
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.rx_almost_full = false;
            // Apply the new flow control limit.
            self.streams.update_max_rx_data(now);
        }

        // Create STOP_SENDING frames if needed.
        for (stream_id, error_code) in self
            .streams
            .stopped()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StopSending {
                stream_id,
                error_code,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_stopped(stream_id, false, 0);
        }

        // Create RESET_STREAM frames if needed.
        for (stream_id, (error_code, final_size)) in self
            .streams
            .reset()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, (u64, u64))>>()
        {
            let frame = frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_reset(stream_id, false, 0, 0);
        }

        // Create STREAM_DATA_BLOCKED frames if needed.
        for (stream_id, limit) in self
            .streams
            .blocked()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StreamDataBlocked {
                stream_id,
                max: limit,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_blocked(stream_id, false, 0);
        }

        // Create STREAMS_BLOCKED frames if needed.
        for bidi in &[true, false] {
            if let Some(streams_blocked_at) = self.streams.streams_blocked_at(*bidi) {
                let frame = frame::Frame::StreamsBlocked {
                    bidi: *bidi,
                    max: streams_blocked_at,
                };

                Connection::write_frame_to_packet(frame, buf, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                // Clear the streams_blocked state.
                self.streams.update_streams_blocked_at(*bidi, None);
            }
        }

        Ok(())
    }

    /// Populate ConnectionClose frame to packet payload buffer.
    fn try_write_close_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // CONNECTION_CLOSE should be sent on the active path or the last available path.
        if !self.paths.get(path_id)?.active() && self.paths.len() > 1 {
            return Ok(());
        }

        if let Some(ref e) = self.local_error {
            let frame = if !e.is_app {
                Some(Frame::ConnectionClose {
                    error_code: e.error_code,
                    frame_type: 0,
                    reason: e.reason.clone(),
                })
            } else if pkt_type == PacketType::OneRTT || pkt_type == PacketType::ZeroRTT {
                // The application-specific variant of CONNECTION_CLOSE can
                // only be sent using 0-RTT or 1-RTT packets.
                // RFC 9000 Section 19.19
                Some(Frame::ApplicationClose {
                    error_code: e.error_code,
                    reason: e.reason.clone(),
                })
            } else {
                None
            };

            if let Some(frame) = frame {
                Connection::write_frame_to_packet(frame, out, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                let pto = self.paths.get(path_id)?.recovery.rtt.pto_base();
                let draining_timeout = time::Instant::now() + pto * 3;
                self.timers.set(Timer::Draining, draining_timeout);
            }
        }

        Ok(())
    }

    /// Populate Crypto frame to packet payload buffer.
    fn try_write_crypto_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // The CRYPTO frame is used to transmit cryptographic handshake messages
        // and can be sent in all packet types except 0-RTT.
        if pkt_type == PacketType::ZeroRTT {
            return Ok(());
        }

        let level = pkt_type.to_level()?;
        let mut crypto_streams = self.crypto_streams.borrow_mut();
        let stream = crypto_streams.get_mut(level)?;
        let out = &mut out[st.written..];

        if !(stream.is_sendable()
            && out.len() > frame::MAX_CRYPTO_OVERHEAD
            && !self.is_closing()
            && self.paths.get(path_id)?.active())
        {
            return Ok(());
        }

        let crypto_off = stream.send.send_off();
        let frame_hdr_len = frame::crypto_header_wire_len(crypto_off);
        if out.len() <= frame_hdr_len {
            return Ok(());
        }

        let (frame_data_len, _, retransmission) = stream
            .send
            .read_with_retransmission(&mut out[frame_hdr_len..])?;
        frame::encode_crypto_header(crypto_off, frame_data_len as u64, out)?;
        st.written += frame_hdr_len + frame_data_len;
        st.frames.push(Frame::Crypto {
            offset: crypto_off,
            length: frame_data_len,
            data: Bytes::default(),
        });
        st.ack_eliciting = true;
        st.in_flight = true;
        st.has_data = true;
        st.contains_retransmission |= retransmission;

        Ok(())
    }

    /// Populate Stream frame to packet payload buffer.
    fn try_write_stream_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        let out = &mut out[st.written..];
        if (pkt_type != PacketType::OneRTT && pkt_type != PacketType::ZeroRTT)
            || self.is_closing()
            || out.len() <= frame::MAX_STREAM_OVERHEAD
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }

        let mut len = 0;
        let mut cap: usize = out.len();

        while let Some(stream_id) = self.streams.peek_sendable() {
            let stream = match self.streams.get_mut(stream_id) {
                // We should not send frames for streams that were already stopped.
                Some(s) if !s.send.is_stopped() => s,
                _ => {
                    self.streams.remove_sendable();
                    continue;
                }
            };

            // Get the lowest offset of data to be sent.
            let stream_off = stream.send.send_off();

            // Encode stream frame, instead of create a `frame::Frame::Stream`,
            // encode the data into the packet buffer directly.
            //
            // 1. Reserve some space in the output buffer for writing
            // the frame header.
            // 2. Read the data from the stream's SendBuf.
            // 3. encode the frame header with the updated frame header segments.
            let frame_hdr_len = frame::stream_header_wire_len(stream_id, stream_off);

            // Read stream data and write into the packet buffer directly.
            let (frame_data_len, fin, retransmission) = stream
                .send
                .read_with_retransmission(&mut out[len + frame_hdr_len..])?;

            // Retain stream data if needed.
            let data = if self.flags.contains(EnableMultipath)
                && buffer_required(self.multipath_conf.multipath_algorithm)
            {
                let start = len + frame_hdr_len;
                Bytes::copy_from_slice(&out[start..start + frame_data_len])
            } else {
                Bytes::new()
            };

            frame::encode_stream_header(
                stream_id,
                stream_off,
                frame_data_len as u64,
                fin,
                &mut out[len..len + frame_hdr_len],
            )?;

            let frame_len = frame_hdr_len + frame_data_len;
            st.written += frame_len;
            len += frame_len;
            cap -= frame_len;

            st.ack_eliciting = true;
            st.in_flight = true;
            st.has_data = true;
            st.contains_retransmission |= retransmission;
            st.frames.push(Frame::Stream {
                stream_id,
                offset: stream_off,
                length: frame_data_len,
                fin,
                data,
            });

            // If the stream is no longer sendable, remove it from the queue
            if !stream.is_sendable() {
                self.streams.remove_sendable();
            }

            // If the buffer is too short, we won't attempt to write any more stream frames into it.
            if cap <= frame::MAX_STREAM_OVERHEAD {
                break;
            }
        }

        Ok(())
    }

    /// Populate NewToken frame to packet payload buffer.
    fn try_write_new_token_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if !(pkt_type == PacketType::OneRTT
            && self.is_server
            && self.token.is_some()
            && !self.is_closing()
            && self.paths.get(path_id)?.active()
            && self.flags.contains(NeedSendNewToken))
        {
            return Ok(());
        }

        let frame = Frame::NewToken {
            token: self.token.clone().unwrap(), // always success
        };

        Connection::write_frame_to_packet(frame, out, st)?;
        st.ack_eliciting = true;
        st.in_flight = true;
        self.flags.remove(NeedSendNewToken);

        Ok(())
    }

    /// Populate buffered frame to packet payload buffer.
    fn try_write_buffered_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Ok(());
        }

        let path = self.paths.get(path_id)?;
        if pkt_type != PacketType::OneRTT
            || self.is_closing()
            || out.len() - st.written <= frame::MAX_STREAM_OVERHEAD
            || !path.active()
        {
            return Ok(());
        }

        // Get buffered frames on the path.
        let space = self
            .spaces
            .get_mut(path.space_id)
            .ok_or(Error::InternalError)?;
        if space.buffered.is_empty() {
            return Ok(());
        }
        debug!(
            "{} try to write buffered frames: path_id={} frames={}",
            self.trace_id,
            path_id,
            space.buffered.len()
        );

        while let Some((frame, buffer_type)) = space.buffered.pop_front() {
            match frame {
                Frame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    data,
                } => {
                    let stream = match self.streams.get_mut(stream_id) {
                        Some(v) => v,
                        _ => continue,
                    };

                    // Check acked range and write the first non-acked subrange
                    let range = offset..offset + length as u64;
                    if let Some(r) = stream.send.filter_acked(range) {
                        let data_len = Self::write_buffered_stream_frame_to_packet(
                            stream_id,
                            r.start,
                            fin && r.end == offset + length as u64,
                            data.slice((r.start - offset) as usize..(r.end - offset) as usize),
                            out,
                            buffer_type,
                            st,
                        )?;

                        // Processing the following subrange.
                        if r.start + (data_len as u64) < offset + length as u64 {
                            let tail_len =
                                (offset + length as u64 - r.start - data_len as u64) as usize;
                            let frame = Frame::Stream {
                                stream_id,
                                offset: r.start + data_len as u64,
                                length: tail_len,
                                fin,
                                data: data.slice(length - tail_len..),
                            };
                            space.buffered.push_front(frame, buffer_type);
                        }

                        if data_len == 0 {
                            break;
                        }
                    }
                }

                // Ignore other buffered frames.
                _ => continue,
            }
        }

        Ok(())
    }

    fn write_buffered_stream_frame_to_packet(
        stream_id: u64,
        offset: u64,
        mut fin: bool,
        mut data: Bytes,
        out: &mut [u8],
        buffer_type: BufferType,
        st: &mut FrameWriteStatus,
    ) -> Result<usize> {
        let out = &mut out[st.written..];
        if out.len() <= frame::MAX_STREAM_OVERHEAD {
            return Ok(0);
        }

        let hdr_len = frame::stream_header_wire_len(stream_id, offset);
        let data_len = cmp::min(data.len(), out.len() - hdr_len);
        if data_len < data.len() {
            data.truncate(data_len);
            fin = false;
        }

        frame::encode_stream_header(stream_id, offset, data_len as u64, fin, out)?;
        out[hdr_len..hdr_len + data.len()].copy_from_slice(&data);

        st.written += hdr_len + data_len;
        st.ack_eliciting = true;
        st.in_flight = true;
        st.has_data = true;
        st.buffer_flags.mark(buffer_type);
        st.frames.push(Frame::Stream {
            stream_id,
            offset,
            length: data.len(),
            fin,
            data,
        });
        Ok(data_len)
    }

    /// Populate a QUIC frame to the give buffer.
    fn write_frame_to_packet(
        frame: Frame,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
    ) -> Result<()> {
        // Check whether there is enough room to write the frame.
        if st.written + frame.wire_len() > out.len() {
            return Err(Error::Done);
        }

        st.written += frame.to_bytes(&mut out[st.written..])?;
        st.frames.push(frame);
        Ok(())
    }

    /// Convert the frame list produced before encryption into the stable metadata
    /// exposed to the socket backend. This is deliberately adjacent to packet
    /// composition: downstream code must never infer control semantics from
    /// encrypted wire bytes.
    fn packet_send_meta(
        frames: &[Frame],
        pkt_type: PacketType,
        is_probe: bool,
        contains_retransmission: bool,
    ) -> PacketSendMeta {
        let mut meta = PacketSendMeta {
            contains_handshake: pkt_type != PacketType::OneRTT,
            contains_probe: is_probe,
            contains_retransmission,
            ..PacketSendMeta::default()
        };
        for frame in frames {
            match frame {
                // Only application STREAM bytes consume the data allowance. QUIC
                // CRYPTO frames carry handshake state and must remain eligible for
                // the bounded control reserve while application data is paused.
                Frame::Stream { .. } | Frame::Datagram { .. } => meta.contains_data = true,
                Frame::Crypto { .. } | Frame::HandshakeDone => meta.contains_handshake = true,
                Frame::Ack { .. } => meta.contains_ack = true,
                Frame::PathChallenge { .. } | Frame::PathResponse { .. } => {
                    meta.contains_path_validation = true
                }
                Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. } => {
                    meta.contains_close = true
                }
                Frame::Ping { pmtu_probe } => meta.contains_probe |= pmtu_probe.is_some(),
                _ => {}
            }
        }
        meta
    }

    /// Check whether a HANDHSAKE_DONE frame should be sent.
    fn need_send_handshake_done_frame(&self) -> bool {
        self.is_server && self.is_established() && self.flags.contains(NeedSendHandshakeDone)
    }

    /// Check whether a NEW_TOKEN frame should be sent.
    fn need_send_new_token_frame(&self) -> bool {
        self.is_server && self.is_established() && self.flags.contains(NeedSendNewToken)
    }

    /// Process lost frames in all packet number spaces and prepare for retransmitting
    ///
    /// QUIC packets that are determined to be lost are not retransmitted whole.
    /// The same applies to the frames that are contained within lost packets.
    /// Instead, the information that might be carried in frames is sent again
    /// in new frames as needed.
    /// See RFC 9000 Section 13.3
    fn process_all_lost_frames(&mut self) {
        for (_, space) in self.spaces.iter_mut() {
            for lost_frame in space.lost.drain(..) {
                match lost_frame {
                    // ACK frames carry the most recent set of acknowledgments and
                    // the acknowledgment delay from the largest acknowledged packet
                    Frame::Ack { .. } => {
                        space.need_send_ack = true;
                    }

                    // The HANDSHAKE_DONE frame MUST be retransmitted until it
                    // is acknowledged.
                    Frame::HandshakeDone if !self.flags.contains(HandshakeDoneAcked) => {
                        self.flags.insert(NeedSendHandshakeDone);
                    }

                    // New connection IDs are sent in NEW_CONNECTION_ID frames
                    // and retransmitted if the packet containing them is lost.
                    Frame::NewConnectionId { seq_num, .. } => {
                        self.cids.mark_scid_to_advertise(seq_num, true);
                    }

                    // Retired connection IDs are sent in RETIRE_CONNECTION_ID
                    // frames and retransmitted if the packet containing them is
                    // lost.
                    Frame::RetireConnectionId { seq_num } => {
                        self.cids.mark_dcid_to_retire(seq_num, true);
                    }

                    // PATH_ABANDON is sent again if the packet carrying it
                    // is lost.
                    Frame::PathAbandon { dcid_seq_num, .. } => {
                        if !self.pending_path_abandons.contains(&dcid_seq_num) {
                            self.pending_path_abandons.push_back(dcid_seq_num);
                        }
                    }

                    // NEW_TOKEN frames are retransmitted if the packet
                    // containing them is lost.
                    Frame::NewToken { .. } => {
                        self.flags.insert(NeedSendNewToken);
                    }

                    // Data sent in CRYPTO frames is retransmitted according to
                    // the rules in [QUIC-RECOVERY], until all data has been
                    // acknowledged.
                    Frame::Crypto { offset, length, .. } => {
                        let level = space.id.to_level();
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        if let Ok(stream) = crypto_streams.get_mut(level) {
                            stream.send.retransmit(offset, length);
                        }
                    }

                    // Application data sent in STREAM frames is retransmitted
                    // in new STREAM frames unless the endpoint has sent a
                    // RESET_STREAM for that stream.
                    Frame::Stream {
                        stream_id,
                        offset,
                        length,
                        fin,
                        ..
                    } => {
                        self.streams
                            .on_stream_frame_lost(stream_id, offset, length, fin);
                    }

                    // Cancellation of stream transmission, as carried in a
                    // RESET_STREAM frame, is sent until acknowledged or until
                    // all stream data is acknowledged by the peer.
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        self.streams
                            .on_reset_stream_frame_lost(stream_id, error_code, final_size);
                    }

                    // An updated value is sent when the packet containing the
                    // most recent MAX_STREAM_DATA frame for a stream is lost.
                    Frame::MaxStreamData { stream_id, .. } => {
                        self.streams.on_max_stream_data_frame_lost(stream_id);
                    }

                    // An updated value is sent in a MAX_DATA frame if the packet
                    // containing the most recently sent MAX_DATA frame is
                    // declared lost.
                    Frame::MaxData { .. } => {
                        self.streams.on_max_data_frame_lost();
                    }

                    // Request that a peer cease transmission of data on a stream,
                    // as carried in a STOP_SENDING frame, is sent until acknowledged
                    // or until receive-side of the stream is finished.
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    } => {
                        self.streams
                            .on_stop_sending_frame_lost(stream_id, error_code);
                    }

                    // Request that a peer update its max_streams limit, is sent until
                    // acknowledged or receive MAX_STREAMS frame from peer.
                    Frame::StreamsBlocked { bidi, max } => {
                        self.streams.on_streams_blocked_frame_lost(bidi, max);
                    }

                    // A new frame is sent if a packet containing the most recent
                    // frame for a stream scope is lost, but only while the
                    // endpoint is blocked on the corresponding limit.
                    Frame::StreamDataBlocked { stream_id, max } => {
                        self.streams
                            .on_stream_data_blocked_frame_lost(stream_id, max);
                    }

                    // A new frame is sent if a packet containing the most recent
                    // frame for a connection scope is lost, but only while the
                    // endpoint is blocked on the corresponding limit.
                    Frame::DataBlocked { max } => {
                        self.streams.on_data_blocked_frame_lost(max);
                    }

                    // An updated value is sent when a packet containing the
                    // most recent MAX_STREAMS for a stream type frame is
                    // declared lost.
                    Frame::MaxStreams { bidi, max } => {
                        self.streams.on_max_streams_frame_lost(bidi, max);
                    }

                    // An OBSERVED_ADDRESS frame is sent again if the address
                    // it carries is still the peer's address on its path.
                    Frame::ObservedAddress { addr, .. } => {
                        for (_, path) in self.paths.iter_mut() {
                            path.on_observed_addr_lost(addr);
                        }
                    }

                    // A PING frame contain no information, so lost PING frames
                    // do not require repair. However, if it indicates the loss
                    // of a PMTU probe, we will try to schedule a new probe.
                    Frame::Ping {
                        pmtu_probe: Some((path_id, probe_size)),
                    } => {
                        if let Ok(path) = self.paths.get_mut(path_id) {
                            let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
                            path.dplpmtud.on_pmtu_probe_lost(probe_size, peer_mds);
                            debug!(
                                "{} lost MTU probe on path {:?} size={}",
                                self.trace_id, path, probe_size
                            );
                        }
                    }

                    _ => (),
                }
            }
        }
    }

    /// Select an available path for sending packet
    ///
    /// The selected path should have a packet that can be sent out, unless none
    /// of the paths are feasible.
    /// `send` found nothing to write: every established path that the
    /// congestion window, the pacer and the sender's data gate would still let
    /// send is application-limited.
    fn mark_paths_with_nothing_to_send(&mut self, sender: &dyn PacketSendHandler) {
        if !self.is_established() {
            return;
        }
        for (_, path) in self.paths.iter_mut() {
            let gate_open = sender.can_send_data(
                path.local_addr(),
                path.remote_addr(),
                path.recovery.max_datagram_size,
            );
            if gate_open {
                path.recovery.on_nothing_to_send();
            }
        }
    }

    /// The largest difference in propagation delay between the paths a
    /// datagram may take: a flow that paused longer than this can move to
    /// another of them without its packets overtaking each other.
    fn flowlet_gap(&self) -> time::Duration {
        let held = self.paths.held_back();
        let delays = self
            .paths
            .iter()
            .filter(|(_, p)| {
                p.active() && !held.applies(p) && p.scheduler_target_rate() != Some(0)
            })
            .map(|(_, p)| p.recovery.rtt.windowed_min_rtt());
        let (lo, hi) = delays.fold((None, None), |(lo, hi), d| {
            (
                Some(lo.map_or(d, |lo: time::Duration| lo.min(d))),
                Some(hi.map_or(d, |hi: time::Duration| hi.max(d))),
            )
        });
        match (lo, hi) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => time::Duration::ZERO,
        }
    }

    /// The path of every flow with queued datagrams: the one it keeps, or,
    /// at a flowlet boundary or when its path can no longer be used, the
    /// one ECF places it on (`ecf_place`, S-I5/I6). A flow with no usable path
    /// is left out and waits.
    fn datagram_flow_paths(&mut self, now: time::Instant) -> HashMap<Option<u32>, usize> {
        let gap = self.flowlet_gap();
        let held = self.paths.held_back();
        let mut placed = HashMap::new();
        for i in 0..self.datagrams.outgoing_len() {
            let Some(flow) = self.datagrams.flow_at(i) else {
                break;
            };
            if placed.contains_key(&flow) {
                continue;
            }
            let paths = &self.paths;
            let usable = |pid: usize| {
                paths.get(pid).is_ok_and(|p| {
                    p.active() && !held.applies(p) && p.scheduler_target_rate() != Some(0)
                })
            };
            let pid = match self.datagrams.flow_paths.current(flow, now, gap, usable) {
                Some(pid) => pid,
                None => match ecf_place(&mut self.paths, self.datagrams.outgoing_bytes() as u64) {
                    Some(pid) => {
                        self.datagrams.flow_paths.place(flow, pid, now);
                        pid
                    }
                    None => continue,
                },
            };
            placed.insert(flow, pid);
        }
        placed
    }

    /// A path that can send the oldest datagram of some flow now: under the
    /// bypass any path a flow is on, otherwise one whose congestion window,
    /// pacer and data gate allow it.
    fn select_datagram_path(&mut self, sender: &dyn PacketSendHandler) -> Option<usize> {
        if !self.is_established() || !self.datagrams.has_outgoing() {
            return None;
        }
        let bypass = self.datagrams.breaker.active();
        let flow_path = self.datagram_flow_paths(time::Instant::now());
        let mut tried = Vec::new();
        for i in 0..self.datagrams.outgoing_len() {
            let Some(pid) = self.datagrams.flow_at(i).and_then(|flow| flow_path.get(&flow)) else {
                continue;
            };
            if tried.contains(pid) {
                continue;
            }
            tried.push(*pid);
            if bypass || self.datagrams.is_measurement_at(i) {
                return Some(*pid);
            }
            let can_send = self
                .paths
                .get_mut(*pid)
                .is_ok_and(|p| p.recovery.can_send());
            if can_send && self.data_gate_open(sender, PacketType::OneRTT, *pid).unwrap_or(false) {
                return Some(*pid);
            }
        }
        None
    }

    fn select_send_path(&mut self, sender: &dyn PacketSendHandler) -> Result<usize> {
        // Select an unvalidated path with path probing packets to send
        if self.is_established() {
            let mut probing = self
                .paths
                .iter_mut()
                .filter(|(_, p)| p.dcid_seq.is_some())
                .filter(|(_, p)| p.need_send_validation_frames(self.is_server))
                .map(|(pid, _)| pid);

            if let Some(pid) = probing.next() {
                return Ok(pid);
            }
        }

        // Multipath scheduling for Multipath QUIC
        if self.flags.contains(EnableMultipath) {
            // A backed-off path is passed over by the schedulers, but its PTO
            // probes must still go out, or nothing would ever end the back-off.
            let probing_backed_off = self
                .paths
                .iter()
                .find(|(_, p)| {
                    p.active()
                        && p.backed_off()
                        && self.spaces.get(p.space_id).is_some_and(|s| s.loss_probes > 0)
                })
                .map(|(pid, _)| pid);
            if let Some(pid) = probing_backed_off {
                return Ok(pid);
            }

            // Datagrams go on the path their flow keeps (S-I5/I6).
            if let Some(pid) = self.select_datagram_path(sender) {
                return Ok(pid);
            }

            // Select a validated path with sufficient congestion window by the
            // multipath scheduler.
            if self.need_send_path_unaware_frames() {
                let s = match self.multipath_scheduler {
                    Some(ref mut scheduler) => scheduler,
                    None => return Err(Error::InternalError),
                };
                if let Ok(pid) = s.on_select(&mut self.paths, &mut self.spaces, &mut self.streams) {
                    return Ok(pid);
                }
            }

            // Select a validated path with ACK/PTO/Buffered packets or an
            // address report to send.
            let observed_address_reporting = self.observed_address_reporting();
            for (pid, path) in self.paths.iter_mut() {
                if !path.active() {
                    // An idle path still owes the peer ACKs for its space, and
                    // keep-alive PINGs keep its NAT mappings open.
                    let ack_due = self.spaces.get(path.space_id).is_some_and(|space| {
                        !space.recv_pkt_num_need_ack.is_empty() && space.need_send_ack
                    });
                    if path.can_send_ack() && (ack_due || path.need_send_ping) {
                        return Ok(pid);
                    }
                    continue;
                }
                match self.spaces.get(path.space_id) {
                    Some(space) => {
                        if !space.recv_pkt_num_need_ack.is_empty() && space.need_send_ack {
                            return Ok(pid);
                        }
                        if space.loss_probes > 0 {
                            return Ok(pid);
                        }
                        if space.need_send_buffered_frames() && path.recovery.can_send() {
                            return Ok(pid);
                        }
                        if path.need_send_ping {
                            return Ok(pid);
                        }
                        // The report is ack-eliciting: like buffered frames it
                        // waits for congestion window, so a blocked path never
                        // shadows another path's ACK.
                        if observed_address_reporting
                            && path.need_report_observed_addr()
                            && path.recovery.can_send()
                        {
                            return Ok(pid);
                        }
                        continue;
                    }
                    None => continue,
                }
            }
        }

        // Select the active path
        self.paths.get_active_path_id()
    }

    /// Select packet type for outgoing packets
    fn select_send_packet_type(&mut self, pid: usize) -> Result<PacketType> {
        // When sending a CONNECTION_CLOSE frame, the goal is to ensure that
        // the peer will process the frame. Generally, this means sending the
        // frame in a packet with the highest level of packet protection to
        // avoid the packet being discarded.
        // See RFC 9000 Section 10.2.3
        if self.local_error.as_ref().is_some_and(|e| !e.is_app) {
            let pkt_type = match self.tls_session.write_level() {
                Level::Initial => PacketType::Initial,
                Level::Handshake => PacketType::Handshake,
                Level::ZeroRTT => unreachable!(),
                Level::OneRTT => PacketType::OneRTT,
            };

            // However, prior to confirming the handshake, it is possible that
            // more advanced packet protection keys are not available to the peer.
            if !self.is_established() {
                match pkt_type {
                    PacketType::OneRTT => return Ok(PacketType::Handshake),

                    PacketType::Handshake
                        if self.tls_session.get_keys(Level::Initial).seal.is_some() =>
                    {
                        return Ok(PacketType::Initial)
                    }

                    _ => (),
                };
            }
            return Ok(pkt_type);
        }

        // Coalescing packets in order of increasing encryption levels
        // (Initial, 0-RTT, Handshake, 1-RTT) makes it more likely that the
        // receiver will be able to process all the packets in a single pass.
        let pkt_types = [
            PacketType::Initial,
            PacketType::Handshake,
            PacketType::OneRTT,
        ];
        for pkt_type in pkt_types.iter() {
            // Only send packets in a space when we have the send keys for it.
            let level = pkt_type.to_level()?;
            if self.tls_session.get_keys(level).seal.is_none() {
                continue;
            }

            // We are ready to send data for this packet number space.
            let mut crypto_streams = self.crypto_streams.borrow_mut();
            if crypto_streams.get_mut(level)?.is_sendable() {
                return Ok(*pkt_type);
            }

            // We are ready to send ack for this packet number space.
            let space_id = self.get_space_id(*pkt_type, pid)?;
            let space = self.spaces.get(space_id).ok_or(Error::InternalError)?;
            if space.need_send_ack {
                return Ok(*pkt_type);
            }

            // There are lost frames in this packet number space.
            if !space.lost.is_empty() {
                return Ok(*pkt_type);
            }

            // We need to send PTO probe packets.
            if space.loss_probes > 0 {
                return Ok(*pkt_type);
            }
        }

        // If there are sendable, reset, stopped, almost full, blocked streams,
        // or need to update concurrency limits, use the 0RTT/1RTT packet.
        let path = self.paths.get(pid)?;
        if (self.is_established()
            // Note: The server's use of 1-RTT keys before the handshake is
            // complete is limited to sending data. BoringSSL will provide 1-RTT
            // write secret until the handshake is complete.
            // See RFC 9001 Section 5.7
            || self.tls_session.get_keys(Level::OneRTT).seal.is_some()
            || self.tls_session.is_in_early_data())
            && (self.need_send_handshake_done_frame()
                || self.need_send_new_token_frame()
                || self.local_error.as_ref().is_some_and(|e| e.is_app)
                || path.need_send_validation_frames(self.is_server)
                || path.dplpmtud.should_probe()
                || path.need_send_ping
                || self.cids.need_send_cid_control_frames()
                || !self.pending_path_abandons.is_empty()
                || self.streams.need_send_stream_frames()
                || self.spaces.need_send_buffered_frames()
                || self.datagrams.has_outgoing()
                || (self.observed_address_reporting() && path.need_report_observed_addr()))
        {
            if !self.is_server && self.tls_session.is_in_early_data() {
                return Ok(PacketType::ZeroRTT);
            }
            return Ok(PacketType::OneRTT);
        }

        Err(Error::Done)
    }

    /// Check whether there are any unsent frames that can be sent on any path.
    fn need_send_path_unaware_frames(&self) -> bool {
        self.need_send_handshake_done_frame()
            || self.need_send_new_token_frame()
            || self.local_error.as_ref().is_some_and(|e| e.is_app)
            || self.cids.need_send_cid_control_frames()
            || !self.pending_path_abandons.is_empty()
            || self.streams.need_send_stream_frames()
            || self.datagrams.has_outgoing()
    }

    /// Find space id for the specified packet type and path id.
    fn get_space_id(&self, pkt_type: PacketType, path_id: usize) -> Result<SpaceId> {
        if !self.flags.contains(EnableMultipath) {
            return pkt_type.to_space();
        }

        if pkt_type != PacketType::OneRTT {
            return pkt_type.to_space();
        }

        match self.paths.get(path_id) {
            Ok(path) => Ok(path.space_id),
            Err(e) => Err(e),
        }
    }

    /// Select the path that the incoming packet belongs to, or creates a new
    /// one if no existing path matches.
    fn get_or_create_path(
        &mut self,
        recv_pid: Option<usize>,
        dcid: &ConnectionId,
        info: &PacketInfo,
        buf_len: usize,
    ) -> Result<usize> {
        // Note: If the incoming packet carrys an unknown dcid, just ignore and drop it.
        let (cid_seq, mut cid_pid) = self.cids.find_scid(dcid).ok_or(Error::Done)?;

        // A straggler addressed to the CID of a path discarded here: it must
        // neither open a path nor be taken for a new path on an open 4-tuple.
        if self.cids.scid_released(cid_seq) {
            return Err(Error::Done);
        }

        // A packet from the 4-tuple of an abandoned path, addressed to a CID
        // other than that path's: the peer opened a new path on the same
        // 4-tuple. Drop the old path and treat this as a new one. Packets
        // still addressed to the old path's CID are its stragglers.
        //
        // The same holds for a path still open here when Multipath QUIC is
        // negotiated: the new path's first packets can overtake the
        // PATH_ABANDON for the old one, which travels on another path. In
        // this CID-based multipath a path's packet number space and AEAD
        // nonce are bound to its CID sequence (`space.add()` per CID in
        // `add_path`, `cid_seq` in `decrypt_payload`), and the only reason to
        // change a live path's CID is our own Retire Prior To (checked by
        // `scid_retiring`). A different, unused CID without that is thus the
        // peer opening a new path on this 4-tuple, i.e. having abandoned the
        // old one: drop it without telling anyone, so the late PATH_ABANDON
        // finds nothing to act on.
        let mut recv_pid = recv_pid;
        if let Some(pid) = recv_pid {
            let multipath = self.flags.contains(EnableMultipath);
            let stale = self.paths.get(pid).is_ok_and(|p| {
                p.scid_seq != Some(cid_seq)
                    && (p.is_abandoned()
                        || (multipath
                            && cid_pid.is_none()
                            && p.scid_seq.is_some_and(|old| !self.cids.scid_retiring(old))))
            });
            if stale {
                self.abandon_path_by_id(pid, false)?;
                self.discard_path(pid, time::Instant::now());
                recv_pid = None;
                cid_pid = self.cids.find_scid(dcid).ok_or(Error::Done)?.1;
            }
        }

        // The incoming packet arrived on the existing path (for Client/Server).
        if let Some(recv_pid) = recv_pid {
            let recv_path = self.paths.get_mut(recv_pid)?;
            let cid_item = recv_path.scid_seq.and_then(|v| self.cids.get_scid(v).ok());

            if cid_item.map(|c| &c.cid) != Some(dcid) {
                recv_path.scid_seq = Some(cid_seq);
                self.cids.mark_scid_used(cid_seq, recv_pid)?;
            }
            return Ok(recv_pid);
        }

        // The incoming packet arrived on a new path (for Server).
        if self.paths.is_full() {
            // Room comes from an abandoned path that has drained; that may
            // be the one this CID was attached to.
            self.discard_drained_paths(time::Instant::now());
            cid_pid = self.cids.find_scid(dcid).ok_or(Error::Done)?.1;
        }
        if self.cids.zero_length_scid() {
            cid_pid = None;
        }
        let mut path = path::Path::new(
            info.dst,
            info.src,
            false,
            &self.recovery_conf,
            &self.trace_id,
        );
        if self.is_server {
            path.anti_ampl_limit = buf_len * self.paths.anti_ampl_factor;
        }

        path.scid_seq = Some(cid_seq);
        path.initiate_path_chal();

        // Try to create a packet number space for the new path in MPQUIC mode.
        if self.flags.contains(EnableMultipath) {
            match cid_pid {
                None => {
                    // Found a new path initiated by client
                    let space_id = self.spaces.add();
                    path.space_id = space_id;
                }
                Some(cid_pid) => {
                    // Found NAT rebinding: If path migration occurs, the new path
                    // will simply share the same packet number space with the
                    // original path.
                    path.space_id = self.paths.get(cid_pid)?.space_id;
                }
            }
        }

        path.set_serial(self.next_path_serial);
        self.next_path_serial += 1;
        let (local, remote, serial) = (path.local_addr(), path.remote_addr(), path.serial());
        let pid = self.paths.insert_path(path)?;
        self.paths.get_mut(pid)?.update_trace_id(pid);
        self.push_path_event(crate::PathLifecycleEvent::Opened {
            local,
            remote,
            serial,
        });
        if cid_pid.is_none() {
            self.cids.mark_scid_used(cid_seq, pid)?;
        }
        Ok(pid)
    }

    /// Return the amount of time until the next timeout event.
    pub(crate) fn timeout(&mut self) -> Option<time::Duration> {
        if self.is_closed() {
            return None;
        }

        let time = if self.is_draining() {
            // Draining timer takes precedence over all other timers. If it is
            // set, it means the connection is in draining state and there's
            // need to process the other timers.
            self.timers.get(Timer::Draining)
        } else {
            // Use the lowest timer among all the other timers
            match self.paths.min_loss_detection_timer() {
                Some(time) => self.timers.set(Timer::LossDetection, time),
                None => self.timers.stop(Timer::LossDetection),
            }
            match self.paths.min_pacer_timer() {
                Some(time) => self.timers.set(Timer::Pacer, time),
                None => self.timers.stop(Timer::Pacer),
            }
            match self.paths.min_path_chal_timer() {
                Some(time) => self.timers.set(Timer::PathChallenge, time),
                None => self.timers.stop(Timer::PathChallenge),
            }
            match self.spaces.min_ack_timer() {
                Some(time) => self.timers.set(Timer::Ack, time),
                None => self.timers.stop(Timer::Ack),
            }
            self.update_path_drain_timer();

            self.timers.next_timeout()
        };

        // Calculate duration since now.
        let d = time.map(|v| {
            let now = time::Instant::now();
            if v <= now {
                time::Duration::ZERO
            } else {
                v.duration_since(now)
            }
        });
        trace!("{} next timeout duration {:?}", self.trace_id(), d);
        d
    }

    /// Process timeout event on the connection.
    pub(crate) fn on_timeout(&mut self, now: time::Instant) {
        for timer in Timer::iter() {
            if !self.timers.is_expired(timer, now) {
                continue;
            }
            trace!("{} timer {:?} timeout", self.trace_id, timer);

            let handshake_status = self.handshake_status();
            self.timers.stop(timer);
            match timer {
                Timer::LossDetection => {
                    let mut backed_off_spaces = Vec::new();
                    for (_, path) in self.paths.iter_mut() {
                        if let Some(timer) = path.recovery.loss_detection_timer() {
                            if timer > now {
                                continue;
                            }
                            let (lost_pkts, lost_bytes) = path.recovery.on_loss_detection_timeout(
                                path.space_id,
                                &mut self.spaces,
                                handshake_status,
                                #[cfg(feature = "qlog")]
                                self.qlog.as_mut(),
                                now,
                            );
                            self.stats.lost_count += lost_pkts;
                            self.stats.lost_bytes += lost_bytes;

                            // Full-size packets stopped getting through (the
                            // path MTU shrank): fall back to the base PMTU.
                            if let Some(current) = path.check_pmtu_black_hole() {
                                debug!("{} path {:?} PMTU black hole, MTU is {} now", self.trace_id, path, current);
                            }

                            // Repeated PTOs: the scheduler passes the path over
                            // from now on, so what it holds moves to the others.
                            if path.backed_off() && path.mark_backoff_flushed() {
                                backed_off_spaces.push(path.space_id);
                            }

                            // Write RecoveryMetricsUpdate event to qlog.
                            #[cfg(feature = "qlog")]
                            if let Some(qlog) = &mut self.qlog {
                                path.recovery.qlog_recovery_metrics_updated(qlog);
                            }
                        }
                    }
                    for space_id in backed_off_spaces {
                        self.retransmit_path_inflight(space_id, now, false);
                    }
                    self.try_process_lost_datagrams(now);
                }

                Timer::Ack => {
                    for (_, space) in self.spaces.iter_mut() {
                        if let Some(timer) = space.ack_timer {
                            if timer > now {
                                continue;
                            }
                            debug!("{} ack timeout for space {:?}", self.trace_id, space.id);
                            space.need_send_ack = true;
                            space.ack_timer = None;
                        }
                    }
                }

                Timer::Pacer => {
                    for (_, path) in self.paths.iter_mut() {
                        if let Some(timer) = path.recovery.pacer_timer {
                            if timer > now {
                                continue;
                            }
                        }
                        path.recovery.pacer_timer = None;
                    }
                    self.mark_tickable(true);
                }

                Timer::Idle => {
                    info!("{} idle timeout", self.trace_id);
                    self.flags.insert(Closed);
                    self.flags.insert(IdleTimeout);
                }

                Timer::Draining => self.flags.insert(Closed),

                Timer::KeyDiscard => self.tls_session.discard_prev_key(),

                Timer::KeepAlive => (), // TODO: schedule an outgoing Ping

                Timer::PathChallenge => self.paths.on_path_chal_timeout(now),

                Timer::PathDrain => self.discard_drained_paths(now),

                Timer::Handshake => {
                    info!("{} handshake timeout", self.trace_id);
                    self.flags.insert(Closed);
                    self.flags.insert(HandshakeTimeout);
                }
            }
        }
    }

    /// Return the idle timeout of the connection.
    fn idle_timeout(&mut self) -> Option<time::Duration> {
        // The idle timeout is disabled.
        if self.local_transport_params.max_idle_timeout == 0
            && self.peer_transport_params.max_idle_timeout == 0
        {
            return None;
        }

        // The effective value at an endpoint is computed as the minimum of
        // the two advertised values.
        let idle_timeout = if self.local_transport_params.max_idle_timeout == 0 {
            self.peer_transport_params.max_idle_timeout
        } else if self.peer_transport_params.max_idle_timeout == 0 {
            self.local_transport_params.max_idle_timeout
        } else {
            cmp::min(
                self.local_transport_params.max_idle_timeout,
                self.peer_transport_params.max_idle_timeout,
            )
        };
        let idle_timeout = time::Duration::from_millis(idle_timeout);

        // To avoid excessively small idle timeout periods, endpoints MUST
        // increase the idle timeout period to be at least three times the
        // current Probe Timeout (PTO).
        // See RFC 9000 Section 10.1
        let path_pto = match self.paths.get_active_mut() {
            Ok(p) => p.recovery.rtt.pto_base(),
            Err(_) => time::Duration::ZERO,
        };
        let idle_timeout = cmp::max(idle_timeout, 3 * path_pto);

        Some(idle_timeout)
    }

    /// Whether encryption on the specified packet type should be disabled
    fn is_encryption_disabled(&self, pkt_type: PacketType) -> bool {
        pkt_type == PacketType::OneRTT && self.flags.contains(DisableEncryption)
    }

    /// Check whether the connection is a server connection.
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Check whether the connection handshake is complete.
    pub fn is_established(&self) -> bool {
        self.flags.contains(HandshakeCompleted)
    }

    /// Check whether the connection handshake is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.flags.contains(HandshakeConfirmed)
    }

    /// Check whether the connection is resumed.
    pub fn is_resumed(&self) -> bool {
        self.tls_session.is_resumed()
    }

    /// Check whether the connection has a pending handshake that has progressed
    /// enough to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        self.tls_session.is_in_early_data()
    }

    /// Check whether the multipath have been negotiated.
    pub fn is_multipath(&self) -> bool {
        self.flags.contains(EnableMultipath)
    }

    /// Return the negotiated application level protocol.
    pub fn application_proto(&self) -> &[u8] {
        self.tls_session.alpn_protocol()
    }

    /// Return the server name in the TLS SNI extension.
    pub fn server_name(&self) -> Option<&str> {
        self.tls_session.server_name()
    }

    /// Return the session data used by resumption.
    pub fn session(&self) -> Option<&[u8]> {
        self.tls_session.session()
    }

    /// Return details why 0-RTT was accepted or rejected.
    pub fn early_data_reason(&self) -> tls::SslEarlyDataReason {
        self.tls_session.early_data_reason()
    }

    /// Return a string representation for reason why 0-RTT was accepted or rejected.
    pub fn early_data_reason_string(&self) -> Result<Option<&str>> {
        self.tls_session.early_data_reason_string()
    }

    /// Check whether the connection is draining.
    ///
    /// If true, the connection object can not yet be dropped, but no data can
    /// be sent or received.
    pub fn is_draining(&self) -> bool {
        self.timers.get(Timer::Draining).is_some()
    }

    /// Check whether the connection is closing.
    pub fn is_closing(&self) -> bool {
        self.local_error.is_some()
    }

    /// Check whether the connection is closed.
    ///
    /// If true, the connection object can be dropped.
    pub fn is_closed(&self) -> bool {
        self.flags.contains(Closed)
    }

    /// Check whether the connection was closed due to idle timeout.
    pub fn is_idle_timeout(&self) -> bool {
        self.flags.contains(IdleTimeout)
    }

    /// Check whether the connection was closed due to handshake timeout.
    pub fn is_handshake_timeout(&self) -> bool {
        self.flags.contains(HandshakeTimeout)
    }

    /// Check whether the connection was closed due to stateless reset.
    pub fn is_reset(&self) -> bool {
        self.flags.contains(GotReset)
    }

    /// Close the connection.
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        if self.local_error.is_some() {
            return Err(Error::Done);
        }

        self.local_error = Some(ConnectionError {
            is_app: app,
            error_code: err,
            frame: None,
            reason: reason.to_vec(),
        });
        self.mark_tickable(true);
        Ok(())
    }

    /// Mark the connection as stateless reset by the peer.
    pub(crate) fn reset(&mut self) {
        if self.is_closed() || self.is_draining() {
            return;
        }

        // The connection is reset by the peer and it MUST enter the draining
        // period and not send any further packets on this connection.
        self.flags.insert(GotReset);
        if let Ok(p) = self.paths.get_active_mut() {
            let pto = p.recovery.rtt.pto_base();
            let now = time::Instant::now();
            self.timers.set(Timer::Draining, now + pto * 3);
        }
    }

    /// Returns the error from the peer, if any.
    pub fn peer_error(&self) -> Option<&ConnectionError> {
        self.peer_error.as_ref()
    }

    /// Returns the local error, if any.
    pub fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    /// Return statistics about the connection.
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Discard packet number space and related secrets.
    ///
    /// After QUIC has completed a move to a new encryption level, packet
    /// protection keys for previous encryption levels can be discarded.
    /// This occurs several times during the handshake, as well as when keys
    /// are updated.
    /// See RFC 9001 Section 4.9
    fn drop_space_state(&mut self, sid: SpaceId, now: time::Instant) {
        let level = match sid {
            SpaceId::Initial => Level::Initial,
            SpaceId::Handshake => Level::Handshake,
            _ => return,
        };

        // Discard unused keys for given level
        if self.tls_session.get_keys(level).open.is_none() {
            return;
        }
        self.tls_session.drop_keys(level);
        let mut crypto_streams = self.crypto_streams.borrow_mut();
        crypto_streams.clear(level);

        // When Initial and Handshake packet protection keys are discarded, all
        // packets that were sent with those keys can no longer be acknowledged
        // because their acknowledgments cannot be processed.
        // The sender MUST discard all recovery state associated with those
        // packets and MUST remove them from the count of bytes in flight.
        let handshake_status = self.handshake_status();
        if let Ok(path) = self.paths.get_active_mut() {
            path.recovery
                .on_pkt_num_space_discarded(sid, &mut self.spaces, handshake_status, now);
        }
    }

    /// Return the handshake status
    fn handshake_status(&self) -> HandshakeStatus {
        let keys = self.tls_session.get_keys(Level::Handshake);

        HandshakeStatus {
            derived_handshake_keys: keys.seal.is_some() && keys.open.is_some(),
            peer_verified_address: self.flags.contains(PeerVerifiedInitialAddress),
            completed: self.is_established(),
        }
    }

    /// Return scid of the active path
    pub fn scid(&self) -> Result<ConnectionId> {
        let seq = self
            .paths
            .get_active()?
            .scid_seq
            .ok_or(Error::InternalError)?;
        let item = self.cids.get_scid(seq)?;
        Ok(item.cid)
    }

    /// Return an iterator over source ConnectionIdItem
    pub fn scid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.cids.scid_iter()
    }

    /// Provide additional source CID and trigger sending NEW_CONNECTION_ID
    /// frames.
    pub(crate) fn add_scid(
        &mut self,
        scid: ConnectionId,
        reset_token: u128,
        retire_if_needed: bool,
    ) -> Result<u64> {
        self.cids
            .add_scid(scid, Some(reset_token), true, None, retire_if_needed)
    }

    /// Return true if the source CID is zero length
    pub fn zero_length_scid(&self) -> bool {
        self.cids.zero_length_scid()
    }

    /// Return dcid of the active path
    pub fn dcid(&self) -> Result<ConnectionId> {
        let seq = self
            .paths
            .get_active()?
            .dcid_seq
            .ok_or(Error::InternalError)?;
        let item = self.cids.get_dcid(seq)?;
        Ok(item.cid)
    }

    /// Return an iterator over destination ConnectionIdItem
    pub fn dcid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.cids.dcid_iter()
    }

    /// Return true if the destination CID is zero length
    pub fn zero_length_dcid(&self) -> bool {
        self.cids.zero_length_dcid()
    }

    /// Return original destination cid
    pub(crate) fn odcid(&self) -> Option<ConnectionId> {
        if self.is_server {
            self.local_transport_params
                .original_destination_connection_id
        } else {
            self.odcid
        }
    }

    /// Return the unique trace id.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Set dcid provided by peer
    fn try_set_dcid_for_initial_path(&mut self, pid: usize, hdr: &PacketHeader) -> Result<()> {
        if self.flags.contains(GotPeerCid) {
            return Ok(());
        }

        if !self.is_server {
            if self.odcid.is_none() {
                self.odcid = Some(self.dcid()?);
            }
            self.set_initial_dcid(
                hdr.scid,
                self.peer_transport_params.stateless_reset_token,
                pid,
            )?;
        } else {
            self.set_initial_dcid(
                hdr.scid,
                self.peer_transport_params.stateless_reset_token,
                pid,
            )?;

            if !self.flags.contains(DidRetry) {
                self.local_transport_params
                    .original_destination_connection_id = Some(hdr.dcid);
                self.set_transport_params()?;
            }
        }

        self.flags.insert(GotPeerCid);
        Ok(())
    }

    /// Set dcid for initial path of the connection
    fn set_initial_dcid(
        &mut self,
        cid: ConnectionId,
        reset_token: Option<u128>,
        path_id: usize,
    ) -> Result<()> {
        self.cids.set_initial_dcid(cid, reset_token, Some(path_id));
        self.paths.get_mut(path_id)?.dcid_seq = Some(0);

        Ok(())
    }

    /// Configure tls session to send transport parameters in the
    /// quic_transport_parameters extension in either the ClientHello or
    /// EncryptedExtensions handshake message.
    fn set_transport_params(&mut self) -> Result<()> {
        let mut raw_params = [0; 128];
        let len = TransportParams::encode(
            &self.local_transport_params,
            self.is_server,
            &mut raw_params,
        )?;
        self.tls_session.set_transport_params(&raw_params[..len])?;
        Ok(())
    }

    /// Return a func for writing crypto data from the TLS session to the crypto stream.
    fn get_write_method(&mut self) -> tls::WriteMethod {
        let crypto_streams = self.crypto_streams.clone();
        Box::new(move |level, data| {
            let mut crypto_streams = crypto_streams.borrow_mut();
            let stream = crypto_streams.get_mut(level)?;
            stream.send.write(Bytes::copy_from_slice(data), false)?;
            Ok(())
        })
    }

    /// Send a Ping frame for keep-alive.
    ///
    /// If `path_addr` is `None`, a Ping frame will be sent on each active path.
    /// Otherwise, a Ping frame will be on the specified path.
    pub fn ping(&mut self, path_addr: Option<FourTuple>) -> Result<()> {
        self.paths.mark_ping(path_addr)
    }

    /// Client add a new path on the connection.
    pub fn add_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<u64> {
        if self.is_server {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        if !self.flags.contains(HandshakeCompleted) {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        if let Some(pid) = self.paths.get_path_id(&(local_addr, remote_addr)) {
            let path = self.paths.get(pid)?;
            // The path is open already.
            if !path.is_abandoned() {
                return Err(Error::Done);
            }
            // An abandoned path is never reused (noq opens a new path with a
            // new path id; here a new CID and packet number space): drop it
            // now rather than after its drain period, and open a new one on
            // the same 4-tuple. Not before the peer was told, or it would
            // see the new CID on a path it still believes open.
            if path
                .dcid_seq
                .is_some_and(|seq| self.pending_path_abandons.contains(&seq))
            {
                return Err(Error::Done);
            }
            self.discard_path(pid, time::Instant::now());
            // Its CID went back to the peer; the new path waits for the
            // peer's replacement rather than opening without one.
            if !self.cids.zero_length_dcid() && self.cids.lowest_unused_dcid_seq().is_none() {
                return Err(Error::Done);
            }
        }

        if self.paths.is_full() {
            // Abandoned paths that have drained give their slots back.
            self.discard_drained_paths(time::Instant::now());
        }

        let dcid_seq = if self.cids.zero_length_dcid() {
            Some(0)
        } else {
            self.cids.lowest_unused_dcid_seq()
        };

        let mut path = path::Path::new(
            local_addr,
            remote_addr,
            false,
            &self.recovery_conf,
            &self.trace_id,
        );
        path.dcid_seq = dcid_seq;
        path.set_serial(self.next_path_serial);
        self.next_path_serial += 1;
        let (local, remote, serial) = (path.local_addr(), path.remote_addr(), path.serial());
        let pid = self.paths.insert_path(path)?;
        self.paths.get_mut(pid)?.update_trace_id(pid);
        self.push_path_event(crate::PathLifecycleEvent::Opened {
            local,
            remote,
            serial,
        });

        if let Some(dcid_seq) = dcid_seq {
            self.cids.mark_dcid_used(dcid_seq, pid)?;
        }

        let path = self.paths.get_mut(pid)?;
        path.initiate_path_chal();

        // Create packet number space for the path when Multipath QUIC is enabled.
        if self.flags.contains(EnableMultipath) {
            let space_id = self.spaces.add();
            path.space_id = space_id;
        }

        self.mark_tickable(true);
        Ok(pid as u64)
    }

    /// Abandon a path for a Multipath QUIC connection.
    #[doc(hidden)]
    pub fn abandon_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        let pid = match self.paths.get_path_id(&(local_addr, remote_addr)) {
            Some(pid) => pid,
            None => return Ok(()),
        };
        self.abandon_path_by_id(pid, true)
    }

    fn record_path_abandon_event(&mut self, event: String) {
        if self.path_abandon_events.len() >= 16 {
            self.path_abandon_events.pop_front();
        }
        self.path_abandon_events.push_back(event);
    }

    fn push_path_event(&mut self, event: crate::PathLifecycleEvent) {
        // The host drains these every turn; the bound only guards against one
        // that never does.
        if self.path_events.len() >= 1024 {
            self.path_events.pop_front();
        }
        self.path_events.push_back(event);
    }

    /// Path lifecycle events since the last call, oldest first. The host
    /// decides from these what became of its paths instead of polling their
    /// state, which a path can pass through unseen between two polls.
    #[doc(hidden)]
    pub fn take_path_events(&mut self) -> Vec<crate::PathLifecycleEvent> {
        self.path_events.drain(..).collect()
    }

    /// Recent path abandon events since the last call, oldest first.
    #[doc(hidden)]
    pub fn take_path_abandon_events(&mut self) -> Vec<String> {
        self.path_abandon_events.drain(..).collect()
    }

    /// Abandon path `pid`; with `notify`, tell the peer in a PATH_ABANDON
    /// frame (sent on another path) so it stops sending there as well.
    fn abandon_path_by_id(&mut self, pid: usize, notify: bool) -> Result<()> {
        // Mark the path as abandoned.
        let path = self.paths.get_mut(pid)?;
        let newly_abandoned = !path.is_abandoned();
        path.abandon();
        let space_id = path.space_id;
        let lifecycle = newly_abandoned.then(|| crate::PathLifecycleEvent::Abandoned {
            local: path.local_addr(),
            remote: path.remote_addr(),
            serial: path.serial(),
            scid_seq: path.scid_seq,
            dcid_seq: path.dcid_seq,
            by_peer: !notify,
        });
        let event = format!(
            "abandon path {} {:?}->{:?} notify {} new {} dcid_seq {:?} scid_seq {:?}",
            pid,
            path.local_addr(),
            path.remote_addr(),
            notify,
            newly_abandoned,
            path.dcid_seq,
            path.scid_seq
        );
        let dcid_seq = path.dcid_seq;
        self.record_path_abandon_event(event);
        if let Some(lifecycle) = lifecycle {
            self.push_path_event(lifecycle);
        }
        if notify && newly_abandoned {
            if let Some(seq) = dcid_seq {
                if !self.pending_path_abandons.contains(&seq) {
                    self.pending_path_abandons.push_back(seq);
                }
            }
        }

        // Draining starts when the PATH_ABANDON goes out (see
        // `try_write_path_abandon_frames`), or right away when there is none
        // to send (the peer abandoned the path, or it has no CID).
        let now = time::Instant::now();
        let frame_pending =
            dcid_seq.is_some_and(|seq| self.pending_path_abandons.contains(&seq));
        if !frame_pending {
            self.start_path_drain(pid, now);
        }

        self.retransmit_path_inflight(space_id, now, true);
        Ok(())
    }

    /// Everything still unacknowledged in `space_id` is handed to
    /// retransmission now (it goes out on the other paths) instead of
    /// trickling out one PTO probe at a time, which stalls every stream
    /// behind the lost bytes.
    ///
    /// With `abandoned` the path is gone for good: its packets are marked
    /// lost and every frame moves. Otherwise the path is only backed off and
    /// may still deliver: packets stay as they are (their ACKs still count)
    /// and only the stream data is queued again, a duplicate at worst.
    fn retransmit_path_inflight(&mut self, space_id: SpaceId, now: time::Instant, abandoned: bool) {
        if let Some(space) = self.spaces.get_mut(space_id) {
            let mut lost = Vec::new();
            for pkt in space
                .sent
                .iter_mut()
                .filter(|p| p.time_acked.is_none() && p.time_lost.is_none())
            {
                if abandoned {
                    pkt.time_lost = Some(now);
                }
                lost.extend(
                    pkt.frames
                        .iter()
                        .filter(|f| match f {
                            frame::Frame::Datagram { .. } => false,
                            frame::Frame::Stream { .. } => true,
                            _ => abandoned,
                        })
                        .cloned(),
                );
            }
            space.lost.extend(lost);
        }
    }

    /// Start the drain period of the abandoned path `pid` (3 PTO, as in
    /// noq's `PathDrained` timer) and arm the timer that ends it.
    fn start_path_drain(&mut self, pid: usize, now: time::Instant) {
        let max_ack_delay = time::Duration::from_millis(self.peer_transport_params.max_ack_delay);
        if let Ok(path) = self.paths.get_mut(pid) {
            path.start_drain(now, max_ack_delay);
        }
        self.update_path_drain_timer();
    }

    /// Point `Timer::PathDrain` at the earliest drain deadline, if any.
    fn update_path_drain_timer(&mut self) {
        match self.paths.iter().filter_map(|(_, p)| p.drain_deadline()).min() {
            Some(time) => self.timers.set(Timer::PathDrain, time),
            None => self.timers.stop(Timer::PathDrain),
        }
    }

    /// Discard every abandoned path whose drain period is over.
    fn discard_drained_paths(&mut self, now: time::Instant) {
        let drained: Vec<usize> = self
            .paths
            .iter()
            .filter(|(_, p)| p.drain_deadline().is_some_and(|t| t <= now))
            .map(|(pid, _)| pid)
            .collect();
        for pid in drained {
            self.discard_path(pid, now);
        }
        self.update_path_drain_timer();
    }

    /// Drop the abandoned path `pid` and give back what it held: in-flight
    /// frames go to retransmission, its Destination CID is retired (the peer
    /// answers by retiring the matching Source CID, which the endpoint then
    /// replaces), its slot and packet number space are freed. Same steps as
    /// noq's `discard_path` after `PathDrained`.
    ///
    /// Unlike noq the last remaining path is never abandoned by the callers
    /// (ET rebuilds the whole session instead of relying on a 3 PTO grace
    /// period), so this never leaves the connection without a path.
    fn discard_path(&mut self, pid: usize, now: time::Instant) {
        let Ok(path) = self.paths.get(pid) else {
            return;
        };
        let (space_id, dcid_seq, scid_seq, serial) =
            (path.space_id, path.dcid_seq, path.scid_seq, path.serial());
        let (local_addr, remote_addr) = (path.local_addr(), path.remote_addr());
        let event = format!(
            "discard path {} {:?}->{:?} dcid_seq {:?} scid_seq {:?}",
            pid,
            path.local_addr(),
            path.remote_addr(),
            dcid_seq,
            path.scid_seq
        );
        self.record_path_abandon_event(event);
        self.push_path_event(crate::PathLifecycleEvent::Discarded {
            local: local_addr,
            remote: remote_addr,
            serial,
            scid_seq,
            dcid_seq,
        });

        self.retransmit_path_inflight(space_id, now, true);

        if let Some(seq) = dcid_seq {
            if !self.cids.zero_length_dcid() {
                if let Some(item) = self.cids.retire_dcid(seq) {
                    if let Some(token) = item.reset_token {
                        self.events
                            .add(Event::DcidRetired(ResetToken(token.to_be_bytes())));
                    }
                }
            }
        }
        self.cids.release_path(pid);
        self.paths.remove(pid);

        // The packet number space goes with the path, unless a NAT-rebound
        // path still shares it. What its ACKs and losses would have told the
        // streams is applied first.
        if matches!(space_id, SpaceId::DataExt(_))
            && !self.paths.iter().any(|(_, p)| p.space_id == space_id)
        {
            self.process_all_lost_frames();
            self.try_process_acked_frames();
            self.spaces.drop(space_id);
        }
        // Connection-level counters (`self.stats`) are not derived from the
        // paths, so nothing needs folding in as noq's `partial_stats` does.
        self.mark_tickable(true);
    }

    /// Return an immutable reference to the specified path
    pub fn get_path(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<&path::Path> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        self.paths.get(pid)
    }

    /// Return an immutable reference to the active path
    pub fn get_active_path(&self) -> Result<&path::Path> {
        self.paths.get_active()
    }

    /// Return an mutable reference to the specified path
    pub fn get_path_stats(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<&crate::PathStats> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        Ok(self.paths.get_mut(pid)?.stats())
    }

    /// Set or clear the externally optimized send-rate target for a path.
    ///
    /// `None` restores the scheduler's native congestion-control/RTT policy.
    /// `Some(0)` excludes the path from non-probing data scheduling while
    /// leaving it available for path validation and recovery traffic.
    pub fn set_path_target_rate(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        rate: Option<u64>,
    ) -> Result<()> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        self.paths.get_mut(pid)?.set_scheduler_target_rate(rate);
        self.mark_tickable(true);
        Ok(())
    }

    /// Mark a path as standby: it carries no data while another active
    /// path is not on standby, however full that path's window is, and
    /// takes over once none is left. Validation and recovery are unaffected.
    pub fn set_path_standby(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        standby: bool,
    ) -> Result<()> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        self.paths.get_mut(pid)?.set_standby(standby);
        self.mark_tickable(true);
        Ok(())
    }

    /// Replace the live multipath packet scheduler without rebuilding the
    /// connection. Existing path validation, recovery and congestion-control
    /// state are preserved.
    pub fn set_multipath_scheduler(&mut self, algorithm: MultipathAlgorithm) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Err(Error::InvalidOperation("multipath is disabled".into()));
        }
        self.multipath_conf.multipath_algorithm = algorithm;
        self.multipath_scheduler = Some(build_multipath_scheduler(&self.multipath_conf));
        self.mark_tickable(true);
        Ok(())
    }

    /// Migrates the connection to the specified path.
    #[doc(hidden)]
    pub fn migrate_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        // TODO: support migration
        Err(Error::InternalError)
    }

    /// Return an iterator over path addresses.
    pub fn paths_iter(&self) -> FourTupleIter {
        // Instead of trying to identify whether packets will be sent on the
        // given 4-tuple, simply filter paths that cannot be used.
        FourTupleIter {
            addrs: self
                .paths
                .iter()
                .map(|(_, p)| FourTuple {
                    local: p.local_addr(),
                    remote: p.remote_addr(),
                })
                .collect(),
        }
    }

    /// Queue an unreliable datagram (RFC 9221) for sending.
    ///
    /// If `drop_oldest` is true, older unsent datagrams are discarded when
    /// the send queue is full; otherwise `SendDatagramError::Blocked` hands
    /// the datagram back.
    pub fn dgram_send(
        &mut self,
        data: Bytes,
        drop_oldest: bool,
    ) -> std::result::Result<(), SendDatagramError> {
        if self.local_transport_params.max_datagram_frame_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .dgram_max_writable_len()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        self.datagrams
            .queue(data, drop_oldest, self.datagram_send_buffer_size)?;
        self.mark_tickable(true);
        Ok(())
    }

    /// Queue an unreliable datagram that belongs to the application flow
    /// `flow` (a hash of the flow's identity, the same for all its packets).
    ///
    /// A packet carries datagrams of one flow only, and reports the flow in
    /// `PacketSendMeta::flow_hash`, so that a send queue below QUIC can keep
    /// the flows apart even though they share one outer 4-tuple.
    pub fn dgram_send_with_flow(
        &mut self,
        data: Bytes,
        drop_oldest: bool,
        flow: u32,
    ) -> std::result::Result<(), SendDatagramError> {
        if self.local_transport_params.max_datagram_frame_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .dgram_max_writable_len()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        self.datagrams
            .queue_with_flow(data, Some(flow), drop_oldest, self.datagram_send_buffer_size)?;
        self.mark_tickable(true);
        Ok(())
    }

    /// Queue a measurement datagram of the path itself (a delay probe or its
    /// report; `flow` as for `dgram_send_with_flow`, `None` when it belongs to
    /// none). Unlike application data it is not held back by the congestion
    /// window, the data gate or a tripped bypass breaker.
    pub fn dgram_send_measurement(
        &mut self,
        data: Bytes,
        drop_oldest: bool,
        flow: Option<u32>,
    ) -> std::result::Result<(), SendDatagramError> {
        if self.local_transport_params.max_datagram_frame_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .dgram_max_writable_len()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        self.datagrams
            .queue_measurement(data, flow, drop_oldest, self.datagram_send_buffer_size)?;
        self.mark_tickable(true);
        Ok(())
    }

    /// Receive an unreliable datagram.
    pub fn dgram_recv(&mut self) -> Option<Bytes> {
        self.datagrams.recv()
    }

    /// Receive a datagram and the application timestamp of its containing
    /// packet. Delayed reads retain the original `PacketInfo::recv_timestamp`;
    /// applications that do not supply one receive `None`.
    pub fn dgram_recv_with_timestamp(&mut self) -> Option<(Bytes, Option<u64>)> {
        self.datagrams.recv_with_timestamp()
    }

    /// Return the largest datagram payload `dgram_send` currently accepts,
    /// or `None` if datagrams are disabled locally or not supported by the
    /// peer.
    ///
    /// It is the smaller of the peer's `max_datagram_frame_size` and the
    /// smallest path MTU of the active paths, both less the frame header;
    /// the latter also less the 1-RTT packet overhead. It grows as DPLPMTUD
    /// raises the path MTU.
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        self.local_transport_params.max_datagram_frame_size?;
        if !self.flags.contains(AppliedPeerTransportParams) {
            return None;
        }
        let peer_max = self.peer_transport_params.max_datagram_frame_size?;

        let mtu = self
            .paths
            .iter()
            .filter(|(_, p)| p.active())
            .map(|(pid, _)| self.max_datagram_size(pid))
            .min()
            .or_else(|| {
                self.paths
                    .get_active_path_id()
                    .ok()
                    .map(|pid| self.max_datagram_size(pid))
            })?;
        let by_path = mtu
            .saturating_sub(self.short_packet_overhead())
            .saturating_sub(frame::MAX_DATAGRAM_OVERHEAD);
        let by_peer = (peer_max as usize).saturating_sub(frame::MAX_DATAGRAM_OVERHEAD);
        Some(cmp::min(by_path, by_peer))
    }

    /// Upper bound of the 1-RTT packet overhead: header, packet number and
    /// AEAD tag.
    fn short_packet_overhead(&self) -> usize {
        let dcid_len = self
            .paths
            .get_active()
            .ok()
            .and_then(|p| p.dcid_seq)
            .and_then(|seq| self.cids.get_dcid(seq).ok())
            .map_or(crate::MAX_CID_LEN, |c| c.cid.len());
        let tag_len = self.tls_session.get_overhead(Level::OneRTT).unwrap_or(16);
        1 + dcid_len + 4 + tag_len
    }

    /// Return the number of datagrams waiting to be sent.
    pub fn dgram_send_queue_len(&self) -> usize {
        self.datagrams.outgoing_len()
    }

    /// Return the bytes of datagrams waiting to be sent.
    pub fn dgram_send_queue_bytes(&self) -> usize {
        self.datagrams.outgoing_bytes()
    }

    /// Return the number of received datagrams not yet read.
    pub fn dgram_recv_queue_len(&self) -> usize {
        self.datagrams.incoming_len()
    }

    /// Return cumulative datagram counters.
    pub fn dgram_stats(&self) -> DatagramStats {
        self.datagrams.snapshot_stats()
    }

    /// Let datagrams exceed the congestion window, or stop doing so.
    /// Enabling it again re-arms a tripped circuit breaker.
    pub fn dgram_set_bypass_cwnd(&mut self, v: bool) {
        self.datagrams.breaker.set_enabled(v);
        self.mark_tickable(true);
    }

    /// Let the bypass's circuit breaker (RFC 8084) trip, or never: see
    /// `Config::enable_datagram_bypass_breaker`.
    pub fn dgram_set_bypass_breaker(&mut self, v: bool) {
        self.datagrams.breaker.set_trips(v);
        self.mark_tickable(true);
    }

    /// Return an iterator over streams that have data to read or an error to collect.
    pub fn stream_readable_iter(&self) -> StreamIter {
        self.streams.readable_iter()
    }

    /// Return an iterator over streams that can be written
    pub fn stream_writable_iter(&self) -> StreamIter {
        self.streams.writable_iter()
    }

    /// Return an iterator over all the existing streams on the connection.
    pub fn stream_iter(&self) -> StreamIter {
        self.streams.iter()
    }

    /// Return true if the stream has enough flow control capacity to send data
    /// and application wants to send more data.
    pub(crate) fn stream_check_writable(&self, stream_id: u64) -> bool {
        self.streams.check_writable(stream_id)
    }

    /// Return true if application wants to read more data from the stream.
    pub(crate) fn stream_check_readable(&self, stream_id: u64) -> bool {
        self.streams.check_readable(stream_id)
    }

    /// Set want write flag for a stream.
    pub fn stream_want_write(&mut self, stream_id: u64, want: bool) -> Result<()> {
        self.mark_tickable(true);
        self.streams.want_write(stream_id, want)
    }

    /// Set want read flag for a stream.
    pub fn stream_want_read(&mut self, stream_id: u64, want: bool) -> Result<()> {
        self.mark_tickable(true);
        self.streams.want_read(stream_id, want)
    }

    /// Read data from a stream
    pub fn stream_read(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        self.mark_tickable(true);
        let read_off = self.streams.stream_read_offset(stream_id);

        match self.streams.stream_read(stream_id, out) {
            Ok((read, fin)) => {
                // Write QuicStreamDataMoved event to qlog
                #[cfg(feature = "qlog")]
                if let Some(qlog) = &mut self.qlog {
                    Self::qlog_transport_data_read(qlog, stream_id, read_off.unwrap_or(0), read);
                }

                Ok((read, fin))
            }
            Err(e) => Err(e),
        }
    }

    /// Write data to a stream.
    pub fn stream_write(&mut self, stream_id: u64, buf: Bytes, fin: bool) -> Result<usize> {
        self.mark_tickable(true);
        let write_off = self.streams.stream_write_offset(stream_id);

        match self.streams.stream_write(stream_id, buf, fin) {
            Ok(written) => {
                // Write QuicStreamDataMoved event to qlog
                #[cfg(feature = "qlog")]
                if let Some(qlog) = &mut self.qlog {
                    Self::qlog_transport_data_write(
                        qlog,
                        stream_id,
                        write_off.unwrap_or(0),
                        written,
                    );
                }
                Ok(written)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a new stream with given stream id and priority.
    /// This is a low-level API for stream creation. It is recommended to use
    /// `stream_bidi_new` for bidirectional streams or `stream_uni_new` for
    /// undirectional streams.
    pub fn stream_new(&mut self, stream_id: u64, urgency: u8, incremental: bool) -> Result<()> {
        self.stream_set_priority(stream_id, urgency, incremental)
    }

    /// Create a new bidirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_bidi_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        self.mark_tickable(true);
        self.streams.stream_bidi_new(urgency, incremental)
    }

    /// Create a new undirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_uni_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        self.mark_tickable(true);
        self.streams.stream_uni_new(urgency, incremental)
    }

    /// Shutdown stream reading or writing.
    pub fn stream_shutdown(&mut self, stream_id: u64, direction: Shutdown, err: u64) -> Result<()> {
        self.mark_tickable(true);
        self.streams.stream_shutdown(stream_id, direction, err)
    }

    /// Set priority for a stream.
    pub fn stream_set_priority(
        &mut self,
        stream_id: u64,
        urgency: u8,
        incremental: bool,
    ) -> Result<()> {
        self.mark_tickable(true);
        self.streams
            .stream_set_priority(stream_id, urgency, incremental)
    }

    /// Return the number of bytes written to the stream that have never been
    /// sent (retransmissions not included), or `None` for an unknown stream.
    /// Lets an application keep its own queue in front of the stream instead
    /// of parking a whole flow-control window of data inside it.
    pub fn stream_unsent_bytes(&mut self, stream_id: u64) -> Option<u64> {
        self.streams.stream_unsent_bytes(stream_id)
    }

    /// Return the number of bytes written to the stream that the peer has
    /// not yet acknowledged in order, or `None` for an unknown (e.g. already
    /// collected) stream. Zero means everything written has arrived.
    pub fn stream_unacked_bytes(&mut self, stream_id: u64) -> Option<u64> {
        self.streams.stream_unacked_bytes(stream_id)
    }

    /// Return the stream's send capacity in bytes.
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        self.streams.stream_capacity(stream_id)
    }

    /// Return true if the stream has enough send capacity.
    pub fn stream_writable(&mut self, stream_id: u64, len: usize) -> Result<bool> {
        self.streams.stream_writable(stream_id, len)
    }

    /// Return true if the stream has data to be read or an error to be collected.
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        self.streams.stream_readable(stream_id)
    }

    /// Return true if the stream's receive-side final size is known,
    /// and the application has read all data from the stream.
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.streams.stream_finished(stream_id)
    }

    /// Set user context for a stream.
    pub fn stream_set_context<T: Any + Send + Sync>(
        &mut self,
        stream_id: u64,
        ctx: T,
    ) -> Result<()> {
        self.streams.stream_set_context(stream_id, ctx)
    }

    /// Return the stream's user context.
    pub fn stream_context(&mut self, stream_id: u64) -> Option<&mut dyn Any> {
        self.streams.stream_context(stream_id)
    }

    /// Return immutable reference to streams
    pub(crate) fn get_streams(&self) -> &stream::StreamMap {
        &self.streams
    }

    /// Destroy the closed stream. It's only used by the Endpoint.
    pub(crate) fn stream_destroy(&mut self, stream_id: u64) {
        self.streams.stream_destroy(stream_id);
    }

    /// Return the internal identifier of the connection on the Endpoint. The
    /// internal identifier is not the same as the Connection ID as described
    /// in RFC 9000.
    pub fn index(&self) -> Option<u64> {
        self.index
    }

    /// Set the connection index on the Endpoint. It also enable generating
    /// endpoint-facing events.
    pub(crate) fn set_index(&mut self, v: u64) {
        self.index = Some(v);
        self.events.enable();
        self.streams.events.enable();
    }

    /// Set the queues shared by the endpoint and the connection.
    pub(crate) fn set_queues(&mut self, queues: Rc<RefCell<ConnectionQueues>>) {
        self.queues = Some(queues);
    }

    /// Client start handshake.
    pub(crate) fn start_handshake(&mut self) -> Result<()> {
        if self.is_server {
            return Ok(());
        }

        match self.tls_session.process() {
            Ok(_) => Ok(()),
            Err(Error::Done) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Return an endpoint-facing event.
    pub(crate) fn poll(&mut self) -> Option<Event> {
        if let Some(event) = self.events.poll() {
            return Some(event);
        }
        if let Some(event) = self.streams.events.poll() {
            return Some(event);
        }
        None
    }

    /// Check whether internal events should be processed.
    pub(crate) fn is_ready(&mut self) -> bool {
        !self.events.is_empty()
            || !self.streams.events.is_empty()
            || self.streams.has_readable()
            || self.streams.has_writable()
            || self.datagrams.readable_pending
            || self.is_closed()
    }

    /// Return true once after new datagrams became readable.
    pub(crate) fn take_datagram_readable(&mut self) -> bool {
        std::mem::take(&mut self.datagrams.readable_pending)
    }

    /// Check whether the connection is tickable (i.e. on the tickable queue
    /// of the endpoint)
    pub(crate) fn is_tickable(&self) -> bool {
        self.flags.contains(Tickable)
    }

    /// Mark the connection as tickable.
    pub(crate) fn mark_tickable(&mut self, tickable: bool) {
        if tickable == self.is_tickable() {
            return;
        }

        if let Some(idx) = self.index {
            let mut queues = match &self.queues {
                Some(v) => v.borrow_mut(),
                None => unreachable!(),
            };
            if tickable {
                queues.tickable.insert(idx);
                self.flags.insert(Tickable);
            } else {
                queues.tickable.remove(&idx);
                self.flags.remove(Tickable);
            }
            trace!("{} marked tickable {}", self.trace_id, tickable);
        }
    }

    /// Check whether the connection is sendable (i.e. on the sendable queue
    /// of the endpoint)
    pub(crate) fn is_sendable(&self) -> bool {
        self.flags.contains(Sendable)
    }

    /// Mark the connection as sendable.
    pub(crate) fn mark_sendable(&mut self, sendable: bool) {
        if sendable == self.is_sendable() {
            return;
        }

        if let Some(idx) = self.index {
            let mut queues = match &self.queues {
                Some(v) => v.borrow_mut(),
                None => unreachable!(),
            };
            if sendable {
                queues.sendable.insert(idx);
                self.flags.insert(Sendable);
            } else {
                queues.sendable.remove(&idx);
                self.flags.remove(Sendable);
            }
            trace!("{} marked sendable {}", self.trace_id, sendable);
        }
    }

    /// Get user context for the connection.
    pub fn context(&mut self) -> Option<&mut dyn Any> {
        match self.context {
            Some(ref mut data) => Some(data.as_mut()),
            None => None,
        }
    }

    /// Set user context for the connection.
    pub fn set_context<T: Any + Send + Sync>(&mut self, data: T) {
        self.context = Some(Box::new(data))
    }

    /// Write a QuicParametersSet event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_params_set(
        qlog: &mut qlog::QlogWriter,
        params: &TransportParams,
        owner: events::Owner,
        cipher: Option<tls::Algorithm>,
    ) {
        let ev_data = params.to_qlog(owner, cipher);
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicPacketReceived event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_packet_received(
        qlog: &mut qlog::QlogWriter,
        hdr: &PacketHeader,
        pkt_num: u64,
        pkt_len: usize,
        payload_len: usize,
        qlog_frames: Vec<qlog::events::QuicFrame>,
    ) {
        let qlog_pkt_hdr = events::PacketHeader::new_with_type(
            hdr.pkt_type.to_qlog(),
            pkt_num,
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );
        let qlog_raw_info = events::RawInfo {
            length: Some(pkt_len as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };
        let ev_data = events::EventData::QuicPacketReceived {
            header: qlog_pkt_hdr,
            frames: Some(qlog_frames.into()),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(qlog_raw_info),
            datagram_id: None,
            trigger: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicPacketSent event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_packet_sent(
        qlog: &mut qlog::QlogWriter,
        hdr: &PacketHeader,
        pkt_num: u64,
        pkt_len: usize,
        payload_len: usize,
        qlog_frames: Vec<qlog::events::QuicFrame>,
    ) {
        let qlog_pkt_hdr = events::PacketHeader::new_with_type(
            hdr.pkt_type.to_qlog(),
            pkt_num,
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );
        let qlog_raw_info = events::RawInfo {
            length: Some(pkt_len as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };
        let now = time::Instant::now();

        let ev_data = events::EventData::QuicPacketSent {
            header: qlog_pkt_hdr,
            frames: Some(qlog_frames.into()),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(qlog_raw_info),
            datagram_id: None,
            is_mtu_probe_packet: None,
            trigger: None,
        };
        qlog.add_event_data(now, ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_data_acked(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        offset: u64,
        length: usize,
    ) {
        let ev_data = events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(offset),
            length: Some(length as u64),
            from: Some(events::DataRecipient::Transport),
            to: Some(events::DataRecipient::Dropped),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_transport_data_read(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        read_off: u64,
        read: usize,
    ) {
        let ev_data = qlog::events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(read_off),
            length: Some(read as u64),
            from: Some(qlog::events::DataRecipient::Transport),
            to: Some(qlog::events::DataRecipient::Application),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_transport_data_write(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        write_off: u64,
        written: usize,
    ) {
        let ev_data = qlog::events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(write_off),
            length: Some(written as u64),
            from: Some(qlog::events::DataRecipient::Application),
            to: Some(qlog::events::DataRecipient::Transport),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }
}

/// A set of crypto streams for Initial/Handshake/1RTT level.
struct CryptoStreams {
    streams: [Stream; 3],
}

impl CryptoStreams {
    /// Create crypto streams for Initial/Handshake/1RTT level.
    pub fn new() -> Self {
        CryptoStreams {
            streams: [
                CryptoStreams::new_stream(),
                CryptoStreams::new_stream(),
                CryptoStreams::new_stream(),
            ],
        }
    }

    /// Get crypto stream for the given encryption level.
    pub fn get_mut(&mut self, level: Level) -> Result<&mut Stream> {
        match level {
            Level::Initial => Ok(&mut self.streams[0]),
            Level::Handshake => Ok(&mut self.streams[1]),
            Level::OneRTT => Ok(&mut self.streams[2]),
            _ => Err(Error::InternalError),
        }
    }

    /// Clear a crypto stream when dropping the corresponding keys.
    pub fn clear(&mut self, level: Level) {
        match level {
            Level::Initial => {
                self.streams[0] = CryptoStreams::new_stream();
            }
            Level::Handshake => {
                self.streams[0] = CryptoStreams::new_stream();
            }
            _ => (),
        }
    }

    /// Create a crypto stream.
    ///
    /// Data sent in CRYPTO frames is not flow controlled in the same way as
    /// stream data. QUIC relies on the implementation to avoid excessive
    /// buffering of data
    fn new_stream() -> Stream {
        Stream::new(true, true, u64::MAX, u64::MAX, stream::MAX_STREAM_WINDOW)
    }
}

/// Collection of packets which were received before decryption keys are available.
struct UndecryptablePackets {
    zerortt_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    handshake_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    onertt_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    capacity: usize,
}

impl UndecryptablePackets {
    fn new(capacity: usize) -> Self {
        Self {
            zerortt_pkts: VecDeque::with_capacity(capacity),
            handshake_pkts: VecDeque::with_capacity(capacity),
            onertt_pkts: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, pkt_type: &PacketType, pkt: Vec<u8>, info: &PacketInfo) -> bool {
        match pkt_type {
            PacketType::ZeroRTT => {
                if self.zerortt_pkts.len() > self.capacity {
                    false
                } else {
                    self.zerortt_pkts.push_back((pkt, *info));
                    true
                }
            }
            PacketType::Handshake => {
                if self.handshake_pkts.len() > self.capacity {
                    false
                } else {
                    self.handshake_pkts.push_back((pkt, *info));
                    true
                }
            }
            PacketType::OneRTT => {
                if self.onertt_pkts.len() > self.capacity {
                    false
                } else {
                    self.onertt_pkts.push_back((pkt, *info));
                    true
                }
            }
            _ => false,
        }
    }

    fn pop(&mut self, pkt_type: &PacketType) -> Option<(Vec<u8>, PacketInfo)> {
        match pkt_type {
            PacketType::ZeroRTT => self.zerortt_pkts.pop_front(),
            PacketType::Handshake => self.handshake_pkts.pop_front(),
            PacketType::OneRTT => self.onertt_pkts.pop_front(),
            _ => None,
        }
    }

    fn is_empty(&self, pkt_type: &PacketType) -> bool {
        match pkt_type {
            PacketType::ZeroRTT => self.zerortt_pkts.is_empty(),
            PacketType::Handshake => self.handshake_pkts.is_empty(),
            PacketType::OneRTT => self.onertt_pkts.is_empty(),
            _ => true,
        }
    }

    fn all_empty(&self) -> bool {
        self.zerortt_pkts.is_empty()
            && self.handshake_pkts.is_empty()
            && self.onertt_pkts.is_empty()
    }
}

/// Various flags of QUIC connection
#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy)]
enum ConnectionFlags {
    /// The version negotiation has been performed.
    DidVersionNegotiation = 1 << 0,

    /// The stateless retry has been performed.
    DidRetry = 1 << 1,

    /// The initial secrets have been derived.
    DerivedInitialSecrets = 1 << 2,

    /// The client's session has been started to handshake.
    InitiatedClientHandshake = 1 << 3,

    /// The peer's cid has been saved.
    GotPeerCid = 1 << 4,

    /// The peer's transport parameters have been processed.
    AppliedPeerTransportParams = 1 << 5,

    /// The peer has verified local initial address.
    PeerVerifiedInitialAddress = 1 << 6,

    /// The handshake has been completed.
    HandshakeCompleted = 1 << 7,

    /// The connection has been confirmed.
    HandshakeConfirmed = 1 << 8,

    /// The connection has been closed.
    Closed = 1 << 9,

    /// The connection was closed due to the idle timeout.
    IdleTimeout = 1 << 10,

    /// The connection was closed due to handshake timeout.
    HandshakeTimeout = 1 << 11,

    /// The connection was closed due to stateless reset.
    GotReset = 1 << 12,

    /// An ack-eliciting packet should be sent.
    NeedSendAckEliciting = 1 << 13,

    /// A NewToken frame should be sent.
    NeedSendNewToken = 1 << 14,

    /// A HandshakeDone frame should be sent.
    NeedSendHandshakeDone = 1 << 15,

    /// The client has acknowledged the server's HandshakeDone.
    HandshakeDoneAcked = 1 << 16,

    /// The connection has sent an ack-eliciting packet since receiving a packet.
    /// It is used for resetting Idle timer.
    SentAckElicitingSinceRecvPkt = 1 << 17,

    /// The connection is in the tickable queue of the endpoint.
    Tickable = 1 << 18,

    /// The connection is in the sendable queue of the endpoint.
    Sendable = 1 << 19,

    /// The multipath extension is successfully negotiated.
    EnableMultipath = 1 << 20,

    /// The disable_1rtt_encryption is successfully negotiated.
    DisableEncryption = 1 << 21,
}

/// Statistics about a QUIC connection.
#[repr(C)]
#[derive(Default)]
pub struct ConnectionStats {
    /// Total number of received packets.
    pub recv_count: u64,

    /// Total number of bytes received on the connection.
    pub recv_bytes: u64,

    /// Total number of sent packets.
    pub sent_count: u64,

    /// Total number of bytes sent on the connection.
    pub sent_bytes: u64,

    /// Total number of lost packets.
    pub lost_count: u64,

    /// Total number of bytes lost on the connection.
    pub lost_bytes: u64,
}

/// FrameWriteStatus is used to collect various states during writing frames
/// to a QUIC packet.
#[derive(Clone, Debug, Default)]
struct FrameWriteStatus {
    /// Number of bytes written to the packet payload
    written: usize,

    /// Frames written to the packet payload
    frames: Vec<Frame>,

    /// Whether it contains frames other than ACK, PADDING, and CONNECTION_CLOSE
    ack_eliciting: bool,

    /// Whether it is an in-flight packet (ack-eliciting packet or contain a
    /// PADDING frame)
    in_flight: bool,

    /// Whether it contains CRYPTO or STREAM frame
    has_data: bool,

    /// Whether it contains a PATH_CHALLENGE frame
    challenge: Option<[u8; 8]>,

    /// Whether a PING frame should be added to elicit an ACK from the peer.
    ack_elicit_required: bool,

    /// Whether the congestion window should be ignored.
    is_probe: bool,

    /// Whether it is a PMTU probe packet
    is_pmtu_probe: bool,

    /// Whether it consumes the pacer's tokens
    pacing: bool,

    /// Packet overhead (i.e. packet header and crypto overhead) in bytes
    overhead: usize,

    /// Status about buffered frames written to the packet.
    buffer_flags: BufferFlags,

    /// Whether a STREAM/CRYPTO range emitted into this packet was selected
    /// from the recovery retransmission set. This intentionally excludes
    /// multipath buffered copies, which are replication/scheduling state and
    /// not loss recovery.
    contains_retransmission: bool,

    /// The flow of the DATAGRAM frames written so far (`None` while there are
    /// none; `Some(None)` for datagrams without a flow).
    datagram_flow: Option<Option<u32>>,
}

/// Handshake status for loss recovery
#[derive(Clone, Copy, Debug)]
struct HandshakeStatus {
    /// Whether the Handshake keys have been derived.
    derived_handshake_keys: bool,

    /// Whether the peer has verified local initial address.
    peer_verified_address: bool,

    /// whether the connection handshake is complete.
    completed: bool,
}

#[cfg(test)]
pub(crate) mod tests {
    use self::path::PathState;
    use super::*;
    use crate::multipath_scheduler::MultipathAlgorithm;
    use crate::packet;
    use crate::ranges::RangeSet;
    use crate::tls::tests::ServerConfigSelector;
    use crate::tls::TlsConfig;
    use crate::tls::TlsConfigSelector;
    use crate::token::ResetToken;
    use crate::CongestionControlAlgorithm;
    use crate::ConnectionIdGenerator;
    use crate::RandomConnectionIdGenerator;
    use bytes::BytesMut;
    use rand::prelude::SliceRandom;
    use rand::thread_rng;
    use rand::RngCore;
    use ring::aead;
    use ring::aead::LessSafeKey;
    use ring::aead::UnboundKey;
    use std::io::Read;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    /// A trivial `PacketSendHandler` for tests that exercise `Connection::send`
    /// directly, bypassing `Endpoint`. `on_packets_send` is never actually
    /// invoked by these tests (they collect the bytes returned by `send()`
    /// themselves), and the default `can_send_data` (always admit) matches
    /// the pre-data-gate behavior these tests were written against.
    struct NoopSender;

    impl PacketSendHandler for NoopSender {
        fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> Result<usize> {
            Ok(pkts.len())
        }
    }

    /// A `PacketSendHandler` whose `can_send_data` answer is fixed at
    /// construction, for exercising `send_frames`'s data gate directly via
    /// `Connection::send`. Like `NoopSender`, `on_packets_send` is never
    /// actually invoked by these tests.
    struct GateSender {
        data_admitted: bool,
    }

    impl GateSender {
        fn open() -> Self {
            Self {
                data_admitted: true,
            }
        }

        fn closed() -> Self {
            Self {
                data_admitted: false,
            }
        }
    }

    impl PacketSendHandler for GateSender {
        fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> Result<usize> {
            Ok(pkts.len())
        }

        fn can_send_data(&self, _local: SocketAddr, _remote: SocketAddr, _bytes: usize) -> bool {
            self.data_admitted
        }
    }

    pub struct TestPair {
        pub client: Connection,
        pub server: Connection,
    }

    impl TestPair {
        pub fn new(client_config: &mut Config, server_config: &mut Config) -> Result<TestPair> {
            Self::new_with_server_name(client_config, server_config, "example.org")
        }

        pub fn new_with_server_name(
            client_config: &mut Config,
            server_config: &mut Config,
            server_name: &str,
        ) -> Result<TestPair> {
            let mut cli_cid_gen = RandomConnectionIdGenerator::new(client_config.cid_len);
            let mut srv_cid_gen = RandomConnectionIdGenerator::new(server_config.cid_len);
            let client_scid = cli_cid_gen.generate();
            let server_scid = srv_cid_gen.generate();
            let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
            let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

            Ok(TestPair {
                client: Connection::new_client(
                    &client_scid,
                    client_addr,
                    server_addr,
                    Some(server_name),
                    client_config,
                )?,
                server: Connection::new_server(
                    &server_scid,
                    server_addr,
                    client_addr,
                    None,
                    server_config,
                )?,
            })
        }

        pub fn new_with_test_config() -> Result<TestPair> {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.cid_len = crate::MAX_CID_LEN;
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.cid_len = crate::MAX_CID_LEN;
            TestPair::new(&mut client_config, &mut server_config)
        }

        pub fn new_with_zero_cid() -> Result<TestPair> {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.cid_len = 0;
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.cid_len = 0;
            TestPair::new(&mut client_config, &mut server_config)
        }

        /// Establish QUIC connection between client and server
        pub fn handshake(&mut self) -> Result<()> {
            while !self.client.is_established() || !self.server.is_established() {
                // client conn send all packets to server conn
                let packets = TestPair::conn_packets_out(&mut self.client)?;
                TestPair::conn_packets_in(&mut self.server, packets)?;

                // server conn send all packets to client conn
                let packets = TestPair::conn_packets_out(&mut self.server)?;
                TestPair::conn_packets_in(&mut self.client, packets)?;
            }
            Ok(())
        }

        pub fn move_forward(&mut self) -> Result<()> {
            let mut client_done = false;
            let mut server_done = false;

            while !client_done || !server_done {
                match TestPair::conn_packets_out(&mut self.client) {
                    Ok(flight) => {
                        if flight.is_empty() {
                            client_done = true;
                        } else {
                            TestPair::conn_packets_in(&mut self.server, flight)?;
                        }
                    }
                    Err(Error::Done) => client_done = true,
                    Err(e) => return Err(e),
                };

                match TestPair::conn_packets_out(&mut self.server) {
                    Ok(flight) => {
                        if flight.is_empty() {
                            server_done = true;
                        } else {
                            TestPair::conn_packets_in(&mut self.client, flight)?;
                        }
                    }
                    Err(Error::Done) => server_done = true,
                    Err(e) => return Err(e),
                };
            }

            Ok(())
        }

        /// Generate all outgoing packets
        pub fn conn_packets_out(conn: &mut Connection) -> Result<Vec<(Vec<u8>, PacketInfo)>> {
            let mut packets = Vec::new();
            loop {
                let mut out = vec![0u8; 1500];
                let info = match conn.send(&mut out, &NoopSender) {
                    Ok((written, info)) => {
                        out.truncate(written);
                        info
                    }
                    Err(Error::BufferTooShort) => break,
                    Err(Error::Done) => break,
                    Err(e) => return Err(e),
                };
                packets.push((out, info));
            }
            Ok(packets)
        }

        /// Process all incoming packets
        fn conn_packets_in(
            conn: &mut Connection,
            packets: Vec<(Vec<u8>, PacketInfo)>,
        ) -> Result<()> {
            for (mut pkt, info) in packets {
                match conn.recv(&mut pkt, &info) {
                    Ok(_) => (),
                    Err(Error::Done) => (),
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }

        /// Build an outgoing packet with the given frames on the active path of the connection.
        pub fn conn_build_packet(
            conn: &mut Connection,
            pkt_type: PacketType,
            frames: &[frame::Frame],
        ) -> Result<Vec<u8>> {
            let mut packet = vec![0; 1500];
            let buf = &mut packet;

            let path = conn.paths.get_active()?;
            let dcid_seq = path.dcid_seq.ok_or(Error::InternalError)?;
            let dcid = conn.cids.get_dcid(dcid_seq)?.cid;
            let scid = if let Some(scid_seq) = path.scid_seq {
                conn.cids.get_scid(scid_seq)?.cid
            } else if pkt_type == PacketType::OneRTT {
                ConnectionId::default()
            } else {
                return Err(Error::InternalError);
            };

            let space_id = pkt_type.to_space()?;
            let space = conn.spaces.get_mut(space_id).unwrap();
            let pkt_num = space.next_pkt_num;
            let pkt_num_len = 4;

            // Write packet header
            let pkt_hdr = PacketHeader {
                pkt_type,
                version: conn.version,
                dcid,
                scid,
                pkt_num: 0,
                pkt_num_len,
                token: conn.token.clone(),
                key_phase: false,
            };
            let hdr_offset = pkt_hdr.to_bytes(buf)?;

            // Fill Length field
            let mut bw = &mut buf[hdr_offset..];
            let payload_len = frames.iter().fold(0, |sum, f| sum + f.wire_len());
            let crypto_overhead = conn
                .tls_session
                .get_overhead(pkt_type.to_level()?)
                .ok_or(Error::InternalError)?;
            if pkt_type != PacketType::OneRTT {
                let length = pkt_num_len + payload_len + crypto_overhead;
                bw.write_varint_with_len(length as u64, crate::LENGTH_FIELD_LEN)?;
            }

            // Fill packet number field
            bw.write_u32(pkt_num as u32)?;

            // Write packet payload
            let payload_offset = if pkt_type != PacketType::OneRTT {
                hdr_offset + crate::LENGTH_FIELD_LEN + pkt_num_len
            } else {
                hdr_offset + pkt_num_len
            };
            let mut off = payload_offset;
            for frame in frames {
                off += frame.to_bytes(&mut buf[off..])?;
            }

            // Encrypt the packet
            let key = conn.tls_session.get_keys(pkt_type.to_level()?);
            let key = match &key.seal {
                Some(seal) => seal,
                None => return Err(Error::InternalError),
            };
            let written = packet::encrypt_packet(
                buf,
                None,
                pkt_num,
                pkt_num_len,
                payload_len,
                payload_offset,
                None,
                key,
            )?;
            space.next_pkt_num += 1;

            packet.truncate(written);
            Ok(packet)
        }

        /// Build an outgoing packet with the given frames on the connection and send it to the peer.
        pub fn build_packet_and_send(
            &mut self,
            pkt_type: PacketType,
            frames: &[frame::Frame],
            is_server: bool,
        ) -> Result<()> {
            let (local_conn, peer_conn) = match is_server {
                false => (&mut self.client, &mut self.server),
                true => (&mut self.server, &mut self.client),
            };

            // Local connection build packet.
            let packet = TestPair::conn_build_packet(local_conn, PacketType::OneRTT, frames)?;
            let info = TestPair::new_test_packet_info(is_server);

            // Peer connection receive OneRTT packet
            TestPair::conn_packets_in(peer_conn, vec![(packet, info)])?;

            Ok(())
        }

        /// Create default test config
        pub fn new_test_config(is_server: bool) -> Result<Config> {
            let mut conf = Config::new()?;
            conf.set_initial_max_data(90);
            conf.set_initial_max_stream_data_bidi_local(50);
            conf.set_initial_max_stream_data_bidi_remote(40);
            conf.set_initial_max_stream_data_uni(30);
            conf.set_initial_max_streams_bidi(3);
            conf.set_initial_max_streams_uni(2);
            conf.set_recv_udp_payload_size(6000);
            conf.set_max_connection_window(1024 * 1024);
            conf.set_max_stream_window(1024 * 1024);
            conf.set_max_concurrent_conns(10);
            conf.set_active_connection_id_limit(2);
            conf.set_ack_delay_exponent(3);
            conf.set_max_ack_delay(25);
            conf.set_congestion_control_algorithm(CongestionControlAlgorithm::Cubic);
            conf.set_initial_congestion_window(10);
            conf.set_min_congestion_window(2);
            conf.set_reset_token_key([1u8; 64]);
            conf.set_address_token_lifetime(3600);
            conf.set_send_batch_size(2);
            conf.set_max_handshake_timeout(0);
            conf.enable_multipath(false);
            conf.enable_dplpmtud(true);
            conf.enable_pacing(false);

            let application_protos = vec![b"h3".to_vec()];
            let tls_config = if !is_server {
                TlsConfig::new_client_config(application_protos, true)?
            } else {
                let mut tls_config = TlsConfig::new_server_config(
                    "src/tls/testdata/cert.crt",
                    "src/tls/testdata/cert.key",
                    application_protos,
                    true,
                )?;
                tls_config.set_ticket_key(&vec![0x73; 48])?;
                tls_config
            };
            conf.set_tls_config(tls_config);

            Ok(conf)
        }

        /// Create default test packet info
        pub fn new_test_packet_info(is_server: bool) -> PacketInfo {
            let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
            let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

            PacketInfo {
                src: if is_server { server_addr } else { client_addr },
                dst: if is_server { client_addr } else { server_addr },
                time: time::Instant::now(),
                recv_timestamp: None,
                send_meta: PacketSendMeta::default(),
            }
        }

        /// Create default test Stream frame
        pub fn new_test_stream_frame(content: &[u8]) -> frame::Frame {
            frame::Frame::Stream {
                stream_id: 0,
                offset: 0,
                length: content.len(),
                fin: false,
                data: Bytes::copy_from_slice(content),
            }
        }

        /// Assemble new version negotiation packet.
        fn new_test_version_negotiation_packet(
            dcid: &ConnectionId,
            scid: &ConnectionId,
            versions: &[u8],
        ) -> Vec<u8> {
            let mut pkt = vec![
                0x80, // Header form and unused bits.
                0x00, 0x00, 0x00, 0x00, // The Version field must be set to 0x00000000.
            ];

            // Append DCID.
            pkt.push(dcid.len);
            pkt.append(&mut dcid.data.to_vec());
            // Append SCID.
            pkt.push(scid.len);
            pkt.append(&mut scid.data.to_vec());
            // Append supported versions.
            let mut versions = versions.to_vec();
            pkt.append(&mut versions);

            pkt
        }

        /// Create random test data
        pub fn new_test_data(len: usize) -> bytes::Bytes {
            let mut data = BytesMut::with_capacity(len);
            data.resize(len, 0);
            rand::thread_rng().fill_bytes(&mut data);
            data.freeze()
        }

        /// Advertise new cids for each other
        pub fn advertise_new_cids(&mut self) -> Result<()> {
            let (scid, reset_token) = (ConnectionId::random(), Some(1));
            self.client
                .cids
                .add_scid(scid, reset_token, true, None, true)?;
            let packets = TestPair::conn_packets_out(&mut self.client)?;
            TestPair::conn_packets_in(&mut self.server, packets)?;

            let (scid, reset_token) = (ConnectionId::random(), Some(2));
            self.server
                .cids
                .add_scid(scid, reset_token, true, None, true)?;
            let packets = TestPair::conn_packets_out(&mut self.server)?;
            TestPair::conn_packets_in(&mut self.client, packets)?;
            Ok(())
        }

        /// Client add a new path and initiate the path validation
        pub fn add_and_validate_path(
            &mut self,
            client_addr: SocketAddr,
            server_addr: SocketAddr,
        ) -> Result<()> {
            self.client.add_path(client_addr, server_addr)?;

            // Client send PATH_CHALLENGE
            let packets = TestPair::conn_packets_out(&mut self.client)?;
            TestPair::conn_packets_in(&mut self.server, packets)?;

            // Server send PATH_RESPONSE/PATH_CHALLENGE
            let packets = TestPair::conn_packets_out(&mut self.server)?;
            TestPair::conn_packets_in(&mut self.client, packets)?;

            // Client send PATH_RESPONSE
            let packets = TestPair::conn_packets_out(&mut self.client)?;
            TestPair::conn_packets_in(&mut self.server, packets)?;
            Ok(())
        }
    }

    #[test]
    fn version_negotiation_with_unknown_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert_eq!(
            test_pair.client.recv(&mut pkt, &info),
            Err(Error::UnknownVersion)
        );

        Ok(())
    }

    #[test]
    fn version_negotiation_with_same_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x01],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_with_invalid_dcid() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.dcid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_with_invalid_scid() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Assemble version negotiation packet.
        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.scid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_with_invalid_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0xFF],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_after_other_packet() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn handshake_complete() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert!(test_pair.client.timers.get(Timer::Handshake).is_none());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_none());
        assert_eq!(test_pair.client.is_server(), false);
        assert_eq!(test_pair.server.is_server(), true);

        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        assert_eq!(test_pair.client.scid(), test_pair.server.dcid());
        assert_eq!(test_pair.server.scid(), test_pair.client.dcid());
        assert_eq!(test_pair.client.odcid(), test_pair.server.odcid());

        assert_eq!(test_pair.client.local_error(), None);
        assert_eq!(test_pair.server.local_error(), None);
        assert_eq!(test_pair.client.peer_error(), None);
        assert_eq!(test_pair.server.peer_error(), None);

        assert_eq!(test_pair.client.application_proto(), b"h3");
        assert_eq!(test_pair.client.server_name(), Some("example.org"));

        Ok(())
    }

    #[test]
    fn handshake_resume() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        // Client perform the first handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.client.is_resumed(), false);
        assert_eq!(test_pair.server.is_resumed(), false);

        // Client extract session state for resumption
        let session = test_pair.client.session().unwrap();

        // Client perform the second handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.client.is_resumed(), true);
        assert_eq!(test_pair.server.is_resumed(), true);
        assert_eq!(test_pair.client.application_proto(), b"h3");
        assert_eq!(test_pair.client.application_proto(), b"h3");

        Ok(())
    }

    #[test]
    fn handshake_confirm() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), false);
        assert_eq!(test_pair.client.is_confirmed(), false);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.is_confirmed(), false);
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send Handshake and completes handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.client.is_confirmed(), false);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.is_confirmed(), false);
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server complete and confirm handshake, send HANDSHAKE_DONE
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.client.is_confirmed(), false);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.server.is_confirmed(), true);

        // Client confirm handshake
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.client.is_confirmed(), true);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.server.is_confirmed(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_version_negotiation() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Inject a Version Negotiation packet to client
        let (initial_pkt, initial_info) = packets.pop().unwrap();
        let hdr = PacketHeader::from_bytes(&initial_pkt, 20)?.0;
        let mut buf = vec![0; 256];
        let len = packet::version_negotiation(&hdr.dcid, &hdr.scid, &mut buf)?;
        buf.truncate(len);
        let info = PacketInfo {
            src: initial_info.dst,
            dst: initial_info.src,
            time: initial_info.time,
            recv_timestamp: None,
            send_meta: PacketSendMeta::default(),
        };

        // Client drop the Version Negotiation packet with the same version.
        TestPair::conn_packets_in(&mut test_pair.client, vec![(buf, info)])?;

        // Client/Server continue the handshake
        TestPair::conn_packets_in(&mut test_pair.server, vec![(initial_pkt, initial_info)])?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_retry() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let lifetime = Duration::from_secs(86400);

        // Client send Initial without token
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Server build a Retry
        let (initial_pkt, info) = packets.pop().unwrap();
        let hdr = PacketHeader::from_bytes(&initial_pkt, 20)?.0;

        let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &[1; 16]).unwrap());
        let retry_scid = ConnectionId::random();
        let token = AddressToken::new_retry_token(client_addr, hdr.dcid, retry_scid);
        let token = token.encode(&key)?;

        let mut buf = vec![0; 256];
        let len = packet::retry(
            &retry_scid,
            &hdr.scid,
            &hdr.dcid,
            &token,
            crate::QUIC_VERSION_V1,
            &mut buf,
        )?;
        buf.truncate(len);
        let info = PacketInfo {
            src: info.dst,
            dst: info.src,
            time: info.time,
            recv_timestamp: None,
            send_meta: PacketSendMeta::default(),
        };

        // Client recv Retry
        TestPair::conn_packets_in(&mut test_pair.client, vec![(buf, info)])?;

        // Client send Initial with token
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Server validate token in Initial
        let (mut initial_pkt, info) = packets.pop().unwrap();
        let hdr = PacketHeader::from_bytes(&initial_pkt, 20)?.0;
        assert!(hdr.token.is_some());
        let token = AddressToken::decode(
            &key,
            &mut hdr.token.unwrap(),
            &client_addr,
            &hdr.dcid,
            lifetime,
        )?;

        // Server create server-side conn
        let server_iscid = ConnectionId::random();
        test_pair.server = Connection::new_server(
            &server_iscid,
            server_addr,
            client_addr,
            Some(&token),
            &mut TestPair::new_test_config(true)?,
        )?;
        test_pair.server.recv(&mut initial_pkt, &info)?;

        // Client/Server continue the handshake
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_0rtt_data() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        // Client perform the first handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client extract session state and try to perform the second handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;

        // Client send Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(test_pair.client.is_in_early_data());
        assert!(!packets.is_empty());

        // Client send ZeroRTT packet
        let content = "client zero rtt data";
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::ZeroRTT, &[frame])?;
        let info = packets.first().unwrap().1;

        // Server recv Initial packet
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert!(test_pair.client.is_in_early_data());

        // Server recv ZeroRTT packet
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(test_pair.server.streams.has_readable_streams());

        let stream = test_pair.server.streams.get_mut(0).unwrap();
        assert!(stream.is_readable());

        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);

        Ok(())
    }

    #[test]
    fn handshake_with_0rtt_reordered_server_side() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client perform the resumed handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;

        // Client send Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(test_pair.client.is_in_early_data());
        assert!(!packets.is_empty());

        // Client send ZeroRTT packet
        let content = "client zero rtt data before initial";
        let mut frames = vec![];
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        frames.push(frame);
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::ZeroRTT, &frames)?;
        let info = packets.first().unwrap().1;

        // Server recv ZeroRTT packet before Initial packet
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(test_pair.client.is_in_early_data());
        assert!(!test_pair.server.streams.has_readable_streams());
        assert!(!test_pair
            .server
            .undecryptable_packets
            .zerortt_pkts
            .is_empty());

        // Server recv the reordered Initial packet
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.is_in_early_data(), true);
        assert!(test_pair
            .server
            .undecryptable_packets
            .zerortt_pkts
            .is_empty());
        assert!(test_pair.server.streams.has_readable_streams());
        let stream = test_pair.server.streams.get_mut(0).unwrap();
        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);

        Ok(())
    }

    #[test]
    fn handshake_with_1rtt_reordered_server_side() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send and server recv Initial.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send and client recv Initial and Handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.is_established());

        // Client send OneRTT packet.
        let content = "client one rtt data before handshake";
        let mut frames = vec![];
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        frames.push(frame);
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &frames)?;

        // Client send Handshake packets.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let info = packets.first().unwrap().1;

        // Server recv OneRTT packet before Handshake packets.
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(!test_pair.server.is_confirmed());
        assert!(!test_pair
            .server
            .undecryptable_packets
            .onertt_pkts
            .is_empty());

        // Server recv the reordered Handshake packets.
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert!(test_pair.server.is_confirmed());
        assert!(test_pair
            .server
            .tls_session
            .get_keys(Level::OneRTT)
            .open
            .is_some());
        assert!(test_pair.server.streams.has_readable_streams());
        let stream = test_pair.server.streams.get_mut(0).unwrap();
        assert!(stream.is_readable());
        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);

        Ok(())
    }

    #[test]
    fn handshake_with_handshake_reordered_client_side() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), false);
        assert_eq!(test_pair.client.flags.contains(HandshakeConfirmed), false);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.flags.contains(HandshakeConfirmed), false);

        // Client recv Handshake before Initial.
        TestPair::conn_packets_in(&mut test_pair.client, vec![packets[1].clone()])?;
        assert_eq!(test_pair.client.is_established(), false);
        let undecryptable_handshake_packets =
            &test_pair.client.undecryptable_packets.handshake_pkts;
        assert_eq!(undecryptable_handshake_packets.is_empty(), false);
        TestPair::conn_packets_in(&mut test_pair.client, vec![packets[0].clone()])?;
        assert_eq!(test_pair.client.is_established(), true);
        let undecryptable_handshake_packets =
            &test_pair.client.undecryptable_packets.handshake_pkts;
        assert_eq!(undecryptable_handshake_packets.is_empty(), true);

        // Client send Initial/Handshake(ack)
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Continue handshake
        test_pair.handshake()?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_packet_loss() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Fake dropping client Initial packets
        packets.clear();
        let timeout = test_pair.client.timeout();
        let loss_time = test_pair.client.timers.get(Timer::LossDetection);
        assert!(loss_time.is_some());

        // Advance ticks until loss timeout
        let now = loss_time.unwrap();
        test_pair.client.on_timeout(now);
        packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send Handshake and complete handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), false);
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server complete handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_packet_corrupted() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send a Handshake but the packet is corrupted
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());
        let packet = &mut packets[0].0;
        let packet_len = packet.len();
        packet[packet_len - 1] = packet[packet_len - 1].wrapping_add(1);

        // Server recv a corrupted Handshake
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), false);

        // Client resend Handshake
        let timeout = test_pair.client.timeout();
        let loss_time = test_pair.client.timers.get(Timer::LossDetection);
        assert!(loss_time.is_some());
        test_pair.client.on_timeout(loss_time.unwrap());
        packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server complete handshake
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_anti_amplification_deadlock() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake.
        let mut packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Fake dropping the second Handshake packet.
        packets.truncate(1);

        // Client recv Initial and the first Handshake.
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(!test_pair.client.tls_session.is_completed());

        // Client send ACK and PADDING and wait for retransmission of the second packet.
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Client must set LossDetection timer to avoid deadlock
        assert!(test_pair.client.timeout().is_some());
        assert!(test_pair.client.timers.get(Timer::LossDetection).is_some());

        // Server retransmit Handshake but lost again
        for i in 0..5 {
            let dur = test_pair.server.timeout().unwrap();
            test_pair.server.on_timeout(time::Instant::now() + dur);
            let _ = TestPair::conn_packets_out(&mut test_pair.server)?;
        }

        // Server is blocked by anti-amplification limit
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(path.anti_ampl_limit, 0);
        }

        // A deadlock could occur when the server reaches its anti-amplification limit
        // and the client has received acknowledgments for all the data it has sent.
        // In this case, when the client has no reason to send additional packets, the
        // server will be unable to send more data because it has not validated the
        // client's address. To prevent this deadlock, clients MUST send a packet on a
        // Probe Timeout (PTO).
        let dur = test_pair.client.timeout().unwrap();
        test_pair.client.on_timeout(time::Instant::now() + dur);
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());

        // Server and client continue the handshake.
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert!(path.anti_ampl_limit > 0);
        }
        let dur = test_pair.server.timeout().unwrap();
        test_pair.server.on_timeout(time::Instant::now() + dur);

        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_alpn_mismatched() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        let tls_config = TlsConfig::new_server_config(
            "src/tls/testdata/cert.crt",
            "src/tls/testdata/cert.key",
            vec![b"http/0.9".to_vec()],
            true,
        )?;
        server_config.set_tls_config(tls_config);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert!(test_pair.handshake().is_err());

        Ok(())
    }

    #[test]
    fn handshake_with_timeout_enabled() -> Result<()> {
        const TIMEOUT: u64 = 3 * 1000;
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        client_config.set_max_handshake_timeout(TIMEOUT);
        server_config.set_max_handshake_timeout(TIMEOUT);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert!(test_pair.client.timers.get(Timer::Handshake).is_some());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_some());

        assert_eq!(test_pair.handshake(), Ok(()));
        assert!(test_pair.client.is_established());
        assert!(test_pair.server.is_established());
        assert!(test_pair.client.timers.get(Timer::Handshake).is_none());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_none());

        Ok(())
    }

    #[test]
    fn handshake_with_timeout_failed() -> Result<()> {
        const CLIENT_TIMEOUT: u64 = 60 * 1000;
        const SERVER_TIMEOUT: u64 = 30 * 1000;
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        client_config.set_max_handshake_timeout(CLIENT_TIMEOUT);
        server_config.set_max_handshake_timeout(SERVER_TIMEOUT);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert!(test_pair.client.timers.get(Timer::Handshake).is_some());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_some());

        // Client send all packets to server.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Fake losing server packets.
        let _ = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Fake timing out server's Handshake timer.
        let now = time::Instant::now() + time::Duration::from_millis(SERVER_TIMEOUT);
        test_pair.server.on_timeout(now);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.is_closed(), true);
        assert_eq!(test_pair.server.is_handshake_timeout(), true);

        // Fake timing out client's Handshake timer.
        let now = time::Instant::now() + time::Duration::from_millis(CLIENT_TIMEOUT);
        test_pair.client.on_timeout(now);
        assert_eq!(test_pair.client.is_established(), false);
        assert_eq!(test_pair.client.is_closed(), true);
        assert_eq!(test_pair.client.is_handshake_timeout(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_keylog() {
        let logger = NamedTempFile::new().unwrap();
        let mut f = logger.reopen().unwrap();

        let mut test_pair = TestPair::new_with_test_config().unwrap();
        test_pair.server.set_keylog(Box::new(logger));
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut log = String::new();
        f.read_to_string(&mut log).unwrap();
        assert_eq!(log.is_empty(), false);
        assert_eq!(log.contains("TRAFFIC_SECRET"), true);
    }

    #[test]
    fn handshake_multi_cert_with_known_sni() -> Result<()> {
        // New config selector.
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_tls_config_selector(conf_selector.clone());

        for i in 0..conf_selector.len() {
            let mut test_pair = TestPair::new_with_server_name(
                &mut client_config,
                &mut server_config,
                &i.to_string(),
            )?;

            assert!(test_pair.handshake().is_ok());
            assert!(test_pair.client.is_established());
            assert!(test_pair.server.is_established());
        }

        Ok(())
    }

    #[test]
    fn handshake_multi_cert_with_unknown_sni() -> Result<()> {
        // New config selector.
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_tls_config_selector(conf_selector.clone());

        let mut test_pair = TestPair::new_with_server_name(
            &mut client_config,
            &mut server_config,
            &"unknown".to_string(),
        )?;

        assert!(!test_pair.handshake().is_ok());

        Ok(())
    }

    #[test]
    fn handshake_with_multipath_negotiated() -> Result<()> {
        let cases = [
            // The items in each case are as following:
            // - client enable_multipath, client cid_len,
            // - server enable_multipath, server cid_len,
            // - multipath negotiation result
            (true, 8, false, 8, false),
            (false, 8, false, 8, false),
            (false, 8, true, 8, false),
            (true, 8, true, 8, true),
            (true, 0, true, 8, false),
            (true, 8, true, 0, false),
        ];
        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_multipath(case.0);
            client_config.set_cid_len(case.1);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_multipath(case.2);
            server_config.set_cid_len(case.3);

            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            assert_eq!(test_pair.handshake(), Ok(()));
            assert_eq!(test_pair.client.is_multipath(), case.4);
            assert_eq!(test_pair.server.is_multipath(), case.4);
        }

        Ok(())
    }

    #[test]
    fn handshake_with_disable_encryption_negotiated() -> Result<()> {
        let cases = [
            // The items in each case are as following:
            // - client disable_encryption
            // - server disable_encryption
            // - disable_encryption negotiation result
            //(true, false, false),
            //(false,false, false),
            //(false, true, false),
            (true, true, true),
        ];
        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_encryption(!case.0);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_encryption(!case.1);

            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            assert_eq!(test_pair.handshake(), Ok(()));
            assert_eq!(test_pair.client.flags.contains(DisableEncryption), case.2);
            assert_eq!(test_pair.server.flags.contains(DisableEncryption), case.2);
        }

        Ok(())
    }

    #[test]
    fn max_datagram_size() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_send_udp_payload_size(1200);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_recv_udp_payload_size(1550);
        server_config.set_initial_max_data(10000);
        server_config.set_initial_max_stream_data_bidi_remote(10000);
        server_config.set_ack_eliciting_threshold(1);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(
            test_pair.client.paths.get(0)?.recovery.max_datagram_size,
            1200,
        );

        // Handshake and discovery path MTU
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        // Check path MTU
        let mds_ipv4 = 1472;
        assert_eq!(
            test_pair.client.paths.get(0)?.recovery.max_datagram_size,
            mds_ipv4
        );

        // Check outgoing packet size
        let mut buf = vec![0; 2000];
        assert!(test_pair
            .client
            .stream_write(0, Bytes::from(vec![0; 2000]), true)
            .is_ok());
        let r = test_pair.client.send(&mut buf, &NoopSender);
        assert!(r.is_ok());
        assert_eq!(r.unwrap().0, mds_ipv4);

        Ok(())
    }

    #[test]
    fn transport_params() -> Result<()> {
        let server_trans_params = TransportParams {
            max_idle_timeout: 15000,
            initial_max_data: 1024000,
            ..TransportParams::default()
        };

        // Client perform the first handshake
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = server_trans_params.clone();

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(
            test_pair.client.peer_transport_params.max_idle_timeout,
            server_trans_params.max_idle_timeout
        );
        assert_eq!(
            test_pair.client.peer_transport_params.initial_max_data,
            server_trans_params.initial_max_data
        );

        // Client perform the second handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;
        assert_eq!(
            test_pair.client.peer_transport_params.max_idle_timeout,
            server_trans_params.max_idle_timeout
        );
        assert_eq!(
            test_pair.client.peer_transport_params.initial_max_data,
            server_trans_params.initial_max_data
        );
        assert_eq!(test_pair.handshake(), Ok(()));

        Ok(())
    }

    #[test]
    fn cid_advertise_and_retire() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.client.set_index(0);
        test_pair.server.set_index(0);
        test_pair.handshake()?;

        // Client add a new cid
        let (scid, reset_token) = (ConnectionId::random(), 1);
        test_pair.client.add_scid(scid, reset_token, true)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 0);

        // Client send NEW_CONNECTION_ID
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1);

        // Client add another cid
        let (scid, reset_token) = (ConnectionId::random(), 2);
        test_pair.client.add_scid(scid, reset_token, true)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 2);

        // Client send NEW_CONNECTION_ID
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 2);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1); // exceed cid limit

        // Server send RETIRE_CONNECTION_ID
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1);

        Ok(())
    }

    #[test]
    fn cid_add_exceed_limit() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client add a new cid
        test_pair.client.add_scid(ConnectionId::random(), 1, true)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);

        // Client add more cid
        assert_eq!(
            test_pair.client.add_scid(ConnectionId::random(), 2, false),
            Err(Error::ConnectionIdLimitError)
        );

        Ok(())
    }

    #[test]
    fn cid_advertise_on_zero_cid_conn() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let frame = frame::Frame::NewConnectionId {
            seq_num: 1,
            retire_prior_to: 0,
            conn_id: ConnectionId::random(),
            reset_token: ResetToken(1_u128.to_be_bytes()),
        };
        let mut packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;

        let info = TestPair::new_test_packet_info(false);
        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn cid_retire_on_zero_cid_conn() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let frame = frame::Frame::RetireConnectionId { seq_num: 1 };
        let mut packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;

        let info = TestPair::new_test_packet_info(false);
        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn path_new_by_client() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.paths_iter().len(), 1);
        assert_eq!(test_pair.server.paths_iter().len(), 1);

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        // Client and server advertise new cids
        test_pair.advertise_new_cids()?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.client.cids.unused_dcids(), 1);
        assert_eq!(test_pair.server.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1);

        // Client try to add path again
        test_pair.client.add_path(client_addr, server_addr)?;
        assert_eq!(test_pair.client.paths_iter().len(), 2);
        assert_eq!(test_pair.server.paths_iter().len(), 1);
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Unknown
        );

        // Client send PATH_CHALLENGE
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validating
        );

        // Server send PATH_RESPONSE/PATH_CHALLENGE
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.server.paths_iter().len(), 2);
        assert_eq!(
            test_pair.server.get_path(server_addr, client_addr)?.state(),
            PathState::Validating
        );

        // Client recv PATH_RESPONSE/PATH_CHALLENGE
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validated
        );

        // Client send PATH_RESPONSE
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(
            test_pair.server.get_path(server_addr, client_addr)?.state(),
            PathState::Validated
        );

        Ok(())
    }

    #[test]
    fn path_new_duplicated() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        assert_eq!(
            test_pair.client.add_path(client_addr, server_addr),
            Err(Error::Done)
        );
        Ok(())
    }

    #[test]
    fn path_new_with_zero_cid() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        // Client try to add path the connection with non-zero cid
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.add_path(client_addr, server_addr), Ok(1));
        let path = test_pair.client.get_path(client_addr, server_addr)?;
        assert_eq!(path.dcid_seq, None);

        // Client try to add path on the connection with zero cid
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.add_path(client_addr, server_addr), Ok(1));

        Ok(())
    }

    #[test]
    fn path_new_by_server() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 444);

        // Server try to add path
        assert_eq!(
            test_pair.server.add_path(server_addr, client_addr),
            Err(Error::InvalidOperation("disallowed".into()))
        );
        Ok(())
    }

    #[test]
    fn path_chal_timer_operations() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client and server advertise new cids.
        test_pair.advertise_new_cids()?;

        // Client try to add path.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.client.add_path(client_addr, server_addr)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Unknown
        );
        assert!(test_pair.client.timers.get(Timer::PathChallenge).is_none());

        // Client send PATH_CHALLENGE and start PathChallenge timer.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validating
        );
        assert!(test_pair.client.timeout().is_some());
        assert!(test_pair.client.timers.get(Timer::PathChallenge).is_some());

        // Client recv PATH_RESPONSE and stop PathChallenge timer.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validated
        );
        assert!(test_pair.client.timeout().is_some());
        assert!(test_pair.client.timers.get(Timer::PathChallenge).is_none());

        Ok(())
    }

    #[test]
    fn path_chal_with_packet_loss() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;

        // Client send and fake lost of PATH_CHALLENGE.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let pid = test_pair.client.add_path(client_addr, server_addr)? as usize;
        TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(
            test_pair.client.paths.get(pid)?.state(),
            PathState::Validating
        );

        // Advance ticks until PATH_CHALLENGE timeout.
        assert!(test_pair.client.timeout().is_some());
        let now = time::Instant::now() + time::Duration::from_millis(path::INITIAL_CHAL_TIMEOUT);
        test_pair.client.on_timeout(now);

        // Client send PATH_CHALLENGE again.
        assert!(test_pair
            .client
            .paths
            .get(pid)?
            .need_send_validation_frames(false));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Client recv PATH_RESPONSE.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.paths.get(pid)?.state(),
            PathState::Validated
        );

        Ok(())
    }

    #[test]
    fn path_chal_loss_and_failed() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;

        // Client send and fake lost of PATH_CHALLENGE.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let pid = test_pair.client.add_path(client_addr, server_addr)? as usize;
        TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(
            test_pair.client.paths.get(pid)?.state(),
            PathState::Validating
        );

        for i in 0..path::MAX_PROBING_TIMEOUTS {
            // Advance ticks until PATH_CHALLENGE timeout.
            assert!(test_pair.client.timeout().is_some());
            let now = test_pair.client.timers.get(Timer::PathChallenge).unwrap();
            test_pair.client.on_timeout(now);

            // Try to send PATH_CHALLENGE again.
            TestPair::conn_packets_out(&mut test_pair.client)?;
        }

        // Path validation finally failed.
        assert_eq!(test_pair.client.paths.get(pid)?.state(), PathState::Failed);

        Ok(())
    }

    #[test]
    fn path_active_all_failed() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Fake failing of all active path
        let path = test_pair.client.paths.get_mut(0)?;
        path.set_active(false);

        assert!(test_pair.client.scid().is_err());
        assert!(test_pair.client.dcid().is_err());

        Ok(())
    }

    #[test]
    fn path_anti_ampl_limit() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(path.anti_ampl_limit, 0);
        }

        // Client send Initial.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let len_in: usize = packets.iter().map(|p| p.0.len()).sum();

        // Server recv Initial.
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(
                path.anti_ampl_limit,
                len_in * test_pair.server.paths.anti_ampl_factor
            );
        }

        // Server send Initial and Handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        let len_out: usize = packets.iter().map(|p| p.0.len()).sum();
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(
                path.anti_ampl_limit,
                len_in * test_pair.server.paths.anti_ampl_factor - len_out
            );
        }

        Ok(())
    }

    #[test]
    fn path_mtu_discovery_max() -> Result<()> {
        let cases = [
            // (cli_enable_dplpmtud, srv_enable_dplpmtud, cli_mtu , srv_mtu)
            (false, false, 1200, 1200),
            (false, true, 1200, 1472),
            (true, false, 1472, 1200),
            (true, true, 1472, 1472),
        ];

        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_dplpmtud(case.0);
            client_config.set_ack_eliciting_threshold(1);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_dplpmtud(case.1);
            server_config.set_ack_eliciting_threshold(1);
            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            assert_eq!(test_pair.handshake(), Ok(()));

            test_pair.move_forward()?;
            assert_eq!(
                test_pair.client.paths.get(0)?.recovery.max_datagram_size,
                case.2
            );
            assert_eq!(
                test_pair.server.paths.get(0)?.recovery.max_datagram_size,
                case.3
            );
        }

        Ok(())
    }

    #[test]
    fn path_mtu_discovery_lost() -> Result<()> {
        let cases = [
            // (router_mtu, searched_mtu)
            (1472, 1463),
            (1452, 1446),
            (1432, 1429),
            (1412, 1404),
            (1392, 1387),
            (1372, 1370),
        ];

        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_dplpmtud(true);
            client_config.set_ack_eliciting_threshold(1);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_dplpmtud(false);
            server_config.set_initial_max_data(10240);
            server_config.set_initial_max_stream_data_bidi_remote(10240);
            server_config.set_ack_eliciting_threshold(1);
            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            let router_mtu: usize = case.0;

            // Handshake
            while !test_pair.client.is_established() || !test_pair.server.is_established() {
                let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
                packets.retain(|p| p.0.len() < router_mtu); // fake dropping packets
                TestPair::conn_packets_in(&mut test_pair.server, packets)?;

                let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
                TestPair::conn_packets_in(&mut test_pair.client, packets)?;
            }

            // Path MTU searching
            let data = Bytes::from_static(b"data");
            for i in 0..30 {
                let _ = test_pair.client.stream_write(0, data.clone(), false);
                let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
                packets.retain(|p| p.0.len() < router_mtu); // fake dropping packets

                TestPair::conn_packets_in(&mut test_pair.server, packets)?;
                let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
                TestPair::conn_packets_in(&mut test_pair.client, packets)?;

                if test_pair.client.timeout().is_some() {
                    let timeout = test_pair.client.timers.get(Timer::LossDetection);
                    test_pair.client.on_timeout(timeout.unwrap());
                }
            }

            // Check final MTU
            assert_eq!(
                test_pair.client.paths.get(0)?.recovery.max_datagram_size,
                case.1
            );
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "qlog")]
    fn ping() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_dplpmtud(false);
        client_config.local_transport_params = TransportParams {
            max_idle_timeout: 15000,
            ..TransportParams::default()
        };
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.enable_dplpmtud(false);
        server_config.local_transport_params = TransportParams {
            max_idle_timeout: 15000,
            ..TransportParams::default()
        };
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;

        // Move both connections to idle state
        test_pair.move_forward()?;

        // Enable qlog for Server
        let slog = NamedTempFile::new().unwrap();
        let mut sfile = slog.reopen().unwrap();
        test_pair
            .server
            .set_qlog(Box::new(slog), "title".into(), "desc".into());

        // Client send a Ping frame
        test_pair.client.ping(None)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets.clone())?;

        let mut slog_content = String::new();
        sfile.read_to_string(&mut slog_content).unwrap();
        assert_eq!(slog_content.contains("quic:packet_received"), true);
        assert_eq!(slog_content.contains("frame_type\":\"ping"), true);

        Ok(())
    }

    #[test]
    fn conn_basic_operations() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;

        assert!(test_pair.client.trace_id().contains("CLIENT"));
        assert!(test_pair.server.trace_id().contains("SERVER"));

        assert!(test_pair.client.stats().recv_count > 0);
        assert!(test_pair.client.stats().sent_count > 0);

        assert!(test_pair.client.context().is_none());
        let cli_ctx = String::from("client context");
        test_pair.client.set_context(cli_ctx);
        assert!(test_pair.client.context().is_some());

        let ctx = test_pair.client.context().unwrap();
        let ctx = ctx.downcast_ref::<String>().unwrap();
        assert_eq!(ctx, "client context");

        assert!(test_pair.client.stream_context(0).is_none());
        let stream_ctx = String::from("client stream context");
        test_pair.client.stream_set_context(0, stream_ctx)?;
        assert!(test_pair.client.stream_context(0).is_some());

        let ctx = test_pair.client.stream_context(0).unwrap();
        let ctx = ctx.downcast_ref::<String>().unwrap();
        assert_eq!(ctx, "client stream context");

        Ok(())
    }

    #[test]
    fn recv_packet_empty_buffer() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Ignore the empty packet
        assert_eq!(test_pair.server.recv(&mut [], &info), Err(Error::NoError));
        assert_eq!(
            test_pair.server.recv_packet(&mut [], &info, None),
            Err(Error::Done)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unknown_addr() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Server send NEW_CONNECTION_ID
        let (scid, reset_token) = (ConnectionId::random(), Some(1));
        test_pair
            .server
            .cids
            .add_scid(scid, reset_token, true, None, true)?;
        let mut packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert!(!packets.is_empty());

        // Change the packet address
        let (mut packet, mut info) = packets.pop().unwrap();
        info.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 10, 10, 10)), 443);

        // Client drop the packet with unknown address
        test_pair.client.recv(&mut packet, &info)?;
        Ok(())
    }

    #[test]
    fn recv_packet_empty_payload() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let mut packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[])?;
        let info = TestPair::new_test_packet_info(false);

        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_duplicated() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv Initial
        TestPair::conn_packets_in(&mut test_pair.server, packets.clone())?;

        // Server recv duplicated Initial
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unknown_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Version field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        let mut version = &mut initial_pkt[1..5]; // version field
        version.write_u32(0x1a1a1a1a)?;

        // Server recv Initial packet with unknown version
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Err(Error::UnknownVersion)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unmatched_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial/Handshake packet
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send Handshake
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Version field of the Handshake packet
        let initial_pkt = &mut packets[0].0;
        let mut version = &mut initial_pkt[1..5]; // version field
        version.write_u32(0xbabababa)?;

        // Server drop the packet with unmatched version
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_length_too_big() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Length field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        let mut len = &mut initial_pkt[48..50]; // length field
        len.write_varint_with_len(10000 as u64, 2)?;

        // Server drop Initial packet with invalid length
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_length_too_small() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Length field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        let mut len = &mut initial_pkt[48..50]; // length field
        len.write_varint_with_len(1 as u64, 2)?;

        // Server drop Initial packet with invalid length
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_length_variant_error() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial.
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Tamper Length field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        initial_pkt[48] = 0;
        initial_pkt[49] = 0;

        // Server drop Initial packet with invalid length
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_truncated() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Truncate the Initial packet
        let (mut initial_pkt, info) = packets.pop().unwrap();
        initial_pkt.truncate(100);

        // Server drop the truncated packet
        assert_eq!(
            test_pair.server.recv_packet(&mut initial_pkt, &info, None),
            Err(Error::Done)
        );
        assert_eq!(
            test_pair.server.recv(&mut initial_pkt, &info),
            Ok(initial_pkt.len())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_handshake_done() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut packet = TestPair::conn_build_packet(
            &mut test_pair.client,
            PacketType::OneRTT,
            &[frame::Frame::HandshakeDone],
        )?;
        let info = TestPair::new_test_packet_info(false);

        // Server recv HANDSHAKE_DONE
        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unknown_dcid() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client send NEW_CONNECTION_ID
        let (scid, reset_token) = (ConnectionId::random(), Some(1));
        test_pair
            .server
            .cids
            .add_scid(scid, reset_token, true, None, true)?;
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());

        // Tamper dcid field of the OneRTT packet
        let (mut packet, info) = packets.pop().unwrap();
        packet[1] = packet[1].wrapping_add(1); // change first byte of dcid field

        // Server drop the packet with unknown dcid
        assert!(test_pair.server.recv(&mut packet, &info).is_ok());
        Ok(())
    }

    #[test]
    fn recv_packet_stream_frame() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send OneRTT packet
        let content = "client one rtt data";
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;
        let info = TestPair::new_test_packet_info(false);

        // Server recv OneRTT packet
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(test_pair.server.streams.has_readable_streams());

        let stream = test_pair.server.streams.get_mut(0).unwrap();
        assert!(stream.is_readable());

        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);
        Ok(())
    }

    #[test]
    fn recv_packet_skipped_packet_number() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.enable_dplpmtud(false);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let info = TestPair::new_test_packet_info(false);
        for i in 0..crate::MAX_ACK_RANGES + 10 {
            // Inject OneRTT packet with skipped packet number
            let space = test_pair.client.spaces.get_mut(SpaceId::Data).unwrap();
            space.next_pkt_num += 1;
            let packet = TestPair::conn_build_packet(
                &mut test_pair.client,
                PacketType::OneRTT,
                &[frame::Frame::Ping { pmtu_probe: None }],
            )?;

            // Server recv OneRTT packet and send ack
            TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;

            let space = &test_pair.server.spaces.get(SpaceId::Data).unwrap();
            let ranges_expected = if i < crate::MAX_ACK_RANGES {
                i + 1
            } else {
                crate::MAX_ACK_RANGES
            };
            assert_eq!(space.recv_pkt_num_need_ack.len(), ranges_expected);
        }
        Ok(())
    }

    #[test]
    fn send_packet_consecutive_non_ack_eliciting() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let info = TestPair::new_test_packet_info(false);
        for i in 0..space::MAX_NON_ACK_ELICITING + 10 {
            // Client send OneRTT packet
            let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            let space = test_pair.client.spaces.get_mut(SpaceId::Data).unwrap();
            space.next_pkt_num += 1;
            packets.push((
                TestPair::conn_build_packet(
                    &mut test_pair.client,
                    PacketType::OneRTT,
                    &[frame::Frame::Ping { pmtu_probe: None }],
                )?,
                info,
            ));

            // Server recv OneRTT packet
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;

            // Server send ack packet with occasional PING to elicit ack
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;

            let space = test_pair.server.spaces.get(SpaceId::Data).unwrap();
            assert!(space.consecutive_non_ack_eliciting_sent <= space::MAX_NON_ACK_ELICITING);
        }

        Ok(())
    }

    #[test]
    fn ack_initial_or_handshake_space() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(2);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(2);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        // Client send 1 UDP datagram carrying 1 Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(packets.len(), 1);

        // Server send 2 UDP datagrams carrying 1 Initial packet and 2 Handshake packets
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(packets.len(), 2);

        // Client's Initial must be acknowledged immediately
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        {
            let stat = test_pair.client.paths.get_active_mut()?.stats();
            assert_eq!(stat.acked_count, 1);
        }

        // Client send Handshake and completes handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server's Initial/Handshake must be acknowledged immediately
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        {
            let stat = test_pair.server.paths.get_active_mut()?.stats();
            assert_eq!(stat.acked_count, 3);
        }

        Ok(())
    }

    #[test]
    fn ack_data_space_ack_eliciting_threshold() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(4);
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(4);
        server_config.enable_dplpmtud(false);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        let data = Bytes::from_static(b"QUIC");
        let sid = test_pair.client.stream_bidi_new(0, false)?;
        let acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;

        for i in 0..4 {
            // Client write data on the stream
            test_pair.client.stream_write(sid, data.clone(), false)?;
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

            // Server recv packets from the client
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

            TestPair::conn_packets_in(&mut test_pair.client, packets)?;
            let new_acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;
            if i < 3 {
                assert_eq!(acked_pkts, new_acked_pkts);
            } else {
                assert_eq!(acked_pkts + 4, new_acked_pkts);
            }
        }

        Ok(())
    }

    #[test]
    fn stream_unacked_bytes_cover_written_until_acked() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        let sid = test_pair.client.stream_bidi_new(0, false)?;
        assert_eq!(test_pair.client.stream_unacked_bytes(sid), Some(0));
        test_pair.client.stream_write(sid, Bytes::from_static(b"QUIC"), false)?;
        // Written, not even sent.
        assert_eq!(test_pair.client.stream_unacked_bytes(sid), Some(4));

        // Sent but lost: still unacknowledged.
        let _lost = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.stream_unacked_bytes(sid), Some(4));
        test_pair.client.stream_write(sid, Bytes::from_static(b"DATA"), false)?;
        assert_eq!(test_pair.client.stream_unacked_bytes(sid), Some(8));

        // The second chunk arrives and is acknowledged; the first is still
        // missing, so nothing is acknowledged in order yet.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.stream_unacked_bytes(sid), Some(8));

        // Recovery resends the first chunk (declared lost right away by the
        // time threshold, or on the loss timer); once acknowledged, all is.
        for _ in 0..10 {
            if test_pair.client.stream_unacked_bytes(sid) == Some(0) {
                break;
            }
            // `timeout()` brings the paths' loss timers into `timers`.
            if test_pair.client.timeout().is_some() {
                if let Some(now) = test_pair.client.timers.get(Timer::LossDetection) {
                    test_pair.client.on_timeout(now);
                }
            }
            test_pair.move_forward()?;
        }
        assert_eq!(test_pair.client.stream_unacked_bytes(sid), Some(0));
        assert_eq!(test_pair.client.stream_unacked_bytes(sid + 4), None);
        Ok(())
    }

    #[test]
    fn ack_data_space_ack_timeout() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(4);
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(4);
        server_config.enable_dplpmtud(false);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        let data = Bytes::from_static(b"QUIC");
        let sid = test_pair.client.stream_bidi_new(0, false)?;
        let acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;

        // Client write data on the stream
        test_pair.client.stream_write(sid, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv packets from the client
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(packets.len(), 0);

        // Advance server ticks until ack timeout
        assert!(test_pair.server.timeout().is_some());
        let ack_timeout = test_pair.server.timers.get(Timer::Ack);
        assert!(ack_timeout.is_some());
        let now = ack_timeout.unwrap();
        test_pair.server.on_timeout(now);

        // Server send ack
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        let new_acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;
        assert_eq!(acked_pkts + 1, new_acked_pkts);

        Ok(())
    }

    #[test]
    fn conn_close_by_application() -> Result<()> {
        // Establish a connection
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let err = ConnectionError {
            is_app: true,
            error_code: 0x1,
            frame: None,
            reason: b"exit".to_vec(),
        };

        // Client close the connection
        test_pair.client.close(true, 0x1, "exit".as_bytes())?;
        assert!(test_pair.client.is_closing());
        assert_eq!(test_pair.client.local_error(), Some(&err));
        assert_eq!(test_pair.client.peer_error(), None);

        // Client try to close the connection again
        assert_eq!(test_pair.client.close(true, 0x2, &[]), Err(Error::Done));

        // Client send CONNECTION_CLOSE
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.server.is_closing(), false);
        assert_eq!(test_pair.server.is_draining(), false);

        // Server recv CONNECTION_CLOSE and enter DRAINING
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.is_draining(), true);
        assert_eq!(test_pair.server.local_error(), None);
        assert_eq!(test_pair.server.peer_error(), Some(&err));
        assert_eq!(test_pair.server.close(false, 0x3, &[]), Err(Error::Done));

        Ok(())
    }

    #[test]
    fn conn_close_by_transport() -> Result<()> {
        // Establish a connection
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client close the connection
        test_pair.client.close(false, 0, "shutdown".as_bytes())?;
        assert!(test_pair.client.is_closing());
        assert_eq!(test_pair.client.close(false, 0, &[]), Err(Error::Done));

        // Client send CONNECTION_CLOSE and Server enter DRAINING
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.server.is_closing(), false);
        assert_eq!(test_pair.server.is_draining(), false);

        TestPair::conn_packets_in(&mut test_pair.server, packets.clone())?;
        assert_eq!(test_pair.server.is_draining(), true);

        // Server try to close the connection again
        assert_eq!(test_pair.server.close(false, 0, &[]), Err(Error::Done));

        // Connection in the draining state drop the incoming packets
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );

        Ok(())
    }

    #[test]
    fn conn_idle_timeout() -> Result<()> {
        let client_trans_params = TransportParams {
            max_idle_timeout: 60000,
            ..TransportParams::default()
        };
        let server_trans_params = TransportParams {
            max_idle_timeout: 15000,
            ..TransportParams::default()
        };
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.local_transport_params = client_trans_params.clone();
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = server_trans_params.clone();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.client.timeout(), None);
        assert_eq!(test_pair.server.timeout(), None);

        // Client/Server establish a connection
        test_pair.handshake()?;

        assert!(test_pair.client.timeout().is_some());
        let client_idle_timeout = test_pair.client.timers.get(Timer::Idle);
        assert!(client_idle_timeout.is_some());

        assert!(test_pair.server.timeout().is_some());
        let server_idle_timeout = test_pair.server.timers.get(Timer::Idle);
        assert!(server_idle_timeout.is_some());

        // Advance server ticks until idle timeout
        let now = server_idle_timeout.unwrap();
        test_pair.server.on_timeout(now);
        assert!(test_pair.server.is_idle_timeout());
        assert!(test_pair.server.is_closed());

        // Advance client ticks until idle timeout
        let now = client_idle_timeout.unwrap();
        test_pair.client.on_timeout(now);
        assert!(test_pair.client.is_idle_timeout());
        assert!(test_pair.client.is_closed());

        Ok(())
    }

    #[test]
    fn conn_idle_timeout_without_active_paths() -> Result<()> {
        let trans_params = TransportParams {
            max_idle_timeout: 10000,
            ..TransportParams::default()
        };
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.local_transport_params = trans_params.clone();
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = trans_params.clone();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        // Client/Server establish a connection
        test_pair.handshake()?;

        // Fake failing of initial path
        let path = test_pair.client.paths.get_mut(0)?;
        path.set_active(false);

        assert!(test_pair.client.timeout().is_some());
        assert_eq!(
            test_pair.client.idle_timeout(),
            Some(time::Duration::from_millis(10000))
        );

        Ok(())
    }

    #[test]
    fn conn_draining_timeout() -> Result<()> {
        // Client/Server establish a connection
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client close the connection and send CONNECTION_CLOSE
        test_pair.client.close(false, 0, "shutdown".as_bytes())?;
        assert!(test_pair.client.is_closing());

        // Server recv CONNECTION_CLOSE and enters DRAINING
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.is_draining(), true);

        assert!(test_pair.server.timeout().is_some());
        let draining_timeout = test_pair.server.timers.get(Timer::Draining);
        assert!(draining_timeout.is_some());

        // Advance ticks until draining timeout
        let now = draining_timeout.unwrap();

        // Server connection closed.
        test_pair.server.on_timeout(now);
        assert!(test_pair.server.is_closed());
        assert_eq!(test_pair.server.timeout(), None);

        Ok(())
    }

    #[test]
    fn stream_operations() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let data = Bytes::from_static(b"EverythingOverQUIC");
        let sid = 4;

        // Client create a stream
        test_pair.client.stream_new(sid, 0, false)?;
        test_pair.client.stream_set_priority(sid, 1, false)?;
        test_pair.client.stream_want_write(sid, true)?;
        test_pair.client.stream_want_read(sid, true)?;
        assert_eq!(test_pair.client.get_streams().len(), 1);
        assert_eq!(test_pair.client.stream_writable_iter().len(), 1);
        assert!(test_pair.client.stream_writable(sid, data.len())?);
        assert!(test_pair.client.stream_capacity(sid)? > 0);

        // Client write data on the stream
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), true),
            Ok(data.len())
        );

        // Client shutdown the stream
        test_pair.client.stream_shutdown(sid, Shutdown::Read, 0)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read data from the client-initiated stream
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.stream_readable_iter().len(), 1);
        assert!(test_pair.server.stream_readable(sid));

        let mut buf = vec![0; data.len()];
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf)?,
            (data.len(), true)
        );
        assert_eq!(&buf[..data.len()], &data[..]);
        assert!(test_pair.server.stream_finished(sid));

        // Server shutdown the stream
        assert_eq!(
            test_pair.server.stream_shutdown(sid, Shutdown::Read, 0),
            Err(Error::Done)
        );
        assert_eq!(
            test_pair.server.stream_shutdown(sid, Shutdown::Write, 0),
            Err(Error::Done)
        );

        Ok(())
    }

    #[test]
    fn stream_multiply_write_and_read() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        for (data, fin) in vec![
            (Bytes::from_static(b"Everything"), false),
            (Bytes::from_static(b"Over"), false),
            (Bytes::from_static(b"QUIC"), true),
        ] {
            // Client write and send data on stream 4
            let len = data.len();
            assert_eq!(test_pair.client.stream_write(4, data.clone(), fin), Ok(len));
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

            // Server recv and read data on stream 4
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            let mut buf = vec![0; 18];
            assert_eq!(test_pair.server.stream_read(4, &mut buf)?, (len, fin));
            assert_eq!(&buf[..len], &data[..]);
        }

        Ok(())
    }

    #[test]
    fn stream_multiplex_write_and_read() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut tests = vec![
            (0, Bytes::from_static(b"Everything"), true),
            (4, Bytes::from_static(b"Over"), true),
            (8, Bytes::from_static(b"QUIC"), true),
        ];

        // Client write data on each stream
        for (sid, data, fin) in &tests {
            let len = data.len();
            assert_eq!(
                test_pair.client.stream_write(*sid, data.clone(), *fin),
                Ok(len)
            );
        }
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read data on each stream
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        tests.shuffle(&mut thread_rng());
        for (sid, data, fin) in &tests {
            let mut buf = vec![0; 18];
            let len = data.len();
            assert_eq!(test_pair.server.stream_read(*sid, &mut buf)?, (len, *fin));
            assert_eq!(&buf[..len], &data[..]);
        }

        Ok(())
    }

    #[test]
    fn stream_0rtt() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        // Client perform the first handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client extract session state and try to perform the second handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;

        // Client write data on the stream
        let data = Bytes::from_static(b"Zero RTT data");
        let sid = 0;
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false),
            Ok(data.len())
        );
        let packets2 = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv Initial/ZeroRTT packet
        TestPair::conn_packets_in(&mut test_pair.server, packets2)?;
        let stream = test_pair.server.streams.get_mut(sid).unwrap();
        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (data.len(), false));
        assert_eq!(&data, &buf[..data.len()]);

        Ok(())
    }

    #[test]
    fn stream_flow_control_update() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create a stream
        let sid = 0;
        test_pair.client.stream_set_priority(sid, 0, false)?;
        assert_eq!(test_pair.client.stream_capacity(sid)?, 40);

        // Client send data on the stream
        let data = TestPair::new_test_data(30);
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false)?,
            data.len()
        );
        assert_eq!(test_pair.client.stream_capacity(sid)?, 10);

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server read data from the stream
        let mut buf = [0; 64];
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf)?,
            (data.len(), false)
        );

        // Server send MAX_STREAM_DATA
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.stream_capacity(sid)?, 40);

        Ok(())
    }

    #[test]
    fn stream_flow_control_limit_error() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send a STREAM to the server
        let data = TestPair::new_test_data(41);
        let frame = TestPair::new_test_stream_frame(&data);
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;
        let info = TestPair::new_test_packet_info(false);

        // Server found FlowControlError
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)]),
            Err(Error::FlowControlError)
        );
        let ConnectionError { error_code, .. } = test_pair.server.local_error().unwrap();
        assert_eq!(*error_code, Error::FlowControlError.to_wire());

        Ok(())
    }

    #[test]
    fn conn_multi_incremental_streams_send_round_robin() -> Result<()> {
        let server_transport_params = TransportParams {
            initial_max_data: 20000,
            initial_max_stream_data_bidi_remote: 20000,
            initial_max_streams_bidi: 4,
            ..TransportParams::default()
        };

        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = server_transport_params.clone();

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // 1. Client create four bidi streams [0, 4, 8, 12], and write data on them
        let data = TestPair::new_test_data(1000);
        for i in 0..4 {
            assert_eq!(
                test_pair.client.stream_write(i * 4, data.clone(), true)?,
                data.len()
            );
        }

        // 2. Try to send stream data in round-robin order
        let mut packets = Vec::new();
        for i in 0..4 {
            let mut out = vec![0u8; 1500];
            let info = match test_pair.client.send(&mut out, &NoopSender) {
                Ok((written, info)) => {
                    out.truncate(written);
                    info
                }
                Err(e) => return Err(e),
            };
            packets.push((out, info));
        }

        // 3. Server recv stream data, all streams must be readable
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        for i in 0..4 {
            assert!(test_pair.server.stream_readable(i * 4));
        }

        Ok(())
    }

    /// A connection whose sends run dry with room left in the congestion
    /// window reports itself application-limited to BBR, so the keep-alive
    /// PING it sends next is acknowledged as an application-limited
    /// delivery-rate sample rather than a bandwidth measurement.
    #[test]
    fn conn_running_out_of_data_marks_bbr_samples_app_limited() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_congestion_control_algorithm(CongestionControlAlgorithm::Bbr);
        client_config.set_initial_max_data(1 << 20);
        client_config.set_initial_max_stream_data_bidi_remote(1 << 20);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_initial_max_data(1 << 20);
        server_config.set_initial_max_stream_data_bidi_remote(1 << 20);
        // Acknowledge the lone PING at once: the test does not advance the
        // clock to the delayed-ACK timer.
        server_config.set_ack_eliciting_threshold(1);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let data = TestPair::new_test_data(20_000);
        test_pair.client.stream_write(0, data, true)?;
        test_pair.move_forward()?;

        test_pair.client.ping(None)?;
        test_pair.move_forward()?;

        let (local, remote) = {
            let path = test_pair.client.paths.get_active()?;
            (path.local_addr(), path.remote_addr())
        };
        let stats = test_pair.client.get_path_stats(local, remote)?;
        assert!(stats.bandwidth_model_valid);
        assert!(
            stats.delivery_rate_sample_app_limited,
            "the PING sent after the stream ran dry must be an app-limited sample"
        );
        Ok(())
    }

    #[test]
    fn conn_max_streams_bidi() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(1);
        let mut server_config = TestPair::new_test_config(true)?;

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create bidi streams
        let data = TestPair::new_test_data(5);
        for _ in 0..3 {
            let sid = test_pair.client.stream_bidi_new(0, false)?;
            assert_eq!(
                test_pair.client.stream_write(sid, data.clone(), true)?,
                data.len()
            );
        }
        // Client fail to create more streams
        assert_eq!(
            test_pair.client.stream_bidi_new(0, false),
            Err(Error::StreamLimitError)
        );
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read and shutdown streams
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = [0; 64];
        for i in 0..3 {
            test_pair.server.stream_read(i * 4, &mut buf)?;
            test_pair
                .server
                .stream_shutdown(i * 4, Shutdown::Write, 0)?;
        }
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv RESET_STREAM and send ACK
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send MAX_STREAMS
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client create more streams
        assert_eq!(
            test_pair.client.stream_write(16, data.clone(), true)?,
            data.len()
        );

        Ok(())
    }

    #[test]
    fn conn_max_streams_uni() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create uni streams
        let data = TestPair::new_test_data(5);
        for _ in 0..2 {
            let sid = test_pair.client.stream_uni_new(0, false)?;
            assert_eq!(
                test_pair.client.stream_write(sid, data.clone(), true)?,
                data.len()
            );
        }
        // Client fail to create more streams
        assert_eq!(
            test_pair.client.stream_uni_new(0, false),
            Err(Error::StreamLimitError)
        );
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read streams and send MAX_STREAMS
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = [0; 64];
        for i in 0..2 {
            test_pair.server.stream_read(2 + i * 4, &mut buf)?;
        }
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv MAX_STREAMS
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client create more streams
        assert_eq!(
            test_pair.client.stream_write(10, data.clone(), true)?,
            data.len()
        );

        Ok(())
    }

    #[test]
    fn stream_data_blocked() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send data on the stream
        let (sid, data) = (0, TestPair::new_test_data(40));
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false)?,
            data.len()
        );
        assert_eq!(test_pair.client.stream_capacity(sid)?, 0);

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server recv STREAM and send ACK
        assert_eq!(test_pair.server.stream_readable(sid), true);
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv ACK
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.stream_capacity(sid)?, 0);
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false),
            Err(Error::Done)
        );

        // client send STREAM_DATA_BLOCKED
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        Ok(())
    }

    #[test]
    fn conn_data_blocked() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send data on the streams
        let data = TestPair::new_test_data(30);
        for i in 0..3 {
            assert_eq!(
                test_pair.client.stream_write(i * 4, data.clone(), false)?,
                data.len()
            );
        }

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server recv STREAM and send ACK
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client reck ACK
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        for i in 0..3 {
            assert_eq!(test_pair.client.stream_writable(i * 4, 1)?, false)
        }

        // client send DATA_BLOCKED
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        Ok(())
    }

    #[test]
    fn stream_reset() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(1);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(1);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        assert_eq!(test_pair.handshake(), Ok(()));
        let mut buf = vec![0; 16];

        // Client send data on a stream
        let (sid, data) = (0, TestPair::new_test_data(10));
        test_pair.client.stream_write(sid, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server shutdown the stream (Read/Write)
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Read, 1)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Write, 2)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv STOP_SENDING/RESET_STREAM
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.stream_writable(sid, 1),
            Err(Error::StreamStopped(1))
        );
        assert_eq!(test_pair.client.stream_readable(sid), true);
        assert_eq!(
            test_pair.client.stream_read(sid, &mut buf),
            Err(Error::StreamReset(2))
        );

        // Client send ACK/RESET_STREAM
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv ACK/RESET_STREAM
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.streams.is_closed(sid), true);
        assert_eq!(test_pair.server.stream_readable(sid), false);
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf),
            Err(Error::StreamStateError)
        );

        Ok(())
    }

    #[test]
    fn stream_shutdown_abnormal() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));
        let mut buf = vec![0; 16];

        // Client send data on a stream
        let (sid, data) = (0, TestPair::new_test_data(10));
        test_pair.client.stream_write(sid, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server shutdown the stream (Read/Write)
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Read, 1)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Write, 2)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv STOP_SENDING/RESET_STREAM
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send ACK
        let mut ack_ranges = RangeSet::new(1);
        ack_ranges.insert(0..2);
        let frame = frame::Frame::Ack {
            ack_delay: 0,
            ack_ranges,
            ecn_counts: None,
        };
        test_pair.build_packet_and_send(PacketType::OneRTT, &[frame], false)?;
        assert_eq!(test_pair.server.streams.is_closed(sid), false);

        // Client send RESET_STREAM
        let frame = frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 1,
            final_size: 10,
        };
        test_pair.build_packet_and_send(PacketType::OneRTT, &[frame], false)?;

        // Server stream 0 should be closed now
        assert_eq!(test_pair.server.streams.is_closed(sid), true);
        assert_eq!(test_pair.server.stream_readable(sid), false);
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf),
            Err(Error::StreamStateError)
        );

        Ok(())
    }

    // Establish a multipath connection between the client and server and then
    // send data blocks from the client to the server.
    //
    // The size of data block in `blocks` should be less than 256.
    fn conn_multipath_transfer(test_pair: &mut TestPair, blocks: Vec<Bytes>) -> Result<()> {
        // Handshake with multipath enabled
        test_pair.handshake()?;
        assert!(test_pair.client.is_multipath());
        assert!(test_pair.server.is_multipath());

        // Client and server advertise new cids
        test_pair.advertise_new_cids()?;

        // Client try to add a new path
        assert_eq!(test_pair.client.paths_iter().count(), 1);
        assert_eq!(test_pair.server.paths_iter().count(), 1);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        assert_eq!(test_pair.client.paths_iter().count(), 2);
        assert_eq!(test_pair.server.paths_iter().count(), 2);

        // Client send bytes over multipath
        let mut buf = vec![0; 2048];
        for data in blocks.iter() {
            // Client write and send data on stream 4
            let len = data.len();
            assert_eq!(
                test_pair.client.stream_write(4, data.clone(), false),
                Ok(len)
            );
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

            // Server recv and read data on stream 4
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            assert_eq!(test_pair.server.stream_read(4, &mut buf)?, (len, false));
            assert_eq!(&buf[..len], &data[..]);

            // Server reply ack
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        }

        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        Ok(())
    }

    // Data in flight on a path that went dark is retransmitted on the
    // remaining path as soon as that path is abandoned, without waiting for
    // PTO probes on the dead path.
    #[test]
    fn conn_multipath_abandon_path_retransmits_its_inflight_data() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
        for config in [&mut client_config, &mut server_config] {
            config.set_initial_max_data(1 << 20);
            config.set_initial_max_stream_data_bidi_local(1 << 20);
            config.set_initial_max_stream_data_bidi_remote(1 << 20);
        }
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        test_pair.handshake()?;
        test_pair.advertise_new_cids()?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;

        // More than one initial window, so both paths carry some of it.
        let data = Bytes::from(vec![7u8; 40_000]);
        assert_eq!(test_pair.client.stream_write(4, data.clone(), true), Ok(data.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let (dark, delivered): (Vec<_>, Vec<_>) =
            packets.into_iter().partition(|(_, info)| info.src == client_addr);
        assert!(!dark.is_empty(), "the second path must carry part of the data");
        TestPair::conn_packets_in(&mut test_pair.server, delivered)?;

        test_pair.client.abandon_path(client_addr, server_addr)?;
        test_pair.move_forward()?;

        let mut buf = vec![0; 65536];
        let mut read = 0;
        while let Ok((n, _)) = test_pair.server.stream_read(4, &mut buf) {
            read += n;
            test_pair.move_forward()?;
        }
        assert_eq!(read, data.len());
        Ok(())
    }

    fn multipath_pair_with_two_paths() -> Result<(TestPair, SocketAddr, SocketAddr)> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        for config in [&mut client_config, &mut server_config] {
            config.set_cid_len(crate::MAX_CID_LEN);
            config.enable_multipath(true);
            config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
            config.set_initial_max_data(1 << 20);
            config.set_initial_max_stream_data_bidi_local(1 << 20);
            config.set_initial_max_stream_data_bidi_remote(1 << 20);
        }
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.advertise_new_cids()?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        Ok((test_pair, client_addr, server_addr))
    }

    // A path the receiver holds idle (target rate 0) must still acknowledge
    // what the peer keeps sending on it.
    #[test]
    fn conn_multipath_idle_path_still_acks() -> Result<()> {
        let (mut test_pair, client_addr, server_addr) = multipath_pair_with_two_paths()?;
        // The client sends only on the second path; the server idles it.
        let first_client_addr = test_pair
            .client
            .paths_iter()
            .map(|p| p.local)
            .find(|addr| *addr != client_addr)
            .unwrap();
        test_pair
            .client
            .set_path_target_rate(first_client_addr, server_addr, Some(0))?;
        test_pair
            .server
            .set_path_target_rate(server_addr, client_addr, Some(0))?;

        let data = Bytes::from(vec![7u8; 3000]);
        assert_eq!(test_pair.client.stream_write(4, data.clone(), true), Ok(data.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.iter().any(|(_, info)| info.src == client_addr));
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        let replies = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert!(
            replies.iter().any(|(_, info)| info.dst == client_addr),
            "the idle path must carry the ACKs for its own packet number space"
        );
        TestPair::conn_packets_in(&mut test_pair.client, replies)?;
        test_pair.move_forward()?;

        // A keep-alive PING also goes out on the idle path.
        test_pair.server.ping(Some(FourTuple {
            local: server_addr,
            remote: client_addr,
        }))?;
        let pings = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert!(pings.iter().any(|(_, info)| info.dst == client_addr));
        Ok(())
    }

    // Adding back a 4-tuple that was abandoned brings the path back into use.
    // Abandoning a path tells the peer, which stops sending on it as well.
    #[test]
    fn conn_multipath_abandon_path_is_signalled_to_the_peer() -> Result<()> {
        let (mut test_pair, client_addr, server_addr) = multipath_pair_with_two_paths()?;
        assert!(test_pair.server.get_path(server_addr, client_addr)?.active());

        test_pair.client.abandon_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        let server_path = test_pair.server.get_path(server_addr, client_addr)?;
        assert!(server_path.is_abandoned());
        assert!(!server_path.active());

        // Traffic now flows on the remaining path only, both ways.
        let data = Bytes::from(vec![9u8; 3000]);
        assert_eq!(test_pair.client.stream_write(4, data.clone(), true), Ok(data.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.iter().all(|(_, info)| info.src != client_addr));
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let replies = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert!(!replies.is_empty());
        assert!(replies.iter().all(|(_, info)| info.dst != client_addr));
        Ok(())
    }

    #[test]
    fn conn_multipath_readding_an_abandoned_four_tuple_opens_a_new_path() -> Result<()> {
        let (mut test_pair, client_addr, server_addr) = multipath_pair_with_two_paths()?;
        let mut token = 100;
        let old_client_dcid = test_pair.client.get_path(client_addr, server_addr)?.dcid_seq;
        let old_server_scid = test_pair.server.get_path(server_addr, client_addr)?.scid_seq;
        test_pair.client.abandon_path(client_addr, server_addr)?;
        test_pair.move_forward()?;

        // The abandoned path is dropped on the spot; without a spare CID the
        // new one waits until the peer has replaced the retired one.
        assert_eq!(test_pair.client.add_path(client_addr, server_addr), Err(Error::Done));
        assert!(test_pair.client.get_path(client_addr, server_addr).is_err());
        top_up_scids(&mut test_pair, &mut token)?;
        assert!(test_pair.client.add_path(client_addr, server_addr).is_ok());
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        // The server's new path needs a CID of the client's for its own
        // direction: the one its dropped path used was retired.
        top_up_scids(&mut test_pair, &mut token)?;
        test_pair.move_forward()?;

        // A new path on both ends: new CIDs, validated, and not abandoned.
        let client_path = test_pair.client.get_path(client_addr, server_addr)?;
        assert!(client_path.validated(), "client {:?}", client_path.state());
        assert!(!client_path.is_abandoned());
        assert!(client_path.active(), "client dcid {:?}", client_path.dcid_seq);
        assert_ne!(client_path.dcid_seq, old_client_dcid);
        let server_path = test_pair.server.get_path(server_addr, client_addr)?;
        assert!(server_path.validated(), "server {:?}", server_path.state());
        assert!(!server_path.is_abandoned());
        assert!(server_path.active(), "server dcid {:?}", server_path.dcid_seq);
        assert_ne!(server_path.scid_seq, old_server_scid);
        assert_eq!(test_pair.client.paths_iter().count(), 2);
        assert_eq!(test_pair.server.paths_iter().count(), 2);
        assert!(test_pair.client.cids.get_dcid(old_client_dcid.unwrap()).is_err());

        // Data flows over it.
        test_pair.client.set_path_target_rate(client_addr, server_addr, None)?;
        let data = Bytes::from(vec![5u8; 40_000]);
        assert_eq!(test_pair.client.stream_write(4, data.clone(), true), Ok(data.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.iter().any(|(_, info)| info.src == client_addr));
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.move_forward()?;
        let mut buf = vec![0; 65536];
        let mut read = 0;
        while let Ok((n, _)) = test_pair.server.stream_read(4, &mut buf) {
            read += n;
            test_pair.move_forward()?;
        }
        assert_eq!(read, data.len());
        Ok(())
    }

    // Acts as the endpoint does for a connection: hands out source CIDs up to
    // the peer's limit (at startup, and again for every one the peer retired).
    fn top_up_scids(test_pair: &mut TestPair, next_token: &mut u128) -> Result<()> {
        test_pair.move_forward()?;
        for conn in [&mut test_pair.client, &mut test_pair.server] {
            while conn.poll().is_some() {}
            loop {
                *next_token += 1;
                match conn.add_scid(ConnectionId::random(), *next_token, false) {
                    Ok(_) => (),
                    Err(Error::ConnectionIdLimitError) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        test_pair.move_forward()
    }

    // Both ends run the timers far enough ahead for every abandoned path to
    // have drained.
    fn expire_path_drain(test_pair: &mut TestPair) {
        let later = time::Instant::now() + Duration::from_secs(30);
        for conn in [&mut test_pair.client, &mut test_pair.server] {
            conn.timeout();
            conn.on_timeout(later);
        }
    }

    fn multipath_pair_with_cid_limit(limit: u64) -> Result<(TestPair, u128)> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        for config in [&mut client_config, &mut server_config] {
            config.set_cid_len(crate::MAX_CID_LEN);
            config.enable_multipath(true);
            config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
            config.set_active_connection_id_limit(limit);
            config.set_initial_max_data(1 << 20);
            config.set_initial_max_stream_data_bidi_local(1 << 20);
            config.set_initial_max_stream_data_bidi_remote(1 << 20);
        }
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        let mut token = 100;
        top_up_scids(&mut test_pair, &mut token)?;
        Ok((test_pair, token))
    }

    // Opening and abandoning paths over and over must neither run out of path
    // slots nor of connection IDs: an abandoned path gives both back once it
    // has drained.
    fn abandon_paths_in_a_loop(abandoned_by_client: bool) -> Result<()> {
        const LIMIT: usize = 4;
        let (mut test_pair, mut token) = multipath_pair_with_cid_limit(LIMIT as u64)?;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        for i in 0..24u16 {
            let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9500 + i);
            test_pair.add_and_validate_path(client_addr, server_addr)?;
            test_pair.move_forward()?;
            assert!(test_pair.client.get_path(client_addr, server_addr)?.validated());
            assert!(test_pair.server.get_path(server_addr, client_addr)?.validated());
            assert_eq!(test_pair.client.paths_iter().count(), 2);
            assert_eq!(test_pair.server.paths_iter().count(), 2);

            if abandoned_by_client {
                test_pair.client.abandon_path(client_addr, server_addr)?;
            } else {
                test_pair.server.abandon_path(server_addr, client_addr)?;
            }
            test_pair.move_forward()?;
            expire_path_drain(&mut test_pair);
            top_up_scids(&mut test_pair, &mut token)?;

            for conn in [&test_pair.client, &test_pair.server] {
                assert_eq!(conn.paths_iter().count(), 1, "round {i}");
                assert!(conn.cids.dcid_iter().count() <= LIMIT, "round {i}");
                assert!(conn.cids.scid_iter().count() <= LIMIT, "round {i}");
            }
        }
        Ok(())
    }

    #[test]
    fn conn_multipath_abandoned_paths_release_cids_and_slots() -> Result<()> {
        abandon_paths_in_a_loop(true)
    }

    // The spike's S5 (`spike/noq_mp/RESULTS.md`): beside two lasting paths,
    // a path on a fresh local port is opened, abandoned as soon as it is
    // validated, and drained, over and over; data must keep flowing. The
    // spike's client stopped sending on every path after 11 to 23 rounds.
    #[test]
    fn conn_multipath_data_keeps_flowing_through_path_churn() -> Result<()> {
        let (mut test_pair, mut token) = multipath_pair_with_cid_limit(16)?;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let lasting = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9400);
        test_pair.add_and_validate_path(lasting, server_addr)?;
        test_pair.move_forward()?;

        let mut buf = vec![0; 65536];
        for i in 0..40u16 {
            let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9500 + i);
            test_pair.add_and_validate_path(client_addr, server_addr)?;
            test_pair.client.abandon_path(client_addr, server_addr)?;
            test_pair.move_forward()?;
            expire_path_drain(&mut test_pair);
            top_up_scids(&mut test_pair, &mut token)?;

            let data = Bytes::from(vec![i as u8; 3000]);
            assert_eq!(test_pair.client.stream_write(4, data, false), Ok(3000), "round {i}");
            test_pair.move_forward()?;
            let mut read = 0;
            while let Ok((n, _)) = test_pair.server.stream_read(4, &mut buf) {
                read += n;
            }
            assert_eq!(read, 3000, "round {i}");
            assert_eq!(test_pair.client.paths_iter().count(), 2, "round {i}");
        }
        Ok(())
    }

    #[test]
    fn conn_multipath_peer_abandon_also_releases() -> Result<()> {
        abandon_paths_in_a_loop(false)
    }

    // The RETIRE_CONNECTION_ID for the CID of a discarded path goes out on
    // the remaining path, never on a packet addressed to that CID (RFC 9000
    // Section 19.16), and the peer accepts it.
    #[test]
    fn conn_multipath_retire_frame_never_on_retired_cid() -> Result<()> {
        let (mut test_pair, _) = multipath_pair_with_cid_limit(4)?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        let pid = test_pair
            .client
            .paths
            .get_path_id(&(client_addr, server_addr))
            .unwrap();
        let retired_seq = test_pair.client.paths.get(pid)?.dcid_seq.unwrap();

        test_pair.client.abandon_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        // Only the client's timers run: the server still has the path.
        let later = time::Instant::now() + Duration::from_secs(30);
        test_pair.client.timeout();
        test_pair.client.on_timeout(later);
        assert!(test_pair.client.paths.get_path_id(&(client_addr, server_addr)).is_none());
        assert!(test_pair.client.cids.get_dcid(retired_seq).is_err());
        assert!(test_pair.client.cids.next_dcid_to_retire().is_some());

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());
        assert!(packets.iter().all(|(_, info)| info.src != client_addr));
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert!(!test_pair.server.is_closed() && !test_pair.server.is_closing());
        assert!(test_pair.server.cids.get_scid(retired_seq).is_err());
        assert!(test_pair.client.cids.next_dcid_to_retire().is_none());
        Ok(())
    }

    // A path whose packets all vanish stops being scheduled after repeated
    // PTOs and its in-flight data goes out on the other path, without waiting
    // for the path to be given up; the first ACK on it ends the back-off.
    #[test]
    fn conn_multipath_pto_backed_off_path_is_skipped_then_resumes() -> Result<()> {
        let (mut test_pair, client_addr, server_addr) = multipath_pair_with_two_paths()?;
        let pid = test_pair
            .client
            .paths
            .get_path_id(&(client_addr, server_addr))
            .unwrap();

        // More than one initial window: both paths carry part of it; the
        // second path's packets are dropped.
        let data = Bytes::from(vec![7u8; 40_000]);
        assert_eq!(test_pair.client.stream_write(4, data.clone(), true), Ok(data.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let (dark, delivered): (Vec<_>, Vec<_>) =
            packets.into_iter().partition(|(_, info)| info.src == client_addr);
        assert!(!dark.is_empty(), "the second path must carry part of the data");
        TestPair::conn_packets_in(&mut test_pair.server, delivered)?;

        // PTOs fire on the dark path; everything it sends is dropped as well.
        let mut rounds = 0;
        while !test_pair.client.paths.get(pid)?.backed_off() {
            rounds += 1;
            assert!(rounds < 20, "the path never backed off");
            test_pair.client.timeout();
            let timer = test_pair.client.timers.get(Timer::LossDetection).unwrap();
            test_pair.client.on_timeout(timer);
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            let delivered: Vec<_> = packets
                .into_iter()
                .filter(|(_, info)| info.src != client_addr)
                .collect();
            TestPair::conn_packets_in(&mut test_pair.server, delivered)?;
            let replies = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, replies)?;
        }

        // All the data arrives over the other path alone.
        let mut buf = vec![0; 65536];
        let mut read = 0;
        for _ in 0..200 {
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            let delivered: Vec<_> = packets
                .into_iter()
                .filter(|(_, info)| info.src != client_addr)
                .collect();
            TestPair::conn_packets_in(&mut test_pair.server, delivered)?;
            while let Ok((n, _)) = test_pair.server.stream_read(4, &mut buf) {
                read += n;
            }
            // Delayed ACKs are due.
            test_pair.server.timeout();
            if let Some(timer) = test_pair.server.timers.get(Timer::Ack) {
                test_pair.server.on_timeout(timer);
            }
            let replies = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, replies)?;
            if read == data.len() {
                break;
            }
        }
        assert_eq!(read, data.len());
        assert!(test_pair.client.paths.get(pid)?.backed_off());

        // New data is not scheduled on the backed-off path.
        let more = Bytes::from(vec![8u8; 40_000]);
        assert_eq!(test_pair.client.stream_write(8, more.clone(), true), Ok(more.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());
        assert!(packets.iter().all(|(_, info)| info.src != client_addr));
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // The batch is delivered and acknowledged over the live path, so what
        // is left to time out is the dark path's own loss detection.
        for _ in 0..100 {
            test_pair.server.timeout();
            if let Some(timer) = test_pair.server.timers.get(Timer::Ack) {
                test_pair.server.on_timeout(timer);
            }
            let replies = TestPair::conn_packets_out(&mut test_pair.server)?;
            let more: Vec<_> = TestPair::conn_packets_out(&mut test_pair.client)?
                .into_iter()
                .filter(|(_, info)| info.src != client_addr)
                .collect();
            if replies.is_empty() && more.is_empty() {
                break;
            }
            TestPair::conn_packets_in(&mut test_pair.client, replies)?;
            TestPair::conn_packets_in(&mut test_pair.server, more)?;
        }

        // A probe getting through ends the back-off. Its PTO keeps firing
        // with backoff while the path stays dark, so give it a few rounds.
        let mut probes = Vec::new();
        for _ in 0..10 {
            test_pair.client.timeout();
            let Some(timer) = test_pair.client.timers.get(Timer::LossDetection) else {
                break;
            };
            test_pair.client.on_timeout(timer);
            let (dark, live): (Vec<_>, Vec<_>) =
                TestPair::conn_packets_out(&mut test_pair.client)?
                    .into_iter()
                    .partition(|(_, info)| info.src == client_addr);
            TestPair::conn_packets_in(&mut test_pair.server, live)?;
            if !dark.is_empty() {
                probes = dark;
                break;
            }
        }
        assert!(!probes.is_empty(), "the backed-off path must still get its PTO probes");
        TestPair::conn_packets_in(&mut test_pair.server, probes)?;
        let replies = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, replies)?;
        assert!(!test_pair.client.paths.get(pid)?.backed_off());

        let again = Bytes::from(vec![9u8; 60_000]);
        assert_eq!(test_pair.client.stream_write(0, again.clone(), true), Ok(again.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.iter().any(|(_, info)| info.src == client_addr));
        Ok(())
    }

    // The new path's first packets (new CID) can overtake the PATH_ABANDON
    // for the old path on the same 4-tuple, which travels on another path. A
    // packet on an open path's 4-tuple addressed to a new, unused CID is a new
    // path, not a CID rotation: the old path is dropped and the late
    // PATH_ABANDON changes nothing.
    #[test]
    fn conn_multipath_new_cid_overtaking_path_abandon_opens_a_new_path() -> Result<()> {
        let (mut test_pair, mut token) = multipath_pair_with_cid_limit(4)?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        let old_pid = test_pair
            .server
            .paths
            .get_path_id(&(server_addr, client_addr))
            .unwrap();
        let old_space = test_pair.server.paths.get(old_pid)?.space_id;
        let old_scid = test_pair.server.paths.get(old_pid)?.scid_seq;
        let old_serial = test_pair.server.paths.get(old_pid)?.serial();
        test_pair.server.take_path_events();

        // The PATH_ABANDON is held back on its way to the server.
        test_pair.client.abandon_path(client_addr, server_addr)?;
        let abandon = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!abandon.is_empty());
        assert!(abandon.iter().all(|(_, info)| info.src != client_addr));

        // The new path's PATH_CHALLENGE arrives first.
        test_pair.client.add_path(client_addr, server_addr)?;
        let (challenge, others): (Vec<_>, Vec<_>) =
            TestPair::conn_packets_out(&mut test_pair.client)?
                .into_iter()
                .partition(|(_, info)| info.src == client_addr);
        assert!(!challenge.is_empty());
        TestPair::conn_packets_in(&mut test_pair.server, challenge)?;
        TestPair::conn_packets_in(&mut test_pair.server, abandon)?;
        TestPair::conn_packets_in(&mut test_pair.server, others)?;
        assert!(!test_pair.server.is_closed() && !test_pair.server.is_closing());
        let events = test_pair.server.take_path_events();
        assert!(matches!(
            events[..],
            [
                crate::PathLifecycleEvent::Abandoned { serial, by_peer: true, .. },
                crate::PathLifecycleEvent::Discarded { serial: gone, .. },
                crate::PathLifecycleEvent::Opened { serial: new, .. },
            ] if serial == old_serial && gone == old_serial && new != old_serial
        ), "{events:?}");

        top_up_scids(&mut test_pair, &mut token)?;
        test_pair.move_forward()?;

        let server_path = test_pair.server.get_path(server_addr, client_addr)?;
        assert!(server_path.validated() && !server_path.is_abandoned());
        assert_ne!(server_path.scid_seq, old_scid);
        let new_pid = test_pair
            .server
            .paths
            .get_path_id(&(server_addr, client_addr))
            .unwrap();
        assert_ne!(test_pair.server.paths.get(new_pid)?.space_id, old_space);
        let client_path = test_pair.client.get_path(client_addr, server_addr)?;
        assert!(client_path.validated() && !client_path.is_abandoned());
        assert_eq!(test_pair.server.paths_iter().count(), 2);

        // Data flows over it.
        let data = Bytes::from(vec![3u8; 40_000]);
        assert_eq!(test_pair.client.stream_write(4, data.clone(), true), Ok(data.len()));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.iter().any(|(_, info)| info.src == client_addr));
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.move_forward()?;
        let mut buf = vec![0; 65536];
        let mut read = 0;
        while let Ok((n, _)) = test_pair.server.stream_read(4, &mut buf) {
            read += n;
            test_pair.move_forward()?;
        }
        assert_eq!(read, data.len());
        Ok(())
    }

    // A straggler of a dropped path, addressed to its CID, arrives after a new
    // path was opened on the same 4-tuple: it is neither a new path nor a CID
    // rotation, and must leave the new path alone.
    #[test]
    fn conn_multipath_straggler_of_a_discarded_path_leaves_the_new_path_alone() -> Result<()> {
        let (mut test_pair, mut token) = multipath_pair_with_cid_limit(4)?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;

        // A packet of the old path, held back.
        let data = Bytes::from(vec![1u8; 3000]);
        assert_eq!(test_pair.client.stream_write(4, data, false), Ok(3000));
        let straggler: Vec<_> = TestPair::conn_packets_out(&mut test_pair.client)?
            .into_iter()
            .filter(|(_, info)| info.src == client_addr)
            .collect();
        assert!(!straggler.is_empty());

        test_pair.client.abandon_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        // Both ends drop the old path; the RETIRE_CONNECTION_IDs are not out yet.
        expire_path_drain(&mut test_pair);
        assert_eq!(test_pair.server.paths_iter().count(), 1);

        // A straggler alone does not make a path.
        TestPair::conn_packets_in(&mut test_pair.server, straggler.clone())?;
        assert_eq!(test_pair.server.paths_iter().count(), 1);

        // The new path on the same 4-tuple (only its own packets for now).
        test_pair.client.add_path(client_addr, server_addr)?;
        let (challenge, others): (Vec<_>, Vec<_>) =
            TestPair::conn_packets_out(&mut test_pair.client)?
                .into_iter()
                .partition(|(_, info)| info.src == client_addr);
        assert!(!challenge.is_empty());
        TestPair::conn_packets_in(&mut test_pair.server, challenge)?;
        let serial = test_pair
            .server
            .get_path(server_addr, client_addr)?
            .serial();

        TestPair::conn_packets_in(&mut test_pair.server, straggler)?;
        let path = test_pair.server.get_path(server_addr, client_addr)?;
        assert!(!path.is_abandoned());
        assert_eq!(path.serial(), serial);
        assert_eq!(test_pair.server.paths_iter().count(), 2);

        TestPair::conn_packets_in(&mut test_pair.server, others)?;
        top_up_scids(&mut test_pair, &mut token)?;
        test_pair.move_forward()?;
        let path = test_pair.server.get_path(server_addr, client_addr)?;
        assert!(path.validated() && path.serial() == serial);
        assert!(test_pair.client.get_path(client_addr, server_addr)?.validated());
        Ok(())
    }

    // The host learns what became of its paths from events, in order, each
    // path told apart by its serial; a 4-tuple opened again gets a new one.
    #[test]
    fn conn_multipath_path_events_follow_the_lifecycle() -> Result<()> {
        use crate::PathLifecycleEvent::*;
        let (mut test_pair, mut token) = multipath_pair_with_cid_limit(4)?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.client.take_path_events();
        test_pair.server.take_path_events();

        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        let client_events = test_pair.client.take_path_events();
        let server_events = test_pair.server.take_path_events();
        let [Opened { serial: first_client, .. }] = client_events[..] else {
            panic!("{client_events:?}");
        };
        let [Opened { serial: first_server, .. }] = server_events[..] else {
            panic!("{server_events:?}");
        };

        test_pair.client.abandon_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        expire_path_drain(&mut test_pair);
        let client_events = test_pair.client.take_path_events();
        let server_events = test_pair.server.take_path_events();
        assert!(matches!(
            client_events[..],
            [Abandoned { serial, by_peer: false, .. }, Discarded { serial: gone, .. }]
                if serial == first_client && gone == first_client
        ), "{client_events:?}");
        assert!(matches!(
            server_events[..],
            [Abandoned { serial, by_peer: true, .. }, Discarded { serial: gone, .. }]
                if serial == first_server && gone == first_server
        ), "{server_events:?}");

        // The same 4-tuple again is a new path.
        top_up_scids(&mut test_pair, &mut token)?;
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        test_pair.move_forward()?;
        let [Opened { serial, .. }] = test_pair.client.take_path_events()[..] else {
            panic!("client reopen");
        };
        assert_ne!(serial, first_client);
        let [Opened { serial, .. }] = test_pair.server.take_path_events()[..] else {
            panic!("server reopen");
        };
        assert_ne!(serial, first_server);
        Ok(())
    }

    #[test]
    fn conn_multipath_transfer_minrtt() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        let mut blocks = vec![];
        for i in 0..1000 {
            blocks.push(Bytes::from_static(b"Everything over multipath"));
        }
        conn_multipath_transfer(&mut test_pair, blocks)?;
        // Note: The scheduling result is uncertain, so we only verify if the
        // transmission was successful.
        Ok(())
    }

    #[test]
    fn conn_multipath_transfer_redundant() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::Redundant);
        client_config.set_ack_eliciting_threshold(1);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);

        // Handshake with multipath enabled
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::Redundant);
        server_config.set_ack_eliciting_threshold(1);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        let blocks = vec![
            Bytes::from_static(b"Everything"),
            Bytes::from_static(b"Over"),
            Bytes::from_static(b"Multipath QUIC"),
        ];

        conn_multipath_transfer(&mut test_pair, blocks)?;

        for (i, path) in test_pair.server.paths.iter_mut() {
            let s = path.stats();
            assert!(s.sent_count > 3);
            assert!(s.recv_count > 3);
        }
        Ok(())
    }

    #[test]
    fn conn_multipath_transfer_roundrobin() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::RoundRobin);
        client_config.set_ack_eliciting_threshold(1);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::RoundRobin);
        server_config.set_ack_eliciting_threshold(1);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        let mut blocks = vec![];
        for i in 0..100 {
            blocks.push(Bytes::from_static(b"Everything over multipath"));
        }
        conn_multipath_transfer(&mut test_pair, blocks)?;

        for (i, path) in test_pair.server.paths.iter_mut() {
            let s = path.stats();
            assert!(s.sent_count > 50);
            assert!(s.recv_count > 50);
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "qlog")]
    fn conn_write_qlog() -> Result<()> {
        let clog = NamedTempFile::new().unwrap();
        let mut cfile = clog.reopen().unwrap();
        let slog = NamedTempFile::new().unwrap();
        let mut sfile = slog.reopen().unwrap();

        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair
            .client
            .set_qlog(Box::new(clog), "title".into(), "desc".into());
        test_pair
            .server
            .set_qlog(Box::new(slog), "title".into(), "desc".into());
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create a stream and send data
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Client lost some packets
        test_pair.client.stream_write(0, data.clone(), false)?;
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server read data from the stream
        let mut buf = vec![0; data.len()];
        test_pair.server.stream_read(0, &mut buf)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // The dropped packets may be declared as lost based on the time threshold.
        // If not, advance ticks until loss timeout.
        if test_pair.client.timeout().is_some() {
            let timeout = test_pair.client.timers.get(Timer::LossDetection);
            test_pair.client.on_timeout(timeout.unwrap());
        }

        // Check client qlog
        let mut clog_content = String::new();
        cfile.read_to_string(&mut clog_content).unwrap();
        assert_eq!(clog_content.contains("client"), true);
        assert_eq!(clog_content.contains("quic:parameters_set"), true);
        assert_eq!(clog_content.contains("quic:stream_data_moved"), true);
        assert_eq!(clog_content.contains("quic:packet_sent"), true);
        assert_eq!(clog_content.contains("recovery:metrics_updated"), true);
        assert_eq!(clog_content.contains("recovery:packet_lost"), true);

        // Check server qlog
        let mut slog_content = String::new();
        sfile.read_to_string(&mut slog_content).unwrap();
        assert_eq!(slog_content.contains("server"), true);
        assert_eq!(slog_content.contains("quic:parameters_set"), true);
        assert_eq!(slog_content.contains("quic:stream_data_moved"), true);
        assert_eq!(slog_content.contains("quic:packet_received"), true);
        assert_eq!(slog_content.contains("recovery:metrics_updated"), true);

        Ok(())
    }

    fn test_pair_for_key_update() -> Result<TestPair> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.set_initial_max_data(10000);
        client_config.set_initial_max_stream_data_bidi_local(10000);
        client_config.set_initial_max_stream_data_bidi_remote(10000);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.set_initial_max_data(10000);
        server_config.set_initial_max_stream_data_bidi_local(10000);
        server_config.set_initial_max_stream_data_bidi_remote(10000);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Transfer some data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf)?, (19, false));
        assert_eq!(&buf[..19], &data[..]);

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(!test_pair.client.tls_session.current_key_phase());
        assert!(!test_pair.server.tls_session.current_key_phase());

        Ok(test_pair)
    }

    #[test]
    fn key_update() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(space, false)?;

        // Transfer some data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf)?, (19, false));
        assert_eq!(&buf[..19], &data[..]);

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.tls_session.current_key_phase());
        assert!(test_pair.server.tls_session.current_key_phase());

        Ok(())
    }

    #[test]
    fn key_update_with_packet_reorder() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client send data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let prev_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(space, false)?;

        // Client send with new key.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), true)?;
        let new_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server receive reordered packets.
        TestPair::conn_packets_in(&mut test_pair.server, new_key_packets)?;
        TestPair::conn_packets_in(&mut test_pair.server, prev_key_packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf)?, (38, true));

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.tls_session.current_key_phase());
        assert!(test_pair.server.tls_session.current_key_phase());

        Ok(())
    }

    #[test]
    fn key_update_with_previous_key_discard() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client send data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let prev_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(space, false)?;
        // Client send with new key.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), true)?;
        let new_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server discard previous key and receive reordered packets.
        TestPair::conn_packets_in(&mut test_pair.server, new_key_packets)?;

        let timeout = test_pair.server.timers.get(Timer::KeyDiscard);
        test_pair.server.on_timeout(timeout.unwrap());

        TestPair::conn_packets_in(&mut test_pair.server, prev_key_packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf), Err(Error::Done));

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.tls_session.current_key_phase());
        assert!(test_pair.server.tls_session.current_key_phase());

        Ok(())
    }

    #[test]
    fn key_update_with_consecutive_update() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(space, false)?;

        // Client init another key update.
        assert_eq!(
            test_pair
                .client
                .tls_session
                .initiate_key_update(space, false),
            Err(Error::Done)
        );

        Ok(())
    }

    #[test]
    fn packet_send_meta_keeps_handshake_liveness_outside_data_budget() {
        let crypto = frame::Frame::Crypto {
            offset: 0,
            length: 3,
            data: Bytes::from_static(b"tls"),
        };
        let crypto_meta = Connection::packet_send_meta(&[crypto], PacketType::Initial, false, true);
        assert!(crypto_meta.contains_handshake);
        assert!(crypto_meta.contains_retransmission);
        assert!(!crypto_meta.contains_data);
        assert!(crypto_meta.is_control_only());

        let mut ack_ranges = RangeSet::new(1);
        ack_ranges.insert(1..2);
        let mixed_meta = Connection::packet_send_meta(
            &[
                frame::Frame::Ack {
                    ack_delay: 0,
                    ack_ranges,
                    ecn_counts: None,
                },
                frame::Frame::PathChallenge { data: [7; 8] },
                frame::Frame::Stream {
                    stream_id: 0,
                    offset: 0,
                    length: 7,
                    fin: false,
                    data: Bytes::from_static(b"payload"),
                },
            ],
            PacketType::OneRTT,
            false,
            false,
        );
        assert!(mixed_meta.contains_data);
        assert!(mixed_meta.contains_ack);
        assert!(mixed_meta.contains_path_validation);
        assert!(
            !mixed_meta.is_control_only(),
            "mixed ACK+STREAM consumes data credit"
        );

        let control_meta = Connection::packet_send_meta(
            &[
                frame::Frame::Ping {
                    pmtu_probe: Some((0, 1200)),
                },
                frame::Frame::ApplicationClose {
                    error_code: 0,
                    reason: Vec::new(),
                },
                frame::Frame::HandshakeDone,
            ],
            PacketType::OneRTT,
            true,
            false,
        );
        assert!(control_meta.contains_probe);
        assert!(control_meta.contains_close);
        assert!(control_meta.contains_handshake);
        assert!(control_meta.is_control_only());
    }

    #[test]
    fn data_gate_closed_keeps_ack_flowing_but_suppresses_stream_data() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Give the client data to send, and deliver it to the server so the
        // server now owes the client an ACK. Then give the server its own
        // data to send back: with the gate open this would naturally
        // coalesce ACK + STREAM into a single Data-classified packet -- the
        // exact scenario that traps a piggybacked ACK behind paused data.
        let (sid, data) = (0, TestPair::new_test_data(10));
        test_pair.client.stream_write(sid, data.clone(), true)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.server.stream_write(sid, data, false)?;

        // With the data gate closed, the server's next packet must still
        // carry the pending ACK, but must not carry the pending STREAM data.
        let gate = GateSender::closed();
        let mut buf = vec![0u8; 1500];
        let (written, info) = test_pair.server.send(&mut buf, &gate)?;
        buf.truncate(written);
        assert!(
            info.send_meta.contains_ack,
            "ACK must not be trapped behind a closed data gate"
        );
        assert!(
            !info.send_meta.contains_data,
            "STREAM frames must not be written while the data gate is closed"
        );

        Ok(())
    }

    #[test]
    fn data_gate_reopen_lets_stream_frames_through() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Stream 1 is server-initiated bidi, so the server can open it
        // unilaterally without any prior client activity on it.
        let (sid, data) = (1, TestPair::new_test_data(10));
        test_pair.server.stream_write(sid, data, false)?;

        // Closed, with nothing else pending: no STREAM frame is written and
        // the packet is empty, exactly like the pre-gate "no frames" path.
        let closed = GateSender::closed();
        let mut buf = vec![0u8; 1500];
        match test_pair.server.send(&mut buf, &closed) {
            Err(Error::Done) => {}
            other => panic!(
                "nothing else is pending, so a closed gate must yield no packet, got {:?}",
                other.map(|(written, _)| written)
            ),
        }

        // Reopened: the same pending STREAM data is now written -- the gate
        // is a live, per-call query, not a one-shot latch.
        let open = GateSender::open();
        let (written, info) = test_pair.server.send(&mut buf, &open)?;
        buf.truncate(written);
        assert!(
            info.send_meta.contains_data,
            "data must flow again once the gate reopens"
        );

        Ok(())
    }

    // ---- RFC 9221 DATAGRAM and draft-ietf-quic-address-discovery ----

    fn dgram_test_pair(client_max: u64, server_max: u64) -> Result<TestPair> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_max_datagram_frame_size(client_max);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_max_datagram_frame_size(server_max);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.move_forward()?;
        Ok(test_pair)
    }

    #[test]
    fn dgram_disabled_by_default_and_unsupported_by_peer() -> Result<()> {
        let mut test_pair = dgram_test_pair(0, 1500)?;
        assert_eq!(
            test_pair
                .client
                .dgram_send(Bytes::from_static(b"x"), false),
            Err(SendDatagramError::Disabled)
        );
        assert_eq!(
            test_pair
                .server
                .dgram_send(Bytes::from_static(b"x"), false),
            Err(SendDatagramError::UnsupportedByPeer)
        );
        assert_eq!(test_pair.server.dgram_max_writable_len(), None);
        Ok(())
    }

    #[test]
    fn dgram_default_config_keeps_the_transport_parameter_absent() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.peer_transport_params.max_datagram_frame_size, None);
        assert_eq!(test_pair.server.peer_transport_params.max_datagram_frame_size, None);
        assert_eq!(test_pair.client.peer_transport_params.address_discovery, None);
        Ok(())
    }

    #[test]
    fn dgram_round_trip() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;

        let data = Bytes::from_static(b"unreliable hello");
        test_pair.client.dgram_send(data.clone(), false).unwrap();
        assert_eq!(test_pair.client.dgram_send_queue_len(), 1);
        assert_eq!(test_pair.client.dgram_send_queue_bytes(), data.len());

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.iter().any(|(_, info)| info.send_meta.contains_data));
        assert_eq!(test_pair.client.dgram_send_queue_len(), 0);
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        assert!(test_pair.server.take_datagram_readable());
        assert!(!test_pair.server.take_datagram_readable());
        assert_eq!(test_pair.server.dgram_recv_queue_len(), 1);
        assert_eq!(test_pair.server.dgram_recv(), Some(data));
        assert_eq!(test_pair.server.dgram_recv(), None);

        test_pair.move_forward()?;
        let stats = test_pair.client.dgram_stats();
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.acked, 1);
        assert_eq!(stats.lost, 0);
        assert_eq!(test_pair.server.dgram_stats().received, 1);
        Ok(())
    }

    #[test]
    fn dgram_receive_preserves_packet_timestamp_across_delayed_reads() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;
        for timestamp in [Some(123), Some(456), None] {
            test_pair.client.dgram_send(Bytes::from_static(b"probe"), false).unwrap();
            let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            for (_, info) in &mut packets {
                info.recv_timestamp = timestamp;
            }
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        }
        // All three are already received. Reading them later must not replace
        // timestamps, mix them between packets, or invent one for old callers.
        for expected in [Some(123), Some(456), None] {
            let (data, timestamp) = test_pair.server.dgram_recv_with_timestamp().unwrap();
            assert_eq!(data, Bytes::from_static(b"probe"));
            assert_eq!(timestamp, expected);
        }
        assert_eq!(test_pair.server.dgram_recv_queue_len(), 0);
        assert_eq!(test_pair.server.dgram_recv_with_timestamp(), None);
        Ok(())
    }

    #[test]
    fn dgram_lost_is_counted_and_never_retransmitted() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;

        test_pair
            .client
            .dgram_send(Bytes::from_static(b"lost"), false)
            .unwrap();
        let dropped = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!dropped.is_empty());

        for id in 10..14u64 {
            let data = Bytes::from(format!("dgram {id}"));
            test_pair.client.dgram_send(data, false).unwrap();
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        }
        test_pair.move_forward()?;

        let stats = test_pair.client.dgram_stats();
        assert_eq!(stats.lost, 1);
        assert_eq!(stats.acked, 4);

        let mut received = vec![];
        while let Some(d) = test_pair.server.dgram_recv() {
            received.push(d);
        }
        assert_eq!(received.len(), 4);
        assert!(received.iter().all(|d| d.as_ref() != b"lost"));
        Ok(())
    }

    #[test]
    fn dgram_size_limits() -> Result<()> {
        // The server accepts DATAGRAM frames of at most 100 bytes.
        let mut test_pair = dgram_test_pair(65535, 100)?;
        let max = test_pair.client.dgram_max_writable_len().unwrap();
        assert_eq!(max, 100 - frame::MAX_DATAGRAM_OVERHEAD);
        assert_eq!(
            test_pair
                .client
                .dgram_send(TestPair::new_test_data(max + 1), false),
            Err(SendDatagramError::TooLarge)
        );
        assert!(test_pair
            .client
            .dgram_send(TestPair::new_test_data(max), false)
            .is_ok());

        // Limited by the path MTU when the peer allows large frames.
        let max = test_pair.server.dgram_max_writable_len().unwrap();
        let mtu = test_pair
            .server
            .max_datagram_size(test_pair.server.paths.get_active_path_id()?);
        assert!(max < mtu);
        assert!(max + 60 > mtu);
        Ok(())
    }

    #[test]
    fn dgram_receiver_rejects_frames_it_did_not_ask_for() -> Result<()> {
        let mut test_pair = dgram_test_pair(0, 1500)?;
        let frame = frame::Frame::Datagram {
            data: Bytes::from_static(b"unexpected"),
        };
        assert!(test_pair
            .build_packet_and_send(PacketType::OneRTT, &[frame], true)
            .is_err());
        Ok(())
    }

    #[test]
    fn dgram_receiver_rejects_frames_above_its_limit() -> Result<()> {
        let mut test_pair = dgram_test_pair(20, 1500)?;
        let frame = frame::Frame::Datagram {
            data: TestPair::new_test_data(40),
        };
        assert!(test_pair
            .build_packet_and_send(PacketType::OneRTT, &[frame], true)
            .is_err());
        Ok(())
    }

    #[test]
    fn dgram_shares_the_congestion_window_and_optionally_bypasses_it() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;

        // Fill the congestion window.
        {
            let r = &mut test_pair.client.paths.get_active_mut()?.recovery;
            r.bytes_in_flight = r.congestion.congestion_window() as usize;
        }
        test_pair
            .client
            .dgram_send(Bytes::from_static(b"held"), false)
            .unwrap();
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.dgram_send_queue_len(), 1);

        // RFC 9484 Section 10.2: datagrams may bypass the window when asked.
        test_pair.client.dgram_set_bypass_cwnd(true);
        assert!(test_pair.client.dgram_stats().bypass_active);
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.dgram_send_queue_len(), 0);
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.dgram_recv(), Some(Bytes::from_static(b"held")));
        Ok(())
    }

    #[test]
    fn dgram_respects_the_data_gate() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;
        test_pair
            .client
            .dgram_send(Bytes::from_static(b"gated"), false)
            .unwrap();

        let mut buf = vec![0; 1500];
        let _ = test_pair.client.send(&mut buf, &GateSender::closed());
        assert_eq!(test_pair.client.dgram_send_queue_len(), 1);

        let (written, info) = test_pair.client.send(&mut buf, &GateSender::open())?;
        assert!(written > 0);
        assert!(info.send_meta.contains_data);
        assert_eq!(test_pair.client.dgram_send_queue_len(), 0);
        Ok(())
    }

    /// B1 of CAKE_SQM_PLAN.md: the packets of a send queue below QUIC can be
    /// told apart by flow, so a packet carries the datagrams of one flow only
    /// and reports it.
    #[test]
    fn dgram_packets_hold_one_flow_and_report_it() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;
        for (flow, byte) in [(1u32, 1u8), (1, 2), (2, 3), (2, 4), (1, 5)] {
            test_pair
                .client
                .dgram_send_with_flow(Bytes::from(vec![byte; 100]), false, flow)
                .unwrap();
        }
        test_pair
            .client
            .dgram_send(Bytes::from(vec![6u8; 100]), false)
            .unwrap();
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let flows: Vec<_> = packets
            .iter()
            .filter(|(_, info)| info.send_meta.contains_data)
            .map(|(_, info)| info.send_meta.flow_hash)
            .collect();
        assert_eq!(
            flows,
            vec![Some(1), Some(2), Some(1), None],
            "queued order 1,1,2,2,1,none gives one packet per run of equal flow"
        );
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let got: Vec<u8> = std::iter::from_fn(|| test_pair.server.dgram_recv())
            .map(|d| d[0])
            .collect();
        assert_eq!(got, vec![1, 2, 3, 4, 5, 6], "order is kept");
        Ok(())
    }

    #[test]
    fn a_packet_with_stream_data_has_no_flow() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;
        let sid = 0;
        test_pair.client.stream_write(sid, Bytes::from(vec![9u8; 200]), false)?;
        test_pair.client.dgram_send(Bytes::from(vec![1u8; 100]), false).unwrap();
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets
            .iter()
            .any(|(_, info)| info.send_meta.contains_data && info.send_meta.flow_hash.is_none()));
        assert!(packets.iter().all(|(_, info)| info.send_meta.flow_hash.is_none()));
        Ok(())
    }

    #[test]
    fn dgram_send_queue_drop_oldest_and_blocked() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_max_datagram_frame_size(65535);
        client_config.set_datagram_buffer_sizes(1000, 100);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_max_datagram_frame_size(65535);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.move_forward()?;

        let conn = &mut test_pair.client;
        conn.dgram_send(TestPair::new_test_data(60), false).unwrap();
        assert!(matches!(
            conn.dgram_send(TestPair::new_test_data(60), false),
            Err(SendDatagramError::Blocked(_))
        ));
        conn.dgram_send(TestPair::new_test_data(60), true).unwrap();
        assert_eq!(conn.dgram_send_queue_len(), 1);
        assert_eq!(conn.dgram_stats().dropped_outgoing, 1);
        Ok(())
    }

    #[test]
    fn dgram_max_writable_len_grows_with_dplpmtud() -> Result<()> {
        let mut test_pair = dgram_test_pair(65535, 65535)?;
        for _ in 0..20 {
            test_pair
                .client
                .dgram_send(Bytes::from_static(b"probe traffic"), true)
                .unwrap();
            test_pair.move_forward()?;
        }
        let max = test_pair.client.dgram_max_writable_len().unwrap();
        assert!(max >= 1400, "max datagram payload {max}");
        Ok(())
    }

    /// A client and server with datagrams on and two validated paths, the
    /// client's from 127.0.0.1:9443 (`first`) and 127.0.0.1:9444 (`second`).
    fn dgram_multipath_pair(bypass: bool) -> Result<(TestPair, SocketAddr, SocketAddr, SocketAddr)> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::SqmWeighted);
        client_config.set_max_datagram_frame_size(65535);
        client_config.enable_datagram_bypass_cwnd(bypass);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::SqmWeighted);
        server_config.set_max_datagram_frame_size(65535);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.advertise_new_cids()?;
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(second, server)?;
        test_pair.move_forward()?;
        Ok((test_pair, first, second, server))
    }

    /// Give the client's path from `local` a steady delay of `rtt_ms`, as
    /// measured over many round trips (rttvar near zero).
    fn set_path_rtt(conn: &mut Connection, local: SocketAddr, rtt_ms: u64) -> Result<()> {
        let rtt = time::Duration::from_millis(rtt_ms);
        let pid = conn
            .paths
            .iter()
            .find(|(_, p)| p.local_addr() == local)
            .map(|(pid, _)| pid)
            .ok_or(Error::InternalError)?;
        let path = conn.paths.get_mut(pid)?;
        path.recovery.rtt = rtt::RttEstimator::new(rtt);
        for _ in 0..30 {
            path.recovery.rtt.update(time::Duration::ZERO, rtt);
        }
        Ok(())
    }

    fn path_of(conn: &mut Connection, local: SocketAddr) -> Result<&mut path::Path> {
        let pid = conn
            .paths
            .iter()
            .find(|(_, p)| p.local_addr() == local)
            .map(|(pid, _)| pid)
            .ok_or(Error::InternalError)?;
        conn.paths.get_mut(pid)
    }

    /// I2 (MP_FIX_PHASES.md S-I2): a standby path chosen to send a PING or an
    /// ACK while the regular path's window is full carried STREAM and
    /// DATAGRAM frames too. draft-ietf-quic-multipath Section 3.3: no data on
    /// a backup path while another path is available.
    #[test]
    fn a_standby_path_carries_no_data_while_another_path_is_available() -> Result<()> {
        for bypass in [false, true] {
            let (mut test_pair, first, second, server) = dgram_multipath_pair(bypass)?;
            test_pair.client.set_path_standby(second, server, true)?;
            {
                let r = &mut path_of(&mut test_pair.client, first)?.recovery;
                r.bytes_in_flight = r.congestion.congestion_window() as usize;
            }
            path_of(&mut test_pair.client, second)?.need_send_ping = true;
            test_pair.client.stream_write(0, Bytes::from(vec![9u8; 30]), false)?;
            for _ in 0..5 {
                test_pair
                    .client
                    .dgram_send_with_flow(TestPair::new_test_data(200), false, 7)
                    .unwrap();
            }

            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            assert!(
                packets.iter().any(|(_, info)| info.src == second),
                "bypass={bypass}: the standby path still sends its PING"
            );
            assert!(
                packets
                    .iter()
                    .all(|(_, info)| info.src != second || !info.send_meta.contains_data),
                "bypass={bypass}: data on the standby path: {:?}",
                packets
                    .iter()
                    .map(|(_, info)| (info.src, info.send_meta.contains_data))
                    .collect::<Vec<_>>()
            );
            // Once no regular path is left, the standby path takes the data.
            path_of(&mut test_pair.client, first)?.set_active(false);
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            assert!(packets
                .iter()
                .any(|(_, info)| info.src == second && info.send_meta.contains_data));
        }
        Ok(())
    }

    /// I6 (S-I5/I6): the datagrams of one flow were spread packet by packet
    /// over a 20 ms and a 200 ms path, and the inner transport saw them out
    /// of order. Now a flow keeps its path; a new flow goes where ECF places
    /// it: a single datagram waits behind the full fast path, a backlog takes
    /// the slower one.
    #[test]
    fn datagrams_of_a_flow_keep_one_path_and_a_new_flow_takes_the_free_one() -> Result<()> {
        let (mut test_pair, first, second, server) = dgram_multipath_pair(true)?;
        set_path_rtt(&mut test_pair.client, first, 20)?;
        set_path_rtt(&mut test_pair.client, second, 200)?;
        // 80 kB/s each: 1 600 bytes per round trip on the 20 ms path.
        for local in [first, second] {
            test_pair.client.set_path_target_rate(local, server, Some(80_000))?;
        }

        let mut sent = Vec::new();
        let mut send = |test_pair: &mut TestPair, batch: &[(u32, usize)]| -> Result<()> {
            for &(flow, count) in batch {
                for _ in 0..count {
                    test_pair
                        .client
                        .dgram_send_with_flow(TestPair::new_test_data(1_000), false, flow)
                        .unwrap();
                }
            }
            for (_, info) in TestPair::conn_packets_out(&mut test_pair.client)? {
                if info.send_meta.contains_data {
                    sent.push((info.send_meta.flow_hash, info.src));
                }
            }
            Ok(())
        };
        send(&mut test_pair, &[(1, 1)])?;
        path_of(&mut test_pair.client, first)?.recovery.bytes_in_flight = 2_000;
        send(&mut test_pair, &[(3, 1)])?;
        send(&mut test_pair, &[(2, 40), (1, 5)])?;
        let paths_of = |flow: u32| {
            sent.iter()
                .filter(|(f, _)| *f == Some(flow))
                .map(|(_, src)| *src)
                .collect::<std::collections::HashSet<_>>()
        };
        assert_eq!(paths_of(1), [first].into(), "flow 1 kept the fast path: {sent:?}");
        assert_eq!(paths_of(3), [first].into(), "flow 3 waits for the fast path: {sent:?}");
        assert_eq!(paths_of(2), [second].into(), "flow 2's backlog took the free path: {sent:?}");
        Ok(())
    }

    /// A flow moves only after a pause longer than the paths' delay
    /// difference (flowlet switching): its next packet then cannot overtake
    /// the last one.
    #[test]
    fn a_flow_moves_to_a_free_path_only_after_a_flowlet_gap() -> Result<()> {
        let (mut test_pair, first, second, server) = dgram_multipath_pair(true)?;
        set_path_rtt(&mut test_pair.client, first, 5)?;
        set_path_rtt(&mut test_pair.client, second, 45)?;
        for local in [first, second] {
            test_pair.client.set_path_target_rate(local, server, Some(80_000))?;
        }
        let send = |test_pair: &mut TestPair,
                    count: usize|
         -> Result<std::collections::HashSet<SocketAddr>> {
            for _ in 0..count {
                test_pair
                    .client
                    .dgram_send_with_flow(TestPair::new_test_data(1_000), false, 1)
                    .unwrap();
            }
            Ok(TestPair::conn_packets_out(&mut test_pair.client)?
                .into_iter()
                .filter(|(_, info)| info.send_meta.contains_data)
                .map(|(_, info)| info.src)
                .collect())
        };
        assert_eq!(send(&mut test_pair, 1)?, [first].into());
        // The fast path is over its rate now (80 kB/s over 5 ms is less than
        // one packet per round trip), and ECF would send a 40 kB backlog on
        // the slower path; within the flowlet the flow stays.
        path_of(&mut test_pair.client, first)?.recovery.bytes_in_flight = 2_000;
        assert_eq!(send(&mut test_pair, 40)?, [first].into());
        // A pause longer than 40 ms ends the flowlet.
        std::thread::sleep(time::Duration::from_millis(60));
        assert_eq!(send(&mut test_pair, 40)?, [second].into());
        Ok(())
    }

    /// S-I1/S-I12: under the bypass, datagrams leave whatever the data gate
    /// says (the sender's queue below QUIC is where they wait), while stream
    /// data still waits for the gate.
    #[test]
    fn bypassed_datagrams_do_not_wait_for_the_data_gate() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_max_datagram_frame_size(65535);
        client_config.enable_datagram_bypass_cwnd(true);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_max_datagram_frame_size(65535);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.move_forward()?;

        test_pair.client.stream_write(0, Bytes::from(vec![9u8; 30]), false)?;
        test_pair
            .client
            .dgram_send(Bytes::from_static(b"not gated"), false)
            .unwrap();
        let mut buf = vec![0; 1500];
        while test_pair.client.send(&mut buf, &GateSender::closed()).is_ok() {}
        assert_eq!(test_pair.client.dgram_send_queue_len(), 0);
        assert_eq!(test_pair.client.stream_unsent_bytes(0), Some(30));
        Ok(())
    }

    fn address_discovery_pair(client: bool, server: bool) -> Result<TestPair> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_address_discovery(client);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.enable_address_discovery(server);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.move_forward()?;
        Ok(test_pair)
    }

    fn active_observed(conn: &mut Connection) -> Option<SocketAddr> {
        conn.paths.get_active().ok()?.observed_local_addr()
    }

    #[test]
    fn observed_address_reported_on_the_validated_path() -> Result<()> {
        let mut test_pair = address_discovery_pair(true, true)?;
        assert_eq!(
            active_observed(&mut test_pair.client),
            Some("127.0.0.1:9443".parse().unwrap())
        );
        assert_eq!(
            active_observed(&mut test_pair.server),
            Some("127.0.0.1:443".parse().unwrap())
        );
        let pid = test_pair.client.paths.get_active_path_id()?;
        assert_eq!(
            test_pair.client.paths.get_mut(pid)?.stats().observed_local_addr,
            Some("127.0.0.1:9443".parse().unwrap())
        );
        // Reported once: no OBSERVED_ADDRESS is pending afterwards.
        assert!(!test_pair.server.paths.get_active()?.need_report_observed_addr());
        Ok(())
    }

    #[test]
    fn observed_address_only_after_negotiation() -> Result<()> {
        // The server does not provide reports; the client does not ask.
        for (client, server) in [(true, false), (false, true), (false, false)] {
            let mut test_pair = address_discovery_pair(client, server)?;
            if !(client && server) {
                assert_eq!(active_observed(&mut test_pair.client), None);
            }
            if !(client && server) {
                assert_eq!(active_observed(&mut test_pair.server), None);
            }
        }
        Ok(())
    }

    #[test]
    fn observed_address_stale_sequence_is_ignored() -> Result<()> {
        let mut test_pair = address_discovery_pair(true, true)?;
        let newer: SocketAddr = "203.0.113.7:4000".parse().unwrap();
        let older: SocketAddr = "203.0.113.8:5000".parse().unwrap();
        let frame = frame::Frame::ObservedAddress {
            seq_num: 100,
            addr: newer,
        };
        test_pair.build_packet_and_send(PacketType::OneRTT, &[frame], true)?;
        assert_eq!(active_observed(&mut test_pair.client), Some(newer));

        let frame = frame::Frame::ObservedAddress {
            seq_num: 99,
            addr: older,
        };
        test_pair.build_packet_and_send(PacketType::OneRTT, &[frame], true)?;
        assert_eq!(active_observed(&mut test_pair.client), Some(newer));
        Ok(())
    }

    #[test]
    fn observed_address_rejected_when_not_requested() -> Result<()> {
        let mut test_pair = address_discovery_pair(false, true)?;
        let frame = frame::Frame::ObservedAddress {
            seq_num: 0,
            addr: "203.0.113.7:4000".parse().unwrap(),
        };
        assert!(test_pair
            .build_packet_and_send(PacketType::OneRTT, &[frame], true)
            .is_err());
        Ok(())
    }

    #[test]
    fn observed_address_differs_per_path() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.enable_address_discovery(true);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.enable_address_discovery(true);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.advertise_new_cids()?;

        // A second source IP, as a second WAN would present it.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        for _ in 0..3 {
            test_pair.move_forward()?;
        }

        let mut observed: Vec<(SocketAddr, Option<SocketAddr>)> = test_pair
            .client
            .paths
            .iter()
            .map(|(_, p)| (p.local_addr(), p.observed_local_addr()))
            .collect();
        observed.sort();
        assert_eq!(
            observed,
            vec![
                (
                    "127.0.0.1:9443".parse().unwrap(),
                    Some("127.0.0.1:9443".parse().unwrap())
                ),
                (client_addr, Some(client_addr)),
            ]
        );
        Ok(())
    }

    #[test]
    fn pending_address_report_on_a_blocked_path_does_not_shadow_other_paths() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.enable_address_discovery(true);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.enable_address_discovery(true);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;
        test_pair.advertise_new_cids()?;
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(second, server_addr)?;
        for _ in 0..3 {
            test_pair.move_forward()?;
        }

        let server = &mut test_pair.server;
        let pid_of = |conn: &Connection, remote: bool| {
            conn.paths
                .iter()
                .find(|(_, p)| (p.remote_addr() == second) == remote)
                .map(|(pid, _)| pid)
                .unwrap()
        };
        let (blocked, other) = (pid_of(server, false), pid_of(server, true));

        // The first path owes a report but its congestion window is full;
        // the second path has a PING to send.
        let blocked_path = server.paths.get_mut(blocked)?;
        let remote = blocked_path.remote_addr();
        blocked_path.on_observed_addr_lost(remote);
        blocked_path.recovery.bytes_in_flight = usize::MAX / 2;
        server.paths.get_mut(other)?.need_send_ping = true;
        assert_eq!(server.select_send_path(&NoopSender)?, other);

        // Once the window opens the report goes out on its own path.
        server.paths.get_mut(blocked)?.recovery.bytes_in_flight = 0;
        server.paths.get_mut(other)?.need_send_ping = false;
        assert_eq!(server.select_send_path(&NoopSender)?, blocked);
        Ok(())
    }
}

mod cid;
mod datagrams;
mod flowcontrol;
pub mod path;
mod pmtu;
mod recovery;
pub(crate) mod rtt;
pub(crate) mod space;
pub(crate) mod stream;
pub(crate) mod timer;
