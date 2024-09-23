use super::{
    schedule_resend_if_dropped, SendEvent, SendEventReceiver, UdpConnectionVars, UdpPacket,
    UdpPacketType,
};
use anyhow::{Error, Result};
use log::*;
use std::sync::{Arc, Mutex};
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::delay_for;

pub(super) struct UdpConnectionOrchestrator {
    con: Arc<Mutex<UdpConnectionVars>>,
    state: OrchestratorState,
}

enum OrchestratorState {
    Waiting(RecvLoop, SendLoop),
    Starting,
    Running {
        task: JoinHandle<(RecvLoop, SendLoop)>,
        recv_terminator: UnboundedSender<()>,
        send_terminator: UnboundedSender<()>,
    },
}

struct RecvLoop {
    socket: RecvHalf,
    con: Arc<Mutex<UdpConnectionVars>>,
}

struct SendLoop {
    socket: SendHalf,
    con: Arc<Mutex<UdpConnectionVars>>,
    event_receiver: SendEventReceiver,
}

impl RecvLoop {
    pub(super) fn new(socket: RecvHalf, con: Arc<Mutex<UdpConnectionVars>>) -> Self {
        Self { socket, con }
    }

    async fn start(
        mut self,
        mut recv_terminator: UnboundedReceiver<()>,
        send_terminator: UnboundedSender<()>,
    ) -> Self {
        let recv_timeout = {
            let con = self.con.lock().unwrap();
            let config = con.config();

            config.recv_timeout()
        };

        let mut recv_buff = [0u8; 1024];

        debug!("recv loop started");

        while is_connected(&self.con) {
            let result = tokio::select! {
                result = self.socket.recv(&mut recv_buff) => match result {
                    Ok(read) => handle_recv_packet(Arc::clone(&self.con), &recv_buff[..read]),
                    Err(err) => Err(Error::from(err))
                },
                _ = delay_for(recv_timeout) => handle_recv_timeout(Arc::clone(&self.con)),
                _ = recv_terminator.recv() => break
            };

            if let Err(err) = result {
                warn!("error during recv loop: {}", err);
                break;
            }

            // Prevent the loop from blocking the executor
            _ = tokio::task::yield_now().await;
        }

        try_disconnect(&self.con);
        debug!("recv loop ended");
        send_terminator.send(()).unwrap_or(());
        self
    }
}

impl SendLoop {
    pub(super) fn new(
        socket: SendHalf,
        con: Arc<Mutex<UdpConnectionVars>>,
        event_receiver: SendEventReceiver,
    ) -> Self {
        Self {
            socket,
            con,
            event_receiver,
        }
    }

    async fn start(
        mut self,
        mut send_terminator: UnboundedReceiver<()>,
        recv_terminator: UnboundedSender<()>,
    ) -> Self {
        let keep_alive_interval = {
            let con = self.con.lock().unwrap();
            let config = con.config();

            config.keep_alive_interval()
        };

        debug!("send loop started");

        while is_connected(&self.con) {
            let result = tokio::select! {
                result = self.event_receiver.wait_for_next_sendable_packet(
                    Arc::clone(&self.con)
                ) => match result {
                    Some(packet) => handle_send_packet(Arc::clone(&self.con), packet, &mut self.socket).await,
                    None => Err(Error::msg("send channel has been dropped"))
                },
                _ = delay_for(keep_alive_interval) => handle_keep_alive(Arc::clone(&self.con), &mut self.socket).await,
                _ = send_terminator.recv() => break
            };

            if let Err(err) = result {
                warn!("error during send loop: {}", err);
                break;
            }

            // Prevent the loop from blocking the executor
            _ = tokio::task::yield_now().await;
        }

        try_disconnect(&self.con);
        debug!("send loop ended");
        recv_terminator.send(()).unwrap_or(());
        self
    }
}

impl UdpConnectionOrchestrator {
    pub(super) fn new(
        socket: UdpSocket,
        con: Arc<Mutex<UdpConnectionVars>>,
        send_receiver: UnboundedReceiver<SendEvent>,
    ) -> Self {
        let (recv, send) = socket.split();

        Self {
            con: Arc::clone(&con),
            state: OrchestratorState::Waiting(
                RecvLoop::new(recv, Arc::clone(&con)),
                SendLoop::new(
                    send,
                    Arc::clone(&con),
                    SendEventReceiver::new(send_receiver),
                ),
            ),
        }
    }

    pub(super) fn start_orchestration_loop(&mut self) {
        let state = std::mem::replace(&mut self.state, OrchestratorState::Starting);

        let (recv_loop, send_loop) = match state {
            OrchestratorState::Waiting(recv_loop, send_loop) => (recv_loop, send_loop),
            _ => panic!("loop must be in waiting state"),
        };

        let (tx_recv, rx_recv) = unbounded_channel();
        let (tx_send, rx_send) = unbounded_channel();

        let (tx_recv2, tx_send2) = (tx_recv.clone(), tx_send.clone());
        let task = tokio::spawn(async move {
            tokio::join!(
                recv_loop.start(rx_recv, tx_send2.clone()),
                send_loop.start(rx_send, tx_recv2.clone()),
            )
        });

        self.state = OrchestratorState::Running {
            task,
            recv_terminator: tx_recv,
            send_terminator: tx_send,
        }
    }

    fn stop_loops(&mut self) {
        let (_, recv_terminator, send_terminator) = match &mut self.state {
            OrchestratorState::Running {
                task,
                recv_terminator,
                send_terminator,
            } => (task, recv_terminator, send_terminator),
            OrchestratorState::Waiting(_, _) => return,
            OrchestratorState::Starting => panic!("cannot stop loops while in starting state"),
        };

        recv_terminator
            .send(())
            .unwrap_or_else(|err| info!("recv loop terminator channel error: {}", err));
        send_terminator
            .send(())
            .unwrap_or_else(|err| info!("send loop terminator channel error: {}", err));
    }
}

impl Drop for UdpConnectionOrchestrator {
    fn drop(&mut self) {
        try_disconnect(&self.con);

        self.stop_loops();
    }
}

fn is_connected(con: &Arc<Mutex<UdpConnectionVars>>) -> bool {
    let con = con.lock().unwrap();

    con.is_connected()
}

fn try_disconnect(con: &Arc<Mutex<UdpConnectionVars>>) {
    match con.try_lock() {
        Ok(mut con) => {
            con.try_set_state_disconnected();
            con.wake_recv_tasks();
        }
        Err(err) => warn!("failed to lock connection state: {}", err),
    };
}

fn handle_recv_packet(con: Arc<Mutex<UdpConnectionVars>>, packet: &[u8]) -> Result<()> {
    let packet = match UdpPacket::parse(packet) {
        Ok(packet) => packet,
        Err(err) => {
            warn!("could not parse packet from incoming datagram: {}", err);
            return Ok(());
        }
    };

    if !packet.is_checksum_valid() {
        warn!(
            "received packet {} with invalid checksum, expected {}, received {}, discarding",
            packet.sequence_number,
            packet.calculate_checksum(),
            packet.checksum
        );
        return Ok(());
    }

    debug!(
        "recv packet [{}, {}] (ack: {}, window: {})",
        packet.sequence_number,
        packet.end_sequence_number(),
        packet.ack_number,
        packet.window
    );

    match packet.packet_type {
        UdpPacketType::Data => {}
        UdpPacketType::Close => {
            try_disconnect(&con);
            return Err(Error::msg("close packet received"));
        }
        _ => return Err(Error::msg("unexpected packet type received")),
    }

    let mut con = con.lock().unwrap();

    match con.recv_process_packet(packet.clone()) {
        Ok(_) => {
            con.update_peer_ack_number(packet.ack_number);
            con.update_peer_window(packet.window);
            con.adjust_rtt_estimate(&packet);
        }
        Err(err) => warn!("error while receiving packet: {}", err),
    }

    Ok(())
}

fn handle_recv_timeout(con: Arc<Mutex<UdpConnectionVars>>) -> Result<()> {
    try_disconnect(&con);
    Err(Error::msg(
        "connection timed out while waiting for next packet",
    ))
}

async fn handle_send_packet(
    con: Arc<Mutex<UdpConnectionVars>>,
    packet: UdpPacket,
    socket_send: &mut SendHalf,
) -> Result<()> {
    match socket_send.send(&packet.to_vec()[..]).await {
        Ok(_) => {}
        Err(err) => return Err(Error::from(err)),
    }

    let peer_window = {
        let con = con.lock().unwrap();
        con.peer_window
    };
    debug!(
        "sent packet [{}, {}] (ack: {}, window: {}, peer window: {})",
        packet.sequence_number,
        packet.end_sequence_number(),
        packet.ack_number,
        packet.window,
        peer_window
    );

    match packet.packet_type {
        UdpPacketType::Data => {
            {
                let mut con = con.lock().unwrap();
                con.store_send_time_of_packet(&packet);
                con.increase_transit_window_after_send();
            }

            if !packet.payload.is_empty() {
                schedule_resend_if_dropped(con, packet);
            }

            Ok(())
        }
        UdpPacketType::Close => {
            info!("close packet sent");
            try_disconnect(&con);
            Ok(())
        }
        _ => panic!("unexpected send packet type"),
    }
}

async fn handle_keep_alive(
    con: Arc<Mutex<UdpConnectionVars>>,
    socket_send: &mut SendHalf,
) -> Result<()> {
    let keep_alive_packet = {
        let mut con = con.lock().unwrap();

        // Send empty packet for keep alive
        con.create_data_packet(&[])
    };

    debug!("sending keep alive packet");
    handle_send_packet(con, keep_alive_packet, socket_send).await
}

#[cfg(test)]
mod tests {
    use super::super::{SequenceNumber, UdpConnectionConfig, UdpConnectionState};
    use super::*;
    use lazy_static::lazy_static;
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

    lazy_static! {
        static ref UDP_PORT_NUMBER: Mutex<u16> = Mutex::from(25660);
    }

    async fn init_udp_socket_pair() -> (UdpSocket, UdpSocket) {
        let (port1, port2) = {
            let mut port = UDP_PORT_NUMBER.lock().unwrap();

            *port += 2;
            (*port, *port - 1)
        };

        let socket1 = UdpSocket::bind("0.0.0.0:".to_owned() + &port1.to_string())
            .await
            .unwrap();

        socket1
            .connect("127.0.0.1:".to_owned() + &port2.to_string())
            .await
            .unwrap();

        let socket2 = UdpSocket::bind("0.0.0.0:".to_owned() + &port2.to_string())
            .await
            .unwrap();
        socket2
            .connect("127.0.0.1:".to_owned() + &port1.to_string())
            .await
            .unwrap();

        return (socket1, socket2);
    }

    async fn init_udp_orchestrator_and_raw_socket(
        config: UdpConnectionConfig,
    ) -> (
        UdpConnectionOrchestrator,
        Arc<Mutex<UdpConnectionVars>>,
        UnboundedSender<SendEvent>,
        UdpSocket,
    ) {
        let (socket1, socket2) = init_udp_socket_pair().await;

        let (tx, rx) = unbounded_channel();

        let mut con = UdpConnectionVars::new(config);
        con.state = UdpConnectionState::Connected;
        con.event_sender.replace(tx.clone());
        let con = Arc::new(Mutex::new(con));

        let orchestrator = UdpConnectionOrchestrator::new(socket1, Arc::clone(&con), rx);

        (orchestrator, con, tx, socket2)
    }

    #[test]
    fn test_recv_single_packet() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default();
            let (mut orchestrator, con, _, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            socket
                .send(
                    UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[1, 2, 3, 4])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            // Should successfully receive packet
            let mut con = con.lock().unwrap();

            assert_eq!(con.recv_drain_bytes(10), vec![1, 2, 3, 4]);
            assert_eq!(con.sequence_number, SequenceNumber(0));
            assert_eq!(con.ack_number, SequenceNumber(5));
        });
    }

    #[test]
    fn test_recv_single_packet_update_peer_state() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default();
            let (mut orchestrator, con, _, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            socket
                .send(
                    UdpPacket::data(SequenceNumber(0), SequenceNumber(50), 1000, &[])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            // Should successfully receive packet
            let con = con.lock().unwrap();

            assert_eq!(con.ack_number, SequenceNumber(0));
            assert_eq!(con.peer_window, 1000);
            assert_eq!(con.peer_ack_number, SequenceNumber(50));
        });
    }

    #[test]
    fn test_recv_out_of_order_packets() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default();
            let (mut orchestrator, con, _, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            socket
                .send(
                    UdpPacket::data(SequenceNumber(6), SequenceNumber(0), 1000, &[5, 6, 7, 8])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            // Should not receive data until gap is filled
            {
                let mut con = con.lock().unwrap();

                assert_eq!(con.recv_drain_bytes(10), Vec::<u8>::new());
                assert_eq!(con.sequence_number, SequenceNumber(0));
                assert_eq!(con.ack_number, SequenceNumber(0));
                assert_eq!(con.recv_packets.len(), 1);
            }

            socket
                .send(
                    UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[1, 2, 3, 4])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            // Should successfully reassemble data
            let mut con = con.lock().unwrap();

            assert_eq!(con.recv_drain_bytes(10), vec![1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(con.sequence_number, SequenceNumber(0));
            assert_eq!(con.ack_number, SequenceNumber(10));
            assert_eq!(con.recv_packets.len(), 0);
        });
    }

    #[test]
    fn test_recv_packet_with_invalid_checksum() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default();
            let (mut orchestrator, con, _, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            let mut packet = UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[]);
            packet.checksum = 0;

            socket.send(packet.to_vec().as_slice()).await.unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            // Should discard packet with invalid checksum
            {
                let con = con.lock().unwrap();

                assert_eq!(con.sequence_number, SequenceNumber(0));
                assert_eq!(con.ack_number, SequenceNumber(0));
                assert_eq!(con.recv_packets.len(), 0);
            }
        });
    }

    #[test]
    fn test_recv_packet_sends_ack_update() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default().with_recv_window(1000);
            let (mut orchestrator, _, _, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            socket
                .send(
                    UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[1, 2, 3, 4])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            let mut buff = [0u8; 1024];
            let received = socket.recv(&mut buff).await.unwrap();
            let received_packet = UdpPacket::parse(&buff[..received]).unwrap();

            assert_eq!(
                received_packet,
                UdpPacket::data(SequenceNumber(0), SequenceNumber(5), 1000 - 4, &[])
            );
        });
    }

    #[test]
    fn test_send_single_packet() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default();
            let (mut orchestrator, con, tx, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            let sent_packet = {
                let mut con = con.lock().unwrap();
                con.peer_window = 1000;
                let sent_packet = con.create_data_packet(&[1, 2, 3, 4, 5]);
                tx.send(SendEvent::Send(sent_packet.clone())).unwrap();

                sent_packet
            };

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            let mut buff = [0u8; 1024];
            let received = socket.recv(&mut buff).await.unwrap();
            let received_packet = UdpPacket::parse(&buff[..received]).unwrap();

            assert_eq!(received_packet, sent_packet);
        });
    }

    #[test]
    fn test_send_and_handle_ack() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default();
            let (mut orchestrator, con, tx, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            // Send packet
            {
                let mut con = con.lock().unwrap();
                con.peer_window = 1000;
                let sent_packet = con.create_data_packet(&[1, 2, 3, 4, 5]);
                tx.send(SendEvent::Send(sent_packet.clone())).unwrap();

                sent_packet
            };

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            {
                let con = con.lock().unwrap();

                assert_eq!(con.peer_ack_number, SequenceNumber(0));
                assert_eq!(con.sent_packets.len(), 1);
                assert_eq!(con.send_times.len(), 1);
            }

            // Send mock ack
            socket
                .send(
                    UdpPacket::data(SequenceNumber(1), SequenceNumber(6), 1000, &[])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            {
                let con = con.lock().unwrap();

                assert_eq!(con.peer_ack_number, SequenceNumber(6));
                assert_eq!(con.sent_packets.len(), 0);
                assert_eq!(con.send_times.len(), 0);

                // RTT estimation not reliable on CI/CD pipeline
                if std::env::var("CI").is_err() {
                    // RTT estimate should be roughly the initial delay time (50ms)
                    // as the ack will be sent almost instantly
                    assert_eq!((con.rtt_estimate.as_millis() as i32 - 50) < 10, true);
                }
            }
        });
    }

    #[test]
    fn test_wait_until_peer_window_permits_new_packet() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default().with_recv_window(1000);
            let (mut orchestrator, con, tx, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            // Send packet
            {
                let mut con = con.lock().unwrap();
                con.peer_window = 0;
                let sent_packet = con.create_data_packet(&[1, 2, 3, 4, 5]);
                tx.send(SendEvent::Send(sent_packet.clone())).unwrap();

                sent_packet
            };

            // Packet should not send due to zero window
            tokio::time::delay_for(Duration::from_millis(50)).await;

            {
                let con = con.lock().unwrap();

                assert_eq!(con.sent_packets.len(), 0);
            }

            // Send mock window update
            socket
                .send(
                    UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for packet to send and process
            tokio::time::delay_for(Duration::from_millis(50)).await;

            {
                let con = con.lock().unwrap();

                assert_eq!(con.sent_packets.len(), 1);
                assert_eq!(con.send_times.len(), 1);
            }

            let mut buff = [0u8; 1024];
            let received = socket.recv(&mut buff).await.unwrap();
            let received_packet = UdpPacket::parse(&buff[..received]).unwrap();

            assert_eq!(
                received_packet,
                UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[1, 2, 3, 4, 5])
            );
        });
    }

    #[test]
    fn test_resends_dropped_packet() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default().with_recv_window(1000);
            let (mut orchestrator, con, tx, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            // Send packet
            {
                let mut con = con.lock().unwrap();
                con.peer_window = 1000;
                con.rtt_estimate = Duration::from_millis(100);
                let sent_packet = con.create_data_packet(&[1, 2, 3, 4, 5]);
                tx.send(SendEvent::Send(sent_packet.clone())).unwrap();

                sent_packet
            };

            // Wait for packet to send
            tokio::time::delay_for(Duration::from_millis(50)).await;

            let mut buff = [0u8; 1024];
            let received = socket.recv(&mut buff).await.unwrap();
            let received_packet = UdpPacket::parse(&buff[..received]).unwrap();

            assert_eq!(
                received_packet,
                UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[1, 2, 3, 4, 5])
            );

            {
                let con = con.lock().unwrap();

                assert_eq!(con.sent_packets.len(), 1);
            }

            // Wait for 2.5 RTT to force packet to reset
            tokio::time::delay_for(Duration::from_millis(200)).await;

            let mut buff = [0u8; 1024];
            let received = socket.recv(&mut buff).await.unwrap();
            let received_packet = UdpPacket::parse(&buff[..received]).unwrap();

            assert_eq!(
                received_packet,
                UdpPacket::data(SequenceNumber(1), SequenceNumber(0), 1000, &[1, 2, 3, 4, 5])
            );

            {
                let con = con.lock().unwrap();

                assert_eq!(con.sent_packets.len(), 1);
            }

            // Send mock ack
            socket
                .send(
                    UdpPacket::data(SequenceNumber(1), SequenceNumber(6), 1000, &[])
                        .to_vec()
                        .as_slice(),
                )
                .await
                .unwrap();

            // Wait for ack to be received and processed
            tokio::time::delay_for(Duration::from_millis(50)).await;

            {
                let con = con.lock().unwrap();

                assert_eq!(con.peer_ack_number, SequenceNumber(6));
                assert_eq!(con.sent_packets.len(), 0);
            }

            // Wait for 2.5 RTT to verify acknowledged packet is not resent
            tokio::time::delay_for(Duration::from_millis(200)).await;

            tokio::select! {
                _ = socket.recv(&mut buff) => panic!("packet should not be resent after being acknowledged by the peer"),
                _ = delay_for(Duration::from_millis(10)) => {}
            }
        });
    }

    #[test]
    fn test_recv_timeout() {
        // TODO: fix flaky test
        if std::env::var("CI").is_ok() {
            return;
        }

        Runtime::new().unwrap().block_on(async {
            let config =
                UdpConnectionConfig::default().with_recv_timeout(Duration::from_millis(50));
            let (mut orchestrator, con, _, _) = init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            // Wait for recv timeout
            tokio::time::delay_for(Duration::from_millis(100)).await;

            {
                let con = con.lock().unwrap();

                assert_eq!(con.state, UdpConnectionState::Disconnected);
            }
        });
    }

    #[test]
    fn test_keep_alive_packet() {
        Runtime::new().unwrap().block_on(async {
            let config = UdpConnectionConfig::default()
                .with_recv_window(1000)
                .with_keep_alive_interval(Duration::from_millis(50));
            let (mut orchestrator, _, _, mut socket) =
                init_udp_orchestrator_and_raw_socket(config).await;

            orchestrator.start_orchestration_loop();

            for _ in 1..=3 {
                // Wait for keep alive interval
                tokio::time::delay_for(Duration::from_millis(60)).await;

                let mut buff = [0u8; 1024];
                let received = socket.recv(&mut buff).await.unwrap();
                let received_packet = UdpPacket::parse(&buff[..received]).unwrap();

                assert_eq!(
                    received_packet,
                    UdpPacket::data(SequenceNumber(0), SequenceNumber(0), 1000, &[])
                );
            }
        });
    }
}
