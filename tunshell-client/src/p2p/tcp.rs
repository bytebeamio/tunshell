use crate::p2p::P2PConnection;
use crate::TunnelStream;
use anyhow::{Error, Result};
use async_trait::async_trait;
use futures::future::pending;
use futures::TryFutureExt;
use futures::{AsyncRead, AsyncWrite};
use log::*;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tunshell_shared::PeerJoinedPayload;

pub struct TcpConnection {
    peer_info: PeerJoinedPayload,
    listener: Option<TcpListener>,
    socket: Option<Compat<TcpStream>>,
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buff: &mut [u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        Pin::new(&mut self.socket.as_mut().unwrap())
            .poll_read(cx, buff)
            .map(|c| c.map(|_| 0))
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buff: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        Pin::new(&mut self.socket.as_mut().unwrap()).poll_write(cx, buff)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.socket.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.socket.as_mut().unwrap()).poll_close(cx)
    }
}

impl TunnelStream for TcpConnection {}

#[async_trait]
impl P2PConnection for TcpConnection {
    fn new(peer_info: PeerJoinedPayload) -> Self {
        Self {
            peer_info,
            listener: None,
            socket: None,
        }
    }

    async fn bind(&mut self) -> Result<u16> {
        let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        let port = listener.local_addr()?.port();

        self.listener.replace(listener);

        Ok(port)
    }

    async fn connect(&mut self, peer_port: u16, _master_side: bool) -> Result<()> {
        assert!(self.listener.is_some());

        info!(
            "Attempting to connect to {} via TCP",
            self.peer_info.peer_ip_address
        );

        let peer_addr = (self.peer_info.peer_ip_address.as_str(), peer_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let connect_future =
            TcpStream::connect(peer_addr).or_else(|_| pending::<std::io::Result<TcpStream>>());

        let listen_future = self
            .listener
            .as_mut()
            .unwrap()
            .accept()
            .or_else(|_| pending::<std::io::Result<(TcpStream, SocketAddr)>>());

        let result = tokio::select! {
            result = connect_future => result.map(|socket| (socket, peer_addr)),
            result = listen_future => result,
        };

        if let Ok((socket, peer_addr)) = result {
            let connected_ip = self.peer_info.peer_ip_address.parse::<IpAddr>().unwrap();

            if peer_addr.ip() == connected_ip {
                // socket.set_keepalive(Some(Duration::from_secs(30)))?;
                self.socket.replace(socket.compat());
                return Ok(());
            } else {
                error!("received connection from unknown ip address: {}", peer_addr);
            }
        }

        Err(Error::msg("Direct TCP connection failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};
    use std::time::Duration;
    use tokio::{runtime::Runtime, time::sleep};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[test]
    fn test_connect_via_connect() {
        Runtime::new().unwrap().block_on(async {
            let listener = TcpListener::bind("0.0.0.0:22335".to_owned())
                .await
                .expect("failed listen for connection");

            let mut connection1 = TcpConnection::new(PeerJoinedPayload {
                peer_ip_address: "127.0.0.1".to_owned(),
                peer_key: "test".to_owned(),
                session_nonce: "nonce".to_owned(),
            });

            connection1.bind().await.expect("failed to bind");
            connection1
                .connect(22335, false)
                .await
                .expect("failed to connect");

            let (socket, _) = listener
                .accept()
                .await
                .expect("failed to accept connection");
            let mut socket = socket.compat();

            connection1
                .write("hello".as_bytes())
                .await
                .expect("failed to write to socket");

            let mut buff = [0; 1024];
            let read = socket
                .read(&mut buff)
                .await
                .expect("failed to read from socket");

            assert_eq!(String::from_utf8(buff[..read].to_vec()).unwrap(), "hello");

            socket
                .write("hi".as_bytes())
                .await
                .expect("failed to write to socket");

            let read = connection1
                .read(&mut buff)
                .await
                .expect("failed to read from socket");

            assert_eq!(String::from_utf8(buff[..read].to_vec()).unwrap(), "hi");
        });
    }

    #[test]
    fn test_connect_via_listener() {
        Runtime::new().unwrap().block_on(async {
            let peer_info = PeerJoinedPayload {
                peer_ip_address: "127.0.0.1".to_owned(),
                peer_key: "test".to_owned(),
                session_nonce: "nonce".to_owned(),
            };
            let mut connection1 = TcpConnection::new(peer_info.clone());

            let port = connection1.bind().await.expect("failed to bind");

            let socket = sleep(Duration::from_millis(100))
                .then(|_| TcpStream::connect(format!("127.0.0.1:{}", port)))
                .or_else(|err| futures::future::err(Error::new(err)));

            let (_, socket) = futures::try_join!(connection1.connect(22444, false), socket)
                .expect("failed to connect");
            let mut socket = socket.compat();

            socket.write("hello".as_bytes()).await.unwrap();

            let mut buff = [0; 1024];
            let read = connection1.read(&mut buff).await.unwrap();

            assert_eq!(String::from_utf8(buff[..read].to_vec()).unwrap(), "hello");

            connection1.write("hi".as_bytes()).await.unwrap();

            let read = socket.read(&mut buff).await.unwrap();

            assert_eq!(String::from_utf8(buff[..read].to_vec()).unwrap(), "hi");
        });
    }
}
