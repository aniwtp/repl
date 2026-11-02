//! Connection plumbing: TCP tuning, TLS connect/accept, framed `Conn` with a
//! dedicated reader task (cancel-safe receive, bounded backpressure).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use compio_net::TcpStream;
use compio_tls::{TlsAcceptor, TlsConnector, TlsStream};
use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use futures::{SinkExt, StreamExt};
use rustls::{ClientConfig, ServerConfig};

use crate::Error;
use crate::msg::{Msg, read_msg, write_msg};

pub type Tls = TlsStream<TcpStream>;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn with_timeout<T>(
    d: Duration,
    what: &'static str,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    match ntex::time::timeout(d, fut).await {
        Ok(r) => r,
        Err(_) => Err(Error::Timeout(what)),
    }
}

/// Dead-peer detection below TLS: keepalive probes and `TCP_USER_TIMEOUT`
/// catch blackholed links the application timers would notice only later.
fn tune(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5))
        .with_retries(3);
    let _ = sock.set_tcp_keepalive(&ka);
    let _ = sock.set_tcp_user_timeout(Some(Duration::from_secs(20)));
    let _ = sock.set_tcp_nodelay(true);
}

/// Framed connection. `recv` is cancel-safe (frames are read by a separate
/// task); dropping the `Conn` cancels that task and closes the socket.
pub struct Conn {
    w: WriteHalf<Tls>,
    rx: mpsc::Receiver<Result<Msg, Error>>,
    /// Dropping it wakes the reader task, which then exits. Unlike
    /// `JoinHandle::cancel` this needs no runtime, so a `Conn` held in a
    /// thread-local may be dropped during thread teardown.
    _stop: oneshot::Sender<()>,
}

impl Conn {
    pub fn new(tls: Tls) -> Self {
        let (mut r, w) = tls.split();
        let (mut tx, rx) = mpsc::channel(32);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        drop(ntex::rt::spawn(async move {
            let mut stop = stop_rx;
            loop {
                let read = std::pin::pin!(read_msg(&mut r));
                match futures::future::select(read, &mut stop).await {
                    futures::future::Either::Right(_) => break,
                    futures::future::Either::Left((Ok(Some(m)), _)) => {
                        if tx.send(Ok(m)).await.is_err() {
                            break;
                        }
                    }
                    // Clean EOF between frames; the receiver sees the stream end.
                    futures::future::Either::Left((Ok(None), _)) => break,
                    futures::future::Either::Left((Err(e), _)) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        }));
        Self { w, rx, _stop: stop_tx }
    }

    pub async fn send(&mut self, m: &Msg) -> Result<usize, Error> {
        with_timeout(WRITE_TIMEOUT, "write", write_msg(&mut self.w, m)).await
    }

    pub async fn recv(&mut self) -> Result<Msg, Error> {
        match self.rx.next().await {
            Some(r) => r,
            None => Err(Error::Closed),
        }
    }

    pub async fn recv_timeout(&mut self, d: Duration, what: &'static str) -> Result<Msg, Error> {
        with_timeout(d, what, self.recv()).await
    }

    /// Non-blocking receive: `Ok(None)` = nothing buffered right now.
    pub fn try_recv(&mut self) -> Result<Option<Msg>, Error> {
        match self.rx.try_recv() {
            Ok(r) => r.map(Some),
            Err(futures::channel::mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(Error::Closed),
        }
    }

    /// TLS close_notify; the peer treats a missing one as an error.
    pub async fn close(mut self) {
        let _ = ntex::time::timeout(Duration::from_secs(1), self.w.close()).await;
    }
}

pub async fn connect(addr: &str, cfg: &Arc<ClientConfig>) -> Result<Conn, Error> {
    let stream = with_timeout(CONNECT_TIMEOUT, "connect", async { Ok(TcpStream::connect(addr).await?) }).await?;
    tune(&stream);
    let connector = TlsConnector::from(cfg.clone());
    // The name is irrelevant: trust comes from the pinned certificate.
    let tls = with_timeout(HANDSHAKE_TIMEOUT, "tls handshake", async {
        Ok(connector.connect("repl.local", stream).await?)
    })
    .await?;
    Ok(Conn::new(tls))
}

pub async fn accept(stream: TcpStream, cfg: &Arc<ServerConfig>) -> Result<Conn, Error> {
    tune(&stream);
    let acceptor = TlsAcceptor::from(cfg.clone());
    let tls = with_timeout(HANDSHAKE_TIMEOUT, "tls handshake", async { Ok(acceptor.accept(stream).await?) }).await?;
    Ok(Conn::new(tls))
}
