//! Main node: accepts replica connections; per connection either streams
//! committed changes (with snapshot fallback) or executes forwarded requests.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use db_wrapper::{CdcRead, DBWrapper, RawOp};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use ntex::http::header::{HeaderName, HeaderValue};
use ntex::http::Method;

use crate::conn::{self, Conn, HANDSHAKE_TIMEOUT};
use crate::msg::*;
use crate::stats::{Latency, ReplicaEntry, mono_us};
use crate::{Cmd, ConnHandle, Error, Shared};

pub(crate) async fn listen(sh: Arc<Shared>) -> Result<(), Error> {
    let listener = compio_net::TcpListener::bind(&sh.cfg.bind).await?;
    log::info!("repl[{}]: main node listening on {}", sh.cfg.node_id, sh.cfg.bind);
    ntex::rt::spawn(async move {
        while !sh.stop.load(Ordering::Relaxed) {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let sh = sh.clone();
                    ntex::rt::spawn(async move {
                        if let Err(e) = session(&sh, stream).await {
                            log::warn!("repl[{}]: connection from {peer}: {e}", sh.cfg.node_id);
                        }
                    })
                    ;
                }
                Err(e) => {
                    log::error!("repl: accept: {e}");
                    ntex::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
    ;
    Ok(())
}

async fn refuse(conn: &mut Conn, code: FaultCode, text: String) -> Error {
    let _ = conn.send(&Msg::Fault(Fault { code, msg: text.clone() })).await;
    Error::Fault { code, msg: text }
}

async fn session(sh: &Arc<Shared>, stream: compio_net::TcpStream) -> Result<(), Error> {
    let tls = sh.tls_server.as_ref().expect("primary tls");
    let mut conn = conn::accept(stream, tls).await?;
    let hello = match conn.recv_timeout(HANDSHAKE_TIMEOUT, "hello").await? {
        Msg::Hello(h) => h,
        other => return Err(Error::Proto(format!("expected hello, got {}", other.name()))),
    };
    if hello.proto != PROTO || hello.schema != sh.cfg.schema {
        let text = format!(
            "proto {}/schema {} here, {}/{} there",
            PROTO, sh.cfg.schema, hello.proto, hello.schema
        );
        return Err(refuse(&mut conn, FaultCode::VersionMismatch, text).await);
    }
    if !sh.cfg.peers.contains_name(&hello.node_id) {
        return Err(refuse(&mut conn, FaultCode::Unauthorized, format!("unknown node `{}`", hello.node_id)).await);
    }
    match hello.kind {
        Kind::Stream => stream_session(sh, conn, hello).await,
        Kind::Rpc => rpc_session(sh, conn, hello).await,
    }
}

pub(crate) async fn db_call<T: Send + 'static>(
    sh: &Shared,
    f: impl FnOnce(&DBWrapper) -> Result<T, db_wrapper::DbError> + Send + 'static,
) -> Result<T, Error> {
    let db = sh.db().clone();
    match ntex::rt::spawn_blocking(move || f(&db)).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(Error::Proto("blocking task failed".into())),
    }
}

// -- snapshot -------------------------------------------------------------------

enum SnapItem {
    Start { txn: u64, tables: u32 },
    Rows { table: String, rows: Vec<(Vec<u8>, Vec<u8>)> },
    Done { entries: u64, digest: [u8; 32] },
    Err(Error),
}

struct SnapGuard(Arc<Shared>);
impl Drop for SnapGuard {
    fn drop(&mut self) {
        self.0.snapshots_active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Reads a consistent snapshot on a blocking thread and feeds it through a
/// bounded channel (backpressure from the socket reaches the reader).
fn spawn_snapshot(db: DBWrapper, chunk_bytes: usize) -> mpsc::Receiver<SnapItem> {
    let (mut tx, rx) = mpsc::channel(4);
    ntex::rt::spawn_blocking(move || {
        let send = |tx: &mut mpsc::Sender<SnapItem>, item| futures::executor::block_on(tx.send(item)).is_ok();
        let run = |tx: &mut mpsc::Sender<SnapItem>| -> Result<(), Error> {
            let snap = db.repl_snapshot()?;
            let tables = snap.tables();
            if !send(tx, SnapItem::Start { txn: snap.txn, tables: tables.len() as u32 }) {
                return Ok(());
            }
            let mut hasher = blake3::Hasher::new();
            let mut entries = 0u64;
            for t in &tables {
                let mut after: Option<Vec<u8>> = None;
                loop {
                    let (rows, more) = snap.scan(t, after.as_deref(), chunk_bytes)?;
                    if let Some((k, _)) = rows.last() {
                        after = Some(k.clone());
                    }
                    for (k, v) in &rows {
                        feed_row(&mut hasher, t, k, Some(v));
                    }
                    entries += rows.len() as u64;
                    if !rows.is_empty() && !send(tx, SnapItem::Rows { table: t.clone(), rows }) {
                        return Ok(());
                    }
                    if !more {
                        break;
                    }
                }
            }
            send(tx, SnapItem::Done { entries, digest: *hasher.finalize().as_bytes() });
            Ok(())
        };
        if let Err(e) = run(&mut tx) {
            send(&mut tx, SnapItem::Err(e));
        }
    })
    .detach();
    rx
}

// -- stream session ---------------------------------------------------------------

struct Registered<'a> {
    sh: &'a Shared,
    node: String,
    id: u64,
}
impl Drop for Registered<'_> {
    fn drop(&mut self) {
        let mut conns = self.sh.conns.lock();
        if conns.get(&self.node).is_some_and(|h| h.id == self.id) {
            conns.remove(&self.node);
        }
        if let Some(e) = self.sh.stats.replicas.lock().get_mut(&self.node) {
            e.since = None;
            e.mode = "disconnected";
        }
    }
}

async fn stream_session(sh: &Arc<Shared>, mut conn: Conn, hello: Hello) -> Result<(), Error> {
    let node = hello.node_id.clone();
    let stream_id = (*sh.stream_id.lock()).expect("primary has a stream id");
    let head = db_call(sh, |db| db.cdc_head()).await?;

    let mut mode = Mode::Snapshot;
    if hello.stream_id == stream_id && hello.applied > 0 && hello.applied <= head {
        let from = hello.applied;
        if !matches!(db_call(sh, move |db| db.cdc_read(from, 0)).await?, CdcRead::Behind) {
            mode = Mode::Stream;
        }
    }

    // Admission: replica cap, snapshot cap; a reconnecting node evicts its stale connection.
    let (kill, cmd_rx, id, _registered) = {
        let mut conns = sh.conns.lock();
        if let Some(old) = conns.get(&node) {
            old.kill.store(true, Ordering::Relaxed);
        } else if conns.len() >= sh.cfg.max_replicas {
            drop(conns);
            return Err(refuse(&mut conn, FaultCode::Busy, "too many replicas".into()).await);
        }
        let id = sh.conn_seq.fetch_add(1, Ordering::Relaxed);
        let kill = Arc::new(AtomicBool::new(false));
        let (cmd_tx, cmd_rx) = mpsc::unbounded();
        conns.insert(node.clone(), ConnHandle { id, kill: kill.clone(), cmd: cmd_tx });
        (kill, cmd_rx, id, Registered { sh, node: node.clone(), id })
    };
    let _ = id;
    {
        let mut st = sh.stats.replicas.lock();
        let e = st.entry(node.clone()).or_insert_with(ReplicaEntry::default);
        e.since = Some(Instant::now());
        e.mode = if mode == Mode::Snapshot { "snapshot" } else { "streaming" };
        e.applied = hello.applied;
        e.head = head;
    }

    let mut cursor = hello.applied;
    if mode == Mode::Snapshot {
        if sh.snapshots_active.fetch_add(1, Ordering::Relaxed) >= sh.cfg.max_snapshots {
            sh.snapshots_active.fetch_sub(1, Ordering::Relaxed);
            return Err(refuse(&mut conn, FaultCode::Busy, "too many snapshots in progress".into()).await);
        }
        let _guard = SnapGuard(sh.clone());
        let mut rx = spawn_snapshot(sh.db().clone(), sh.cfg.snapshot_chunk_bytes);
        let Some(SnapItem::Start { txn, tables }) = rx.next().await else {
            return Err(Error::Proto("snapshot did not start".into()));
        };
        conn.send(&Msg::Welcome(Welcome {
            node_id: sh.cfg.node_id.clone(),
            stream_id: stream_id.to_vec(),
            head,
            mode: Mode::Snapshot,
            snapshot_txn: txn,
        }))
        .await?;
        log::info!("repl[{}]: snapshot to `{node}` at txn {txn} ({tables} tables)", sh.cfg.node_id);
        loop {
            match rx.next().await {
                Some(SnapItem::Rows { table, rows }) => {
                    let n = conn.send(&Msg::Chunk(Chunk { table, entries: rows })).await?;
                    if let Some(e) = sh.stats.replicas.lock().get_mut(&node) {
                        e.bytes_sent += n as u64;
                    }
                }
                Some(SnapItem::Done { entries, digest }) => {
                    conn.send(&Msg::SnapEnd(SnapEnd { txn, tables, entries, digest })).await?;
                    break;
                }
                Some(SnapItem::Err(e)) => return Err(e),
                Some(SnapItem::Start { .. }) | None => return Err(Error::Proto("snapshot aborted".into())),
            }
        }
        cursor = txn;
        if let Some(e) = sh.stats.replicas.lock().get_mut(&node) {
            e.snapshots += 1;
            e.mode = "streaming";
            e.applied = txn;
        }
    } else {
        conn.send(&Msg::Welcome(Welcome {
            node_id: sh.cfg.node_id.clone(),
            stream_id: stream_id.to_vec(),
            head,
            mode: Mode::Stream,
            snapshot_txn: 0,
        }))
        .await?;
    }

    stream_loop(sh, &mut conn, &node, &kill, cmd_rx, cursor).await
}

struct Probe {
    left: u32,
    outstanding: Option<u64>,
    samples: Vec<u64>,
    started: Instant,
    done: Option<oneshot::Sender<Vec<u64>>>,
}

struct Loop<'a> {
    sh: &'a Shared,
    node: &'a str,
    inflight: VecDeque<(u64, usize, Instant)>,
    inflight_bytes: usize,
    last_rx: Instant,
    probe: Option<Probe>,
    rtt: Latency,
}

impl Loop<'_> {
    /// Reaction to one message from the replica; returns an optional reply.
    fn on_msg(&mut self, m: Msg) -> Result<Option<Msg>, Error> {
        self.last_rx = Instant::now();
        match m {
            Msg::Ack(a) => {
                let mut sent_at = None;
                while self.inflight.front().is_some_and(|(to, ..)| *to <= a.txn) {
                    let (_, bytes, at) = self.inflight.pop_front().expect("checked");
                    self.inflight_bytes = self.inflight_bytes.saturating_sub(bytes);
                    sent_at = Some(at);
                }
                if let Some(e) = self.sh.stats.replicas.lock().get_mut(self.node) {
                    if let Some(at) = sent_at {
                        e.ack.record(at.elapsed().as_micros() as u64);
                    }
                    e.applied = e.applied.max(a.txn);
                }
                Ok(None)
            }
            Msg::Ping(p) => {
                if let Some(e) = self.sh.stats.replicas.lock().get_mut(self.node) {
                    e.replica_rtt_us = p.peer_rtt_us;
                    e.applied = e.applied.max(p.applied);
                }
                Ok(Some(Msg::Pong(Pong { seq: p.seq, echo_us: p.sent_us })))
            }
            Msg::Pong(p) => {
                let rtt = mono_us().saturating_sub(p.echo_us);
                let probe_hit = self.probe.as_mut().is_some_and(|pr| {
                    let hit = pr.outstanding == Some(p.seq);
                    if hit {
                        pr.outstanding = None;
                        pr.samples.push(rtt);
                    }
                    hit
                });
                self.rtt.record(rtt);
                if let Some(e) = self.sh.stats.replicas.lock().get_mut(self.node) {
                    e.rtt.record(rtt);
                }
                let _ = probe_hit;
                Ok(None)
            }
            Msg::Fault(f) => Err(Error::Fault { code: f.code, msg: f.msg }),
            other => Err(Error::Proto(format!("unexpected {} from replica", other.name()))),
        }
    }
}

async fn stream_loop(
    sh: &Arc<Shared>,
    conn: &mut Conn,
    node: &str,
    kill: &AtomicBool,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    mut cursor: u64,
) -> Result<(), Error> {
    let cfg = &sh.cfg;
    let mut lp = Loop {
        sh,
        node,
        inflight: VecDeque::new(),
        inflight_bytes: 0,
        last_rx: Instant::now(),
        probe: None,
        rtt: Latency::default(),
    };
    let mut next_ping = Instant::now();
    let mut seq = 0u64;
    let ping = |seq: &mut u64, head: u64, last_rtt: u64| {
        *seq += 1;
        Msg::Ping(Ping { seq: *seq, sent_us: mono_us(), peer_rtt_us: last_rtt, applied: 0, head })
    };

    loop {
        if kill.load(Ordering::Relaxed) || sh.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let now = Instant::now();
        if now.duration_since(lp.last_rx) > cfg.liveness {
            return Err(Error::Timeout("replica silent"));
        }
        let head_now = sh.head.load(Ordering::Relaxed);

        while let Ok(Cmd::Probe { n, done }) = cmd_rx.try_recv() {
            if lp.probe.is_none() {
                lp.probe = Some(Probe { left: n, outstanding: None, samples: Vec::new(), started: now, done: Some(done) });
            }
        }
        if let Some(p) = &mut lp.probe {
            if p.outstanding.is_none() {
                if p.left == 0 || p.started.elapsed() > Duration::from_secs(10) {
                    if let Some(done) = p.done.take() {
                        let _ = done.send(std::mem::take(&mut p.samples));
                    }
                    lp.probe = None;
                } else {
                    let m = ping(&mut seq, head_now, lp.rtt.last());
                    if let Msg::Ping(pi) = &m {
                        p.outstanding = Some(pi.seq);
                    }
                    p.left -= 1;
                    conn.send(&m).await?;
                }
            } else if p.started.elapsed() > Duration::from_secs(10) {
                p.outstanding = None;
                p.left = 0;
            }
        }
        if now >= next_ping {
            conn.send(&ping(&mut seq, head_now, lp.rtt.last())).await?;
            next_ping = now + cfg.ping_every;
        }

        let mut more = false;
        if lp.inflight_bytes < cfg.window_bytes {
            let from = cursor;
            let max = cfg.batch_bytes;
            match db_call(sh, move |db| db.cdc_read(from, max)).await? {
                CdcRead::Behind => {
                    return Err(refuse(conn, FaultCode::Resync, "change log no longer covers this replica".into()).await);
                }
                CdcRead::Page { txns, last, head } => {
                    sh.head.store(head, Ordering::Relaxed);
                    if last > cursor {
                        let ops: Vec<RawOp> = txns.into_iter().flat_map(|t| t.ops).collect();
                        let bytes: usize = ops.iter().map(RawOp::encoded_len).sum();
                        if bytes > MAX_FRAME_BYTES / 2 {
                            return Err(refuse(conn, FaultCode::Resync, "transaction too large for one batch".into()).await);
                        }
                        let digest = digest_ops(&ops);
                        let n = conn.send(&Msg::Batch(Batch { from: cursor, to: last, head, ops, digest })).await?;
                        if let Some(e) = sh.stats.replicas.lock().get_mut(node) {
                            e.bytes_sent += n as u64;
                            e.batches += 1;
                            e.head = head;
                        }
                        lp.inflight.push_back((last, n, Instant::now()));
                        lp.inflight_bytes += n;
                        cursor = last;
                        more = last < head;
                    } else if let Some(e) = sh.stats.replicas.lock().get_mut(node) {
                        e.head = head;
                    }
                }
            }
        }

        while let Some(m) = conn.try_recv()? {
            if let Some(reply) = lp.on_msg(m)? {
                conn.send(&reply).await?;
            }
        }
        if more {
            continue;
        }
        match ntex::time::timeout(cfg.poll, conn.recv()).await {
            Ok(m) => {
                if let Some(reply) = lp.on_msg(m?)? {
                    conn.send(&reply).await?;
                }
            }
            Err(_) => {}
        }
    }
}

// -- forwarded requests ---------------------------------------------------------------

const HOP_BY_HOP: [&str; 9] = [
    "host", "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
    "content-length",
];

pub(crate) fn skip_header(name: &str) -> bool {
    HOP_BY_HOP.contains(&name) || name.starts_with("x-repl-")
}

fn http_error(id: u64, status: u16, error: String) -> ForwardResp {
    ForwardResp { id, status, headers: Vec::new(), body: Vec::new(), txn: 0, error }
}

async fn execute(sh: &Arc<Shared>, f: Forward) -> ForwardResp {
    let Ok(method) = Method::from_bytes(f.method.as_bytes()) else {
        return http_error(f.id, 400, format!("bad method `{}`", f.method));
    };
    if !f.target.starts_with('/') {
        return http_error(f.id, 400, "target must be a path".into());
    }
    let url = format!("http://{}{}", sh.cfg.local_http, f.target);
    let deadline = Duration::from_millis(u64::from(f.deadline_ms).clamp(100, sh.cfg.forward_timeout.as_millis() as u64));
    let mutating = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);

    // Loopback; a client per call keeps its pool from outliving the runtime.
    let client = ntex::client::Client::new();
    let mut rq = client.request(method, url.as_str());
    for (k, v) in &f.headers {
        if skip_header(k) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_bytes(v)) {
            rq = rq.header(name, value);
        }
    }
    rq = rq.header("x-repl-auth", sh.token.as_str()).header("x-repl-from", f.from_node.as_str());

    let limit = sh.cfg.forward_body_limit;
    let exec = async {
        let resp = rq.send_body(ntex::util::Bytes::from(f.body)).await.map_err(|e| format!("main http: {e}"))?;
        let status = resp.status().as_u16();
        let headers: Headers = resp
            .headers()
            .iter()
            .filter(|(n, _)| !skip_header(n.as_str()))
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect();
        let body = resp.body().limit(limit).await.map_err(|e| format!("main body: {e}"))?;
        Ok::<_, String>((status, headers, body.to_vec()))
    };
    let (status, headers, body) = match ntex::time::timeout(deadline, exec).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return http_error(f.id, 502, e),
        Err(_) => return http_error(f.id, 504, "main node did not answer in time".into()),
    };

    // The write must reach the change stream before the replica waits for it.
    let flush = sh.cfg.flush_on_forward && mutating;
    let txn = db_call(sh, move |db| {
        if flush {
            db.flush_buffers()?;
        }
        db.cdc_head()
    })
    .await
    .unwrap_or(0);
    ForwardResp { id: f.id, status, headers, body, txn, error: String::new() }
}

async fn rpc_session(sh: &Arc<Shared>, mut conn: Conn, hello: Hello) -> Result<(), Error> {
    conn.send(&Msg::Welcome(Welcome {
        node_id: sh.cfg.node_id.clone(),
        stream_id: Vec::new(),
        head: 0,
        mode: Mode::Rpc,
        snapshot_txn: 0,
    }))
    .await?;
    log::debug!("repl[{}]: rpc connection from `{}`", sh.cfg.node_id, hello.node_id);
    loop {
        match conn.recv_timeout(Duration::from_secs(90), "rpc idle").await {
            Ok(Msg::Forward(mut f)) => {
                f.from_node = hello.node_id.clone();
                let resp = execute(sh, f).await;
                conn.send(&Msg::ForwardResp(resp)).await?;
            }
            Ok(Msg::Ping(p)) => {
                conn.send(&Msg::Pong(Pong { seq: p.seq, echo_us: p.sent_us })).await?;
            }
            Ok(other) => return Err(Error::Proto(format!("unexpected {} on rpc connection", other.name()))),
            // Idle or closed: replicas reopen on demand.
            Err(Error::Timeout(_) | Error::Closed) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}
