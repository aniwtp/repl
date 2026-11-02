//! Replica → main request forwarding over pinned TLS (`rpc` connections).
//!
//! Connections are per-thread (ntex workers each run their own runtime) and
//! pooled. A request is retried on a fresh connection **only** if writing it
//! to a pooled (possibly stale) connection failed — after that point the main
//! node may already have executed it, and mutations are not replayed.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::conn::{self, Conn, HANDSHAKE_TIMEOUT, with_timeout};
use crate::msg::*;
use crate::{Error, Role, Shared};

#[derive(Debug, Clone, Default)]
pub struct ForwardRequest {
    pub method: String,
    /// Path and query, e.g. `/v1/title/5?x=1`.
    pub target: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// `None` = the configured forward timeout.
    pub deadline: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct ForwardResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// Main node's change-log position after the request: wait for it with
    /// `Repl::wait_applied` to read your own write on this replica.
    pub txn: u64,
}

const IDLE_MAX: usize = 8;
const IDLE_TTL: Duration = Duration::from_secs(20);

thread_local! {
    static IDLE: RefCell<Vec<(Conn, Instant)>> = const { RefCell::new(Vec::new()) };
}

fn take_idle() -> Option<Conn> {
    IDLE.with(|p| {
        let mut p = p.borrow_mut();
        while let Some((c, at)) = p.pop() {
            if at.elapsed() < IDLE_TTL {
                return Some(c);
            }
        }
        None
    })
}

fn put_idle(c: Conn) {
    IDLE.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < IDLE_MAX {
            p.push((c, Instant::now()));
        }
    });
}

async fn connect_rpc(sh: &Arc<Shared>) -> Result<Conn, Error> {
    let tls = sh.tls_client.as_ref().expect("follower tls");
    let n = sh.cfg.primaries.len();
    let start = sh.primary_idx.load(Ordering::Relaxed);
    let mut last = Error::Closed;
    for i in 0..n {
        let addr = &sh.cfg.primaries[(start + i) % n];
        match connect_one(sh, addr, tls).await {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn connect_one(sh: &Arc<Shared>, addr: &str, tls: &Arc<rustls::ClientConfig>) -> Result<Conn, Error> {
    let mut c = conn::connect(addr, tls).await?;
    c.send(&Msg::Hello(Hello {
        proto: PROTO,
        node_id: sh.cfg.node_id.clone(),
        schema: sh.cfg.schema,
        kind: Kind::Rpc,
        stream_id: Vec::new(),
        applied: 0,
    }))
    .await?;
    match c.recv_timeout(HANDSHAKE_TIMEOUT, "welcome").await? {
        Msg::Welcome(w) if w.mode == Mode::Rpc => Ok(c),
        Msg::Fault(f) => Err(Error::Fault { code: f.code, msg: f.msg }),
        other => Err(Error::Proto(format!("expected rpc welcome, got {}", other.name()))),
    }
}

pub(crate) async fn call(sh: &Arc<Shared>, req: ForwardRequest) -> Result<ForwardResponse, Error> {
    if sh.cfg.role != Role::Follower {
        return Err(Error::Config("forward is only available on a replica".into()));
    }
    let deadline = req.deadline.unwrap_or(sh.cfg.forward_timeout);
    let id = sh.rpc_seq.fetch_add(1, Ordering::Relaxed);
    let msg = Msg::Forward(Forward {
        id,
        method: req.method,
        target: req.target,
        headers: req.headers,
        body: req.body,
        deadline_ms: deadline.as_millis().min(u128::from(u32::MAX)) as u32,
        from_node: sh.cfg.node_id.clone(),
    });

    let (mut conn, reused) = match take_idle() {
        Some(c) => (c, true),
        None => (connect_rpc(sh).await?, false),
    };
    if let Err(e) = conn.send(&msg).await {
        if !reused {
            return Err(e);
        }
        conn = connect_rpc(sh).await?;
        conn.send(&msg).await?;
    }
    // Slack over the main node's own deadline so its 504 reaches us first.
    let resp = with_timeout(deadline + Duration::from_secs(2), "forward response", conn.recv()).await?;
    match resp {
        Msg::ForwardResp(r) if r.id == id => {
            put_idle(conn);
            if !r.error.is_empty() {
                return Err(Error::Proto(format!("main node: {} ({})", r.error, r.status)));
            }
            Ok(ForwardResponse { status: r.status, headers: r.headers, body: r.body, txn: r.txn })
        }
        Msg::Fault(f) => Err(Error::Fault { code: f.code, msg: f.msg }),
        other => Err(Error::Proto(format!("unexpected {} for forward {id}", other.name()))),
    }
}
