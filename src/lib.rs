//! Read-only replication for redb-backed services.
//!
//! * One **main** node (primary) writes; **replicas** (followers) pull its
//!   committed changes (CDC) over capnp frames on TCP + TLS 1.3 with
//!   self-signed, pinned certificates, and serve reads locally.
//! * Replicas are also **proxies**: a mutating HTTP request is forwarded to
//!   the main node (over the same pinned TLS), the replica waits for the main
//!   node's answer and — before replying — for its own copy to catch up with
//!   the write. Handlers that do expensive pre-checks (upload validation, S3)
//!   can run them on the replica and delegate only the database write with
//!   [`web::forward_request`].
//! * Link health is measured continuously (RTT, ack latency, lag) and exposed
//!   by [`Repl::stats`] / `GET /repl/stats`.
//!
//! Wiring in a service: open the database with [`open_db`], register **all**
//! tables, then `Repl::start(cfg, &db).await`; add `repl.gate()` as the
//! first (outermost) middleware, before XOR. Only the main node runs
//! migrations, background jobs and any other writer.

#[allow(dead_code, clippy::all)]
mod repl_capnp {
    include!(concat!(env!("OUT_DIR"), "/repl_capnp.rs"));
}

mod config;
mod conn;
mod error;
mod follower;
mod forward;
pub mod msg;
mod primary;
mod stats;
pub mod tls;
pub mod web;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use db_wrapper::{CommitPolicy, DBWrapper, StreamId};
use futures::channel::{mpsc, oneshot};
use parking_lot::Mutex;
use serde_json::{Value, json};

pub use config::{Config, Role};
pub use error::Error;
pub use forward::{ForwardRequest, ForwardResponse};
pub use stats::{LatencySummary, Stats};

/// Open the service database for the configured role: the main node needs the
/// CDC log, everything else opens it the usual way.
pub fn open_db(
    cfg: Option<&Config>,
    path: &str,
    policy: CommitPolicy,
    cache_bytes: Option<usize>,
) -> Result<DBWrapper, db_wrapper::DbError> {
    match (cfg, cache_bytes) {
        (Some(c), _) if c.role == Role::Primary => DBWrapper::with_cdc(path, policy, cache_bytes, c.cdc_retention),
        (_, Some(bytes)) => DBWrapper::with_cache_size(path, policy, bytes),
        (_, None) => DBWrapper::with_commit_policy(path, policy),
    }
}

pub(crate) enum Cmd {
    /// Send `n` extra pings and report the measured round trips (µs).
    Probe { n: u32, done: oneshot::Sender<Vec<u64>> },
}

pub(crate) struct ConnHandle {
    pub id: u64,
    pub kill: Arc<AtomicBool>,
    pub cmd: mpsc::UnboundedSender<Cmd>,
}

pub(crate) struct Shared {
    pub cfg: Config,
    pub db: Option<DBWrapper>,
    pub stats: Stats,
    /// Replica: last applied main-node transaction. Main: unused.
    pub applied: AtomicU64,
    /// Newest main-node transaction seen.
    pub head: AtomicU64,
    pub stream_id: Mutex<Option<StreamId>>,
    /// Secret known only to this (main) process: proves a request came through
    /// the forward executor, never from a client.
    pub token: String,
    pub tls_server: Option<Arc<rustls::ServerConfig>>,
    pub tls_client: Option<Arc<rustls::ClientConfig>>,
    pub conns: Mutex<HashMap<String, ConnHandle>>,
    pub conn_seq: AtomicU64,
    pub snapshots_active: AtomicUsize,
    pub primary_idx: AtomicUsize,
    /// Replica: the next connection must resync by snapshot.
    pub force_snapshot: AtomicBool,
    pub rpc_seq: AtomicU64,
    pub stop: AtomicBool,
}

impl Shared {
    pub fn db(&self) -> &DBWrapper {
        self.db.as_ref().expect("replication role without database")
    }
}

/// Cheap clonable handle; `Send + Sync`, usable from every ntex worker.
#[derive(Clone)]
pub struct Repl {
    sh: Arc<Shared>,
}

fn random_token() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("os randomness");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Repl {
    /// Replication off: this node is the only writer (all checks pass through).
    pub fn standalone() -> Self {
        Self::build(Config::new(Role::Standalone, "standalone", 0), None, None)
    }

    fn build(cfg: Config, db: Option<DBWrapper>, tls: Option<(Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>)>) -> Self {
        let (tls_server, tls_client) = tls.map_or((None, None), |(s, c)| (Some(s), Some(c)));
        Self {
            sh: Arc::new(Shared {
                cfg,
                db,
                stats: Stats::default(),
                applied: AtomicU64::new(0),
                head: AtomicU64::new(0),
                stream_id: Mutex::new(None),
                token: random_token(),
                tls_server,
                tls_client,
                conns: Mutex::new(HashMap::new()),
                conn_seq: AtomicU64::new(0),
                snapshots_active: AtomicUsize::new(0),
                primary_idx: AtomicUsize::new(0),
                force_snapshot: AtomicBool::new(false),
                rpc_seq: AtomicU64::new(1),
                stop: AtomicBool::new(false),
            }),
        }
    }

    /// Start replication in the current ntex runtime. Call after **all**
    /// tables are registered on `db` and (main node only) migrations ran.
    /// `None` config = standalone.
    pub async fn start(cfg: Option<Config>, db: &DBWrapper) -> Result<Self, Error> {
        let Some(cfg) = cfg else {
            return Ok(Self::standalone());
        };
        if cfg.role == Role::Standalone {
            return Ok(Self::standalone());
        }
        let missing = db.unregistered_tables()?;
        if !missing.is_empty() {
            return Err(Error::Config(format!(
                "tables not registered with the DBWrapper (they would not replicate): {}",
                missing.join(", ")
            )));
        }
        let identity = tls::Identity::load(&cfg.cert_path, &cfg.key_path)?;
        if !cfg.peers.contains_pin(&identity.pin()) {
            return Err(Error::Config(format!(
                "own certificate pin {} is not in REPL_PEERS",
                tls::pin_hex(&identity.pin())
            )));
        }
        let tls = tls::configs(&identity, &cfg.peers)?;
        let repl = Self::build(cfg, Some(db.clone()), Some(tls));
        let sh = repl.sh.clone();
        match sh.cfg.role {
            Role::Primary => {
                let id = sh.db().repl_stream_id()?;
                *sh.stream_id.lock() = Some(id);
                sh.head.store(sh.db().cdc_head()?, Ordering::Relaxed);
                primary::listen(sh).await?;
            }
            Role::Follower => {
                let st = sh.db().repl_state()?;
                sh.applied.store(st.applied, Ordering::Relaxed);
                *sh.stream_id.lock() = st.stream;
                // Tasks stay alive after the handle drops (cancel_on_drop is off); stopped via `stop`.
                drop(ntex::rt::spawn(follower::run(sh)));
            }
            Role::Standalone => unreachable!(),
        }
        Ok(repl)
    }

    pub fn role(&self) -> Role {
        self.sh.cfg.role
    }

    pub fn node_id(&self) -> &str {
        &self.sh.cfg.node_id
    }

    /// True on the node that may write (main node or a standalone service).
    /// Migrations, background jobs, seeders, GC — everything that writes
    /// outside request handling — must be gated on this.
    pub fn is_primary(&self) -> bool {
        self.sh.cfg.role != Role::Follower
    }

    pub fn is_replica(&self) -> bool {
        self.sh.cfg.role == Role::Follower
    }

    /// Replica: last main-node transaction applied locally.
    pub fn applied_txn(&self) -> u64 {
        self.sh.applied.load(Ordering::Relaxed)
    }

    /// Wait until the local copy reached `txn` (read-your-writes). `false` on timeout.
    pub async fn wait_applied(&self, txn: u64, timeout: Duration) -> bool {
        if !self.is_replica() {
            return true;
        }
        let deadline = Instant::now() + timeout;
        while self.applied_txn() < txn {
            if Instant::now() >= deadline {
                return false;
            }
            ntex::time::sleep(Duration::from_millis(5)).await;
        }
        true
    }

    /// Constant-time check of the `x-repl-key` value for the `/repl/*` endpoints.
    pub fn api_key_ok(&self, given: &str) -> bool {
        self.sh.cfg.api_key.as_deref().is_some_and(|k| ct_eq(k.as_bytes(), given.as_bytes()))
    }

    /// True if `token` (the `x-repl-auth` header) was injected by this main
    /// node's forward executor: the request came from a replica, not a client.
    pub fn is_trusted(&self, token: &str) -> bool {
        self.sh.cfg.role == Role::Primary && ct_eq(self.sh.token.as_bytes(), token.as_bytes())
    }

    pub fn config(&self) -> &Config {
        &self.sh.cfg
    }

    /// Replica → main: run an HTTP request on the main node and return its response.
    pub async fn forward(&self, req: ForwardRequest) -> Result<ForwardResponse, Error> {
        forward::call(&self.sh, req).await
    }

    /// Main node: drop the connection of `node` (it reconnects on its own).
    pub fn disconnect(&self, node: &str) -> bool {
        self.sh.conns.lock().get(node).map(|h| h.kill.store(true, Ordering::Relaxed)).is_some()
    }

    /// Stop background tasks (they exit at the next tick).
    pub fn shutdown(&self) {
        self.sh.stop.store(true, Ordering::Relaxed);
        for h in self.sh.conns.lock().values() {
            h.kill.store(true, Ordering::Relaxed);
        }
    }

    /// Statistics of every replica link as JSON. On the main node: all
    /// connected replicas with RTT measured by main and by the replica, ack
    /// latency, lag; on a replica: its view of the link to main.
    pub async fn stats(&self) -> Value {
        let sh = &self.sh;
        let mut out = json!({ "node": sh.cfg.node_id, "role": sh.cfg.role.as_str() });
        match sh.cfg.role {
            Role::Primary => {
                let head = match sh.db.clone() {
                    Some(db) => ntex::rt::spawn_blocking(move || db.cdc_head()).await.ok().and_then(Result::ok).unwrap_or(0),
                    None => 0,
                };
                sh.head.store(head, Ordering::Relaxed);
                let replicas: Vec<_> = sh.stats.replicas_snapshot(|_| head).into_iter().map(|(_, r)| r).collect();
                out["head_txn"] = json!(head);
                out["replicas"] = json!(replicas);
            }
            Role::Follower => {
                let applied = self.applied_txn();
                let link = sh.stats.link_snapshot();
                out["applied_txn"] = json!(applied);
                out["head_txn"] = json!(link.head_txn);
                out["lag_txn"] = json!(link.head_txn.saturating_sub(applied));
                out["main"] = json!(link);
            }
            Role::Standalone => {}
        }
        out
    }

    /// Main node: actively measure every connected replica with `n` extra
    /// pings (fresh samples instead of the rolling ones). Returns per-replica
    /// round-trip statistics in microseconds.
    pub async fn probe(&self, n: u32) -> Value {
        let n = n.clamp(1, 100);
        let handles: Vec<(String, mpsc::UnboundedSender<Cmd>)> =
            self.sh.conns.lock().iter().map(|(k, h)| (k.clone(), h.cmd.clone())).collect();
        let mut waits = Vec::new();
        for (node, cmd) in handles {
            let (done, rx) = oneshot::channel();
            if cmd.unbounded_send(Cmd::Probe { n, done }).is_ok() {
                waits.push((node, rx));
            }
        }
        let mut out = Vec::new();
        for (node, rx) in waits {
            let samples = match ntex::time::timeout(Duration::from_secs(10), rx).await {
                Ok(Ok(s)) => s,
                _ => Vec::new(),
            };
            let mut l = stats::Latency::default();
            samples.iter().for_each(|s| l.record(*s));
            out.push(json!({ "node": node, "sent": n, "received": samples.len(), "rtt": l.summary() }));
        }
        json!({ "node": self.sh.cfg.node_id, "probes": out })
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
