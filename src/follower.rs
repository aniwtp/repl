//! Replica: supervisor that keeps one change-stream connection to the main
//! node alive (backoff + jitter), applies batches atomically and resyncs by
//! snapshot when the stream cannot continue.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use db_wrapper::StreamId;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};

use crate::conn::{self, Conn, HANDSHAKE_TIMEOUT};
use crate::msg::*;
use crate::primary::db_call;
use crate::stats::mono_us;
use crate::{Error, Shared};

/// A connection that streamed this long counts as healthy: backoff restarts.
const STABLE_AFTER: Duration = Duration::from_secs(30);
const APPLY_STALL: Duration = Duration::from_secs(30);
const MISMATCH_RETRY: Duration = Duration::from_secs(60);

fn jitter_ms(cap_ms: u64) -> u64 {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).expect("os randomness");
    cap_ms / 2 + u64::from(u32::from_le_bytes(b)) % (cap_ms / 2 + 1)
}

/// `min(30 s, 200 ms · 2^n)` with jitter in `[½, 1]` of that value.
pub(crate) fn backoff(attempt: u32) -> Duration {
    let cap = (200u64 << attempt.min(8)).min(30_000);
    Duration::from_millis(jitter_ms(cap))
}

fn set_state(sh: &Shared, state: &'static str) {
    sh.stats.link.lock().state = state;
}

pub(crate) async fn run(sh: Arc<Shared>) {
    let mut attempt = 0u32;
    while !sh.stop.load(Ordering::Relaxed) {
        let addrs = &sh.cfg.primaries;
        let addr = addrs[sh.primary_idx.load(Ordering::Relaxed) % addrs.len()].clone();
        {
            let mut l = sh.stats.link.lock();
            l.state = "connecting";
            l.primary_addr = addr.clone();
        }
        let started = Instant::now();
        let res = session(&sh, &addr).await;
        let mismatch = matches!(&res, Err(Error::Fault { code: FaultCode::VersionMismatch, .. }));
        {
            let mut l = sh.stats.link.lock();
            l.reconnects += 1;
            l.since = None;
            l.state = "backoff";
            match &res {
                Ok(()) => log::info!("repl[{}]: link to {addr} closed", sh.cfg.node_id),
                Err(e) => {
                    log::warn!("repl[{}]: link to {addr}: {e}", sh.cfg.node_id);
                    l.last_error = e.to_string();
                }
            }
        }
        attempt = if started.elapsed() >= STABLE_AFTER { 0 } else { attempt.saturating_add(1) };
        if res.is_err() {
            sh.primary_idx.fetch_add(1, Ordering::Relaxed);
        }
        let delay = if mismatch { MISMATCH_RETRY } else { backoff(attempt) };
        ntex::time::sleep(delay).await;
    }
}

enum RestoreMsg {
    Rows(String, Vec<(Vec<u8>, Vec<u8>)>),
    Commit { txn: u64 },
}

async fn session(sh: &Arc<Shared>, addr: &str) -> Result<(), Error> {
    let tls = sh.tls_client.as_ref().expect("follower tls");
    let mut conn = conn::connect(addr, tls).await?;

    let resync = sh.force_snapshot.swap(false, Ordering::Relaxed);
    let (stream_id, applied) = if resync {
        (Vec::new(), 0)
    } else {
        ((*sh.stream_id.lock()).map(|s| s.to_vec()).unwrap_or_default(), sh.applied.load(Ordering::Relaxed))
    };
    conn.send(&Msg::Hello(Hello {
        proto: PROTO,
        node_id: sh.cfg.node_id.clone(),
        schema: sh.cfg.schema,
        kind: Kind::Stream,
        stream_id,
        applied,
    }))
    .await?;
    let welcome = match conn.recv_timeout(HANDSHAKE_TIMEOUT, "welcome").await? {
        Msg::Welcome(w) => w,
        Msg::Fault(f) => return Err(Error::Fault { code: f.code, msg: f.msg }),
        other => return Err(Error::Proto(format!("expected welcome, got {}", other.name()))),
    };
    {
        let mut l = sh.stats.link.lock();
        l.since = Some(Instant::now());
        l.head = welcome.head;
    }
    sh.head.fetch_max(welcome.head, Ordering::Relaxed);
    match welcome.mode {
        Mode::Snapshot => receive_snapshot(sh, &mut conn, &welcome).await?,
        Mode::Stream => {}
        Mode::Rpc => return Err(Error::Proto("stream connection answered with rpc mode".into())),
    }
    set_state(sh, "streaming");
    stream_loop(sh, conn).await
}

async fn receive_snapshot(sh: &Arc<Shared>, conn: &mut Conn, w: &Welcome) -> Result<(), Error> {
    set_state(sh, "snapshot");
    let stream: StreamId =
        w.stream_id.as_slice().try_into().map_err(|_| Error::Proto("stream id must be 16 bytes".into()))?;
    let (mut tx, mut rx) = mpsc::channel::<RestoreMsg>(4);
    let db = sh.db().clone();
    let job = ntex::rt::spawn_blocking(move || -> Result<(), Error> {
        let mut restore = db.repl_restore()?;
        loop {
            match futures::executor::block_on(rx.next()) {
                Some(RestoreMsg::Rows(table, rows)) => restore.put(&table, &rows)?,
                Some(RestoreMsg::Commit { txn }) => {
                    restore.commit(stream, txn)?;
                    return Ok(());
                }
                // Connection dropped mid-snapshot: nothing was committed.
                None => return Err(Error::Proto("snapshot aborted".into())),
            }
        }
    });

    let mut hasher = blake3::Hasher::new();
    let mut entries = 0u64;
    let end = loop {
        match conn.recv_timeout(Duration::from_secs(30), "snapshot chunk").await? {
            Msg::Chunk(c) => {
                for (k, v) in &c.entries {
                    feed_row(&mut hasher, &c.table, k, Some(v));
                }
                entries += c.entries.len() as u64;
                if tx.send(RestoreMsg::Rows(c.table, c.entries)).await.is_err() {
                    // The restore thread stopped: its error is the cause.
                    return match job.await {
                        Ok(Err(e)) => Err(e),
                        _ => Err(Error::Proto("restore thread died".into())),
                    };
                }
            }
            Msg::SnapEnd(e) => break e,
            Msg::Fault(f) => return Err(Error::Fault { code: f.code, msg: f.msg }),
            Msg::Ping(p) => conn.send(&Msg::Pong(Pong { seq: p.seq, echo_us: p.sent_us })).await.map(|_| ())?,
            other => return Err(Error::Proto(format!("unexpected {} during snapshot", other.name()))),
        }
    };
    let tables = sh.db().replicated_tables().len() as u32;
    if end.txn != w.snapshot_txn
        || end.entries != entries
        || end.digest != *hasher.finalize().as_bytes()
        || end.tables != tables
    {
        // Dropping `tx` aborts the restore transaction; the old data stays.
        return Err(Error::Proto(format!(
            "snapshot verification failed (entries {}/{}, tables {}/{})",
            entries, end.entries, tables, end.tables
        )));
    }
    if tx.send(RestoreMsg::Commit { txn: end.txn }).await.is_err() {
        return match job.await {
            Ok(Err(e)) => Err(e),
            _ => Err(Error::Proto("restore thread died".into())),
        };
    }
    match job.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(Error::Proto("restore thread failed".into())),
    }
    *sh.stream_id.lock() = Some(stream);
    sh.applied.store(end.txn, Ordering::Relaxed);
    sh.head.fetch_max(end.txn, Ordering::Relaxed);
    sh.stats.link.lock().snapshots += 1;
    log::info!("repl[{}]: snapshot applied at txn {} ({} rows)", sh.cfg.node_id, end.txn, entries);
    Ok(())
}

async fn stream_loop(sh: &Arc<Shared>, mut conn: Conn) -> Result<(), Error> {
    let cfg = &sh.cfg;
    let mut last_rx = Instant::now();
    let mut next_ping = Instant::now();
    let mut seq = 0u64;
    let mut stalled_since: Option<Instant> = None;
    let mut apply_failures = 0u32;
    let mut last_applied = sh.applied.load(Ordering::Relaxed);

    loop {
        if sh.stop.load(Ordering::Relaxed) {
            conn.close().await;
            return Ok(());
        }
        let now = Instant::now();
        if now.duration_since(last_rx) > cfg.liveness {
            return Err(Error::Timeout("main node silent"));
        }
        let applied = sh.applied.load(Ordering::Relaxed);
        let head = sh.head.load(Ordering::Relaxed);
        if applied != last_applied || head <= applied {
            last_applied = applied;
            stalled_since = None;
        } else if now.duration_since(*stalled_since.get_or_insert(now)) > APPLY_STALL {
            return Err(Error::Timeout("apply stalled behind main"));
        }
        if now >= next_ping {
            seq += 1;
            let rtt = sh.stats.link.lock().rtt.last();
            conn.send(&Msg::Ping(Ping { seq, sent_us: mono_us(), peer_rtt_us: rtt, applied, head })).await?;
            next_ping = now + cfg.ping_every;
        }

        let msg = match ntex::time::timeout(Duration::from_millis(500), conn.recv()).await {
            Ok(m) => m?,
            Err(_) => continue,
        };
        last_rx = Instant::now();
        match msg {
            Msg::Batch(b) => {
                if b.from != applied {
                    return Err(Error::Proto(format!("gap in change stream: have {applied}, batch starts at {}", b.from)));
                }
                let stream = (*sh.stream_id.lock()).ok_or_else(|| Error::Proto("no stream id".into()))?;
                let (to, digest, ops) = (b.to, b.digest, b.ops);
                let n_ops = ops.len();
                let t0 = Instant::now();
                let res = db_call(sh, move |db| {
                    if digest_ops(&ops) != digest {
                        return Err(db_wrapper::DbError::Replication("batch digest mismatch".into()));
                    }
                    db.repl_apply(stream, &ops, to)
                })
                .await;
                if let Err(e) = res {
                    apply_failures += 1;
                    if apply_failures >= 3 {
                        sh.force_snapshot.store(true, Ordering::Relaxed);
                    }
                    return Err(e);
                }
                apply_failures = 0;
                let apply_us = t0.elapsed().as_micros() as u64;
                sh.applied.store(to, Ordering::Relaxed);
                sh.head.fetch_max(b.head, Ordering::Relaxed);
                {
                    let mut l = sh.stats.link.lock();
                    l.apply.record(apply_us);
                    l.batches += 1;
                    l.head = l.head.max(b.head);
                    l.bytes_received += (n_ops * 32) as u64;
                }
                conn.send(&Msg::Ack(Ack { txn: to, apply_us })).await?;
            }
            Msg::Ping(p) => {
                sh.head.fetch_max(p.head, Ordering::Relaxed);
                sh.stats.link.lock().head = sh.head.load(Ordering::Relaxed);
                conn.send(&Msg::Pong(Pong { seq: p.seq, echo_us: p.sent_us })).await?;
            }
            Msg::Pong(p) => {
                sh.stats.link.lock().rtt.record(mono_us().saturating_sub(p.echo_us));
            }
            Msg::Fault(f) => {
                if f.code == FaultCode::Resync {
                    sh.force_snapshot.store(true, Ordering::Relaxed);
                }
                return Err(Error::Fault { code: f.code, msg: f.msg });
            }
            other => return Err(Error::Proto(format!("unexpected {} in change stream", other.name()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::backoff;
    use std::time::Duration;

    #[test]
    fn backoff_grows_is_capped_and_jittered() {
        for _ in 0..50 {
            let first = backoff(0);
            assert!(first >= Duration::from_millis(100) && first <= Duration::from_millis(200), "{first:?}");
            let capped = backoff(30);
            assert!(capped >= Duration::from_secs(15) && capped <= Duration::from_secs(30), "{capped:?}");
        }
    }
}
