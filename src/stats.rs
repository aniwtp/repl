//! Latency/lag statistics of the replication links.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;

static START: OnceLock<Instant> = OnceLock::new();

/// Monotonic microseconds since process start (RTT is measured on one clock only).
pub fn mono_us() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_micros() as u64
}

const RING: usize = 128;

/// Round-trip / response-time samples in microseconds.
#[derive(Debug, Clone)]
pub struct Latency {
    count: u64,
    last: u64,
    ewma: f64,
    min: u64,
    max: u64,
    ring: Vec<u64>,
    pos: usize,
}

impl Default for Latency {
    fn default() -> Self {
        Self { count: 0, last: 0, ewma: 0.0, min: u64::MAX, max: 0, ring: Vec::new(), pos: 0 }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct LatencySummary {
    pub count: u64,
    pub last_us: u64,
    pub avg_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
}

impl Latency {
    pub fn record(&mut self, us: u64) {
        self.count += 1;
        self.last = us;
        self.min = self.min.min(us);
        self.max = self.max.max(us);
        self.ewma = if self.count == 1 { us as f64 } else { self.ewma * 0.8 + us as f64 * 0.2 };
        if self.ring.len() < RING {
            self.ring.push(us);
        } else {
            self.ring[self.pos] = us;
            self.pos = (self.pos + 1) % RING;
        }
    }

    pub fn last(&self) -> u64 {
        self.last
    }

    pub fn summary(&self) -> LatencySummary {
        if self.count == 0 {
            return LatencySummary::default();
        }
        let mut s = self.ring.clone();
        s.sort_unstable();
        let pct = |p: usize| s[((s.len() - 1) * p) / 100];
        LatencySummary {
            count: self.count,
            last_us: self.last,
            avg_us: self.ewma as u64,
            min_us: self.min,
            max_us: self.max,
            p50_us: pct(50),
            p95_us: pct(95),
        }
    }
}

/// What the main node knows about one connected replica.
#[derive(Debug, Clone, Serialize)]
pub struct ReplicaStats {
    pub node: String,
    pub connected_secs: u64,
    pub mode: &'static str,
    /// RTT main → replica → main, measured by main (ping/pong).
    pub rtt: LatencySummary,
    /// RTT as measured by the replica itself (reported in its pings).
    pub replica_rtt_us: u64,
    /// Time from sending a batch until its ack arrived (network + apply).
    pub ack: LatencySummary,
    pub applied_txn: u64,
    pub lag_txn: u64,
    pub bytes_sent: u64,
    pub batches: u64,
    pub snapshots: u64,
}

#[derive(Debug, Default)]
pub struct ReplicaEntry {
    pub since: Option<Instant>,
    pub mode: &'static str,
    pub rtt: Latency,
    pub replica_rtt_us: u64,
    pub ack: Latency,
    pub applied: u64,
    pub head: u64,
    pub bytes_sent: u64,
    pub batches: u64,
    pub snapshots: u64,
}

/// Replica-side view of the link to the main node.
#[derive(Debug, Default)]
pub struct LinkEntry {
    pub state: &'static str,
    pub since: Option<Instant>,
    pub rtt: Latency,
    pub apply: Latency,
    pub head: u64,
    pub reconnects: u64,
    pub snapshots: u64,
    pub batches: u64,
    pub bytes_received: u64,
    pub last_error: String,
    pub primary_addr: String,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub replicas: Mutex<HashMap<String, ReplicaEntry>>,
    pub link: Mutex<LinkEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkStats {
    pub state: &'static str,
    pub connected_secs: u64,
    pub main_addr: String,
    pub rtt: LatencySummary,
    pub apply: LatencySummary,
    pub head_txn: u64,
    pub reconnects: u64,
    pub snapshots: u64,
    pub batches: u64,
    pub bytes_received: u64,
    pub last_error: String,
}

impl Stats {
    pub fn replicas_snapshot(&self, applied_head: impl Fn(&ReplicaEntry) -> u64) -> Vec<(String, ReplicaStats)> {
        let map = self.replicas.lock();
        let mut out: Vec<_> = map
            .iter()
            .map(|(node, e)| {
                (
                    node.clone(),
                    ReplicaStats {
                        node: node.clone(),
                        connected_secs: e.since.map_or(0, |t| t.elapsed().as_secs()),
                        mode: e.mode,
                        rtt: e.rtt.summary(),
                        replica_rtt_us: e.replica_rtt_us,
                        ack: e.ack.summary(),
                        applied_txn: e.applied,
                        lag_txn: applied_head(e).saturating_sub(e.applied),
                        bytes_sent: e.bytes_sent,
                        batches: e.batches,
                        snapshots: e.snapshots,
                    },
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn link_snapshot(&self) -> LinkStats {
        let l = self.link.lock();
        LinkStats {
            state: l.state,
            connected_secs: l.since.map_or(0, |t| t.elapsed().as_secs()),
            main_addr: l.primary_addr.clone(),
            rtt: l.rtt.summary(),
            apply: l.apply.summary(),
            head_txn: l.head,
            reconnects: l.reconnects,
            snapshots: l.snapshots,
            batches: l.batches,
            bytes_received: l.bytes_received,
            last_error: l.last_error.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_summary_percentiles_and_ring_wrap() {
        let mut l = Latency::default();
        assert_eq!(l.summary(), LatencySummary::default());
        for us in 1..=200u64 {
            l.record(us * 10);
        }
        let s = l.summary();
        assert_eq!((s.count, s.min_us, s.max_us, s.last_us), (200, 10, 2000, 2000));
        // ring keeps the last 128 samples: 730..=2000
        assert!(s.p50_us > 1300 && s.p50_us < 1400, "{}", s.p50_us);
        assert!(s.p95_us > 1900, "{}", s.p95_us);
    }
}
