//! Replication settings (environment-driven, `REPL_*`).

use std::time::Duration;

use crate::Error;
use crate::tls::Peers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Replication disabled: this node owns its data and writes locally.
    Standalone,
    /// Main node: the only writer; serves the change stream and forwarded requests.
    Primary,
    /// Read-only replica: follows the main node, forwards writes to it.
    Follower,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Standalone => "standalone",
            Role::Primary => "primary",
            Role::Follower => "follower",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub role: Role,
    pub node_id: String,
    /// Primary: address to listen on for replicas.
    pub bind: String,
    /// Follower: main node addresses (tried in order, rotated on failure).
    pub primaries: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    /// Allowlist of all cluster nodes (name → certificate pin).
    pub peers: Peers,
    /// Data-format generation. Replicas with a different value are refused:
    /// bump it with every breaking change of the stored formats.
    pub schema: u32,
    /// Primary: where forwarded HTTP requests are executed (own HTTP listener).
    pub local_http: String,
    /// Key (`x-repl-key`) for `/repl/stats`; the endpoints are off without it.
    pub api_key: Option<String>,
    /// Primary: CDC log retention in transactions.
    pub cdc_retention: u64,
    pub poll: Duration,
    pub batch_bytes: usize,
    pub window_bytes: usize,
    pub snapshot_chunk_bytes: usize,
    pub max_replicas: usize,
    pub max_snapshots: usize,
    pub ping_every: Duration,
    pub liveness: Duration,
    /// Primary: flush the write buffers after a forwarded request so its
    /// effects reach the change stream immediately.
    pub flush_on_forward: bool,
    pub forward_timeout: Duration,
    pub forward_body_limit: usize,
    /// Replica: how long a forwarded write waits for its effects to be applied locally.
    pub wait_applied: Duration,
}

impl Config {
    pub fn new(role: Role, node_id: &str, schema: u32) -> Self {
        Self {
            role,
            node_id: node_id.to_owned(),
            bind: String::new(),
            primaries: Vec::new(),
            cert_path: String::new(),
            key_path: String::new(),
            peers: Peers::default(),
            schema,
            local_http: String::new(),
            api_key: None,
            cdc_retention: 100_000,
            poll: Duration::from_millis(100),
            batch_bytes: 4 << 20,
            window_bytes: 16 << 20,
            snapshot_chunk_bytes: 2 << 20,
            max_replicas: 16,
            max_snapshots: 2,
            ping_every: Duration::from_secs(2),
            liveness: Duration::from_secs(15),
            flush_on_forward: true,
            forward_timeout: Duration::from_secs(30),
            forward_body_limit: 16 << 20,
            wait_applied: Duration::from_secs(2),
        }
    }

    /// `None` when `REPL_ROLE` is unset (replication off).
    pub fn from_env(schema: u32) -> Result<Option<Self>, Error> {
        Self::from_vars(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()), schema)
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<String>, schema: u32) -> Result<Option<Self>, Error> {
        let Some(role) = get("REPL_ROLE") else {
            return Ok(None);
        };
        let role = match role.trim() {
            "primary" => Role::Primary,
            "follower" => Role::Follower,
            other => return Err(Error::Config(format!("REPL_ROLE={other}: expected primary|follower"))),
        };
        let need = |k: &str| get(k).ok_or_else(|| Error::Config(format!("{k} is required for REPL_ROLE={}", role.as_str())));
        let mut c = Config::new(role, &need("REPL_NODE_ID")?, schema);
        c.cert_path = need("REPL_CERT")?;
        c.key_path = need("REPL_KEY")?;
        c.peers = Peers::parse(&need("REPL_PEERS")?)?;
        if !c.peers.contains_name(&c.node_id) {
            return Err(Error::Config(format!("REPL_NODE_ID={} is not listed in REPL_PEERS", c.node_id)));
        }
        match role {
            Role::Primary => {
                c.bind = need("REPL_BIND")?;
                c.local_http = need("REPL_LOCAL_HTTP")?;
            }
            _ => {
                c.primaries = need("REPL_PRIMARY")?.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
            }
        }
        c.api_key = get("REPL_API_KEY");
        let num = |k: &str, d: u64| -> Result<u64, Error> {
            get(k).map_or(Ok(d), |v| v.trim().parse().map_err(|_| Error::Config(format!("{k}={v}: not a number"))))
        };
        c.cdc_retention = num("REPL_CDC_RETENTION", c.cdc_retention)?;
        c.poll = Duration::from_millis(num("REPL_POLL_MS", 100)?.max(10));
        c.max_replicas = num("REPL_MAX_REPLICAS", c.max_replicas as u64)? as usize;
        c.flush_on_forward = num("REPL_FLUSH_ON_FORWARD", 1)? != 0;
        c.forward_timeout = Duration::from_secs(num("REPL_FORWARD_TIMEOUT_SECS", 30)?);
        c.wait_applied = Duration::from_millis(num("REPL_WAIT_APPLIED_MS", 2000)?);
        Ok(Some(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn unset_role_disables_replication() {
        assert!(Config::from_vars(vars(&[]), 1).unwrap().is_none());
    }

    #[test]
    fn follower_requires_primary_and_known_node_id() {
        let pin = format!("sha256:{}", "ab".repeat(32));
        let peers = format!("n1={pin},n2={pin}");
        let ok = [
            ("REPL_ROLE", "follower"),
            ("REPL_NODE_ID", "n2"),
            ("REPL_CERT", "c"),
            ("REPL_KEY", "k"),
            ("REPL_PEERS", peers.as_str()),
            ("REPL_PRIMARY", "main:9500, main2:9500"),
        ];
        let c = Config::from_vars(vars(&ok), 3).unwrap().unwrap();
        assert_eq!((c.role, c.schema, c.primaries.len()), (Role::Follower, 3, 2));
        let mut bad = ok.to_vec();
        bad[1] = ("REPL_NODE_ID", "n9");
        assert!(Config::from_vars(vars(&bad), 3).is_err());
        let bad: Vec<_> = ok.iter().filter(|(k, _)| *k != "REPL_PRIMARY").cloned().collect();
        assert!(Config::from_vars(vars(&bad), 3).is_err());
    }
}
