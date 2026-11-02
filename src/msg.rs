//! Wire messages (`capnp/repl.capnp`) as plain Rust types, their capnp codec
//! and stream framing. One frame = one capnp message.

use capnp::message::{Builder, ReaderOptions};
use db_wrapper::RawOp;
use futures::io::{AsyncRead, AsyncWrite};

use crate::Error;

use crate::repl_capnp::{fault, hello, msg, welcome};

pub const PROTO: u16 = 1;

/// Hard bound for one frame (also the capnp traversal limit): protects both
/// ends from absurd allocations by a misbehaving peer.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stream,
    Rpc,
}

#[derive(Debug, Clone)]
pub struct Hello {
    pub proto: u16,
    pub node_id: String,
    pub schema: u32,
    pub kind: Kind,
    pub stream_id: Vec<u8>,
    pub applied: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Stream,
    Snapshot,
    Rpc,
}

#[derive(Debug, Clone)]
pub struct Welcome {
    pub node_id: String,
    pub stream_id: Vec<u8>,
    pub head: u64,
    pub mode: Mode,
    pub snapshot_txn: u64,
}

#[derive(Debug, Clone)]
pub struct Batch {
    pub from: u64,
    pub to: u64,
    pub head: u64,
    pub ops: Vec<RawOp>,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub table: String,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct SnapEnd {
    pub txn: u64,
    pub tables: u32,
    pub entries: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct Ack {
    pub txn: u64,
    pub apply_us: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Ping {
    pub seq: u64,
    pub sent_us: u64,
    pub peer_rtt_us: u64,
    pub applied: u64,
    pub head: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Pong {
    pub seq: u64,
    pub echo_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCode {
    VersionMismatch,
    Unauthorized,
    Busy,
    Resync,
    Internal,
}

#[derive(Debug, Clone)]
pub struct Fault {
    pub code: FaultCode,
    pub msg: String,
}

pub type Headers = Vec<(String, Vec<u8>)>;

#[derive(Debug, Clone)]
pub struct Forward {
    pub id: u64,
    pub method: String,
    pub target: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub deadline_ms: u32,
    pub from_node: String,
}

#[derive(Debug, Clone)]
pub struct ForwardResp {
    pub id: u64,
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub txn: u64,
    pub error: String,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Hello(Hello),
    Welcome(Welcome),
    Batch(Batch),
    Chunk(Chunk),
    SnapEnd(SnapEnd),
    Ack(Ack),
    Ping(Ping),
    Pong(Pong),
    Fault(Fault),
    Forward(Forward),
    ForwardResp(ForwardResp),
}

impl Msg {
    pub fn name(&self) -> &'static str {
        match self {
            Msg::Hello(_) => "hello",
            Msg::Welcome(_) => "welcome",
            Msg::Batch(_) => "batch",
            Msg::Chunk(_) => "chunk",
            Msg::SnapEnd(_) => "snap_end",
            Msg::Ack(_) => "ack",
            Msg::Ping(_) => "ping",
            Msg::Pong(_) => "pong",
            Msg::Fault(_) => "fault",
            Msg::Forward(_) => "forward",
            Msg::ForwardResp(_) => "forward_resp",
        }
    }
}

// -- digests -----------------------------------------------------------------

/// blake3 over the ops of a batch; both ends compute it with this function.
pub fn digest_ops(ops: &[RawOp]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for op in ops {
        feed_row(&mut h, &op.table, &op.key, op.value.as_deref());
    }
    *h.finalize().as_bytes()
}

/// Feed one row into a rolling digest (snapshot digest and batch digest).
pub fn feed_row(h: &mut blake3::Hasher, table: &str, key: &[u8], value: Option<&[u8]>) {
    h.update(&(table.len() as u32).to_le_bytes());
    h.update(table.as_bytes());
    h.update(&(key.len() as u32).to_le_bytes());
    h.update(key);
    match value {
        Some(v) => {
            h.update(&[1]);
            h.update(&(v.len() as u32).to_le_bytes());
            h.update(v);
        }
        None => {
            h.update(&[0]);
        }
    }
}

// -- encode --------------------------------------------------------------------

fn put_headers(mut list: capnp::struct_list::Builder<'_, crate::repl_capnp::header::Owned>, headers: &Headers) {
    for (i, (name, value)) in headers.iter().enumerate() {
        let mut h = list.reborrow().get(i as u32);
        h.set_name(name);
        h.set_value(value);
    }
}

pub fn encode(m: &Msg) -> Builder<capnp::message::HeapAllocator> {
    let mut message = Builder::new_default();
    let root = message.init_root::<msg::Builder<'_>>();
    match m {
        Msg::Hello(v) => {
            let mut b = root.init_hello();
            b.set_proto(v.proto);
            b.set_node_id(&v.node_id);
            b.set_schema(v.schema);
            b.set_kind(match v.kind {
                Kind::Stream => hello::Kind::Stream,
                Kind::Rpc => hello::Kind::Rpc,
            });
            b.set_stream_id(&v.stream_id);
            b.set_applied_txn(v.applied);
        }
        Msg::Welcome(v) => {
            let mut b = root.init_welcome();
            b.set_node_id(&v.node_id);
            b.set_stream_id(&v.stream_id);
            b.set_head_txn(v.head);
            b.set_mode(match v.mode {
                Mode::Stream => welcome::Mode::Stream,
                Mode::Snapshot => welcome::Mode::Snapshot,
                Mode::Rpc => welcome::Mode::Rpc,
            });
            b.set_snapshot_txn(v.snapshot_txn);
        }
        Msg::Batch(v) => {
            let mut b = root.init_batch();
            b.set_from_txn(v.from);
            b.set_to_txn(v.to);
            b.set_head_txn(v.head);
            b.set_digest(&v.digest);
            let mut ops = b.init_ops(v.ops.len() as u32);
            for (i, op) in v.ops.iter().enumerate() {
                let mut o = ops.reborrow().get(i as u32);
                o.set_table(&op.table);
                o.set_key(&op.key);
                if let Some(val) = &op.value {
                    o.set_has_value(true);
                    o.set_value(val);
                }
            }
        }
        Msg::Chunk(v) => {
            let mut b = root.init_chunk();
            b.set_table(&v.table);
            let mut entries = b.init_entries(v.entries.len() as u32);
            for (i, (k, val)) in v.entries.iter().enumerate() {
                let mut e = entries.reborrow().get(i as u32);
                e.set_key(k);
                e.set_value(val);
            }
        }
        Msg::SnapEnd(v) => {
            let mut b = root.init_snap_end();
            b.set_txn(v.txn);
            b.set_tables(v.tables);
            b.set_entries(v.entries);
            b.set_digest(&v.digest);
        }
        Msg::Ack(v) => {
            let mut b = root.init_ack();
            b.set_txn(v.txn);
            b.set_apply_us(v.apply_us);
        }
        Msg::Ping(v) => {
            let mut b = root.init_ping();
            b.set_seq(v.seq);
            b.set_sent_us(v.sent_us);
            b.set_peer_rtt_us(v.peer_rtt_us);
            b.set_applied_txn(v.applied);
            b.set_head_txn(v.head);
        }
        Msg::Pong(v) => {
            let mut b = root.init_pong();
            b.set_seq(v.seq);
            b.set_echo_us(v.echo_us);
        }
        Msg::Fault(v) => {
            let mut b = root.init_fault();
            b.set_code(match v.code {
                FaultCode::VersionMismatch => fault::Code::VersionMismatch,
                FaultCode::Unauthorized => fault::Code::Unauthorized,
                FaultCode::Busy => fault::Code::Busy,
                FaultCode::Resync => fault::Code::Resync,
                FaultCode::Internal => fault::Code::Internal,
            });
            b.set_msg(&v.msg);
        }
        Msg::Forward(v) => {
            let mut b = root.init_forward();
            b.set_id(v.id);
            b.set_method(&v.method);
            b.set_target(&v.target);
            b.set_body(&v.body);
            b.set_deadline_ms(v.deadline_ms);
            b.set_from_node(&v.from_node);
            put_headers(b.init_headers(v.headers.len() as u32), &v.headers);
        }
        Msg::ForwardResp(v) => {
            let mut b = root.init_forward_resp();
            b.set_id(v.id);
            b.set_status(v.status);
            b.set_body(&v.body);
            b.set_txn(v.txn);
            b.set_error(&v.error);
            put_headers(b.init_headers(v.headers.len() as u32), &v.headers);
        }
    }
    message
}

// -- decode --------------------------------------------------------------------

fn text(r: capnp::text::Reader<'_>) -> Result<String, Error> {
    Ok(r.to_str().map_err(|e| Error::Proto(format!("bad utf8: {e}")))?.to_owned())
}

fn digest32(d: &[u8]) -> Result<[u8; 32], Error> {
    d.try_into().map_err(|_| Error::Proto("digest must be 32 bytes".into()))
}

fn get_headers(list: capnp::struct_list::Reader<'_, crate::repl_capnp::header::Owned>) -> Result<Headers, Error> {
    let mut out = Vec::with_capacity(list.len() as usize);
    for h in list.iter() {
        out.push((text(h.get_name()?)?, h.get_value()?.to_vec()));
    }
    Ok(out)
}

pub fn decode(r: msg::Reader<'_>) -> Result<Msg, Error> {
    use msg::Which;
    Ok(match r.which().map_err(|e| Error::Proto(format!("unknown message tag {}", e.0)))? {
        Which::Hello(h) => {
            let h = h?;
            Msg::Hello(Hello {
                proto: h.get_proto(),
                node_id: text(h.get_node_id()?)?,
                schema: h.get_schema(),
                kind: match h.get_kind().map_err(|e| Error::Proto(format!("bad kind {}", e.0)))? {
                    hello::Kind::Stream => Kind::Stream,
                    hello::Kind::Rpc => Kind::Rpc,
                },
                stream_id: h.get_stream_id()?.to_vec(),
                applied: h.get_applied_txn(),
            })
        }
        Which::Welcome(w) => {
            let w = w?;
            Msg::Welcome(Welcome {
                node_id: text(w.get_node_id()?)?,
                stream_id: w.get_stream_id()?.to_vec(),
                head: w.get_head_txn(),
                mode: match w.get_mode().map_err(|e| Error::Proto(format!("bad mode {}", e.0)))? {
                    welcome::Mode::Stream => Mode::Stream,
                    welcome::Mode::Snapshot => Mode::Snapshot,
                    welcome::Mode::Rpc => Mode::Rpc,
                },
                snapshot_txn: w.get_snapshot_txn(),
            })
        }
        Which::Batch(b) => {
            let b = b?;
            let mut ops = Vec::with_capacity(b.get_ops()?.len() as usize);
            for o in b.get_ops()?.iter() {
                ops.push(RawOp {
                    table: text(o.get_table()?)?,
                    key: o.get_key()?.to_vec(),
                    value: o.get_has_value().then(|| o.get_value().map(<[u8]>::to_vec)).transpose()?,
                });
            }
            Msg::Batch(Batch {
                from: b.get_from_txn(),
                to: b.get_to_txn(),
                head: b.get_head_txn(),
                ops,
                digest: digest32(b.get_digest()?)?,
            })
        }
        Which::Chunk(c) => {
            let c = c?;
            let mut entries = Vec::with_capacity(c.get_entries()?.len() as usize);
            for e in c.get_entries()?.iter() {
                entries.push((e.get_key()?.to_vec(), e.get_value()?.to_vec()));
            }
            Msg::Chunk(Chunk { table: text(c.get_table()?)?, entries })
        }
        Which::SnapEnd(s) => {
            let s = s?;
            Msg::SnapEnd(SnapEnd {
                txn: s.get_txn(),
                tables: s.get_tables(),
                entries: s.get_entries(),
                digest: digest32(s.get_digest()?)?,
            })
        }
        Which::Ack(a) => {
            let a = a?;
            Msg::Ack(Ack { txn: a.get_txn(), apply_us: a.get_apply_us() })
        }
        Which::Ping(p) => {
            let p = p?;
            Msg::Ping(Ping {
                seq: p.get_seq(),
                sent_us: p.get_sent_us(),
                peer_rtt_us: p.get_peer_rtt_us(),
                applied: p.get_applied_txn(),
                head: p.get_head_txn(),
            })
        }
        Which::Pong(p) => {
            let p = p?;
            Msg::Pong(Pong { seq: p.get_seq(), echo_us: p.get_echo_us() })
        }
        Which::Fault(f) => {
            let f = f?;
            Msg::Fault(Fault {
                code: match f.get_code().map_err(|e| Error::Proto(format!("bad fault code {}", e.0)))? {
                    fault::Code::VersionMismatch => FaultCode::VersionMismatch,
                    fault::Code::Unauthorized => FaultCode::Unauthorized,
                    fault::Code::Busy => FaultCode::Busy,
                    fault::Code::Resync => FaultCode::Resync,
                    fault::Code::Internal => FaultCode::Internal,
                },
                msg: text(f.get_msg()?)?,
            })
        }
        Which::Forward(f) => {
            let f = f?;
            Msg::Forward(Forward {
                id: f.get_id(),
                method: text(f.get_method()?)?,
                target: text(f.get_target()?)?,
                headers: get_headers(f.get_headers()?)?,
                body: f.get_body()?.to_vec(),
                deadline_ms: f.get_deadline_ms(),
                from_node: text(f.get_from_node()?)?,
            })
        }
        Which::ForwardResp(f) => {
            let f = f?;
            Msg::ForwardResp(ForwardResp {
                id: f.get_id(),
                status: f.get_status(),
                headers: get_headers(f.get_headers()?)?,
                body: f.get_body()?.to_vec(),
                txn: f.get_txn(),
                error: text(f.get_error()?)?,
            })
        }
    })
}

// -- framing -------------------------------------------------------------------

fn reader_options() -> ReaderOptions {
    let mut o = ReaderOptions::new();
    o.traversal_limit_in_words(Some(MAX_FRAME_BYTES / 8));
    o
}

/// Write one frame; returns its size in bytes.
pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, m: &Msg) -> Result<usize, Error> {
    let message = encode(m);
    let bytes = capnp::serialize::compute_serialized_size_in_words(&message) * 8;
    if bytes > MAX_FRAME_BYTES {
        return Err(Error::Proto(format!("{} frame of {bytes} bytes exceeds the limit", m.name())));
    }
    capnp_futures::serialize::write_message(&mut *w, &message).await?;
    futures::io::AsyncWriteExt::flush(w).await?;
    Ok(bytes)
}

/// Read one frame; `None` = the peer closed the stream cleanly between frames.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Msg>, Error> {
    let Some(message) = capnp_futures::serialize::try_read_message(&mut *r, reader_options()).await? else {
        return Ok(None);
    };
    let root = message.get_root::<msg::Reader<'_>>()?;
    decode(root).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: Msg) -> Msg {
        let b = encode(&m);
        let r = b.get_root_as_reader::<msg::Reader<'_>>().unwrap();
        decode(r).unwrap()
    }

    #[test]
    fn batch_roundtrip_keeps_put_delete_and_digest() {
        let ops = vec![
            RawOp { table: "t".into(), key: vec![1, 2], value: Some(vec![9; 5]) },
            RawOp { table: "t".into(), key: vec![3], value: None },
            RawOp { table: "u".into(), key: vec![], value: Some(vec![]) },
        ];
        let digest = digest_ops(&ops);
        let Msg::Batch(b) = roundtrip(Msg::Batch(Batch { from: 4, to: 9, head: 12, ops: ops.clone(), digest })) else {
            panic!()
        };
        assert_eq!((b.from, b.to, b.head), (4, 9, 12));
        assert_eq!(b.ops, ops);
        assert_eq!(digest_ops(&b.ops), b.digest);
    }

    #[test]
    fn forward_roundtrip() {
        let f = Forward {
            id: 7,
            method: "POST".into(),
            target: "/v1/x?y=1".into(),
            headers: vec![("x-key".into(), b"12".to_vec())],
            body: vec![0, 1, 2],
            deadline_ms: 500,
            from_node: "n2".into(),
        };
        let Msg::Forward(g) = roundtrip(Msg::Forward(f.clone())) else { panic!() };
        assert_eq!((g.id, g.method, g.target, g.headers, g.body), (7, f.method, f.target, f.headers, f.body));
    }

    #[test]
    fn digest_differs_on_value_vs_delete() {
        let a = [RawOp { table: "t".into(), key: vec![1], value: Some(vec![]) }];
        let b = [RawOp { table: "t".into(), key: vec![1], value: None }];
        assert_ne!(digest_ops(&a), digest_ops(&b));
    }
}
