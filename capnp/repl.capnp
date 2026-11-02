@0xb5f3a9c2d41e7086;

# Replication wire protocol v1. One capnp message = one frame (standard stream framing).
# Connection kinds are selected by Hello.kind:
#   stream — replica pulls the change stream (batch / snapshot) and exchanges ping/pong;
#   rpc    — replica forwards HTTP requests to the main node (forward / forwardResp).

struct Entry { key @0 :Data; value @1 :Data; }
struct Op { table @0 :Text; key @1 :Data; hasValue @2 :Bool; value @3 :Data; }   # !hasValue = delete
struct Header { name @0 :Text; value @1 :Data; }

struct Hello {
  proto @0 :UInt16;
  nodeId @1 :Text;
  schema @2 :UInt32;
  kind @3 :Kind;
  streamId @4 :Data;        # empty = replica has no data
  appliedTxn @5 :UInt64;
  enum Kind { stream @0; rpc @1; }
}

struct Welcome {
  nodeId @0 :Text;
  streamId @1 :Data;
  headTxn @2 :UInt64;
  mode @3 :Mode;
  snapshotTxn @4 :UInt64;   # mode = snapshot: position the snapshot corresponds to
  enum Mode { stream @0; snapshot @1; rpc @2; }
}

struct Batch {
  fromTxn @0 :UInt64;       # must equal the replica's applied position
  toTxn @1 :UInt64;
  headTxn @2 :UInt64;
  ops @3 :List(Op);
  digest @4 :Data;          # blake3 over ops
}

struct Chunk { table @0 :Text; entries @1 :List(Entry); }
struct SnapEnd { txn @0 :UInt64; tables @1 :UInt32; entries @2 :UInt64; digest @3 :Data; }

struct Ping {
  seq @0 :UInt64;
  sentUs @1 :UInt64;        # sender's monotonic clock; only echoed back, never compared
  peerRttUs @2 :UInt64;     # sender's last measured RTT to the peer (0 = none yet)
  appliedTxn @3 :UInt64;
  headTxn @4 :UInt64;
}
struct Pong { seq @0 :UInt64; echoUs @1 :UInt64; }
struct Ack { txn @0 :UInt64; applyUs @1 :UInt64; }

struct Fault {
  code @0 :Code;
  msg @1 :Text;
  enum Code { versionMismatch @0; unauthorized @1; busy @2; resync @3; internal @4; }
}

struct Forward {
  id @0 :UInt64;
  method @1 :Text;
  target @2 :Text;          # path + query
  headers @3 :List(Header);
  body @4 :Data;
  deadlineMs @5 :UInt32;
  fromNode @6 :Text;
}

struct ForwardResp {
  id @0 :UInt64;
  status @1 :UInt16;
  headers @2 :List(Header);
  body @3 :Data;
  txn @4 :UInt64;           # main's CDC head after the request (read-your-writes position)
  error @5 :Text;           # non-empty = could not execute (status = 502/504)
}

struct Msg {
  union {
    hello @0 :Hello;
    welcome @1 :Welcome;
    batch @2 :Batch;
    chunk @3 :Chunk;
    snapEnd @4 :SnapEnd;
    ack @5 :Ack;
    ping @6 :Ping;
    pong @7 :Pong;
    fault @8 :Fault;
    forward @9 :Forward;
    forwardResp @10 :ForwardResp;
  }
}
