//! End-to-end: main + replica over real TLS sockets in one process.

use std::time::{Duration, Instant};

use db_wrapper::{CommitPolicy, DBWrapper};
use ntex::SharedCfg;
use ntex::util::Bytes;
use ntex::web::{self, App, HttpRequest, HttpResponse, HttpServer};
use repl::tls::{Peers, generate, pin_hex};
use repl::{Config, Repl, Role};
use shodh_redb::{ReadableDatabase, ReadableTable, TableDefinition};

const ITEMS: TableDefinition<u64, String> = TableDefinition::new("items");

fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Node {
    cfg: Config,
    db: DBWrapper,
}

fn dump(db: &DBWrapper) -> Vec<(u64, String)> {
    let rtx = db.db.begin_read().unwrap();
    let t = rtx.open_table(ITEMS).unwrap();
    t.iter().unwrap().map(|r| {
        let (k, v) = r.unwrap();
        (k.value(), v.value())
    }).collect()
}

async fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < end, "timeout waiting for: {what}");
        ntex::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn http(method: &str, url: &str, body: &'static str) -> (u16, String) {
    let c = ntex::client::Client::new();
    let r = c.request(method.parse().unwrap(), url).send_body(Bytes::from(body)).await.unwrap();
    let status = r.status().as_u16();
    (status, String::from_utf8(r.body().await.unwrap().to_vec()).unwrap())
}

#[ntex::test]
async fn replica_converges_forwards_and_reports_latency() {
    let dir = tempfile::tempdir().unwrap();
    let p = |n: &str| dir.path().join(n).to_string_lossy().into_owned();

    let ids = ["main", "r1", "evil"];
    let gens: Vec<_> = ids.iter().map(|id| generate(id).unwrap()).collect();
    for (id, g) in ids.iter().zip(&gens) {
        std::fs::write(p(&format!("{id}.crt")), &g.cert_pem).unwrap();
        std::fs::write(p(&format!("{id}.key")), &g.key_pem).unwrap();
    }
    // `evil` has a certificate but is not in the allowlist.
    let peers = format!("main=sha256:{},r1=sha256:{}", pin_hex(&gens[0].pin), pin_hex(&gens[1].pin));
    let (repl_port, http_main, http_r1) = (port(), port(), port());

    let mk = |id: &str, role: Role| {
        let mut c = Config::new(role, id, 1);
        c.cert_path = p(&format!("{id}.crt"));
        c.key_path = p(&format!("{id}.key"));
        c.peers = Peers::parse(&peers).unwrap();
        c.ping_every = Duration::from_millis(200);
        c.poll = Duration::from_millis(20);
        c.api_key = Some("k".into());
        if role == Role::Primary {
            c.bind = format!("127.0.0.1:{repl_port}");
            c.local_http = format!("127.0.0.1:{http_main}");
        } else {
            c.primaries = vec![format!("127.0.0.1:{repl_port}")];
        }
        c
    };
    let open = |id: &str, cfg: &Config| {
        let db = repl::open_db(Some(cfg), &p(&format!("{id}.redb")), CommitPolicy::Durable, None).unwrap();
        db.register_table(ITEMS);
        db
    };

    // Main: data exists before any replica connects (snapshot), more arrives later (stream).
    let main = Node { cfg: mk("main", Role::Primary), db: DBWrapper::new(&p("unused")).unwrap() };
    let main = Node { db: open("main", &main.cfg), ..main };
    for i in 0..200u64 {
        main.db.write(ITEMS, i, format!("v{i}")).unwrap();
    }
    main.db.flush_buffers().unwrap();
    let main_repl = Repl::start(Some(main.cfg.clone()), &main.db).await.unwrap();

    // Main's own HTTP API: the write endpoint reports whether the call was trusted.
    let (mdb, mrepl) = (main.db.clone(), main_repl.clone());
    let srv = HttpServer::new(async move |_| {
        let (db, repl) = (mdb.clone(), mrepl.clone());
        App::new().service(web::resource("/write/{id}").route(web::post().to(
            move |req: HttpRequest, body: Bytes| {
                let (db, repl) = (db.clone(), repl.clone());
                async move {
                    let id: u64 = req.path().rsplit('/').next().unwrap().parse().unwrap();
                    db.write(ITEMS, id, String::from_utf8(body.to_vec()).unwrap()).unwrap();
                    let trusted = repl::web::is_trusted(&repl, req.headers());
                    HttpResponse::Ok().body(format!("trusted={trusted}"))
                }
            },
        )))
    })
    .bind(format!("127.0.0.1:{http_main}"), SharedCfg::new("main"))
    .unwrap()
    .workers(1)
    .run();
    ntex::rt::spawn(async move { let _ = srv.await; });

    // Wrong certificate is refused; nothing is replicated to it.
    let mut ecfg = mk("evil", Role::Follower);
    ecfg.peers = Peers::parse(&format!("{peers},evil=sha256:{}", pin_hex(&gens[2].pin))).unwrap();
    let edb = open("evil", &ecfg);
    // Its own pin is allowlisted locally, but the main node's allowlist lacks it.
    let evil = Repl::start(Some(ecfg), &edb).await.unwrap();
    ntex::time::sleep(Duration::from_millis(700)).await;
    assert!(dump(&edb).is_empty(), "unlisted node got data");
    evil.shutdown();

    // Legit replica.
    let rcfg = mk("r1", Role::Follower);
    let rdb = open("r1", &rcfg);
    let r1 = Repl::start(Some(rcfg), &rdb).await.unwrap();
    until("snapshot convergence", 10, || dump(&rdb) == dump(&main.db)).await;
    assert_eq!(dump(&rdb).len(), 200);

    // Streaming of later writes.
    for i in 200..260u64 {
        main.db.write(ITEMS, i, format!("s{i}")).unwrap();
    }
    main.db.flush_buffers().unwrap();
    until("stream convergence", 10, || dump(&rdb) == dump(&main.db)).await;

    // Forced disconnect → reconnect → resumes without a new snapshot.
    assert!(main_repl.disconnect("r1"));
    main.db.write(ITEMS, 1000, "after-reconnect".into()).unwrap();
    main.db.flush_buffers().unwrap();
    until("resume after reconnect", 15, || dump(&rdb) == dump(&main.db)).await;
    let s = r1.stats().await;
    assert!(s["main"]["reconnects"].as_u64().unwrap() >= 1, "{s}");
    assert_eq!(s["main"]["snapshots"].as_u64().unwrap(), 1, "{s}");

    // Replica as proxy: a write sent to the replica is executed by main
    // (trusted), and is readable on the replica right after the response.
    let r1c = r1.clone();
    let srv = HttpServer::new(async move |_| App::new().middleware(r1c.gate()).default_service(web::route().to(async || HttpResponse::NotFound())))
        .bind(format!("127.0.0.1:{http_r1}"), SharedCfg::new("r1"))
        .unwrap()
        .workers(1)
        .run();
    ntex::rt::spawn(async move { let _ = srv.await; });
    let (status, body) = http("POST", &format!("http://127.0.0.1:{http_r1}/write/5000"), "proxied").await;
    assert_eq!((status, body.as_str()), (200, "trusted=true"));
    assert_eq!(rdb.db.begin_read().unwrap().open_table(ITEMS).unwrap().get(5000).unwrap().unwrap().value(), "proxied");
    // A client cannot fake the trust header.
    let (_, body) = http("POST", &format!("http://127.0.0.1:{http_main}/write/5001"), "x").await;
    assert_eq!(body, "trusted=false");

    // Latency statistics on both sides.
    until("rtt samples", 5, || true).await;
    let ms = main_repl.stats().await;
    let rep = &ms["replicas"][0];
    assert_eq!(rep["node"], "r1", "{ms}");
    assert!(rep["rtt"]["count"].as_u64().unwrap() > 0, "{ms}");
    assert!(rep["ack"]["count"].as_u64().unwrap() > 0, "{ms}");
    let rs = r1.stats().await;
    assert!(rs["main"]["rtt"]["count"].as_u64().unwrap() > 0, "{rs}");
    let probe = main_repl.probe(5).await;
    assert_eq!(probe["probes"][0]["received"], 5, "{probe}");

    // HTTP stats endpoint is key-guarded.
    let (st, _) = http("GET", &format!("http://127.0.0.1:{http_r1}/repl/stats"), "").await;
    assert_eq!(st, 403);
}
