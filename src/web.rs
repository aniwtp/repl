//! ntex integration: the [`Gate`] middleware and request-forwarding helpers.
//!
//! ```ignore
//! App::new()
//!     .middleware(repl.gate().local("/v1/upload"))  // outermost: before XOR
//!     .middleware(XorMiddleware::new(state))
//! ```
//!
//! On the main node (or standalone) the gate only serves `/repl/stats` and
//! `/repl/probe`. On a replica it also
//! * passes safe methods (`GET`/`HEAD`/`OPTIONS`) to the local handlers,
//! * passes paths registered with [`Gate::local`] to the local handlers (they
//!   do their pre-checks and delegate the write with [`forward_request`]),
//! * forwards everything else — mutating methods and paths registered with
//!   [`Gate::forward`] (e.g. `GET` handlers that write, like view counters) —
//!   to the main node, waits for its answer and for the local copy to catch up.
//!
//! Requests are forwarded *before* the XOR layer decodes them, so the XOR
//! replay window works once, on the main node.

use std::net::SocketAddr;

use ntex::http::header::{HeaderMap, HeaderName, HeaderValue};
use ntex::http::{Method, StatusCode};
use ntex::service::{Ctx, Middleware, Service};
use ntex::util::Bytes;
use ntex::web::{HttpRequest, HttpResponse, WebRequest, WebResponse};

use crate::{ForwardRequest, Repl, Role};

const KEY_HEADER: &str = "x-repl-key";
const AUTH_HEADER: &str = "x-repl-auth";

#[derive(Clone)]
pub struct Gate {
    repl: Repl,
    local: Vec<String>,
    forward: Vec<String>,
}

impl Repl {
    pub fn gate(&self) -> Gate {
        Gate { repl: self.clone(), local: Vec::new(), forward: Vec::new() }
    }
}

impl Gate {
    /// Paths (prefix match) whose mutating handlers run on the replica.
    #[must_use]
    pub fn local(mut self, prefix: &str) -> Self {
        self.local.push(prefix.to_owned());
        self
    }

    /// Paths (prefix match) forwarded to the main node whatever the method.
    #[must_use]
    pub fn forward(mut self, prefix: &str) -> Self {
        self.forward.push(prefix.to_owned());
        self
    }

    fn must_forward(&self, method: &Method, path: &str) -> bool {
        if !self.repl.is_replica() || path.starts_with("/repl/") {
            return false;
        }
        if self.forward.iter().any(|p| path.starts_with(p.as_str())) {
            return true;
        }
        if self.local.iter().any(|p| path.starts_with(p.as_str())) {
            return false;
        }
        !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    }
}

/// True if the request carries this main node's forward-executor token, i.e.
/// it was forwarded by a replica rather than sent by a client.
pub fn is_trusted(repl: &Repl, headers: &HeaderMap) -> bool {
    headers.get(AUTH_HEADER).and_then(|v| v.to_str().ok()).is_some_and(|t| repl.is_trusted(t))
}

fn collect_headers(h: &HeaderMap, peer: Option<SocketAddr>) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> =
        h.iter().map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec())).collect();
    if let Some(p) = peer {
        out.push(("x-forwarded-for".to_owned(), p.ip().to_string().into_bytes()));
    }
    out
}

fn plain(status: StatusCode, repl: &Repl, text: &str) -> HttpResponse {
    HttpResponse::builder(status)
        .header("x-repl-served-by", repl.node_id())
        .content_type("text/plain; charset=utf-8")
        .body(text.to_owned())
}

/// Run an HTTP request on the main node and turn its answer into a response.
/// Waits until this replica has applied the write (read-your-writes); when it
/// does not catch up in time the answer is still returned, marked
/// `x-repl-stale: 1`.
pub async fn forward_http(
    repl: &Repl,
    method: &str,
    target: String,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    body: Vec<u8>,
) -> HttpResponse {
    let req = ForwardRequest {
        method: method.to_owned(),
        target,
        headers: collect_headers(headers, peer),
        body,
        deadline: None,
    };
    let resp = match repl.forward(req).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("repl[{}]: forward failed: {e}", repl.node_id());
            return plain(StatusCode::BAD_GATEWAY, repl, "main node unavailable");
        }
    };
    let caught_up = repl.wait_applied(resp.txn, repl.config().wait_applied).await;
    let mut b = HttpResponse::builder(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (n, v) in &resp.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_bytes(v)) {
            b.header(name, value);
        }
    }
    b.header("x-repl-served-by", repl.node_id()).header("x-repl-txn", resp.txn);
    if !caught_up {
        b.header("x-repl-stale", "1");
    }
    b.body(resp.body)
}

/// For handlers that pre-check on the replica: delegate the database part of
/// the request being handled to the main node and wait for its answer.
/// `body` replaces the request body; `target` (path + query) replaces the
/// request target when given (e.g. an internal commit endpoint that is only
/// reachable through [`is_trusted`] requests).
pub async fn forward_request(repl: &Repl, req: &HttpRequest, body: Bytes, target: Option<&str>) -> HttpResponse {
    let target = match target {
        Some(t) => t.to_owned(),
        None if req.query_string().is_empty() => req.path().to_owned(),
        None => format!("{}?{}", req.path(), req.query_string()),
    };
    forward_http(repl, req.method().as_str(), target, req.headers(), req.peer_addr(), body.to_vec()).await
}

async fn endpoint(repl: &Repl, path: &str, query: &str, headers: &HeaderMap) -> Option<HttpResponse> {
    if !matches!(path, "/repl/stats" | "/repl/probe") {
        return None;
    }
    let given = headers.get(KEY_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    if repl.config().api_key.is_none() {
        return Some(HttpResponse::NotFound().build());
    }
    if !repl.api_key_ok(given) {
        return Some(HttpResponse::Forbidden().build());
    }
    let body = if path == "/repl/probe" {
        let n = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("n="))
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        repl.probe(n).await
    } else {
        repl.stats().await
    };
    Some(HttpResponse::Ok().content_type("application/json").body(body.to_string()))
}

impl<S, St> Middleware<S, St> for Gate {
    type Service = GateService<S>;

    fn create(&self, _: &St, service: S) -> Self::Service {
        GateService { service, gate: self.clone() }
    }
}

pub struct GateService<S> {
    service: S,
    gate: Gate,
}

impl<S, St, In> Service<St, WebRequest<In>> for GateService<S>
where
    S: Service<St, WebRequest<In>, Res = WebResponse>,
{
    type Res = WebResponse;
    type Error = S::Error;

    ntex::forward_bind!(St, service);
    ntex::forward_ready!(St, service);
    ntex::forward_shutdown!(St, service);

    async fn call(&self, mut req: WebRequest<In>, ctx: Ctx<'_, Self, St>) -> Result<WebResponse, Self::Error> {
        let repl = &self.gate.repl;
        if repl.role() == Role::Standalone {
            return ctx.call(&self.service, req).await;
        }
        if req.path().starts_with("/repl/") {
            if let Some(resp) = endpoint(repl, req.path(), req.query_string(), req.headers()).await {
                return Ok(req.into_response(resp));
            }
        }
        if !self.gate.must_forward(req.method(), req.path()) {
            return ctx.call(&self.service, req).await;
        }

        let limit = repl.config().forward_body_limit;
        let mut payload = req.take_payload();
        let mut body = Vec::new();
        while let Some(chunk) = payload.recv().await {
            let Ok(chunk) = chunk else {
                return Ok(req.into_response(plain(StatusCode::BAD_REQUEST, repl, "request body read failed")));
            };
            if body.len() + chunk.len() > limit {
                return Ok(req.into_response(plain(StatusCode::PAYLOAD_TOO_LARGE, repl, "request body too large")));
            }
            body.extend_from_slice(&chunk);
        }
        let target = if req.query_string().is_empty() {
            req.path().to_owned()
        } else {
            format!("{}?{}", req.path(), req.query_string())
        };
        let resp = forward_http(repl, req.method().as_str(), target, req.headers(), req.peer_addr(), body).await;
        Ok(req.into_response(resp))
    }
}
