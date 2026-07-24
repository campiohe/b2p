# `b2p relay serve` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `b2p` binary a server mode (`b2p relay serve`) with full relay-protocol-v1 parity, so any machine can be a relay; replace the test mock with the real server; ship a Docker image.

**Architecture:** `src/relay_server.rs`: tokio TCP accept loop → optional rustls TLS → hand-parsed HTTP head (`httparse`) that answers `/healthz`/401/400/404/426 directly and upgrades real WebSocket requests via a hand-written 101 (`derive_accept_key`) + `WebSocketStream::from_raw_socket` behind a prefix-replaying stream. Room semantics mirror `relay-worker/src/index.js` exactly: pair, forward verbatim, pong pings, peer-left, takeover-on-rejoin with suppression, 30-min unpaired expiry.

**Tech Stack:** tokio, tokio-tungstenite 0.30 (existing), rustls 0.23 + tokio-rustls (server TLS), httparse (new, zero-dep), rcgen (existing dev-dep) for TLS tests.

**Spec:** `docs/superpowers/specs/2026-07-23-b2p-relay-serve-design.md` (spike already resolved — see spec §4).

## Global Constraints

- Every cargo command needs `export PATH="$HOME/.cargo/bin:$PATH"` first.
- GATE before every commit: `cargo fmt --all` (check clean), `cargo clippy --all-targets -- -D warnings`, `cargo test`. Clippy MUST use `--all-targets`.
- Commit subjects end with ` (relay serve)`.
- rustls: ALWAYS `builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))` — never bare `builder()`.
- New crates allowed: `httparse = "1"`, `tokio-rustls = { version = "0.26", default-features = false }`. Nothing else.
- Protocol parity is defined by `relay-worker/src/index.js` + `relay-worker/test.mjs`; when in doubt, match the Worker's observable behavior (status codes: 404 unknown path, 401 bad/missing token, 426 non-websocket on a room path, 400 bad role; close codes: 1012 takeover, 1013 expiry).
- Inbound WS message cap: 1 MiB (Workers parity).
- Do not modify `relay-worker/src/index.js`, `relay-worker/test.mjs`, or `src/transport/relay.rs` (except the one test noted in Task 4).

---

### Task 1: Deps + head parsing, routing, and the prefix-replaying stream

**Files:**
- Modify: `Cargo.toml`
- Create: `src/relay_server.rs` (helpers only in this task)
- Modify: `src/lib.rs` (add `pub mod relay_server;` alphabetically)

**Interfaces (produced, used by Tasks 2/3/5):**
- `pub(crate) struct Head { path: String, bearer: Option<String>, ws_key: Option<Vec<u8>>, is_upgrade: bool }`
- `pub(crate) fn parse_head(buf: &[u8]) -> anyhow::Result<Head>`
- `pub(crate) enum Route { Healthz, Join { room: String, role: RoomRole }, Reject { status: u16, body: &'static str } }`
- `#[derive(Clone, Copy, PartialEq)] pub(crate) enum RoomRole { Send, Recv }` with `fn as_str(&self) -> &'static str` and `fn other(&self) -> RoomRole`
- `pub(crate) fn route(head: &Head, token: Option<&str>) -> Route`
- `pub(crate) struct Prefixed<S> { prefix: Vec<u8>, pos: usize, inner: S }` implementing `AsyncRead + AsyncWrite` (replays `prefix` first on reads, passes writes through).

- [ ] **Step 1: Add deps to `Cargo.toml`** (alphabetical in `[dependencies]`):

```toml
httparse = "1"
tokio-rustls = { version = "0.26", default-features = false }
```

Run: `cargo check` → success.

- [ ] **Step 2: Write the failing tests** — create `src/relay_server.rs` with only a test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(raw: &str) -> Head {
        parse_head(raw.as_bytes()).expect("parses")
    }

    #[test]
    fn parses_upgrade_and_plain_heads() {
        let h = head_of(
            "GET /v1/room/abc?role=recv HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        );
        assert_eq!(h.path, "/v1/room/abc?role=recv");
        assert!(h.is_upgrade);
        assert_eq!(h.ws_key.as_deref(), Some(b"dGhlIHNhbXBsZSBub25jZQ==".as_slice()));

        let h = head_of("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(h.path, "/healthz");
        assert!(!h.is_upgrade);
        assert!(h.ws_key.is_none());

        let h = head_of("GET / HTTP/1.1\r\nAuthorization: Bearer sekrit\r\n\r\n");
        assert_eq!(h.bearer.as_deref(), Some("sekrit"));

        assert!(parse_head(b"not http at all\r\n\r\n").is_err());
    }

    fn upgrade_head(path: &str, bearer: Option<&str>) -> Head {
        Head {
            path: path.to_string(),
            bearer: bearer.map(str::to_string),
            ws_key: Some(b"dGhlIHNhbXBsZSBub25jZQ==".to_vec()),
            is_upgrade: true,
        }
    }

    #[test]
    fn routes_match_the_worker() {
        // healthz needs no auth even with a token set
        assert!(matches!(
            route(&upgrade_head("/healthz", None), Some("t")),
            Route::Healthz
        ));
        // unknown path / bad room charset → 404
        assert!(matches!(
            route(&upgrade_head("/nope", None), None),
            Route::Reject { status: 404, .. }
        ));
        assert!(matches!(
            route(&upgrade_head("/v1/room/bad_room!?role=recv", None), None),
            Route::Reject { status: 404, .. }
        ));
        // token required and wrong/missing → 401 (before role validation)
        assert!(matches!(
            route(&upgrade_head("/v1/room/abc?role=recv", None), Some("t")),
            Route::Reject { status: 401, .. }
        ));
        assert!(matches!(
            route(&upgrade_head("/v1/room/abc?role=recv", Some("wrong")), Some("t")),
            Route::Reject { status: 401, .. }
        ));
        // non-upgrade request on a room path → 426
        let mut plain = upgrade_head("/v1/room/abc?role=recv", None);
        plain.is_upgrade = false;
        plain.ws_key = None;
        assert!(matches!(
            route(&plain, None),
            Route::Reject { status: 426, .. }
        ));
        // bad/missing role → 400
        assert!(matches!(
            route(&upgrade_head("/v1/room/abc?role=pilot", None), None),
            Route::Reject { status: 400, .. }
        ));
        assert!(matches!(
            route(&upgrade_head("/v1/room/abc", None), None),
            Route::Reject { status: 400, .. }
        ));
        // the happy path, token honored
        match route(&upgrade_head("/v1/room/Abc123?role=send", Some("t")), Some("t")) {
            Route::Join { room, role } => {
                assert_eq!(room, "Abc123");
                assert!(matches!(role, RoomRole::Send));
            }
            _ => panic!("expected Join"),
        }
    }

    #[tokio::test]
    async fn prefixed_replays_then_passes_through() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, server) = tokio::io::duplex(64);
        let mut pre = Prefixed {
            prefix: b"HELLO".to_vec(),
            pos: 0,
            inner: server,
        };
        let mut client = client;
        client.write_all(b"WORLD").await.unwrap();
        let mut buf = [0u8; 10];
        pre.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLOWORLD");
        // writes pass through untouched
        pre.write_all(b"BACK").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"BACK");
    }
}
```

Add `pub mod relay_server;` to `src/lib.rs` (after `pub mod protocol;`... alphabetically: between `pub mod rendezvous;` and `pub mod rvcode;`).

- [ ] **Step 3: Run to verify failure** — `cargo test --lib relay_server` → FAIL (unresolved names).

- [ ] **Step 4: Implement** (top of `src/relay_server.rs`, above the test module):

```rust
//! `b2p relay serve`: a native implementation of relay protocol v1 — the
//! same contract as relay-worker/ (see the P2b spec §4 and its as-built
//! notes). Any machine that can run this binary and accept inbound
//! connections can be a relay. The relay sees only ciphertext.
//!
//! HTTP handling is deliberately hand-rolled (spike-verified): tungstenite
//! rejects non-upgrade requests before its callback runs, so we read the
//! request head ourselves, answer /healthz and rejections directly, and
//! hand real upgrades to tungstenite via a hand-written 101 +
//! `from_raw_socket` behind a prefix-replaying stream.

use anyhow::Context as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// One parsed HTTP request head.
pub(crate) struct Head {
    pub path: String,
    pub bearer: Option<String>,
    pub ws_key: Option<Vec<u8>>,
    pub is_upgrade: bool,
}

pub(crate) fn parse_head(buf: &[u8]) -> anyhow::Result<Head> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => anyhow::bail!("incomplete request head"),
        Err(e) => anyhow::bail!("bad request head: {e}"),
    }
    let path = req.path.context("request has no path")?.to_string();
    let mut bearer = None;
    let mut ws_key = None;
    let mut upgrade_hdr = false;
    let mut connection_upgrade = false;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("authorization") {
            if let Ok(v) = std::str::from_utf8(h.value) {
                if let Some(t) = v.strip_prefix("Bearer ") {
                    bearer = Some(t.to_string());
                }
            }
        } else if h.name.eq_ignore_ascii_case("sec-websocket-key") {
            ws_key = Some(h.value.to_vec());
        } else if h.name.eq_ignore_ascii_case("upgrade") {
            upgrade_hdr = std::str::from_utf8(h.value)
                .is_ok_and(|v| v.eq_ignore_ascii_case("websocket"));
        } else if h.name.eq_ignore_ascii_case("connection") {
            connection_upgrade = std::str::from_utf8(h.value)
                .is_ok_and(|v| v.to_ascii_lowercase().contains("upgrade"));
        }
    }
    Ok(Head {
        path,
        bearer,
        ws_key,
        is_upgrade: upgrade_hdr && connection_upgrade,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RoomRole {
    Send,
    Recv,
}

impl RoomRole {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            RoomRole::Send => "send",
            RoomRole::Recv => "recv",
        }
    }
    pub(crate) fn other(&self) -> RoomRole {
        match self {
            RoomRole::Send => RoomRole::Recv,
            RoomRole::Recv => RoomRole::Send,
        }
    }
}

pub(crate) enum Route {
    Healthz,
    Join { room: String, role: RoomRole },
    Reject { status: u16, body: &'static str },
}

/// Mirror the Worker's observable decisions exactly:
/// healthz → 200; non-room path or bad room charset → 404; wrong/missing
/// token → 401; non-websocket request on a room path → 426; bad role → 400.
pub(crate) fn route(head: &Head, token: Option<&str>) -> Route {
    if head.path == "/healthz" {
        return Route::Healthz;
    }
    let Some(rest) = head.path.strip_prefix("/v1/room/") else {
        return Route::Reject { status: 404, body: "not found" };
    };
    let (room, query) = rest.split_once('?').unwrap_or((rest, ""));
    if room.is_empty() || room.len() > 64 || !room.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Route::Reject { status: 404, body: "not found" };
    }
    if let Some(t) = token {
        if head.bearer.as_deref() != Some(t) {
            return Route::Reject { status: 401, body: "unauthorized" };
        }
    }
    if !head.is_upgrade || head.ws_key.is_none() {
        return Route::Reject { status: 426, body: "expected websocket" };
    }
    let role = match query.split('&').find_map(|kv| kv.strip_prefix("role=")) {
        Some("send") => RoomRole::Send,
        Some("recv") => RoomRole::Recv,
        _ => return Route::Reject { status: 400, body: "bad role" },
    };
    Route::Join {
        room: room.to_string(),
        role,
    }
}

/// AsyncRead+AsyncWrite wrapper that replays `prefix` before the inner
/// stream — for bytes read past the request head before the WebSocket
/// layer takes over.
pub(crate) struct Prefixed<S> {
    pub(crate) prefix: Vec<u8>,
    pub(crate) pos: usize,
    pub(crate) inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
```

- [ ] **Step 5: Run tests** — `cargo test --lib relay_server` → PASS (3 tests).

- [ ] **Step 6: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add Cargo.toml Cargo.lock src/lib.rs src/relay_server.rs
git commit -m "feat: relay-server head parsing, routing, prefixed stream (relay serve)"
```

---

### Task 2: Server core — accept loop, rooms, pairing, forwarding

**Files:**
- Modify: `src/relay_server.rs`

**Interfaces (produced):**
- `pub struct ServeCfg { pub listen: std::net::SocketAddr, pub token: Option<String>, pub tls: Option<(std::path::PathBuf, std::path::PathBuf)>, pub expire_unpaired: Duration, pub sweep_every: Duration }` with `Default` (listen `0.0.0.0:9009`, no token/tls, 30 min, 60 s).
- `pub struct RelayServer { pub addr: std::net::SocketAddr, /* private stop+handle */ }` with `pub async fn shutdown(self)`; `Drop` aborts the accept task.
- `pub async fn start(cfg: ServeCfg) -> anyhow::Result<RelayServer>` — binds, spawns accept loop + sweeper, returns immediately.
- Protocol constants: control strings identical to the Worker (`{"t":"peer-joined"}`, `{"t":"peer-left"}`, `{"t":"ping"}`→`{"t":"pong"}`).

**Consumes:** everything from Task 1. TLS in `ServeCfg.tls` is carried but ignored until Task 5 (error if set: "TLS not yet wired" — replaced in Task 5).

- [ ] **Step 1: Write the failing tests** (append to the test module):

```rust
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::Message;

    async fn spawn_server(cfg: ServeCfg) -> RelayServer {
        start(ServeCfg {
            listen: "127.0.0.1:0".parse().expect("addr"),
            ..cfg
        })
        .await
        .expect("server starts")
    }

    async fn ws_client(
        addr: std::net::SocketAddr,
        room: &str,
        role: &str,
    ) -> tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    > {
        let (ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/v1/room/{room}?role={role}"))
                .await
                .expect("connects");
        ws
    }

    async fn next_text(
        ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
    ) -> String {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                .await
                .expect("timely")
                .expect("stream alive")
                .expect("no error")
            {
                Message::Text(t) => return t.to_string(),
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn healthz_and_rejections_over_real_http() {
        let srv = spawn_server(ServeCfg::default()).await;
        let http = |path: &str| format!("http://{}{}", srv.addr, path);
        let client = reqwest::Client::new();
        let r = client.get(http("/healthz")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "ok");
        assert_eq!(client.get(http("/nope")).send().await.unwrap().status(), 404);
        assert_eq!(
            client.get(http("/v1/room/abc?role=recv")).send().await.unwrap().status(),
            426
        );
    }

    #[tokio::test]
    async fn token_gates_rooms_but_not_healthz() {
        let srv = spawn_server(ServeCfg {
            token: Some("sekrit".into()),
            ..Default::default()
        })
        .await;
        let client = reqwest::Client::new();
        let base = format!("http://{}", srv.addr);
        assert_eq!(
            client.get(format!("{base}/healthz")).send().await.unwrap().status(),
            200
        );
        assert_eq!(
            client
                .get(format!("{base}/v1/room/abc?role=recv"))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        // right token gets past auth (upgrade still required → 426 via GET)
        assert_eq!(
            client
                .get(format!("{base}/v1/room/abc?role=recv"))
                .header("authorization", "Bearer sekrit")
                .send()
                .await
                .unwrap()
                .status(),
            426
        );
    }

    #[tokio::test]
    async fn pairs_forwards_pongs_and_reports_departure() {
        let srv = spawn_server(ServeCfg::default()).await;
        let mut recv = ws_client(srv.addr, "roomA", "recv").await;
        let mut send = ws_client(srv.addr, "roomA", "send").await;
        assert_eq!(next_text(&mut recv).await, r#"{"t":"peer-joined"}"#);
        assert_eq!(next_text(&mut send).await, r#"{"t":"peer-joined"}"#);

        // binary forwarded verbatim
        let payload = vec![9u8; 600 * 1024];
        send.send(Message::Binary(payload.clone().into())).await.unwrap();
        loop {
            match recv.next().await.unwrap().unwrap() {
                Message::Binary(b) => {
                    assert_eq!(b.as_ref(), payload.as_slice());
                    break;
                }
                _ => continue,
            }
        }
        // text (acks) forwarded verbatim
        recv.send(Message::Text(r#"{"t":"ack","n":1}"#.into())).await.unwrap();
        assert_eq!(next_text(&mut send).await, r#"{"t":"ack","n":1}"#);
        // ping answered locally, not forwarded
        send.send(Message::Text(r#"{"t":"ping"}"#.into())).await.unwrap();
        assert_eq!(next_text(&mut send).await, r#"{"t":"pong"}"#);
        // departure notifies the survivor
        send.close(None).await.unwrap();
        assert_eq!(next_text(&mut recv).await, r#"{"t":"peer-left"}"#);
    }

    #[tokio::test]
    async fn oversized_inbound_message_is_refused() {
        let srv = spawn_server(ServeCfg::default()).await;
        let mut recv = ws_client(srv.addr, "roomBig", "recv").await;
        let mut send = ws_client(srv.addr, "roomBig", "send").await;
        let _ = next_text(&mut recv).await;
        let _ = next_text(&mut send).await;
        // over the 1 MiB parity cap → server closes the offender
        send.send(Message::Binary(vec![0u8; 2 * 1024 * 1024].into()))
            .await
            .unwrap();
        let died = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match send.next().await {
                    None | Some(Err(_)) => break,
                    Some(Ok(Message::Close(_))) => break,
                    _ => continue,
                }
            }
        })
        .await;
        assert!(died.is_ok(), "sender socket should be closed");
    }
```

- [ ] **Step 2: Run to verify failure** — `cargo test --lib relay_server` → FAIL.

- [ ] **Step 3: Implement.** Add to `src/relay_server.rs`:

```rust
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

const MAX_HEAD: usize = 8 * 1024;
/// Parity with Cloudflare Workers' 1 MiB WS message limit.
const MAX_MSG: usize = 1024 * 1024;
const PEER_JOINED: &str = r#"{"t":"peer-joined"}"#;
const PEER_LEFT: &str = r#"{"t":"peer-left"}"#;
const PING: &str = r#"{"t":"ping"}"#;
const PONG: &str = r#"{"t":"pong"}"#;

#[derive(Clone)]
pub struct ServeCfg {
    pub listen: SocketAddr,
    pub token: Option<String>,
    pub tls: Option<(std::path::PathBuf, std::path::PathBuf)>,
    pub expire_unpaired: Duration,
    pub sweep_every: Duration,
}

impl Default for ServeCfg {
    fn default() -> Self {
        ServeCfg {
            listen: "0.0.0.0:9009".parse().expect("static addr"),
            token: None,
            tls: None,
            expire_unpaired: Duration::from_secs(30 * 60),
            sweep_every: Duration::from_secs(60),
        }
    }
}

type Tx = mpsc::UnboundedSender<Message>;

struct Slot {
    tx: Tx,
    id: u64,
}

#[derive(Default)]
struct RoomState {
    send: Option<Slot>,
    recv: Option<Slot>,
    alone_since: Option<Instant>,
}

impl RoomState {
    fn slot_mut(&mut self, role: RoomRole) -> &mut Option<Slot> {
        match role {
            RoomRole::Send => &mut self.send,
            RoomRole::Recv => &mut self.recv,
        }
    }
    fn occupancy(&self) -> usize {
        self.send.is_some() as usize + self.recv.is_some() as usize
    }
}

type Rooms = Arc<Mutex<HashMap<String, RoomState>>>;

pub struct RelayServer {
    pub addr: SocketAddr,
    stop: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RelayServer {
    /// Graceful stop: no new connections; existing sockets close as their
    /// tasks finish.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.handle.await;
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub async fn start(cfg: ServeCfg) -> anyhow::Result<RelayServer> {
    anyhow::ensure!(cfg.tls.is_none(), "TLS not yet wired (Task 5)");
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));
    let (stop, stop_rx) = watch::channel(false);
    let conn_ids = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // Expiry sweeper (Task 3 asserts its behavior; wired from the start).
    tokio::spawn(sweeper(
        rooms.clone(),
        cfg.expire_unpaired,
        cfg.sweep_every,
        stop_rx.clone(),
    ));

    let token = cfg.token.clone();
    let mut accept_stop = stop_rx;
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accept_stop.changed() => return,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { return };
                    let rooms = rooms.clone();
                    let token = token.clone();
                    let id = conn_ids.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::spawn(async move {
                        handle_conn(stream, rooms, token, id, peer).await;
                    });
                }
            }
        }
    });
    Ok(RelayServer { addr, stop, handle })
}

async fn write_http<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &str,
) {
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

fn reason_of(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        426 => "Upgrade Required",
        _ => "OK",
    }
}

async fn handle_conn<S>(mut stream: S, rooms: Rooms, token: Option<String>, id: u64, peer: SocketAddr)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Read the request head ourselves (see module docs / spike).
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        let mut chunk = [0u8; 1024];
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HEAD {
            write_http(&mut stream, 400, "Bad Request", "request head too large").await;
            return;
        }
    };
    let head = match parse_head(&buf[..head_end]) {
        Ok(h) => h,
        Err(_) => {
            write_http(&mut stream, 400, "Bad Request", "bad request").await;
            return;
        }
    };
    match route(&head, token.as_deref()) {
        Route::Healthz => write_http(&mut stream, 200, "OK", "ok").await,
        Route::Reject { status, body } => {
            write_http(&mut stream, status, reason_of(status), body).await
        }
        Route::Join { room, role } => {
            let key = head.ws_key.expect("route guarantees a key");
            let accept = derive_accept_key(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
            );
            if stream.write_all(resp.as_bytes()).await.is_err() {
                return;
            }
            let pre = Prefixed {
                prefix: buf[head_end..].to_vec(),
                pos: 0,
                inner: stream,
            };
            let ws_cfg = WebSocketConfig::default().max_message_size(Some(MAX_MSG));
            let ws = WebSocketStream::from_raw_socket(pre, Role::Server, Some(ws_cfg)).await;
            eprintln!("relay: {peer} joined room {room} as {}", role.as_str());
            run_room_conn(ws, rooms, room, role, id).await;
        }
    }
}

/// Register in the room (takeover semantics), then pump messages until the
/// socket or the room says stop. Mirrors relay-worker/src/index.js.
async fn run_room_conn<S>(
    ws: WebSocketStream<Prefixed<S>>,
    rooms: Rooms,
    room: String,
    role: RoomRole,
    id: u64,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // Join with takeover: close any existing same-role socket (1012); it
    // discovers it was replaced at cleanup (its id no longer registered)
    // and stays silent — the peer keeps its pairing.
    {
        let mut map = rooms.lock().expect("rooms lock");
        let state = map.entry(room.clone()).or_default();
        if let Some(old) = state.slot_mut(role).take() {
            let _ = old.tx.send(Message::Close(Some(CloseFrame {
                code: CloseCode::from(1012),
                reason: "replaced by a new connection".into(),
            })));
            eprintln!("relay: room {room} {} taken over", role.as_str());
        }
        *state.slot_mut(role) = Some(Slot { tx: tx.clone(), id });
        if state.slot_mut(role.other()).is_some() {
            for r in [role, role.other()] {
                if let Some(s) = state.slot_mut(r) {
                    let _ = s.tx.send(Message::Text(PEER_JOINED.into()));
                }
            }
            state.alone_since = None;
        } else {
            state.alone_since = Some(Instant::now());
        }
    }

    let (mut sink, mut stream) = ws.split();
    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Some(m @ Message::Close(_)) => { let _ = sink.send(m).await; break; }
                Some(m) => { if sink.send(m).await.is_err() { break; } }
                None => break,
            },
            item = stream.next() => match item {
                Some(Ok(Message::Text(t))) if t == PING => {
                    if sink.send(Message::Text(PONG.into())).await.is_err() { break; }
                }
                Some(Ok(m @ (Message::Text(_) | Message::Binary(_)))) => {
                    let peer_tx = {
                        let mut map = rooms.lock().expect("rooms lock");
                        map.get_mut(&room)
                            .and_then(|s| s.slot_mut(role.other()).as_ref().map(|p| p.tx.clone()))
                    };
                    if let Some(p) = peer_tx {
                        let _ = p.send(m);
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }

    // Cleanup with takeover suppression: only the currently-registered
    // connection (same id) announces its departure.
    let mut map = rooms.lock().expect("rooms lock");
    if let Some(state) = map.get_mut(&room) {
        let mine = state
            .slot_mut(role)
            .as_ref()
            .is_some_and(|s| s.id == id);
        if mine {
            *state.slot_mut(role) = None;
            if let Some(peer) = state.slot_mut(role.other()).as_ref() {
                let _ = peer.tx.send(Message::Text(PEER_LEFT.into()));
                state.alone_since = Some(Instant::now());
                eprintln!("relay: room {room} {} left", role.as_str());
            }
            if state.occupancy() == 0 {
                map.remove(&room);
            }
        }
    }
}

/// Close (1013) any socket that has been alone in its room too long —
/// the Worker's alarm, as a sweep.
async fn sweeper(
    rooms: Rooms,
    expire: Duration,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = stop.changed() => return,
        }
        let mut map = rooms.lock().expect("rooms lock");
        for (room, state) in map.iter_mut() {
            if state.alone_since.is_some_and(|t| t.elapsed() >= expire) {
                for role in [RoomRole::Send, RoomRole::Recv] {
                    if let Some(s) = state.slot_mut(role).as_ref() {
                        let _ = s.tx.send(Message::Close(Some(CloseFrame {
                            code: CloseCode::from(1013),
                            reason: "room expired".into(),
                        })));
                    }
                }
                eprintln!("relay: room {room} expired");
            }
        }
    }
}
```

Note on `WebSocketConfig`: in tokio-tungstenite 0.30 it's constructed builder-style (`WebSocketConfig::default().max_message_size(Some(MAX_MSG))`); if the compiler objects, use the struct-update form the crate documents for that version — the requirement is only `max_message_size = Some(MAX_MSG)`.

Also add `reqwest` availability for the tests: it's already a main dependency (used by `http.rs`), so the test module can use it directly.

- [ ] **Step 4: Run tests** — `cargo test --lib relay_server` → PASS.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/relay_server.rs
git commit -m "feat: relay server core — rooms, pairing, forwarding, ping (relay serve)"
```

---

### Task 3: Takeover + expiry behavior tests

The mechanics landed in Task 2; this task pins them with tests a reviewer can trust (they encode the Worker-parity rules that reviews caught bugs in before).

**Files:**
- Modify: `src/relay_server.rs` (tests only)

- [ ] **Step 1: Write the tests:**

```rust
    #[tokio::test]
    async fn takeover_replaces_old_socket_without_spurious_peer_left() {
        let srv = spawn_server(ServeCfg::default()).await;
        let mut recv = ws_client(srv.addr, "roomT", "recv").await;
        let mut send1 = ws_client(srv.addr, "roomT", "send").await;
        assert_eq!(next_text(&mut recv).await, r#"{"t":"peer-joined"}"#);
        assert_eq!(next_text(&mut send1).await, r#"{"t":"peer-joined"}"#);

        let mut send2 = ws_client(srv.addr, "roomT", "send").await;
        // the old sender is closed by the server (1012)
        let old_closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match send1.next().await {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    _ => continue,
                }
            }
        })
        .await;
        assert!(old_closed.is_ok(), "old sender must be closed on takeover");
        // the newcomer pairs; the receiver hears peer-joined, NOT peer-left
        assert_eq!(next_text(&mut send2).await, r#"{"t":"peer-joined"}"#);
        assert_eq!(
            next_text(&mut recv).await,
            r#"{"t":"peer-joined"}"#,
            "receiver must re-pair without a spurious peer-left"
        );
        // and the new pairing forwards
        send2.send(Message::Binary(vec![1, 2, 3].into())).await.unwrap();
        loop {
            match recv.next().await.unwrap().unwrap() {
                Message::Binary(b) => {
                    assert_eq!(b.as_ref(), &[1, 2, 3]);
                    break;
                }
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn lone_room_expires_and_paired_room_does_not() {
        let srv = spawn_server(ServeCfg {
            expire_unpaired: std::time::Duration::from_millis(300),
            sweep_every: std::time::Duration::from_millis(100),
            ..Default::default()
        })
        .await;
        // paired room survives well past the expiry window
        let mut r1 = ws_client(srv.addr, "paired", "recv").await;
        let mut s1 = ws_client(srv.addr, "paired", "send").await;
        let _ = next_text(&mut r1).await;
        let _ = next_text(&mut s1).await;
        // lone room gets closed with 1013
        let mut lone = ws_client(srv.addr, "lone", "recv").await;
        let expired = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match lone.next().await {
                    Some(Ok(Message::Close(f))) => break f,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break None,
                }
            }
        })
        .await
        .expect("lone room must be expired");
        if let Some(f) = expired {
            assert_eq!(u16::from(f.code), 1013, "close code should be 1013");
        }
        // the paired room is still alive and forwarding
        s1.send(Message::Binary(vec![7].into())).await.unwrap();
        loop {
            match r1.next().await.unwrap().unwrap() {
                Message::Binary(b) => {
                    assert_eq!(b.as_ref(), &[7]);
                    break;
                }
                _ => continue,
            }
        }
    }
```

- [ ] **Step 2: Run** — `cargo test --lib relay_server` → PASS (if the takeover/expiry code from Task 2 has gaps, fix them here; both behaviors are already implemented).

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/relay_server.rs
git commit -m "test: pin takeover suppression and room expiry (relay serve)"
```

---

### Task 4: The test suite runs against the real server

**Files:**
- Rewrite: `src/transport/mock.rs`
- Modify: `src/transport/relay.rs` (ONLY the test `duplicate_role_is_a_room_busy_error`)

**Interfaces:**
- `mock::start() -> MockRelay { pub url: String }` keeps its exact shape — every existing caller (relay/session/doctor tests) compiles unchanged, now against production code.
- The real server does takeover (no 409), so the client's RoomBusy test gets a 10-line inline stub that always answers HTTP 409.

- [ ] **Step 1: Rewrite `src/transport/mock.rs` entirely:**

```rust
//! Test fixture: spawns the REAL relay server (src/relay_server.rs) on an
//! ephemeral port, so the offline suite exercises production relay code.
//! (Until `relay serve` existed this file carried a hand-rolled lookalike;
//! the conformance suite relay-worker/test.mjs guards Worker parity.)

use crate::relay_server::{start, RelayServer, ServeCfg};

pub struct MockRelay {
    pub url: String,
    _server: RelayServer, // Drop aborts the accept loop
}

/// Kept as `start` so every existing test compiles unchanged.
pub async fn start() -> MockRelay {
    let server = crate::relay_server::start(ServeCfg {
        listen: "127.0.0.1:0".parse().expect("addr"),
        ..Default::default()
    })
    .await
    .expect("relay server starts");
    MockRelay {
        url: format!("ws://{}", server.addr),
        _server: server,
    }
}
```

(Adjust the `use` line accordingly: `use crate::relay_server::{RelayServer, ServeCfg};`.)

- [ ] **Step 2: Replace the 409 test** in `src/transport/relay.rs` — the real server takes over instead of rejecting, so `duplicate_role_is_a_room_busy_error` becomes a stub-driven classification test:

```rust
    #[tokio::test]
    async fn http_409_maps_to_room_busy() {
        // The real server (like the Worker) does takeover, so 409 comes only
        // from older/stale deployments — pin the client's classification
        // with a stub that always answers 409.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 409 Conflict\r\ncontent-length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        let e = connect(
            &url,
            "roomDup",
            Role::Receiver,
            None,
            &TlsOpts::default(),
            Duration::from_secs(5),
        )
        .await
        .err()
        .expect("409 must be an error");
        assert!(e.downcast_ref::<RoomBusy>().is_some(), "got: {e:#}");
    }
```

Delete the old `duplicate_role_is_a_room_busy_error` test.

- [ ] **Step 3: Run the whole suite** — `cargo test` → ALL PASS. Every relay/session/doctor test now exercises `relay_server.rs`. If any test hangs or fails, the server has a parity gap vs the old mock — fix the server, not the test.

- [ ] **Step 4: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/transport/mock.rs src/transport/relay.rs
git commit -m "test: offline suite now runs against the real relay server (relay serve)"
```

---

### Task 5: Built-in TLS

**Files:**
- Modify: `src/relay_server.rs`

**Interfaces:** `ServeCfg.tls: Option<(PathBuf, PathBuf)>` (cert, key) becomes functional; `start()` loads them at startup (fail fast on bad files).

- [ ] **Step 1: Write the failing test** (rcgen is already a dev-dependency):

```rust
    #[tokio::test]
    async fn tls_serves_wss_end_to_end() {
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("cert");
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

        let srv = spawn_server(ServeCfg {
            tls: Some((cert_path.clone(), key_path)),
            ..Default::default()
        })
        .await;
        // full client stack through TLS: RelayChannel with --cafile trust
        let tls = crate::http::TlsOpts {
            cafile: Some(cert_path),
        };
        let url = format!("wss://127.0.0.1:{}", srv.addr.port());
        let (r, s) = tokio::join!(
            crate::transport::relay::connect(
                &url,
                "roomTls",
                crate::pake::Role::Receiver,
                None,
                &tls,
                std::time::Duration::from_secs(10)
            ),
            crate::transport::relay::connect(
                &url,
                "roomTls",
                crate::pake::Role::Sender,
                None,
                &tls,
                std::time::Duration::from_secs(10)
            )
        );
        use crate::stream::MsgChannel;
        let (mut r, mut s) = (r.unwrap(), s.unwrap());
        s.send(b"over tls").await.unwrap();
        assert_eq!(r.recv().await.unwrap(), b"over tls");
    }
```

(Check rcgen 0.13's exact accessor names — `cert.cert.pem()` / `cert.signing_key.serialize_pem()` — against how `tlsprobe`'s tests already use rcgen in this repo, and match that usage.)

- [ ] **Step 2: Run to verify failure** — fails on `ensure!(cfg.tls.is_none())`.

- [ ] **Step 3: Implement.** Replace the `ensure!` in `start()` with acceptor construction, and generalize the accept loop:

```rust
fn tls_acceptor(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_path).with_context(|| format!("opening {}", cert_path.display()))?,
    ))
    .collect::<Result<_, _>>()
    .context("parsing TLS certificates")?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {}", cert_path.display());
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key_path).with_context(|| format!("opening {}", key_path.display()))?,
    ))
    .context("parsing TLS key")?
    .context("no private key found")?;
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol setup")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("building TLS config")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}
```

In `start()`:

```rust
    let acceptor = match &cfg.tls {
        Some((cert, key)) => Some(tls_acceptor(cert, key)?),
        None => None,
    };
```

and in the accept arm:

```rust
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { return };
                    let rooms = rooms.clone();
                    let token = token.clone();
                    let acceptor = acceptor.clone();
                    let id = conn_ids.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::spawn(async move {
                        match acceptor {
                            Some(a) => match a.accept(stream).await {
                                Ok(tls) => handle_conn(tls, rooms, token, id, peer).await,
                                Err(e) => eprintln!("relay: TLS handshake from {peer} failed: {e}"),
                            },
                            None => handle_conn(stream, rooms, token, id, peer).await,
                        }
                    });
                }
```

- [ ] **Step 4: Run tests** — `cargo test --lib relay_server` → PASS.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/relay_server.rs
git commit -m "feat: optional built-in TLS for relay serve (relay serve)"
```

---

### Task 6: CLI — `b2p relay serve`

**Files:**
- Modify: `src/main.rs` (`RelayCmd` + handler)

**Interfaces:** `b2p relay serve [--listen 0.0.0.0:9009] [--token T] [--tls-cert C --tls-key K]`; token falls back to env `RELAY_TOKEN`; ctrl-c shuts down gracefully.

- [ ] **Step 1: Extend `RelayCmd`:**

```rust
    /// Run a relay server on this machine (protocol-compatible with the
    /// Cloudflare Worker in relay-worker/).
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:9009")]
        listen: std::net::SocketAddr,
        /// Require this bearer token (falls back to env RELAY_TOKEN)
        #[arg(long)]
        token: Option<String>,
        /// PEM certificate chain — serve TLS directly (else put a proxy in front)
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
```

- [ ] **Step 2: Handle it in `run()`'s `Cmd::Relay` match:**

```rust
            RelayCmd::Serve {
                listen,
                token,
                tls_cert,
                tls_key,
            } => {
                let token = token.or_else(|| std::env::var("RELAY_TOKEN").ok());
                let tls = tls_cert.zip(tls_key);
                let secure = tls.is_some();
                let cfg = b2p::relay_server::ServeCfg {
                    listen,
                    token: token.clone(),
                    tls,
                    ..Default::default()
                };
                let server = b2p::relay_server::start(cfg).await?;
                eprintln!(
                    "b2p relay listening on {} ({}{})",
                    server.addr,
                    if secure { "wss — built-in TLS" } else { "ws — plain; put TLS (Caddy/nginx/ingress) in front for internet use" },
                    if token.is_some() { ", token required" } else { "" },
                );
                tokio::signal::ctrl_c().await?;
                eprintln!("shutting down");
                server.shutdown().await;
                Ok(())
            }
```

- [ ] **Step 3: Add a bin test** (in `src/main.rs`'s test module):

```rust
    #[test]
    fn relay_serve_flags_validate() {
        use clap::Parser;
        // tls flags require each other
        assert!(Cli::try_parse_from(["b2p", "relay", "serve", "--tls-cert", "c.pem"]).is_err());
        assert!(Cli::try_parse_from(["b2p", "relay", "serve", "--tls-key", "k.pem"]).is_err());
        // happy path parses with a custom listen addr
        let cli =
            Cli::try_parse_from(["b2p", "relay", "serve", "--listen", "127.0.0.1:7777"]).unwrap();
        match cli.cmd {
            Cmd::Relay { cmd: RelayCmd::Serve { listen, .. } } => {
                assert_eq!(listen.port(), 7777);
            }
            _ => panic!("expected relay serve"),
        }
    }
```

- [ ] **Step 4: Manual verification (REQUIRED — the conformance suite against the real binary):**

```bash
cargo build
./target/debug/b2p relay serve --listen 127.0.0.1:9010 &
sleep 1
node relay-worker/test.mjs ws://127.0.0.1:9010     # expect: ALL OK
# and a real transfer through it:
mkdir -p /tmp/rs-out && echo "native relay $(date +%s)" > /tmp/rs-in.txt
B2P_RELAY=ws://127.0.0.1:9010 ./target/debug/b2p receive --out /tmp/rs-out --yes &
sleep 2  # grab the printed short code from the receiver output
B2P_RELAY=ws://127.0.0.1:9010 ./target/debug/b2p send '<code>' /tmp/rs-in.txt
diff /tmp/rs-in.txt /tmp/rs-out/rs-in.txt && echo NATIVE-RELAY-OK
kill %1
```

Expected: `ALL OK` from test.mjs and `NATIVE-RELAY-OK`.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/main.rs
git commit -m "feat: b2p relay serve CLI (relay serve)"
```

---

### Task 7: CI conformance step

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append to the `test` job's steps** (after the `Test` step; runners ship Node 20, the conformance script needs ≥22 for the WebSocket global):

```yaml
      - name: Set up Node 22 (conformance script)
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Relay conformance (test.mjs vs b2p relay serve)
        run: |
          cargo build
          ./target/debug/b2p relay serve --listen 127.0.0.1:9009 &
          SERVER=$!
          sleep 2
          node relay-worker/test.mjs ws://127.0.0.1:9009
          kill $SERVER
```

- [ ] **Step 2: Commit** (CI proves it on push):

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run relay-worker conformance suite against b2p relay serve (relay serve)"
```

---

### Task 8: Docker image + GHCR publish

**Files:**
- Create: `Dockerfile`
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Write `Dockerfile`** (repo root; built in CI from the already-compiled static musl binary placed at `./b2p`):

```dockerfile
# Built by release.yml from the static musl binary — image ≈ binary size.
# Local build: put a x86_64-unknown-linux-musl `b2p` binary at ./b2p first.
FROM scratch
COPY b2p /b2p
EXPOSE 9009
ENTRYPOINT ["/b2p", "relay", "serve"]
```

- [ ] **Step 2: Add the job to `.github/workflows/release.yml`** (after the `release` job):

```yaml
  docker:
    name: Publish Docker image
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Download linux binary
        uses: actions/download-artifact@v4
        with:
          name: b2p-linux-x86_64.tar.gz

      - name: Extract binary
        run: tar xzf b2p-linux-x86_64.tar.gz b2p && chmod +x b2p

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        run: |
          IMAGE=ghcr.io/${{ github.repository }}
          docker build -t "$IMAGE:${GITHUB_REF_NAME}" -t "$IMAGE:latest" .
          docker push "$IMAGE:${GITHUB_REF_NAME}"
          docker push "$IMAGE:latest"
```

- [ ] **Step 3: Local sanity** (no push): `docker build` needs a musl binary; if `musl-gcc` isn't installed locally, skip the local build — the workflow is exercised by the next release tag. At minimum: `docker --version` works and the Dockerfile lints by eye (4 lines).

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .github/workflows/release.yml
git commit -m "feat: Docker image for relay serve, pushed to GHCR on release (relay serve)"
```

---

### Task 9: Docs + backlog + final verification

**Files:**
- Modify: `README.md`, `todo.md`, `docs/superpowers/specs/2026-07-23-b2p-relay-serve-design.md` (as-built note if anything deviated)

- [ ] **Step 1: README** — add a "Self-host the relay (alternative to Cloudflare)" section after the deploy-your-relay section:

```markdown
## Self-host the relay (alternative to Cloudflare)

The same `b2p` binary can be the relay — any VPS, home server, or container
platform works:

    b2p relay serve                          # plain ws on 0.0.0.0:9009
    b2p relay serve --token S3CR3T           # require a bearer token
    b2p relay serve --tls-cert c.pem --tls-key k.pem   # built-in TLS

or with Docker:

    docker run -p 9009:9009 -e RELAY_TOKEN=S3CR3T ghcr.io/campiohe/b2p:latest

For internet use put TLS in front (unless using --tls-cert). Caddy does it in
two lines with automatic Let's Encrypt certificates:

    relay.example.com {
        reverse_proxy 127.0.0.1:9009
    }

(Kubernetes: terminate TLS at the ingress and point it at port 9009.) Then on
each machine: `b2p relay set wss://relay.example.com`. The Cloudflare Worker
(`relay-worker/`) and `b2p relay serve` implement the same protocol and are
interchangeable; `relay-worker/test.mjs` is the conformance suite for both.
```

Also update the Notes bullet about `cargo test` to mention the offline suite runs against the built-in relay server.

- [ ] **Step 2: `todo.md`** — under a new "relay serve — shipped" entry, mark the self-host relay delivered (pointer to spec/plan); add follow-ups: ACME built-in certs (only with demand), metrics endpoint (only with demand), publish a standalone protocol document if third-party relays appear.

- [ ] **Step 3: Spec as-built note** — if implementation deviated anywhere (e.g. `WebSocketConfig` construction, rcgen accessors), add a short "As-built notes" block to the spec; otherwise skip.

- [ ] **Step 4: Final whole-feature verification**

1. `cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test` — green.
2. `node relay-worker/test.mjs ws://127.0.0.1:<port>` against a running `b2p relay serve` — ALL OK.
3. Real transfer through `b2p relay serve` (Task 6 Step 4 repeated) — byte-identical.
4. TLS path: covered by the `tls_serves_wss_end_to_end` test.
5. Whole-branch review (project rule — it has caught real bugs every phase), attention on: rooms mutex around forwarding (deadlocks/poisoning), takeover id-suppression race, sweeper vs join interleavings, head-parse on adversarial input (oversized/split/pipelined requests), and the Docker/CI YAML.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add README.md todo.md docs/superpowers/specs/2026-07-23-b2p-relay-serve-design.md
git commit -m "docs: self-host relay guide, backlog update (relay serve)"
```
