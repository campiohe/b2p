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
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl RelayServer {
    /// Graceful stop: no new connections; existing sockets close as their
    /// tasks finish.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        if let Some(h) = &self.handle {
            h.abort();
        }
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
    Ok(RelayServer {
        addr,
        stop,
        handle: Some(handle),
    })
}

async fn write_http<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, reason: &str, body: &str) {
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

async fn handle_conn<S>(
    mut stream: S,
    rooms: Rooms,
    token: Option<String>,
    id: u64,
    peer: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
        let mine = state.slot_mut(role).as_ref().is_some_and(|s| s.id == id);
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
async fn sweeper(rooms: Rooms, expire: Duration, every: Duration, mut stop: watch::Receiver<bool>) {
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
            upgrade_hdr =
                std::str::from_utf8(h.value).is_ok_and(|v| v.eq_ignore_ascii_case("websocket"));
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
        return Route::Reject {
            status: 404,
            body: "not found",
        };
    };
    let (room, query) = rest.split_once('?').unwrap_or((rest, ""));
    if room.is_empty() || room.len() > 64 || !room.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Route::Reject {
            status: 404,
            body: "not found",
        };
    }
    if let Some(t) = token {
        if head.bearer.as_deref() != Some(t) {
            return Route::Reject {
                status: 401,
                body: "unauthorized",
            };
        }
    }
    if !head.is_upgrade || head.ws_key.is_none() {
        return Route::Reject {
            status: 426,
            body: "expected websocket",
        };
    }
    let role = match query.split('&').find_map(|kv| kv.strip_prefix("role=")) {
        Some("send") => RoomRole::Send,
        Some("recv") => RoomRole::Recv,
        _ => {
            return Route::Reject {
                status: 400,
                body: "bad role",
            }
        }
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
        assert_eq!(
            h.ws_key.as_deref(),
            Some(b"dGhlIHNhbXBsZSBub25jZQ==".as_slice())
        );

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
            route(
                &upgrade_head("/v1/room/abc?role=recv", Some("wrong")),
                Some("t")
            ),
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
        match route(
            &upgrade_head("/v1/room/Abc123?role=send", Some("t")),
            Some("t"),
        ) {
            Route::Join { room, role } => {
                assert_eq!(room, "Abc123");
                assert!(matches!(role, RoomRole::Send));
            }
            _ => panic!("expected Join"),
        }
    }

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
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let (ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/v1/room/{room}?role={role}"))
                .await
                .expect("connects");
        ws
    }

    async fn next_text(
        ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
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
        assert_eq!(
            client.get(http("/nope")).send().await.unwrap().status(),
            404
        );
        assert_eq!(
            client
                .get(http("/v1/room/abc?role=recv"))
                .send()
                .await
                .unwrap()
                .status(),
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
            client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
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
        send.send(Message::Binary(payload.clone().into()))
            .await
            .unwrap();
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
        recv.send(Message::Text(r#"{"t":"ack","n":1}"#.into()))
            .await
            .unwrap();
        assert_eq!(next_text(&mut send).await, r#"{"t":"ack","n":1}"#);
        // ping answered locally, not forwarded
        send.send(Message::Text(r#"{"t":"ping"}"#.into()))
            .await
            .unwrap();
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
