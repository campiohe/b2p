//! Relay transport (P2b): a WebSocket to the operator's Cloudflare Worker,
//! which pairs the two peers in a room and forwards opaque messages. Both
//! sides dial outbound 443, so this works on the UDP-blocked and CGNAT
//! networks where WebRTC cannot form. Every frame is sealed before it
//! reaches the socket — the relay carries ciphertext only.
//!
//! Wire format (protocol v1, mirrored by relay-worker/): binary WS messages
//! carry one or more `u32 LE header || bytes` pieces — the header's low 31
//! bits are the piece length, the MSB says "this logical frame continues in
//! a later piece" (so a frame larger than Workers' 1 MiB message cap still
//! travels). Text WS messages are small JSON controls.

use crate::http::TlsOpts;
use crate::pake::Role;
use crate::stream::MsgChannel;
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};

pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const ACK_EVERY: u64 = 1024 * 1024;
const WINDOW: u64 = 8 * 1024 * 1024;
const PING_EVERY: Duration = Duration::from_secs(30);
const PING: &str = r#"{"t":"ping"}"#;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Cloudflare Workers reject WS messages over 1 MiB; stay well under.
pub const MAX_WS_PAYLOAD: usize = 960 * 1024;
const CONT: u32 = 1 << 31;

/// Drain `pending` logical frames into one WS payload. A frame that doesn't
/// fit is split; the continuation bit on a piece's header says "the next
/// piece of this logical frame follows in a later payload".
pub fn pack_frames(pending: &mut VecDeque<Vec<u8>>) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(front) = pending.front_mut() {
        let room = MAX_WS_PAYLOAD.saturating_sub(buf.len() + 4);
        if room == 0 {
            break;
        }
        if front.len() <= room {
            let f = pending.pop_front().expect("front exists");
            buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            buf.extend_from_slice(&f);
        } else {
            let rest = front.split_off(room);
            let piece = std::mem::replace(front, rest);
            buf.extend_from_slice(&((piece.len() as u32) | CONT).to_le_bytes());
            buf.extend_from_slice(&piece);
            break; // payload is full
        }
    }
    (!buf.is_empty()).then_some(buf)
}

/// Reassembles logical frames from WS payloads, buffering continuations.
#[derive(Default)]
pub struct Debatcher {
    partial: Vec<u8>,
}

impl Debatcher {
    pub fn push(&mut self, mut p: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        while !p.is_empty() {
            if p.len() < 4 {
                bail!("truncated sub-frame header");
            }
            let hdr = u32::from_le_bytes(p[..4].try_into().expect("4 bytes"));
            let (cont, len) = (hdr & CONT != 0, (hdr & !CONT) as usize);
            p = &p[4..];
            if p.len() < len {
                bail!("truncated sub-frame body");
            }
            self.partial.extend_from_slice(&p[..len]);
            p = &p[len..];
            if !cont {
                out.push(std::mem::take(&mut self.partial));
            }
        }
        Ok(out)
    }
}

/// Marks a mid-session loss of the relay connection, so callers can re-arm
/// and resume instead of treating it as fatal. Mirrors `EstablishError`.
#[derive(Debug)]
pub struct TransportLost(pub anyhow::Error);
impl std::fmt::Display for TransportLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}
impl std::error::Error for TransportLost {}

fn lost(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(TransportLost(anyhow!(msg.into())))
}

pub fn normalize_relay_url(s: &str) -> anyhow::Result<String> {
    let s = s.trim().trim_end_matches('/');
    for (from, to) in [("https://", "wss://"), ("http://", "ws://")] {
        if let Some(rest) = s.strip_prefix(from) {
            return Ok(format!("{to}{rest}"));
        }
    }
    if s.starts_with("wss://") || s.starts_with("ws://") {
        return Ok(s.to_string());
    }
    anyhow::bail!("relay URL must start with wss:// or https:// (got '{s}')");
}

/// OS trust store + optional --cafile, with an explicit ring provider (the
/// dep tree may also link aws-lc; a bare builder() panics on ambiguity).
fn tls_connector(tls: &TlsOpts) -> anyhow::Result<Connector> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    if let Some(path) = &tls.cafile {
        for der in crate::tlsprobe::load_pem_roots(path)? {
            roots.add(der)?;
        }
    }
    anyhow::ensure!(!roots.is_empty(), "no trusted TLS roots available");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol setup")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

#[derive(Debug, PartialEq)]
enum Control {
    PeerJoined,
    PeerLeft,
    Pong,
    Ack(u64),
}

fn parse_control(t: &str) -> Option<Control> {
    let v: serde_json::Value = serde_json::from_str(t).ok()?;
    match v.get("t")?.as_str()? {
        "peer-joined" => Some(Control::PeerJoined),
        "peer-left" => Some(Control::PeerLeft),
        "pong" => Some(Control::Pong),
        "ack" => Some(Control::Ack(v.get("n")?.as_u64()?)),
        _ => None,
    }
}

async fn dial(
    relay_url: &str,
    room: &str,
    role: Role,
    token: Option<&str>,
    tls: &TlsOpts,
) -> anyhow::Result<Ws> {
    let base = normalize_relay_url(relay_url)?;
    let role_s = match role {
        Role::Receiver => "recv",
        Role::Sender => "send",
    };
    let mut req = format!("{base}/v1/room/{room}?role={role_s}").into_client_request()?;
    if let Some(t) = token {
        req.headers_mut()
            .insert("authorization", format!("Bearer {t}").parse()?);
    }
    let connector = tls_connector(tls)?; // unused for ws:// but cheap
                                         // third arg disables Nagle: our WS messages are already batched, and
                                         // small ack/control frames must not be delayed.
    let (ws, _resp) = tokio::time::timeout(
        RELAY_CONNECT_TIMEOUT,
        connect_async_tls_with_config(req, None, true, Some(connector)),
    )
    .await
    .map_err(|_| anyhow!("timed out connecting to the relay {base}"))?
    .map_err(|e| relay_dial_help(e, &base))?;
    Ok(ws)
}

/// Turn tungstenite's HTTP-rejection errors into actionable messages.
fn relay_dial_help(e: tokio_tungstenite::tungstenite::Error, base: &str) -> anyhow::Error {
    use tokio_tungstenite::tungstenite::Error::Http;
    if let Http(resp) = &e {
        return match resp.status().as_u16() {
            401 => anyhow!(
                "the relay {base} requires a token — set it with `b2p relay set {base} --token <T>` or B2P_RELAY_TOKEN"
            ),
            409 => anyhow!(
                "another transfer is already using this code's room on {base} — get a fresh code and try again"
            ),
            s => anyhow!("the relay {base} refused the connection (HTTP {s})"),
        };
    }
    anyhow::Error::new(e).context(format!("could not connect to the relay {base}"))
}

pub async fn connect(
    relay_url: &str,
    room: &str,
    role: Role,
    token: Option<&str>,
    tls: &TlsOpts,
    wait_peer: Duration,
) -> anyhow::Result<RelayChannel> {
    let mut ws = dial(relay_url, room, role, token, tls).await?;
    // Wait for the peer, pinging so NATs/proxies keep the idle socket alive.
    let deadline = tokio::time::Instant::now() + wait_peer;
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                anyhow::bail!("timed out waiting for the other side — is it running with the same code?");
            }
            _ = ping.tick() => {
                ws.send(Message::Text(PING.into())).await
                    .context("relay connection dropped while waiting")?;
            }
            item = ws.next() => {
                let msg = item
                    .ok_or_else(|| anyhow!("the relay closed the connection while waiting"))?
                    .context("relay connection failed while waiting")?;
                match msg {
                    Message::Text(t) => {
                        if parse_control(&t) == Some(Control::PeerJoined) { break; }
                    }
                    Message::Close(_) => anyhow::bail!("the relay closed the connection while waiting (room expired?)"),
                    _ => {}
                }
            }
        }
    }
    Ok(RelayChannel::spawn(ws))
}

enum OutMsg {
    Frame(Vec<u8>),
    Close,
}

pub struct RelayChannel {
    out_tx: mpsc::UnboundedSender<OutMsg>,
    in_rx: mpsc::Receiver<Vec<u8>>,
    acked_rx: watch::Receiver<u64>,
    dead_rx: watch::Receiver<Option<String>>,
    sent: u64,
}

impl RelayChannel {
    fn spawn(ws: Ws) -> RelayChannel {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::channel(64);
        let (acked_tx, acked_rx) = watch::channel(0u64);
        let (dead_tx, dead_rx) = watch::channel(None);
        tokio::spawn(io_task(ws, out_rx, in_tx, acked_tx, dead_tx));
        RelayChannel {
            out_tx,
            in_rx,
            acked_rx,
            dead_rx,
            sent: 0,
        }
    }

    fn death_reason(&self, fallback: &str) -> anyhow::Error {
        let reason = self
            .dead_rx
            .borrow()
            .clone()
            .unwrap_or_else(|| fallback.to_string());
        lost(reason)
    }

    /// Flush queued frames and close the socket; bounded.
    pub async fn close(mut self) {
        let _ = self.out_tx.send(OutMsg::Close);
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while self.dead_rx.borrow().is_none() {
                if self.dead_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
    }
}

#[async_trait]
impl MsgChannel for RelayChannel {
    async fn send(&mut self, msg: &[u8]) -> anyhow::Result<()> {
        // Window check. watch::changed() is version-counted, so an ack that
        // lands between borrow() and changed() still wakes us — no lost-
        // wakeup race (the P2a close-latch lesson).
        loop {
            let acked = *self.acked_rx.borrow();
            if self.sent.saturating_sub(acked) + msg.len() as u64 <= WINDOW {
                break;
            }
            if self.acked_rx.changed().await.is_err() {
                return Err(self.death_reason("connection lost while sending"));
            }
        }
        self.sent += msg.len() as u64;
        self.out_tx
            .send(OutMsg::Frame(msg.to_vec()))
            .map_err(|_| self.death_reason("connection lost while sending"))?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<Vec<u8>> {
        self.in_rx
            .recv()
            .await
            .ok_or_else(|| self.death_reason("the other side disconnected"))
    }
}

async fn io_task(
    mut ws: Ws,
    mut out_rx: mpsc::UnboundedReceiver<OutMsg>,
    in_tx: mpsc::Sender<Vec<u8>>,
    acked_tx: watch::Sender<u64>,
    dead_tx: watch::Sender<Option<String>>,
) {
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut debatch = Debatcher::default();
    let mut consumed: u64 = 0;
    let mut acked_out: u64 = 0;
    let mut closing = false;
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let reason: String = 'io: loop {
        // Write-behind: flush everything queued before selecting again.
        // Frames queued while a ws.send was in flight batch automatically;
        // a lone frame goes out immediately. Bounded by the send window,
        // so this drain can't starve reads for long.
        if let Some(payload) = pack_frames(&mut pending) {
            if let Err(e) = ws.send(Message::Binary(payload.into())).await {
                break 'io format!("could not send to the relay: {e}");
            }
            continue;
        }
        if closing {
            let _ = ws.close(None).await;
            break 'io "closed".to_string();
        }
        tokio::select! {
            out = out_rx.recv() => match out {
                Some(OutMsg::Frame(f)) => pending.push_back(f),
                Some(OutMsg::Close) | None => closing = true,
            },
            _ = ping.tick() => {
                if ws.send(Message::Text(PING.into())).await.is_err() {
                    break 'io "relay connection dropped (keepalive failed)".to_string();
                }
            }
            item = ws.next() => {
                let msg = match item {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => break 'io format!("relay socket error: {e}"),
                    None => break 'io "the relay closed the connection".to_string(),
                };
                match msg {
                    Message::Binary(b) => {
                        let frames = match debatch.push(&b) {
                            Ok(f) => f,
                            Err(e) => break 'io format!("bad frame from the relay: {e}"),
                        };
                        for f in frames {
                            consumed += f.len() as u64;
                            if in_tx.send(f).await.is_err() {
                                // Local consumer is gone; wind down.
                                closing = true;
                                break;
                            }
                        }
                        if consumed - acked_out >= ACK_EVERY {
                            acked_out = consumed;
                            let ack = format!("{{\"t\":\"ack\",\"n\":{consumed}}}");
                            if ws.send(Message::Text(ack.into())).await.is_err() {
                                break 'io "relay connection dropped (ack failed)".to_string();
                            }
                        }
                    }
                    Message::Text(t) => match parse_control(&t) {
                        Some(Control::Ack(n)) => { let _ = acked_tx.send(n); }
                        Some(Control::PeerLeft) => break 'io "the other side disconnected".to_string(),
                        _ => {}
                    },
                    Message::Close(_) => break 'io "the relay closed the connection".to_string(),
                    _ => {}
                }
            }
        }
    };
    let _ = dead_tx.send(Some(reason));
    // Dropping in_tx / acked_tx here wakes any blocked recv()/send().
}

/// Doctor probe: join a throwaway room, round-trip a ping.
pub async fn probe(relay_url: &str, token: Option<&str>, tls: &TlsOpts) -> anyhow::Result<()> {
    let mut rnd = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    // hex keeps the room inside the worker's [A-Za-z0-9] charset
    let room = format!("doctor{}", hex::encode(rnd));
    let mut ws = dial(relay_url, &room, Role::Receiver, token, tls).await?;
    ws.send(Message::Text(PING.into())).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .map_err(|_| anyhow!("relay accepted the connection but never answered a ping"))?
            .ok_or_else(|| anyhow!("relay closed the connection during the probe"))??;
        if let Message::Text(t) = msg {
            if parse_control(&t) == Some(Control::Pong) {
                let _ = ws.close(None).await;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_frames_batch_into_one_payload() {
        let mut q: VecDeque<Vec<u8>> = [vec![1u8; 10], vec![2u8; 20]].into();
        let p = pack_frames(&mut q).unwrap();
        assert!(q.is_empty());
        assert_eq!(p.len(), 4 + 10 + 4 + 20);
        let mut d = Debatcher::default();
        assert_eq!(d.push(&p).unwrap(), vec![vec![1u8; 10], vec![2u8; 20]]);
    }

    #[test]
    fn oversized_frame_splits_and_reassembles() {
        let big = vec![7u8; MAX_WS_PAYLOAD * 2 + 123];
        let mut q: VecDeque<Vec<u8>> = [big.clone()].into();
        let mut d = Debatcher::default();
        let mut out = vec![];
        while let Some(p) = pack_frames(&mut q) {
            assert!(p.len() <= MAX_WS_PAYLOAD);
            out.extend(d.push(&p).unwrap());
        }
        assert_eq!(out, vec![big]);
    }

    #[test]
    fn empty_queue_yields_none() {
        assert!(pack_frames(&mut VecDeque::new()).is_none());
    }

    #[test]
    fn debatcher_rejects_garbage() {
        let mut d = Debatcher::default();
        assert!(d.push(&[1, 2, 3]).is_err()); // truncated header
        let mut bad = 5u32.to_le_bytes().to_vec(); // claims 5 bytes, has 2
        bad.extend_from_slice(&[9, 9]);
        assert!(Debatcher::default().push(&bad).is_err());
        drop(d);
    }

    #[test]
    fn normalizes_relay_urls() {
        assert_eq!(
            normalize_relay_url("https://x.dev/").unwrap(),
            "wss://x.dev"
        );
        assert_eq!(normalize_relay_url("wss://x.dev").unwrap(), "wss://x.dev");
        assert_eq!(
            normalize_relay_url("http://127.0.0.1:1").unwrap(),
            "ws://127.0.0.1:1"
        );
        assert!(normalize_relay_url("ftp://x").is_err());
        assert!(normalize_relay_url("x.dev").is_err());
    }

    #[tokio::test]
    async fn round_trips_frames_through_the_mock_relay() {
        let relay = crate::transport::mock::start().await;
        let tls = TlsOpts::default();
        let recv_fut = connect(
            &relay.url,
            "roomA",
            Role::Receiver,
            None,
            &tls,
            Duration::from_secs(10),
        );
        let send_fut = connect(
            &relay.url,
            "roomA",
            Role::Sender,
            None,
            &tls,
            Duration::from_secs(10),
        );
        let (r, s) = tokio::join!(recv_fut, send_fut);
        let (mut r, mut s) = (r.unwrap(), s.unwrap());
        s.send(b"hello").await.unwrap();
        // a logical frame bigger than one WS payload must arrive whole
        let big = vec![9u8; MAX_WS_PAYLOAD + 777];
        s.send(&big).await.unwrap();
        assert_eq!(r.recv().await.unwrap(), b"hello");
        assert_eq!(r.recv().await.unwrap(), big);
        // and the reverse direction works on the same channel
        r.send(b"ack-path").await.unwrap();
        assert_eq!(s.recv().await.unwrap(), b"ack-path");
    }

    #[tokio::test]
    async fn peer_death_errors_both_ops_instead_of_hanging() {
        let relay = crate::transport::mock::start().await;
        let tls = TlsOpts::default();
        let (r, s) = tokio::join!(
            connect(
                &relay.url,
                "roomB",
                Role::Receiver,
                None,
                &tls,
                Duration::from_secs(10)
            ),
            connect(
                &relay.url,
                "roomB",
                Role::Sender,
                None,
                &tls,
                Duration::from_secs(10)
            )
        );
        let (mut r, s) = (r.unwrap(), s.unwrap());
        drop(s); // abrupt sender death
        let got = tokio::time::timeout(Duration::from_secs(10), r.recv()).await;
        let err = got.expect("recv must not hang").expect_err("recv must Err");
        assert!(err.downcast_ref::<TransportLost>().is_some());
        let sent = tokio::time::timeout(Duration::from_secs(10), r.send(b"x")).await;
        assert!(sent.expect("send must not hang").is_err());
    }

    #[tokio::test]
    async fn sender_stalls_at_window_until_receiver_drains() {
        // The io task acks as it INGESTS (bounding what the relay buffers),
        // and its in_tx buffer holds 64 frames — so with the app not
        // consuming, a pump must stall near WINDOW (8 MiB) plus ~1 MiB of
        // local buffering, and resume once the app drains.
        let relay = crate::transport::mock::start().await;
        let tls = TlsOpts::default();
        let (r, s) = tokio::join!(
            connect(
                &relay.url,
                "roomC",
                Role::Receiver,
                None,
                &tls,
                Duration::from_secs(10)
            ),
            connect(
                &relay.url,
                "roomC",
                Role::Sender,
                None,
                &tls,
                Duration::from_secs(10)
            )
        );
        let (mut r, mut s) = (r.unwrap(), s.unwrap());
        let total: usize = 768; // 12 MiB of 16 KiB frames
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sent2 = sent.clone();
        let pump = tokio::spawn(async move {
            let chunk = vec![0u8; 16 * 1024];
            for _ in 0..total {
                s.send(&chunk).await.unwrap();
                sent2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            s
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        let stalled_at = sent.load(std::sync::atomic::Ordering::SeqCst);
        assert!(stalled_at < total, "pump must stall before {total} frames");
        // window (512 frames) + io buffers; anything ≤ ~11 MiB is a real stall
        assert!(stalled_at <= 704, "stall too late: {stalled_at} frames");
        for _ in 0..total {
            r.recv().await.unwrap();
        }
        let s = tokio::time::timeout(Duration::from_secs(10), pump)
            .await
            .expect("pump resumes after drain")
            .unwrap();
        drop(s);
    }

    #[tokio::test]
    async fn probe_round_trips_ping() {
        let relay = crate::transport::mock::start().await;
        probe(&relay.url, None, &TlsOpts::default()).await.unwrap();
    }
}
