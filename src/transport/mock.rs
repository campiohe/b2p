//! In-process relay speaking protocol v1 for offline tests. Mirrors
//! relay-worker/src/index.js; the live smoke (tests/relay_live.rs) guards
//! against drift from the real Worker.
//!
//! One DELIBERATE divergence: a duplicate-role join gets HTTP 409 here,
//! while the real Worker performs a takeover (closes the old socket). The
//! mock models the stale-socket case so the client's RoomBusy retry path
//! has offline coverage; the Worker side is covered by relay-worker/test.mjs.

use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::Message;

type Peers = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Message>>>>;

pub struct MockRelay {
    pub url: String,
    shutdown: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        if let Some(h) = self.shutdown.take() {
            h.abort();
        }
    }
}

fn send_to(key: &str, m: Message, peers: &Peers) {
    if let Some(tx) = peers.lock().expect("lock").get(key) {
        let _ = tx.send(m);
    }
}

pub async fn start() -> MockRelay {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("addr"));
    let peers: Peers = Arc::new(Mutex::new(HashMap::new()));
    let accept_loop = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let peers = peers.clone();
            tokio::spawn(async move {
                let mut path = String::new();
                let cb_peers = peers.clone();
                // The Err type (an http::Response) is tungstenite's Callback
                // contract, not ours.
                #[allow(clippy::result_large_err)]
                let ws =
                    tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
                        path = req.uri().to_string();
                        // 409 on duplicate role — see module docs.
                        if let Some((room, role)) = path
                            .strip_prefix("/v1/room/")
                            .and_then(|r| r.split_once("?role="))
                        {
                            let key = format!("{room}/{role}");
                            if cb_peers.lock().expect("lock").contains_key(&key) {
                                let mut err = tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(None);
                                *err.status_mut() =
                                    tokio_tungstenite::tungstenite::http::StatusCode::CONFLICT;
                                return Err(err);
                            }
                        }
                        Ok(resp)
                    })
                    .await;
                let Ok(ws) = ws else { return };
                // path: /v1/room/<room>?role=<role>
                let (room, role) = match path
                    .strip_prefix("/v1/room/")
                    .and_then(|r| r.split_once("?role="))
                {
                    Some((room, role)) => (room.to_string(), role.to_string()),
                    None => return,
                };
                let me = format!("{room}/{role}");
                let them = format!("{room}/{}", if role == "send" { "recv" } else { "send" });
                let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
                let joined = {
                    let mut map = peers.lock().expect("lock");
                    map.insert(me.clone(), tx);
                    map.contains_key(&them)
                };
                if joined {
                    send_to(&me, Message::Text(r#"{"t":"peer-joined"}"#.into()), &peers);
                    send_to(
                        &them,
                        Message::Text(r#"{"t":"peer-joined"}"#.into()),
                        &peers,
                    );
                }
                let (mut sink, mut stream) = ws.split();
                loop {
                    tokio::select! {
                        out = rx.recv() => match out {
                            Some(m) => { if sink.send(m).await.is_err() { break; } }
                            None => break,
                        },
                        item = stream.next() => match item {
                            Some(Ok(Message::Text(t))) if t == r#"{"t":"ping"}"# => {
                                send_to(&me, Message::Text(r#"{"t":"pong"}"#.into()), &peers);
                            }
                            Some(Ok(m @ (Message::Text(_) | Message::Binary(_)))) => {
                                send_to(&them, m, &peers);
                            }
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => {}
                        },
                    }
                }
                peers.lock().expect("lock").remove(&me);
                send_to(&them, Message::Text(r#"{"t":"peer-left"}"#.into()), &peers);
            });
        }
    });
    MockRelay {
        url,
        shutdown: Some(accept_loop),
    }
}
