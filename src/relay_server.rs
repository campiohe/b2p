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

// TEMPORARY (removed when the server core lands in the next commit): the
// helpers below are consumed by handle_conn/start, which don't exist yet.
#![allow(dead_code)]

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
