//! ntfy.sh implementation of `Rendezvous`. Frames are base64-wrapped (ntfy
//! messages are UTF-8 text). Built on the P0 OS-trust HTTP client so it works
//! through an inspecting proxy. Subscribe pulls a recent cache window so a
//! peer that connects slightly late still sees the other's first frame.

use super::{parse_ntfy_message, Rendezvous};
use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use futures::stream::{BoxStream, StreamExt};
use tokio::io::AsyncBufReadExt;
use tokio_util::io::StreamReader;

/// How far back the subscribe stream pulls cached frames. Only needs to
/// cover a peer frame published just before this side subscribed — a live
/// peer never waits longer than the ~120s handshake step budget. Keeping
/// this short shrinks the stale-frame collision cross-section on
/// channel-shared topics (multiple transfers reusing the same topic).
const SINCE_WINDOW: &str = "3m";

pub struct NtfyRendezvous {
    base: String,
    client: reqwest::Client,
}

impl NtfyRendezvous {
    pub fn new(base: &str, tls: &crate::http::TlsOpts) -> anyhow::Result<NtfyRendezvous> {
        Ok(NtfyRendezvous {
            base: base.trim_end_matches('/').to_string(),
            client: crate::http::client(tls)?,
        })
    }
}

#[async_trait]
impl Rendezvous for NtfyRendezvous {
    async fn publish(&self, topic: &str, frame: &[u8]) -> anyhow::Result<()> {
        let body = base64::engine::general_purpose::STANDARD.encode(frame);
        self.client
            .post(format!("{}/{}", self.base, topic))
            .body(body)
            .send()
            .await
            .context("publishing to the rendezvous failed")?
            .error_for_status()
            .context("rendezvous rejected the publish")?;
        Ok(())
    }

    async fn subscribe(&self, topic: &str) -> anyhow::Result<BoxStream<'static, Vec<u8>>> {
        let url = format!("{}/{}/json?since={}", self.base, topic, SINCE_WINDOW);
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .context("subscribing to the rendezvous failed")?
            .error_for_status()
            .context("rendezvous rejected the subscribe")?;
        // reqwest byte stream -> AsyncRead -> line reader -> decoded frames
        let byte_stream = resp
            .bytes_stream()
            .map(|r| r.map_err(std::io::Error::other));
        let reader = tokio::io::BufReader::new(StreamReader::new(byte_stream));
        let lines = reader.lines();
        let out = futures::stream::unfold(lines, |mut lines| async move {
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if let Some(frame) = parse_ntfy_message(&line) {
                            return Some((frame, lines));
                        }
                        // open / keepalive / other — keep reading
                    }
                    _ => return None, // EOF or error ends the stream
                }
            }
        });
        Ok(out.boxed())
    }

    async fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::TlsOpts;
    use futures::StreamExt;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn publish_posts_base64_body_to_topic() {
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
        let seen2 = seen.clone();
        let app = axum::Router::new().route(
            "/{topic}",
            axum::routing::post(
                |axum::extract::Path(topic): axum::extract::Path<String>, body: String| async move {
                    seen2.lock().unwrap().push((topic, body));
                    "ok"
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let rv = NtfyRendezvous::new(&format!("http://{addr}"), &TlsOpts::default()).unwrap();
        rv.publish("mytopic", b"hello").await.unwrap();

        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "mytopic");
        // base64("hello") == "aGVsbG8="
        assert_eq!(got[0].1, "aGVsbG8=");
    }

    #[tokio::test]
    async fn subscribe_yields_decoded_message_frames() {
        // canned multi-line JSON body mimicking ntfy's stream, then EOF
        let body = concat!(
            r#"{"event":"open","topic":"t"}"#,
            "\n",
            r#"{"event":"message","topic":"t","message":"aGVsbG8="}"#,
            "\n",
            r#"{"event":"keepalive","topic":"t"}"#,
            "\n",
            r#"{"event":"message","topic":"t","message":"d29ybGQ="}"#,
            "\n",
        );
        let app = axum::Router::new().route(
            "/{topic}/json",
            axum::routing::get(move || async move { body }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let rv = NtfyRendezvous::new(&format!("http://{addr}"), &TlsOpts::default()).unwrap();
        let mut stream = rv.subscribe("t").await.unwrap();
        let mut got = vec![];
        while let Some(frame) = stream.next().await {
            got.push(frame);
        }
        assert_eq!(got, vec![b"hello".to_vec(), b"world".to_vec()]);
    }
}
