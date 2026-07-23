//! P1 session orchestration: run the PAKE handshake, form the WebRTC
//! transport, and move the payload — the composition `b2p receive`/`send`
//! use by default (design §5). Parameterized on a `Rendezvous` + STUN list
//! so it runs offline in tests (MemRendezvous + loopback). One handshake +
//! one transfer per call — a SessionKey is single-use (see stream::stream_key).

use crate::archive::Source;
use crate::handshake::handshake;
use crate::pake::Role;
use crate::protocol::Manifest;
use crate::rendezvous::Rendezvous;
use crate::stream::{recv_into, send_source, MsgChannel};
use crate::transport::webrtc::connect;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Marks an error as having occurred during *establishment* (handshake or
/// WebRTC connect) rather than during the transfer itself (design §6 scopes
/// `b2p doctor` to establishment failures — not to a declined transfer, a
/// hash mismatch, or a version mismatch, which are transfer-phase outcomes
/// no amount of network diagnosis explains). `main.rs`'s call sites use
/// `downcast_ref::<EstablishError>` to decide whether to run the doctor.
#[derive(Debug)]
pub struct EstablishError(pub anyhow::Error);
impl std::fmt::Display for EstablishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `{:#}` (not `{}`): anyhow's own alternate-Display chain-walking only
        // triggers for a `anyhow::Error` value itself (it walks the boxed
        // error's `std::error::Error::source()` chain, which a bare wrapper
        // struct like this doesn't have). Forcing alternate here bakes the
        // full "context: cause: cause" chain into this Display's own output,
        // so it survives being re-boxed into a new `anyhow::Error` by the
        // `?`/`From` conversion below — otherwise the cause chain (e.g. the
        // underlying reqwest/WebRTC error) would silently disappear from
        // whatever prints `e` afterwards, regardless of `{}` vs `{:#}` there.
        write!(f, "{:#}", self.0)
    }
}
impl std::error::Error for EstablishError {}

// 8 params matches the P1e interface contract exactly (Task 2's CLI calls
// this directly); a params struct would just move the same fields elsewhere.
#[allow(clippy::too_many_arguments)]
pub async fn receive_p1(
    rv: Arc<dyn Rendezvous>,
    topic: &str,
    secret: &[u8],
    out_dir: &Path,
    accept: impl FnOnce(&Manifest) -> bool + Send,
    stun: &[String],
    timeout: Duration,
    progress: Option<indicatif::ProgressBar>,
) -> anyhow::Result<String> {
    let key = handshake(rv.as_ref(), topic, secret, Role::Receiver)
        .await
        .map_err(EstablishError)?;
    let mut ch = connect(rv.clone(), topic, &key, Role::Receiver, stun, timeout)
        .await
        .map_err(EstablishError)?;
    let desc = recv_into(&mut ch, &key, out_dir, accept, progress).await?;
    // Graceful close: keep the connection alive until the sender closes it,
    // which confirms the sender received our final CommitAck. Without this the
    // receiver can tear down the peer connection before the CommitAck is flushed,
    // hanging the sender's wait for it. A dropped/closed channel makes `recv`
    // return Err (that's the expected success signal here); the timeout guards
    // against a sender that died. Bounded so we never wait forever.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), ch.recv()).await;
    Ok(desc)
}

pub async fn send_p1(
    rv: Arc<dyn Rendezvous>,
    topic: &str,
    secret: &[u8],
    source: &Source,
    stun: &[String],
    timeout: Duration,
    progress: Option<indicatif::ProgressBar>,
) -> anyhow::Result<String> {
    let key = handshake(rv.as_ref(), topic, secret, Role::Sender)
        .await
        .map_err(EstablishError)?;
    let mut ch = connect(rv.clone(), topic, &key, Role::Sender, stun, timeout)
        .await
        .map_err(EstablishError)?;
    send_source(&mut ch, &key, source, progress).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive;
    use crate::rendezvous::Rendezvous;
    use async_trait::async_trait;
    use futures::stream::{BoxStream, StreamExt};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // Same in-memory rendezvous as handshake.rs / transport tests (history replay).
    struct MemRendezvous {
        log: Mutex<Vec<(String, Vec<u8>)>>,
        tx: tokio::sync::broadcast::Sender<(String, Vec<u8>)>,
    }
    impl MemRendezvous {
        fn new() -> Arc<Self> {
            Arc::new(MemRendezvous {
                log: Mutex::new(vec![]),
                tx: tokio::sync::broadcast::channel(1024).0,
            })
        }
    }
    #[async_trait]
    impl Rendezvous for MemRendezvous {
        async fn publish(&self, topic: &str, frame: &[u8]) -> anyhow::Result<()> {
            self.log
                .lock()
                .unwrap()
                .push((topic.to_string(), frame.to_vec()));
            let _ = self.tx.send((topic.to_string(), frame.to_vec()));
            Ok(())
        }
        async fn subscribe(&self, topic: &str) -> anyhow::Result<BoxStream<'static, Vec<u8>>> {
            let topic = topic.to_string();
            let rx = self.tx.subscribe();
            let history: Vec<Vec<u8>> = self
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _)| *t == topic)
                .map(|(_, f)| f.clone())
                .collect();
            let live = futures::stream::unfold((rx, topic), move |(mut rx, topic)| async move {
                loop {
                    match rx.recv().await {
                        Ok((t, f)) if t == topic => return Some((f, (rx, topic))),
                        Ok(_) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return None,
                    }
                }
            });
            Ok(futures::stream::iter(history).chain(live).boxed())
        }
        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_p1_stack_file_transfer() {
        let rv = MemRendezvous::new();
        let topic = "b2p-p1e-test";
        let secret = vec![7u8, 42, 99]; // stand-in for a parsed human code's 3 bytes

        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..(crate::stream::STREAM_FRAME_SIZE as usize * 2 + 5))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(src.path().join("f.bin"), &content).unwrap();
        let source = archive::prepare(&[src.path().join("f.bin")]).unwrap();

        let (rv_r, sec_r) = (rv.clone(), secret.clone());
        let out_path = out.path().to_path_buf();
        let recv = tokio::spawn(async move {
            receive_p1(
                rv_r,
                topic,
                &sec_r,
                &out_path,
                |_| true,
                &[],
                Duration::from_secs(20),
                None,
            )
            .await
        });
        let (rv_s, sec_s) = (rv.clone(), secret.clone());
        let send = tokio::spawn(async move {
            send_p1(
                rv_s,
                topic,
                &sec_s,
                &source,
                &[],
                Duration::from_secs(20),
                None,
            )
            .await
        });

        send.await.unwrap().unwrap();
        recv.await.unwrap().unwrap();
        assert_eq!(std::fs::read(out.path().join("f.bin")).unwrap(), content);
    }
}
