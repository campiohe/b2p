//! Session orchestration: connect through the relay, run the in-band PAKE
//! handshake, and move the payload — the composition `b2p receive`/`send`
//! use. One handshake + one transfer per call — a SessionKey is single-use
//! (see stream::stream_key).

use crate::archive::Source;
use crate::handshake::{handshake_over_channel, CodeMismatch};
use crate::pake::Role;
use crate::protocol::Manifest;
use crate::stream::{recv_into, send_source, MsgChannel};
use crate::transport::relay::{self, TransportLost, WaitClosed};
use std::path::Path;
use std::time::Duration;

/// Marks an error as having occurred during *establishment* (dial or
/// handshake) rather than during the transfer itself (design §6 scopes
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
        // underlying transport error) would silently disappear from whatever
        // prints `e` afterwards, regardless of `{}` vs `{:#}` there.
        write!(f, "{:#}", self.0)
    }
}
impl std::error::Error for EstablishError {}

/// Wrap only genuine establishment problems; CodeMismatch and TransportLost
/// pass through so the receiver's loop can keep waiting on the same code.
fn establish_unless_rearmed(e: anyhow::Error) -> anyhow::Error {
    if e.downcast_ref::<TransportLost>().is_some() || e.downcast_ref::<CodeMismatch>().is_some() {
        e
    } else {
        EstablishError(e).into()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn receive_relay(
    relay_url: &str,
    token: Option<&str>,
    topic: &str,
    secret: &[u8],
    out_dir: &Path,
    accept: impl FnOnce(&Manifest) -> bool + Send,
    tls: &crate::http::TlsOpts,
    wait_peer: Duration,
    progress: Option<indicatif::ProgressBar>,
) -> anyhow::Result<String> {
    // WaitClosed (room expiry / relay restart mid-wait) passes through: the
    // caller re-dials, and a genuinely dead network fails THAT dial fast as
    // a real EstablishError.
    let mut ch = relay::connect(relay_url, topic, Role::Receiver, token, tls, wait_peer)
        .await
        .map_err(|e| {
            if e.downcast_ref::<WaitClosed>().is_some() {
                e
            } else {
                EstablishError(e).into()
            }
        })?;
    // Post-pairing handshake failures are the PEER's doing (mismatch, silent
    // stall, disconnect), never the network's — all re-armable, so a hostile
    // or broken sender can't kill a waiting receiver.
    let key = match handshake_over_channel(&mut ch, topic, secret, Role::Receiver).await {
        Ok(k) => k,
        Err(e)
            if e.downcast_ref::<CodeMismatch>().is_some()
                || e.downcast_ref::<TransportLost>().is_some() =>
        {
            return Err(e)
        }
        Err(e) => return Err(anyhow::Error::new(TransportLost(e))),
    };
    let desc = recv_into(&mut ch, &key, out_dir, accept, progress).await?;
    // Graceful close: keep the connection alive (bounded) until the sender
    // closes it, which confirms the sender received our final CommitAck.
    // Without this the receiver can tear the socket down before the CommitAck
    // is flushed, hanging the sender's wait for it.
    let _ = tokio::time::timeout(Duration::from_secs(10), ch.recv()).await;
    ch.close().await;
    Ok(desc)
}

#[allow(clippy::too_many_arguments)]
pub async fn send_relay(
    relay_url: &str,
    token: Option<&str>,
    topic: &str,
    secret: &[u8],
    source: &Source,
    tls: &crate::http::TlsOpts,
    wait_peer: Duration,
    progress: Option<indicatif::ProgressBar>,
) -> anyhow::Result<String> {
    let mut ch = relay::connect(relay_url, topic, Role::Sender, token, tls, wait_peer)
        .await
        .map_err(EstablishError)?;
    let key = handshake_over_channel(&mut ch, topic, secret, Role::Sender)
        .await
        .map_err(establish_unless_rearmed)?;
    let desc = send_source(&mut ch, &key, source, progress).await?;
    ch.close().await;
    Ok(desc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn full_relay_stack_file_transfer_with_rearm_after_drop() {
        let relay = crate::transport::mock::start().await;
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..(crate::stream::STREAM_FRAME_SIZE as usize * 3 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(src.path().join("payload.bin"), &content).unwrap();
        let source = crate::archive::prepare(&[src.path().join("payload.bin")]).unwrap();
        let code = crate::rvcode::RendezvousCode::generate_url();
        let tls = crate::http::TlsOpts::default();
        let url = relay.url.clone();
        let (topic, secret) = (code.topic.clone(), code.secret.0.clone());

        // Round 1: a sender that dies mid-handshake must surface on the
        // receiver as a re-armable error, not a hang and not success.
        let receiver1 = tokio::spawn({
            let (url, topic, secret) = (url.clone(), topic.clone(), secret.clone());
            let out_path = out.path().to_path_buf();
            async move {
                receive_relay(
                    &url,
                    None,
                    &topic,
                    &secret,
                    &out_path,
                    |_| true,
                    &crate::http::TlsOpts::default(),
                    Duration::from_secs(30),
                    None,
                )
                .await
            }
        });
        // dying sender: connect to the room, then hang up without a handshake
        let dying = crate::transport::relay::connect(
            &url,
            &topic,
            Role::Sender,
            None,
            &tls,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        drop(dying);
        let r1 = tokio::time::timeout(Duration::from_secs(30), receiver1)
            .await
            .expect("receiver must not hang")
            .unwrap();
        let e1 = r1.expect_err("receiver round 1 must error");
        assert!(
            e1.downcast_ref::<TransportLost>().is_some(),
            "round-1 error must be re-armable, got: {e1:#}"
        );

        // Round 2: an honest sender completes the transfer on the SAME code.
        let receiver2 = tokio::spawn({
            let (url, topic, secret) = (url.clone(), topic.clone(), secret.clone());
            let out_path = out.path().to_path_buf();
            async move {
                receive_relay(
                    &url,
                    None,
                    &topic,
                    &secret,
                    &out_path,
                    |_| true,
                    &crate::http::TlsOpts::default(),
                    Duration::from_secs(30),
                    None,
                )
                .await
            }
        });
        send_relay(
            &url,
            None,
            &topic,
            &secret,
            &source,
            &tls,
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        receiver2.await.unwrap().unwrap();
        assert_eq!(
            std::fs::read(out.path().join("payload.bin")).unwrap(),
            content
        );
    }
}
