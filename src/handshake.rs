//! Runs the SPAKE2 handshake (P1a `pake`) over a `Rendezvous`. Each peer
//! publishes its SPAKE2 message tagged with its role, waits for the peer's
//! (skipping its own echo), derives the key, then exchanges and verifies
//! key-confirmation MACs before returning. A wrong code — or an active MITM
//! on the rendezvous — is caught at confirmation and aborts. Design §2.

use crate::pake::{confirmation, verify_confirmation, Pake, Role, SessionKey};
use crate::rendezvous::Rendezvous;
use crate::rvcode::PakeSecret;
use anyhow::Context;
use futures::stream::{BoxStream, StreamExt};
use std::time::Duration;

/// Max wait for each peer step. Matches P0's accept timeout budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) const KIND_PAKE: u8 = 1;
pub(crate) const KIND_CONFIRM: u8 = 2;
pub(crate) const KIND_SDP: u8 = 3;
pub(crate) const KIND_ICE: u8 = 4;

pub(crate) fn role_byte(r: Role) -> u8 {
    match r {
        Role::Receiver => 0,
        Role::Sender => 1,
    }
}

fn other(r: Role) -> Role {
    match r {
        Role::Receiver => Role::Sender,
        Role::Sender => Role::Receiver,
    }
}

pub(crate) fn encode_frame(kind: u8, role: Role, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + payload.len());
    v.push(kind);
    v.push(role_byte(role));
    v.extend_from_slice(payload);
    v
}

pub(crate) fn decode_frame(frame: &[u8]) -> Option<(u8, u8, &[u8])> {
    if frame.len() < 2 {
        return None;
    }
    Some((frame[0], frame[1], &frame[2..]))
}

pub async fn handshake(
    rv: &dyn Rendezvous,
    topic: &str,
    password: &[u8],
    role: Role,
) -> anyhow::Result<SessionKey> {
    handshake_with_timeout(rv, topic, password, role, HANDSHAKE_TIMEOUT).await
}

pub(crate) async fn handshake_with_timeout(
    rv: &dyn Rendezvous,
    topic: &str,
    password: &[u8],
    role: Role,
    timeout: Duration,
) -> anyhow::Result<SessionKey> {
    tokio::time::timeout(timeout, handshake_inner(rv, topic, password, role))
        .await
        .context("timed out on the rendezvous — is the other side running?")?
}

/// The full exchange (subscribe + both publishes + both reads), run under a
/// single deadline by `handshake_with_timeout` so a rendezvous that accepts
/// the connection but never responds can't hang any one step for minutes.
async fn handshake_inner(
    rv: &dyn Rendezvous,
    topic: &str,
    password: &[u8],
    role: Role,
) -> anyhow::Result<SessionKey> {
    let mut stream = rv.subscribe(topic).await?;

    // 1. exchange SPAKE2 messages
    let (pake, my_msg) = Pake::start(&PakeSecret(password.to_vec()), topic);
    rv.publish(topic, &encode_frame(KIND_PAKE, role, &my_msg))
        .await?;
    let peer_msg = wait_for(&mut stream, KIND_PAKE, role_byte(other(role))).await?;
    let key = pake.finish(&peer_msg)?;

    // 2. exchange + verify key confirmation before trusting the key
    rv.publish(
        topic,
        &encode_frame(KIND_CONFIRM, role, &confirmation(&key, role)),
    )
    .await?;
    let peer_conf = wait_for(&mut stream, KIND_CONFIRM, role_byte(other(role))).await?;
    if !verify_confirmation(&key, other(role), &peer_conf) {
        anyhow::bail!(
            "the code didn't match — double-check it, or another transfer may be using the \
             same channel; try a fresh code"
        );
    }
    Ok(key)
}

/// Read frames until one matches (kind, role), skipping our own echoes and
/// unrelated frames. Unbounded on its own — the outer `handshake_with_timeout`
/// deadline cancels this when a peer never shows up.
async fn wait_for(
    stream: &mut BoxStream<'static, Vec<u8>>,
    want_kind: u8,
    want_role: u8,
) -> anyhow::Result<Vec<u8>> {
    while let Some(frame) = stream.next().await {
        if let Some((k, r, payload)) = decode_frame(&frame) {
            if k == want_kind && r == want_role {
                return Ok(payload.to_vec());
            }
        }
    }
    anyhow::bail!("rendezvous stream ended before the peer responded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::Rendezvous;
    use async_trait::async_trait;
    use futures::stream::{BoxStream, StreamExt};
    use std::sync::{Arc, Mutex};

    /// In-memory rendezvous: stores every published frame and, on subscribe,
    /// replays the stored history for the topic then streams live ones via a
    /// broadcast channel. Mirrors ntfy-with-`since`, so a late subscriber
    /// still sees the peer's earlier frame.
    struct MemRendezvous {
        log: Mutex<Vec<(String, Vec<u8>)>>,
        tx: tokio::sync::broadcast::Sender<(String, Vec<u8>)>,
    }
    impl MemRendezvous {
        fn new() -> Arc<Self> {
            Arc::new(MemRendezvous {
                log: Mutex::new(vec![]),
                tx: tokio::sync::broadcast::channel(256).0,
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
            // subscribe before snapshot so a concurrent publish duplicates rather than drops
            let rx = self.tx.subscribe();
            let history: Vec<Vec<u8>> = self
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _)| *t == topic)
                .map(|(_, f)| f.clone())
                .collect();
            let live =
                futures::stream::unfold((rx, topic.clone()), move |(mut rx, topic)| async move {
                    loop {
                        match rx.recv().await {
                            Ok((t, f)) if t == topic => return Some((f, (rx, topic))),
                            Ok(_) => continue, // other topic
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => return None,
                        }
                    }
                });
            // buffered history first, then live frames for this topic
            Ok(futures::stream::iter(history).chain(live).boxed())
        }
        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn two_peers_reach_the_same_key() {
        let rv = MemRendezvous::new();
        let pw = vec![7u8, 42, 99];
        let (rv_r, rv_s) = (rv.clone(), rv.clone());
        let (pw_r, pw_s) = (pw.clone(), pw.clone());
        let recv =
            tokio::spawn(
                async move { handshake(rv_r.as_ref(), "topic", &pw_r, Role::Receiver).await },
            );
        let send =
            tokio::spawn(
                async move { handshake(rv_s.as_ref(), "topic", &pw_s, Role::Sender).await },
            );
        let kr = recv.await.unwrap().unwrap();
        let ks = send.await.unwrap().unwrap();
        assert_eq!(kr.0, ks.0);
    }

    #[tokio::test]
    async fn mismatched_code_fails_confirmation() {
        let rv = MemRendezvous::new();
        let (rv_r, rv_s) = (rv.clone(), rv.clone());
        let recv = tokio::spawn(async move {
            handshake(rv_r.as_ref(), "topic", &[1u8, 2, 3], Role::Receiver).await
        });
        let send = tokio::spawn(async move {
            handshake(rv_s.as_ref(), "topic", &[9u8, 9, 9], Role::Sender).await
        });
        // both sides derive different keys, so confirmation fails on both
        assert!(recv.await.unwrap().is_err());
        assert!(send.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn times_out_without_a_peer() {
        let rv = MemRendezvous::new();
        // handshake_with_timeout lets the test use a short bound
        let r = handshake_with_timeout(
            rv.as_ref(),
            "lonely",
            &[1u8, 2, 3],
            Role::Receiver,
            std::time::Duration::from_millis(300),
        )
        .await;
        assert!(r.is_err());
    }

    /// Rendezvous double whose subscribe stream is already ended — drives
    /// the "stream ended before the peer responded" bail! path in `wait_for`,
    /// distinct from the deadline-elapsed path above.
    struct DeadRendezvous;
    #[async_trait]
    impl Rendezvous for DeadRendezvous {
        async fn publish(&self, _t: &str, _f: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn subscribe(&self, _t: &str) -> anyhow::Result<BoxStream<'static, Vec<u8>>> {
            Ok(futures::stream::empty().boxed())
        }
        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn errors_when_stream_ends_before_peer() {
        let rv = DeadRendezvous;
        // generous timeout so the failure is the stream ending, not the deadline
        let r = handshake_with_timeout(
            &rv,
            "t",
            &[1u8, 2, 3],
            Role::Receiver,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(r.is_err());
    }

    #[test]
    fn frame_round_trips() {
        let f = encode_frame(KIND_PAKE, Role::Receiver, b"payload");
        let (k, r, p) = decode_frame(&f).unwrap();
        assert_eq!(k, KIND_PAKE);
        assert_eq!(r, role_byte(Role::Receiver));
        assert_eq!(p, b"payload");
        assert!(decode_frame(&[]).is_none());
        assert!(decode_frame(&[1]).is_none());
    }

    #[test]
    fn signaling_frame_kinds_are_distinct() {
        assert_ne!(KIND_SDP, KIND_ICE);
        assert_ne!(KIND_SDP, KIND_PAKE);
        assert_ne!(KIND_SDP, KIND_CONFIRM);
        assert_ne!(KIND_ICE, KIND_CONFIRM);
    }
}
