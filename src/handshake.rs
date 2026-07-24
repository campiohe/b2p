//! Runs the SPAKE2 handshake (P1a `pake`) in-band over an established
//! `MsgChannel` (the relay). Each peer sends its SPAKE2 message tagged with
//! its role, waits for the peer's, derives the key, then exchanges and
//! verifies key-confirmation MACs before returning. A wrong code — or an
//! active MITM on the relay — is caught at confirmation and aborts. Design §2.

use crate::pake::{confirmation, verify_confirmation, Pake, Role, SessionKey};
use crate::rvcode::PakeSecret;
use crate::stream::MsgChannel;
use anyhow::Context;
use std::time::Duration;

/// Max wait for the whole exchange. Matches P0's accept timeout budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) const KIND_PAKE: u8 = 1;
pub(crate) const KIND_CONFIRM: u8 = 2;

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

/// The peer is present but proved a different code (confirmation failed).
/// A receiver can keep waiting for an honest sender after seeing this.
#[derive(Debug)]
pub struct CodeMismatch;
impl std::fmt::Display for CodeMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the code didn't match — double-check it, or another transfer may be using the same \
             channel; try a fresh code"
        )
    }
}
impl std::error::Error for CodeMismatch {}

/// SPAKE2 + key confirmation over an established `MsgChannel` (P2b relay).
/// No echo-skipping needed — the relay forwards only the peer's frames.
pub async fn handshake_over_channel(
    ch: &mut dyn MsgChannel,
    context: &str,
    password: &[u8],
    role: Role,
) -> anyhow::Result<SessionKey> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_channel_inner(ch, context, password, role),
    )
    .await
    .context("timed out during the key exchange — the other side stopped responding")?
}

async fn handshake_channel_inner(
    ch: &mut dyn MsgChannel,
    context: &str,
    password: &[u8],
    role: Role,
) -> anyhow::Result<SessionKey> {
    let (pake, my_msg) = Pake::start(&PakeSecret(password.to_vec()), context);
    ch.send(&encode_frame(KIND_PAKE, role, &my_msg)).await?;
    let peer_msg = recv_kind(ch, KIND_PAKE, role_byte(other(role))).await?;
    let key = pake.finish(&peer_msg)?;

    ch.send(&encode_frame(KIND_CONFIRM, role, &confirmation(&key, role)))
        .await?;
    let peer_conf = recv_kind(ch, KIND_CONFIRM, role_byte(other(role))).await?;
    if !verify_confirmation(&key, other(role), &peer_conf) {
        return Err(anyhow::Error::new(CodeMismatch));
    }
    Ok(key)
}

/// Read frames until one matches (kind, from_role); skip anything else.
async fn recv_kind(ch: &mut dyn MsgChannel, kind: u8, from_role: u8) -> anyhow::Result<Vec<u8>> {
    loop {
        let frame = ch.recv().await?;
        if let Some((k, r, payload)) = decode_frame(&frame) {
            if k == kind && r == from_role {
                return Ok(payload.to_vec());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::MsgChannel;
    use async_trait::async_trait;
    use tokio::sync::mpsc;

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

    struct Pipe {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }
    fn pipe() -> (Pipe, Pipe) {
        let (a_tx, a_rx) = mpsc::channel(64);
        let (b_tx, b_rx) = mpsc::channel(64);
        (Pipe { tx: a_tx, rx: b_rx }, Pipe { tx: b_tx, rx: a_rx })
    }
    #[async_trait]
    impl MsgChannel for Pipe {
        async fn send(&mut self, msg: &[u8]) -> anyhow::Result<()> {
            self.tx
                .send(msg.to_vec())
                .await
                .map_err(|_| anyhow::anyhow!("pipe closed"))
        }
        async fn recv(&mut self) -> anyhow::Result<Vec<u8>> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("pipe closed"))
        }
    }

    #[tokio::test]
    async fn channel_handshake_reaches_the_same_key() {
        let (mut a, mut b) = pipe();
        let (ka, kb) = tokio::join!(
            handshake_over_channel(&mut a, "room1", b"pw", Role::Receiver),
            handshake_over_channel(&mut b, "room1", b"pw", Role::Sender),
        );
        assert_eq!(ka.unwrap().0, kb.unwrap().0);
    }

    #[tokio::test]
    async fn channel_handshake_flags_wrong_code_as_mismatch() {
        let (mut a, mut b) = pipe();
        let (ka, kb) = tokio::join!(
            handshake_over_channel(&mut a, "room1", b"pw", Role::Receiver),
            handshake_over_channel(&mut b, "room1", b"WRONG", Role::Sender),
        );
        let ea = ka.err().expect("receiver must reject");
        assert!(ea.downcast_ref::<CodeMismatch>().is_some());
        assert!(kb.is_err());
    }

    #[tokio::test]
    async fn channel_handshake_dead_pipe_errors() {
        let (mut a, b) = pipe();
        drop(b);
        assert!(handshake_over_channel(&mut a, "r", b"pw", Role::Receiver)
            .await
            .is_err());
    }
}
