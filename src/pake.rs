//! Balanced PAKE (SPAKE2) turning a low-entropy code into a strong session
//! key, plus explicit key confirmation. SPAKE2 alone has no confirmation:
//! a wrong code still `finish()`es, just to a *different* key — so we
//! exchange keyed-hash tags and verify the peer's before trusting the key.
//! Design: b2p-v2-spec.md §3.2 and the P1 design §2.

use crate::rvcode::PakeSecret;
use spake2::{Ed25519Group, Identity, Password, Spake2};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Receiver,
    Sender,
}

#[derive(Clone)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    /// Subkey for the AEAD payload stream (design §4.3). Independent of the
    /// raw session key so the two are never used as the same AEAD key.
    ///
    /// SECURITY: at most ONE transfer per SessionKey. `stream_key` is
    /// deterministic and the stream frame indices restart at 0 each transfer, so
    /// running two transfers under one SessionKey reuses (key, nonce) pairs. A
    /// retry must run a fresh PAKE handshake (which yields a new SessionKey),
    /// never resend on a cached key.
    pub fn stream_key(&self) -> [u8; 32] {
        blake3::derive_key("b2p-v2 stream key v1", &self.0)
    }
}

pub struct Pake {
    state: Spake2<Ed25519Group>,
}

impl Pake {
    /// Begin a handshake. Returns our state and the outbound SPAKE2 message
    /// to publish. The topic is bound into the transcript identity, so a
    /// message replayed on another topic yields a different (non-matching) key.
    pub fn start(secret: &PakeSecret, topic: &str) -> (Pake, Vec<u8>) {
        let identity = format!("b2p-v2:{topic}");
        let (state, msg) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(&secret.0),
            &Identity::new(identity.as_bytes()),
        );
        (Pake { state }, msg)
    }

    /// Complete the handshake with the peer's SPAKE2 message.
    pub fn finish(self, peer_msg: &[u8]) -> anyhow::Result<SessionKey> {
        let key = self
            .state
            .finish(peer_msg)
            .map_err(|e| anyhow::anyhow!("PAKE handshake failed: {e:?}"))?;
        let arr: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("unexpected PAKE key length {}", key.len()))?;
        Ok(SessionKey(arr))
    }
}

fn confirm_tag(sender_role: Role) -> &'static [u8] {
    match sender_role {
        Role::Receiver => b"b2p-v2-confirm-receiver",
        Role::Sender => b"b2p-v2-confirm-sender",
    }
}

/// The confirmation MAC a peer in `sender_role` sends.
pub fn confirmation(key: &SessionKey, sender_role: Role) -> [u8; 32] {
    *blake3::keyed_hash(&key.0, confirm_tag(sender_role)).as_bytes()
}

/// Verify a confirmation MAC claimed to come from `peer_role`.
pub fn verify_confirmation(key: &SessionKey, peer_role: Role, mac: &[u8]) -> bool {
    let expected = confirmation(key, peer_role);
    constant_time_eq::constant_time_eq(&expected, mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rvcode::PakeSecret;

    fn run(
        secret_a: Vec<u8>,
        topic_a: &str,
        secret_b: Vec<u8>,
        topic_b: &str,
    ) -> (SessionKey, SessionKey) {
        let (pa, ma) = Pake::start(&PakeSecret(secret_a), topic_a);
        let (pb, mb) = Pake::start(&PakeSecret(secret_b), topic_b);
        (pa.finish(&mb).unwrap(), pb.finish(&ma).unwrap())
    }

    #[test]
    fn matching_secret_same_topic_confirms_both_ways() {
        let (ka, kb) = run(vec![7, 42, 99], "topic", vec![7, 42, 99], "topic");
        assert_eq!(ka.0, kb.0);
        // receiver confirms to sender, and vice-versa; each verifies the peer's tag
        let conf_recv = confirmation(&ka, Role::Receiver);
        assert!(verify_confirmation(&kb, Role::Receiver, &conf_recv));
        let conf_send = confirmation(&kb, Role::Sender);
        assert!(verify_confirmation(&ka, Role::Sender, &conf_send));
    }

    #[test]
    fn wrong_secret_diverges_and_confirmation_fails() {
        let (ka, kb) = run(vec![1, 2, 3], "topic", vec![9, 9, 9], "topic");
        assert_ne!(ka.0, kb.0);
        let conf_recv = confirmation(&ka, Role::Receiver);
        assert!(!verify_confirmation(&kb, Role::Receiver, &conf_recv));
    }

    #[test]
    fn same_secret_different_topic_diverges() {
        let (ka, kb) = run(vec![1, 2, 3], "topic-a", vec![1, 2, 3], "topic-b");
        assert_ne!(ka.0, kb.0);
    }

    #[test]
    fn confirmation_rejects_wrong_role_and_short_mac() {
        let (ka, _kb) = run(vec![5, 5, 5], "t", vec![5, 5, 5], "t");
        let conf_recv = confirmation(&ka, Role::Receiver);
        // a verifier expecting the Sender's tag must reject the Receiver's tag
        assert!(!verify_confirmation(&ka, Role::Sender, &conf_recv));
        assert!(!verify_confirmation(&ka, Role::Receiver, &conf_recv[..16]));
    }

    #[test]
    fn finish_rejects_garbage_peer_message() {
        let (pa, _ma) = Pake::start(&PakeSecret(vec![1, 2, 3]), "topic");
        assert!(pa.finish(b"not a valid spake2 message").is_err());
    }

    #[test]
    fn golden_confirmation_vector() {
        // FROZEN: pins the keyed-hash confirmation tag construction.
        let key = SessionKey([0x11u8; 32]);
        assert_eq!(
            hex::encode(confirmation(&key, Role::Receiver)),
            "52a4095ab3cc8f216bcd5147a0978d99bed6dec4ae39f07f8ab50f171b668ffc"
        );
        assert_eq!(
            hex::encode(confirmation(&key, Role::Sender)),
            "57f2c8c7d298695bf5ae7c20a097e6886d48e40699cc7ec654535fc6a2aaa841"
        );
    }

    #[test]
    fn stream_key_is_derived_and_deterministic() {
        let k = SessionKey([3u8; 32]);
        assert_eq!(k.stream_key(), SessionKey([3u8; 32]).stream_key());
        assert_ne!(k.stream_key(), k.0); // not the raw session key
        assert_ne!(k.stream_key(), SessionKey([4u8; 32]).stream_key());
    }
}
