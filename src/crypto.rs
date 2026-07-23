use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

pub const CHUNK_SIZE: u64 = 4 * 1024 * 1024;
pub const SECRET_LEN: usize = 16;

const CTX_AUTH: &str = "b2p 2026-07-22 v1 auth";
const CTX_DATA: &str = "b2p 2026-07-22 v1 data";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Manifest = 0x01,
    Data = 0x02,
    Commit = 0x03,
    StreamToReceiver = 0x04,
    StreamToSender = 0x05,
}

#[derive(Debug, thiserror::Error)]
#[error("decryption failed")]
pub struct CryptoError;

#[derive(Clone)]
pub struct Secret(pub [u8; SECRET_LEN]);

impl Secret {
    pub fn generate() -> Self {
        let mut b = [0u8; SECRET_LEN];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Secret(b)
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn from_base58(s: &str) -> anyhow::Result<Self> {
        let bytes = bs58::decode(s).into_vec()?;
        let arr: [u8; SECRET_LEN] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret must decode to {SECRET_LEN} bytes"))?;
        Ok(Secret(arr))
    }

    pub fn auth_token(&self) -> String {
        bs58::encode(blake3::derive_key(CTX_AUTH, &self.0)).into_string()
    }

    pub fn data_key(&self) -> [u8; 32] {
        blake3::derive_key(CTX_DATA, &self.0)
    }
}

fn make_nonce(domain: Domain, index: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[0] = domain as u8;
    n[16..24].copy_from_slice(&index.to_le_bytes());
    XNonce::from(n)
}

pub fn seal(key: &[u8; 32], domain: Domain, index: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &make_nonce(domain, index),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption is infallible for in-memory buffers")
}

pub fn open(
    key: &[u8; 32],
    domain: Domain,
    index: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &make_nonce(domain, index),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError)
}

/// Seal with a fresh random 192-bit nonce, prepended to the ciphertext.
/// Use for messages with no natural monotonic index (e.g. trickled ICE
/// candidates). XChaCha20's nonce is large enough that random nonces are
/// collision-safe.
pub fn seal_random(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption is infallible for in-memory buffers");
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open_random(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 24 {
        return Err(CryptoError);
    }
    let (nonce, body) = ciphertext.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
        .map_err(|_| CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        Secret([7u8; 16]).data_key()
    }

    #[test]
    fn seal_open_round_trip() {
        let ct = seal(&key(), Domain::Data, 3, b"tid", b"hello world");
        let pt = open(&key(), Domain::Data, 3, b"tid", &ct).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut ct = seal(&key(), Domain::Data, 0, b"tid", b"payload");
        ct[0] ^= 1;
        assert!(open(&key(), Domain::Data, 0, b"tid", &ct).is_err());
    }

    #[test]
    fn wrong_index_rejected() {
        let ct = seal(&key(), Domain::Data, 0, b"tid", b"payload");
        assert!(open(&key(), Domain::Data, 1, b"tid", &ct).is_err());
    }

    #[test]
    fn wrong_domain_rejected() {
        let ct = seal(&key(), Domain::Manifest, 0, b"", b"payload");
        assert!(open(&key(), Domain::Data, 0, b"", &ct).is_err());
    }

    #[test]
    fn wrong_aad_rejected() {
        let ct = seal(&key(), Domain::Data, 0, b"tid-a", b"payload");
        assert!(open(&key(), Domain::Data, 0, b"tid-b", &ct).is_err());
    }

    #[test]
    fn auth_and_data_keys_are_independent_and_deterministic() {
        let s = Secret([1u8; 16]);
        assert_eq!(s.auth_token(), Secret([1u8; 16]).auth_token());
        assert_ne!(s.auth_token(), bs58::encode(s.data_key()).into_string());
        assert_ne!(Secret([2u8; 16]).auth_token(), s.auth_token());
    }

    #[test]
    fn secret_base58_round_trip() {
        let s = Secret::generate();
        let parsed = Secret::from_base58(&s.to_base58()).unwrap();
        assert_eq!(s.0, parsed.0);
        assert!(Secret::from_base58("tooshort").is_err());
    }

    #[test]
    fn stream_directions_have_independent_nonces() {
        // Same key, same index, different direction domain -> different ciphertext,
        // and a frame sealed one way must not open the other way (no nonce reuse).
        let k = key();
        let a = seal(&k, Domain::StreamToReceiver, 0, b"", b"frame");
        let b = seal(&k, Domain::StreamToSender, 0, b"", b"frame");
        assert_ne!(a, b);
        assert!(open(&k, Domain::StreamToSender, 0, b"", &a).is_err());
        assert_eq!(
            open(&k, Domain::StreamToReceiver, 0, b"", &a).unwrap(),
            b"frame"
        );
    }

    #[test]
    fn random_nonce_seal_round_trip_and_uniqueness() {
        let k = key();
        let a = seal_random(&k, b"aad", b"sdp offer");
        let b = seal_random(&k, b"aad", b"sdp offer");
        assert_ne!(a, b, "random nonce -> different ciphertext each time");
        assert_eq!(open_random(&k, b"aad", &a).unwrap(), b"sdp offer");
        // tamper + wrong aad + truncation all fail
        let mut t = a.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(open_random(&k, b"aad", &t).is_err());
        assert!(open_random(&k, b"other", &a).is_err());
        assert!(open_random(&k, b"aad", &a[..10]).is_err());
    }
}
