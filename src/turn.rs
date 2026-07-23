//! TURN relay configuration for the WebRTC transport (P2a design §3–§5).
//!
//! Resolves the `--turn*` CLI flags into a list of ICE servers, minting a
//! short-lived coturn `use-auth-secret` credential when a shared secret is
//! supplied. Transport-agnostic: `transport::webrtc` maps `IceServer` onto the
//! webrtc crate's `RTCIceServer`. Only the peer that *allocates* a relay
//! authenticates; the other peer reaches the allocated address as an ordinary
//! ICE candidate with no credentials (design §3.1).

use anyhow::bail;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

/// A transport-agnostic ICE server (STUN or TURN). `username`/`credential` are
/// empty for STUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// Seconds a minted ephemeral credential stays valid — aligned with the
/// code-expiry window (design §3.2).
const EPHEMERAL_TTL_SECS: u64 = 600;

/// Bundled best-effort free relay for `--turn-public` (Open Relay / metered.ca).
/// Best-effort only: a third-party, rate-limited service that may change or
/// disappear — hence opt-in, never automatic (design §5).
const PUBLIC_TURN_URLS: [&str; 3] = [
    "turn:openrelay.metered.ca:80",
    "turn:openrelay.metered.ca:443?transport=tcp",
    "turns:openrelay.metered.ca:443?transport=tcp",
];
const PUBLIC_TURN_USER: &str = "openrelayproject";
const PUBLIC_TURN_PASS: &str = "openrelayproject";

/// Mint a coturn `use-auth-secret` credential:
/// `username = "{expiry_unix}:{nonce}"`, `credential = base64(HMAC_SHA1(secret, username))`.
/// Pure/deterministic in its inputs (caller supplies `nonce`/`expiry`) so it is
/// unit-testable with a fixed known-answer vector.
pub fn ephemeral_credential(secret: &str, nonce: &str, expiry_unix: u64) -> (String, String) {
    let username = format!("{expiry_unix}:{nonce}");
    let mut mac =
        HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(username.as_bytes());
    let credential =
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    (username, credential)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the TURN CLI flags into ICE servers to append to the STUN defaults.
/// Empty vec when no TURN is configured (STUN-only — unchanged default). `nonce`
/// disambiguates concurrent allocations; the caller supplies a random one.
pub fn resolve(
    turn_urls: &[String],
    secret: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    public: bool,
    nonce: &str,
) -> anyhow::Result<Vec<IceServer>> {
    let mut servers = Vec::new();
    if !turn_urls.is_empty() {
        let (username, credential) = match (secret, user, pass) {
            (Some(s), None, None) => {
                ephemeral_credential(s, nonce, now_unix() + EPHEMERAL_TTL_SECS)
            }
            (None, Some(u), Some(p)) => (u.to_string(), p.to_string()),
            _ => bail!(
                "--turn requires credentials: either --turn-secret, \
                 or both --turn-user and --turn-pass"
            ),
        };
        servers.push(IceServer {
            urls: turn_urls.to_vec(),
            username,
            credential,
        });
    }
    if public {
        servers.push(IceServer {
            urls: PUBLIC_TURN_URLS.iter().map(|s| s.to_string()).collect(),
            username: PUBLIC_TURN_USER.to_string(),
            credential: PUBLIC_TURN_PASS.to_string(),
        });
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_credential_matches_known_answer() {
        // HMAC-SHA1("topsecret", "1700000000:b2p") -> base64, cross-checked with
        // an independent tool (python `hmac`). coturn computes the same value.
        let (username, cred) = ephemeral_credential("topsecret", "b2p", 1_700_000_000);
        assert_eq!(username, "1700000000:b2p");
        assert_eq!(cred, "MMEmLNCfJ3NvrGNM+eBdFp5wwps=");
    }

    #[test]
    fn resolve_no_flags_is_empty() {
        assert!(resolve(&[], None, None, None, false, "n").unwrap().is_empty());
    }

    #[test]
    fn resolve_turn_with_secret_mints_ephemeral() {
        let urls = vec!["turns:turn.example.com:443?transport=tcp".to_string()];
        let s = resolve(&urls, Some("sekret"), None, None, false, "nonce123").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].urls, urls);
        assert!(s[0].username.ends_with(":nonce123"));
        assert!(!s[0].credential.is_empty());
    }

    #[test]
    fn resolve_turn_with_static_creds() {
        let urls = vec!["turn:turn.example.com:3478".to_string()];
        let s = resolve(&urls, None, Some("alice"), Some("pw"), false, "n").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].username, "alice");
        assert_eq!(s[0].credential, "pw");
    }

    #[test]
    fn resolve_turn_without_creds_errors() {
        let urls = vec!["turn:turn.example.com:3478".to_string()];
        assert!(resolve(&urls, None, None, None, false, "n").is_err());
    }

    #[test]
    fn resolve_public_adds_open_relay() {
        let s = resolve(&[], None, None, None, true, "n").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].username, "openrelayproject");
        assert!(s[0].urls.iter().any(|u| u.starts_with("turns:")));
    }
}
