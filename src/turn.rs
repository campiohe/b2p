//! TURN relay configuration for the WebRTC transport (P2a design §3–§5).
//!
//! Resolves the `--turn*` CLI flags into a list of ICE servers, minting a
//! short-lived coturn `use-auth-secret` credential when a shared secret is
//! supplied. Transport-agnostic: `transport::webrtc` maps `IceServer` onto the
//! webrtc crate's `RTCIceServer`. Only the peer that *allocates* a relay
//! authenticates; the other peer reaches the allocated address as an ordinary
//! ICE candidate with no credentials (design §3.1).
//!
//! **UDP only.** `webrtc-ice` (all published versions, incl. 0.17.2) implements
//! TURN over UDP alone — `turns:` (TLS) and `?transport=tcp` are unimplemented
//! upstream and would silently gather no relay candidate. We reject those URLs
//! loudly. So TURN here traverses symmetric NAT where UDP egress works; for
//! UDP-*blocked* networks the answer is the HTTPS relay (P2b), not TURN.

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

/// Seconds a minted ephemeral credential stays valid. Must comfortably exceed
/// the longest a transfer might run: webrtc-rs re-authenticates TURN allocation
/// and permission *refreshes* with the same timestamped username, so a short TTL
/// would 401 a long relayed transfer mid-flight (coturn enforces the timestamp
/// on refresh). 12h is ample and harmless — the human code itself is single-use
/// and short-lived, independent of this.
const EPHEMERAL_TTL_SECS: u64 = 12 * 60 * 60;

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

/// Reject TURN URLs the WebRTC engine can't actually use. `webrtc-ice` gathers
/// relay candidates over UDP only; `turns:` (TLS) and `?transport=tcp` are
/// unimplemented upstream and would silently yield no candidate — so fail loudly
/// and point at the HTTPS relay for UDP-blocked networks.
fn validate_turn_url(url: &str) -> anyhow::Result<()> {
    let (scheme, rest) = url.split_once(':').unwrap_or((url, ""));
    match scheme.to_ascii_lowercase().as_str() {
        "turns" => bail!(
            "TURN over TLS ({url}) is not supported by the current WebRTC engine \
             (webrtc-ice is UDP-only). For a UDP-blocked network, use the HTTPS relay instead."
        ),
        "turn" => {}
        _ => bail!("--turn expects a turn: (UDP) URL, got: {url}"),
    }
    // Reject transport=tcp — but decode the query first, so a percent-encoded
    // value (e.g. `transport=%74%63%70`) can't slip past and then silently
    // gather no relay candidate in webrtc-ice's UDP-only gather.
    if let Some((_, query)) = rest.split_once('?') {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if k.eq_ignore_ascii_case("transport") && v.eq_ignore_ascii_case("tcp") {
                bail!(
                    "TURN over TCP ({url}) is not supported by the current WebRTC engine \
                     (webrtc-ice is UDP-only). Use a udp turn: URL, or the HTTPS relay for \
                     UDP-blocked networks."
                );
            }
        }
    }
    Ok(())
}

/// Resolve the TURN CLI flags into ICE servers to append to the STUN defaults.
/// Empty vec when no TURN is configured (STUN-only — unchanged default). `nonce`
/// disambiguates concurrent allocations; the caller supplies a random one.
pub fn resolve(
    turn_urls: &[String],
    secret: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    nonce: &str,
) -> anyhow::Result<Vec<IceServer>> {
    if turn_urls.is_empty() {
        // Credentials with no --turn URL are a mistake, not a silent no-op — the
        // user thinks TURN is configured, then a transfer fails STUN-only.
        if secret.is_some() || user.is_some() || pass.is_some() {
            bail!("TURN credentials were given but no --turn URL — add --turn turn:HOST:PORT");
        }
        return Ok(Vec::new());
    }
    for u in turn_urls {
        validate_turn_url(u)?;
    }
    let (username, credential) = match (secret, user, pass) {
        (Some(s), None, None) => ephemeral_credential(s, nonce, now_unix() + EPHEMERAL_TTL_SECS),
        (None, Some(u), Some(p)) => (u.to_string(), p.to_string()),
        _ => bail!(
            "--turn requires credentials: either --turn-secret, \
             or both --turn-user and --turn-pass"
        ),
    };
    Ok(vec![IceServer {
        urls: turn_urls.to_vec(),
        username,
        credential,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_credential_matches_known_answer() {
        // HMAC-SHA1("topsecret", "1700000000:b2p") -> base64, cross-checked with
        // an independent tool (python `hmac`) AND against a live coturn.
        let (username, cred) = ephemeral_credential("topsecret", "b2p", 1_700_000_000);
        assert_eq!(username, "1700000000:b2p");
        assert_eq!(cred, "MMEmLNCfJ3NvrGNM+eBdFp5wwps=");
    }

    #[test]
    fn resolve_no_flags_is_empty() {
        assert!(resolve(&[], None, None, None, "n").unwrap().is_empty());
    }

    #[test]
    fn resolve_turn_with_secret_mints_ephemeral() {
        let urls = vec!["turn:turn.example.com:3478".to_string()];
        let s = resolve(&urls, Some("sekret"), None, None, "nonce123").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].urls, urls);
        assert!(s[0].username.ends_with(":nonce123"));
        assert!(!s[0].credential.is_empty());
    }

    #[test]
    fn resolve_turn_with_static_creds() {
        let urls = vec!["turn:turn.example.com:3478".to_string()];
        let s = resolve(&urls, None, Some("alice"), Some("pw"), "n").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].username, "alice");
        assert_eq!(s[0].credential, "pw");
    }

    #[test]
    fn resolve_turn_without_creds_errors() {
        let urls = vec!["turn:turn.example.com:3478".to_string()];
        assert!(resolve(&urls, None, None, None, "n").is_err());
    }

    #[test]
    fn resolve_rejects_tls_and_tcp() {
        // webrtc-ice is UDP-only: turns: and ?transport=tcp must fail loudly.
        assert!(resolve(&["turns:h:5349".into()], Some("s"), None, None, "n").is_err());
        assert!(resolve(&["TURNS:h:5349".into()], Some("s"), None, None, "n").is_err());
        assert!(resolve(
            &["turn:h:3478?transport=tcp".into()],
            Some("s"),
            None,
            None,
            "n"
        )
        .is_err());
        // percent-encoded transport=tcp must not slip past the substring check
        assert!(resolve(
            &["turn:h:3478?transport=%74%63%70".into()],
            Some("s"),
            None,
            None,
            "n"
        )
        .is_err());
        // udp (default and explicit) is fine
        assert!(resolve(&["turn:h:3478".into()], Some("s"), None, None, "n").is_ok());
        assert!(resolve(
            &["turn:h:3478?transport=udp".into()],
            Some("s"),
            None,
            None,
            "n"
        )
        .is_ok());
    }

    #[test]
    fn resolve_creds_without_url_errors() {
        assert!(resolve(&[], Some("s"), None, None, "n").is_err());
        assert!(resolve(&[], None, Some("u"), Some("p"), "n").is_err());
    }
}
