//! The two new v2 code spellings (design §1). Both decode to a rendezvous
//! topic (which ntfy mailbox to meet on) and a PAKE secret (the password
//! SPAKE2 consumes). The v1 tunnel `Code` (src/code.rs) is separate.

use anyhow::{bail, Context};
use rand::RngCore;

/// Context string for deriving a topic id from human-code entropy.
const TOPIC_CTX: &str = "b2p-v2-rendezvous-topic v1";

#[derive(Clone)]
pub struct PakeSecret(pub Vec<u8>);

#[derive(Clone)]
enum Spelling {
    /// Human `<channel>-<word>-<word>`; entropy is the 3 secret bytes.
    Human,
    /// URL `b2p://<topic>#<secret>`.
    Url,
}

pub struct RendezvousCode {
    pub topic: String,
    pub secret: PakeSecret,
    spelling: Spelling,
}

/// Topic id (base58 of 16 KDF bytes) derived from human-code entropy.
fn topic_from_entropy(e: &[u8]) -> String {
    let full = blake3::derive_key(TOPIC_CTX, e);
    bs58::encode(&full[..16]).into_string()
}

pub fn is_rendezvous_code(s: &str) -> bool {
    let s = s.trim();
    if s.starts_with("b2p://") {
        return true;
    }
    // human form: <u8>-<word>-<word>
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].parse::<u8>().is_ok()
        && crate::words::index_of(parts[1]).is_some()
        && crate::words::index_of(parts[2]).is_some()
}

pub fn parse(s: &str) -> anyhow::Result<RendezvousCode> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("b2p://") {
        let (topic, secret_b58) = rest
            .split_once('#')
            .context("b2p code must look like b2p://<topic>#<secret>")?;
        if topic.is_empty() {
            bail!("b2p code has an empty topic");
        }
        let secret = bs58::decode(secret_b58)
            .into_vec()
            .context("b2p code secret is not valid base58")?;
        if secret.is_empty() {
            bail!("b2p code has an empty secret");
        }
        return Ok(RendezvousCode {
            topic: topic.to_string(),
            secret: PakeSecret(secret),
            spelling: Spelling::Url,
        });
    }

    // human form
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        bail!("code must look like <channel>-<word>-<word> or b2p://<topic>#<secret>");
    }
    let channel: u8 = parts[0]
        .parse()
        .with_context(|| format!("channel '{}' must be a number 0-255", parts[0]))?;
    let i1 = crate::words::index_of(parts[1])
        .with_context(|| format!("'{}' is not in the word list", parts[1]))?;
    let i2 = crate::words::index_of(parts[2])
        .with_context(|| format!("'{}' is not in the word list", parts[2]))?;
    let e = vec![channel, i1, i2];
    Ok(RendezvousCode {
        topic: topic_from_entropy(&e),
        secret: PakeSecret(e),
        spelling: Spelling::Human,
    })
}

impl RendezvousCode {
    pub fn generate_human() -> RendezvousCode {
        let mut e = [0u8; 3];
        rand::rngs::OsRng.fill_bytes(&mut e);
        RendezvousCode {
            topic: topic_from_entropy(&e),
            secret: PakeSecret(e.to_vec()),
            spelling: Spelling::Human,
        }
    }

    pub fn generate_url() -> RendezvousCode {
        let mut topic = [0u8; 16];
        let mut secret = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut topic);
        rand::rngs::OsRng.fill_bytes(&mut secret);
        RendezvousCode {
            topic: bs58::encode(&topic).into_string(),
            secret: PakeSecret(secret.to_vec()),
            spelling: Spelling::Url,
        }
    }
}

impl std::fmt::Display for RendezvousCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.spelling {
            Spelling::Human => {
                let e = &self.secret.0;
                write!(
                    f,
                    "{}-{}-{}",
                    e[0],
                    crate::words::word(e[1]),
                    crate::words::word(e[2])
                )
            }
            Spelling::Url => {
                write!(
                    f,
                    "b2p://{}#{}",
                    self.topic,
                    bs58::encode(&self.secret.0).into_string()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_round_trips_and_derives_topic() {
        let c = parse("7-tiger-zebra").unwrap();
        // secret is the 3 entropy bytes: channel, index(tiger), index(zebra)
        assert_eq!(
            c.secret.0,
            vec![
                7u8,
                crate::words::index_of("tiger").unwrap(),
                crate::words::index_of("zebra").unwrap()
            ]
        );
        // topic is a non-empty base58 string, deterministic for the same code
        assert!(!c.topic.is_empty());
        assert_eq!(c.topic, parse("7-tiger-zebra").unwrap().topic);
        // re-renders to the same human spelling
        assert_eq!(c.to_string(), "7-tiger-zebra");
    }

    #[test]
    fn different_human_codes_give_different_topics() {
        assert_ne!(
            parse("7-tiger-zebra").unwrap().topic,
            parse("8-tiger-zebra").unwrap().topic
        );
        assert_ne!(
            parse("7-tiger-zebra").unwrap().topic,
            parse("7-ocean-zebra").unwrap().topic
        );
    }

    #[test]
    fn human_rejects_bad_input() {
        assert!(parse("300-tiger-zebra").is_err()); // channel > 255
        assert!(parse("7-notaword-zebra").is_err()); // unknown word
        assert!(parse("7-tiger").is_err()); // too few parts
        assert!(parse("7-tiger-zebra-extra").is_err());
        assert!(parse("x-tiger-zebra").is_err()); // non-numeric channel
    }

    #[test]
    fn url_round_trips() {
        let gen = RendezvousCode::generate_url();
        let s = gen.to_string();
        assert!(s.starts_with("b2p://"));
        assert!(s.contains('#'));
        let parsed = parse(&s).unwrap();
        assert_eq!(parsed.topic, gen.topic);
        assert_eq!(parsed.secret.0, gen.secret.0);
        assert_eq!(parsed.secret.0.len(), 16);
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn url_rejects_bad_input() {
        assert!(parse("b2p://onlytopic").is_err()); // no '#'
        assert!(parse("b2p://#deadbeef").is_err()); // empty topic
        assert!(parse("b2p://sometopic#").is_err()); // empty secret
        assert!(parse("https://x.com#abc").is_err()); // not a rendezvous code (that's a tunnel code)
    }

    #[test]
    fn generated_human_is_parseable_and_stable() {
        let c = RendezvousCode::generate_human();
        assert_eq!(c.secret.0.len(), 3);
        let reparsed = parse(&c.to_string()).unwrap();
        assert_eq!(reparsed.topic, c.topic);
        assert_eq!(reparsed.secret.0, c.secret.0);
    }

    #[test]
    fn classifier_distinguishes_forms() {
        assert!(is_rendezvous_code("7-tiger-zebra"));
        assert!(is_rendezvous_code("b2p://topic#secret"));
        assert!(!is_rendezvous_code("https://foo.trycloudflare.com#abc")); // tunnel code
        assert!(!is_rendezvous_code("garbage"));
    }
}
