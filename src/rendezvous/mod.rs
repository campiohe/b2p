//! Rendezvous layer: a tiny pub/sub channel used only to run the PAKE and
//! (in P1c) exchange encrypted transport candidates. Carries opaque frame
//! bytes — the handshake decides their meaning. Default provider: ntfy.sh.

pub mod ntfy;

use async_trait::async_trait;
use base64::Engine;
use futures::stream::BoxStream;

#[async_trait]
pub trait Rendezvous: Send + Sync {
    /// Publish one opaque frame to the topic.
    async fn publish(&self, topic: &str, frame: &[u8]) -> anyhow::Result<()>;
    /// Subscribe to a topic, yielding each opaque frame as it arrives.
    async fn subscribe(&self, topic: &str) -> anyhow::Result<BoxStream<'static, Vec<u8>>>;
    /// Release any held resources. Best-effort.
    async fn close(&self) -> anyhow::Result<()>;
}

/// Parse one line of ntfy's JSON stream, returning the decoded frame bytes
/// for a `message` event and `None` for anything else (open / keepalive /
/// non-JSON / bad base64).
pub fn parse_ntfy_message(line: &str) -> Option<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("event")?.as_str()? != "message" {
        return None;
    }
    let msg = v.get("message")?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(msg).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_message_events_only() {
        // real ntfy stream lines
        assert_eq!(
            parse_ntfy_message(r#"{"id":"a","time":1,"event":"open","topic":"t"}"#),
            None
        );
        assert_eq!(
            parse_ntfy_message(r#"{"event":"keepalive","topic":"t"}"#),
            None
        );
        // "aGVsbG8=" is base64("hello")
        assert_eq!(
            parse_ntfy_message(
                r#"{"id":"b","time":2,"event":"message","topic":"t","message":"aGVsbG8="}"#
            ),
            Some(b"hello".to_vec())
        );
        assert_eq!(parse_ntfy_message("not json"), None);
        assert_eq!(
            parse_ntfy_message(r#"{"event":"message","message":"!!!not-base64!!!"}"#),
            None
        );
    }
}
