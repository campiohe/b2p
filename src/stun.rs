//! Minimal STUN (RFC 5389) binding-request probe. Used only by `b2p doctor`
//! to answer one question: does UDP egress to a public STUN server work?
//! (That is what decides whether the v2 WebRTC transport will be viable.)

use anyhow::Context;
use rand::RngCore;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

pub fn encode_binding_request(txn_id: &[u8; 12]) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[0..2].copy_from_slice(&[0x00, 0x01]); // type: binding request
    msg[4..8].copy_from_slice(&MAGIC_COOKIE); // bytes 2..4 stay 0: no attributes
    msg[8..20].copy_from_slice(txn_id);
    msg
}

/// Any STUN message (success or error) that echoes our transaction id.
pub fn is_binding_response(resp: &[u8], txn_id: &[u8; 12]) -> bool {
    resp.len() >= 20 && resp[4..8] == MAGIC_COOKIE && resp[8..20] == txn_id[..]
}

/// `server` is a `host:port` string; Ok(()) means UDP egress works and the
/// server answered our transaction.
pub async fn probe(server: &str, timeout: Duration) -> anyhow::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let mut txn_id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut txn_id);
    sock.send_to(&encode_binding_request(&txn_id), server)
        .await
        .with_context(|| format!("sending STUN request to {server}"))?;
    let mut buf = [0u8; 256];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .context("no STUN response (UDP may be blocked)")??;
    anyhow::ensure!(
        is_binding_response(&buf[..n], &txn_id),
        "response was not a STUN answer to our request"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn binding_request_wire_format() {
        let txn = [7u8; 12];
        let msg = encode_binding_request(&txn);
        assert_eq!(&msg[0..2], &[0x00, 0x01]); // binding request
        assert_eq!(&msg[2..4], &[0, 0]); // zero attribute length
        assert_eq!(&msg[4..8], &[0x21, 0x12, 0xA4, 0x42]); // magic cookie
        assert_eq!(&msg[8..20], &txn);
    }

    #[test]
    fn response_matching() {
        let txn = [9u8; 12];
        let mut resp = encode_binding_request(&txn);
        resp[1] = 0x01; // turn it into a binding success response
        assert!(is_binding_response(&resp, &txn));
        assert!(!is_binding_response(&resp, &[0u8; 12]));
        assert!(!is_binding_response(&resp[..10], &txn));
    }

    #[tokio::test]
    async fn probe_succeeds_against_fake_stun_server() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert!(n >= 20 && buf[0] == 0x00 && buf[1] == 0x01);
            let mut resp = [0u8; 20];
            resp[0] = 0x01;
            resp[1] = 0x01; // binding success response
            resp[4..8].copy_from_slice(&buf[4..8]);
            resp[8..20].copy_from_slice(&buf[8..20]);
            server.send_to(&resp, peer).await.unwrap();
        });
        probe(&addr.to_string(), Duration::from_secs(2))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn probe_fails_without_server() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        assert!(probe(&addr.to_string(), Duration::from_millis(200))
            .await
            .is_err());
    }
}
