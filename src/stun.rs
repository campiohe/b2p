//! Minimal STUN (RFC 5389) binding-request probe. Used only by `b2p doctor`
//! to answer one question: does UDP egress to a public STUN server work?
//! (That is what decides whether the v2 WebRTC transport will be viable.)

use anyhow::Context;
use rand::RngCore;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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

/// Parse XOR-MAPPED-ADDRESS (RFC 5389 §15.2) from a binding response that echoes
/// `txn_id` — the public address the STUN server saw our socket mapped to.
pub fn parse_xor_mapped_address(resp: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if !is_binding_response(resp, txn_id) {
        return None;
    }
    let mut i = 20; // skip the 20-byte STUN header
    while i + 4 <= resp.len() {
        let attr_type = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let len = u16::from_be_bytes([resp[i + 2], resp[i + 3]]) as usize;
        let val = i + 4;
        let end = val + len;
        if end > resp.len() {
            break;
        }
        // XOR-MAPPED-ADDRESS = 0x0020. value: reserved(1) family(1) x-port(2) x-addr.
        if attr_type == 0x0020 && len >= 4 {
            let port = u16::from_be_bytes([resp[val + 2], resp[val + 3]]) ^ 0x2112;
            match resp[val + 1] {
                0x01 if len >= 8 => {
                    let a = [
                        resp[val + 4] ^ MAGIC_COOKIE[0],
                        resp[val + 5] ^ MAGIC_COOKIE[1],
                        resp[val + 6] ^ MAGIC_COOKIE[2],
                        resp[val + 7] ^ MAGIC_COOKIE[3],
                    ];
                    return Some(SocketAddr::from((Ipv4Addr::from(a), port)));
                }
                0x02 if len >= 20 => {
                    let mut key = [0u8; 16];
                    key[..4].copy_from_slice(&MAGIC_COOKIE);
                    key[4..].copy_from_slice(txn_id);
                    let mut a = [0u8; 16];
                    for (j, b) in a.iter_mut().enumerate() {
                        *b = resp[val + 4 + j] ^ key[j];
                    }
                    return Some(SocketAddr::from((Ipv6Addr::from(a), port)));
                }
                _ => return None,
            }
        }
        // attribute values are padded to a 4-byte boundary
        i = end + ((4 - (len % 4)) % 4);
    }
    None
}

/// How this network's NAT maps one local socket to a public address — the thing
/// that actually decides whether STUN-only WebRTC can work peer-to-peer.
#[derive(Debug, PartialEq, Eq)]
pub enum NatMapping {
    /// ≥2 servers answered with the SAME mapped port — endpoint-independent
    /// (cone) NAT or open internet; direct WebRTC is viable.
    EndpointIndependent(SocketAddr),
    /// ≥2 servers answered with DIFFERENT mapped ports — symmetric NAT; a
    /// reflexive candidate points at a port the peer cannot reach, so STUN-only
    /// hole punching to another NATed peer fails.
    Symmetric(Vec<u16>),
    /// Exactly one server answered — reachable, but mapping can't be classified.
    OneResponse(SocketAddr),
    /// No server answered — UDP egress is likely blocked.
    NoResponse,
}

/// Probe each `server` from a single shared UDP socket and classify the NAT's
/// mapping behavior by comparing the observed mapped ports. This is what tells a
/// symmetric NAT (every check green, yet every cross-network transfer fails)
/// apart from a friendly one.
pub async fn nat_mapping(servers: &[&str], timeout: Duration) -> NatMapping {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return NatMapping::NoResponse,
    };
    let mut mapped: Vec<SocketAddr> = Vec::new();
    for server in servers {
        let mut txn_id = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut txn_id);
        if sock
            .send_to(&encode_binding_request(&txn_id), server)
            .await
            .is_err()
        {
            continue;
        }
        let mut buf = [0u8; 256];
        if let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            if let Some(addr) = parse_xor_mapped_address(&buf[..n], &txn_id) {
                mapped.push(addr);
            }
        }
    }
    match mapped.len() {
        0 => NatMapping::NoResponse,
        1 => NatMapping::OneResponse(mapped[0]),
        _ => {
            let ports: Vec<u16> = mapped.iter().map(|a| a.port()).collect();
            if ports.iter().all(|p| *p == ports[0]) {
                NatMapping::EndpointIndependent(mapped[0])
            } else {
                NatMapping::Symmetric(ports)
            }
        }
    }
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

    #[test]
    fn parses_xor_mapped_address() {
        let txn = [3u8; 12];
        let ip = [1u8, 2, 3, 4];
        let port: u16 = 5678;
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x01, 0x01]); // binding success response
        msg.extend_from_slice(&[0x00, 0x0C]); // message length: 4 (attr hdr) + 8 (value)
        msg.extend_from_slice(&MAGIC_COOKIE);
        msg.extend_from_slice(&txn);
        msg.extend_from_slice(&[0x00, 0x20]); // XOR-MAPPED-ADDRESS
        msg.extend_from_slice(&[0x00, 0x08]); // attr length 8
        msg.push(0x00); // reserved
        msg.push(0x01); // family IPv4
        msg.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        msg.extend_from_slice(&[
            ip[0] ^ MAGIC_COOKIE[0],
            ip[1] ^ MAGIC_COOKIE[1],
            ip[2] ^ MAGIC_COOKIE[2],
            ip[3] ^ MAGIC_COOKIE[3],
        ]);
        assert_eq!(
            parse_xor_mapped_address(&msg, &txn).unwrap(),
            "1.2.3.4:5678".parse::<SocketAddr>().unwrap()
        );
        // a response to a different transaction is not ours
        assert!(parse_xor_mapped_address(&msg, &[9u8; 12]).is_none());
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
