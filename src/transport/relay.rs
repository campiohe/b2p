//! Relay transport (P2b): a WebSocket to the operator's Cloudflare Worker,
//! which pairs the two peers in a room and forwards opaque messages. Both
//! sides dial outbound 443, so this works on the UDP-blocked and CGNAT
//! networks where WebRTC cannot form. Every frame is sealed before it
//! reaches the socket — the relay carries ciphertext only.
//!
//! Wire format (protocol v1, mirrored by relay-worker/): binary WS messages
//! carry one or more `u32 LE header || bytes` pieces — the header's low 31
//! bits are the piece length, the MSB says "this logical frame continues in
//! a later piece" (so a frame larger than Workers' 1 MiB message cap still
//! travels). Text WS messages are small JSON controls.

use anyhow::bail;
use std::collections::VecDeque;

/// Cloudflare Workers reject WS messages over 1 MiB; stay well under.
pub const MAX_WS_PAYLOAD: usize = 960 * 1024;
const CONT: u32 = 1 << 31;

/// Drain `pending` logical frames into one WS payload. A frame that doesn't
/// fit is split; the continuation bit on a piece's header says "the next
/// piece of this logical frame follows in a later payload".
pub fn pack_frames(pending: &mut VecDeque<Vec<u8>>) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(front) = pending.front_mut() {
        let room = MAX_WS_PAYLOAD.saturating_sub(buf.len() + 4);
        if room == 0 {
            break;
        }
        if front.len() <= room {
            let f = pending.pop_front().expect("front exists");
            buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            buf.extend_from_slice(&f);
        } else {
            let rest = front.split_off(room);
            let piece = std::mem::replace(front, rest);
            buf.extend_from_slice(&((piece.len() as u32) | CONT).to_le_bytes());
            buf.extend_from_slice(&piece);
            break; // payload is full
        }
    }
    (!buf.is_empty()).then_some(buf)
}

/// Reassembles logical frames from WS payloads, buffering continuations.
#[derive(Default)]
pub struct Debatcher {
    partial: Vec<u8>,
}

impl Debatcher {
    pub fn push(&mut self, mut p: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        while !p.is_empty() {
            if p.len() < 4 {
                bail!("truncated sub-frame header");
            }
            let hdr = u32::from_le_bytes(p[..4].try_into().expect("4 bytes"));
            let (cont, len) = (hdr & CONT != 0, (hdr & !CONT) as usize);
            p = &p[4..];
            if p.len() < len {
                bail!("truncated sub-frame body");
            }
            self.partial.extend_from_slice(&p[..len]);
            p = &p[len..];
            if !cont {
                out.push(std::mem::take(&mut self.partial));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_frames_batch_into_one_payload() {
        let mut q: VecDeque<Vec<u8>> = [vec![1u8; 10], vec![2u8; 20]].into();
        let p = pack_frames(&mut q).unwrap();
        assert!(q.is_empty());
        assert_eq!(p.len(), 4 + 10 + 4 + 20);
        let mut d = Debatcher::default();
        assert_eq!(d.push(&p).unwrap(), vec![vec![1u8; 10], vec![2u8; 20]]);
    }

    #[test]
    fn oversized_frame_splits_and_reassembles() {
        let big = vec![7u8; MAX_WS_PAYLOAD * 2 + 123];
        let mut q: VecDeque<Vec<u8>> = [big.clone()].into();
        let mut d = Debatcher::default();
        let mut out = vec![];
        while let Some(p) = pack_frames(&mut q) {
            assert!(p.len() <= MAX_WS_PAYLOAD);
            out.extend(d.push(&p).unwrap());
        }
        assert_eq!(out, vec![big]);
    }

    #[test]
    fn empty_queue_yields_none() {
        assert!(pack_frames(&mut VecDeque::new()).is_none());
    }

    #[test]
    fn debatcher_rejects_garbage() {
        let mut d = Debatcher::default();
        assert!(d.push(&[1, 2, 3]).is_err()); // truncated header
        let mut bad = 5u32.to_le_bytes().to_vec(); // claims 5 bytes, has 2
        bad.extend_from_slice(&[9, 9]);
        assert!(Debatcher::default().push(&bad).is_err());
        drop(d);
    }
}
