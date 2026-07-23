//! WebRTC data-channel transport (design §4.1–4.2). Establishes an
//! `RTCPeerConnection`, exchanges SDP + trickled ICE (each E2E-encrypted under
//! the session `signaling_key`) over a `Rendezvous`, and exposes the opened
//! data channel as a `stream::MsgChannel`. STUN-only in P1 (no TURN → P2).

use crate::crypto::{open_random, seal_random};
use crate::handshake::{decode_frame, encode_frame, role_byte, KIND_ICE, KIND_SDP};
use crate::pake::{Role, SessionKey};
use crate::rendezvous::Rendezvous;
use crate::stream::MsgChannel;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

fn other(r: Role) -> Role {
    match r {
        Role::Receiver => Role::Sender,
        Role::Sender => Role::Receiver,
    }
}

/// Item flowing through `WebRtcChannel`'s internal mpsc. webrtc-0.17.2 fires
/// `on_close` on remote disconnect but does NOT drop the `on_message` closure
/// (which holds a `Sender` clone kept alive by `WebRtcChannel`'s own `dc`
/// handle) — so without an explicit close signal, `rx.recv()` would pend
/// forever instead of erroring per the `MsgChannel` contract.
enum Item {
    Msg(Vec<u8>),
    Closed,
}

/// A message channel over an open WebRTC data channel.
pub struct WebRtcChannel {
    dc: Arc<RTCDataChannel>,
    rx: mpsc::Receiver<Item>,
    _pc: Arc<RTCPeerConnection>, // kept alive for the channel's lifetime
}

#[async_trait]
impl MsgChannel for WebRtcChannel {
    async fn send(&mut self, msg: &[u8]) -> anyhow::Result<()> {
        self.dc
            .send(&Bytes::copy_from_slice(msg))
            .await
            .context("data channel send failed")?;
        Ok(())
    }
    async fn recv(&mut self) -> anyhow::Result<Vec<u8>> {
        match self.rx.recv().await {
            Some(Item::Msg(m)) => Ok(m),
            Some(Item::Closed) | None => anyhow::bail!("data channel closed by peer"),
        }
    }
}

impl Drop for WebRtcChannel {
    fn drop(&mut self) {
        // RTCPeerConnection has no Drop impl of its own; close() is the only
        // clean teardown (stops ICE/DTLS/SCTP + internal tasks). Best-effort:
        // skip if we're not inside a tokio runtime (e.g. during process exit).
        //
        // `dc.send()` only hands data to the local SCTP stack — it does not
        // wait for the peer to receive it. Closing right away can tear down
        // ICE/DTLS before a just-sent final message (e.g. a protocol's last
        // ack) actually leaves the machine, which the peer would otherwise
        // observe as a disconnect instead of that message. Give the local
        // send queue a brief, bounded chance to drain first.
        let pc = self._pc.clone();
        let dc = self.dc.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                for _ in 0..50 {
                    if dc.buffered_amount().await == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let _ = pc.close().await;
            });
        }
    }
}

fn build_pc_config(stun_servers: &[String]) -> RTCConfiguration {
    RTCConfiguration {
        ice_servers: if stun_servers.is_empty() {
            vec![] // tests: host candidates only (loopback)
        } else {
            vec![RTCIceServer {
                urls: stun_servers.to_vec(),
                ..Default::default()
            }]
        },
        ..Default::default()
    }
}

async fn build_pc(stun_servers: &[String]) -> anyhow::Result<Arc<RTCPeerConnection>> {
    let mut m = MediaEngine::default();
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();
    Ok(Arc::new(
        api.new_peer_connection(build_pc_config(stun_servers))
            .await?,
    ))
}

/// Wire on_ice_candidate to publish sealed ICE frames to the rendezvous.
fn wire_local_ice(
    pc: &Arc<RTCPeerConnection>,
    rv: Arc<dyn Rendezvous>,
    topic: String,
    sig_key: [u8; 32],
    role: Role,
) {
    pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let rv = rv.clone();
        let topic = topic.clone();
        Box::pin(async move {
            if let Some(c) = c {
                if let Ok(init) = c.to_json() {
                    if let Ok(json) = serde_json::to_vec(&init) {
                        let sealed = seal_random(&sig_key, &[KIND_ICE, role_byte(role)], &json);
                        let _ = rv
                            .publish(&topic, &encode_frame(KIND_ICE, role, &sealed))
                            .await;
                    }
                }
            }
        })
    }));
}

/// Bridge the data channel's on_message/on_close to an mpsc the MsgChannel
/// drains, and fire `open` when the channel opens.
fn wire_channel(dc: &Arc<RTCDataChannel>, open: Arc<Notify>) -> mpsc::Receiver<Item> {
    let (tx, rx) = mpsc::channel::<Item>(64);
    let close_tx = tx.clone();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send(Item::Msg(msg.data.to_vec())).await;
        })
    }));
    dc.on_close(Box::new(move || {
        let close_tx = close_tx.clone();
        Box::pin(async move {
            let _ = close_tx.send(Item::Closed).await;
        })
    }));
    let open2 = open.clone();
    dc.on_open(Box::new(move || {
        let open2 = open2.clone();
        Box::pin(async move {
            open2.notify_one();
        })
    }));
    rx
}

/// Aborts the wrapped task when dropped — guarantees the signaling pump task
/// (spawned in `establish`) never leaks, whether `establish` returns
/// successfully, errors out via `?`, or is cancelled by `connect`'s outer
/// timeout.
struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Establish an `RTCPeerConnection`'s data channel over `rv`: subscribes,
/// wires ICE/data-channel handlers, drives the offer (Receiver) or waits for
/// it (Sender), and waits for the channel to open. Unbounded by itself —
/// `connect` applies the single overall deadline and tears down `pc` (and
/// aborts the signaling pump, via `AbortOnDrop`) on every exit path.
async fn establish(
    pc: Arc<RTCPeerConnection>,
    rv: Arc<dyn Rendezvous>,
    topic: &str,
    key: &SessionKey,
    role: Role,
) -> anyhow::Result<WebRtcChannel> {
    let sig_key = key.signaling_key();
    wire_local_ice(&pc, rv.clone(), topic.to_string(), sig_key, role);

    let open = Arc::new(Notify::new());
    // channel handle differs by role: receiver creates it, sender receives it.
    let (chan_tx, mut chan_rx) = mpsc::channel::<(Arc<RTCDataChannel>, mpsc::Receiver<Item>)>(1);

    match role {
        Role::Receiver => {
            let dc = pc.create_data_channel("b2p", None).await?;
            let rx = wire_channel(&dc, open.clone());
            chan_tx.send((dc, rx)).await.ok();
        }
        Role::Sender => {
            let open2 = open.clone();
            let chan_tx2 = chan_tx.clone();
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let open2 = open2.clone();
                let chan_tx2 = chan_tx2.clone();
                Box::pin(async move {
                    let rx = wire_channel(&dc, open2.clone());
                    let _ = chan_tx2.send((dc, rx)).await;
                })
            }));
        }
    }

    // Background pump: apply inbound sealed SDP/ICE frames from the rendezvous.
    // Clone everything the task needs (all Copy or Arc/String) before moving.
    let mut sub = rv.subscribe(topic).await?;
    let pump_pc = pc.clone();
    let pump_rv = rv.clone();
    let pump_topic = topic.to_string();
    let want_role = role_byte(other(role));
    let pump = tokio::spawn(async move {
        // Candidates can trickle in before we've processed the remote SDP;
        // add_ice_candidate errors immediately (doesn't queue) without a
        // remote description set, so buffer and flush once it lands.
        let mut pending_ice: Vec<RTCIceCandidateInit> = Vec::new();
        while let Some(frame) = sub.next().await {
            let Some((kind, r, payload)) = decode_frame(&frame) else {
                continue;
            };
            if r != want_role {
                continue; // our own echo or the wrong peer
            }
            let Ok(plain) = open_random(&sig_key, &[kind, r], payload) else {
                continue;
            };
            if kind == KIND_SDP {
                let Ok(sdp) = serde_json::from_slice::<RTCSessionDescription>(&plain) else {
                    continue;
                };
                if pump_pc.set_remote_description(sdp).await.is_err() {
                    continue;
                }
                for cand in pending_ice.drain(..) {
                    let _ = pump_pc.add_ice_candidate(cand).await;
                }
                // The Sender is the answerer: on the offer, create + publish the answer.
                if role == Role::Sender {
                    if let Ok(answer) = pump_pc.create_answer(None).await {
                        if pump_pc.set_local_description(answer.clone()).await.is_ok() {
                            if let Ok(j) = serde_json::to_vec(&answer) {
                                let sealed =
                                    seal_random(&sig_key, &[KIND_SDP, role_byte(role)], &j);
                                let _ = pump_rv
                                    .publish(&pump_topic, &encode_frame(KIND_SDP, role, &sealed))
                                    .await;
                            }
                        }
                    }
                }
            } else if kind == KIND_ICE {
                if let Ok(init) = serde_json::from_slice::<RTCIceCandidateInit>(&plain) {
                    if pump_pc.remote_description().await.is_some() {
                        let _ = pump_pc.add_ice_candidate(init).await;
                    } else {
                        pending_ice.push(init);
                    }
                }
            }
        }
    });
    // Guarantees the pump is aborted on every exit path below: success
    // return, `?` error, or cancellation by `connect`'s outer timeout. Once
    // the channel is open there's nothing left for the pump to apply for a
    // one-shot transfer, so aborting on success is correct too.
    let _pump_guard = AbortOnDrop(pump.abort_handle());

    // Receiver drives the offer.
    if role == Role::Receiver {
        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer.clone()).await?;
        let j = serde_json::to_vec(&offer)?;
        let sealed = seal_random(&sig_key, &[KIND_SDP, role_byte(role)], &j);
        rv.publish(topic, &encode_frame(KIND_SDP, role, &sealed))
            .await?;
    }

    // Wait for the data channel to open. No inner timeout here — `connect`
    // bounds this whole function (subscribe/publish/wait) with one deadline.
    open.notified().await;
    let (dc, rx) = chan_rx
        .recv()
        .await
        .context("data channel opened but handle was lost")?;
    Ok(WebRtcChannel { dc, rx, _pc: pc })
}

pub async fn connect(
    rv: Arc<dyn Rendezvous>,
    topic: &str,
    key: &SessionKey,
    role: Role,
    stun_servers: &[String],
    timeout: Duration,
) -> anyhow::Result<WebRtcChannel> {
    let pc = build_pc(stun_servers).await?;
    match tokio::time::timeout(timeout, establish(pc.clone(), rv, topic, key, role)).await {
        Ok(Ok(ch)) => Ok(ch),
        Ok(Err(e)) => {
            // Ensure ICE/DTLS/SCTP + internal tasks are torn down on any
            // failed establishment, not just leaked until process exit.
            let _ = pc.close().await;
            Err(e)
        }
        Err(_) => {
            let _ = pc.close().await;
            anyhow::bail!(
                "WebRTC did not connect in time — UDP/STUN may be blocked; \
                 run `b2p doctor`, try --tunnel, or connect on the same LAN"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pake::{Role, SessionKey};
    use crate::rendezvous::Rendezvous;
    use crate::{archive, stream};
    use async_trait::async_trait;
    use futures::stream::{BoxStream, StreamExt};
    use std::sync::{Arc, Mutex};

    // In-memory rendezvous (replays history to late subscribers), same design
    // as handshake.rs's test double.
    struct MemRendezvous {
        log: Mutex<Vec<(String, Vec<u8>)>>,
        tx: tokio::sync::broadcast::Sender<(String, Vec<u8>)>,
    }
    impl MemRendezvous {
        fn new() -> Arc<Self> {
            Arc::new(MemRendezvous {
                log: Mutex::new(vec![]),
                tx: tokio::sync::broadcast::channel(1024).0,
            })
        }
    }
    #[async_trait]
    impl Rendezvous for MemRendezvous {
        async fn publish(&self, topic: &str, frame: &[u8]) -> anyhow::Result<()> {
            self.log
                .lock()
                .unwrap()
                .push((topic.to_string(), frame.to_vec()));
            let _ = self.tx.send((topic.to_string(), frame.to_vec()));
            Ok(())
        }
        async fn subscribe(&self, topic: &str) -> anyhow::Result<BoxStream<'static, Vec<u8>>> {
            let topic = topic.to_string();
            let rx = self.tx.subscribe();
            let history: Vec<Vec<u8>> = self
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _)| *t == topic)
                .map(|(_, f)| f.clone())
                .collect();
            let live = futures::stream::unfold((rx, topic), move |(mut rx, topic)| async move {
                loop {
                    match rx.recv().await {
                        Ok((t, f)) if t == topic => return Some((f, (rx, topic))),
                        Ok(_) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return None,
                    }
                }
            });
            Ok(futures::stream::iter(history).chain(live).boxed())
        }
        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_file_transfer_over_webrtc() {
        let rv = MemRendezvous::new();
        let key = SessionKey([42u8; 32]);
        let topic = "b2p-p1d-test";

        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        // multi-frame content with a short tail
        let content: Vec<u8> = (0..(stream::STREAM_FRAME_SIZE as usize * 2 + 77))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(src.path().join("payload.bin"), &content).unwrap();
        let source = archive::prepare(&[src.path().join("payload.bin")]).unwrap();

        // receiver: connect as Receiver, then recv_into
        let (rv_r, key_r) = (rv.clone(), key.clone());
        let out_path = out.path().to_path_buf();
        let recv = tokio::spawn(async move {
            let mut ch = connect(
                rv_r,
                topic,
                &key_r,
                Role::Receiver,
                &[],
                std::time::Duration::from_secs(20),
            )
            .await
            .unwrap();
            stream::recv_into(&mut ch, &key_r, &out_path, true, false, None).await
        });

        // sender: connect as Sender, then send_source
        let (rv_s, key_s) = (rv.clone(), key.clone());
        let send = tokio::spawn(async move {
            let mut ch = connect(
                rv_s,
                topic,
                &key_s,
                Role::Sender,
                &[],
                std::time::Duration::from_secs(20),
            )
            .await
            .unwrap();
            stream::send_source(&mut ch, &key_s, &source, None).await
        });

        send.await.unwrap().unwrap();
        recv.await.unwrap().unwrap();
        assert_eq!(
            std::fs::read(out.path().join("payload.bin")).unwrap(),
            content
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_errors_when_peer_disconnects() {
        let rv = MemRendezvous::new();
        let key = SessionKey([7u8; 32]);
        let topic = "b2p-p1d-disconnect-test";

        let (rv_r, key_r) = (rv.clone(), key.clone());
        let recv_task = tokio::spawn(async move {
            connect(
                rv_r,
                topic,
                &key_r,
                Role::Receiver,
                &[],
                std::time::Duration::from_secs(20),
            )
            .await
            .unwrap()
        });

        let (rv_s, key_s) = (rv.clone(), key.clone());
        let send_task = tokio::spawn(async move {
            connect(
                rv_s,
                topic,
                &key_s,
                Role::Sender,
                &[],
                std::time::Duration::from_secs(20),
            )
            .await
            .unwrap()
        });

        let mut recv_ch = recv_task.await.unwrap();
        let send_ch = send_task.await.unwrap();

        // Drop the sender's channel: its `Drop` impl closes its `pc`, tearing
        // down ICE/DTLS/SCTP — the receiver's data channel should observe
        // this as a remote close and fire `on_close`.
        drop(send_ch);

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), recv_ch.recv())
            .await
            .expect("recv should observe the peer's disconnect, not hang");
        assert!(
            result.is_err(),
            "recv should return Err once the peer's data channel closes, not hang or succeed"
        );
    }
}
