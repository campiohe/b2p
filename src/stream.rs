//! Framed AEAD payload transfer over a reliable, ordered message channel
//! (design §4.3). Frame sequence, sender → receiver:
//!   1. manifest        (Domain::StreamToReceiver, index 0)
//!   2. [receiver replies ManifestAck, Domain::StreamToSender, index 0]
//!   3. payload frames  (Domain::StreamToReceiver, index 1..=N)   — blobs only
//!   4. commit (hash)   (Domain::StreamToReceiver, index N+1)
//!   5. [receiver replies CommitAck, Domain::StreamToSender, index 1]
//!
//! Each direction has its own Domain so the shared stream key never reuses a
//! nonce. The receiver stages into the existing `Store`, so blake3 verification
//! and finalize/unpack are identical to the tunnel transport.

use crate::archive::{unpack_tar, Source};
use crate::crypto::{open, seal, Domain};
use crate::pake::SessionKey;
use crate::protocol::{Commit, CommitAck, Kind, Manifest, ManifestAck, PROTOCOL_VERSION};
use crate::send::read_chunk;
use crate::store::Store;
use anyhow::{bail, Context};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::io::Read;
use std::path::Path;

/// Payload framing size. One frame + AEAD tag fits comfortably in a single
/// SCTP data-channel message.
pub const STREAM_FRAME_SIZE: u64 = 16 * 1024;

#[async_trait]
pub trait MsgChannel: Send {
    async fn send(&mut self, msg: &[u8]) -> anyhow::Result<()>;
    async fn recv(&mut self) -> anyhow::Result<Vec<u8>>;
}

/// Seal a JSON value at an EXPLICIT frame index. Unlike `protocol::seal_json`
/// (fixed internal index 0), this is safe for multiple frames in one direction
/// because each carries its own index → its own nonce.
fn seal_val<T: Serialize>(sk: &[u8; 32], domain: Domain, index: u64, v: &T) -> Vec<u8> {
    seal(
        sk,
        domain,
        index,
        b"",
        &serde_json::to_vec(v).expect("serializable"),
    )
}

fn open_val<T: DeserializeOwned>(
    sk: &[u8; 32],
    domain: Domain,
    index: u64,
    ct: &[u8],
) -> anyhow::Result<T> {
    let pt =
        open(sk, domain, index, b"", ct).map_err(|_| anyhow::anyhow!("frame failed to decrypt"))?;
    Ok(serde_json::from_slice(&pt)?)
}

fn safe_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "b2p-download".to_string())
}

fn blake3_file(path: &Path) -> anyhow::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn stream_manifest(source: &Source) -> Manifest {
    match source {
        Source::Blob {
            kind,
            name,
            entries,
            total_size,
            transfer_id,
            ..
        } => Manifest {
            version: PROTOCOL_VERSION,
            transfer_id: transfer_id.clone(),
            kind: *kind,
            name: name.clone(),
            entries: entries.clone(),
            total_size: *total_size,
            chunk_size: STREAM_FRAME_SIZE,
            text: None,
        },
        Source::Text {
            content,
            transfer_id,
        } => Manifest {
            version: PROTOCOL_VERSION,
            transfer_id: transfer_id.clone(),
            kind: Kind::Text,
            name: String::new(),
            entries: vec![],
            total_size: content.len() as u64,
            chunk_size: STREAM_FRAME_SIZE,
            text: Some(content.clone()),
        },
    }
}

pub async fn send_source(
    ch: &mut dyn MsgChannel,
    key: &SessionKey,
    source: &Source,
    progress: Option<indicatif::ProgressBar>,
) -> anyhow::Result<String> {
    let sk = key.stream_key();
    let manifest = stream_manifest(source);

    // 1. manifest  (StreamToReceiver, index 0)
    ch.send(&seal_val(&sk, Domain::StreamToReceiver, 0, &manifest))
        .await?;
    // 2. accept    (StreamToSender, index 0)
    let ack: ManifestAck = open_val(&sk, Domain::StreamToSender, 0, &ch.recv().await?)
        .context("could not read the receiver's response (wrong code?)")?;
    if !ack.accepted {
        bail!("the receiver declined the transfer");
    }
    if manifest.kind == Kind::Text {
        return Ok("text delivered".to_string());
    }

    // 3. payload frames  (StreamToReceiver, index 1..=total_chunks)
    let (path, total_size) = match source {
        Source::Blob {
            path, total_size, ..
        } => (path.clone(), *total_size),
        Source::Text { .. } => unreachable!("text returned above"),
    };
    let total_chunks = manifest.total_chunks();
    if let Some(pb) = &progress {
        pb.set_length(total_size);
    }
    for i in 0..total_chunks {
        let plain = read_chunk(&path, i, STREAM_FRAME_SIZE, total_size)?;
        let n = plain.len() as u64;
        ch.send(&seal(&sk, Domain::StreamToReceiver, 1 + i, b"", &plain))
            .await?;
        if let Some(pb) = &progress {
            pb.inc(n);
        }
    }

    // 4. commit  (StreamToReceiver, index total_chunks+1)
    let hash = blake3_file(&path)?;
    ch.send(&seal_val(
        &sk,
        Domain::StreamToReceiver,
        1 + total_chunks,
        &Commit { blake3_hex: hash },
    ))
    .await?;
    // 5. result  (StreamToSender, index 1)
    let cack: CommitAck = open_val(&sk, Domain::StreamToSender, 1, &ch.recv().await?)?;
    if !cack.ok {
        bail!(
            "receiver failed to finalize: {}",
            cack.error.unwrap_or_default()
        );
    }
    Ok("transfer complete".to_string())
}

pub async fn recv_into(
    ch: &mut dyn MsgChannel,
    key: &SessionKey,
    out_dir: &Path,
    auto_accept: bool,
    overwrite: bool,
    progress: Option<indicatif::ProgressBar>,
) -> anyhow::Result<String> {
    let sk = key.stream_key();

    // 1. manifest  (StreamToReceiver, index 0)
    let manifest: Manifest = open_val(&sk, Domain::StreamToReceiver, 0, &ch.recv().await?)
        .context("could not decrypt the manifest (wrong code?)")?;
    if manifest.version != PROTOCOL_VERSION {
        ch.send(&seal_val(
            &sk,
            Domain::StreamToSender,
            0,
            &ManifestAck {
                accepted: false,
                complete: false,
                have: vec![],
            },
        ))
        .await?;
        bail!("protocol version mismatch");
    }

    // 2. accept decision (auto for now; P1e adds the interactive prompt)  (StreamToSender, index 0)
    let name = safe_name(&manifest.name);
    let dest_exists = manifest.kind == Kind::File && out_dir.join(&name).exists();
    let accepted = auto_accept && !(dest_exists && !overwrite);
    ch.send(&seal_val(
        &sk,
        Domain::StreamToSender,
        0,
        &ManifestAck {
            accepted,
            complete: false,
            have: vec![],
        },
    ))
    .await?;
    if !accepted {
        bail!("declined (destination exists; pass --overwrite)");
    }

    if manifest.kind == Kind::Text {
        return Ok(manifest.text.unwrap_or_default());
    }

    // 3. stage payload frames into the Store
    let mut store = Store::open_or_create(
        out_dir,
        &name,
        &manifest.transfer_id,
        manifest.total_size,
        manifest.chunk_size,
    )?;
    if let Some(pb) = &progress {
        pb.set_length(manifest.total_size);
    }
    let total_chunks = manifest.total_chunks();
    for i in 0..total_chunks {
        let ct = ch.recv().await?;
        let plain = open(&sk, Domain::StreamToReceiver, 1 + i, b"", &ct)
            .map_err(|_| anyhow::anyhow!("frame {i} failed to decrypt"))?;
        let n = plain.len() as u64;
        store.write_chunk(i, &plain)?;
        if let Some(pb) = &progress {
            pb.inc(n);
        }
    }

    // 4. commit + verify + finalize  (commit: StreamToReceiver idx total_chunks+1; ack: StreamToSender idx 1)
    let commit: Commit = open_val(
        &sk,
        Domain::StreamToReceiver,
        1 + total_chunks,
        &ch.recv().await?,
    )?;
    let result = finalize(store, &manifest, &commit, out_dir, &name);
    let (ok, error, desc) = match &result {
        Ok(desc) => (true, None, desc.clone()),
        Err(e) => (false, Some(e.to_string()), String::new()),
    };
    ch.send(&seal_val(
        &sk,
        Domain::StreamToSender,
        1,
        &CommitAck { ok, error },
    ))
    .await?;
    result.map(|_| desc)
}

fn finalize(
    store: Store,
    manifest: &Manifest,
    commit: &Commit,
    out_dir: &Path,
    name: &str,
) -> anyhow::Result<String> {
    if !store.is_complete() {
        bail!("transfer incomplete");
    }
    if store.file_hash()? != commit.blake3_hex {
        bail!("integrity check failed: hash mismatch");
    }
    match manifest.kind {
        Kind::File => {
            let dest = out_dir.join(name);
            store.finalize_file(&dest)?;
            Ok(format!("saved {}", dest.display()))
        }
        Kind::Tar => {
            unpack_tar(store.data_path(), out_dir)?;
            store.cleanup()?;
            Ok(format!("unpacked archive into {}", out_dir.display()))
        }
        Kind::Text => unreachable!("text returned before staging"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive;
    use crate::pake::SessionKey;
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    struct Pipe {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }
    fn pipe() -> (Pipe, Pipe) {
        let (a_tx, a_rx) = mpsc::channel(64);
        let (b_tx, b_rx) = mpsc::channel(64);
        (Pipe { tx: a_tx, rx: b_rx }, Pipe { tx: b_tx, rx: a_rx })
    }
    #[async_trait]
    impl MsgChannel for Pipe {
        async fn send(&mut self, msg: &[u8]) -> anyhow::Result<()> {
            self.tx
                .send(msg.to_vec())
                .await
                .map_err(|_| anyhow::anyhow!("pipe closed"))
        }
        async fn recv(&mut self) -> anyhow::Result<Vec<u8>> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("pipe closed"))
        }
    }

    fn key() -> SessionKey {
        SessionKey([7u8; 32])
    }

    #[tokio::test]
    async fn round_trips_a_multi_frame_file() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        // > 1 frame: content spans several STREAM_FRAME_SIZE chunks with a short tail
        let content: Vec<u8> = (0..(STREAM_FRAME_SIZE as usize * 3 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(src.path().join("big.bin"), &content).unwrap();
        let source = archive::prepare(&[src.path().join("big.bin")]).unwrap();

        let (mut s, mut r) = pipe();
        let k = key();
        let out_path = out.path().to_path_buf();
        let recv =
            tokio::spawn(
                async move { recv_into(&mut r, &key(), &out_path, true, false, None).await },
            );
        send_source(&mut s, &k, &source, None).await.unwrap();
        recv.await.unwrap().unwrap();

        assert_eq!(std::fs::read(out.path().join("big.bin")).unwrap(), content);
    }

    #[tokio::test]
    async fn round_trips_a_folder_tar() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("proj/sub")).unwrap();
        std::fs::write(src.path().join("proj/a.txt"), b"AAA").unwrap();
        std::fs::write(src.path().join("proj/sub/b.txt"), b"BBBB").unwrap();
        let source = archive::prepare(&[src.path().join("proj")]).unwrap();

        let (mut s, mut r) = pipe();
        let k = key();
        let out_path = out.path().to_path_buf();
        let recv =
            tokio::spawn(
                async move { recv_into(&mut r, &key(), &out_path, true, false, None).await },
            );
        send_source(&mut s, &k, &source, None).await.unwrap();
        recv.await.unwrap().unwrap();

        assert_eq!(
            std::fs::read_to_string(out.path().join("proj/a.txt")).unwrap(),
            "AAA"
        );
        assert_eq!(
            std::fs::read_to_string(out.path().join("proj/sub/b.txt")).unwrap(),
            "BBBB"
        );
    }

    #[tokio::test]
    async fn text_completes_at_manifest() {
        let out = tempfile::tempdir().unwrap();
        let source = archive::prepare_text("the wifi password is hunter2");
        let (mut s, mut r) = pipe();
        let k = key();
        let out_path = out.path().to_path_buf();
        let recv =
            tokio::spawn(
                async move { recv_into(&mut r, &key(), &out_path, true, false, None).await },
            );
        let desc = send_source(&mut s, &k, &source, None).await.unwrap();
        let got = recv.await.unwrap().unwrap();
        assert!(desc.contains("text") || desc.contains("delivered"));
        assert!(got.contains("hunter2") || got.contains("text"));
    }

    #[tokio::test]
    async fn declined_transfer_reports_cleanly() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        // pre-create the destination so auto_accept without overwrite declines
        std::fs::write(src.path().join("f.bin"), b"data").unwrap();
        std::fs::write(out.path().join("f.bin"), b"old").unwrap();
        let source = archive::prepare(&[src.path().join("f.bin")]).unwrap();

        let (mut s, mut r) = pipe();
        let k = key();
        let out_path = out.path().to_path_buf();
        let recv =
            tokio::spawn(
                async move { recv_into(&mut r, &key(), &out_path, true, false, None).await },
            );
        let sent = send_source(&mut s, &k, &source, None).await;
        let _ = recv.await.unwrap();
        assert!(sent.is_err(), "sender should see the decline");
        // destination untouched
        assert_eq!(std::fs::read(out.path().join("f.bin")).unwrap(), b"old");
    }

    #[tokio::test]
    async fn wrong_key_receiver_cannot_open_manifest() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f.bin"), b"secret").unwrap();
        let source = archive::prepare(&[src.path().join("f.bin")]).unwrap();
        let (mut s, mut r) = pipe();
        let out_path = out.path().to_path_buf();
        // receiver holds a DIFFERENT key
        let recv = tokio::spawn(async move {
            recv_into(&mut r, &SessionKey([9u8; 32]), &out_path, true, false, None).await
        });
        let _ = send_source(&mut s, &SessionKey([7u8; 32]), &source, None).await;
        assert!(recv.await.unwrap().is_err());
        assert!(!out.path().join("f.bin").exists());
    }
}
