use crate::archive::Source;
use crate::code::Code;
use crate::crypto::{seal, Domain, CHUNK_SIZE};
use crate::protocol::*;
use anyhow::{bail, Context};
use bytes::Bytes;
use futures::stream::{self, TryStreamExt};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

const PARALLEL_UPLOADS: usize = 4;
const CHUNK_ATTEMPTS: u32 = 5;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(120);

pub fn build_manifest(source: &Source) -> anyhow::Result<Manifest> {
    Ok(match source {
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
            chunk_size: CHUNK_SIZE,
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
            chunk_size: CHUNK_SIZE,
            text: Some(content.clone()),
        },
    })
}

pub fn read_chunk(
    path: &Path,
    index: u64,
    chunk_size: u64,
    total_size: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(index * chunk_size))?;
    let len = chunk_size.min(total_size - index * chunk_size) as usize;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
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

#[derive(Debug)]
pub(crate) enum FailLayer {
    Dns,
    Tls,
    Connect,
    Other,
}

/// Classify a rendered error chain into the network layer that failed.
/// Order matters: DNS wording is most specific, TLS next; generic
/// connect/timeout wording comes last.
pub(crate) fn classify_error_text(chain: &str) -> FailLayer {
    let t = chain.to_ascii_lowercase();
    if t.contains("dns error")
        || t.contains("failed to lookup address")
        || t.contains("name or service not known")
        || t.contains("nodename nor servname")
        || t.contains("no such host")
    {
        FailLayer::Dns
    } else if t.contains("certificate")
        || t.contains("unknownissuer")
        || t.contains("handshake")
        || t.contains("tls")
    {
        FailLayer::Tls
    } else if t.contains("connect")
        || t.contains("timed out")
        || t.contains("timeout")
        || t.contains("reset")
        || t.contains("refused")
    {
        FailLayer::Connect
    } else {
        FailLayer::Other
    }
}

fn error_chain_text(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

/// Turn a failed first request into a layered error message, and run the
/// doctor against the code's host so the user sees *why* it failed
/// (spec §6: run automatically on failure).
async fn connect_failure(
    url: &url::Url,
    e: &reqwest::Error,
    tls: &crate::http::TlsOpts,
) -> anyhow::Error {
    let host = url.host_str().unwrap_or("<no host>").to_string();
    let chain = error_chain_text(e);
    let layer = classify_error_text(&chain);
    let (name, hint) = match layer {
        FailLayer::Dns => (
            "DNS",
            format!("this network may be filtering {host} — see the diagnosis below"),
        ),
        FailLayer::Tls => (
            "TLS",
            "if this network intercepts TLS, add its root CA to the OS store or pass --cafile"
                .to_string(),
        ),
        FailLayer::Connect => (
            "transport",
            "the receiver may be gone (re-run `b2p receive`), or the network blocks this host"
                .to_string(),
        ),
        FailLayer::Other => ("transport", "unexpected failure".to_string()),
    };
    eprintln!("\n{name} layer failed reaching {host}: {chain}");
    eprintln!("hint: {hint}");
    let ran_doctor = !matches!(layer, FailLayer::Other);
    if ran_doctor {
        eprintln!("\nRunning diagnostics (b2p doctor)...\n");
        let report = crate::doctor::run(&crate::doctor::DoctorArgs {
            target_host: Some(host.clone()),
            cafile: tls.cafile.clone(),
            relay: None,
            relay_token: None,
        })
        .await;
        eprintln!("{report}");
    }
    anyhow::anyhow!("{}", failure_summary(name, &host, ran_doctor))
}

/// The final error text for `connect_failure`, split out so it's testable
/// without running the async doctor pass.
fn failure_summary(name: &str, host: &str, ran_doctor: bool) -> String {
    if ran_doctor {
        format!("{name} failure reaching {host} — see diagnostics above")
    } else {
        format!("{name} failure reaching {host}")
    }
}

/// Build the sender's HTTP client on top of the OS-trust client, additionally
/// resolving a remote tunnel host over DoH so a DNS-layer filter (e.g. Cisco
/// Umbrella sinkholing `*.trycloudflare.com`) can't redirect us to a block
/// page. Falls back to system DNS if DoH is unavailable. Direct/LAN codes (IP
/// literal or localhost) skip DoH entirely — there is nothing to un-filter.
async fn build_client(
    url: &url::Url,
    tls: &crate::http::TlsOpts,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = crate::http::builder(tls)?;
    if let Some(host) = url.host_str() {
        let is_ip = host.parse::<std::net::IpAddr>().is_ok();
        if !is_ip && host != "localhost" {
            match crate::doh::resolve(host, tls).await {
                Ok(ips) if !ips.is_empty() => {
                    let port = url.port_or_known_default().unwrap_or(443);
                    let addrs: Vec<std::net::SocketAddr> = ips
                        .iter()
                        .map(|ip| std::net::SocketAddr::new(*ip, port))
                        .collect();
                    eprintln!("Resolved {host} via DoH ({} address(es))", addrs.len());
                    builder = builder.resolve_to_addrs(host, &addrs);
                }
                Ok(_) => eprintln!("DoH returned no records for {host}; using system DNS"),
                Err(e) => eprintln!("DoH lookup failed ({e:#}); using system DNS"),
            }
        }
    }
    Ok(builder.build()?)
}

pub async fn send(
    code: &Code,
    source: Source,
    progress: Option<indicatif::ProgressBar>,
    tls: &crate::http::TlsOpts,
) -> anyhow::Result<String> {
    let key = code.secret.data_key();
    let token = code.secret.auth_token();
    let base = code.base_url.as_str().trim_end_matches('/').to_string();
    let client = build_client(&code.base_url, tls).await?;

    let manifest = build_manifest(&source)?;
    let manifest_body = seal_json(&key, Domain::Manifest, b"", &manifest);

    let resp = match client
        .post(format!("{base}/v1/manifest"))
        .bearer_auth(&token)
        .body(manifest_body)
        .timeout(ACCEPT_TIMEOUT + Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return Err(connect_failure(&code.base_url, &e, tls).await),
    };
    if resp.status() == 401 {
        bail!("auth rejected (HTTP 401) — the code is wrong or expired");
    }
    if !resp.status().is_success() {
        bail!("manifest rejected: HTTP {}", resp.status());
    }
    let ack: ManifestAck = resp.json().await.context("invalid manifest response")?;
    if !ack.accepted {
        bail!("receiver declined the transfer (or protocol version mismatch)");
    }
    if ack.complete {
        return Ok("text delivered".to_string());
    }

    let (path, total_size, tid) = match &source {
        Source::Blob {
            path,
            total_size,
            transfer_id,
            ..
        } => (path.clone(), *total_size, transfer_id.clone()),
        Source::Text { .. } => unreachable!("text completes at manifest time"),
    };

    let total_chunks = manifest.total_chunks();
    let have: std::collections::HashSet<u64> = ack.have.into_iter().collect();
    if let Some(pb) = &progress {
        pb.set_length(total_size);
        pb.inc(
            have.iter()
                .map(|i| CHUNK_SIZE.min(total_size - i * CHUNK_SIZE))
                .sum(),
        );
    }

    let missing: Vec<u64> = (0..total_chunks).filter(|i| !have.contains(i)).collect();
    stream::iter(missing.into_iter().map(Ok::<u64, anyhow::Error>))
        .try_for_each_concurrent(PARALLEL_UPLOADS, |index| {
            let client = client.clone();
            let base = base.clone();
            let token = token.clone();
            let tid = tid.clone();
            let path = path.clone();
            let pb = progress.clone();
            async move {
                let plain = tokio::task::spawn_blocking({
                    let path = path.clone();
                    move || read_chunk(&path, index, CHUNK_SIZE, total_size)
                })
                .await??;
                let n = plain.len() as u64;
                let ct = Bytes::from(seal(&key, Domain::Data, index, tid.as_bytes(), &plain));
                upload_with_retry(&client, &base, &token, index, ct).await?;
                if let Some(pb) = &pb {
                    pb.inc(n);
                }
                Ok(())
            }
        })
        .await
        .context("upload failed after retries — re-run the same command to resume, or run `b2p doctor` if it keeps failing")?;

    let hash = tokio::task::spawn_blocking({
        let path = path.clone();
        move || blake3_file(&path)
    })
    .await??;
    let commit_body = seal_json(
        &key,
        Domain::Commit,
        tid.as_bytes(),
        &Commit { blake3_hex: hash },
    );
    let ack: CommitAck = client
        .post(format!("{base}/v1/commit"))
        .bearer_auth(&token)
        .body(commit_body)
        .timeout(Duration::from_secs(600))
        .send()
        .await?
        .json()
        .await?;
    if !ack.ok {
        bail!(
            "receiver failed to finalize: {}",
            ack.error.unwrap_or_default()
        );
    }
    drop(source); // keeps tar spool alive until here
    Ok("transfer complete".to_string())
}

async fn upload_with_retry(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    index: u64,
    body: Bytes,
) -> anyhow::Result<()> {
    let mut delay = Duration::from_millis(500);
    for attempt in 1..=CHUNK_ATTEMPTS {
        let result = client
            .put(format!("{base}/v1/chunk/{index}"))
            .bearer_auth(token)
            .body(body.clone())
            .timeout(Duration::from_secs(120))
            .send()
            .await;
        match result {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) if r.status() == 401 => bail!("auth rejected (HTTP 401) mid-transfer"),
            Ok(r) => {
                if attempt == CHUNK_ATTEMPTS {
                    bail!(
                        "chunk {index}: HTTP {} after {CHUNK_ATTEMPTS} attempts",
                        r.status()
                    );
                }
            }
            Err(e) => {
                if attempt == CHUNK_ATTEMPTS {
                    return Err(e).context(format!(
                        "chunk {index} failed after {CHUNK_ATTEMPTS} attempts"
                    ));
                }
            }
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive;
    use crate::code::Code;
    use crate::crypto::Secret;
    use crate::server::{start, ServerCfg};

    async fn spawn_receiver(overwrite: bool) -> (Code, tempfile::TempDir, crate::server::Handles) {
        let secret = Secret::generate();
        let out = tempfile::tempdir().unwrap();
        let handles = start(
            ServerCfg {
                secret: secret.clone(),
                out_dir: out.path().to_path_buf(),
                auto_accept: true,
                overwrite,
            },
            false,
        )
        .await
        .unwrap();
        let code = Code::new(
            format!("http://127.0.0.1:{}", handles.port)
                .parse()
                .unwrap(),
            secret,
        );
        (code, out, handles)
    }

    #[tokio::test]
    async fn sends_single_file() {
        let (code, out, _h) = spawn_receiver(false).await;
        let src_dir = tempfile::tempdir().unwrap();
        // 9 MB: forces multiple chunks with a short tail
        let content: Vec<u8> = (0..9_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(src_dir.path().join("big.bin"), &content).unwrap();

        let source = archive::prepare(&[src_dir.path().join("big.bin")]).unwrap();
        send(&code, source, None, &crate::http::TlsOpts::default())
            .await
            .unwrap();

        assert_eq!(std::fs::read(out.path().join("big.bin")).unwrap(), content);
    }

    #[tokio::test]
    async fn sends_text() {
        let (code, _out, mut h) = spawn_receiver(false).await;
        let source = archive::prepare_text("meet at noon");
        send(&code, source, None, &crate::http::TlsOpts::default())
            .await
            .unwrap();
        let mut got_text = None;
        while let Some(ev) = h.events_rx.recv().await {
            if let crate::server::Event::Text(t) = ev {
                got_text = Some(t);
                break;
            }
        }
        assert_eq!(got_text.as_deref(), Some("meet at noon"));
    }

    #[tokio::test]
    async fn resumes_skipping_existing_chunks() {
        let (code, out, _h) = spawn_receiver(false).await;
        let src_dir = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..9_000_000u32).map(|i| (i % 241) as u8).collect();
        std::fs::write(src_dir.path().join("big.bin"), &content).unwrap();

        // First: upload only chunk 0 by hand, simulating an interrupted transfer.
        let source = archive::prepare(&[src_dir.path().join("big.bin")]).unwrap();
        let (tid, path) = match &source {
            archive::Source::Blob {
                transfer_id, path, ..
            } => (transfer_id.clone(), path.clone()),
            _ => unreachable!(),
        };
        let manifest = build_manifest(&source).unwrap();
        let key = code.secret.data_key();
        let client = reqwest::Client::new();
        let token = code.secret.auth_token();
        let base = code.base_url.as_str().trim_end_matches('/').to_string();
        let ack: crate::protocol::ManifestAck = client
            .post(format!("{base}/v1/manifest"))
            .bearer_auth(&token)
            .body(crate::protocol::seal_json(
                &key,
                crate::crypto::Domain::Manifest,
                b"",
                &manifest,
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(ack.accepted);
        let chunk0 = read_chunk(&path, 0, manifest.chunk_size, manifest.total_size).unwrap();
        let ct = crate::crypto::seal(
            &key,
            crate::crypto::Domain::Data,
            0,
            tid.as_bytes(),
            &chunk0,
        );
        client
            .put(format!("{base}/v1/chunk/0"))
            .bearer_auth(&token)
            .body(ct)
            .send()
            .await
            .unwrap();

        // Now run the real sender: manifest ack must report chunk 0, sender fills the rest.
        let source2 = archive::prepare(&[src_dir.path().join("big.bin")]).unwrap();
        send(&code, source2, None, &crate::http::TlsOpts::default())
            .await
            .unwrap();
        assert_eq!(std::fs::read(out.path().join("big.bin")).unwrap(), content);
    }

    #[test]
    fn classifies_layers_from_error_text() {
        assert!(matches!(
            classify_error_text(
                "error sending request: dns error: failed to lookup address information"
            ),
            FailLayer::Dns
        ));
        assert!(matches!(
            classify_error_text("invalid peer certificate: UnknownIssuer"),
            FailLayer::Tls
        ));
        assert!(matches!(
            classify_error_text("client error (Connect): tcp connect error: Connection refused"),
            FailLayer::Connect
        ));
        assert!(matches!(
            classify_error_text("operation timed out"),
            FailLayer::Connect
        ));
        assert!(matches!(
            classify_error_text("something odd"),
            FailLayer::Other
        ));
    }

    #[test]
    fn failure_summary_mentions_diagnostics_when_doctor_ran() {
        let msg = failure_summary("DNS", "example.com", true);
        assert_eq!(
            msg,
            "DNS failure reaching example.com — see diagnostics above"
        );
    }

    #[test]
    fn failure_summary_omits_diagnostics_when_doctor_did_not_run() {
        let msg = failure_summary("transport", "example.com", false);
        assert_eq!(msg, "transport failure reaching example.com");
        assert!(!msg.contains("diagnostics"));
    }

    #[tokio::test]
    async fn wrong_secret_fails_with_auth_error() {
        let (code, _out, _h) = spawn_receiver(false).await;
        let bad = Code::new(code.base_url.clone(), Secret::generate());
        let src_dir = tempfile::tempdir().unwrap();
        std::fs::write(src_dir.path().join("f.txt"), "x").unwrap();
        let source = archive::prepare(&[src_dir.path().join("f.txt")]).unwrap();
        let err = send(&bad, source, None, &crate::http::TlsOpts::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("401") || err.to_lowercase().contains("auth"),
            "{err}"
        );
    }
}
