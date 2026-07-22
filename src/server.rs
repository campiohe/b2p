use crate::archive::unpack_tar;
use crate::crypto::{open, Domain, Secret};
use crate::protocol::*;
use crate::store::Store;
use axum::extract::{DefaultBodyLimit, Path as AxPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post, put};
use axum::Router;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;

const MAX_AUTH_FAILURES: u32 = 10;

pub struct ServerCfg {
    pub secret: Secret,
    pub out_dir: PathBuf,
    pub auto_accept: bool,
    pub overwrite: bool,
}

pub struct AcceptRequest {
    pub summary: String,
    pub reply: oneshot::Sender<bool>,
}

pub enum Event {
    Accepted { name: String, total_size: u64 },
    Progress { bytes: u64 },
    Text(String),
    Done(String),
    Failed(String),
}

struct ActiveTransfer {
    manifest: Manifest,
    store: Store,
}

struct App {
    cfg: ServerCfg,
    key: [u8; 32],
    token_hash: blake3::Hash,
    auth_failures: AtomicU32,
    transfer: Mutex<Option<ActiveTransfer>>,
    accept_tx: mpsc::Sender<AcceptRequest>,
    events_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
}

pub struct Handles {
    pub port: u16,
    pub accept_rx: mpsc::Receiver<AcceptRequest>,
    pub events_rx: mpsc::UnboundedReceiver<Event>,
    pub shutdown: CancellationToken,
    pub task: tokio::task::JoinHandle<()>,
}

pub async fn start(cfg: ServerCfg, bind_all: bool) -> anyhow::Result<Handles> {
    let (accept_tx, accept_rx) = mpsc::channel(1);
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let shutdown = CancellationToken::new();

    let app = Arc::new(App {
        key: cfg.secret.data_key(),
        token_hash: blake3::hash(cfg.secret.auth_token().as_bytes()),
        cfg,
        auth_failures: AtomicU32::new(0),
        transfer: Mutex::new(None),
        accept_tx,
        events_tx,
        shutdown: shutdown.clone(),
    });

    let router = Router::new()
        .route("/v1/manifest", post(handle_manifest))
        .route("/v1/chunk/{index}", put(handle_chunk))
        .route("/v1/status", get(handle_status))
        .route("/v1/commit", post(handle_commit))
        .layer(middleware::from_fn_with_state(app.clone(), auth_mw))
        .layer(DefaultBodyLimit::max((crate::crypto::CHUNK_SIZE + 4096) as usize))
        .with_state(app);

    let host = if bind_all { "0.0.0.0" } else { "127.0.0.1" };
    let listener = tokio::net::TcpListener::bind((host, 0)).await?;
    let port = listener.local_addr()?.port();

    let token = shutdown.clone();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move { token.cancelled().await })
            .await;
    });

    Ok(Handles { port, accept_rx, events_rx, shutdown, task })
}

async fn auth_mw(
    State(app): State<Arc<App>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if blake3::hash(provided.as_bytes()) != app.token_hash {
        let fails = app.auth_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if fails >= MAX_AUTH_FAILURES {
            let _ = app
                .events_tx
                .send(Event::Failed("too many bad auth attempts — shutting down".into()));
            app.shutdown.cancel();
        }
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

fn safe_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "b2p-download".to_string())
}

async fn handle_manifest(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let manifest: Manifest = match open_json(&app.key, Domain::Manifest, b"", &body) {
        Ok(m) => m,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if manifest.version != PROTOCOL_VERSION {
        return Json(ManifestAck { accepted: false, complete: false, have: vec![] })
            .into_response();
    }

    let name = safe_name(&manifest.name);
    let dest_exists = app.cfg.out_dir.join(&name).exists();
    let mut summary = match manifest.kind {
        Kind::Text => "Incoming text snippet".to_string(),
        _ => {
            let listing: Vec<String> = manifest
                .entries
                .iter()
                .take(10)
                .map(|e| format!("  {} ({} bytes)", e.path, e.size))
                .collect();
            format!(
                "Incoming: {} file(s), {} bytes total\n{}",
                manifest.entries.len(),
                manifest.total_size,
                listing.join("\n")
            )
        }
    };
    if dest_exists && manifest.kind == Kind::File {
        summary.push_str("\n  WARNING: destination file exists and will be overwritten");
    }

    let accepted = if app.cfg.auto_accept {
        // refuse only when we would clobber an existing file without --overwrite
        !(dest_exists && manifest.kind == Kind::File && !app.cfg.overwrite)
    } else {
        let (tx, rx) = oneshot::channel();
        if app.accept_tx.send(AcceptRequest { summary, reply: tx }).await.is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        rx.await.unwrap_or(false)
    };

    if !accepted {
        return Json(ManifestAck { accepted: false, complete: false, have: vec![] })
            .into_response();
    }

    if manifest.kind == Kind::Text {
        let text = manifest.text.clone().unwrap_or_default();
        let _ = app.events_tx.send(Event::Text(text));
        let _ = app.events_tx.send(Event::Done("text received".into()));
        let shutdown = app.shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            shutdown.cancel();
        });
        return Json(ManifestAck { accepted: true, complete: true, have: vec![] })
            .into_response();
    }

    let store = match Store::open_or_create(
        &app.cfg.out_dir,
        &name,
        &manifest.transfer_id,
        manifest.total_size,
        manifest.chunk_size,
    ) {
        Ok(s) => s,
        Err(e) => {
            let _ = app.events_tx.send(Event::Failed(format!("cannot open store: {e}")));
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let have = store.have();
    let _ = app.events_tx.send(Event::Accepted {
        name: name.clone(),
        total_size: manifest.total_size,
    });
    *app.transfer.lock().await = Some(ActiveTransfer { manifest, store });
    Json(ManifestAck { accepted: true, complete: false, have }).into_response()
}

async fn handle_chunk(
    State(app): State<Arc<App>>,
    AxPath(index): AxPath<u64>,
    body: Bytes,
) -> Response {
    let mut guard = app.transfer.lock().await;
    let Some(active) = guard.as_mut() else {
        return StatusCode::CONFLICT.into_response();
    };
    let aad = active.manifest.transfer_id.clone();
    let plaintext = match open(&app.key, Domain::Data, index, aad.as_bytes(), &body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    match active.store.write_chunk(index, &plaintext) {
        Ok(()) => {
            let _ = app.events_tx.send(Event::Progress { bytes: plaintext.len() as u64 });
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn handle_status(State(app): State<Arc<App>>) -> Response {
    let guard = app.transfer.lock().await;
    match guard.as_ref() {
        Some(active) => Json(StatusResp { have: active.store.have() }).into_response(),
        None => StatusCode::CONFLICT.into_response(),
    }
}

async fn handle_commit(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let mut guard = app.transfer.lock().await;
    let Some(active) = guard.take() else {
        return StatusCode::CONFLICT.into_response();
    };
    let aad = active.manifest.transfer_id.clone();
    let commit: Commit = match open_json(&app.key, Domain::Commit, aad.as_bytes(), &body) {
        Ok(c) => c,
        Err(_) => {
            *guard = Some(active);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let result = finalize(&app, active, &commit);
    let ack = match result {
        Ok(desc) => {
            let _ = app.events_tx.send(Event::Done(desc));
            let shutdown = app.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                shutdown.cancel();
            });
            CommitAck { ok: true, error: None }
        }
        Err(e) => {
            let _ = app.events_tx.send(Event::Failed(e.to_string()));
            CommitAck { ok: false, error: Some(e.to_string()) }
        }
    };
    Json(ack).into_response()
}

fn finalize(app: &App, active: ActiveTransfer, commit: &Commit) -> anyhow::Result<String> {
    if !active.store.is_complete() {
        anyhow::bail!(
            "transfer incomplete: {}/{} chunks",
            active.store.have().len(),
            active.store.total_chunks()
        );
    }
    let actual = active.store.file_hash()?;
    if actual != commit.blake3_hex {
        anyhow::bail!("integrity check failed: hash mismatch");
    }
    let name = safe_name(&active.manifest.name);
    match active.manifest.kind {
        Kind::File => {
            let dest = app.cfg.out_dir.join(&name);
            active.store.finalize_file(&dest)?;
            Ok(format!("saved {}", dest.display()))
        }
        Kind::Tar => {
            unpack_tar(active.store.data_path(), &app.cfg.out_dir)?;
            active.store.cleanup()?;
            Ok(format!("unpacked archive into {}", app.cfg.out_dir.display()))
        }
        Kind::Text => unreachable!("text transfers complete at manifest time"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{seal, Domain, Secret, CHUNK_SIZE};

    struct Ctx {
        base: String,
        client: reqwest::Client,
        token: String,
        key: [u8; 32],
        out: tempfile::TempDir,
        handles: Handles,
    }

    async fn ctx() -> Ctx {
        let secret = Secret::generate();
        let out = tempfile::tempdir().unwrap();
        let handles = start(
            ServerCfg {
                secret: secret.clone(),
                out_dir: out.path().to_path_buf(),
                auto_accept: true,
                overwrite: false,
            },
            false,
        )
        .await
        .unwrap();
        Ctx {
            base: format!("http://127.0.0.1:{}", handles.port),
            client: reqwest::Client::new(),
            token: secret.auth_token(),
            key: secret.data_key(),
            out,
            handles,
        }
    }

    fn manifest(tid: &str, total: u64) -> Manifest {
        Manifest {
            version: PROTOCOL_VERSION,
            transfer_id: tid.into(),
            kind: Kind::File,
            name: "out.bin".into(),
            entries: vec![Entry { path: "out.bin".into(), size: total }],
            total_size: total,
            chunk_size: CHUNK_SIZE,
            text: None,
        }
    }

    async fn post_manifest(c: &Ctx, m: &Manifest) -> ManifestAck {
        let body = seal_json(&c.key, Domain::Manifest, b"", m);
        c.client
            .post(format!("{}/v1/manifest", c.base))
            .bearer_auth(&c.token)
            .body(body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rejects_bad_token_and_locks_out() {
        let c = ctx().await;
        for _ in 0..10 {
            let r = c
                .client
                .get(format!("{}/v1/status", c.base))
                .bearer_auth("wrong-token")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 401);
        }
        // 10 failures triggered shutdown
        tokio::time::timeout(std::time::Duration::from_secs(5), c.handles.task)
            .await
            .expect("server should shut down after lockout")
            .unwrap();
    }

    #[tokio::test]
    async fn full_transfer_small_file() {
        let c = ctx().await;
        let tid = "ab".repeat(16);
        let content = b"hello over the tunnel".to_vec();
        let ack = post_manifest(&c, &manifest(&tid, content.len() as u64)).await;
        assert!(ack.accepted && !ack.complete && ack.have.is_empty());

        let ct = seal(&c.key, Domain::Data, 0, tid.as_bytes(), &content);
        let r = c
            .client
            .put(format!("{}/v1/chunk/0", c.base))
            .bearer_auth(&c.token)
            .body(ct)
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());

        let commit = Commit { blake3_hex: blake3::hash(&content).to_hex().to_string() };
        let body = seal_json(&c.key, Domain::Commit, tid.as_bytes(), &commit);
        let ack: CommitAck = c
            .client
            .post(format!("{}/v1/commit", c.base))
            .bearer_auth(&c.token)
            .body(body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(ack.ok, "{:?}", ack.error);
        assert_eq!(std::fs::read(c.out.path().join("out.bin")).unwrap(), content);
    }

    #[tokio::test]
    async fn corrupted_chunk_rejected() {
        let c = ctx().await;
        let tid = "ab".repeat(16);
        post_manifest(&c, &manifest(&tid, 10)).await;
        let r = c
            .client
            .put(format!("{}/v1/chunk/0", c.base))
            .bearer_auth(&c.token)
            .body(vec![0u8; 26])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    #[tokio::test]
    async fn version_mismatch_rejected() {
        let c = ctx().await;
        let mut m = manifest(&"ab".repeat(16), 10);
        m.version = 999;
        let ack = post_manifest(&c, &m).await;
        assert!(!ack.accepted);
    }

    #[tokio::test]
    async fn traversal_name_is_sanitized() {
        let c = ctx().await;
        let tid = "ab".repeat(16);
        let mut m = manifest(&tid, 4);
        m.name = "../../evil.bin".into();
        let ack = post_manifest(&c, &m).await;
        assert!(ack.accepted);
        let content = b"evil".to_vec();
        let ct = seal(&c.key, Domain::Data, 0, tid.as_bytes(), &content);
        c.client
            .put(format!("{}/v1/chunk/0", c.base))
            .bearer_auth(&c.token)
            .body(ct)
            .send()
            .await
            .unwrap();
        let commit = Commit { blake3_hex: blake3::hash(&content).to_hex().to_string() };
        let body = seal_json(&c.key, Domain::Commit, tid.as_bytes(), &commit);
        c.client
            .post(format!("{}/v1/commit", c.base))
            .bearer_auth(&c.token)
            .body(body)
            .send()
            .await
            .unwrap();
        assert!(c.out.path().join("evil.bin").exists());
        assert!(!c.out.path().parent().unwrap().join("evil.bin").exists());
    }

    #[tokio::test]
    async fn wrong_hash_commit_fails() {
        let c = ctx().await;
        let tid = "ab".repeat(16);
        post_manifest(&c, &manifest(&tid, 4)).await;
        let content = b"data".to_vec();
        let ct = seal(&c.key, Domain::Data, 0, tid.as_bytes(), &content);
        c.client
            .put(format!("{}/v1/chunk/0", c.base))
            .bearer_auth(&c.token)
            .body(ct)
            .send()
            .await
            .unwrap();
        let commit = Commit { blake3_hex: "00".repeat(32) };
        let body = seal_json(&c.key, Domain::Commit, tid.as_bytes(), &commit);
        let ack: CommitAck = c
            .client
            .post(format!("{}/v1/commit", c.base))
            .bearer_auth(&c.token)
            .body(body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(!ack.ok);
    }
}
