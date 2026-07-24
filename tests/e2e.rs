//! End-to-end transfers through the real relay server, composed from the
//! same pub API `b2p receive`/`b2p send` use: `relay_server::start` +
//! `session::{receive_relay, send_relay}`. Everything runs offline on
//! loopback; resume/re-arm and hostile-peer paths are covered by the
//! session/stream/relay unit tests.

use b2p::relay_server::{RelayServer, ServeCfg};
use b2p::session::{receive_relay, send_relay};
use std::fs;
use std::path::Path;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(30);

async fn spawn_relay() -> (String, RelayServer) {
    let server = b2p::relay_server::start(ServeCfg {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    (format!("ws://{}", server.addr), server)
}

fn write(dir: &Path, rel: &str, contents: &[u8]) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, contents).unwrap();
}

/// Run a full receive+send pair through `url` and return the receiver's
/// result description.
async fn transfer(url: &str, source: b2p::archive::Source, out: &Path) -> String {
    let code = b2p::rvcode::RendezvousCode::generate_url();
    let receiver = tokio::spawn({
        let url = url.to_string();
        let (topic, secret) = (code.topic.clone(), code.secret.0.clone());
        let out = out.to_path_buf();
        async move {
            receive_relay(
                &url,
                None,
                &topic,
                &secret,
                &out,
                |_| true,
                &b2p::http::TlsOpts::default(),
                WAIT,
                None,
            )
            .await
        }
    });
    send_relay(
        url,
        None,
        &code.topic,
        &code.secret.0,
        &source,
        &b2p::http::TlsOpts::default(),
        WAIT,
        None,
    )
    .await
    .unwrap();
    receiver.await.unwrap().unwrap()
}

#[tokio::test]
async fn folder_round_trip() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(src.path(), "proj/readme.md", b"# hi");
    write(src.path(), "proj/data/big.bin", &vec![42u8; 5_000_000]);
    write(src.path(), "proj/data/nested/deep.txt", b"deep");

    let (url, _server) = spawn_relay().await;
    let source = b2p::archive::prepare(&[src.path().join("proj")]).unwrap();
    transfer(&url, source, out.path()).await;

    assert_eq!(
        fs::read(out.path().join("proj/readme.md")).unwrap(),
        b"# hi"
    );
    assert_eq!(
        fs::read(out.path().join("proj/data/big.bin")).unwrap(),
        vec![42u8; 5_000_000]
    );
    assert_eq!(
        fs::read(out.path().join("proj/data/nested/deep.txt")).unwrap(),
        b"deep"
    );
}

#[tokio::test]
async fn multiple_paths_round_trip() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(src.path(), "a.txt", b"AAA");
    write(src.path(), "b.txt", b"BB");

    let (url, _server) = spawn_relay().await;
    let source =
        b2p::archive::prepare(&[src.path().join("a.txt"), src.path().join("b.txt")]).unwrap();
    transfer(&url, source, out.path()).await;

    assert_eq!(fs::read(out.path().join("a.txt")).unwrap(), b"AAA");
    assert_eq!(fs::read(out.path().join("b.txt")).unwrap(), b"BB");
}

#[tokio::test]
async fn text_round_trip() {
    let out = tempfile::tempdir().unwrap();
    let (url, _server) = spawn_relay().await;
    let source = b2p::archive::prepare_text("the password is xyzzy");
    // Text completes at the manifest; the receiver returns the snippet itself.
    let desc = transfer(&url, source, out.path()).await;
    assert_eq!(desc, "the password is xyzzy");
}

#[tokio::test]
async fn wrong_code_secret_cannot_transfer() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(src.path(), "secret.txt", b"attack at dawn");

    let (url, _server) = spawn_relay().await;
    let code = b2p::rvcode::RendezvousCode::generate_url();
    let receiver = tokio::spawn({
        let url = url.clone();
        let (topic, secret) = (code.topic.clone(), code.secret.0.clone());
        let out = out.path().to_path_buf();
        async move {
            receive_relay(
                &url,
                None,
                &topic,
                &secret,
                &out,
                |_| true,
                &b2p::http::TlsOpts::default(),
                WAIT,
                None,
            )
            .await
        }
    });
    // Same room topic, WRONG secret: the PAKE confirmation must fail on both
    // sides and nothing may land on disk.
    let source = b2p::archive::prepare(&[src.path().join("secret.txt")]).unwrap();
    let send_err = send_relay(
        &url,
        None,
        &code.topic,
        b"not the secret",
        &source,
        &b2p::http::TlsOpts::default(),
        WAIT,
        None,
    )
    .await;
    assert!(send_err.is_err(), "sender with wrong secret must fail");
    let recv_err = tokio::time::timeout(WAIT, receiver)
        .await
        .expect("receiver must not hang")
        .unwrap();
    assert!(recv_err.is_err(), "receiver must reject the wrong secret");
    assert!(!out.path().join("secret.txt").exists());
}
