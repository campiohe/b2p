use b2p::archive;
use b2p::code::Code;
use b2p::crypto::Secret;
use b2p::server::{start, Event, Handles, ServerCfg};
use std::fs;
use std::path::Path;

async fn spawn_receiver(out: &Path) -> (Code, Handles) {
    let secret = Secret::generate();
    let handles = start(
        ServerCfg {
            secret: secret.clone(),
            out_dir: out.to_path_buf(),
            auto_accept: true,
            overwrite: false,
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
    (code, handles)
}

fn write(dir: &Path, rel: &str, contents: &[u8]) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, contents).unwrap();
}

#[tokio::test]
async fn folder_round_trip() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(src.path(), "proj/readme.md", b"# hi");
    write(src.path(), "proj/data/big.bin", &vec![42u8; 5_000_000]);
    write(src.path(), "proj/data/nested/deep.txt", b"deep");

    let (code, _h) = spawn_receiver(out.path()).await;
    let source = archive::prepare(&[src.path().join("proj")]).unwrap();
    b2p::send::send(&code, source, None, &b2p::http::TlsOpts::default())
        .await
        .unwrap();

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
    assert!(!out.path().join("b2p-bundle.tar.b2p-partial").exists());
}

#[tokio::test]
async fn multiple_paths_round_trip() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(src.path(), "a.txt", b"AAA");
    write(src.path(), "b.txt", b"BB");

    let (code, _h) = spawn_receiver(out.path()).await;
    let source = archive::prepare(&[src.path().join("a.txt"), src.path().join("b.txt")]).unwrap();
    b2p::send::send(&code, source, None, &b2p::http::TlsOpts::default())
        .await
        .unwrap();

    assert_eq!(fs::read(out.path().join("a.txt")).unwrap(), b"AAA");
    assert_eq!(fs::read(out.path().join("b.txt")).unwrap(), b"BB");
}

#[tokio::test]
async fn text_round_trip() {
    let out = tempfile::tempdir().unwrap();
    let (code, mut h) = spawn_receiver(out.path()).await;
    let source = archive::prepare_text("the password is xyzzy");
    b2p::send::send(&code, source, None, &b2p::http::TlsOpts::default())
        .await
        .unwrap();

    let mut got = None;
    while let Some(ev) = h.events_rx.recv().await {
        match ev {
            Event::Text(t) => got = Some(t),
            Event::Done(_) => break,
            _ => {}
        }
    }
    assert_eq!(got.as_deref(), Some("the password is xyzzy"));
}

#[tokio::test]
async fn interrupted_then_resumed_transfer() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let content: Vec<u8> = (0..10_000_000u32).map(|i| (i % 199) as u8).collect();
    write(src.path(), "big.bin", &content);

    // Receiver #1: sender uploads part of the file by driving the protocol by hand,
    // then "dies" (we just stop).
    let (code1, _h1) = spawn_receiver(out.path()).await;
    {
        use b2p::crypto::{seal, Domain, CHUNK_SIZE};
        use b2p::protocol::{seal_json, ManifestAck};
        let source = archive::prepare(&[src.path().join("big.bin")]).unwrap();
        let manifest = b2p::send::build_manifest(&source).unwrap();
        let key = code1.secret.data_key();
        let token = code1.secret.auth_token();
        let base = code1.base_url.as_str().trim_end_matches('/').to_string();
        let client = reqwest::Client::new();
        let ack: ManifestAck = client
            .post(format!("{base}/v1/manifest"))
            .bearer_auth(&token)
            .body(seal_json(&key, Domain::Manifest, b"", &manifest))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(ack.accepted);
        for index in [0u64, 1] {
            let plain = b2p::send::read_chunk(
                match &source {
                    archive::Source::Blob { path, .. } => path,
                    _ => unreachable!(),
                },
                index,
                CHUNK_SIZE,
                manifest.total_size,
            )
            .unwrap();
            let ct = seal(
                &key,
                Domain::Data,
                index,
                manifest.transfer_id.as_bytes(),
                &plain,
            );
            client
                .put(format!("{base}/v1/chunk/{index}"))
                .bearer_auth(&token)
                .body(ct)
                .send()
                .await
                .unwrap();
        }
    }

    // Receiver #2: fresh secret and port (simulates the ephemeral tunnel URL changing),
    // same out dir. The partial state must be picked up via the transfer-id fingerprint.
    let (code2, _h2) = spawn_receiver(out.path()).await;
    let source = archive::prepare(&[src.path().join("big.bin")]).unwrap();
    b2p::send::send(&code2, source, None, &b2p::http::TlsOpts::default())
        .await
        .unwrap();

    assert_eq!(fs::read(out.path().join("big.bin")).unwrap(), content);
    assert!(!out.path().join("big.bin.b2p-partial").exists());
}

#[tokio::test]
async fn wrong_code_secret_cannot_transfer() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(src.path(), "f.txt", b"secret stuff");

    let (code, _h) = spawn_receiver(out.path()).await;
    let bad_code = Code::new(code.base_url.clone(), Secret::generate());
    let source = archive::prepare(&[src.path().join("f.txt")]).unwrap();
    assert!(
        b2p::send::send(&bad_code, source, None, &b2p::http::TlsOpts::default())
            .await
            .is_err()
    );
    assert!(!out.path().join("f.txt").exists());
}
