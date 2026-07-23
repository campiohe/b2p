//! Live smoke against a real deployed Worker. Env-gated like the TURN smoke:
//!   B2P_TEST_RELAY_URL=wss://b2p-relay.<account>.workers.dev \
//!     cargo test --test relay_live -- --nocapture
//! Optional: B2P_TEST_RELAY_TOKEN.

use std::time::Duration;

#[tokio::test]
async fn live_relay_round_trip() {
    let Ok(url) = std::env::var("B2P_TEST_RELAY_URL") else {
        eprintln!("skipping: B2P_TEST_RELAY_URL not set");
        return;
    };
    let token = std::env::var("B2P_TEST_RELAY_TOKEN").ok();
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    // 3 MiB spans many WS messages and several ack-window refreshes.
    let content: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.path().join("live.bin"), &content).unwrap();
    let source = b2p::archive::prepare(&[src.path().join("live.bin")]).unwrap();
    let code = b2p::rvcode::RendezvousCode::generate_url();
    let tls = b2p::http::TlsOpts::default();

    let receiver = tokio::spawn({
        let (url, token) = (url.clone(), token.clone());
        let (topic, secret) = (code.topic.clone(), code.secret.0.clone());
        let out_path = out.path().to_path_buf();
        async move {
            b2p::session::receive_relay(
                &url,
                token.as_deref(),
                &topic,
                &secret,
                &out_path,
                |_| true,
                &b2p::http::TlsOpts::default(),
                Duration::from_secs(60),
                None,
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    b2p::session::send_relay(
        &url,
        token.as_deref(),
        &code.topic,
        &code.secret.0,
        &source,
        &tls,
        Duration::from_secs(60),
        None,
    )
    .await
    .expect("live send");
    receiver.await.unwrap().expect("live receive");
    assert_eq!(std::fs::read(out.path().join("live.bin")).unwrap(), content);
}
