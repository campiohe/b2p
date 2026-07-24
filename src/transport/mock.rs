//! Test fixture: spawns the REAL relay server (src/relay_server.rs) on an
//! ephemeral port, so the offline suite exercises production relay code.
//! (Until `relay serve` existed this file carried a hand-rolled lookalike;
//! the conformance suite relay-worker/test.mjs guards Worker parity.)

use crate::relay_server::{RelayServer, ServeCfg};

pub struct MockRelay {
    pub url: String,
    _server: RelayServer, // Drop aborts the accept loop
}

/// Kept as `start` so every existing test compiles unchanged.
pub async fn start() -> MockRelay {
    let server = crate::relay_server::start(ServeCfg {
        listen: "127.0.0.1:0".parse().expect("addr"),
        ..Default::default()
    })
    .await
    .expect("relay server starts");
    MockRelay {
        url: format!("ws://{}", server.addr),
        _server: server,
    }
}
