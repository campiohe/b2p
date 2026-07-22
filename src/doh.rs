//! DNS-over-HTTPS resolver.
//!
//! Restrictive DNS filters (e.g. Cisco Umbrella) sinkhole shared tunnel domains
//! like `*.trycloudflare.com` by returning a block-page IP from the system
//! resolver. Resolving the tunnel host over HTTPS against a public resolver
//! (queried by literal IP, so it needs no system DNS itself) returns the real
//! address and bypasses the DNS-layer block.

use anyhow::{anyhow, Context};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

/// JSON DoH providers, tried in order. Queried by literal IP so a poisoned or
/// blocking system resolver is never consulted; their TLS certs carry IP SANs
/// (1.1.1.1, 8.8.8.8), so validation still succeeds.
const PROVIDERS: &[(&str, &str)] = &[
    ("cloudflare", "https://1.1.1.1/dns-query"),
    ("google", "https://8.8.8.8/resolve"),
];

const A: u16 = 1;
const AAAA: u16 = 28;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    kind: u16,
    data: String,
}

/// Resolve `host` to IP addresses over DoH, trying each provider until one
/// returns records. Errors only if every provider fails or returns nothing.
pub async fn resolve(host: &str) -> anyhow::Result<Vec<IpAddr>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut last_err = None;
    for (label, base) in PROVIDERS {
        match query(&client, base, host).await {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => last_err = Some(anyhow!("{label}: no A/AAAA records for {host}")),
            Err(e) => last_err = Some(e.context(format!("DoH provider {label} failed"))),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no DoH providers configured")))
}

/// Query a single DoH endpoint for both A and AAAA records.
pub(crate) async fn query(
    client: &reqwest::Client,
    base: &str,
    host: &str,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for kind in ["A", "AAAA"] {
        let resp = client
            .get(base)
            .query(&[("name", host), ("type", kind)])
            .header("accept", "application/dns-json")
            .send()
            .await
            .context("DoH request failed")?
            .error_for_status()
            .context("DoH endpoint returned an error status")?
            .json::<DohResponse>()
            .await
            .context("DoH response was not valid JSON")?;
        for ans in resp.answer {
            if (ans.kind == A || ans.kind == AAAA) && ans.data.parse::<IpAddr>().is_ok() {
                ips.push(ans.data.parse().unwrap());
            }
        }
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::routing::get;
    use axum::Router;
    use std::collections::HashMap;

    /// Spin up a mock DoH endpoint that answers based on the `type` param.
    async fn mock_server() -> (String, tokio::task::JoinHandle<()>) {
        async fn handler(
            Query(p): Query<HashMap<String, String>>,
        ) -> axum::Json<serde_json::Value> {
            let answer = match p.get("type").map(String::as_str) {
                Some("A") => serde_json::json!([
                    { "type": 1, "data": "104.16.132.229" },
                    { "type": 5, "data": "ignored.cname.example" },
                    { "type": 1, "data": "104.16.133.229" }
                ]),
                Some("AAAA") => serde_json::json!([{ "type": 28, "data": "2606:4700::1" }]),
                _ => serde_json::json!([]),
            };
            axum::Json(serde_json::json!({ "Status": 0, "Answer": answer }))
        }
        let app = Router::new().route("/dns-query", get(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://127.0.0.1:{}/dns-query", addr.port()), task)
    }

    #[tokio::test]
    async fn parses_a_and_aaaa_and_skips_other_types() {
        let (base, _task) = mock_server().await;
        let client = reqwest::Client::new();
        let ips = query(&client, &base, "example.com").await.unwrap();
        assert!(ips.contains(&"104.16.132.229".parse().unwrap()));
        assert!(ips.contains(&"104.16.133.229".parse().unwrap()));
        assert!(ips.contains(&"2606:4700::1".parse().unwrap()));
        // the type-5 CNAME record must be ignored
        assert_eq!(ips.len(), 3);
    }

    #[tokio::test]
    async fn empty_answer_yields_no_ips() {
        // a base whose type param never matches A/AAAA in the mock
        async fn empty_handler() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({ "Status": 0, "Answer": [] }))
        }
        let app = Router::new().route("/dns-query", get(empty_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let ips = query(
            &client,
            &format!("http://127.0.0.1:{port}/dns-query"),
            "example.com",
        )
        .await
        .unwrap();
        assert!(ips.is_empty());
    }

    // Real-network check (needs outbound HTTPS to 1.1.1.1). Run explicitly:
    //   cargo test --lib doh -- --ignored
    #[tokio::test]
    #[ignore]
    async fn live_resolves_via_real_doh() {
        let ips = resolve("blog.cloudflare.com").await.unwrap();
        assert!(!ips.is_empty(), "expected real IPs from live DoH");
    }
}
