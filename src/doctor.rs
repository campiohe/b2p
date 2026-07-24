//! `b2p doctor`: name exactly which network layer is broken (DNS / TLS /
//! UDP / relay reachability) and say what to do about it — instead of a
//! generic "could not connect".

use crate::http::TlsOpts;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Generic DNS canary when no relay is configured and no target was given.
pub const DEFAULT_TARGET: &str = "www.google.com";
/// Mainstream host whose certificate issuer reveals TLS inspection.
const TLS_CANARY: &str = "www.google.com";
pub const STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DoctorArgs {
    /// Host to test at the DNS layer (defaults to the relay's host, then
    /// DEFAULT_TARGET).
    pub target_host: Option<String>,
    pub cafile: Option<PathBuf>,
    /// Relay to probe (wss://…), when one is configured or being debugged.
    pub relay: Option<String>,
    pub relay_token: Option<String>,
}

/// Host part of a ws:// or wss:// relay URL, for DNS-layer targeting.
fn relay_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    /// Stable id used by verdict logic: "dns" | "tls" | "stun" | "relay".
    pub name: &'static str,
    /// Human-facing line prefix, e.g. "DNS (trycloudflare.com)".
    pub label: String,
    pub outcome: Outcome,
    pub detail: String,
}

pub struct DoctorReport {
    pub checks: Vec<Check>,
    pub verdict: String,
}

impl fmt::Display for DoctorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            let mark = match c.outcome {
                Outcome::Ok => "✓",
                Outcome::Warn => "!",
                Outcome::Fail => "✗",
            };
            writeln!(f, "{mark} {}: {}", c.label, c.detail)?;
        }
        write!(f, "\nverdict: {}", self.verdict)
    }
}

pub async fn run(args: &DoctorArgs) -> DoctorReport {
    // DNS-layer target: an explicit host wins, else the relay's own host
    // (the name that actually has to resolve for transfers), else a canary.
    let from_relay = args.relay.as_deref().and_then(relay_host);
    let target = args
        .target_host
        .as_deref()
        .or(from_relay.as_deref())
        .unwrap_or(DEFAULT_TARGET);
    let tls = TlsOpts {
        cafile: args.cafile.clone(),
    };
    let (dns, tls_c, stun) = tokio::join!(
        dns_check(target),
        tls_check(args.cafile.clone()),
        stun_check(),
    );
    let mut checks = vec![dns, tls_c, stun];
    if let Some(url) = &args.relay {
        checks.push(relay_check(url, args.relay_token.as_deref(), &tls).await);
    }
    let verdict = verdict(&checks, target);
    DoctorReport { checks, verdict }
}

/// WSS connect + ping/pong round-trip against the configured relay, on a
/// throwaway room. The one check that exercises the transport's actual path
/// (TLS + WebSocket upgrade + the relay itself — Worker or `relay serve`).
pub(crate) async fn relay_check(url: &str, token: Option<&str>, tls: &TlsOpts) -> Check {
    let label = format!("relay ({url})");
    let bounded = tokio::time::timeout(
        Duration::from_secs(15),
        crate::transport::relay::probe(url, token, tls),
    )
    .await;
    match bounded {
        Ok(Ok(())) => Check {
            name: "relay",
            label,
            outcome: Outcome::Ok,
            detail: "WebSocket connect + ping round-trip OK".into(),
        },
        Ok(Err(e)) => Check {
            name: "relay",
            label,
            outcome: Outcome::Fail,
            detail: format!("{e:#}"),
        },
        Err(_) => Check {
            name: "relay",
            label,
            outcome: Outcome::Fail,
            detail: "timed out probing the relay".into(),
        },
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DnsClass {
    Clean,
    BlockPage(IpAddr),
    Sinkhole(IpAddr),
}

pub fn classify_ips(ips: &[IpAddr]) -> DnsClass {
    for ip in ips {
        if let IpAddr::V4(v4) = ip {
            let o = v4.octets();
            // Cisco Umbrella serves its block page from 146.112.61.104-110.
            if o[0] == 146 && o[1] == 112 && o[2] == 61 && (104..=110).contains(&o[3]) {
                return DnsClass::BlockPage(*ip);
            }
        }
        if ip.is_loopback() || ip.is_unspecified() {
            return DnsClass::Sinkhole(*ip);
        }
    }
    DnsClass::Clean
}

async fn dns_check(host: &str) -> Check {
    let label = format!("DNS ({host})");
    let make = |outcome, detail: String| Check {
        name: "dns",
        label: label.clone(),
        outcome,
        detail,
    };
    if host.parse::<std::net::IpAddr>().is_ok() || host == "localhost" {
        return make(
            Outcome::Ok,
            format!("{host} is a literal address — DNS not in play"),
        );
    }
    match tokio::time::timeout(CHECK_TIMEOUT, tokio::net::lookup_host((host, 443))).await {
        Ok(Ok(addrs)) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                return make(Outcome::Fail, "resolver returned no addresses".into());
            }
            match classify_ips(&ips) {
                DnsClass::Clean => make(Outcome::Ok, format!("resolves to {}", ips[0])),
                DnsClass::BlockPage(ip) => make(
                    Outcome::Fail,
                    format!("resolves to {ip} (a Cisco Umbrella block IP) — this network is DNS-filtering it"),
                ),
                DnsClass::Sinkhole(ip) => make(
                    Outcome::Fail,
                    format!("resolves to {ip} — looks sinkholed by a DNS filter"),
                ),
            }
        }
        Ok(Err(e)) => make(Outcome::Fail, format!("resolution failed: {e}")),
        Err(_) => make(Outcome::Fail, "resolution timed out".into()),
    }
}

async fn tls_check(cafile: Option<PathBuf>) -> Check {
    let label = format!("TLS ({TLS_CANARY})");
    let make = |outcome, detail: String| Check {
        name: "tls",
        label: label.clone(),
        outcome,
        detail,
    };
    let extra = match &cafile {
        Some(p) => match crate::tlsprobe::load_pem_roots(p) {
            Ok(v) => v,
            Err(e) => return make(Outcome::Fail, format!("cannot load --cafile: {e:#}")),
        },
        None => vec![],
    };
    match crate::tlsprobe::probe(TLS_CANARY, 443, CHECK_TIMEOUT, extra).await {
        Ok(r) => {
            let inspected = !crate::tlsprobe::looks_public(&r.leaf_issuer);
            match (r.os_store_verifies, inspected) {
                (true, false) => make(
                    Outcome::Ok,
                    format!(
                        "issuer {} — chain verifies against the OS trust store",
                        r.leaf_issuer
                    ),
                ),
                (true, true) => make(
                    Outcome::Warn,
                    format!(
                        "certificates are re-signed by {} — this network runs TLS inspection; \
                         the OS trust store accepts it, so HTTPS works",
                        r.leaf_issuer
                    ),
                ),
                (false, _) => make(
                    Outcome::Fail,
                    format!(
                        "issuer {} is not trusted ({}) — add this network's root CA to the \
                         OS store, or pass --cafile / set SSL_CERT_FILE",
                        r.leaf_issuer,
                        r.os_error.unwrap_or_default()
                    ),
                ),
            }
        }
        Err(e) => make(
            Outcome::Fail,
            format!("cannot complete a TLS handshake: {e:#}"),
        ),
    }
}

async fn stun_check() -> Check {
    let label = "UDP/STUN".to_string();
    let make = |outcome, detail: String| Check {
        name: "stun",
        label: label.clone(),
        outcome,
        detail,
    };
    // Query both STUN servers from ONE socket and compare mapped ports.
    // b2p's relay transport never touches UDP — this check characterizes the
    // network (it explains why P2P tools fail here) rather than gating b2p.
    match crate::stun::nat_mapping(&STUN_SERVERS, Duration::from_secs(3)).await {
        crate::stun::NatMapping::EndpointIndependent(addr) => make(
            Outcome::Ok,
            format!(
                "UDP egress works; mapped to {addr} from every STUN server — \
                 endpoint-independent (P2P-friendly) NAT"
            ),
        ),
        crate::stun::NatMapping::OneResponse(addr) => make(
            Outcome::Ok,
            format!(
                "UDP egress works (mapped to {addr}; only one STUN server answered, so NAT \
                 mapping is unclassified)"
            ),
        ),
        crate::stun::NatMapping::Symmetric(addrs) => make(
            Outcome::Warn,
            format!(
                "UDP egress works, but this NAT is symmetric (mapped addresses differ: {addrs:?}) \
                 — hostile to P2P protocols generally; b2p's relay transport (TCP/443) is \
                 unaffected"
            ),
        ),
        crate::stun::NatMapping::NoResponse => make(
            Outcome::Warn,
            "no STUN response — UDP likely blocked; b2p's relay transport (TCP/443) is \
             unaffected"
                .into(),
        ),
    }
}

pub fn verdict(checks: &[Check], target: &str) -> String {
    let failed = |n: &str| {
        checks
            .iter()
            .any(|c| c.name == n && c.outcome == Outcome::Fail)
    };
    if failed("dns") {
        return format!(
            "this network blocks {target} at the DNS layer — the relay cannot be reached \
             by name here; try another network, or a relay on a domain this network resolves"
        );
    }
    if failed("tls") {
        return "TLS verification is failing — if this network runs TLS inspection, add its \
                root CA to the OS trust store, or pass --cafile / set SSL_CERT_FILE"
            .into();
    }
    if failed("relay") {
        return "the relay is unreachable — transfers cannot proceed; check the URL \
                (b2p relay show) and that the relay is up (Worker: npx wrangler deploy in \
                relay-worker/; self-hosted: b2p relay serve on the server)"
            .into();
    }
    // A symmetric NAT is worth naming even when every check passes: it is why
    // generic P2P tools fail on this network, and why b2p relays instead.
    if checks
        .iter()
        .any(|c| c.name == "stun" && c.outcome == Outcome::Warn && c.detail.contains("symmetric"))
    {
        if checks
            .iter()
            .any(|c| c.name == "relay" && c.outcome == Outcome::Ok)
        {
            return "this network's NAT is symmetric (hostile to direct P2P), but b2p's relay \
                    transport is unaffected and the relay is reachable; transfers should work"
                .into();
        }
        return "this network's NAT is symmetric (hostile to direct P2P) — b2p's relay \
                transport is unaffected; configure a relay (b2p relay set) and re-run doctor \
                to probe it"
            .into();
    }
    "no blockers found — DNS, TLS, and HTTPS reachability look clean".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(name: &'static str, outcome: Outcome) -> Check {
        Check {
            name,
            label: name.to_string(),
            outcome,
            detail: format!("{name} detail"),
        }
    }

    #[test]
    fn classifies_umbrella_block_ips() {
        let block: std::net::IpAddr = "146.112.61.106".parse().unwrap();
        let clean: std::net::IpAddr = "104.16.132.229".parse().unwrap();
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(classify_ips(&[block]), DnsClass::BlockPage(block));
        assert_eq!(classify_ips(&[clean]), DnsClass::Clean);
        assert_eq!(classify_ips(&[loopback]), DnsClass::Sinkhole(loopback));
        // any bad answer taints the set, wherever it appears
        assert_eq!(classify_ips(&[clean, block]), DnsClass::BlockPage(block));
    }

    #[tokio::test]
    async fn relay_check_against_mock() {
        let relay = crate::transport::mock::start().await;
        let c = relay_check(&relay.url, None, &TlsOpts::default()).await;
        assert!(matches!(c.outcome, Outcome::Ok), "detail: {}", c.detail);
        let dead = relay_check("ws://127.0.0.1:9", None, &TlsOpts::default()).await;
        assert!(matches!(dead.outcome, Outcome::Fail));
    }

    #[test]
    fn relay_failure_dominates_verdict() {
        let checks = vec![check("dns", Outcome::Ok), check("relay", Outcome::Fail)];
        let v = verdict(&checks, "trycloudflare.com");
        assert!(v.contains("relay"), "got: {v}");
    }

    #[test]
    fn dns_block_dominates_verdict() {
        let checks = vec![
            check("dns", Outcome::Fail),
            check("tls", Outcome::Ok),
            check("stun", Outcome::Ok),
        ];
        let v = verdict(&checks, "relay.example.com");
        assert!(v.contains("DNS"), "{v}");
        assert!(v.contains("relay.example.com"), "{v}");
    }

    #[test]
    fn tls_failure_suggests_cafile() {
        let checks = vec![
            check("dns", Outcome::Ok),
            check("tls", Outcome::Fail),
            check("stun", Outcome::Ok),
        ];
        let v = verdict(&checks, "example.com");
        assert!(v.contains("--cafile"), "{v}");
    }

    #[test]
    fn symmetric_nat_named_but_relay_unaffected() {
        let symmetric = Check {
            name: "stun",
            label: "UDP/STUN".into(),
            outcome: Outcome::Warn,
            detail: "UDP egress works, but this NAT is symmetric (mapped ports differ: \
                     [3828, 29126])"
                .into(),
        };
        // Without a relay probe: point at configuring one.
        let v = verdict(
            &[
                check("dns", Outcome::Ok),
                check("tls", Outcome::Ok),
                symmetric,
            ],
            "example.com",
        );
        assert!(v.contains("symmetric"), "{v}");
        assert!(v.contains("relay set"), "{v}");
        // With a reachable relay: transfers should work.
        let symmetric = Check {
            name: "stun",
            label: "UDP/STUN".into(),
            outcome: Outcome::Warn,
            detail: "this NAT is symmetric".into(),
        };
        let v = verdict(
            &[
                check("dns", Outcome::Ok),
                check("tls", Outcome::Ok),
                symmetric,
                check("relay", Outcome::Ok),
            ],
            "example.com",
        );
        assert!(v.contains("should work"), "{v}");
    }

    #[test]
    fn clean_network_positive_verdict() {
        let checks = vec![
            check("dns", Outcome::Ok),
            check("tls", Outcome::Ok),
            check("stun", Outcome::Ok),
        ];
        let v = verdict(&checks, "example.com");
        assert!(v.contains("no blockers"), "{v}");
    }

    #[test]
    fn relay_host_extracted_from_ws_urls() {
        assert_eq!(
            relay_host("wss://b2p-relay.example.workers.dev").as_deref(),
            Some("b2p-relay.example.workers.dev")
        );
        assert_eq!(
            relay_host("ws://127.0.0.1:9009").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(relay_host("not a url"), None);
    }

    #[test]
    fn report_renders_marks_and_verdict() {
        let report = DoctorReport {
            checks: vec![
                check("dns", Outcome::Ok),
                check("tls", Outcome::Warn),
                check("stun", Outcome::Fail),
            ],
            verdict: "sample verdict".into(),
        };
        let text = report.to_string();
        assert!(text.contains("✓ dns"), "{text}");
        assert!(text.contains("! tls"), "{text}");
        assert!(text.contains("✗ stun"), "{text}");
        assert!(text.contains("verdict: sample verdict"), "{text}");
    }

    #[tokio::test]
    async fn dns_check_treats_ip_literal_and_localhost_as_not_dns() {
        for host in ["127.0.0.1", "localhost"] {
            let c = dns_check(host).await;
            assert_eq!(c.outcome, Outcome::Ok, "{}", c.detail);
            assert!(c.detail.contains("DNS"), "{}", c.detail);
            assert!(c.detail.contains("not"), "{}", c.detail);
        }
    }
}
