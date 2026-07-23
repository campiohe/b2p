//! `b2p doctor`: name exactly which network layer is broken (DNS / TLS /
//! UDP / HTTPS reachability) and say what to do about it — instead of the
//! old generic "check the code and their tunnel". Spec: b2p-v2-spec.md §6.

use crate::http::TlsOpts;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// The v1 transport's domain — the default diagnosis target.
pub const DEFAULT_TARGET: &str = "trycloudflare.com";
/// Mainstream host whose certificate issuer reveals TLS inspection.
const TLS_CANARY: &str = "www.google.com";
/// The planned v2 default rendezvous (P1); P0 only reports reachability.
const RENDEZVOUS_HEALTH: &str = "https://ntfy.sh/v1/health";
pub const STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DoctorArgs {
    /// Host to test at the DNS layer (from a code, or DEFAULT_TARGET).
    pub target_host: Option<String>,
    pub cafile: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    /// Stable id used by verdict logic: "dns" | "tls" | "stun" | "rendezvous".
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
    let target = args.target_host.as_deref().unwrap_or(DEFAULT_TARGET);
    let tls = TlsOpts {
        cafile: args.cafile.clone(),
    };
    let (dns, tls_c, stun, rendezvous) = tokio::join!(
        dns_check(target),
        tls_check(args.cafile.clone()),
        stun_check(),
        rendezvous_check(&tls, RENDEZVOUS_HEALTH),
    );
    let checks = vec![dns, tls_c, stun, rendezvous];
    let verdict = verdict(&checks, target);
    DoctorReport { checks, verdict }
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
    // Query both STUN servers from ONE socket and compare mapped ports — a
    // reachability-only probe passes behind a symmetric NAT that then fails
    // every cross-network transfer (the false all-clear this check closes).
    match crate::stun::nat_mapping(&STUN_SERVERS, Duration::from_secs(3)).await {
        crate::stun::NatMapping::EndpointIndependent(addr) => make(
            Outcome::Ok,
            format!(
                "UDP egress works; mapped to {addr} from every STUN server — \
                 endpoint-independent NAT, direct WebRTC viable"
            ),
        ),
        crate::stun::NatMapping::OneResponse(addr) => make(
            Outcome::Ok,
            format!(
                "UDP egress works (mapped to {addr}; only one STUN server answered, so NAT \
                 mapping is unclassified) — WebRTC likely viable"
            ),
        ),
        crate::stun::NatMapping::Symmetric(addrs) => make(
            Outcome::Warn,
            format!(
                "UDP egress works, but this NAT is symmetric (mapped addresses differ: {addrs:?}) \
                 — direct WebRTC to another NAT'd peer will likely fail; use a TURN relay \
                 (--turn) or --tunnel"
            ),
        ),
        crate::stun::NatMapping::NoResponse => make(
            Outcome::Warn,
            "no STUN response — UDP likely blocked (harmless for the tunnel transport; \
             matters for v2 WebRTC)"
                .into(),
        ),
    }
}

async fn rendezvous_check(tls: &TlsOpts, url: &str) -> Check {
    let label = format!("rendezvous ({url})");
    let make = |outcome, detail: String| Check {
        name: "rendezvous",
        label: label.clone(),
        outcome,
        detail,
    };
    let client = match crate::http::client(tls) {
        Ok(c) => c,
        Err(e) => return make(Outcome::Fail, format!("cannot build HTTPS client: {e:#}")),
    };
    match client.get(url).timeout(CHECK_TIMEOUT).send().await {
        Ok(r) if r.status().is_success() => make(
            Outcome::Ok,
            format!("HTTP {} — reachable", r.status().as_u16()),
        ),
        Ok(r) => make(
            Outcome::Warn,
            format!("unexpected HTTP {}", r.status().as_u16()),
        ),
        Err(e) => make(Outcome::Fail, format!("unreachable: {e:#}")),
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
            "this network blocks {target} at the DNS layer — the tunnel transport cannot \
             work here; try `b2p receive --direct` with both machines on the same LAN, or \
             run the receiver on a less restricted network"
        );
    }
    if failed("tls") {
        return "TLS verification is failing — if this network runs TLS inspection, add its \
                root CA to the OS trust store, or pass --cafile / set SSL_CERT_FILE"
            .into();
    }
    if failed("rendezvous") {
        return "HTTPS egress looks restricted (the rendezvous host is unreachable) — \
                transfers may still work if the tunnel host is reachable; otherwise use \
                --direct on a shared LAN"
            .into();
    }
    // A symmetric NAT passes every layer above yet breaks direct WebRTC — the
    // one case where "no blockers found" would be a false all-clear.
    if checks
        .iter()
        .any(|c| c.name == "stun" && c.outcome == Outcome::Warn && c.detail.contains("symmetric"))
    {
        return "every layer is clean, but this network's NAT is symmetric — direct WebRTC to \
                another NAT'd peer will likely fail. Use a TURN relay (--turn), --tunnel, or put \
                both peers on the same LAN"
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

    #[test]
    fn dns_block_dominates_verdict() {
        let checks = vec![
            check("dns", Outcome::Fail),
            check("tls", Outcome::Ok),
            check("stun", Outcome::Ok),
            check("rendezvous", Outcome::Ok),
        ];
        let v = verdict(&checks, "trycloudflare.com");
        assert!(v.contains("DNS"), "{v}");
        assert!(v.contains("--direct"), "{v}");
    }

    #[test]
    fn tls_failure_suggests_cafile() {
        let checks = vec![
            check("dns", Outcome::Ok),
            check("tls", Outcome::Fail),
            check("stun", Outcome::Ok),
            check("rendezvous", Outcome::Ok),
        ];
        let v = verdict(&checks, "example.com");
        assert!(v.contains("--cafile"), "{v}");
    }

    #[test]
    fn symmetric_nat_warns_in_verdict() {
        let checks = vec![
            check("dns", Outcome::Ok),
            check("tls", Outcome::Ok),
            Check {
                name: "stun",
                label: "UDP/STUN".into(),
                outcome: Outcome::Warn,
                detail: "UDP egress works, but this NAT is symmetric (mapped ports differ: \
                         [3828, 29126])"
                    .into(),
            },
            check("rendezvous", Outcome::Ok),
        ];
        let v = verdict(&checks, "example.com");
        assert!(v.contains("symmetric"), "{v}");
        assert!(v.contains("--turn"), "{v}");
    }

    #[test]
    fn clean_network_positive_verdict() {
        let checks = vec![
            check("dns", Outcome::Ok),
            check("tls", Outcome::Ok),
            check("stun", Outcome::Ok),
            check("rendezvous", Outcome::Ok),
        ];
        let v = verdict(&checks, "example.com");
        assert!(v.contains("no blockers"), "{v}");
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

    #[tokio::test]
    async fn rendezvous_check_against_local_server() {
        // any 200-returning local HTTP endpoint stands in for ntfy.sh
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let tls = crate::http::TlsOpts::default();
        let c = rendezvous_check(&tls, &format!("http://{addr}/health")).await;
        assert_eq!(c.outcome, Outcome::Ok, "{}", c.detail);
        let c = rendezvous_check(&tls, &format!("http://{addr}/missing")).await;
        assert_eq!(c.outcome, Outcome::Warn, "{}", c.detail);
    }
}
