//! TLS-interception probe for `b2p doctor`: connect to a host, capture the
//! certificate the network actually presents, name its issuer, and check
//! whether the chain verifies against the OS trust store (+ extra roots).
//! The permissive capture pass never carries application data — it exists
//! only to read the certificate for diagnosis.

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct TlsReport {
    /// Issuer DN of the leaf certificate the network presented.
    pub leaf_issuer: String,
    /// Whether the presented chain verifies against the OS store + extra roots.
    pub os_store_verifies: bool,
    pub os_error: Option<String>,
}

const PUBLIC_CA_MARKERS: &[&str] = &[
    "Let's Encrypt",
    "ISRG",
    "Google Trust Services",
    "DigiCert",
    "Cloudflare",
    "Amazon",
    "Sectigo",
    "COMODO",
    "USERTrust",
    "GlobalSign",
    "Entrust",
    "GoDaddy",
    "Starfield",
    "ZeroSSL",
    "SSL.com",
    "IdenTrust",
    "QuoVadis",
    "Buypass",
    "Actalis",
    "Microsoft",
    "Apple",
];

/// Heuristic: does this issuer look like a public CA (vs. a corporate
/// re-signing proxy)? Only ever used to phrase a warning, never to block.
pub fn looks_public(issuer: &str) -> bool {
    PUBLIC_CA_MARKERS.iter().any(|m| issuer.contains(m))
}

pub fn issuer_of(der: &[u8]) -> anyhow::Result<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("parsing server certificate: {e}"))?;
    Ok(cert.issuer().to_string())
}

pub fn load_pem_roots(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut &pem[..]).collect();
    certs.with_context(|| format!("parsing PEM certificates in {}", path.display()))
}

pub async fn probe(
    host: &str,
    port: u16,
    timeout: Duration,
    extra_roots: Vec<CertificateDer<'static>>,
) -> anyhow::Result<TlsReport> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || probe_blocking(&host, port, timeout, extra_roots)).await?
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn connect(host: &str, port: u16, timeout: Duration) -> anyhow::Result<TcpStream> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .context("hostname did not resolve")?;
    let s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
}

fn handshake(
    config: rustls::ClientConfig,
    host: &str,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<()> {
    let name = ServerName::try_from(host.to_string())?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name)?;
    let mut tcp = connect(host, port, timeout)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).context("TLS handshake")?;
    }
    Ok(())
}

fn probe_blocking(
    host: &str,
    port: u16,
    timeout: Duration,
    extra_roots: Vec<CertificateDer<'static>>,
) -> anyhow::Result<TlsReport> {
    // Pass 1: permissive verifier, only to capture the presented leaf cert.
    let captured = Arc::new(Mutex::new(None));
    let verifier = Arc::new(CaptureVerifier {
        captured: captured.clone(),
        schemes: provider()
            .signature_verification_algorithms
            .supported_schemes(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    handshake(config, host, port, timeout)?;
    let leaf: Vec<u8> = captured
        .lock()
        .unwrap()
        .take()
        .context("server presented no certificate")?;
    let leaf_issuer = issuer_of(&leaf)?;

    // Pass 2: real verification against the OS trust store + extra roots.
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    for cert in extra_roots {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let os = handshake(config, host, port, timeout);
    Ok(TlsReport {
        leaf_issuer,
        os_store_verifies: os.is_ok(),
        os_error: os.err().map(|e| format!("{e:#}")),
    })
}

#[derive(Debug)]
struct CaptureVerifier {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
    schemes: Vec<rustls::SignatureScheme>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.captured.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    fn spawn_tls_server() -> (SocketAddr, rcgen::CertifiedKey, std::thread::JoinHandle<()>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let listener = std::net::TcpListener::bind(("localhost", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(config);
        // probe() opens two connections (capture pass + verify pass)
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let Ok(mut tcp) = stream else { break };
                let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut tcp).is_err() {
                        break; // untrusted-client alert is expected in one test
                    }
                }
            }
        });
        (addr, ck, handle)
    }

    #[test]
    fn issuer_parses_from_der() {
        let ck = rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap();
        let issuer = issuer_of(ck.cert.der()).unwrap();
        assert!(issuer.contains("rcgen"), "{issuer}");
        assert!(issuer_of(b"garbage").is_err());
    }

    #[test]
    fn public_ca_heuristic() {
        assert!(looks_public("C=US, O=Let's Encrypt, CN=R11"));
        assert!(looks_public("C=US, O=Google Trust Services, CN=WR2"));
        assert!(!looks_public("CN=BTG Pactual-RootCA"));
    }

    #[tokio::test]
    async fn probe_reports_issuer_and_untrusted_chain() {
        let (addr, _ck, _h) = spawn_tls_server();
        let r = probe("localhost", addr.port(), Duration::from_secs(5), vec![])
            .await
            .unwrap();
        assert!(r.leaf_issuer.contains("rcgen"), "{}", r.leaf_issuer);
        assert!(!r.os_store_verifies);
        assert!(r.os_error.is_some());
    }

    #[tokio::test]
    async fn probe_trusts_extra_root() {
        let (addr, ck, _h) = spawn_tls_server();
        let root = CertificateDer::from(ck.cert.der().to_vec());
        let r = probe("localhost", addr.port(), Duration::from_secs(5), vec![root])
            .await
            .unwrap();
        assert!(r.os_store_verifies, "{:?}", r.os_error);
    }
}
