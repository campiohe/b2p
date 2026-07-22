use anyhow::Context;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// TLS trust options shared by every outbound HTTPS client b2p builds.
/// The OS certificate store is always trusted (via rustls-native-certs,
/// which also honors SSL_CERT_FILE / SSL_CERT_DIR); `cafile` adds extra
/// PEM roots on top — e.g. a TLS-inspecting proxy's CA.
#[derive(Clone, Default)]
pub struct TlsOpts {
    pub cafile: Option<PathBuf>,
}

pub fn client(opts: &TlsOpts) -> anyhow::Result<reqwest::Client> {
    Ok(builder(opts)?.build()?)
}

pub fn builder(opts: &TlsOpts) -> anyhow::Result<reqwest::ClientBuilder> {
    let mut b = reqwest::Client::builder().connect_timeout(Duration::from_secs(15));
    if let Some(path) = &opts.cafile {
        for cert in load_pem_certs(path)? {
            b = b.add_root_certificate(cert);
        }
    }
    Ok(b)
}

fn load_pem_certs(path: &Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let pem =
        std::fs::read(path).with_context(|| format!("reading --cafile {}", path.display()))?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .with_context(|| format!("parsing PEM certificates in {}", path.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        path.display()
    );
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_no_cafile() {
        client(&TlsOpts::default()).unwrap();
    }

    #[test]
    fn rejects_missing_and_garbage_cafile() {
        let dir = tempfile::tempdir().unwrap();
        let missing = TlsOpts {
            cafile: Some(dir.path().join("nope.pem")),
        };
        assert!(client(&missing).is_err());

        let garbage = dir.path().join("bad.pem");
        std::fs::write(&garbage, "not a pem").unwrap();
        assert!(client(&TlsOpts {
            cafile: Some(garbage)
        })
        .is_err());
    }

    #[test]
    fn accepts_valid_pem_cafile() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, ck.cert.pem()).unwrap();
        client(&TlsOpts { cafile: Some(path) }).unwrap();
    }
}
