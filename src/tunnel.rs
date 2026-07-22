use crate::cloudflared_pins::{CLOUDFLARED_VERSION, PINS};
use anyhow::{bail, Context};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;

pub struct TunnelHandle {
    pub url: Url,
    child: Option<tokio::process::Child>,
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }
}

pub fn direct(port: u16) -> anyhow::Result<TunnelHandle> {
    let ip = lan_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Ok(TunnelHandle {
        url: format!("http://{ip}:{port}").parse()?,
        child: None,
    })
}

fn lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?; // no packet sent; just picks a route
    Some(sock.local_addr().ok()?.ip().to_string())
}

pub(crate) fn parse_tunnel_url(line: &str) -> Option<Url> {
    let start = line.find("https://")?;
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '|')
        .unwrap_or(rest.len());
    let candidate = &rest[..end];
    if candidate.contains(".trycloudflare.com") {
        candidate.parse().ok()
    } else {
        None
    }
}

pub(crate) fn platform_key() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-amd64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64"),
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("windows", "x86_64") => Some("windows-amd64"),
        _ => None,
    }
}

fn binary_path() -> anyhow::Result<PathBuf> {
    let dirs =
        directories::ProjectDirs::from("", "", "b2p").context("cannot determine data directory")?;
    let bin_dir = dirs.data_dir().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let name = if cfg!(windows) {
        "cloudflared.exe"
    } else {
        "cloudflared"
    };
    Ok(bin_dir.join(format!("{name}-{CLOUDFLARED_VERSION}")))
}

async fn ensure_binary(tls: &crate::http::TlsOpts) -> anyhow::Result<PathBuf> {
    let path = binary_path()?;
    if path.exists() {
        return Ok(path);
    }
    let key = platform_key().context("no cloudflared build pinned for this platform")?;
    let (_, file, expected_sha) = PINS
        .iter()
        .find(|(k, _, _)| *k == key)
        .context("platform missing from pin table")?;

    eprintln!("Downloading cloudflared {CLOUDFLARED_VERSION} (first run only)...");
    let url = format!(
        "https://github.com/cloudflare/cloudflared/releases/download/{CLOUDFLARED_VERSION}/{file}"
    );
    let bytes = crate::http::client(tls)?
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != *expected_sha {
        bail!("cloudflared download checksum mismatch — refusing to run it");
    }

    let binary: Vec<u8> = if file.ends_with(".tgz") {
        let gz = flate2::read::GzDecoder::new(bytes.as_ref());
        let mut ar = tar::Archive::new(gz);
        let mut out = Vec::new();
        for entry in ar.entries()? {
            let mut entry = entry?;
            if entry
                .path()?
                .file_name()
                .map(|n| n == "cloudflared")
                .unwrap_or(false)
            {
                std::io::copy(&mut entry, &mut out)?;
                break;
            }
        }
        if out.is_empty() {
            bail!("cloudflared binary not found inside archive");
        }
        out
    } else {
        bytes.to_vec()
    };

    std::fs::write(&path, binary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(path)
}

pub async fn start_cloudflared(
    port: u16,
    tls: &crate::http::TlsOpts,
) -> anyhow::Result<TunnelHandle> {
    let bin = ensure_binary(tls).await?;
    let mut child = tokio::process::Command::new(&bin)
        .args([
            "tunnel",
            "--url",
            &format!("http://127.0.0.1:{port}"),
            "--no-autoupdate",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start cloudflared")?;

    let stderr = child.stderr.take().context("no stderr from cloudflared")?;
    let mut lines = BufReader::new(stderr).lines();

    let url = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(url) = parse_tunnel_url(&line) {
                return Some(url);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .context(
        "tunnel did not come up within 30s — this network may block cloudflared; \
         try --direct on a LAN, or run the receiver on a less restricted network",
    )?;

    Ok(TunnelHandle {
        url,
        child: Some(child),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tunnel_url_from_cloudflared_banner() {
        let line =
            "2026-07-22T10:00:00Z INF |  https://tall-lion-radio-carpet.trycloudflare.com  |";
        let url = parse_tunnel_url(line).unwrap();
        assert_eq!(
            url.as_str(),
            "https://tall-lion-radio-carpet.trycloudflare.com/"
        );
        assert!(parse_tunnel_url("no url here").is_none());
        assert!(parse_tunnel_url("https://api.trycloudflare.com is not a tunnel").is_some());
    }

    #[test]
    fn direct_produces_http_url_with_port() {
        let h = direct(43210).unwrap();
        assert_eq!(h.url.scheme(), "http");
        assert_eq!(h.url.port(), Some(43210));
    }

    #[test]
    fn current_platform_has_a_pin() {
        assert!(
            platform_key().is_some(),
            "no cloudflared pin for this platform"
        );
        let key = platform_key().unwrap();
        assert!(crate::cloudflared_pins::PINS
            .iter()
            .any(|(k, _, _)| *k == key));
    }
}
