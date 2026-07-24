use anyhow::{bail, Context};
use b2p::http::TlsOpts;
use b2p::{archive, progress};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// How long a sender sits in the relay room waiting for the receiver to show
/// up and pair before giving up and running the doctor.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// How long a receiver sits in the relay room waiting for its sender.
const WAIT_FOR_SENDER: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Parser)]
#[command(name = "b2p", version, about = "Encrypted peer-to-peer file transfer")]
struct Cli {
    /// Extra PEM CA bundle to trust (e.g. a TLS-inspecting proxy's root CA)
    #[arg(long, global = true)]
    cafile: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wait for a transfer through the relay.
    Receive {
        /// Output directory (default: current directory)
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Accept the incoming transfer without prompting
        #[arg(long)]
        yes: bool,
        /// Overwrite existing files without warning
        #[arg(long)]
        overwrite: bool,
        /// Relay URL override (default: config / B2P_RELAY)
        #[arg(long)]
        relay: Option<String>,
    },
    /// Send files, folders, or text to a waiting receiver.
    Send {
        /// The code printed by `b2p receive` on the other machine
        code: String,
        /// Files and/or directories to send
        #[arg(required_unless_present = "text")]
        paths: Vec<PathBuf>,
        /// Send a text snippet instead of files
        #[arg(long, conflicts_with = "paths")]
        text: Option<String>,
        /// Relay URL override (default: config / B2P_RELAY / the code itself)
        #[arg(long)]
        relay: Option<String>,
    },
    /// Diagnose this network: DNS filtering, TLS inspection, UDP/STUN.
    Doctor {
        /// A URL or hostname to test (default: a public canary domain)
        target: Option<String>,
    },
    /// Configure the relay this machine uses by default.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Remember the relay URL (and optional token) in the config file.
    Set {
        /// wss://<your-worker>.workers.dev
        url: String,
        /// Bearer token, if the worker was deployed with RELAY_TOKEN
        #[arg(long)]
        token: Option<String>,
    },
    /// Print the configured relay.
    Show,
    /// Run a relay server on this machine (protocol-compatible with the
    /// Cloudflare Worker in relay-worker/).
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:9009")]
        listen: std::net::SocketAddr,
        /// Require this bearer token (falls back to env RELAY_TOKEN)
        #[arg(long)]
        token: Option<String>,
        /// PEM certificate chain — serve TLS directly (else put a proxy in front)
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let tls = TlsOpts {
        cafile: cli.cafile.clone(),
    };
    match cli.cmd {
        Cmd::Receive {
            out,
            yes,
            overwrite,
            relay,
        } => receive_relay_cli(out, yes, overwrite, relay, &tls).await,
        Cmd::Send {
            code,
            paths,
            text,
            relay,
        } => do_send(code, paths, text, relay, &tls).await,
        Cmd::Relay { cmd } => match cmd {
            RelayCmd::Set { url, token } => {
                let url = b2p::transport::relay::normalize_relay_url(&url)?;
                let mut cfg = b2p::config::load()?;
                cfg.relay = Some(url.clone());
                if token.is_some() {
                    cfg.relay_token = token;
                }
                let p = b2p::config::save(&cfg)?;
                eprintln!("relay set to {url} ({})", p.display());
                Ok(())
            }
            RelayCmd::Show => {
                let cfg = b2p::config::load()?;
                match cfg.relay {
                    Some(u) => println!(
                        "{u}{}",
                        if cfg.relay_token.is_some() {
                            " (token set)"
                        } else {
                            ""
                        }
                    ),
                    None => println!("(none configured)"),
                }
                Ok(())
            }
            RelayCmd::Serve {
                listen,
                token,
                tls_cert,
                tls_key,
            } => {
                let token = token.or_else(|| std::env::var("RELAY_TOKEN").ok());
                let tls = tls_cert.zip(tls_key);
                let secure = tls.is_some();
                let cfg = b2p::relay_server::ServeCfg {
                    listen,
                    token: token.clone(),
                    tls,
                    ..Default::default()
                };
                let server = b2p::relay_server::start(cfg).await?;
                eprintln!(
                    "b2p relay listening on {} ({}{})",
                    server.addr,
                    if secure {
                        "wss — built-in TLS"
                    } else {
                        "ws — plain; put TLS (Caddy/nginx/ingress) in front for internet use"
                    },
                    if token.is_some() {
                        ", token required"
                    } else {
                        ""
                    },
                );
                tokio::signal::ctrl_c().await?;
                eprintln!("shutting down");
                server.shutdown().await;
                Ok(())
            }
        },
        Cmd::Doctor { target } => {
            let target_host = target.as_deref().map(parse_target).transpose()?;
            // Probe the configured relay too, when there is one — resolution
            // errors here just mean "no relay yet", not a doctor failure.
            let relay_cfg = b2p::config::load().ok().and_then(|cfg| {
                b2p::config::resolve_relay(
                    None,
                    None,
                    std::env::var("B2P_RELAY").ok().as_deref(),
                    std::env::var("B2P_RELAY_TOKEN").ok().as_deref(),
                    &cfg,
                )
                .ok()
            });
            let (relay, relay_token) = match relay_cfg {
                Some(r) => (Some(r.url), r.token),
                None => (None, None),
            };
            let report = b2p::doctor::run(&b2p::doctor::DoctorArgs {
                target_host,
                cafile: cli.cafile.clone(),
                relay,
                relay_token,
            })
            .await;
            println!("{report}");
            Ok(())
        }
    }
}

/// Decide whether to accept an incoming transfer. `--yes` skips the prompt
/// (still refusing a `Kind::File` clobber unless `--overwrite`); otherwise it
/// prints a summary and reads y/N from stdin.
fn accept_decision(
    m: &b2p::protocol::Manifest,
    out_dir: &std::path::Path,
    yes: bool,
    overwrite: bool,
) -> bool {
    use b2p::protocol::Kind;
    let clobber = m.kind == Kind::File
        && out_dir
            .join(
                std::path::Path::new(&m.name)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
            )
            .exists();
    if yes {
        return !(clobber && !overwrite);
    }
    let summary = match m.kind {
        Kind::Text => "Incoming text snippet".to_string(),
        _ => format!(
            "Incoming: {} file(s), {} bytes total",
            m.entries.len(),
            m.total_size
        ),
    };
    eprintln!("\n{summary}");
    if clobber {
        eprintln!("  WARNING: destination file exists and will be overwritten");
    }
    eprint!("Accept? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    line.trim().eq_ignore_ascii_case("y")
}

/// Default (P2b) receive path: everything through the operator's relay.
/// One code, re-armed across sender retries — a dropped connection resumes
/// from the staged chunks instead of restarting.
async fn receive_relay_cli(
    out: PathBuf,
    yes: bool,
    overwrite: bool,
    relay_flag: Option<String>,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&out)?;
    let cfg = b2p::config::load()?;
    let relay = b2p::config::resolve_relay(
        relay_flag.as_deref(),
        None,
        std::env::var("B2P_RELAY").ok().as_deref(),
        std::env::var("B2P_RELAY_TOKEN").ok().as_deref(),
        &cfg,
    )?;
    let code = b2p::rvcode::RendezvousCode::generate_human();
    let host = relay
        .url
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .to_string();
    eprintln!("\nOn the other machine, run:\n");
    println!("    b2p send {code} <files...>");
    eprintln!("\n  or, if that machine has no relay configured:\n");
    println!(
        "    b2p send '{}' <files...>",
        code.url_spelling(Some(&host))
    );
    eprintln!("\nWaiting for the sender... (Ctrl-C to abort)");

    // A 409 right after re-arming usually means the DO hasn't reaped our
    // previous socket yet — retry briefly before treating it as fatal.
    let mut busy_retries = 0u32;
    loop {
        let out_for_accept = out.clone();
        let accept =
            move |m: &b2p::protocol::Manifest| accept_decision(m, &out_for_accept, yes, overwrite);
        let attempt = b2p::session::receive_relay(
            &relay.url,
            relay.token.as_deref(),
            &code.topic,
            &code.secret.0,
            &out,
            accept,
            tls,
            WAIT_FOR_SENDER,
            None,
        )
        .await;
        match attempt {
            Ok(desc) => {
                eprintln!("via relay");
                eprintln!("Done: {desc}");
                return Ok(());
            }
            // Room expiry / relay restart while waiting: quiet re-dial (the
            // dial itself surfaces a genuinely dead network as an
            // EstablishError below).
            Err(e)
                if e.downcast_ref::<b2p::transport::relay::WaitClosed>()
                    .is_some() =>
            {
                busy_retries = 0;
            }
            Err(e)
                if e.downcast_ref::<b2p::transport::relay::TransportLost>()
                    .is_some() =>
            {
                eprintln!(
                    "connection lost ({e:#}) — the code is still valid; waiting for the sender to retry..."
                );
                busy_retries = 0;
            }
            Err(e) if e.downcast_ref::<b2p::handshake::CodeMismatch>().is_some() => {
                eprintln!("a sender connected with a non-matching code — still waiting...");
                busy_retries = 0;
                // Backoff so a wrong-code (or hostile) sender can't make the
                // receiver hot-cycle full connect+PAKE rounds.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            // Transient 409: the edge can hold a dead predecessor socket for
            // minutes — back off exponentially (~2 min total budget). The
            // counter is per-stretch: any other outcome resets it.
            Err(e)
                if busy_retries < 8
                    && e.downcast_ref::<b2p::session::EstablishError>()
                        .is_some_and(|ee| {
                            ee.0.downcast_ref::<b2p::transport::relay::RoomBusy>()
                                .is_some()
                        }) =>
            {
                let delay = (2u64 << busy_retries).min(20);
                busy_retries += 1;
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            Err(e) if e.downcast_ref::<b2p::session::EstablishError>().is_some() => {
                return connect_failed_relay(e, &relay, tls).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn do_send(
    code: String,
    paths: Vec<PathBuf>,
    text: Option<String>,
    relay_flag: Option<String>,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    // Parse the code BEFORE `archive::prepare`, which can tar a large
    // folder — an invalid code should fail fast, not after a long tar.
    if !b2p::rvcode::is_rendezvous_code(&code) {
        bail!(
            "unrecognized code — expected the form `7-otter-zebra` or `b2p://…` as printed by \
             `b2p receive` (v1 `https://…#…` tunnel codes are no longer supported; update b2p \
             on both machines)"
        );
    }
    let rc = b2p::rvcode::parse(&code).context("invalid code")?;

    let source = match &text {
        Some(t) => archive::prepare_text(t),
        None => {
            eprintln!("Preparing...");
            archive::prepare(&paths)?
        }
    };
    let cfg = b2p::config::load()?;
    let relay = b2p::config::resolve_relay(
        relay_flag.as_deref(),
        rc.relay_host.as_deref(),
        std::env::var("B2P_RELAY").ok().as_deref(),
        std::env::var("B2P_RELAY_TOKEN").ok().as_deref(),
        &cfg,
    )?;
    let bar = match &source {
        archive::Source::Blob { total_size, .. } => Some(progress::transfer_bar(*total_size)),
        archive::Source::Text { .. } => None,
    };
    eprintln!("Waiting for the receiver...");
    let desc = match b2p::session::send_relay(
        &relay.url,
        relay.token.as_deref(),
        &rc.topic,
        &rc.secret.0,
        &source,
        tls,
        CONNECT_TIMEOUT,
        bar.clone(),
    )
    .await
    {
        Ok(d) => d,
        Err(e) if e.downcast_ref::<b2p::session::EstablishError>().is_some() => {
            return connect_failed_relay(e, &relay, tls).await
        }
        Err(e) => return Err(e),
    };
    if let Some(b) = bar {
        b.finish();
    }
    eprintln!("via relay");
    eprintln!("Done: {desc}");
    Ok(())
}

/// Run on a relay establishment failure (design §6: dial/handshake only —
/// never a transfer-phase error, see `EstablishError`): print the error, run
/// the doctor against the failing relay itself, and surface both to the user.
///
/// Prints the full error itself (via `{e:#}`) and returns a short, distinct
/// error so `main`'s own `error: {e:#}` doesn't repeat the same text —
/// callers should propagate this return value as-is, not re-wrap `e`.
async fn connect_failed_relay(
    e: anyhow::Error,
    relay: &b2p::config::RelayCfg,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    eprintln!("\nCould not connect: {e:#}");
    eprintln!("Running diagnostics (b2p doctor)...\n");
    let report = b2p::doctor::run(&b2p::doctor::DoctorArgs {
        target_host: None,
        cafile: tls.cafile.clone(),
        relay: Some(relay.url.clone()),
        relay_token: relay.token.clone(),
    })
    .await;
    eprintln!("{report}");
    Err(anyhow::anyhow!(
        "could not establish a connection (see diagnostics above)"
    ))
}

fn parse_target(s: &str) -> anyhow::Result<String> {
    let host = if s.contains("://") {
        url::Url::parse(s)
            .context("invalid URL")?
            .host_str()
            .context("URL has no host")?
            .to_string()
    } else {
        s.to_string()
    };
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_accepts_url_and_host() {
        assert_eq!(
            parse_target("https://example.com/x").unwrap(),
            "example.com"
        );
        assert_eq!(parse_target("example.com").unwrap(), "example.com");
        assert!(parse_target("http://#nope").is_err());
    }

    #[test]
    fn send_accepts_only_relay_codes() {
        // human + b2p:// codes are valid; v1 https:// tunnel codes are not
        assert!(b2p::rvcode::is_rendezvous_code("7-otter-zebra"));
        assert!(b2p::rvcode::is_rendezvous_code("b2p://topic#secret"));
        assert!(!b2p::rvcode::is_rendezvous_code(
            "https://x.trycloudflare.com#abc"
        ));
    }

    #[test]
    fn relay_serve_flags_validate() {
        use clap::Parser;
        // tls flags require each other
        assert!(Cli::try_parse_from(["b2p", "relay", "serve", "--tls-cert", "c.pem"]).is_err());
        assert!(Cli::try_parse_from(["b2p", "relay", "serve", "--tls-key", "k.pem"]).is_err());
        // happy path parses with a custom listen addr
        let cli =
            Cli::try_parse_from(["b2p", "relay", "serve", "--listen", "127.0.0.1:7777"]).unwrap();
        match cli.cmd {
            Cmd::Relay {
                cmd: RelayCmd::Serve { listen, .. },
            } => {
                assert_eq!(listen.port(), 7777);
            }
            _ => panic!("expected relay serve"),
        }
    }

    #[test]
    fn accept_decision_honors_yes_and_clobber() {
        use b2p::protocol::{Entry, Kind, Manifest, PROTOCOL_VERSION};
        let dir = tempfile::tempdir().unwrap();
        let m = Manifest {
            version: PROTOCOL_VERSION,
            transfer_id: "t".into(),
            kind: Kind::File,
            name: "f.bin".into(),
            entries: vec![Entry {
                path: "f.bin".into(),
                size: 4,
            }],
            total_size: 4,
            chunk_size: 16 * 1024,
            text: None,
        };
        // --yes, no existing file → accept
        assert!(accept_decision(&m, dir.path(), true, false));
        // --yes but destination exists and no --overwrite → decline
        std::fs::write(dir.path().join("f.bin"), b"old").unwrap();
        assert!(!accept_decision(&m, dir.path(), true, false));
        // --yes + --overwrite → accept despite existing
        assert!(accept_decision(&m, dir.path(), true, true));
    }
}
