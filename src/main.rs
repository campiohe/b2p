use anyhow::{bail, Context};
use b2p::code::Code;
use b2p::crypto::Secret;
use b2p::http::TlsOpts;
use b2p::server::{AcceptRequest, Event, ServerCfg};
use b2p::{archive, progress, send, server, tunnel};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// STUN servers offered to the WebRTC ICE agent for the P1 (default) stack.
const STUN_SERVERS: [&str; 2] = [
    "stun:stun.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
];
/// Default rendezvous service (ntfy.sh) used to run the PAKE handshake and
/// exchange SDP/ICE for the P1 stack.
const DEFAULT_RENDEZVOUS: &str = "https://ntfy.sh";
/// How long to wait for the WebRTC connection to form before giving up and
/// running the doctor. Bounds the *whole* negotiation (ntfy subscribe, SDP
/// offer/answer, ICE trickle + connectivity checks, DTLS, SCTP), so a
/// slow-but-viable WAN path needs headroom; the extra wait is only felt on
/// failure.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

/// The STUN defaults as a single `IceServer` (no credentials). TURN entries are
/// appended in `ice_servers` (Task 3).
fn default_ice_servers() -> Vec<b2p::turn::IceServer> {
    vec![b2p::turn::IceServer {
        urls: STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
        username: String::new(),
        credential: String::new(),
    }]
}

/// STUN defaults plus any resolved TURN servers. Errors if `--turn` was given
/// without a credential mode.
fn ice_servers(turn: &TurnArgs) -> anyhow::Result<Vec<b2p::turn::IceServer>> {
    let mut servers = default_ice_servers();
    servers.extend(turn.resolve()?);
    Ok(servers)
}

#[derive(Parser)]
#[command(name = "b2p", version, about = "Encrypted peer-to-peer file transfer")]
struct Cli {
    /// Extra PEM CA bundle to trust (e.g. a TLS-inspecting proxy's root CA)
    #[arg(long, global = true)]
    cafile: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

/// TURN relay flags shared by `receive` and `send` (design §4). With no flags,
/// the transport stays STUN-only. Only the peer that allocates a relay needs
/// credentials (design §3.1), so either peer may set these independently.
#[derive(clap::Args, Clone)]
struct TurnArgs {
    /// TURN relay URL (turn: UDP only — webrtc-ice can't do TLS/TCP). Repeat for several.
    #[arg(long = "turn")]
    turn: Vec<String>,
    /// coturn use-auth-secret shared secret; b2p mints a short-lived credential.
    #[arg(long, conflicts_with_all = ["turn_user", "turn_pass"])]
    turn_secret: Option<String>,
    /// Static TURN username (requires --turn-pass).
    #[arg(long, requires = "turn_pass", conflicts_with = "turn_secret")]
    turn_user: Option<String>,
    /// Static TURN password (requires --turn-user).
    #[arg(long, requires = "turn_user", conflicts_with = "turn_secret")]
    turn_pass: Option<String>,
}

impl TurnArgs {
    fn resolve(&self) -> anyhow::Result<Vec<b2p::turn::IceServer>> {
        // Random nonce disambiguates concurrent coturn allocations.
        let nonce = format!("{:08x}", rand::random::<u32>());
        b2p::turn::resolve(
            &self.turn,
            self.turn_secret.as_deref(),
            self.turn_user.as_deref(),
            self.turn_pass.as_deref(),
            &nonce,
        )
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Wait for a transfer over the peer-to-peer (WebRTC) stack by default.
    Receive {
        /// Output directory (default: current directory)
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Skip the tunnel and serve directly on the LAN (--tunnel only)
        #[arg(long, requires = "tunnel")]
        direct: bool,
        /// Accept the incoming transfer without prompting
        #[arg(long)]
        yes: bool,
        /// Overwrite existing files without warning
        #[arg(long)]
        overwrite: bool,
        /// Use the v1 Cloudflare tunnel instead of the P2P (WebRTC) stack
        #[arg(long)]
        tunnel: bool,
        /// Rendezvous base URL (default: https://ntfy.sh)
        #[arg(long)]
        rendezvous: Option<String>,
        #[command(flatten)]
        turn: TurnArgs,
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
        /// Rendezvous base URL (default: https://ntfy.sh)
        #[arg(long)]
        rendezvous: Option<String>,
        #[command(flatten)]
        turn: TurnArgs,
    },
    /// Diagnose this network: DNS filtering, TLS inspection, UDP/STUN.
    Doctor {
        /// A b2p code, URL, or hostname to test (default: the tunnel domain)
        target: Option<String>,
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
            direct,
            yes,
            overwrite,
            tunnel,
            rendezvous,
            turn,
        } => {
            if tunnel {
                receive_tunnel(out, direct, yes, overwrite, &tls).await
            } else {
                receive_p1_cli(out, yes, overwrite, rendezvous, turn, &tls).await
            }
        }
        Cmd::Send {
            code,
            paths,
            text,
            rendezvous,
            turn,
        } => do_send(code, paths, text, rendezvous, turn, &tls).await,
        Cmd::Doctor { target } => {
            let target_host = target.as_deref().map(parse_target).transpose()?;
            let report = b2p::doctor::run(&b2p::doctor::DoctorArgs {
                target_host,
                cafile: cli.cafile.clone(),
            })
            .await;
            println!("{report}");
            Ok(())
        }
    }
}

async fn receive_tunnel(
    out: PathBuf,
    direct: bool,
    yes: bool,
    overwrite: bool,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&out)?;
    let secret = Secret::generate();
    let mut handles = server::start(
        ServerCfg {
            secret: secret.clone(),
            out_dir: out.clone(),
            auto_accept: yes,
            overwrite,
        },
        direct,
    )
    .await?;

    let tunnel_handle = if direct {
        tunnel::direct(handles.port)?
    } else {
        eprintln!("Opening tunnel...");
        tunnel::start_cloudflared(handles.port, tls).await?
    };

    let code = Code::new(tunnel_handle.url.clone(), secret);
    eprintln!("\nOn the other machine, run:\n");
    println!("    b2p send '{code}' <files...>\n");
    eprintln!("Waiting for the sender... (Ctrl-C to abort; partial data is kept)");

    let mut bar: Option<indicatif::ProgressBar> = None;
    loop {
        tokio::select! {
            Some(AcceptRequest { summary, reply }) = handles.accept_rx.recv() => {
                eprintln!("\n{summary}");
                eprint!("Accept? [y/N] ");
                std::io::stderr().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                let _ = reply.send(line.trim().eq_ignore_ascii_case("y"));
            }
            Some(ev) = handles.events_rx.recv() => match ev {
                Event::Accepted { name, total_size } => {
                    eprintln!("Receiving {name}...");
                    bar = Some(progress::transfer_bar(total_size));
                }
                Event::Progress { bytes } => {
                    if let Some(b) = &bar { b.inc(bytes); }
                }
                Event::Text(t) => {
                    eprintln!("--- text snippet ---");
                    println!("{t}");
                }
                Event::Done(desc) => {
                    if let Some(b) = &bar { b.finish(); }
                    eprintln!("Done: {desc}");
                    break;
                }
                Event::Failed(msg) => {
                    if let Some(b) = &bar { b.abandon(); }
                    bail!("{msg}");
                }
            },
            _ = handles.shutdown.cancelled() => break,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nAborted. Partial data kept — run `b2p receive` again to resume.");
                handles.shutdown.cancel();
                break;
            }
        }
    }
    drop(tunnel_handle);
    Ok(())
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

/// P1 (default) receive path: PAKE handshake + WebRTC transport over the
/// rendezvous service, no tunnel or local server involved. A live
/// byte-accurate progress bar is deferred to a follow-up — this prints
/// status lines instead of animating one.
async fn receive_p1_cli(
    out: PathBuf,
    yes: bool,
    overwrite: bool,
    rendezvous: Option<String>,
    turn: TurnArgs,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&out)?;
    // Resolve ICE servers early so a bad --turn combo fails before we print a code.
    let ice = ice_servers(&turn)?;
    let code = b2p::rvcode::RendezvousCode::generate_human();
    eprintln!("\nOn the other machine, run:\n");
    println!("    b2p send {code} <files...>\n");
    eprintln!("Waiting for the sender...");

    let base = rendezvous.as_deref().unwrap_or(DEFAULT_RENDEZVOUS);
    let rv: Arc<dyn b2p::rendezvous::Rendezvous> =
        Arc::new(b2p::rendezvous::ntfy::NtfyRendezvous::new(base, tls)?);
    let out_for_accept = out.clone();
    let accept =
        move |m: &b2p::protocol::Manifest| accept_decision(m, &out_for_accept, yes, overwrite);

    let desc = match b2p::session::receive_p1(
        rv,
        &code.topic,
        &code.secret.0,
        &out,
        accept,
        &ice,
        CONNECT_TIMEOUT,
        None,
    )
    .await
    {
        Ok(d) => d,
        // Only an establishment (handshake/connect) failure runs the doctor
        // (design §6) — a transfer-phase error (declined, hash mismatch,
        // version mismatch) is returned as-is for `main` to print once.
        Err(e) if e.downcast_ref::<b2p::session::EstablishError>().is_some() => {
            return connect_failed(e, base, tls).await
        }
        Err(e) => return Err(e),
    };
    eprintln!("via WebRTC");
    eprintln!("Done: {desc}");
    Ok(())
}

async fn do_send(
    code: String,
    paths: Vec<PathBuf>,
    text: Option<String>,
    rendezvous: Option<String>,
    turn: TurnArgs,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    // Classify/parse the code BEFORE `archive::prepare`, which can tar a
    // large folder — an invalid code should fail fast, not after a long tar.
    enum Dest {
        Rendezvous(b2p::rvcode::RendezvousCode),
        Tunnel(Code),
    }
    let dest = if b2p::rvcode::is_rendezvous_code(&code) {
        Dest::Rendezvous(b2p::rvcode::parse(&code).context("invalid code")?)
    } else {
        Dest::Tunnel(Code::parse(&code).context("invalid code — paste it exactly as printed")?)
    };

    // Resolve TURN before the (possibly long) tar so a bad --turn combo fails
    // fast, mirroring the code parse above. It only applies to the WebRTC path.
    let ice = ice_servers(&turn)?;
    if !turn.turn.is_empty() && matches!(dest, Dest::Tunnel(_)) {
        eprintln!("note: --turn only applies to the WebRTC path; ignoring it for this tunnel code");
    }

    let source = match &text {
        Some(t) => archive::prepare_text(t),
        None => {
            eprintln!("Preparing...");
            archive::prepare(&paths)?
        }
    };
    match dest {
        Dest::Rendezvous(rc) => {
            let base = rendezvous.as_deref().unwrap_or(DEFAULT_RENDEZVOUS);
            let rv: Arc<dyn b2p::rendezvous::Rendezvous> =
                Arc::new(b2p::rendezvous::ntfy::NtfyRendezvous::new(base, tls)?);
            let bar = match &source {
                archive::Source::Blob { total_size, .. } => {
                    Some(progress::transfer_bar(*total_size))
                }
                archive::Source::Text { .. } => None,
            };
            eprintln!("Waiting for the receiver...");
            let desc = match b2p::session::send_p1(
                rv,
                &rc.topic,
                &rc.secret.0,
                &source,
                &ice,
                CONNECT_TIMEOUT,
                bar.clone(),
            )
            .await
            {
                Ok(d) => d,
                // Only an establishment (handshake/connect) failure runs the
                // doctor (design §6) — a transfer-phase error is returned
                // as-is for `main` to print once.
                Err(e) if e.downcast_ref::<b2p::session::EstablishError>().is_some() => {
                    return connect_failed(e, base, tls).await
                }
                Err(e) => return Err(e),
            };
            if let Some(b) = bar {
                b.finish();
            }
            eprintln!("via WebRTC");
            eprintln!("Done: {desc}");
            Ok(())
        }
        Dest::Tunnel(code) => {
            // v1 tunnel code
            let bar = match &source {
                archive::Source::Blob { total_size, .. } => {
                    Some(progress::transfer_bar(*total_size))
                }
                archive::Source::Text { .. } => None,
            };
            eprintln!("Waiting for the receiver to accept...");
            let desc = send::send(&code, source, bar.clone(), tls).await?;
            if let Some(b) = bar {
                b.finish();
            }
            eprintln!("Done: {desc}");
            Ok(())
        }
    }
}

/// Run on a P1 establishment failure (design §6: handshake/connect only —
/// never a transfer-phase error, see `EstablishError`): print the error, run
/// the doctor, and surface both to the user.
///
/// Prints the full error itself (via `{e:#}`) and returns a short, distinct
/// error so `main`'s own `error: {e:#}` doesn't repeat the same text —
/// callers should propagate this return value as-is, not re-wrap `e`.
///
/// `rendezvous_base` is used only to point the doctor's DNS check at the
/// right host. Note the doctor's rendezvous-*reachability* check is still
/// hard-coded to ntfy.sh regardless of `--rendezvous` (a known limitation
/// for custom rendezvous hosts — a follow-up; see src/doctor.rs).
async fn connect_failed(
    e: anyhow::Error,
    rendezvous_base: &str,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    eprintln!("\nCould not connect: {e:#}");
    eprintln!("Running diagnostics (b2p doctor)...\n");
    let host = url::Url::parse(rendezvous_base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));
    let report = b2p::doctor::run(&b2p::doctor::DoctorArgs {
        target_host: host,
        cafile: tls.cafile.clone(),
    })
    .await;
    eprintln!("{report}");
    Err(anyhow::anyhow!(
        "could not establish a connection (see diagnostics above)"
    ))
}

fn parse_target(s: &str) -> anyhow::Result<String> {
    let host = if s.contains('#') {
        Code::parse(s)?
            .base_url
            .host_str()
            .context("code URL has no host")?
            .to_string()
    } else if s.contains("://") {
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
    fn parse_target_accepts_code_url_and_host() {
        let secret = b2p::crypto::Secret::generate();
        let code = b2p::code::Code::new(
            "https://tall-lion.trycloudflare.com".parse().unwrap(),
            secret,
        );
        assert_eq!(
            parse_target(&code.to_string()).unwrap(),
            "tall-lion.trycloudflare.com"
        );
        assert_eq!(
            parse_target("https://example.com/x").unwrap(),
            "example.com"
        );
        assert_eq!(parse_target("example.com").unwrap(), "example.com");
        assert!(parse_target("http://#nope").is_err());
    }

    #[test]
    fn dispatch_picks_transport_by_code_form() {
        // human + b2p:// codes → rendezvous (P1); https:// → tunnel (P0)
        assert!(b2p::rvcode::is_rendezvous_code("7-otter-zebra"));
        assert!(b2p::rvcode::is_rendezvous_code("b2p://topic#secret"));
        assert!(!b2p::rvcode::is_rendezvous_code(
            "https://x.trycloudflare.com#abc"
        ));
    }

    #[test]
    fn turn_flags_validate() {
        use clap::Parser;
        // --turn-user requires --turn-pass
        assert!(Cli::try_parse_from(["b2p", "receive", "--turn-user", "u"]).is_err());
        // --turn-secret conflicts with static creds
        assert!(Cli::try_parse_from([
            "b2p", "receive", "--turn-secret", "s", "--turn-user", "u", "--turn-pass", "p"
        ])
        .is_err());
        // valid: udp turn: + --turn-secret on send
        let cli = Cli::try_parse_from([
            "b2p", "send", "7-a-b", "f", "--turn", "turn:h:3478", "--turn-secret", "s",
        ])
        .unwrap();
        if let Cmd::Send { turn, .. } = cli.cmd {
            assert!(turn.resolve().is_ok());
        } else {
            panic!("expected send");
        }
        // turns: (TLS) rejected at resolve() — webrtc-ice is UDP-only
        let cli =
            Cli::try_parse_from(["b2p", "receive", "--turn", "turns:h:5349", "--turn-secret", "s"])
                .unwrap();
        if let Cmd::Receive { turn, .. } = cli.cmd {
            assert!(turn.resolve().is_err());
        } else {
            panic!("expected receive");
        }
        // --turn with no creds fails at resolve()
        let cli = Cli::try_parse_from(["b2p", "receive", "--turn", "turn:h:3478"]).unwrap();
        if let Cmd::Receive { turn, .. } = cli.cmd {
            assert!(turn.resolve().is_err());
        } else {
            panic!("expected receive");
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
