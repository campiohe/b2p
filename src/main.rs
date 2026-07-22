use anyhow::{bail, Context};
use b2p::code::Code;
use b2p::crypto::Secret;
use b2p::http::TlsOpts;
use b2p::server::{AcceptRequest, Event, ServerCfg};
use b2p::{archive, progress, send, server, tunnel};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "b2p",
    version,
    about = "Encrypted file transfer over plain HTTPS uploads"
)]
struct Cli {
    /// Extra PEM CA bundle to trust (e.g. a TLS-inspecting proxy's root CA)
    #[arg(long, global = true)]
    cafile: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wait for a transfer: host the server, open a tunnel, print the code.
    Receive {
        /// Output directory (default: current directory)
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Skip the tunnel and serve directly on the LAN
        #[arg(long)]
        direct: bool,
        /// Accept the incoming transfer without prompting
        #[arg(long)]
        yes: bool,
        /// Overwrite existing files without warning
        #[arg(long)]
        overwrite: bool,
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
        } => receive(out, direct, yes, overwrite, &tls).await,
        Cmd::Send { code, paths, text } => do_send(code, paths, text, &tls).await,
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

async fn receive(
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

async fn do_send(
    code: String,
    paths: Vec<PathBuf>,
    text: Option<String>,
    tls: &TlsOpts,
) -> anyhow::Result<()> {
    let code = Code::parse(&code).context("invalid code — paste it exactly as printed")?;
    let source = match &text {
        Some(t) => archive::prepare_text(t),
        None => {
            eprintln!("Preparing...");
            archive::prepare(&paths)?
        }
    };
    let bar = match &source {
        archive::Source::Blob { total_size, .. } => Some(progress::transfer_bar(*total_size)),
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
}
