# b2p

Encrypted file transfer between two PCs that works on real-world networks —
every transfer travels through a tiny relay you deploy once, for free, on
Cloudflare Workers. Both machines only ever make an ordinary outbound
HTTPS/WebSocket connection on port 443, the same thing opening a web page
needs, so CGNAT, symmetric NAT, UDP-blocking firewalls, and DNS filtering
don't matter.

## How it works

The **receiver** prints a one-time code. Both sides derive a room id from it
and dial your relay; the relay's only job is to pair the two connections and
forward bytes — it sees ciphertext only. A SPAKE2 key exchange over that pipe
proves both sides know the code, then the file streams end-to-end encrypted
with XChaCha20-Poly1305. Interrupted transfers resume from the staged chunks
instead of restarting.

## Quick install

Download a prebuilt binary from the
[latest release](https://github.com/campiohe/b2p/releases) — Linux (static
musl), macOS (Apple Silicon), or Windows (`b2p.exe`) — and put it on your
`PATH`. No runtime dependencies.

## Deploy your relay (free, ~5 minutes, once)

The relay is a ~100-line Cloudflare Worker in `relay-worker/`. You need a free
Cloudflare account and Node.js:

    cd relay-worker
    npx wrangler login          # opens the browser once
    npx wrangler deploy         # prints https://b2p-relay.<account>.workers.dev

Optionally restrict it to holders of a shared token (recommended once your
relay URL circulates — short human codes use a small, enumerable room
namespace, so the token is what keeps strangers from squatting rooms on your
relay; your data is end-to-end encrypted either way):

    npx wrangler secret put RELAY_TOKEN

The token stays private to your own relay: b2p never sends it to a relay
address that came from someone else's `b2p://` code.

Then, on each machine that will use b2p:

    b2p relay set wss://b2p-relay.<account>.workers.dev [--token <T>]

(`--relay <url>` and the `B2P_RELAY` / `B2P_RELAY_TOKEN` env vars override the
config file; `b2p relay show` prints it.)

The free tier comfortably covers personal use — dozens of multi-GB transfers a
day; the relay never stores data.

## Usage

On the receiving machine:

    b2p receive

It prints the code two ways: a short human code like `7-otter-zebra` (works
when the sender has the same relay configured) and a long `b2p://…` form that
**embeds the relay address**, so a freshly-installed sender needs no
configuration at all. Share either over any channel you trust.

On the sending machine:

    b2p send '7-otter-zebra' path/to/file-or-folder
    b2p send 'b2p://b2p-relay.you.workers.dev/…#…' path/to/file
    b2p send '7-otter-zebra' --text "the wifi password is hunter2"

Flags: `receive --out DIR` (destination), `--yes` (no accept prompt),
`--overwrite`, `--relay URL` (override the configured relay, both commands),
`--cafile FILE` (extra root CA, all commands).

## Resume

If the connection drops mid-transfer, the receiver keeps waiting and the code
stays valid — re-run the same `send` command and only the missing chunks are
sent (the receiver reports what it already staged, matched by content
fingerprint). This works on both the relay and `--tunnel` paths.

## Diagnostics

    b2p doctor            # DNS filtering, TLS inspection, UDP/STUN, relay reachability
    b2p doctor '<code>'   # same checks, aimed at a specific code's host

Every check names the layer and ends with a one-line verdict; the relay check
does a real WebSocket connect + ping round-trip. `b2p send` runs the doctor
automatically when it cannot reach the receiver.

## Advanced: direct P2P (`--p2p`) and the tunnel (`--tunnel`)

Two alternative transports predate the relay and remain available:

- `--p2p` on both sides uses the WebRTC stack: ntfy.sh rendezvous + STUN, with
  optional UDP TURN for symmetric NAT (`--turn turn:host:3478` plus
  `--turn-secret S` or `--turn-user U --turn-pass P`; `turn:` UDP only — the
  WebRTC engine can't do TURN over TLS/TCP). Fast and free when it works, but
  it is exactly the path that fails on CGNAT/UDP-blocked networks — that's why
  the relay is the default. `--rendezvous <URL>` overrides the signaling host.
- `receive --tunnel` uses the v1 Cloudflare-tunnel path (auto-detected by the
  sender from the `https://…#…` code form). `--direct` (with `--tunnel`)
  serves directly on the LAN. The first `--tunnel` run downloads a pinned,
  checksum-verified `cloudflared` binary. On DNS-filtered networks the sender
  re-resolves the tunnel host over DNS-over-HTTPS.

## Notes

- b2p trusts the operating system's certificate store (plus `SSL_CERT_FILE` /
  `SSL_CERT_DIR` / `--cafile`); networks with TLS inspection work as long as
  the proxy's root CA is installed.
- Folder transfers briefly need ~2× the transfer size free on both sides
  (tar spool on the sender, staging area on the receiver).
- `cargo test` runs the full offline test suite (an in-process mock relay
  stands in for the Worker). `B2P_TEST_RELAY_URL=wss://… cargo test --test
  relay_live` runs a live smoke against your deployed Worker.
- Some corporate filters category-block `*.workers.dev`; putting a custom
  domain in front of the Worker sidesteps that (future recipe). Proxies that
  require explicit HTTP CONNECT configuration are not supported yet.

## Development

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `cargo clippy`, and
`cargo test` on every push and pull request to `main`.

## Releases

Prebuilt binaries for Linux, macOS (Apple Silicon), and Windows are
attached to each [GitHub Release](https://github.com/campiohe/b2p/releases).

To cut a release:

1. Bump `version` in `Cargo.toml` and commit.
2. Tag and push:

       git tag v0.1.0
       git push origin v0.1.0

The release workflow (`.github/workflows/release.yml`) cross-compiles all three
binaries (Linux x86_64 musl, macOS arm64, Windows x86_64) and publishes them to
a GitHub Release named after the tag.
