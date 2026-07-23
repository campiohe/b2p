# b2p

Encrypted file transfer between two PCs — peer-to-peer by default via WebRTC,
with a Cloudflare tunnel fallback for restricted networks.

## How it works

The **receiver** and **sender** connect peer-to-peer over a WebRTC data channel,
negotiated via a free ntfy.sh rendezvous service. A human-readable code derived
from a SPAKE2 key exchange proves both sides know the transfer secret — no trusted
server or account needed. Everything is end-to-end encrypted with
XChaCha20-Poly1305; the rendezvous server only ever carries encrypted handshakes.

For networks that block peer-to-peer: `--tunnel` on the receiver uses the old
Cloudflare tunnel path (v1 compatibility).

## Usage

On the receiving machine:

    b2p receive

It prints a one-time code like `7-otter-zebra` — share it with the sender over
any channel you trust. The receiver waits for a peer-to-peer connection and
shows `via WebRTC (STUN)` once connected.

On the sending machine:

    b2p send '7-otter-zebra' path/to/file-or-folder
    b2p send '7-otter-zebra' --text "the wifi password is hunter2"

The sender detects the code type and connects accordingly. Codes from older v1
releases (`https://…#…`) automatically use the Cloudflare tunnel path.

Flags: `receive --out DIR` (destination), `--yes` (no accept prompt),
`--overwrite`, `--tunnel` (use Cloudflare tunnel instead of WebRTC),
`--rendezvous <URL>` (override signaling host; default `https://ntfy.sh`),
`--cafile FILE` (extra root CA, both commands).

## Resume

With `--tunnel`, interrupted transfers resume automatically: re-run the same
`send` command. If the receiver restarted (new code), re-run `send` with the
new code — the partial data is matched by content fingerprint and only
missing chunks are uploaded.

The default WebRTC transport does not resume yet: an interrupted transfer
re-sends from the start on retry. Resume for it is a planned follow-up.

## Diagnostics

    b2p doctor            # is this network filtering DNS, inspecting TLS, blocking UDP?
    b2p doctor '<code>'   # same checks, aimed at a specific code's host

Every check names the layer (DNS / TLS / UDP / HTTPS) and ends with a one-line
verdict. `b2p send` runs it automatically when it cannot reach the receiver.

## Notes

- b2p trusts the operating system's certificate store (plus `SSL_CERT_FILE` /
  `SSL_CERT_DIR` / `--cafile`) for the rendezvous service; networks with TLS
  inspection work as long as the proxy's root CA is installed. `b2p doctor`
  verifies all layers (DNS, TLS, UDP, HTTPS).
- If WebRTC is blocked, use `receive --tunnel` to fall back to the Cloudflare
  path. The sender auto-detects the code type.
- Folder transfers briefly need ~2× the transfer size free on both sides
  (tar spool on the sender, staging area on the receiver).
- `cargo test` runs the full offline test suite.

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

The release workflow (`.github/workflows/release.yml`) cross-compiles all four
binaries and publishes them to a GitHub Release named after the tag.
