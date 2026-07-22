# b2p

Encrypted file transfer between two PCs — like croc, but the only traffic the
sender's network ever sees is a plain HTTPS upload.

## How it works

The **receiver** hosts a local HTTP server and exposes it through a free
Cloudflare quick tunnel (an outbound connection — no port forwarding, no
hosting, no account). The **sender** uploads the data as encrypted chunks with
ordinary HTTPS requests. Everything is end-to-end encrypted with
XChaCha20-Poly1305; the tunnel only ever carries ciphertext.

## Usage

On the receiving machine:

    b2p receive

It prints a one-time code like
`https://tall-lion-radio.trycloudflare.com#hV8kPz3q...` — share it with the
sender over any channel you trust. The part after `#` never travels over the
network.

On the sending machine:

    b2p send '<code>' path/to/file-or-folder
    b2p send '<code>' --text "the wifi password is hunter2"

Flags: `receive --out DIR` (destination), `--yes` (no accept prompt),
`--overwrite`, `--direct` (same-LAN mode, no tunnel).

## Resume

Interrupted transfers resume automatically: re-run the same `send` command.
If the receiver restarted (new code), re-run `send` with the new code — the
partial data is matched by content fingerprint and only missing chunks are
uploaded.

## Notes

- First `receive` run downloads a pinned, checksum-verified `cloudflared`
  binary into the b2p data directory.
- Folder transfers briefly need ~2× the transfer size free on both sides
  (tar spool on the sender, staging area on the receiver).
- `cargo test` runs the full offline test suite; `scripts/smoke-tunnel.sh`
  exercises a real tunnel.

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
