# b2p CI/CD — GitHub Actions

**Date:** 2026-07-22
**Status:** Approved design

## Problem

The b2p repo has no automation. We want: fast test/lint feedback on every change,
and reproducible cross-platform binary releases when we cut a version.

## Solution overview

Two GitHub Actions workflows:

1. **`ci.yml`** — on push/PR to `main`, run formatting, lint, and tests on Linux.
2. **`release.yml`** — on tag push matching `v*`, cross-compile binaries on native
   runners and publish them to a GitHub Release.

## CI workflow (`.github/workflows/ci.yml`)

**Triggers:** `push` to `main`, and `pull_request` targeting `main`.

**Single job on `ubuntu-latest`:**
- `actions/checkout@v4`
- `dtolnay/rust-toolchain@stable` with components `clippy, rustfmt`
- `Swatinem/rust-cache@v2` (caches `~/.cargo` + `target/` keyed on `Cargo.lock`)
- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all`

**Precondition:** the codebase must already be `rustfmt`-clean, otherwise the first
`fmt --check` fails. Implementation runs `cargo fmt` and commits any diff before the
workflow lands.

## Release workflow (`.github/workflows/release.yml`)

**Trigger:** `push` with `tags: ['v*']`.

**Permissions:** `contents: write` (required to create the release).

**Job A — `build` (matrix, native runners):**

| Runner | `target` | Asset name |
|---|---|---|
| `ubuntu-latest` | `x86_64-unknown-linux-gnu` | `b2p-linux-x86_64.tar.gz` |
| `macos-14` | `aarch64-apple-darwin` | `b2p-macos-arm64.tar.gz` |
| `windows-latest` | `x86_64-pc-windows-msvc` | `b2p-windows-x86_64.zip` |

Intel macOS (`x86_64-apple-darwin` on `macos-13`) is intentionally omitted:
GitHub-hosted Intel-mac runners are scarce and queue for several minutes,
dominating release wall-clock, and Apple Silicon covers the current Mac base.

Each leg:
- checkout, `dtolnay/rust-toolchain@stable` with `targets: <target>`, `rust-cache`
- `cargo build --release --target <target>`
- Package the binary (`b2p` or `b2p.exe`) plus `README.md` and `LICENSE` (if present):
  - Unix runners: `tar czf <asset> -C <staging> .`
  - Windows runner: `Compress-Archive` into the `.zip`
- `actions/upload-artifact@v4` with the asset, named after the asset file.

Matrix uses `fail-fast: false` so one platform's failure doesn't cancel the others.

**Job B — `release` (needs: build, runs on `ubuntu-latest`):**
- `actions/download-artifact@v4` (all artifacts into a directory)
- `softprops/action-gh-release@v2`:
  - `files:` all downloaded archives
  - `generate_release_notes: true`
  - tag/name taken from the pushed tag (`github.ref_name`)

## Release procedure (documented in README)

1. Bump `version` in `Cargo.toml`, commit.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The workflow builds all four binaries and publishes the release.

## Testing / verification

- CI cannot be fully exercised locally; verification is: push the branch and confirm
  the `ci` workflow goes green in the Actions tab.
- Release workflow is verified by pushing a real tag (e.g. `v0.1.0`) and confirming
  four assets attach to the resulting GitHub Release. YAML is validated for syntax
  before pushing (via `actionlint` if available, otherwise a careful read).

## Out of scope

- Publishing to crates.io.
- Code signing / notarization of macOS and Windows binaries.
- Linux ARM64 and other niche targets (pin table has linux-arm64, but no release
  build for it yet — can be added later).
- Docker images.
