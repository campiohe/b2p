# b2p — TODO / backlog

Follow-ups deferred during the v2 build-out (P0 + P1 shipped). Grouped by the
spec phase they belong to. See `b2p-v2-spec.md` and
`docs/superpowers/specs/2026-07-22-b2p-v2-p1-design.md` for context.

## P2 — relay + TURN + negotiation

- [ ] **Self-hostable relay + signaling binary** (`b2p relay`) — HTTPS PUT/GET
      store-and-forward; the reference relay both peers can reach over ordinary
      HTTPS when live P2P can't form. Sees only ciphertext + an opaque id.
- [ ] **TURN fallback** for symmetric NAT / blocked UDP: self-hosted `coturn`
      first, ephemeral-credential provider as fallback-only, and
      **TURN-over-TLS on 443** as the escape hatch for UDP-blocked networks.
      `transport::webrtc::connect` already takes a STUN list — extend to TURN.
- [ ] **`Transport` trait + negotiation engine** — `src/transport/mod.rs` is
      currently just `pub mod webrtc;`. Add the trait (design §4.1) and the
      per-stage-budget negotiation (design §5) so LAN / WebRTC / relay are tried
      in order instead of chosen only by code form.
- [ ] **Send-side SCTP stall guard** — a `dc.send` parked on webrtc's 128 MiB
      backpressure semaphore with a dead receiver never unblocks. Guard
      `WebRtcChannel::send` with a `tokio::select!` on the close signal
      (there's a `// TODO(p2)` marker in `src/transport/webrtc.rs`).

## P3 — LAN, async, resume

- [ ] **LAN / mDNS auto-direct** (T0) — advertise `_b2p._tcp`, connect directly
      when both peers are on the same subnet; make `--direct` automatic.
- [ ] **Store-and-forward** (self-hosted relay) — blocks persist until fetched
      or TTL expires, so the receiver can be offline.
- [ ] **Cross-transport resume** — the P1 WebRTC stream currently always
      re-sends from scratch (`ManifestAck.have` is hard-coded empty; `Store`
      staging exists but isn't used for resume on this path). Only the
      `--tunnel` path resumes today.

## P1 polish (reviewer follow-ups — do opportunistically)

**Robustness / UX**
- [ ] **Longer receive patience window** — the receiver's handshake times out at
      120s. Extend toward the ~10 min code-expiry (design §2) — needs the
      receiver to periodically *re-publish* its PAKE frame, because the ntfy
      `since=3m` window ages it out otherwise (couples to the freshness filter).
- [ ] **Rendezvous freshness filter** — use ntfy's `time` field
      (`parse_ntfy_message` currently discards it) to skip stale frames, shrinking
      the shared-channel collision window and the `SINCE_WINDOW=3m` stale-frame
      poisoning risk.
- [ ] **Live status lines on the P1 path** — `rendezvous connected → PAKE ok →
      gathering ICE → via WebRTC (STUN)` (design §6); a live progress bar on the
      *receive* side (sender side already has one).
- [ ] **`Kind::Tar` (folder) clobber check** in the accept flow — currently only
      a `Kind::File` destination is checked before overwrite (mirrors a
      pre-existing gap in `server.rs`); a folder transfer can overwrite files
      under `--out` without prompting, and `--yes` bypasses it entirely.
- [ ] **Blocking stdin in the accept prompt** runs on a runtime worker — on a
      1-core box it can stall ICE keepalives and drop the fresh connection. Use
      `spawn_blocking` / `block_in_place`.

**Diagnostics / messaging**
- [ ] **`b2p doctor` reachability for custom `--rendezvous`** — the rendezvous
      health check is still hard-coded to `ntfy.sh` (only the DNS target now
      honors `--rendezvous`). Thread the rendezvous URL into `DoctorArgs`.
- [ ] **`--rendezvous` silently ignored** with `--tunnel` and with `https://`
      codes on `send` — add a clap `conflicts_with` or a warning.
- [ ] **Text snippets on the P1 receive path** print as `Done: <text>` on stderr;
      the tunnel path prints the snippet to stdout under a header. Make them
      consistent (and pipe-friendly).
- [ ] **README** dropped the cloudflared first-run download note (still applies
      under `--tunnel`) and `--direct` fell out of the flags list.

**Internals**
- [ ] **`Store` per-chunk persistence write-amplification** on the stream path —
      at 16 KiB frames, `state.json` is rewritten every chunk (O(n²) writes) and
      buys nothing since the stream path never resumes. Batch or disable
      persistence for this path.
- [ ] **Orphaned `.b2p-partial` staging cleanup** for abandoned P1 transfers.

## Housekeeping

- [ ] `b2p://` power-user URL code form is parseable but no command emits one
      (only the human code is printed by `receive`). Add a flag if wanted.
- [ ] Consider a `--code-expiry` / `--timeout` flag once the patience window
      work lands.
