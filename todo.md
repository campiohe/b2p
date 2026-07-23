# b2p — TODO / backlog

Follow-ups deferred during the v2 build-out (P0 + P1 shipped). Grouped by the
spec phase they belong to. See `b2p-v2-spec.md` and
`docs/superpowers/specs/2026-07-22-b2p-v2-p1-design.md` for context.

## P2 — relay + TURN + negotiation

- [x] **P2b: always-relay transport via Cloudflare Worker** — SHIPPED. The
      default path now runs entirely through a self-deployed Worker
      (`relay-worker/`): WSS 443, DO room pairing, PAKE in-band, e2e flow
      control, real resume, `b2p relay set` config, relay-host-embedding
      codes, doctor probe. See
      `docs/superpowers/specs/2026-07-23-b2p-v2-p2b-relay-design.md` (+
      as-built notes) and
      `docs/superpowers/plans/2026-07-23-b2p-v2-p2b-relay.md`. Field failures
      that drove the redesign: CGNAT/symmetric far sides + UDP-blocked
      networks defeated WebRTC/TURN/tunnel everywhere the user tried v0.3.0.
- [ ] **`Transport` trait + negotiation engine** — deferred: with the relay as
      the sole default transport there is nothing to negotiate; revisit if
      LAN-direct (P3) lands and ordering matters again.

### P2b deferred follow-ups

- [ ] **Custom-domain recipe** for networks that category-block
      `*.workers.dev` (attach a domain to the Worker; doc + doctor hint).
- [ ] **HTTP CONNECT proxy support** for corporate proxies that require
      explicit proxy configuration (doctor at least names the failure today).
- [ ] **Receiver-side progress bar / status lines** on the relay path
      (receive_relay passes `progress: None` today, like P1).
- [ ] **Decide the WebRTC/ntfy/TURN stack's fate** (`--p2p`) once relay
      reliability is field-confirmed — keep as opt-in or delete and shrink
      the binary.
- [ ] **Store-and-forward via R2** (P3) — receiver can be offline; rooms
      currently require both peers live.

### P2a shipped (UDP TURN + SCTP stall guard); deferred follow-ups

- [x] **TURN fallback** for **symmetric NAT** — `--turn`/`--turn-secret`/
      `--turn-user`/`--turn-pass` (UDP `turn:` only), verified against a live
      coturn. See `docs/superpowers/specs/2026-07-23-b2p-v2-p2a-turn-design.md`.
- [x] **Send-side SCTP stall guard** — `WebRtcChannel::send` now races `dc.send`
      against a close latch, so a dead peer surfaces as `Err` instead of hanging.
- [x] **`doctor` detects symmetric NAT** (network casefile) — `stun::nat_mapping`
      probes two STUN servers from one socket and compares mapped ports, closing
      the "no blockers found" false all-clear; connect-timeout error now names
      symmetric NAT + `--turn`; `CONNECT_TIMEOUT` 20s→45s.
- [x] **`--tunnel` dead-code hang fixed** (casefile Issue 2) — `parse_tunnel_url`
      no longer scrapes cloudflared's error line; `start_cloudflared` fails fast.
- [ ] **Receiver-side DoH for the tunnel registration** — cloudflared registers
      the quick tunnel itself and offers no resolver override, so the sender's DoH
      can't help it on a DNS-filtered network. Would mean registering the tunnel
      ourselves and handing cloudflared a named tunnel — a big change, low
      priority now that `--tunnel` fails fast and the WebRTC+TURN path exists.
- [ ] **TURN over TCP/TLS is blocked upstream** — `webrtc-ice` (0.17.2, newest
      published) gathers relay candidates over UDP only; `turns:`/`?transport=tcp`
      are commented-out TODOs, so b2p rejects them. This means TURN does **not**
      cover UDP-blocked networks (use the relay above). Revisit if a newer
      `webrtc-ice` implements TCP/TLS gathering.
- [ ] **TURN credential advertisement / borrowing** — let a zero-config peer use
      the *other* peer's TURN server (advertise minted creds over the encrypted
      signaling channel before ICE gathering). P2a instead has the affected peer
      pass `--turn` (design §3.1).
- [ ] **Precise transport in the status line** — report `via WebRTC (TURN)` vs
      `(STUN)` by reading the selected candidate pair (P2a prints plain
      `via WebRTC`; reading the pair type from webrtc-0.17 is not cheap).
- [ ] **`b2p doctor` TURN reachability** when `--turn` is supplied.

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

## Out-of-core transport plugins (open interface — not shipped in the core binary)

Per spec §11, these are **not maintained in the core binary** but the open
`Transport`/`Rendezvous` interfaces (Appendix A) are meant to accept them as
out-of-tree plugins. Captured here so the door stays explicitly open rather than
foreclosed. Each changes b2p's threat/abuse profile, so gate behind an explicit
opt-in flag and ship outside the default build.

- [ ] **Traffic obfuscation / mimicry** transport — shape traffic to look like an
      allowed protocol on hostile networks.
- [ ] **Domain fronting** transport — front through a permitted CDN hostname.
- [ ] **SNI spoofing / ECH** transport — decouple the visible SNI from the real
      destination.
- [ ] **Blocklist-evasion domain cycling** for the rendezvous — rotate rendezvous
      hostnames when one is blocked.

## Housekeeping

- [ ] `b2p://` power-user URL code form is parseable but no command emits one
      (only the human code is printed by `receive`). Add a flag if wanted.
- [ ] Consider a `--code-expiry` / `--timeout` flag once the patience window
      work lands.
