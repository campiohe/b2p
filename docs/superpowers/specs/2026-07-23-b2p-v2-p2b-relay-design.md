# b2p v2 — P2b design: always-relay transport (Cloudflare Worker)

*Sub-phase of P2. Replaces the default transport with a relayed stream through a
self-deployed Cloudflare Worker that both peers reach over an outbound
WebSocket on port 443 — the only network capability required becomes "can open
an HTTPS connection". WebRTC moves behind an opt-in flag; `--tunnel` is
untouched. This is the "self-hostable relay" the P2 backlog called for, with a
Worker instead of a VPS binary as the reference host.*

Status: **Implemented (as-built)** · Companion to `b2p-v2-spec.md` (§4 T2, §5)
and `docs/superpowers/specs/2026-07-23-b2p-v2-p2a-turn-design.md`. Plan:
`docs/superpowers/plans/2026-07-23-b2p-v2-p2b-relay.md`.

> **As-built notes (implementation refinements, all verified by tests):**
> 1. PAKE-in-band is `handshake::handshake_over_channel()` reusing `pake.rs`
>    and the existing frame encoding directly over `MsgChannel` — no
>    `Rendezvous` adapter (§2 as-specced). Same outcome, less machinery. A
>    wrong-code sender surfaces as a typed `CodeMismatch` the receiver's loop
>    re-arms on.
> 2. Room id = `RendezvousCode.topic` verbatim — already channel-only for
>    human codes / independently random for URL codes, which is exactly the
>    security property §4's new HKDF domain was for. No new derivation.
> 3. The Worker rejects bad joins with plain HTTP statuses (401/409/400)
>    before the upgrade instead of a `{"t":"error"}` control message; the
>    client maps them to actionable errors at dial time.
> 4. Binary framing supports splitting one logical frame across WS messages
>    (a continuation bit in the `u32` sub-frame header), so a huge `Manifest`
>    (10k-file folder) or resume ack can never hit Workers' 1 MiB message
>    cap. Batching is write-behind: immediate when the socket is idle,
>    coalesced (≤960 KiB) when it's busy.
> 5. Resume uses a NEW `protocol::StreamManifestAck` with run-length
>    `have_runs: Vec<(start, len)>` — the tunnel path's `ManifestAck` wire
>    format stays frozen (it is also v1's HTTP ack). Mixed-version `--p2p`
>    peers therefore fail the manifest ack parse; both sides should run the
>    same version (the default relay path already requires that).
> 6. Config uses the already-present `directories` crate (not `dirs`);
>    doctor's symmetric-NAT verdict now points at the relay default rather
>    than `--turn`, and notes when the configured relay is reachable.

---

## 1. Why always-relay (field data)

Real-world use of v0.3.0 failed to connect in **every** scenario tried: two
different home networks, a corporate network, and a mobile hotspot. The local
network was clean (`doctor`: endpoint-independent NAT, UDP egress fine, ntfy
reachable), so the failures came from the far side:

- Residential and mobile networks here are typically behind **CGNAT**, often
  symmetric → STUN fails; the P2a answer (`--turn`) requires a self-hosted
  coturn, which defeats "install on two machines and it works".
- Corporate networks **block UDP** outright → WebRTC cannot form at all, and
  TURN cannot help (webrtc-ice is UDP-only — P2a as-built finding).
- The `--tunnel` fallback dies on DNS-filtered networks (`*.trycloudflare.com`
  sinkholed; cloudflared cannot use the sender-side DoH workaround).

croc demonstrates the reliable architecture: both sides make an **outbound
TCP/TLS connection to an always-on relay** which splices the two streams.
Outbound 443 works on effectively every network.

Three approaches were considered:

- **A — P2P-first, relay fallback:** try WebRTC ~15 s, then fall back. Faster
  on easy networks, but two paths to debug and the field data shows P2P never
  once succeeded for the operator's real networks.
- **B — always-relay (chosen):** every transfer goes through the relay. One
  path, one failure mode, croc-grade predictability. Cost: same-LAN transfers
  round-trip the internet (accepted; LAN-direct returns as a P3 optimization),
  and relay quota is spent even when P2P could have worked.
- **C — TURN over TCP/TLS (rejected):** not implementable on the Rust WebRTC
  stack (P2a verified), would require a coturn VPS anyway.

Hosting: **Cloudflare Workers free tier** (chosen over a free VPS). $0,
serverless, one-command deploy (`wrangler deploy`), nothing to maintain,
reachable on 443. GitHub Pages was considered and ruled out — static hosting
cannot accept uploads or hold connections.

## 2. Scope

**In P2b:**

- `relay-worker/`: a TypeScript Cloudflare Worker + Durable Object implementing
  relay protocol v1 (§4). Deployed by the operator once.
- `src/transport/relay.rs`: a `RelayChannel` implementing `stream::MsgChannel`
  over a WebSocket to the Worker, plus a `Rendezvous` adapter so the existing
  SPAKE2 `handshake()` runs **in-band** over the same socket (ntfy.sh leaves
  the default path).
- Session rewiring: `receive`/`send` default to the relay path. WebRTC+ntfy
  becomes opt-in via `--p2p`. `--tunnel` unchanged.
- Relay URL configuration: `--relay` flag > `B2P_RELAY` env > config file
  (`b2p relay set <url>` / `b2p relay show`). Long-form `b2p://` codes embed
  the relay host so an unconfigured sender can connect by pasting the code.
- **Resume** on the relay path: `ManifestAck.have` becomes real (receiver
  reports staged chunks by content fingerprint; sender skips them).
- `b2p doctor`: relay reachability check (WSS connect + ping round-trip).
- Tests: in-process Rust mock relay for offline e2e; env-gated networked smoke
  against a deployed Worker.

**Out of P2b** (later phases): LAN/mDNS direct (P3), store-and-forward for an
offline receiver (P3, would need R2), HTTP CONNECT proxy support, custom
domain in front of `workers.dev`, deleting the WebRTC/ntfy/TURN code (kept
compiled behind `--p2p`; removal is a separate decision), `Transport` trait +
negotiation engine (pointless until there are ≥2 default transports again).

## 3. Architecture

```
sender ── WSS 443 ──▶ ┌──────────────────────────────┐ ◀── WSS 443 ── receiver
                      │ Cloudflare Worker             │
                      │  └─ Durable Object (per room) │
                      │     pairs 2 peers, forwards   │
                      │     opaque binary frames      │
                      └──────────────────────────────┘
```

Both peers derive the same **room id** from the transfer code and connect to
`wss://<worker-host>/v1/room/<room-id>`. The Durable Object for that room holds
at most two sockets (one per role) and forwards binary messages from one to the
other verbatim. All application content — PAKE handshake, manifest, file
chunks — is end-to-end encrypted before it reaches the socket; the relay sees
ciphertext, sizes, and timing only.

Connection flow (replaces `session::receive_p1`/`send_p1` internals):

1. Open WSS to the room (bounded connect, 15 s — a relay that works answers in
   seconds; keep 45 s only for the overall establish budget).
2. Wait for `peer-joined` (receiver may wait long; sender expects it fast).
3. Run the existing `handshake()` (SPAKE2 + confirmation) over the socket via
   the `Rendezvous` adapter — unchanged code, new carrier.
4. Continue on the same socket as the `MsgChannel` for `stream.rs` framing
   (16 KiB AEAD frames, unchanged).

## 4. Relay protocol v1

- **Endpoint:** `GET wss://<host>/v1/room/<room-id>?role=send|recv`. Optional
  shared secret: `Authorization: Bearer <token>` (Worker checks against a
  `RELAY_TOKEN` secret if configured; native client, so headers are fine).
- **Room id:** 32 bytes, lowercase hex, derived from the code's secret via the
  existing crypto-domain machinery with a **new domain string**
  (`b2p relay room v1`) — same pattern as the ntfy channel topic, distinct
  output, not invertible to the PAKE password.
- **Message types:**
  - *Text* WS messages: control JSON between client and DO —
    `{"t":"peer-joined"}`, `{"t":"peer-left"}`, `{"t":"ping"}`/`{"t":"pong"}`,
    `{"t":"ack","n":<bytes>}` (end-to-end, forwarded), and
    `{"t":"error","code":...}` (`room-full`, `bad-role`, `unauthorized`).
  - *Binary* WS messages: payload, forwarded verbatim to the other peer. Each
    contains one or more length-prefixed sub-frames (`u32 LE length` +
    `MsgChannel` frame), batched by the sender up to **512 KiB** per WS message
    (hard cap 960 KiB — Workers' limit is 1 MiB). Batching lives entirely in
    `RelayChannel`; `stream.rs` still sees one logical message per frame.
- **Flow control (end-to-end):** the receiving client sends `ack` every 1 MiB
  consumed; the sending client stops writing at **8 MiB unacknowledged**. This
  bounds DO memory to ~one window regardless of peer speed mismatch.
- **Liveness:** the DO notifies the survivor with `peer-left` on any close;
  `RelayChannel::recv`/`send` surface that as `Err` promptly (the P1d/P2a
  no-hang lessons apply: bounded waits, close-latch armed *before* flag
  checks). Client pings every 30 s to keep NAT/proxy idle timeouts away.
- **Room lifecycle:** max 2 sockets, role-tagged; a duplicate role or third
  socket is rejected with `error`. Unpaired rooms expire after **30 min** (DO
  alarm). When either peer disconnects the room resets (the receiver may
  re-arm and wait again — see resume, §6).

## 5. The Worker (`relay-worker/`)

TypeScript, ~200 lines: a stateless router Worker that forwards
`/v1/room/<id>` upgrades to the room's Durable Object, and the DO class using
the **WebSocket Hibernation API** (a waiting receiver consumes no duration;
incoming messages bill 20:1). `wrangler.toml` in-repo; deploy is
`npx wrangler deploy`, token via `npx wrangler secret put RELAY_TOKEN`
(optional). README gains a "deploy your relay (free, 5 minutes)" section.

Free-tier budget for the target use (100 MB–2 GB files, a few transfers/day),
to be re-verified against Cloudflare's current pricing page during
implementation: a 2 GiB transfer at 512 KiB per message ≈ 4–8 k incoming
messages ≈ a few hundred billable DO requests (20:1) against a 100 k/day free
allowance; forwarding is ~memcpy, far under CPU-time limits; Workers currently
bills no egress bandwidth. Dozens of 2 GiB transfers per day fit in $0.

## 6. Resume (relay path)

Today `ManifestAck.have` is hard-coded empty and every retry restarts from
zero — unacceptable for 2 GiB through a relay. P2b implements it: the receiver
matches the incoming manifest against its `Store` staging by content
fingerprint and returns the chunk indices it already holds; the sender skips
those. On a dropped connection the receiver stays up, prints that the code is
still valid, and re-arms the room; the sender re-runs `send` with the same
code — a fresh PAKE handshake, then a transfer of only the missing chunks.
Codes remain single-use **on success**.

## 7. CLI & configuration

- `b2p receive` / `b2p send` default to the relay path. New `--p2p` flag on
  both selects the previous WebRTC+ntfy stack. `--rendezvous` and `--turn`
  **require** `--p2p` (clap `requires`, so using them without it is a clear
  error, not a silent implication). `--tunnel` unchanged.
- Relay URL resolution: `--relay <wss://…>` flag > `B2P_RELAY` env >
  `b2p relay set <url>` config (`~/.config/b2p/config.toml` or platform
  equivalent; `b2p relay show` prints it) > a clear error telling the user to
  deploy + set one.
- **Code forms:** `b2p receive` prints both the short human code
  (`7-otter-zebra` — requires both machines configured with the same relay)
  and the long `b2p://` form, which now **embeds the relay host** so a
  freshly-installed sender needs zero configuration. `rvcode` parsing is
  extended accordingly (long form stays versioned/forward-compatible).
- `b2p doctor` gains a relay check when a relay is configured or given:
  WSS connect + `ping`/`pong` round-trip, reported as its own layer line.
- Distribution needs no new work: `release.yml` already publishes Linux
  (musl), macOS (arm64), and Windows (`b2p.exe`) binaries on every tag.
  README gets a quick-install section pointing at the release assets.

## 8. Security model (unchanged posture)

SPAKE2 code-derived keys; XChaCha20-Poly1305 AEAD on every frame; the relay
carries ciphertext only and cannot learn the code, keys, or filenames. Room
ids are derived one-way from the code secret. A wrong-code sender fails PAKE
confirmation exactly as on the ntfy path. New trust surface: the operator's
own Cloudflare account replaces ntfy.sh as the (blind) traffic carrier — a
strict improvement. Abuse of an open relay by strangers is limited by
high-entropy room ids (unguessable; both parties must know the code) and,
where wanted, the deploy-time bearer token.

Known residual gaps, accepted for P2b: networks that category-block
`*.workers.dev` (fix later with a custom domain), and corporate proxies that
require explicit HTTP CONNECT configuration (doctor will at least name the
failure; proxy support is future work).

## 9. Testing

- Unit: room-id derivation vectors; batching/splitting round-trip; ack window
  arithmetic (stall at 8 MiB unacked, resume on ack).
- Offline e2e: an in-process Rust mock relay (tokio + tungstenite server
  implementing protocol v1's happy path + `peer-left`) drives the full
  receive|send session including PAKE-in-band, resume-after-drop, and
  abrupt-peer-death (recv/send must `Err`, never hang — regression tests
  mirroring the P1d/P2a hang bugs).
- Networked smoke (env-gated, e.g. `B2P_TEST_RELAY_URL`): full transfer
  against a real deployed Worker — **required before release** per the
  project rule that transport changes get a real-network verification;
  offline tests cannot exercise Cloudflare's WS behavior (message limits,
  hibernation, close codes).
- Gate: `cargo clippy --all-targets -- -D warnings` + `cargo test`, as always.
- De-risk first (proven workflow): before the implementation plan is written,
  a scratchpad spike must validate the two unknown APIs — tokio-tungstenite
  WSS through rustls-with-OS-store, and a minimal DO echo/pair Worker under
  `wrangler dev` — including one real `workers.dev` round-trip.

## 10. Open follow-ups this creates

- LAN/mDNS direct transport (P3) — restores local-network speed.
- Store-and-forward via R2 (P3) — receiver can be offline.
- Custom-domain recipe for category-blocked `workers.dev`.
- Decide the fate of the WebRTC/ntfy/TURN stack once relay reliability is
  field-confirmed (keep as `--p2p`, or delete and shrink the binary).
