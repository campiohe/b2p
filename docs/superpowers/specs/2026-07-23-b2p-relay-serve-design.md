# b2p — `relay serve` design: a self-hostable native relay

*Adds a server mode to the existing `b2p` binary implementing relay protocol
v1 — the same contract as `relay-worker/` — so any machine that can run a
process (VPS, EC2, Kubernetes pod, Raspberry Pi) can be a relay. The
Cloudflare Worker stays exactly as it is: the easy, free, zero-maintenance
default. This adds provider independence, not a replacement.*

Status: **Approved design** · Protocol defined in
`docs/superpowers/specs/2026-07-23-b2p-v2-p2b-relay-design.md` (§4) and its
as-built notes; reference implementation `relay-worker/src/index.js`;
conformance suite `relay-worker/test.mjs`.

---

## 1. Why

Two implementations of one protocol, kept honest by one conformance test.
Cloudflare Workers cannot run a native server binary (event-driven platform,
proprietary APIs), so a literal shared codebase is impossible — the single
source of truth is the protocol plus `test.mjs`, which already runs unchanged
against workerd, the deployed Worker, and (after this) `b2p relay serve`.
The native server exists for users and environments outside Cloudflare;
the operator's personal Worker deployment is unaffected.

## 2. Scope

**In:**

- `b2p relay serve` subcommand: full protocol-v1 parity — room pairing by
  `/v1/room/<[A-Za-z0-9]{1,64}>?role=send|recv`, verbatim text+binary
  forwarding, `{"t":"ping"}`→`{"t":"pong"}` answered locally (not forwarded),
  `{"t":"peer-left"}` to the survivor, **takeover on duplicate role** with
  the suppressed-spurious-peer-left rule, 30-minute unpaired-room expiry
  (close 1013), optional bearer token (401), bad role (400), unknown path
  (404), `GET /healthz` → `200 ok`.
- Optional built-in TLS via `--tls-cert`/`--tls-key` (PEM; both or neither);
  default plain WS for reverse-proxy deployments (Caddy/nginx/ALB/ingress).
- One-line stderr logs (start, join, pair, depart, takeover, expiry) — never
  payload contents. Graceful shutdown on ctrl-c (close sockets 1001).
- Per-socket inbound message cap 1 MiB (parity with Workers' platform limit).
- **Replace `src/transport/mock.rs`'s hand-rolled relay** with a thin
  test wrapper that spawns the real server on `127.0.0.1:0` — one Rust relay
  implementation; the whole offline suite starts exercising production code.
  The single client test that needs a strict-409 server keeps a small inline
  stub (the real server, like the Worker, does takeover instead).
- Docker: root `Dockerfile`, `FROM scratch` + the static musl binary,
  entrypoint `b2p relay serve`, `EXPOSE 9009`. `release.yml` builds and
  pushes `ghcr.io/campiohe/b2p:<tag>` and `:latest` (GITHUB_TOKEN,
  `packages: write`).
- CI: boot `b2p relay serve` and run `relay-worker/test.mjs` against it on
  every push — conformance enforced continuously for the Rust server.
- README: "Self-host the relay" section (bare binary, docker run, 2-line
  Caddyfile for auto-TLS, k8s ingress note).

**Out (deliberate):** metrics/admin endpoints, rate limiting (the token is
the abuse gate), built-in ACME/Let's Encrypt (Caddy does it better), Windows
service packaging, changes to the Worker or the client transport.

## 3. CLI

```
b2p relay serve [--listen 0.0.0.0:9009] [--token <T>] [--tls-cert cert.pem --tls-key key.pem]
```

- `--listen` default `0.0.0.0:9009`.
- `--token` falls back to env `RELAY_TOKEN` (the same name the Worker's
  secret uses; the client keeps `B2P_RELAY_TOKEN`).
- `--tls-cert` and `--tls-key` require each other (clap `requires`).
- Lives in the existing `RelayCmd` subcommand enum next to `set`/`show`.

## 4. Architecture (`src/relay_server.rs`)

```
TcpListener → [optional TLS accept (tokio-rustls)] → HTTP request head
  → /healthz → 200 ok
  → /v1/room/... upgrade → per-connection task ⇄ shared Rooms state
```

- **Rooms state:** `HashMap<String, Room>` behind a mutex; `Room` holds up
  to one sender/receiver slot, each an unbounded mpsc of outbound
  `Message`s (the mock's proven shape). Pairing sends `peer-joined` to
  both. Takeover: close the old same-role socket (1012), remove its slot
  *before* inserting the new one — its connection task, finding itself
  absent from the map at cleanup, skips `peer-left` (same suppression the
  Worker does). Departure of a still-registered socket sends `peer-left`
  and stamps the survivor's room `alone_since`.
- **Expiry:** a sweeper task ticks once a minute and closes (1013) rooms
  that have had one occupant for ≥30 min (`alone_since`), matching the
  Worker's alarm. Pairing clears the stamp.
- **TLS:** when cert/key given, wrap accepted TCP in a `tokio-rustls`
  acceptor built with the ring provider (house rule: explicit provider,
  never bare `builder()`); rustls + rustls-pemfile are existing deps.
- **healthz/routing (SPIKE RESOLVED):** tungstenite rejects non-upgrade
  requests before `accept_hdr_async`'s callback runs, so the server owns
  the request head: read until `\r\n\r\n`, parse with `httparse` (the one
  new dependency; zero transitive deps), answer `/healthz`/401/400/404
  directly, and for genuine upgrades write the 101 itself
  (`tungstenite::handshake::derive_accept_key`) then hand the socket to
  `WebSocketStream::from_raw_socket` behind a small prefix-replaying
  AsyncRead+AsyncWrite wrapper for any bytes read past the head. Verified
  end-to-end in a spike: curl `/healthz` → `ok`, and a real
  tokio-tungstenite client round-tripped 100 KB through the manual 101.
  k8s note: `/healthz` works for HTTP probes; `tcpSocket` probes also fine.
- **Isolation:** one tokio task per connection; a panic or slow peer in one
  room cannot affect others (same property the DO gives the Worker).
- New dependencies: none required; possibly `httparse` (spike-dependent);
  `tokio-rustls` is already in the tree via tokio-tungstenite.

## 5. Docker & release

- `Dockerfile` (repo root): `FROM scratch`, `COPY b2p /b2p`,
  `ENTRYPOINT ["/b2p","relay","serve"]`, `EXPOSE 9009`. No CA bundle needed
  (the server makes no outbound TLS connections). Image ≈ binary size.
- `release.yml`: after the linux-musl build, a job logs into GHCR with the
  workflow token and pushes `ghcr.io/campiohe/b2p:vX.Y.Z` + `:latest`.
  Documented run line:
  `docker run -p 9009:9009 -e RELAY_TOKEN=… ghcr.io/campiohe/b2p:latest`.

## 6. Testing

- **Conformance (the point of the design):** `relay-worker/test.mjs`
  unchanged against `b2p relay serve` — locally in the plan's verification
  and as a CI step on every push. The same file validates the Worker, so
  the two implementations cannot drift silently.
- **Unit (Rust):** takeover closes old + suppresses peer-left; expiry
  closes lone rooms and spares paired ones; token 401; bad role 400; path
  404; healthz 200; TLS accept with a self-signed cert (rcgen is already a
  dev-dependency).
- **Existing suite:** `transport/mock.rs` becomes
  `relay_server::spawn_ephemeral()` behind the same `start()` shape —
  every relay/session/doctor offline test now runs against production code.
- **e2e:** a full `receive`/`send` transfer through `b2p relay serve`
  (session-level test + the real binary in the plan's verification).
- Gate unchanged: `cargo fmt --check`, `clippy --all-targets -- -D
  warnings`, `cargo test`.

## 7. Security notes

Identical posture to the Worker: the relay sees ciphertext, sizes, timing;
rooms for human codes are enumerable (256) so the token is the abuse gate
for any relay whose address circulates; the client never sends a configured
token to a host embedded in someone else's code. Built-in TLS trusts
operator-provided certs only. The 1 MiB message cap and per-connection
tasks bound per-client memory; room state is O(occupied rooms).

## 8. Follow-ups this creates

- Publish a versioned protocol document if third-party relays appear.
- Optional: `b2p doctor` hint distinguishing "relay reachable but token
  rejected" (already surfaced as a 401 message by the client).
- Optional later: metrics endpoint, rate limiting, ACME — only with real
  demand.

## 9. As-built hardening (two-reviewer whole-branch pass)

A native server has none of the platform shields Cloudflare gives the
Worker, so the review round added the guards a public-facing server needs —
all with regression tests:

- **Bounded per-connection outbound queue** (was unbounded → unauthenticated
  remote OOM): a peer that stops reading while being flooded overflows its
  24-slot queue and is dropped ("slow consumer = dead consumer"); honest
  clients stay far under it thanks to the 8 MiB end-to-end window.
- **Handshake deadline + connection cap**: the head read and TLS handshake
  run under a 10 s budget (configurable), and a semaphore caps concurrent
  connections at 4096 — slow-loris can no longer park tasks/fds forever.
- **Accept loop survives errors**: a per-`accept()` error (e.g. EMFILE under
  an fd flood) logs + backs off + continues instead of killing the listener.
- **Docker release fix**: the tarball stores `./b2p`, so the GHCR job
  extracts `./b2p` (the bare `b2p` member did not exist → every release
  would have failed to publish the image).
- **Frame-size cap** (`max_frame_size = 1 MiB`): without it a single 16 MiB
  frame buffered before the message check, making the real inbound peak 16×.
- **Atomic expiry** (sweeper removes the slot under the lock): closes the
  narrow sweeper-vs-pairing race where a joiner could pair with a doomed
  socket and see a spurious peer-left, spuriously failing `b2p send`.
- **Mutex-poison recovery** (`lock_rooms`): a panic under the rooms lock no
  longer cascades a server-wide outage, honoring the §4 isolation claim.
- **Graceful shutdown**: live sockets now receive a 1001 "going away" close.
- Known benign parity NITs left as-is (uncaught by test.mjs): duplicate
  `Authorization` is last-wins here vs comma-joined on the Worker; the 426
  gate additionally requires `Connection: upgrade` + `Sec-WebSocket-Key`.
  Real clients send all three; neither is exploitable.
