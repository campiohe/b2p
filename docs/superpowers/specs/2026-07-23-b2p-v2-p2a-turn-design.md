# b2p v2 — P2a design: TURN fallback (+ SCTP stall-guard)

*Sub-phase of P2. Adds TURN relay support to the existing WebRTC transport so
transfers survive **symmetric NAT** (where UDP egress works), and hardens the
send path against a stall on a dead peer. No new transport, no negotiation
engine — those are later P2 sub-phases.*

Status: **Implemented (as-built)** · Companion to `b2p-v2-spec.md` (§4 T1, §5) and
`docs/superpowers/specs/2026-07-22-b2p-v2-p1-design.md`.

> **As-built correction (verified against a live coturn).** `webrtc-ice` (all
> published versions, incl. 0.17.2) gathers TURN relay candidates **over UDP
> only** — `turns:` (TLS) and `?transport=tcp` are commented-out TODOs upstream
> and silently gather nothing. So the **UDP-blocked escape hatch
> (TURN-over-TLS-443) is not deliverable** with the Rust WebRTC stack, and
> `--turn-public` is dropped (its endpoint is also dead). What P2a ships: **UDP
> TURN for symmetric NAT** — verified end-to-end, including coturn accepting our
> ephemeral `use-auth-secret` credentials. The correct answer for UDP-blocked
> networks is the **HTTPS relay (P2b)** (TCP; passes inspecting proxies).
> Sections below are annotated where the plan changed.

---

## 1. Scope

**In P2a:**

- TURN relay support in the WebRTC transport: extend the ICE configuration with
  TURN servers (with credentials), so ICE can gather relay candidates.
- `turn:` (UDP) URLs only. `turns:`/`?transport=tcp` are **rejected with a clear
  error** (webrtc-ice can't gather over them). UDP-blocked networks use the HTTPS
  relay (P2b) instead.
- CLI flags on both `receive` and `send` to supply a TURN server, with two
  credential modes: ephemeral (coturn `use-auth-secret`) and static long-term.
- Send-side SCTP stall guard (the `// TODO(p2)` in `transport/webrtc.rs`).

**Out of P2a** (later P2/P3 sub-phases): the self-hostable relay binary
(`b2p relay`), the `Transport` trait, the negotiation engine, LAN/mDNS,
credential *advertisement/borrowing* (see §3.1), and automating coturn setup
(documented instead).

## 2. Why TURN is an enhancement, not a new transport

In WebRTC, if the `RTCConfiguration` lists both STUN and TURN servers, the ICE
agent gathers host, server-reflexive (STUN), and relayed (TURN) candidates and
selects the best working candidate pair on its own. Relay candidates carry the
lowest ICE priority, so a relay path is used only when direct/reflexive pairs
fail. There is no manual "STUN failed, now try TURN" escalation to write: TURN is
simply more entries in the ICE config on the same `WebRtcChannel`.

Confirmed against `webrtc-0.17.2` / `webrtc-ice-0.17.2`:

- `RTCIceServer { urls: Vec<String>, username: String, credential: String }` —
  carries credentials (no `credential_type` field; username + credential only).
- The `turns:` scheme parses, including `turns:host:443?transport=tcp`
  (`SchemeType::Turns`). Note: `turns:` requires `transport=tcp`; `transport=udp`
  is rejected by the URL parser.

**Resolved (de-risk run against a live coturn).** `webrtc-ice-0.17.2` gathers
relay candidates **over UDP only**: `agent_gather.rs` handles `ProtoType::Udp &&
SchemeType::Turn` and drops everything else (`turns:`, `?transport=tcp`) through
a commented-out TODO. Verified: `turn:host:3478` (UDP) gathers a relay candidate
and coturn accepts our `use-auth-secret` credential; `turn:…?transport=tcp` and
`turns:…` both gather nothing. So `--turn` rejects non-UDP URLs, and TURN covers
symmetric NAT only — not UDP-blocked networks (→ P2b relay).

## 3. Credential model

Only the peer that **allocates** a relay authenticates to the TURN server. The
other peer connects to the allocated public transport address as an ordinary ICE
candidate and presents **no credentials**. This is the load-bearing insight for
§3.1.

### 3.1 No credential advertisement (the simple model)

Each peer builds its own `RTCConfiguration` purely from *its own* CLI flags
(default STUN + any `--turn*` it was given). Relay candidates flow to the peer
through the **normal, already-encrypted ICE candidate exchange** (P1d's sealed
`KIND_ICE` frames). Consequences:

- **Symmetric NAT** (the proving-ground network's risk — UDP egress worked, but
  symmetric NAT can prevent a direct pair): the receiver runs
  `b2p receive --turn … --turn-secret …`, allocates a relay, and offers that
  relay candidate over ICE. The **sender connects zero-config**.
- **UDP fully blocked:** TURN can't help — webrtc-ice has no TCP/TLS relay path.
  Use the HTTPS relay (P2b), which is TCP and works where UDP is blocked.

This needs **no new signaling frame kind, no pre-connection exchange round, and
no credential sharing between peers.** A peer with no TURN flags behaves exactly
as today (STUN-only) — zero regression on the default path.

**Deferred (→ `todo.md`):** letting a zero-config peer *borrow* the other peer's
TURN server (so, e.g., a UDP-blocked sender needs no flag because the receiver
configured one). That requires advertising credentials over signaling before ICE
gathering starts, plus a pre-connection exchange round. It is a real convenience
but not needed for the cases above, where the *affected* peer passes a flag.

### 3.2 Ephemeral credentials (primary; coturn `use-auth-secret`)

The peer holding the shared secret mints a short-lived credential locally:

```
username   = "{unix_expiry}:{nonce}"        # expiry = now + TTL (unix seconds)
credential = base64( HMAC_SHA1( secret, username ) )
```

- `nonce` is a short random token (disambiguates concurrent allocations; coturn
  accepts `timestamp` or `timestamp:userid`, and any suffix after the timestamp
  is ignored for validation).
- `TTL` defaults to ~600 s, aligned with the code-expiry window.
- Deterministic given `(secret, username)` → unit-testable with a fixed
  known-answer vector.
- New crate deps: `hmac`, `sha1` (small). `base64` is already a dependency.

`SystemTime::now()` supplies the expiry; there is no ordering/replay concern
because the credential authenticates only *this* peer to *its own* TURN server.

### 3.3 Static credentials

`--turn-user U --turn-pass P` pass straight through to `RTCIceServer.username` /
`.credential`. Matches the most basic coturn setup and how free providers publish
fixed credentials.

## 4. CLI surface

Flags added to **both** `receive` and `send` (either peer may run coturn or be
the network-restricted side):

| Flag | Meaning |
| --- | --- |
| `--turn <URL>` (repeatable) | A `turn:` (UDP) URL, e.g. `turn:turn.me.com:3478`. `turns:`/`?transport=tcp` are rejected. |
| `--turn-secret <S>` | coturn `use-auth-secret` shared secret; b2p mints ephemeral creds (§3.2). |
| `--turn-user <U>` / `--turn-pass <P>` | Static long-term creds (§3.3). |

Validation (clap + `turn::resolve`):

- `--turn` requires exactly one credential mode: `--turn-secret`, **or** both
  `--turn-user` and `--turn-pass`. The one credential set applies to all `--turn`
  URLs given.
- `--turn-secret` and the `--turn-user`/`--turn-pass` pair are mutually exclusive.
- `--turn-user` and `--turn-pass` require each other.
- Non-UDP URLs (`turns:`, `?transport=tcp`) are rejected at `resolve` with a
  message pointing at the HTTPS relay for UDP-blocked networks.

## 5. `--turn-public` — dropped

Planned as a bundled free relay (Open Relay / metered.ca), but dropped in the
as-built. metered.ca deprecated the anonymous Open Relay endpoint — it now
refuses connections (the same `*.trycloudflare.com` fragility, already realized)
— and even a live free relay's main value is TLS/443, which webrtc-ice can't
use. TURN is `--turn`-only: a self-hosted UDP coturn, or a provider's UDP
endpoint.

## 6. ICE integration

- Replace `build_pc_config(stun_servers: &[String])` with a version taking
  `Vec<RTCIceServer>`: one entry for the STUN defaults plus one per configured
  TURN server (`{ urls: [turn_url], username, credential }`).
- Thread the resolved ICE-server list through `transport::webrtc::connect(...)`
  (replacing / augmenting the current `stun_servers: &[String]` parameter). The
  existing STUN defaults remain when no TURN is configured.
- The session/CLI layer resolves flags → `Vec<RTCIceServer>` once (minting
  ephemeral creds at that point) and hands the list to `connect`.
- No manual escalation logic: ICE priority handles STUN-before-TURN.

**Observability:** when the selected candidate pair is a relay pair, the status
line reads `via WebRTC (TURN)` instead of `(STUN)`. Include if reading the
selected pair type from the peer connection is cheap; otherwise note as a
follow-up rather than block the sub-phase.

## 7. SCTP send-side stall guard (warm-up)

`WebRtcChannel::send` calls `dc.send(&Bytes).await`, which can park on SCTP's
128 MiB send-buffer backpressure semaphore. If the peer has died, that await can
hang forever (the `// TODO(p2)` at `transport/webrtc.rs:65`).

Fix: `tokio::select!` the `dc.send` against the transport's close signal — reuse
the P1e teardown detection (`on_peer_connection_state_change` → `Failed|Closed`),
surfaced to `send` via a `tokio::sync::Notify` (or a shared `AtomicBool` +
notify). On close, `send` returns `Err("data channel closed")` instead of
hanging, so the sender fails fast and runs diagnostics.

## 8. Testing

**Unit:**
- Ephemeral credential derivation: fixed known-answer vector
  (`secret`, `username` → expected base64 HMAC-SHA1).
- ICE-server list construction from each flag combination.
- clap flag validation / conflicts (missing creds, mutually-exclusive modes).

**Networked smokes (required — transport change; offline tests cannot trigger
real ICE relay selection):**
1. UDP TURN de-risk: the env-based `gathers_relay_candidate_via_turn` `#[ignore]`
   test pointed at a live coturn (`B2P_TURN_URL=turn:127.0.0.1:3478
   B2P_TURN_SECRET=…`) gathers a `typ relay` candidate — done; also confirmed
   `turns:`/`?transport=tcp` gather nothing.
2. SCTP stall guard: kill the receiver mid-send and confirm the sender's `send`
   returns `Err` promptly rather than hanging (mirrors the P1e kill-smoke).

## 9. Rollout

- New deps: `hmac`, `sha1`.
- Backwards compatible: no flags → identical STUN-only behavior. No code-format,
  crypto, or wire-protocol change (relay candidates ride the existing sealed
  `KIND_ICE` frames).
- Ships as a minor release (new opt-in capability).

## 10. Open items carried to `todo.md`

- **TURN over TCP/TLS** is blocked upstream (webrtc-ice 0.17.2 is UDP-only);
  revisit if a newer webrtc-ice implements it. Until then, UDP-blocked networks
  rely on the HTTPS relay (P2b).
- Credential advertisement/borrowing so a zero-config peer can use the other
  peer's TURN (§3.1).
- `b2p doctor` TURN reachability check when `--turn` is supplied.
- `via WebRTC (TURN)` status line, if not cheaply done in P2a (§6).
