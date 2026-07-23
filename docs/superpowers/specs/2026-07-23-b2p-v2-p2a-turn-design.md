# b2p v2 — P2a design: TURN fallback (+ SCTP stall-guard)

*Sub-phase of P2. Adds TURN relay support to the existing WebRTC transport so
transfers survive symmetric NAT and UDP-blocked networks, and hardens the
send path against a stall on a dead peer. No new transport, no negotiation
engine — those are later P2 sub-phases.*

Status: **Approved for planning** · Companion to `b2p-v2-spec.md` (§4 T1, §5) and
`docs/superpowers/specs/2026-07-22-b2p-v2-p1-design.md`.

---

## 1. Scope

**In P2a:**

- TURN relay support in the WebRTC transport: extend the ICE configuration with
  TURN servers (with credentials), so ICE can gather relay candidates.
- `turn:` (UDP/TCP) and `turns:` (TLS-443) URLs, the latter being the escape
  hatch for networks that block UDP outright.
- CLI flags on both `receive` and `send` to supply a TURN server, with two
  credential modes: ephemeral (coturn `use-auth-secret`) and static long-term.
- `--turn-public`: an explicit, opt-in convenience flag using a bundled
  best-effort free relay, so a user behind symmetric NAT can get a relay without
  running coturn.
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

**Open runtime unknown (de-risk before finalizing the implementation):** whether
`webrtc-0.17.2` actually *completes* a TURN-over-TLS allocation against a real
`turns:443` server. URL parsing is confirmed; the TLS allocation round-trip is
not. The plan MUST include a live smoke against a real `turns:443` relay
(`--turn-public` Open Relay, or a self-hosted coturn) before the sub-phase is
considered done.

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
- **UDP fully blocked:** the blocked peer cannot reach anything over UDP, so it
  must route out through TURN-over-TLS itself. That peer passes
  `--turn`/`--turn-public`; it allocates a relay over `turns:443` and offers the
  candidate; the other peer reaches it zero-config.

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
| `--turn <URL>` (repeatable) | A `turn:` or `turns:` URL, e.g. `turns:turn.me.com:443?transport=tcp`. |
| `--turn-secret <S>` | coturn `use-auth-secret` shared secret; b2p mints ephemeral creds (§3.2). |
| `--turn-user <U>` / `--turn-pass <P>` | Static long-term creds (§3.3). |
| `--turn-public` | Use the bundled best-effort free relay; standalone, no other flags needed. |

Validation (clap):

- `--turn` requires exactly one credential mode: `--turn-secret`, **or** both
  `--turn-user` and `--turn-pass`. The one credential set applies to **all**
  `--turn` URLs given (the expected case is one coturn exposed on several
  ports/schemes, e.g. `turn:host:3478` and `turns:host:443?transport=tcp`).
- `--turn-secret`, the `--turn-user`/`--turn-pass` pair, and `--turn-public` are
  mutually exclusive as credential sources. `--turn-public` needs no `--turn`.
- `--turn-user` and `--turn-pass` require each other.

## 5. `--turn-public`

Expands to a hardcoded set of `RTCIceServer` entries for a known free relay
(Open Relay / metered.ca: `turn:…:80`, `turn:…:443?transport=tcp`,
`turns:…:443?transport=tcp`, with its published static credentials). Kept in a
single constant so it is trivial to update if the endpoint changes.

Documented as **best-effort**: it is a third-party service that is rate-limited
and may disappear (the same fragility that made `*.trycloudflare.com` a bad
default — hence opt-in, never automatic). Error/diagnostic copy should say so
when a `--turn-public` transfer fails.

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
1. A transfer forced onto the relay path (via `--turn-public` or a real coturn),
   asserting byte-identical delivery and that the winning path is the relay.
2. SCTP stall guard: kill the receiver mid-send and confirm the sender's `send`
   returns `Err` promptly rather than hanging (mirrors the P1e kill-smoke).
3. TURN-over-TLS-443 de-risk (§2): confirm a `turns:443` relay yields a relay
   candidate and completes a transfer, exercising the one unverified runtime
   path.

## 9. Rollout

- New deps: `hmac`, `sha1`.
- Backwards compatible: no flags → identical STUN-only behavior. No code-format,
  crypto, or wire-protocol change (relay candidates ride the existing sealed
  `KIND_ICE` frames).
- Ships as a minor release (new opt-in capability).

## 10. Open items carried to `todo.md`

- Credential advertisement/borrowing so a zero-config peer can use the other
  peer's TURN (§3.1).
- `b2p doctor` TURN reachability check when `--turn` is supplied.
- `via WebRTC (TURN)` status line, if not cheaply done in P2a (§6).
